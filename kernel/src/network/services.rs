//! Application-facing network services: datagram, TCP connect, ICMP echo,
//! observation, and configuration.
//!
//! These are the dispatcher endpoints through which an application reaches the
//! kernel's network stack. Each one holds a handle to `KernelNetwork` and
//! therefore a share of the authority ADR 0035 Phase D wants moved out of the
//! kernel: a user-space network service would expose these same interfaces
//! without the kernel holding the device. The endpoints move to that service;
//! the kernel's own calls into it become part of the `kernel/src/client.rs`
//! ADR 0035 names.

use crate::handles::{
    SharedApplicationDatagram, SharedNetwork, SharedRuntime, SharedTcpConnection, SharedTcpListener,
};
use crate::network::{
    KernelNetwork, NetworkError, NetworkStatus, ReceivedUdp, application_network_status,
    emission_segment, map_network_error, map_tcp_error,
};
use crate::runtime::KernelRuntimeCapability;
use alloc::vec::Vec;
use troe_abi::{
    datagram, icmp_echo, network_configuration, network_observation, tcp_connect, tcp_listen,
};
use troe_dispatch::{ReplyStatus, Request, Service, ServiceReply};
use troe_net::NetworkDevice;
use troe_net::{Ipv4Address, TcpConnection, TcpEndpoint, build_tcp};
use troe_task::MonotonicMillis;

pub(crate) struct ApplicationDatagramService {
    state: SharedApplicationDatagram,
    runtime: SharedRuntime,
}

pub(crate) struct ApplicationDatagramState {
    network: SharedNetwork,
    ports: Vec<u16>,
}

pub(crate) struct ApplicationNetworkObservationService {
    pub(crate) network: Option<SharedNetwork>,
}

pub(crate) struct ApplicationNetworkConfigurationService {
    pub(crate) network: Option<SharedNetwork>,
    pub(crate) runtime: SharedRuntime,
}

pub(crate) struct ApplicationIcmpEchoService {
    pub(crate) network: Option<SharedNetwork>,
    pub(crate) runtime: SharedRuntime,
}

pub(crate) struct ApplicationTcpConnectService {
    network: SharedNetwork,
    runtime: SharedRuntime,
    attempted: bool,
    connection: Option<SharedTcpConnection>,
}

/// One bounded inbound listening endpoint and the streams it accepted.
///
/// The handle owns exactly one endpoint for one launch. Accepted connections
/// are named by an identifier this service assigns and are removed with the
/// listener when the owner is torn down, so no inbound stream outlives the
/// application that accepted it.
pub(crate) struct ApplicationTcpListenService {
    network: SharedNetwork,
    runtime: SharedRuntime,
    listener: Option<SharedTcpListener>,
    accepted: Vec<AcceptedStream>,
    next_connection: u16,
}

struct AcceptedStream {
    connection: u16,
    stream: SharedTcpConnection,
}

/// Bounded deadline for one TCP stream operation, shared by both services.
const TCP_OPERATION_MILLISECONDS: u64 = 4_000;
/// Segments transmitted per flush, shared by both services.
const TCP_FLUSH_BUDGET: usize = 2;

/// Transmit at most `TCP_FLUSH_BUDGET` due segments for one connection.
///
/// Both TCP services drive emission the same way, so the stream half of the
/// connect and listen interfaces is one implementation rather than two.
fn tcp_flush(
    network: &SharedNetwork,
    runtime: &SharedRuntime,
    stream: &SharedTcpConnection,
) -> Result<(), NetworkError> {
    for _ in 0..TCP_FLUSH_BUDGET {
        let now = runtime.borrow().now().as_millis();
        let frame = {
            let mut stream = stream.borrow_mut();
            let peer_mac = stream.peer_mac;
            let Some(emission) = stream.machine.poll_emission(now).map_err(map_tcp_error)? else {
                break;
            };
            let source_mac = network.borrow().device.mac_address();
            build_tcp(source_mac, peer_mac, emission_segment(&emission))
                .map_err(map_network_error)?
        };
        network.borrow_mut().transmit(&frame)?;
    }
    Ok(())
}

/// Yield cooperatively until the deadline, then flush any due segment.
fn tcp_wait_checkpoint(
    network: &SharedNetwork,
    runtime: &SharedRuntime,
    stream: &SharedTcpConnection,
    deadline: MonotonicMillis,
) -> Result<(), NetworkError> {
    if runtime.borrow().now() >= deadline {
        return Err(NetworkError::Timeout);
    }
    runtime
        .borrow_mut()
        .checkpoint()
        .map_err(|_| NetworkError::Cancelled)?;
    tcp_flush(network, runtime, stream)
}

/// Deadline one bounded stream operation from now.
fn tcp_deadline(runtime: &SharedRuntime) -> MonotonicMillis {
    runtime
        .borrow()
        .now()
        .saturating_add(TCP_OPERATION_MILLISECONDS)
}

/// Write every byte through bounded single-segment acknowledgements.
fn tcp_write(
    network: &SharedNetwork,
    runtime: &SharedRuntime,
    stream: &SharedTcpConnection,
    bytes: &[u8],
) -> Result<(), NetworkError> {
    let deadline = tcp_deadline(runtime);
    let mut offset = 0;
    while offset < bytes.len() {
        let capacity = {
            let stream = stream.borrow();
            if !matches!(
                stream.machine.state(),
                troe_net::TcpState::Established | troe_net::TcpState::CloseWait
            ) {
                return Err(stream
                    .machine
                    .terminal_error()
                    .map_or(NetworkError::Closed, map_tcp_error));
            }
            stream.machine.send_capacity()
        };
        if capacity == 0 {
            tcp_wait_checkpoint(network, runtime, stream, deadline)?;
            continue;
        }
        let count = capacity.min(bytes.len().saturating_sub(offset));
        let chunk = bytes
            .get(offset..offset.saturating_add(count))
            .ok_or(NetworkError::Protocol)?;
        stream
            .borrow_mut()
            .machine
            .begin_send(chunk)
            .map_err(map_tcp_error)?;
        loop {
            tcp_flush(network, runtime, stream)?;
            if stream
                .borrow()
                .machine
                .send_complete()
                .map_err(map_tcp_error)?
            {
                break;
            }
            tcp_wait_checkpoint(network, runtime, stream, deadline)?;
        }
        offset = offset.saturating_add(count);
    }
    Ok(())
}

/// Wait for and drain bounded retained bytes; zero is orderly end of stream.
fn tcp_read(
    network: &SharedNetwork,
    runtime: &SharedRuntime,
    stream: &SharedTcpConnection,
    destination: &mut [u8],
) -> Result<usize, NetworkError> {
    let deadline = tcp_deadline(runtime);
    loop {
        let read = stream
            .borrow_mut()
            .machine
            .read(destination)
            .map_err(map_tcp_error)?;
        if let Some(count) = read {
            tcp_flush(network, runtime, stream)?;
            return Ok(count);
        }
        tcp_wait_checkpoint(network, runtime, stream, deadline)?;
    }
}

/// Begin and complete one graceful close.
fn tcp_close(
    network: &SharedNetwork,
    runtime: &SharedRuntime,
    stream: &SharedTcpConnection,
) -> Result<(), NetworkError> {
    let deadline = tcp_deadline(runtime);
    {
        let mut stream = stream.borrow_mut();
        if stream.machine.is_closed() {
            return stream
                .machine
                .terminal_error()
                .map_or(Ok(()), |error| Err(map_tcp_error(error)));
        }
        stream.machine.begin_close().map_err(map_tcp_error)?;
    }
    loop {
        tcp_flush(network, runtime, stream)?;
        {
            let stream = stream.borrow();
            if let Some(error) = stream.machine.terminal_error() {
                return Err(map_tcp_error(error));
            }
            if matches!(
                stream.machine.state(),
                troe_net::TcpState::TimeWait | troe_net::TcpState::Closed
            ) {
                return Ok(());
            }
        }
        tcp_wait_checkpoint(network, runtime, stream, deadline)?;
    }
}

pub(crate) fn encode_application_network_status(
    status: NetworkStatus,
) -> Result<[u8; network_observation::STATUS_BYTES], troe_dispatch::DispatchError> {
    let configuration = match (status.address, status.subnet_mask, status.gateway) {
        (Some(address), Some(subnet_mask), Some(gateway)) => {
            Some(network_observation::Ipv4Configuration {
                address,
                subnet_mask,
                gateway,
                lease_seconds: status.lease_seconds,
            })
        }
        (None, None, None) if status.lease_seconds.is_none() => None,
        _ => return Err(troe_dispatch::DispatchError::AccountingOverflow),
    };
    network_observation::encode_status(network_observation::Status {
        mac: status.mac,
        configuration,
    })
    .map_err(|_| troe_dispatch::DispatchError::AccountingOverflow)
}

impl Service for ApplicationNetworkObservationService {
    fn call(&mut self, request: Request<'_>) -> Result<ServiceReply, troe_dispatch::DispatchError> {
        if !request.payload().is_empty() {
            return Ok(ServiceReply::empty(ReplyStatus::InvalidRequest));
        }
        let Some(network) = &self.network else {
            return Ok(ServiceReply::empty(ReplyStatus::NotFound));
        };
        let service = network.borrow();
        match request.opcode() {
            network_observation::GET_STATUS => ServiceReply::with_payload(
                ReplyStatus::Success,
                &encode_application_network_status(service.shell_status())?,
            ),
            network_observation::GET_STATS => {
                let stats = network_observation::Stats {
                    received_frames: service.stats.received_frames,
                    transmitted_frames: service.stats.transmitted_frames,
                    arp_replies: service.stats.arp_replies,
                    icmp_replies: service.stats.icmp_replies,
                    udp_retained: service.stats.udp_retained,
                    udp_unbound: service.stats.udp_unbound,
                    udp_dropped: service.stats.udp_dropped,
                    arp_entries: u64::try_from(service.arp.len())
                        .map_err(|_| troe_dispatch::DispatchError::AccountingOverflow)?,
                    udp_ports: u64::try_from(service.udp.len())
                        .map_err(|_| troe_dispatch::DispatchError::AccountingOverflow)?,
                    checkpoints: service.stats.checkpoints,
                    errors: service.stats.errors,
                };
                ServiceReply::with_payload(
                    ReplyStatus::Success,
                    &network_observation::encode_stats(stats)
                        .map_err(|_| troe_dispatch::DispatchError::AccountingOverflow)?,
                )
            }
            network_observation::GET_NEIGHBORS => {
                let mut entries =
                    [network_observation::Neighbor::default(); network_observation::MAX_NEIGHBORS];
                let mut count = 0;
                for entry in service.arp.entries() {
                    let Some(destination) = entries.get_mut(count) else {
                        return Err(troe_dispatch::DispatchError::AccountingOverflow);
                    };
                    *destination = network_observation::Neighbor {
                        address: entry.address.bytes(),
                        mac: entry.mac.bytes(),
                    };
                    count += 1;
                }
                let neighbors = network_observation::Neighbors::from_slice(&entries[..count])
                    .map_err(|_| troe_dispatch::DispatchError::AccountingOverflow)?;
                let mut encoded = [0_u8; network_observation::MAX_NEIGHBOR_REPLY_BYTES];
                let count = network_observation::encode_neighbors(neighbors, &mut encoded)
                    .map_err(|_| troe_dispatch::DispatchError::AccountingOverflow)?;
                ServiceReply::with_payload(ReplyStatus::Success, &encoded[..count])
            }
            _ => Ok(ServiceReply::empty(ReplyStatus::InvalidRequest)),
        }
    }
}

impl Service for ApplicationNetworkConfigurationService {
    fn call(&mut self, request: Request<'_>) -> Result<ServiceReply, troe_dispatch::DispatchError> {
        if request.opcode() != network_configuration::DHCP || !request.payload().is_empty() {
            return Ok(ServiceReply::empty(ReplyStatus::InvalidRequest));
        }
        let Some(network) = &self.network else {
            return Ok(ServiceReply::empty(ReplyStatus::NotFound));
        };
        let mut network = KernelNetwork::new(network.clone());
        let mut runtime = KernelRuntimeCapability {
            runtime: self.runtime.clone(),
        };
        let status = match network.configure_dhcp(&mut runtime) {
            Ok(status) => status,
            Err(error) => {
                return Ok(ServiceReply::empty(application_network_status(error)));
            }
        };
        ServiceReply::with_payload(
            ReplyStatus::Success,
            &encode_application_network_status(status)?,
        )
    }
}

impl Service for ApplicationIcmpEchoService {
    fn call(&mut self, request: Request<'_>) -> Result<ServiceReply, troe_dispatch::DispatchError> {
        if request.opcode() != icmp_echo::ECHO {
            return Ok(ServiceReply::empty(ReplyStatus::InvalidRequest));
        }
        let Ok(destination) = icmp_echo::decode_request(request.payload()) else {
            return Ok(ServiceReply::empty(ReplyStatus::InvalidRequest));
        };
        let Some(network) = &self.network else {
            return Ok(ServiceReply::empty(ReplyStatus::NotFound));
        };
        let mut network = KernelNetwork::new(network.clone());
        let mut runtime = KernelRuntimeCapability {
            runtime: self.runtime.clone(),
        };
        let reply = match network.ping(destination, &mut runtime) {
            Ok(reply) => reply,
            Err(error) => {
                return Ok(ServiceReply::empty(application_network_status(error)));
            }
        };
        let reply = icmp_echo::Reply {
            source: reply.source,
            sequence: reply.sequence,
            bytes: u16::try_from(reply.bytes)
                .map_err(|_| troe_dispatch::DispatchError::AccountingOverflow)?,
        };
        ServiceReply::with_payload(ReplyStatus::Success, &icmp_echo::encode_reply(reply))
    }
}

impl ApplicationDatagramService {
    pub(crate) fn new(state: SharedApplicationDatagram, runtime: SharedRuntime) -> Self {
        Self { state, runtime }
    }
}

impl ApplicationDatagramState {
    pub(crate) fn new(network: SharedNetwork) -> Self {
        Self {
            network,
            ports: Vec::new(),
        }
    }

    pub(crate) fn claim_port(&mut self, requested: Option<u16>) -> Result<u16, ReplyStatus> {
        if let Some(port) = requested {
            if port == 0 {
                return Err(ReplyStatus::InvalidRequest);
            }
            if self.ports.contains(&port) {
                return Ok(port);
            }
            if self.ports.len() == troe_net::MAX_UDP_PORTS {
                return Err(ReplyStatus::Exhausted);
            }
            let mut network = self.network.borrow_mut();
            if network.udp.is_bound(port) {
                return Err(ReplyStatus::Conflict);
            }
            network
                .udp
                .bind(port)
                .map_err(map_network_error)
                .map_err(application_network_status)?;
            drop(network);
            if self.ports.try_reserve(1).is_err() {
                let _released = self.network.borrow_mut().udp.unbind(port);
                return Err(ReplyStatus::Exhausted);
            }
            self.ports.push(port);
            return Ok(port);
        }

        if self.ports.len() == troe_net::MAX_UDP_PORTS {
            return Err(ReplyStatus::Exhausted);
        }
        let mut network = self.network.borrow_mut();
        for _ in 0..troe_net::MAX_UDP_PORTS {
            let port = network.next_port;
            network.next_port = if port == u16::MAX { 49_152 } else { port + 1 };
            if !network.udp.is_bound(port) {
                network
                    .udp
                    .bind(port)
                    .map_err(map_network_error)
                    .map_err(application_network_status)?;
                drop(network);
                if self.ports.try_reserve(1).is_err() {
                    let _released = self.network.borrow_mut().udp.unbind(port);
                    return Err(ReplyStatus::Exhausted);
                }
                self.ports.push(port);
                return Ok(port);
            }
        }
        Err(ReplyStatus::Exhausted)
    }

    pub(crate) fn receive_now(
        &mut self,
        local_port: u16,
    ) -> Result<Option<ReceivedUdp>, ReplyStatus> {
        if self.network.borrow().configuration.is_none() {
            return Err(ReplyStatus::NotConfigured);
        }
        let datagram = self.network.borrow_mut().udp.receive(local_port);
        Ok(datagram.map(|datagram| ReceivedUdp {
            source: datagram.source_ip.bytes(),
            source_port: datagram.source_port,
            payload: datagram.payload,
        }))
    }
}

impl Service for ApplicationDatagramService {
    fn call(&mut self, request: Request<'_>) -> Result<ServiceReply, troe_dispatch::DispatchError> {
        match request.opcode() {
            datagram::SEND => {
                let Ok(send) = datagram::decode_send_request(request.payload()) else {
                    return Ok(ServiceReply::empty(ReplyStatus::InvalidRequest));
                };
                let requested = (send.source_port != 0).then_some(send.source_port);
                let source_port = match self.state.borrow_mut().claim_port(requested) {
                    Ok(port) => port,
                    Err(status) => return Ok(ServiceReply::empty(status)),
                };
                let mut network = KernelNetwork::new(self.state.borrow().network.clone());
                let mut runtime = KernelRuntimeCapability {
                    runtime: self.runtime.clone(),
                };
                if let Err(error) = network.send_udp(
                    Some(source_port),
                    send.destination,
                    send.destination_port,
                    send.payload,
                    &mut runtime,
                ) {
                    return Ok(ServiceReply::empty(application_network_status(error)));
                }
                let reply = datagram::encode_send_reply(source_port)
                    .map_err(|_| troe_dispatch::DispatchError::AccountingOverflow)?;
                ServiceReply::with_payload(ReplyStatus::Success, &reply)
            }
            datagram::RECEIVE => {
                let Ok(local_port) = datagram::decode_receive_request(request.payload()) else {
                    return Ok(ServiceReply::empty(ReplyStatus::InvalidRequest));
                };
                let local_port = match self.state.borrow_mut().claim_port(Some(local_port)) {
                    Ok(port) => port,
                    Err(status) => return Ok(ServiceReply::empty(status)),
                };
                let received = match self.state.borrow_mut().receive_now(local_port) {
                    Ok(Some(received)) => received,
                    Ok(None) => return Ok(ServiceReply::empty(ReplyStatus::Timeout)),
                    Err(status) => return Ok(ServiceReply::empty(status)),
                };
                let mut encoded = [0_u8; datagram::MAX_RECEIVE_REPLY_BYTES];
                let count = datagram::encode_receive_reply(
                    received.source,
                    received.source_port,
                    &received.payload,
                    &mut encoded,
                )
                .map_err(|_| troe_dispatch::DispatchError::AccountingOverflow)?;
                ServiceReply::with_payload(ReplyStatus::Success, &encoded[..count])
            }
            _ => Ok(ServiceReply::empty(ReplyStatus::InvalidRequest)),
        }
    }
}

impl Drop for ApplicationDatagramState {
    fn drop(&mut self) {
        let mut network = self.network.borrow_mut();
        for port in &self.ports {
            let _released = network.udp.unbind(*port);
        }
    }
}

impl ApplicationTcpConnectService {
    pub(crate) fn new(network: SharedNetwork, runtime: SharedRuntime) -> Self {
        Self {
            network,
            runtime,
            attempted: false,
            connection: None,
        }
    }

    fn connect(
        &mut self,
        destination: [u8; 4],
        destination_port: u16,
    ) -> Result<u16, NetworkError> {
        if self.attempted {
            return Err(NetworkError::Exhausted);
        }
        self.attempted = true;
        let deadline = tcp_deadline(&self.runtime);
        let configuration = self
            .network
            .borrow()
            .configuration
            .ok_or(NetworkError::NotConfigured)?;
        let destination = Ipv4Address::new(destination);
        let peer_mac = {
            let network = KernelNetwork::new(self.network.clone());
            let mut runtime = KernelRuntimeCapability {
                runtime: self.runtime.clone(),
            };
            network.resolve(destination, &mut runtime)?
        };
        let (local_port, initial_sequence) = {
            let mut network = self.network.borrow_mut();
            if network.tcp_connection_count() == troe_net::MAX_TCP_CONNECTIONS {
                return Err(NetworkError::Exhausted);
            }
            let local_port = network.select_ephemeral_tcp_port()?;
            let initial_sequence = network.next_tcp_initial_sequence();
            (local_port, initial_sequence)
        };
        let local =
            TcpEndpoint::new(configuration.address, local_port).map_err(map_network_error)?;
        let remote = TcpEndpoint::new(destination, destination_port).map_err(map_network_error)?;
        let machine =
            TcpConnection::connect(local, remote, initial_sequence).map_err(map_tcp_error)?;
        let connection = self
            .network
            .borrow_mut()
            .retain_tcp_connection(local_port, peer_mac, machine)?;
        self.connection = Some(connection);

        loop {
            let stream = self
                .connection
                .as_ref()
                .ok_or(NetworkError::Closed)?
                .clone();
            if let Err(error) = tcp_flush(&self.network, &self.runtime, &stream) {
                self.release();
                return Err(error);
            }
            let (established, closed) = {
                let machine = &stream.borrow().machine;
                (machine.is_established(), machine.is_closed())
            };
            if established {
                return Ok(local_port);
            }
            if closed {
                let error = stream
                    .borrow()
                    .machine
                    .terminal_error()
                    .map_or(NetworkError::Closed, map_tcp_error);
                self.release();
                return Err(error);
            }
            if self.runtime.borrow().now() >= deadline {
                self.release();
                return Err(NetworkError::Timeout);
            }
            if self.runtime.borrow_mut().checkpoint().is_err() {
                self.release();
                return Err(NetworkError::Cancelled);
            }
        }
    }

    fn write(&mut self, bytes: &[u8]) -> Result<(), NetworkError> {
        let stream = self
            .connection
            .as_ref()
            .ok_or(NetworkError::Closed)?
            .clone();
        tcp_write(&self.network, &self.runtime, &stream, bytes)
    }

    fn read(&mut self, destination: &mut [u8]) -> Result<usize, NetworkError> {
        let stream = self
            .connection
            .as_ref()
            .ok_or(NetworkError::Closed)?
            .clone();
        tcp_read(&self.network, &self.runtime, &stream, destination)
    }

    fn close(&mut self) -> Result<(), NetworkError> {
        let stream = self
            .connection
            .as_ref()
            .ok_or(NetworkError::Closed)?
            .clone();
        match tcp_close(&self.network, &self.runtime, &stream) {
            // The handle's connection slot is consumed, but the connection is
            // left in the frame path so its retained tuple still absorbs a
            // delayed peer FIN. The ambient drain reclaims it at expiry.
            Ok(()) => {
                self.connection = None;
                Ok(())
            }
            Err(error) => {
                self.release();
                Err(error)
            }
        }
    }

    fn release(&mut self) {
        let Some(connection) = self.connection.take() else {
            return;
        };
        let id = connection.borrow().id;
        self.network.borrow_mut().release_tcp_connection(id);
    }
}

impl Service for ApplicationTcpConnectService {
    fn call(&mut self, request: Request<'_>) -> Result<ServiceReply, troe_dispatch::DispatchError> {
        match request.opcode() {
            tcp_connect::CONNECT => {
                let Ok(connect) = tcp_connect::decode_connect_request(request.payload()) else {
                    return Ok(ServiceReply::empty(ReplyStatus::InvalidRequest));
                };
                let local_port = match self.connect(connect.destination, connect.destination_port) {
                    Ok(port) => port,
                    Err(error) => {
                        return Ok(ServiceReply::empty(application_network_status(error)));
                    }
                };
                let reply = tcp_connect::encode_connect_reply(local_port)
                    .map_err(|_| troe_dispatch::DispatchError::AccountingOverflow)?;
                ServiceReply::with_payload(ReplyStatus::Success, &reply)
            }
            tcp_connect::WRITE => {
                let Ok(bytes) = tcp_connect::decode_write_request(request.payload()) else {
                    return Ok(ServiceReply::empty(ReplyStatus::InvalidRequest));
                };
                match self.write(bytes) {
                    Ok(()) => Ok(ServiceReply::empty(ReplyStatus::Success)),
                    Err(error) => Ok(ServiceReply::empty(application_network_status(error))),
                }
            }
            tcp_connect::READ => {
                let Ok(requested) = tcp_connect::decode_read_request(request.payload()) else {
                    return Ok(ServiceReply::empty(ReplyStatus::InvalidRequest));
                };
                let mut bytes = [0_u8; tcp_connect::MAX_READ_BYTES];
                match self.read(&mut bytes[..requested]) {
                    Ok(count) => ServiceReply::with_payload(ReplyStatus::Success, &bytes[..count]),
                    Err(error) => Ok(ServiceReply::empty(application_network_status(error))),
                }
            }
            tcp_connect::CLOSE if request.payload().is_empty() => match self.close() {
                Ok(()) => Ok(ServiceReply::empty(ReplyStatus::Success)),
                Err(error) => Ok(ServiceReply::empty(application_network_status(error))),
            },
            _ => Ok(ServiceReply::empty(ReplyStatus::InvalidRequest)),
        }
    }
}

impl Drop for ApplicationTcpConnectService {
    fn drop(&mut self) {
        self.release();
    }
}

impl ApplicationTcpListenService {
    /// Streams one handle may hold accepted at once.
    ///
    /// Half the system-wide connection budget, so a saturated handle still
    /// leaves room for its own backlog and for an outbound client.
    const MAX_ACCEPTED: usize = 8;

    pub(crate) fn new(network: SharedNetwork, runtime: SharedRuntime) -> Self {
        Self {
            network,
            runtime,
            listener: None,
            accepted: Vec::new(),
            next_connection: 1,
        }
    }

    /// Claim this handle's one local endpoint and its bounded backlog.
    fn listen(&mut self, port: u16, backlog: u8) -> Result<u16, NetworkError> {
        if self.listener.is_some() {
            return Err(NetworkError::Exhausted);
        }
        let address = self
            .network
            .borrow()
            .configuration
            .ok_or(NetworkError::NotConfigured)?
            .address;
        let mut accepted = Vec::new();
        accepted
            .try_reserve_exact(Self::MAX_ACCEPTED)
            .map_err(|_| NetworkError::Exhausted)?;
        let local_port = {
            let mut network = self.network.borrow_mut();
            if port == 0 {
                network.select_ephemeral_tcp_port()?
            } else if network.tcp_port_claimed(port) {
                // A second owner cannot take an endpoint already claimed by a
                // listener or a live connection.
                return Err(NetworkError::Conflict);
            } else {
                port
            }
        };
        let local = TcpEndpoint::new(address, local_port).map_err(map_network_error)?;
        let listener = self
            .network
            .borrow_mut()
            .bind_tcp_listener(local, usize::from(backlog))?;
        self.listener = Some(listener);
        self.accepted = accepted;
        Ok(local_port)
    }

    /// Wait for one complete passive open and take ownership of its stream.
    fn accept(&mut self) -> Result<tcp_listen::AcceptReply, NetworkError> {
        let listener = self
            .listener
            .as_ref()
            .ok_or(NetworkError::NotFound)?
            .clone();
        if self.accepted.len() == Self::MAX_ACCEPTED {
            return Err(NetworkError::Exhausted);
        }
        let deadline = tcp_deadline(&self.runtime);
        loop {
            let now = self.runtime.borrow().now().as_millis();
            self.network.borrow_mut().flush_pending(now);
            let taken = listener.borrow_mut().listener.poll_accept();
            if let Some(machine) = taken {
                return self.retain_accepted(machine);
            }
            if self.runtime.borrow().now() >= deadline {
                return Err(NetworkError::Timeout);
            }
            self.runtime
                .borrow_mut()
                .checkpoint()
                .map_err(|_| NetworkError::Cancelled)?;
        }
    }

    /// Move one accepted connection into the frame path and name it.
    fn retain_accepted(
        &mut self,
        machine: troe_net::TcpConnection,
    ) -> Result<tcp_listen::AcceptReply, NetworkError> {
        let local_port = machine.local().port();
        let remote = machine.remote();
        let peer_mac = self
            .network
            .borrow()
            .peer_mac(remote.address())
            .ok_or(NetworkError::Protocol)?;
        let connection = self.next_connection;
        self.next_connection = self
            .next_connection
            .checked_add(1)
            .ok_or(NetworkError::Exhausted)?;
        let stream = self
            .network
            .borrow_mut()
            .retain_tcp_connection(local_port, peer_mac, machine)?;
        self.accepted.push(AcceptedStream { connection, stream });
        Ok(tcp_listen::AcceptReply {
            connection,
            peer: remote.address().bytes(),
            peer_port: remote.port(),
        })
    }

    /// Resolve one connection identifier this handle assigned.
    fn stream(&self, connection: u16) -> Result<SharedTcpConnection, NetworkError> {
        self.accepted
            .iter()
            .find(|entry| entry.connection == connection)
            .map(|entry| entry.stream.clone())
            .ok_or(NetworkError::NotFound)
    }

    fn write(&mut self, connection: u16, bytes: &[u8]) -> Result<(), NetworkError> {
        let stream = self.stream(connection)?;
        tcp_write(&self.network, &self.runtime, &stream, bytes)
    }

    fn read(&mut self, connection: u16, destination: &mut [u8]) -> Result<usize, NetworkError> {
        let stream = self.stream(connection)?;
        tcp_read(&self.network, &self.runtime, &stream, destination)
    }

    fn close(&mut self, connection: u16) -> Result<(), NetworkError> {
        let stream = self.stream(connection)?;
        let result = tcp_close(&self.network, &self.runtime, &stream);
        // The identifier is spent either way. On success the connection stays
        // in the frame path so its retained tuple absorbs a delayed peer FIN;
        // on failure it is removed immediately.
        self.accepted.retain(|entry| entry.connection != connection);
        if result.is_err() {
            let id = stream.borrow().id;
            self.network.borrow_mut().release_tcp_connection(id);
        }
        result
    }

    /// Abort every live stream and release the endpoint.
    fn release(&mut self) {
        for entry in self.accepted.drain(..) {
            let id = entry.stream.borrow().id;
            self.network.borrow_mut().release_tcp_connection(id);
        }
        if let Some(listener) = self.listener.take() {
            let id = listener.borrow().id;
            self.network.borrow_mut().release_tcp_listener(id);
        }
    }
}

impl Service for ApplicationTcpListenService {
    fn call(&mut self, request: Request<'_>) -> Result<ServiceReply, troe_dispatch::DispatchError> {
        match request.opcode() {
            tcp_listen::LISTEN => {
                let Ok(listen) = tcp_listen::decode_listen_request(request.payload()) else {
                    return Ok(ServiceReply::empty(ReplyStatus::InvalidRequest));
                };
                let port = match self.listen(listen.port, listen.backlog) {
                    Ok(port) => port,
                    Err(error) => {
                        return Ok(ServiceReply::empty(application_network_status(error)));
                    }
                };
                let reply = tcp_listen::encode_listen_reply(port)
                    .map_err(|_| troe_dispatch::DispatchError::AccountingOverflow)?;
                ServiceReply::with_payload(ReplyStatus::Success, &reply)
            }
            tcp_listen::ACCEPT if request.payload().is_empty() => {
                let accepted = match self.accept() {
                    Ok(accepted) => accepted,
                    Err(error) => {
                        return Ok(ServiceReply::empty(application_network_status(error)));
                    }
                };
                let reply = tcp_listen::encode_accept_reply(
                    accepted.connection,
                    accepted.peer,
                    accepted.peer_port,
                )
                .map_err(|_| troe_dispatch::DispatchError::AccountingOverflow)?;
                ServiceReply::with_payload(ReplyStatus::Success, &reply)
            }
            tcp_listen::WRITE => {
                let Ok(write) = tcp_listen::decode_write_request(request.payload()) else {
                    return Ok(ServiceReply::empty(ReplyStatus::InvalidRequest));
                };
                match self.write(write.connection, write.payload) {
                    Ok(()) => Ok(ServiceReply::empty(ReplyStatus::Success)),
                    Err(error) => Ok(ServiceReply::empty(application_network_status(error))),
                }
            }
            tcp_listen::READ => {
                let Ok(read) = tcp_listen::decode_read_request(request.payload()) else {
                    return Ok(ServiceReply::empty(ReplyStatus::InvalidRequest));
                };
                let mut bytes = [0_u8; tcp_listen::MAX_READ_BYTES];
                let destination = bytes
                    .get_mut(..read.requested)
                    .ok_or(troe_dispatch::DispatchError::AccountingOverflow)?;
                match self.read(read.connection, destination) {
                    Ok(count) => {
                        let payload = bytes
                            .get(..count)
                            .ok_or(troe_dispatch::DispatchError::AccountingOverflow)?;
                        ServiceReply::with_payload(ReplyStatus::Success, payload)
                    }
                    Err(error) => Ok(ServiceReply::empty(application_network_status(error))),
                }
            }
            tcp_listen::CLOSE => {
                let Ok(connection) = tcp_listen::decode_close_request(request.payload()) else {
                    return Ok(ServiceReply::empty(ReplyStatus::InvalidRequest));
                };
                match self.close(connection) {
                    Ok(()) => Ok(ServiceReply::empty(ReplyStatus::Success)),
                    Err(error) => Ok(ServiceReply::empty(application_network_status(error))),
                }
            }
            _ => Ok(ServiceReply::empty(ReplyStatus::InvalidRequest)),
        }
    }
}

impl Drop for ApplicationTcpListenService {
    fn drop(&mut self) {
        self.release();
    }
}
