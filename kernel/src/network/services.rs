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
    SharedApplicationDatagram, SharedNetwork, SharedRuntime, SharedTcpConnection,
};
use crate::network::{
    KernelNetwork, KernelTcpConnection, NetworkError, NetworkStatus, ReceivedUdp,
    application_network_status, map_network_error, map_tcp_error,
};
use crate::runtime::KernelRuntimeCapability;
use alloc::rc::Rc;
use alloc::vec::Vec;
use core::cell::RefCell;
use troe_abi::{datagram, icmp_echo, network_configuration, network_observation, tcp_connect};
use troe_dispatch::{ReplyStatus, Request, Service, ServiceReply};
use troe_net::NetworkDevice;
use troe_net::{Ipv4Address, TcpConnection, TcpEndpoint, TcpSegment, build_tcp};
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
    const OPERATION_MILLISECONDS: u64 = 4_000;
    const FLUSH_BUDGET: usize = 2;

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
        let started = self.runtime.borrow().now();
        let deadline = started.saturating_add(Self::OPERATION_MILLISECONDS);
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
        let now = self.runtime.borrow().now().as_millis();
        let (id, local_port, initial_sequence) = {
            let mut network = self.network.borrow_mut();
            if network.tcp.len() == troe_net::MAX_TCP_CONNECTIONS {
                return Err(NetworkError::Exhausted);
            }
            let mut selected = None;
            for _ in 0..=troe_net::MAX_TCP_CONNECTIONS {
                let port = network.next_tcp_port;
                network.next_tcp_port = if port == u16::MAX { 49_152 } else { port + 1 };
                if !network
                    .tcp
                    .iter()
                    .any(|connection| connection.borrow().local_port == port)
                {
                    selected = Some(port);
                    break;
                }
            }
            let local_port = selected.ok_or(NetworkError::Exhausted)?;
            let id = network.next_tcp_id;
            network.next_tcp_id = network
                .next_tcp_id
                .checked_add(1)
                .ok_or(NetworkError::Exhausted)?;
            network.tcp_generation = network.tcp_generation.wrapping_add(1);
            let mac = network.device.mac_address().bytes();
            let mac_word = u32::from_be_bytes([mac[2], mac[3], mac[4], mac[5]]);
            let initial_sequence = u32::try_from(now & u64::from(u32::MAX)).unwrap_or(u32::MAX)
                ^ u32::try_from(now >> 32).unwrap_or(u32::MAX).rotate_left(7)
                ^ mac_word.rotate_left(13)
                ^ network.tcp_generation.wrapping_mul(0x9e37_79b9);
            (id, local_port, initial_sequence)
        };
        let local =
            TcpEndpoint::new(configuration.address, local_port).map_err(map_network_error)?;
        let remote = TcpEndpoint::new(destination, destination_port).map_err(map_network_error)?;
        let machine =
            TcpConnection::connect(local, remote, initial_sequence).map_err(map_tcp_error)?;
        let connection = Rc::new(RefCell::new(KernelTcpConnection {
            id,
            local_port,
            peer_mac,
            machine,
        }));
        self.network.borrow_mut().tcp.push(connection.clone());
        self.connection = Some(connection);

        loop {
            if let Err(error) = self.flush() {
                self.release();
                return Err(error);
            }
            let state = self.connection_state()?;
            if state.0 {
                return Ok(local_port);
            }
            if state.1 {
                let error = self.connection_error().unwrap_or(NetworkError::Closed);
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
        let deadline = self
            .runtime
            .borrow()
            .now()
            .saturating_add(Self::OPERATION_MILLISECONDS);
        let mut offset = 0;
        while offset < bytes.len() {
            let capacity = {
                let connection = self.connection.as_ref().ok_or(NetworkError::Closed)?;
                let connection = connection.borrow();
                if !connection.machine.is_established() {
                    return Err(connection
                        .machine
                        .terminal_error()
                        .map_or(NetworkError::Closed, map_tcp_error));
                }
                connection.machine.send_capacity()
            };
            if capacity == 0 {
                self.wait_checkpoint(deadline)?;
                continue;
            }
            let count = capacity.min(bytes.len() - offset);
            self.connection
                .as_ref()
                .ok_or(NetworkError::Closed)?
                .borrow_mut()
                .machine
                .begin_send(&bytes[offset..offset + count])
                .map_err(map_tcp_error)?;
            loop {
                self.flush()?;
                let complete = self
                    .connection
                    .as_ref()
                    .ok_or(NetworkError::Closed)?
                    .borrow()
                    .machine
                    .send_complete()
                    .map_err(map_tcp_error)?;
                if complete {
                    break;
                }
                self.wait_checkpoint(deadline)?;
            }
            offset += count;
        }
        Ok(())
    }

    fn read(&mut self, destination: &mut [u8]) -> Result<usize, NetworkError> {
        let deadline = self
            .runtime
            .borrow()
            .now()
            .saturating_add(Self::OPERATION_MILLISECONDS);
        loop {
            let read = self
                .connection
                .as_ref()
                .ok_or(NetworkError::Closed)?
                .borrow_mut()
                .machine
                .read(destination)
                .map_err(map_tcp_error)?;
            if let Some(count) = read {
                self.flush()?;
                return Ok(count);
            }
            self.wait_checkpoint(deadline)?;
        }
    }

    fn close(&mut self) -> Result<(), NetworkError> {
        let deadline = self
            .runtime
            .borrow()
            .now()
            .saturating_add(Self::OPERATION_MILLISECONDS);
        let begin = {
            let connection = self.connection.as_ref().ok_or(NetworkError::Closed)?;
            let mut connection = connection.borrow_mut();
            if connection.machine.is_closed() {
                connection
                    .machine
                    .terminal_error()
                    .map_or(Ok(()), |error| Err(map_tcp_error(error)))
            } else {
                connection.machine.begin_close().map_err(map_tcp_error)
            }
        };
        if let Err(error) = begin {
            self.release();
            return Err(error);
        }
        loop {
            if let Err(error) = self.flush() {
                self.release();
                return Err(error);
            }
            let closed = self
                .connection
                .as_ref()
                .is_none_or(|connection| connection.borrow().machine.is_closed());
            if closed {
                self.release();
                return Ok(());
            }
            if let Err(error) = self.wait_checkpoint(deadline) {
                self.release();
                return Err(error);
            }
        }
    }

    fn wait_checkpoint(&mut self, deadline: MonotonicMillis) -> Result<(), NetworkError> {
        if self.runtime.borrow().now() >= deadline {
            return Err(NetworkError::Timeout);
        }
        self.runtime
            .borrow_mut()
            .checkpoint()
            .map_err(|_| NetworkError::Cancelled)?;
        self.flush()
    }

    fn flush(&mut self) -> Result<(), NetworkError> {
        for _ in 0..Self::FLUSH_BUDGET {
            let now = self.runtime.borrow().now().as_millis();
            let frame = {
                let connection = self.connection.as_ref().ok_or(NetworkError::Closed)?;
                let mut connection = connection.borrow_mut();
                let peer_mac = connection.peer_mac;
                let Some(emission) = connection
                    .machine
                    .poll_emission(now)
                    .map_err(map_tcp_error)?
                else {
                    break;
                };
                let source_mac = self.network.borrow().device.mac_address();
                build_tcp(
                    source_mac,
                    peer_mac,
                    TcpSegment {
                        source: emission.source,
                        destination: emission.destination,
                        sequence: emission.sequence,
                        acknowledgement: emission.acknowledgement,
                        flags: emission.flags,
                        window: emission.window,
                        payload: emission.payload,
                    },
                )
                .map_err(map_network_error)?
            };
            self.network.borrow_mut().transmit(&frame)?;
        }
        Ok(())
    }

    fn connection_state(&self) -> Result<(bool, bool), NetworkError> {
        let connection = self.connection.as_ref().ok_or(NetworkError::Closed)?;
        let machine = &connection.borrow().machine;
        Ok((machine.is_established(), machine.is_closed()))
    }

    fn connection_error(&self) -> Option<NetworkError> {
        self.connection
            .as_ref()
            .and_then(|connection| connection.borrow().machine.terminal_error())
            .map(map_tcp_error)
    }

    fn release(&mut self) {
        let Some(connection) = self.connection.take() else {
            return;
        };
        let id = connection.borrow().id;
        self.network
            .borrow_mut()
            .tcp
            .retain(|candidate| candidate.borrow().id != id);
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
