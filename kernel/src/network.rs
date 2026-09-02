//! The kernel-resident network stack: link, address policy, and sockets.
//!
//! `KernelNetwork` owns the device, the ARP cache, the UDP port table, and the
//! TCP connections. `KernelNetworkService` is the DHCP and address-assignment
//! policy layered on top of it.
//!
//! ADR 0035 Phase D removes the network stack from the privileged address
//! space entirely. Everything in this module and its two children is that
//! removal's subject: the kernel holds raw device access, address assignment,
//! and per-connection state that a user-space network service should own. The
//! raw device access is the one part that stays, as the packet-device handle
//! of the `kernel/src/broker/packet.rs` ADR 0035 names.

pub(crate) mod bringup;
pub(crate) mod services;

use crate::handles::{SharedNetwork, SharedTcpConnection};
use alloc::collections::VecDeque;
use alloc::rc::Rc;
use alloc::string::String;
use alloc::vec::Vec;
use core::cell::RefCell;
use core::fmt::Write as _;
use troe_dispatch::ReplyStatus;
use troe_net::NetworkDevice;
use troe_net::{
    ArpCache, DhcpMessageType, DhcpPacket, Ipv4Address, MAX_UDP_PAYLOAD_BYTES, MacAddress,
    NetError, NetworkServiceStats, TcpConnection, TcpError, UdpAdmission, UdpPortTable,
    build_arp_reply, build_arp_request, build_dhcp_discover, build_dhcp_request, build_icmp_echo,
    build_udp, parse_arp, parse_dhcp, parse_icmp_echo, parse_tcp, parse_udp,
};
use troe_task::CooperativeRuntime;

#[derive(Clone, Copy)]
pub(crate) struct Ipv4Configuration {
    address: Ipv4Address,
    subnet_mask: Ipv4Address,
    gateway: Ipv4Address,
    lease_seconds: Option<u32>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum NetworkError {
    NotConfigured,
    Timeout,
    Device,
    Protocol,
    TooLarge,
    Exhausted,
    Cancelled,
    Closed,
}

#[derive(Clone, Copy)]
pub(crate) struct NetworkStatus {
    mac: [u8; 6],
    pub(crate) address: Option<[u8; 4]>,
    pub(crate) subnet_mask: Option<[u8; 4]>,
    gateway: Option<[u8; 4]>,
    lease_seconds: Option<u32>,
}

#[derive(Clone, Copy)]
pub(crate) struct PingReply {
    source: [u8; 4],
    sequence: u16,
    bytes: usize,
}

pub(crate) struct ReceivedUdp {
    pub(crate) source: [u8; 4],
    pub(crate) source_port: u16,
    pub(crate) payload: Vec<u8>,
}

pub(crate) struct KernelNetworkService {
    device: troe_machine::NativeVirtioNetwork,
    configuration: Option<Ipv4Configuration>,
    next_sequence: u16,
    next_port: u16,
    next_tcp_port: u16,
    next_tcp_id: u64,
    tcp_generation: u32,
    dhcp_generation: u16,
    arp: ArpCache,
    udp: UdpPortTable,
    dhcp_inbox: VecDeque<DhcpPacket>,
    echo_inbox: VecDeque<EchoReply>,
    tcp: Vec<SharedTcpConnection>,
    stats: NetworkServiceStats,
}

#[derive(Clone, Copy)]
pub(crate) struct EchoReply {
    source: Ipv4Address,
    identifier: u16,
    sequence: u16,
    bytes: usize,
}

pub(crate) struct KernelTcpConnection {
    id: u64,
    local_port: u16,
    peer_mac: MacAddress,
    machine: TcpConnection,
}

pub(crate) struct KernelNetwork {
    service: SharedNetwork,
}

impl core::fmt::Debug for KernelNetwork {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let service = self.service.borrow();
        formatter
            .debug_struct("KernelNetwork")
            .field("mac", &service.device.mac_address().bytes())
            .field("configured", &service.configuration.is_some())
            .finish_non_exhaustive()
    }
}

pub(crate) fn write_ipv4(output: &mut String, address: [u8; 4]) -> core::fmt::Result {
    write!(
        output,
        "{}.{}.{}.{}",
        address[0], address[1], address[2], address[3]
    )
}

pub(crate) fn subnet_prefix(mask: [u8; 4]) -> u32 {
    mask.into_iter().map(u8::count_ones).sum()
}

pub(crate) fn network_boot_label(status: NetworkStatus) -> String {
    let mut label = String::from("Configuring network");
    if let Some(address) = status.address {
        label.push_str(": ");
        let _formatted = write_ipv4(&mut label, address);
        if let Some(mask) = status.subnet_mask {
            let _formatted = write!(&mut label, "/{}", subnet_prefix(mask));
        }
    }
    label
}

impl KernelNetworkService {
    const POLL_BUDGET: usize = 8;
    const INBOX_CAPACITY: usize = 4;

    fn new(device: troe_machine::NativeVirtioNetwork) -> Result<Self, NetError> {
        let mut dhcp_inbox = VecDeque::new();
        dhcp_inbox
            .try_reserve_exact(Self::INBOX_CAPACITY)
            .map_err(|_| NetError::Exhausted)?;
        let mut echo_inbox = VecDeque::new();
        echo_inbox
            .try_reserve_exact(Self::INBOX_CAPACITY)
            .map_err(|_| NetError::Exhausted)?;
        let mut tcp = Vec::new();
        tcp.try_reserve_exact(troe_net::MAX_TCP_CONNECTIONS)
            .map_err(|_| NetError::Exhausted)?;
        Ok(Self {
            device,
            configuration: None,
            next_sequence: 1,
            next_port: 49_152,
            next_tcp_port: 49_152,
            next_tcp_id: 1,
            tcp_generation: 0,
            dhcp_generation: 0,
            arp: ArpCache::new(),
            udp: UdpPortTable::new()?,
            dhcp_inbox,
            echo_inbox,
            tcp,
            stats: NetworkServiceStats::default(),
        })
    }

    fn shell_status(&self) -> NetworkStatus {
        NetworkStatus {
            mac: self.device.mac_address().bytes(),
            address: self.configuration.map(|value| value.address.bytes()),
            subnet_mask: self.configuration.map(|value| value.subnet_mask.bytes()),
            gateway: self.configuration.map(|value| value.gateway.bytes()),
            lease_seconds: self.configuration.and_then(|value| value.lease_seconds),
        }
    }

    fn next_dhcp_transaction(&mut self) -> u32 {
        self.dhcp_generation = self.dhcp_generation.wrapping_add(1);
        let mac = self.device.mac_address().bytes();
        u32::from_be_bytes([mac[2], mac[3], mac[4], mac[5]])
            ^ u32::from(self.dhcp_generation)
            ^ 0x5452_4f45
    }

    fn transmit(&mut self, frame: &[u8]) -> Result<(), NetworkError> {
        match self.device.transmit(frame) {
            Ok(()) => {
                self.stats.transmitted_frames = self.stats.transmitted_frames.saturating_add(1);
                Ok(())
            }
            Err(error) => {
                self.stats.errors = self.stats.errors.saturating_add(1);
                Err(map_network_error(error))
            }
        }
    }

    pub(crate) fn poll(&mut self) -> Result<(), NetworkError> {
        self.stats.checkpoints = self.stats.checkpoints.saturating_add(1);
        for _ in 0..Self::POLL_BUDGET {
            let frame = match self.device.receive() {
                Ok(Some(frame)) => frame,
                Ok(None) => break,
                Err(error) => {
                    self.stats.errors = self.stats.errors.saturating_add(1);
                    return Err(map_network_error(error));
                }
            };
            self.stats.received_frames = self.stats.received_frames.saturating_add(1);
            if self.handle_frame(&frame).is_err() {
                self.stats.errors = self.stats.errors.saturating_add(1);
            }
        }
        Ok(())
    }

    #[allow(clippy::too_many_lines)]
    fn handle_frame(&mut self, frame: &[u8]) -> Result<(), NetworkError> {
        if let Ok(packet) = parse_dhcp(frame) {
            if self.dhcp_inbox.len() < Self::INBOX_CAPACITY {
                self.dhcp_inbox.push_back(packet);
            }
            return Ok(());
        }
        if let Ok(arp) = parse_arp(frame) {
            self.arp
                .learn(arp.sender_ip, arp.sender_mac)
                .map_err(map_network_error)?;
            let Some(configuration) = self.configuration else {
                return Ok(());
            };
            if arp.operation == 1 && arp.target_ip == configuration.address {
                let reply = build_arp_reply(
                    self.device.mac_address(),
                    configuration.address,
                    arp.sender_mac,
                    arp.sender_ip,
                )
                .map_err(map_network_error)?;
                self.transmit(&reply)?;
                self.stats.arp_replies = self.stats.arp_replies.saturating_add(1);
            }
            return Ok(());
        }
        let Some(configuration) = self.configuration else {
            self.stats.ignored_frames = self.stats.ignored_frames.saturating_add(1);
            return Ok(());
        };
        if let Ok(echo) = parse_icmp_echo(frame)
            && echo.destination_ip == configuration.address
        {
            self.arp
                .learn(echo.source_ip, echo.source_mac)
                .map_err(map_network_error)?;
            if echo.kind == 8 {
                let reply = build_icmp_echo(
                    self.device.mac_address(),
                    echo.source_mac,
                    configuration.address,
                    echo.source_ip,
                    0,
                    echo.identifier,
                    echo.sequence,
                    echo.payload,
                )
                .map_err(map_network_error)?;
                self.transmit(&reply)?;
                self.stats.icmp_replies = self.stats.icmp_replies.saturating_add(1);
            } else if echo.kind == 0 && self.echo_inbox.len() < Self::INBOX_CAPACITY {
                self.echo_inbox.push_back(EchoReply {
                    source: echo.source_ip,
                    identifier: echo.identifier,
                    sequence: echo.sequence,
                    bytes: echo.payload.len(),
                });
            }
            return Ok(());
        }
        if let Ok(segment) = parse_tcp(frame)
            && segment.destination.address() == configuration.address
        {
            let source_mac = MacAddress::new(
                frame
                    .get(6..12)
                    .and_then(|bytes| bytes.try_into().ok())
                    .ok_or(NetworkError::Protocol)?,
            )
            .map_err(map_network_error)?;
            self.arp
                .learn(segment.source.address(), source_mac)
                .map_err(map_network_error)?;
            if let Some(connection) = self
                .tcp
                .iter()
                .find(|connection| connection.borrow().machine.accepts(segment))
            {
                let _admission = connection.borrow_mut().machine.on_segment(segment);
            } else {
                self.stats.ignored_frames = self.stats.ignored_frames.saturating_add(1);
            }
            return Ok(());
        }
        if let Ok(datagram) = parse_udp(frame)
            && datagram.destination_ip == configuration.address
        {
            self.arp
                .learn(datagram.source_ip, datagram.source_mac)
                .map_err(map_network_error)?;
            match self.udp.admit(datagram).map_err(map_network_error)? {
                UdpAdmission::Retained => {
                    self.stats.udp_retained = self.stats.udp_retained.saturating_add(1);
                }
                UdpAdmission::Unbound => {
                    self.stats.udp_unbound = self.stats.udp_unbound.saturating_add(1);
                }
                UdpAdmission::Dropped => {
                    self.stats.udp_dropped = self.stats.udp_dropped.saturating_add(1);
                }
            }
            return Ok(());
        }
        self.stats.ignored_frames = self.stats.ignored_frames.saturating_add(1);
        Ok(())
    }

    fn take_dhcp(&mut self, transaction_id: u32) -> Option<DhcpPacket> {
        let index = self.dhcp_inbox.iter().position(|packet| {
            packet.transaction_id == transaction_id
                && packet.client_mac == self.device.mac_address()
        })?;
        self.dhcp_inbox.remove(index)
    }

    fn take_echo(&mut self, identifier: u16, sequence: u16) -> Option<EchoReply> {
        let index = self
            .echo_inbox
            .iter()
            .position(|reply| reply.identifier == identifier && reply.sequence == sequence)?;
        self.echo_inbox.remove(index)
    }
}

impl KernelNetwork {
    const WAIT_MILLISECONDS: u64 = 2_000;

    pub(crate) fn new(service: SharedNetwork) -> Self {
        Self { service }
    }

    pub(crate) fn configure_dhcp(
        &mut self,
        runtime: &mut dyn CooperativeRuntime,
    ) -> Result<NetworkStatus, NetworkError> {
        let (transaction_id, mac) = {
            let mut service = self.service.borrow_mut();
            (
                service.next_dhcp_transaction(),
                service.device.mac_address(),
            )
        };
        let discover = build_dhcp_discover(mac, transaction_id).map_err(map_network_error)?;
        self.service.borrow_mut().transmit(&discover)?;
        let offer = self.wait_for_dhcp(transaction_id, DhcpMessageType::Offer, runtime)?;
        let server = offer.server_identifier.ok_or(NetworkError::Protocol)?;
        let request = build_dhcp_request(mac, transaction_id, offer.your_ip, server)
            .map_err(map_network_error)?;
        self.service.borrow_mut().transmit(&request)?;
        let acknowledgement =
            self.wait_for_dhcp(transaction_id, DhcpMessageType::Acknowledge, runtime)?;
        let subnet_mask = acknowledgement
            .subnet_mask
            .or(offer.subnet_mask)
            .ok_or(NetworkError::Protocol)?;
        let gateway = acknowledgement
            .router
            .or(offer.router)
            .ok_or(NetworkError::Protocol)?;
        let address = acknowledgement.your_ip;
        if address.bytes() == [0; 4] {
            return Err(NetworkError::Protocol);
        }
        let mut service = self.service.borrow_mut();
        service.configuration = Some(Ipv4Configuration {
            address,
            subnet_mask,
            gateway,
            lease_seconds: acknowledgement.lease_seconds.or(offer.lease_seconds),
        });
        Ok(service.shell_status())
    }

    fn wait_for_dhcp(
        &self,
        transaction_id: u32,
        wanted: DhcpMessageType,
        runtime: &mut dyn CooperativeRuntime,
    ) -> Result<DhcpPacket, NetworkError> {
        let deadline = runtime.now().saturating_add(Self::WAIT_MILLISECONDS);
        while runtime.now() < deadline {
            runtime.checkpoint().map_err(|_| NetworkError::Cancelled)?;
            if let Some(packet) = self.service.borrow_mut().take_dhcp(transaction_id) {
                if packet.message_type == DhcpMessageType::NegativeAcknowledge {
                    return Err(NetworkError::Protocol);
                }
                if packet.message_type == wanted {
                    return Ok(packet);
                }
            }
        }
        Err(NetworkError::Timeout)
    }

    fn resolve(
        &self,
        destination: Ipv4Address,
        runtime: &mut dyn CooperativeRuntime,
    ) -> Result<MacAddress, NetworkError> {
        let (next_hop, request) = {
            let service = self.service.borrow();
            let configuration = service.configuration.ok_or(NetworkError::NotConfigured)?;
            let next_hop = if same_subnet(
                configuration.address,
                destination,
                configuration.subnet_mask,
            ) {
                destination
            } else {
                configuration.gateway
            };
            if let Some(mac) = service.arp.lookup(next_hop) {
                return Ok(mac);
            }
            let request = build_arp_request(
                service.device.mac_address(),
                configuration.address,
                next_hop,
            )
            .map_err(map_network_error)?;
            (next_hop, request)
        };
        self.service.borrow_mut().transmit(&request)?;
        let deadline = runtime.now().saturating_add(Self::WAIT_MILLISECONDS);
        while runtime.now() < deadline {
            runtime.checkpoint().map_err(|_| NetworkError::Cancelled)?;
            if let Some(mac) = self.service.borrow().arp.lookup(next_hop) {
                return Ok(mac);
            }
        }
        Err(NetworkError::Timeout)
    }
}

impl KernelNetwork {
    fn ping(
        &mut self,
        destination: [u8; 4],
        runtime: &mut dyn CooperativeRuntime,
    ) -> Result<PingReply, NetworkError> {
        let configuration = self
            .service
            .borrow()
            .configuration
            .ok_or(NetworkError::NotConfigured)?;
        let destination = Ipv4Address::new(destination);
        if destination == configuration.address {
            let mut service = self.service.borrow_mut();
            let sequence = service.next_sequence;
            service.next_sequence = service.next_sequence.wrapping_add(1);
            return Ok(PingReply {
                source: destination.bytes(),
                sequence,
                bytes: 9,
            });
        }
        let destination_mac = self.resolve(destination, runtime)?;
        let (source_mac, sequence) = {
            let mut service = self.service.borrow_mut();
            let sequence = service.next_sequence;
            service.next_sequence = service.next_sequence.wrapping_add(1);
            (service.device.mac_address(), sequence)
        };
        let request = build_icmp_echo(
            source_mac,
            destination_mac,
            configuration.address,
            destination,
            8,
            0x5452,
            sequence,
            b"troe-ping",
        )
        .map_err(map_network_error)?;
        self.service.borrow_mut().transmit(&request)?;
        let deadline = runtime.now().saturating_add(Self::WAIT_MILLISECONDS);
        while runtime.now() < deadline {
            runtime.checkpoint().map_err(|_| NetworkError::Cancelled)?;
            if let Some(echo) = self.service.borrow_mut().take_echo(0x5452, sequence)
                && echo.source == destination
            {
                return Ok(PingReply {
                    source: echo.source.bytes(),
                    sequence,
                    bytes: echo.bytes,
                });
            }
        }
        Err(NetworkError::Timeout)
    }

    fn send_udp(
        &mut self,
        source_port: Option<u16>,
        destination: [u8; 4],
        destination_port: u16,
        payload: &[u8],
        runtime: &mut dyn CooperativeRuntime,
    ) -> Result<u16, NetworkError> {
        if payload.len() > MAX_UDP_PAYLOAD_BYTES {
            return Err(NetworkError::TooLarge);
        }
        let configuration = self
            .service
            .borrow()
            .configuration
            .ok_or(NetworkError::NotConfigured)?;
        let destination = Ipv4Address::new(destination);
        let destination_mac = self.resolve(destination, runtime)?;
        let source_port = if let Some(port) = source_port {
            self.service
                .borrow_mut()
                .udp
                .bind(port)
                .map_err(map_network_error)?;
            port
        } else {
            let mut service = self.service.borrow_mut();
            let mut selected = None;
            for _ in 0..troe_net::MAX_UDP_PORTS {
                let port = service.next_port;
                service.next_port = if port == u16::MAX { 49_152 } else { port + 1 };
                if !service.udp.is_bound(port) {
                    service.udp.bind(port).map_err(map_network_error)?;
                    selected = Some(port);
                    break;
                }
            }
            selected.ok_or(NetworkError::Exhausted)?
        };
        let source_mac = self.service.borrow().device.mac_address();
        let datagram = build_udp(
            source_mac,
            destination_mac,
            configuration.address,
            destination,
            source_port,
            destination_port,
            payload,
        )
        .map_err(map_network_error)?;
        self.service.borrow_mut().transmit(&datagram)?;
        Ok(source_port)
    }
}

pub(crate) const fn application_network_status(error: NetworkError) -> ReplyStatus {
    match error {
        NetworkError::NotConfigured => ReplyStatus::NotConfigured,
        NetworkError::Timeout => ReplyStatus::Timeout,
        NetworkError::TooLarge => ReplyStatus::TooLarge,
        NetworkError::Exhausted => ReplyStatus::Exhausted,
        NetworkError::Cancelled => ReplyStatus::Cancelled,
        NetworkError::Closed | NetworkError::Device => ReplyStatus::Failure,
        NetworkError::Protocol => ReplyStatus::NetworkProtocol,
    }
}

pub(crate) const fn map_tcp_error(error: TcpError) -> NetworkError {
    match error {
        TcpError::Invalid => NetworkError::Protocol,
        TcpError::Busy | TcpError::WindowClosed | TcpError::Exhausted => NetworkError::Exhausted,
        TcpError::Timeout => NetworkError::Timeout,
        TcpError::Reset | TcpError::Closed => NetworkError::Closed,
    }
}

pub(crate) fn same_subnet(left: Ipv4Address, right: Ipv4Address, mask: Ipv4Address) -> bool {
    left.bytes()
        .iter()
        .zip(right.bytes())
        .zip(mask.bytes())
        .all(|((left, right), mask)| *left & mask == right & mask)
}

pub(crate) const fn map_network_error(error: NetError) -> NetworkError {
    match error {
        NetError::Invalid | NetError::Truncated | NetError::Checksum | NetError::Unsupported => {
            NetworkError::Protocol
        }
        NetError::Exhausted => NetworkError::Exhausted,
        NetError::Device => NetworkError::Device,
        NetError::Timeout => NetworkError::Timeout,
    }
}

pub(crate) fn discover_network_service() -> Option<SharedNetwork> {
    let mut device = troe_machine::discover_virtio_network().ok().flatten()?;
    device.enable_interrupts().ok()?;
    let service = KernelNetworkService::new(device).ok()?;
    Some(Rc::new(RefCell::new(service)))
}
