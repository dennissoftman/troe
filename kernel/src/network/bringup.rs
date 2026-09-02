//! Boot-time network bring-up and the acceptance reachability probe.
//!
//! Runs DHCP to completion and, under `acceptance-probes`, answers the
//! gateway's ARP so the acceptance harness can observe a reachable machine.
//!
//! ADR 0035 Phase D wants this out of the kernel with the rest of the stack.
//! Only the device handoff stays, in the `kernel/src/broker/packet.rs` ADR
//! 0035 names.

#[cfg(feature = "acceptance-probes")]
use troe_net::{
    Ipv4Address, MacAddress, NetworkDevice, build_arp_request, build_udp, parse_arp, parse_udp,
};

#[cfg(feature = "acceptance-probes")]
pub(crate) fn probe_native_network() -> Result<(), ()> {
    let mut network = troe_machine::discover_virtio_network()
        .map_err(|_| ())?
        .ok_or(())?;
    network.enable_interrupts().map_err(|_| ())?;
    let _initial_poll = troe_machine::take_network_interrupt();
    if !troe_machine::write(b"native network: device ready\n") {
        return Err(());
    }
    let guest_ip = Ipv4Address::new([10, 0, 2, 15]);
    let host_ip = Ipv4Address::new([10, 0, 2, 2]);
    let arp = build_arp_request(network.mac_address(), guest_ip, host_ip).map_err(|_| ())?;
    network.transmit(&arp).map_err(|_| ())?;
    if !troe_machine::write(b"native network: ARP request transmitted\n") {
        return Err(());
    }
    let gateway_mac = receive_gateway_arp(&mut network, guest_ip, host_ip)?;
    if !troe_machine::write(b"native network: ARP reply verified\n") {
        return Err(());
    }
    #[cfg(feature = "platform-x86_64-q35-uefi")]
    let host_port = 40_123;
    #[cfg(feature = "platform-aarch64-sbsa-ref")]
    let host_port = 40_124;
    #[cfg(feature = "platform-x86_64-uefi-virtio-pci")]
    let host_port = 40_125;
    #[cfg(feature = "platform-aarch64-uefi-virtio-mmio")]
    let host_port = 40_126;
    let request = build_udp(
        network.mac_address(),
        gateway_mac,
        guest_ip,
        host_ip,
        49_152,
        host_port,
        b"troe-stage8-request",
    )
    .map_err(|_| ())?;
    network.transmit(&request).map_err(|_| ())?;
    if !troe_machine::write(b"native network: UDP request transmitted\n") {
        return Err(());
    }
    for _ in 0..64 {
        let Some(frame) = network.receive().map_err(|_| ())? else {
            wait_for_network_completion();
            continue;
        };
        if frame.get(..6) != Some(&network.mac_address().bytes()) {
            continue;
        }
        let Ok(datagram) = parse_udp(&frame) else {
            continue;
        };
        if datagram.source_ip == host_ip
            && datagram.destination_ip == guest_ip
            && datagram.source_port == host_port
            && datagram.destination_port == 49_152
            && datagram.payload == b"troe-stage8-reply"
        {
            if !troe_machine::write(b"native network: UDP host exchange complete\n") {
                return Err(());
            }
            return Ok(());
        }
    }
    Err(())
}

#[cfg(feature = "acceptance-probes")]
pub(crate) fn receive_gateway_arp<D: NetworkDevice>(
    network: &mut D,
    guest_ip: Ipv4Address,
    host_ip: Ipv4Address,
) -> Result<MacAddress, ()> {
    let mut saw_frame = false;
    let mut saw_arp = false;
    for _ in 0..64 {
        let frame = match network.receive() {
            Ok(Some(frame)) => frame,
            Ok(None) => {
                wait_for_network_completion();
                continue;
            }
            Err(_) => {
                let _ignored = troe_machine::write(b"native network: RX completion invalid\n");
                return Err(());
            }
        };
        saw_frame = true;
        let Ok(arp) = parse_arp(&frame) else {
            continue;
        };
        saw_arp = true;
        if arp.operation == 2
            && arp.sender_ip == host_ip
            && arp.target_ip == guest_ip
            && arp.target_mac == network.mac_address().bytes()
        {
            return Ok(arp.sender_mac);
        }
    }
    if !saw_frame {
        let _ignored = troe_machine::write(b"native network: ARP RX timeout\n");
    } else if !saw_arp {
        let _ignored = troe_machine::write(b"native network: ARP frame rejected\n");
    } else {
        let _ignored = troe_machine::write(b"native network: ARP identity mismatch\n");
    }
    Err(())
}

#[cfg(feature = "acceptance-probes")]
pub(crate) fn wait_for_network_completion() {
    troe_machine::wait_for_runtime_event();
    let _completion = troe_machine::take_network_interrupt();
}
