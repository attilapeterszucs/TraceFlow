use pnet::datalink::{self, Channel, NetworkInterface};
use pnet::packet::ethernet::{EtherTypes, EthernetPacket};
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::ipv4::Ipv4Packet;
use pnet::packet::ipv6::Ipv6Packet;
use pnet::packet::tcp::TcpPacket;
use pnet::packet::udp::UdpPacket;
use pnet::packet::Packet;
use crossbeam_channel::Sender;
use std::net::IpAddr;

use crate::app::PacketEvent;
use crate::config;
use crate::ui::sanitize::sanitize_payload;

pub fn start_sniffing(tx: Sender<PacketEvent>, interface_name: &str, ready_tx: Sender<String>) {
    let interfaces = datalink::interfaces();
    
    // PRIORITY: User-specified interface, then physical interfaces (e... or w...), then any.
    let interface = interfaces.into_iter()
        .find(|iface| iface.name == interface_name)
        .or_else(|| {
            // Priority: Ethernet (e...) or Wifi (w...)
            datalink::interfaces().into_iter()
                .find(|e| e.is_up() && !e.is_loopback() && (e.name.starts_with('e') || e.name.starts_with('w')))
        })
        .unwrap_or_else(|| {
            panic!("Interface '{}' not found. Available: {:?}", 
                   interface_name, 
                   datalink::interfaces().into_iter().map(|i| i.name).collect::<Vec<_>>());
        });

    let actual_iface_name = interface.name.clone();

    let (_, mut rx) = match datalink::channel(&interface, Default::default()) {
        Ok(Channel::Ethernet(tx, rx)) => (tx, rx),
        Ok(_) => panic!("Unhandled channel type. Please use a standard Ethernet/WiFi interface."),
        Err(e) => panic!("An error occurred when creating the datalink channel: {}", e),
    };

    let _ = ready_tx.send(actual_iface_name);

    loop {
        match rx.next() {
            Ok(packet) => {
                if let Some(ethernet) = EthernetPacket::new(packet) {
                    handle_ethernet_packet(&ethernet, &tx);
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(e) => {
                eprintln!("Sniffer error: {}", e);
            }
        }
    }
}

fn handle_ethernet_packet(ethernet: &EthernetPacket, tx: &Sender<PacketEvent>) {
    match ethernet.get_ethertype() {
        EtherTypes::Ipv4 => {
            if let Some(header) = Ipv4Packet::new(ethernet.payload()) {
                handle_ipv4_packet(&header, tx);
            }
        }
        EtherTypes::Ipv6 => {
            if let Some(header) = Ipv6Packet::new(ethernet.payload()) {
                handle_ipv6_packet(&header, tx);
            }
        }
        _ => {}
    }
}

fn handle_ipv4_packet(header: &Ipv4Packet, tx: &Sender<PacketEvent>) {
    let source = IpAddr::V4(header.get_source());
    let dest = IpAddr::V4(header.get_destination());
    let payload = header.payload();

    process_transport_layer(
        header.get_next_level_protocol(),
        source,
        dest,
        payload,
        tx,
    );
}

fn handle_ipv6_packet(header: &Ipv6Packet, tx: &Sender<PacketEvent>) {
    let source = IpAddr::V6(header.get_source());
    let dest = IpAddr::V6(header.get_destination());
    let payload = header.payload();

    process_transport_layer(
        header.get_next_header(),
        source,
        dest,
        payload,
        tx,
    );
}

fn process_transport_layer(
    protocol: pnet::packet::ip::IpNextHeaderProtocol,
    source: IpAddr,
    dest: IpAddr,
    payload: &[u8],
    tx: &Sender<PacketEvent>,
) {
    let (proto_str, app_payload) = match protocol {
        IpNextHeaderProtocols::Tcp => {
            let mut pl = &[] as &[u8];
            if TcpPacket::new(payload).is_some() {
                pl = &payload[..];
            }
            ("TCP", pl)
        }
        IpNextHeaderProtocols::Udp => {
            let mut pl = &[] as &[u8];
            if UdpPacket::new(payload).is_some() {
                pl = &payload[..];
            }
            ("UDP", pl)
        }
        IpNextHeaderProtocols::Icmp => ("ICMP", payload),
        IpNextHeaderProtocols::Icmpv6 => ("ICMPv6", payload),
        _ => ("Other", payload),
    };

    let sanitized = sanitize_payload(app_payload);

    let event = PacketEvent {
        source,
        dest,
        protocol: proto_str.to_string(),
        bytes: payload.len(),
        sanitized_payload: if sanitized.is_empty() { None } else { Some(sanitized) },
    };

    let _ = tx.send(event);
}
