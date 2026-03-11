use pnet::datalink::{self, Channel};
use pnet::packet::ethernet::{EtherTypes, EthernetPacket};
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::ipv4::Ipv4Packet;
use pnet::packet::ipv6::Ipv6Packet;
use pnet::packet::tcp::TcpPacket;
use pnet::packet::udp::UdpPacket;
use pnet::packet::Packet;
use crossbeam_channel::Sender;
use std::net::IpAddr;
use tls_parser::{parse_tls_plaintext, TlsMessage, TlsMessageHandshake, TlsExtension, SNIType};

use crate::app::PacketEvent;
use crate::ui::sanitize::sanitize_payload;

pub fn start_sniffing(tx: Sender<PacketEvent>, interface_name: &str, ready_tx: Sender<String>) {
    let interfaces = datalink::interfaces();
    
    let interface = interfaces.into_iter()
        .find(|iface| iface.name == interface_name)
        .or_else(|| {
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
    let mut sni = None;
    let mut proto_str = "Other";
    let mut sanitized = String::new();

    match protocol {
        IpNextHeaderProtocols::Tcp => {
            proto_str = "TCP";
            if let Some(tcp) = TcpPacket::new(payload) {
                let tcp_payload = tcp.payload();
                if tcp.get_destination() == 443 || tcp.get_source() == 443 {
                    sni = extract_sni(tcp_payload);
                }
                sanitized = sanitize_payload(tcp_payload);
            }
        }
        IpNextHeaderProtocols::Udp => {
            proto_str = "UDP";
            if let Some(udp) = UdpPacket::new(payload) {
                sanitized = sanitize_payload(udp.payload());
            }
        }
        IpNextHeaderProtocols::Icmp => {
            proto_str = "ICMP";
            sanitized = sanitize_payload(payload);
        }
        IpNextHeaderProtocols::Icmpv6 => {
            proto_str = "ICMPv6";
            sanitized = sanitize_payload(payload);
        }
        _ => {
            sanitized = sanitize_payload(payload);
        }
    };

    let event = PacketEvent {
        source,
        dest,
        protocol: proto_str.to_string(),
        bytes: payload.len(),
        sanitized_payload: if sanitized.is_empty() { None } else { Some(sanitized) },
        sni,
    };

    let _ = tx.send(event);
}

fn extract_sni(payload: &[u8]) -> Option<String> {
    if payload.is_empty() || payload[0] != 0x16 {
        return None;
    }
    if let Ok((_, record)) = parse_tls_plaintext(payload) {
        for msg in record.msg {
            if let TlsMessage::Handshake(TlsMessageHandshake::ClientHello(client_hello)) = msg {
                if let Some(extensions) = client_hello.ext {
                    if let Ok((_, extensions)) = tls_parser::parse_tls_extensions(extensions) {
                        for ext in extensions {
                            if let TlsExtension::SNI(sni_list) = ext {
                                for (sni_type, sni_data) in sni_list {
                                    if sni_type == SNIType::HostName {
                                        return String::from_utf8(sni_data.to_vec()).ok();
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    None
}
