use pnet::datalink::{self, Channel};
use pnet::packet::ethernet::{EtherTypes, EthernetPacket};
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::ipv4::Ipv4Packet;
use pnet::packet::ipv6::Ipv6Packet;
use pnet::packet::tcp::TcpPacket;
use pnet::packet::Packet;
use crossbeam_channel::{Sender, Receiver, unbounded};
use std::net::IpAddr;
use std::thread;
use tls_parser::{parse_tls_plaintext, TlsMessage, TlsMessageHandshake, TlsExtension, SNIType};

use crate::app::PacketEvent;

pub struct SnifferManager {
    command_tx: Sender<SnifferCommand>,
}

pub enum SnifferCommand {
    SwitchInterface(String),
}

impl SnifferManager {
    pub fn new(event_tx: Sender<crate::app::AppEvent>, initial_interface: String, ready_tx: Sender<String>) -> Self {
        let (command_tx, command_rx) = unbounded();
        
        thread::spawn(move || {
            sniffer_worker(command_rx, event_tx, initial_interface, ready_tx);
        });

        Self { command_tx }
    }

    pub fn switch_interface(&self, name: String) {
        let _ = self.command_tx.send(SnifferCommand::SwitchInterface(name));
    }
}

fn sniffer_worker(
    command_rx: Receiver<SnifferCommand>,
    event_tx: Sender<crate::app::AppEvent>,
    mut current_interface: String,
    ready_tx: Sender<String>,
) {
    let mut current_channel_rx = None;
    let mut first_run = true;

    loop {
        // 1. Check for commands (switch interface) or wait if we don't have a channel
        let timeout = if current_channel_rx.is_none() {
            std::time::Duration::from_millis(100)
        } else {
            std::time::Duration::from_millis(0)
        };

        if let Ok(cmd) = command_rx.recv_timeout(timeout) {
            match cmd {
                SnifferCommand::SwitchInterface(name) => {
                    current_interface = name;
                    current_channel_rx = None; // Reset to force rebuild
                }
            }
        }

        // 2. Setup channel if needed
        if current_channel_rx.is_none() {
            let interfaces = datalink::interfaces();
            let interface = interfaces.into_iter()
                .find(|iface| iface.name == current_interface)
                .or_else(|| {
                    datalink::interfaces().into_iter()
                        .find(|e| e.is_up() && !e.is_loopback() && (e.name.starts_with('e') || e.name.starts_with('w')))
                });

            if let Some(iface) = interface {
                let actual_name = iface.name.clone();
                let mut config = datalink::Config::default();
                config.read_timeout = Some(std::time::Duration::from_millis(100));
                
                match datalink::channel(&iface, config) {
                    Ok(Channel::Ethernet(_, rx)) => {
                        current_channel_rx = Some(rx);
                        if first_run {
                            let _ = ready_tx.send(actual_name);
                            first_run = false;
                        } else {
                            let _ = event_tx.send(crate::app::AppEvent::SwitchInterface(actual_name));
                        }
                    }
                    _ => {
                        eprintln!("Failed to open channel on {}", actual_name);
                        std::thread::sleep(std::time::Duration::from_secs(1));
                    }
                }
            }
        }

        // 3. Sniff packet
        if let Some(ref mut rx) = current_channel_rx {
            match rx.next() {
                Ok(packet) => {
                    if let Some(ethernet) = EthernetPacket::new(packet) {
                        handle_ethernet_packet(&ethernet, &event_tx);
                    }
                }
                Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
                Err(e) if e.kind() == std::io::ErrorKind::TimedOut => continue,
                Err(e) => {
                    eprintln!("Sniffer error: {}. Attempting to recover...", e);
                    current_channel_rx = None;
                    std::thread::sleep(std::time::Duration::from_secs(1));
                }
            }
        }
    }
}

fn handle_ethernet_packet(ethernet: &EthernetPacket, tx: &Sender<crate::app::AppEvent>) {
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

fn handle_ipv4_packet(header: &Ipv4Packet, tx: &Sender<crate::app::AppEvent>) {
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

fn handle_ipv6_packet(header: &Ipv6Packet, tx: &Sender<crate::app::AppEvent>) {
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
    tx: &Sender<crate::app::AppEvent>,
) {
    let mut sni = None;
    let mut proto_str = "Other";

    match protocol {
        IpNextHeaderProtocols::Tcp => {
            proto_str = "TCP";
            if let Some(tcp) = TcpPacket::new(payload) {
                let tcp_payload = tcp.payload();
                if tcp.get_destination() == 443 || tcp.get_source() == 443 {
                    sni = extract_sni(tcp_payload);
                }
            }
        }
        IpNextHeaderProtocols::Udp => {
            proto_str = "UDP";
        }
        IpNextHeaderProtocols::Icmp => proto_str = "ICMP",
        IpNextHeaderProtocols::Icmpv6 => proto_str = "ICMPv6",
        _ => {}
    };

    let event = PacketEvent {
        source,
        dest,
        protocol: proto_str.to_string(),
        bytes: payload.len(),
        sni,
    };

    let _ = tx.send(crate::app::AppEvent::Packet(event));
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
