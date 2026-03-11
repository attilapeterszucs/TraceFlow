use pcap::{Capture, Device, Active};
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

use crate::app::{AppEvent, PacketEvent, TrafficDirection};

pub struct SnifferManager {
    command_tx: Sender<SnifferCommand>,
}

pub enum SnifferCommand {
    SwitchInterface(String),
    UpdateFilter(String),
    SavePcap(String),
}

impl SnifferManager {
    pub fn new(event_tx: Sender<AppEvent>, initial_interface: String, ready_tx: Sender<String>) -> Self {
        let (command_tx, command_rx) = unbounded();
        
        thread::spawn(move || {
            sniffer_worker(command_rx, event_tx, initial_interface, ready_tx);
        });

        Self { command_tx }
    }

    pub fn switch_interface(&self, name: String) {
        let _ = self.command_tx.send(SnifferCommand::SwitchInterface(name));
    }

    pub fn update_filter(&self, filter: String) {
        let _ = self.command_tx.send(SnifferCommand::UpdateFilter(filter));
    }

    pub fn save_pcap(&self, filename: String) {
        let _ = self.command_tx.send(SnifferCommand::SavePcap(filename));
    }
}

fn sniffer_worker(
    command_rx: Receiver<SnifferCommand>,
    event_tx: Sender<AppEvent>,
    mut current_interface: String,
    ready_tx: Sender<String>,
) {
    let mut cap: Option<Capture<Active>> = None;
    let mut save_next_count = 0;
    let mut current_savefile = None;

    loop {
        // Handle commands
        while let Ok(cmd) = command_rx.try_recv() {
            match cmd {
                SnifferCommand::SwitchInterface(name) => {
                    current_interface = name;
                    cap = None;
                }
                SnifferCommand::UpdateFilter(f_str) => {
                    if let Some(ref mut c) = cap {
                        let filter = if f_str.is_empty() { "ip or ip6" } else { &f_str };
                        let _ = c.filter(filter, true);
                    }
                }
                SnifferCommand::SavePcap(filename) => {
                    if let Some(ref mut c) = cap {
                        if let Ok(sf) = c.savefile(&filename) {
                            current_savefile = Some(sf);
                            save_next_count = 1000;
                        }
                    }
                }
            }
        }

        if cap.is_none() {
            let devices = Device::list().unwrap_or_default();
            let device = devices.into_iter()
                .find(|d| d.name == current_interface)
                .or_else(|| Device::lookup().unwrap_or(None));

            if let Some(d) = device {
                let actual_name = d.name.clone();
                match Capture::from_device(d).unwrap().promisc(true).snaplen(65535).immediate_mode(true).open() {
                    Ok(mut c) => {
                        let _ = c.filter("ip or ip6", true);
                        cap = Some(c);
                        if !ready_tx.is_empty() {
                            let _ = ready_tx.send(actual_name.clone());
                        }
                        let _ = event_tx.send(AppEvent::SwitchInterface(actual_name));
                    }
                    Err(e) => {
                        eprintln!("Failed to open pcap: {}", e);
                        thread::sleep(std::time::Duration::from_secs(1));
                    }
                }
            } else {
                thread::sleep(std::time::Duration::from_millis(100));
                continue;
            }
        }

        if let Some(ref mut c) = cap {
            match c.next_packet() {
                Ok(packet) => {
                    if save_next_count > 0 {
                        if let Some(ref mut sf) = current_savefile {
                            sf.write(&packet);
                            save_next_count -= 1;
                            if save_next_count == 0 {
                                let _ = sf.flush();
                                current_savefile = None;
                            }
                        }
                    }

                    if let Some(ethernet) = EthernetPacket::new(packet.data) {
                        handle_ethernet_packet(&ethernet, &event_tx);
                    }
                }
                Err(pcap::Error::TimeoutExpired) => continue,
                Err(_) => {
                    cap = None;
                    thread::sleep(std::time::Duration::from_secs(1));
                }
            }
        }
    }
}

fn handle_ethernet_packet(ethernet: &EthernetPacket, tx: &Sender<AppEvent>) {
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

fn handle_ipv4_packet(header: &Ipv4Packet, tx: &Sender<AppEvent>) {
    let source = IpAddr::V4(header.get_source());
    let dest = IpAddr::V4(header.get_destination());
    process_transport_layer(header.get_next_level_protocol(), source, dest, header.payload(), tx);
}

fn handle_ipv6_packet(header: &Ipv6Packet, tx: &Sender<AppEvent>) {
    let source = IpAddr::V6(header.get_source());
    let dest = IpAddr::V6(header.get_destination());
    process_transport_layer(header.get_next_header(), source, dest, header.payload(), tx);
}

fn process_transport_layer(
    protocol: pnet::packet::ip::IpNextHeaderProtocol,
    source: IpAddr,
    dest: IpAddr,
    payload: &[u8],
    tx: &Sender<AppEvent>,
) {
    let mut sni = None;
    let mut service_name = None;
    let mut proto_str = "Other";
    let mut src_port = None;
    let mut dst_port = None;
    let mut raw_payload = Vec::new();

    match protocol {
        IpNextHeaderProtocols::Tcp => {
            proto_str = "TCP";
            if let Some(tcp) = TcpPacket::new(payload) {
                src_port = Some(tcp.get_source());
                dst_port = Some(tcp.get_destination());
                let tcp_payload = tcp.payload();
                service_name = crate::network::services::lookup_service(tcp.get_destination())
                    .or_else(|| crate::network::services::lookup_service(tcp.get_source()));
                if tcp.get_destination() == 443 || tcp.get_source() == 443 {
                    sni = extract_sni(tcp_payload);
                }
                raw_payload = tcp_payload.iter().take(256).cloned().collect();
            }
        }
        IpNextHeaderProtocols::Udp => {
            proto_str = "UDP";
            if let Some(udp) = pnet::packet::udp::UdpPacket::new(payload) {
                src_port = Some(udp.get_source());
                dst_port = Some(udp.get_destination());
                let udp_payload = udp.payload();
                service_name = crate::network::services::lookup_service(udp.get_destination())
                    .or_else(|| crate::network::services::lookup_service(udp.get_source()));
                raw_payload = udp_payload.iter().take(256).cloned().collect();
            }
        }
        IpNextHeaderProtocols::Icmp => {
            proto_str = "ICMP";
            raw_payload = payload.iter().take(256).cloned().collect();
        }
        IpNextHeaderProtocols::Icmpv6 => {
            proto_str = "ICMPv6";
            raw_payload = payload.iter().take(256).cloned().collect();
        }
        _ => {
            raw_payload = payload.iter().take(256).cloned().collect();
        }
    };

    let direction = if crate::network::utils::is_local_ip(&source) {
        TrafficDirection::Outgoing
    } else {
        TrafficDirection::Incoming
    };

    let event = PacketEvent {
        source,
        dest,
        src_port,
        dst_port,
        protocol: proto_str.to_string(),
        bytes: payload.len(),
        sni,
        service_name,
        raw_payload,
        direction,
        is_flagged: false,
    };

    let _ = tx.send(AppEvent::Packet(event));
}

fn extract_sni(payload: &[u8]) -> Option<String> {
    if payload.is_empty() || payload[0] != 0x16 { return None; }
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
