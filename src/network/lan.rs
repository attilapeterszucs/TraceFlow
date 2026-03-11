use pnet::datalink::{self, Channel, NetworkInterface};
use pnet::packet::arp::{ArpHardwareTypes, ArpOperations, MutableArpPacket};
use pnet::packet::ethernet::{EtherTypes, MutableEthernetPacket};
use pnet::packet::{Packet, MutablePacket};
use pnet::util::MacAddr;
use std::net::{IpAddr, Ipv4Addr};
use std::thread;
use std::time::{Duration, Instant};
use crossbeam_channel::Sender;

use crate::app::{AppEvent, LanDevice};

pub struct LanScanner {
    _event_tx: Sender<AppEvent>,
}

impl LanScanner {
    pub fn new(event_tx: Sender<AppEvent>) -> Self {
        let scanner = Self { _event_tx: event_tx.clone() };
        let event_tx_clone = event_tx.clone();
        
        thread::spawn(move || {
            loop {
                if let Some(iface) = find_default_interface() {
                    scan_subnet(&iface, &event_tx_clone);
                }
                thread::sleep(Duration::from_secs(30)); // Rescan every 30s
            }
        });

        scanner
    }
}

fn find_default_interface() -> Option<NetworkInterface> {
    datalink::interfaces()
        .into_iter()
        .find(|iface| !iface.is_loopback() && iface.is_up() && !iface.ips.is_empty() && iface.mac.is_some())
}

fn scan_subnet(interface: &NetworkInterface, event_tx: &Sender<AppEvent>) {
    let source_mac = interface.mac.unwrap();
    let source_ip = interface.ips.iter()
        .find(|ip| ip.is_ipv4())
        .map(|ip| match ip.ip() {
            IpAddr::V4(v4) => v4,
            _ => unreachable!(),
        })
        .unwrap_or(Ipv4Addr::new(0, 0, 0, 0));

    let network = interface.ips.iter()
        .find(|ip| ip.is_ipv4())
        .and_then(|ip| {
            if let ipnetwork::IpNetwork::V4(net) = ip {
                Some(*net)
            } else {
                None
            }
        });

    if network.is_none() { return; }
    let ipv4_net = network.unwrap();

    let (mut tx, mut rx) = match datalink::channel(interface, Default::default()) {
        Ok(Channel::Ethernet(tx, rx)) => (tx, rx),
        _ => return,
    };

    // Receiver thread
    let event_tx_inner = event_tx.clone();
    thread::spawn(move || {
        let start = Instant::now();
        while start.elapsed() < Duration::from_secs(5) {
            if let Ok(frame) = rx.next() {
                if let Some(ethernet) = pnet::packet::ethernet::EthernetPacket::new(frame) {
                    if ethernet.get_ethertype() == EtherTypes::Arp {
                        if let Some(arp) = pnet::packet::arp::ArpPacket::new(ethernet.payload()) {
                            if arp.get_operation() == ArpOperations::Reply {
                                let mac = arp.get_sender_hw_addr().to_string();
                                let vendor = crate::network::oui::lookup_vendor(&mac);
                                
                                let _ = event_tx_inner.send(AppEvent::LanDeviceFound(LanDevice {
                                    ip: IpAddr::V4(arp.get_sender_proto_addr()),
                                    mac,
                                    vendor,
                                    _hostname: None,
                                    _last_seen: Instant::now(),
                                }));
                            }
                        }
                    }
                }
            }
        }
    });

    // Sender loop
    for target_ip in ipv4_net.iter() {
        let mut ethernet_buffer = [0u8; 42];
        let mut ethernet_packet = MutableEthernetPacket::new(&mut ethernet_buffer).unwrap();

        ethernet_packet.set_destination(MacAddr::broadcast());
        ethernet_packet.set_source(source_mac);
        ethernet_packet.set_ethertype(EtherTypes::Arp);

        let mut arp_buffer = [0u8; 28];
        let mut arp_packet = MutableArpPacket::new(&mut arp_buffer).unwrap();

        arp_packet.set_hardware_type(ArpHardwareTypes::Ethernet);
        arp_packet.set_protocol_type(EtherTypes::Ipv4);
        arp_packet.set_hw_addr_len(6);
        arp_packet.set_proto_addr_len(4);
        arp_packet.set_operation(ArpOperations::Request);
        arp_packet.set_sender_hw_addr(source_mac);
        arp_packet.set_sender_proto_addr(source_ip);
        arp_packet.set_target_hw_addr(MacAddr::zero());
        arp_packet.set_target_proto_addr(target_ip);

        ethernet_packet.set_payload(arp_packet.packet_mut());
        let _ = tx.send_to(ethernet_packet.packet(), None);
        thread::sleep(Duration::from_millis(5));
    }
}
