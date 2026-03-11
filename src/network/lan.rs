use pnet::datalink::{self, Channel, NetworkInterface};
use pnet::packet::arp::{ArpHardwareTypes, ArpOperations, MutableArpPacket, ArpPacket};
use pnet::packet::ethernet::{EtherTypes, MutableEthernetPacket, EthernetPacket};
use pnet::packet::ipv6::Ipv6Packet;
use pnet::packet::ip::IpNextHeaderProtocols;
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
                thread::sleep(Duration::from_secs(30));
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

    // Receiver thread for both ARP and NDP
    let event_tx_inner = event_tx.clone();
    thread::spawn(move || {
        let start = Instant::now();
        while start.elapsed() < Duration::from_secs(5) {
            if let Ok(frame) = rx.next() {
                if let Some(eth) = EthernetPacket::new(frame) {
                    match eth.get_ethertype() {
                        EtherTypes::Arp => {
                            if let Some(arp) = ArpPacket::new(eth.payload()) {
                                if arp.get_operation() == ArpOperations::Reply {
                                    let mac = arp.get_sender_hw_addr().to_string();
                                    let _ = event_tx_inner.send(AppEvent::LanDeviceFound(LanDevice {
                                        ip: IpAddr::V4(arp.get_sender_proto_addr()),
                                        mac: mac.clone(),
                                        vendor: crate::network::oui::lookup_vendor(&mac),
                                        hostname: None,
                                    }));
                                }
                            }
                        }
                        EtherTypes::Ipv6 => {
                            if let Some(ipv6) = Ipv6Packet::new(eth.payload()) {
                                if ipv6.get_next_header() == IpNextHeaderProtocols::Icmpv6 {
                                    let mac = eth.get_source().to_string();
                                    let _ = event_tx_inner.send(AppEvent::LanDeviceFound(LanDevice {
                                        ip: IpAddr::V6(ipv6.get_source()),
                                        mac: mac.clone(),
                                        vendor: crate::network::oui::lookup_vendor(&mac),
                                        hostname: None,
                                    }));
                                }
                            }
                        }
                        _ => {}
                    }
                }
            }
        }
    });

    // 1. Send ARP requests
    for target_ip in ipv4_net.iter() {
        let mut buffer = [0u8; 42];
        if let Some(mut eth) = MutableEthernetPacket::new(&mut buffer) {
            eth.set_destination(MacAddr::broadcast());
            eth.set_source(source_mac);
            eth.set_ethertype(EtherTypes::Arp);

            let mut arp_buffer = [0u8; 28];
            if let Some(mut arp) = MutableArpPacket::new(&mut arp_buffer) {
                arp.set_hardware_type(ArpHardwareTypes::Ethernet);
                arp.set_protocol_type(EtherTypes::Ipv4);
                arp.set_hw_addr_len(6);
                arp.set_proto_addr_len(4);
                arp.set_operation(ArpOperations::Request);
                arp.set_sender_hw_addr(source_mac);
                arp.set_sender_proto_addr(source_ip);
                arp.set_target_hw_addr(MacAddr::zero());
                arp.set_target_proto_addr(target_ip);
                eth.set_payload(arp.packet_mut());
            }
            let _ = tx.send_to(eth.packet(), None);
        }
        thread::sleep(Duration::from_millis(2));
    }

    // 2. Send one Neighbor Solicitation to all-nodes (IPv6)
    let mut v6_buffer = [0u8; 64];
    if let Some(mut eth_v6) = MutableEthernetPacket::new(&mut v6_buffer) {
        eth_v6.set_destination(MacAddr(0x33, 0x33, 0x00, 0x00, 0x00, 0x01));
        eth_v6.set_source(source_mac);
        eth_v6.set_ethertype(EtherTypes::Ipv6);
        
        let mut icmp_v6 = [0u8; 8];
        icmp_v6[0] = 135; // Neighbor Solicitation type
        eth_v6.set_payload(&icmp_v6);
        let _ = tx.send_to(eth_v6.packet(), None);
    }
}
