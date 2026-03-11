use std::net::IpAddr;
use std::thread;
use std::time::{Duration, Instant};
use crossbeam_channel::{Sender, Receiver, unbounded};
use pnet::packet::icmp::{IcmpTypes, echo_request::MutableEchoRequestPacket};
use pnet::packet::icmpv6::{Icmpv6Types, MutableIcmpv6Packet};
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::util;
use pnet::packet::Packet;
use pnet::transport::{transport_channel, TransportChannelType::Layer3};

use crate::app::{AppEvent, Hop};

pub struct TracerouteManager {
    request_tx: Sender<IpAddr>,
}

impl TracerouteManager {
    pub fn new(event_tx: Sender<AppEvent>) -> Self {
        let (request_tx, request_rx) = unbounded();
        
        thread::spawn(move || {
            traceroute_worker(request_rx, event_tx);
        });

        Self { request_tx }
    }

    pub fn trace(&self, target: IpAddr) {
        let _ = self.request_tx.send(target);
    }
}

fn traceroute_worker(request_rx: Receiver<IpAddr>, event_tx: Sender<AppEvent>) {
    while let Ok(target) = request_rx.recv() {
        match target {
            IpAddr::V4(target_v4) => {
                let protocol = Layer3(IpNextHeaderProtocols::Icmp);
                if let Ok((mut tx, mut rx)) = transport_channel(4096, protocol) {
                    let mut current_path = Vec::new();
                    let mut reached = false;
                    for ttl in 1..=30 {
                        if reached { break; }
                        let mut buffer = [0u8; 64];
                        let mut icmp_packet = MutableEchoRequestPacket::new(&mut buffer).unwrap();
                        icmp_packet.set_icmp_type(IcmpTypes::EchoRequest);
                        icmp_packet.set_identifier(0x1234);
                        icmp_packet.set_sequence_number(ttl as u16);
                        let checksum = util::checksum(icmp_packet.packet(), 1);
                        icmp_packet.set_checksum(checksum);

                        let _ = tx.set_ttl(ttl);
                        let send_time = Instant::now();
                        if tx.send_to(icmp_packet, IpAddr::V4(target_v4)).is_err() { break; }

                        let mut rx_iter = pnet::transport::icmp_packet_iter(&mut rx);
                        while send_time.elapsed() < Duration::from_millis(500) {
                            if let Ok(Some((packet, addr))) = rx_iter.next_with_timeout(Duration::from_millis(100)) {
                                let rtt = send_time.elapsed();
                                if addr == target {
                                    reached = true;
                                    current_path.push(Hop { ip: addr, rtt });
                                    break;
                                } else if packet.get_icmp_type() == IcmpTypes::TimeExceeded {
                                    current_path.push(Hop { ip: addr, rtt });
                                    break;
                                }
                            }
                        }
                        let _ = event_tx.send(AppEvent::TracerouteUpdate(target, current_path.clone()));
                        if reached { break; }
                        thread::sleep(Duration::from_millis(20));
                    }
                }
            }
            IpAddr::V6(target_v6) => {
                let protocol = Layer3(IpNextHeaderProtocols::Icmpv6);
                if let Ok((mut tx, mut rx)) = transport_channel(4096, protocol) {
                    let mut current_path = Vec::new();
                    let mut reached = false;
                    for hop_limit in 1..=30 {
                        if reached { break; }
                        let mut buffer = [0u8; 64];
                        let mut icmp_packet = MutableIcmpv6Packet::new(&mut buffer).unwrap();
                        icmp_packet.set_icmpv6_type(Icmpv6Types::EchoRequest);
                        // pnet's icmpv6 doesn't have id/seq setters in the basic MutableIcmpv6Packet, 
                        // but we can use the raw buffer if needed. For now we just send a basic request.

                        let _ = tx.set_ttl(hop_limit); // set_ttl works for Hop Limit too in pnet transport
                        let send_time = Instant::now();
                        if tx.send_to(icmp_packet, IpAddr::V6(target_v6)).is_err() { break; }

                        let mut rx_iter = pnet::transport::icmpv6_packet_iter(&mut rx);
                        while send_time.elapsed() < Duration::from_millis(500) {
                            if let Ok(Some((packet, addr))) = rx_iter.next_with_timeout(Duration::from_millis(100)) {
                                let rtt = send_time.elapsed();
                                if addr == target {
                                    reached = true;
                                    current_path.push(Hop { ip: addr, rtt });
                                    break;
                                } else if packet.get_icmpv6_type() == Icmpv6Types::TimeExceeded {
                                    current_path.push(Hop { ip: addr, rtt });
                                    break;
                                }
                            }
                        }
                        let _ = event_tx.send(AppEvent::TracerouteUpdate(target, current_path.clone()));
                        if reached { break; }
                        thread::sleep(Duration::from_millis(20));
                    }
                }
            }
        }
    }
}
