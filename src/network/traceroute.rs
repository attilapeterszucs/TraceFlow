use std::net::IpAddr;
use std::thread;
use std::time::{Duration, Instant};
use crossbeam_channel::{Sender, Receiver, unbounded};
use pnet::packet::icmp::{IcmpTypes, echo_request::MutableEchoRequestPacket};
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
    let protocol = Layer3(IpNextHeaderProtocols::Icmp);
    let (mut tx, mut rx) = match transport_channel(4096, protocol) {
        Ok((tx, rx)) => (tx, rx),
        Err(e) => {
            eprintln!("Failed to open traceroute channel: {}", e);
            return;
        }
    };

    while let Ok(target) = request_rx.recv() {
        if let IpAddr::V4(target_v4) = target {
            let mut current_path = Vec::new();
            let mut reached_destination = false;

            for ttl in 1..=30 {
                if reached_destination { break; }

                let mut buffer = [0u8; 64];
                let mut icmp_packet = MutableEchoRequestPacket::new(&mut buffer).unwrap();
                icmp_packet.set_icmp_type(IcmpTypes::EchoRequest);
                icmp_packet.set_identifier(0x1234);
                icmp_packet.set_sequence_number(ttl as u16);
                let checksum = util::checksum(icmp_packet.packet(), 1);
                icmp_packet.set_checksum(checksum);

                if let Err(e) = tx.set_ttl(ttl) {
                    eprintln!("Failed to set TTL: {}", e);
                    break;
                }

                let send_time = Instant::now();
                if let Err(e) = tx.send_to(icmp_packet, IpAddr::V4(target_v4)) {
                    eprintln!("Failed to send traceroute packet: {}", e);
                    break;
                }

                let timeout = Duration::from_millis(500);
                let mut rx_iter = pnet::transport::icmp_packet_iter(&mut rx);
                
                while send_time.elapsed() < timeout {
                    if let Ok(Some((packet, addr))) = rx_iter.next_with_timeout(Duration::from_millis(100)) {
                        let rtt = send_time.elapsed();
                        if addr == target {
                            reached_destination = true;
                            current_path.push(Hop { ip: addr, rtt });
                            break;
                        } else if packet.get_icmp_type() == IcmpTypes::TimeExceeded {
                            current_path.push(Hop { ip: addr, rtt });
                            break;
                        }
                    }
                }

                let _ = event_tx.send(AppEvent::TracerouteUpdate(target, current_path.clone()));
                if reached_destination { break; }
                thread::sleep(Duration::from_millis(20));
            }
        }
    }
}
