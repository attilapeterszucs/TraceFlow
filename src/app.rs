use std::collections::{HashMap, VecDeque};
use std::net::IpAddr;

use crate::config;

#[derive(Debug, Clone)]
pub struct PacketEvent {
    pub source: IpAddr,
    pub dest: IpAddr,
    pub protocol: String,
    pub bytes: usize,
    pub sanitized_payload: Option<String>,
}

#[derive(Debug, Clone)]
pub struct Node {
    pub ip: IpAddr,
    pub hostname: Option<String>,
    pub geo_loc: Option<(f64, f64)>, // Lat, Lon
    pub is_local: bool,
    pub bytes_sent: usize,
    pub bytes_recv: usize,
}

pub struct App {
    pub should_quit: bool,
    pub nodes: HashMap<IpAddr, Node>,
    pub events: VecDeque<PacketEvent>,
    pub local_ip: Option<IpAddr>,
    pub active_interface: String,
    pub total_packets: u64,
}

impl App {
    pub fn new() -> Self {
        Self {
            should_quit: false,
            nodes: HashMap::new(),
            events: VecDeque::with_capacity(config::MAX_HISTORY_EVENTS),
            local_ip: None,
            active_interface: String::from("Detecting..."),
            total_packets: 0,
        }
    }

    pub fn on_tick(&mut self) {
        // Handle routine background tasks
    }

    pub fn add_event(&mut self, event: PacketEvent) {
        self.total_packets += 1;
        if self.events.len() >= config::MAX_HISTORY_EVENTS {
            self.events.pop_back();
        }
        self.events.push_front(event.clone());

        self.update_node(event.source, true, event.bytes);
        self.update_node(event.dest, false, event.bytes);
    }

    fn update_node(&mut self, ip: IpAddr, is_source: bool, bytes: usize) {
        let node = self.nodes.entry(ip).or_insert(Node {
            ip,
            hostname: None,
            geo_loc: None,
            is_local: false, // Updated later via geo IP lookup
            bytes_sent: 0,
            bytes_recv: 0,
        });

        if is_source {
            node.bytes_sent = node.bytes_sent.saturating_add(bytes);
        } else {
            node.bytes_recv = node.bytes_recv.saturating_add(bytes);
        }
    }

    pub fn quit(&mut self) {
        self.should_quit = true;
    }
}
