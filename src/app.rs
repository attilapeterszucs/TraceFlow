use std::collections::{HashMap, VecDeque};
use std::net::IpAddr;

use crate::config;

#[derive(Debug, Clone)]
pub enum AppEvent {
    Packet(PacketEvent),
    TracerouteUpdate(IpAddr, Vec<IpAddr>), // Target, Path
    SwitchInterface(String),
}

#[derive(Debug, Clone)]
pub struct PacketEvent {
    pub source: IpAddr,
    pub dest: IpAddr,
    pub protocol: String,
    pub bytes: usize,
    pub sni: Option<String>,
}

#[derive(Debug, Clone)]
pub struct Node {
    pub ip: IpAddr,
    pub hostname: Option<String>,
    pub sni: Option<String>,
    pub geo_loc: Option<(f64, f64)>, // Lat, Lon
    pub is_local: bool,
    pub bytes_sent: usize,
    pub bytes_recv: usize,
    pub last_seen: std::time::Instant,
    pub path: Vec<IpAddr>,
}

#[derive(PartialEq)]
pub enum InputMode {
    Normal,
    InterfaceSelection,
}

pub struct App {
    pub should_quit: bool,
    pub nodes: HashMap<IpAddr, Node>,
    pub events: VecDeque<PacketEvent>,
    pub active_interface: String,
    pub total_packets: u64,
    pub pulse_frame: u32,
    pub input_mode: InputMode,
    pub available_interfaces: Vec<String>,
    pub selected_interface_index: usize,
}

impl App {
    pub fn new() -> Self {
        Self {
            should_quit: false,
            nodes: HashMap::new(),
            events: VecDeque::with_capacity(config::MAX_HISTORY_EVENTS),
            active_interface: String::from("Detecting..."),
            total_packets: 0,
            pulse_frame: 0,
            input_mode: InputMode::Normal,
            available_interfaces: Vec::new(),
            selected_interface_index: 0,
        }
    }

    pub fn on_tick(&mut self) {
        let now = std::time::Instant::now();
        self.nodes.retain(|_, node| now.duration_since(node.last_seen).as_secs() < 300);
        self.pulse_frame = self.pulse_frame.wrapping_add(1);
    }

    pub fn add_event(&mut self, event: PacketEvent) {
        self.total_packets += 1;
        if self.events.len() >= config::MAX_HISTORY_EVENTS {
            self.events.pop_back();
        }
        self.events.push_front(event.clone());

        self.update_node(event.source, true, event.bytes, event.sni.clone());
        self.update_node(event.dest, false, event.bytes, event.sni);
    }

    pub fn update_path(&mut self, target: IpAddr, path: Vec<IpAddr>) {
        if let Some(node) = self.nodes.get_mut(&target) {
            node.path = path;
        }
    }

    fn update_node(&mut self, ip: IpAddr, is_source: bool, bytes: usize, sni: Option<String>) {
        let node = self.nodes.entry(ip).or_insert(Node {
            ip,
            hostname: None,
            sni: sni.clone(),
            geo_loc: None,
            is_local: crate::network::utils::is_local_ip(&ip),
            bytes_sent: 0,
            bytes_recv: 0,
            last_seen: std::time::Instant::now(),
            path: Vec::new(),
        });

        node.last_seen = std::time::Instant::now();
        if sni.is_some() {
            node.sni = sni;
        }

        if is_source {
            node.bytes_sent = node.bytes_sent.saturating_add(bytes);
        } else {
            node.bytes_recv = node.bytes_recv.saturating_add(bytes);
        }
    }

    pub fn quit(&mut self) {
        self.should_quit = true;
    }

    pub fn clear_state(&mut self) {
        self.nodes.clear();
        self.events.clear();
        self.total_packets = 0;
    }
}
