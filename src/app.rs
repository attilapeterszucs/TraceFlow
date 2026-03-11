use std::collections::{HashMap, VecDeque};
use std::net::IpAddr;
use std::time::{Instant, Duration};
use ratatui::widgets::ListState;

use crate::config;

#[derive(Debug, Clone)]
pub enum AppEvent {
    Packet(PacketEvent),
    TracerouteUpdate(IpAddr, Vec<Hop>), // Target, Path
    SwitchInterface(String),
    LanDeviceFound(LanDevice),
}

#[derive(Debug, Clone)]
pub struct Hop {
    pub ip: IpAddr,
    pub rtt: Duration,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum TrafficDirection {
    Incoming,
    Outgoing,
}

#[derive(Debug, Clone)]
pub struct PacketEvent {
    pub source: IpAddr,
    pub dest: IpAddr,
    pub src_port: Option<u16>,
    pub dst_port: Option<u16>,
    pub protocol: String,
    pub bytes: usize,
    pub sni: Option<String>,
    pub service_name: Option<String>,
    pub raw_payload: Vec<u8>,
    pub direction: TrafficDirection,
    pub is_flagged: bool,
}

#[derive(Debug, Clone)]
pub struct Node {
    pub ip: IpAddr,
    pub hostname: Option<String>,
    pub sni: Option<String>,
    pub service_name: Option<String>,
    pub asn: Option<u32>,
    pub organization: Option<String>,
    pub geo_loc: Option<(f64, f64)>, // Lat, Lon
    pub is_local: bool,
    pub bytes_sent: usize,
    pub bytes_recv: usize,
    pub last_seen: Instant,
    pub path: Vec<Hop>,
    pub process_name: Option<String>,
    pub last_direction: TrafficDirection,
    pub animation_frame: f64,
}

#[derive(Debug, Clone)]
pub struct LanDevice {
    pub ip: IpAddr,
    pub mac: String,
    pub vendor: Option<String>,
    pub _hostname: Option<String>,
    pub _last_seen: Instant,
}

#[derive(PartialEq)]
pub enum InputMode {
    Normal,
    InterfaceSelection,
    Inspection,
    Filter,
}

#[derive(PartialEq)]
pub enum AppView {
    GlobalMap,
    LocalLAN,
}

#[derive(Debug, Clone)]
pub struct SecurityAlert {
    pub _timestamp: Instant,
    pub message: String,
    pub _protocol: String,
    pub _target: IpAddr,
}

pub struct App {
    pub should_quit: bool,
    pub nodes: HashMap<IpAddr, Node>,
    pub events: VecDeque<PacketEvent>,
    pub alerts: VecDeque<SecurityAlert>,
    pub active_interface: String,
    pub total_packets: u64,
    pub pulse_frame: u32,
    pub input_mode: InputMode,
    pub view_mode: AppView,
    pub available_interfaces: Vec<String>,
    pub selected_interface_index: usize,
    pub traffic_list_state: ListState,
    
    // Throughput monitoring
    pub throughput_history: VecDeque<u64>,
    pub bytes_this_second: u64,
    pub bytes_sent_this_second: u64,
    pub bytes_recv_this_second: u64,
    pub last_throughput_update: Instant,
    pub current_upload_speed: u64,
    pub current_download_speed: u64,
    
    // Filtering
    pub filter_text: String,
    pub active_filter: String,
    pub is_paused: bool,

    // LAN Devices
    pub lan_devices: HashMap<IpAddr, LanDevice>,
}

impl App {
    pub fn new() -> Self {
        let mut traffic_list_state = ListState::default();
        traffic_list_state.select(Some(0));
        
        Self {
            should_quit: false,
            nodes: HashMap::new(),
            events: VecDeque::with_capacity(config::MAX_HISTORY_EVENTS),
            alerts: VecDeque::with_capacity(50),
            active_interface: String::from("Detecting..."),
            total_packets: 0,
            pulse_frame: 0,
            input_mode: InputMode::Normal,
            view_mode: AppView::GlobalMap,
            available_interfaces: Vec::new(),
            selected_interface_index: 0,
            traffic_list_state,
            throughput_history: VecDeque::with_capacity(500),
            bytes_this_second: 0,
            bytes_sent_this_second: 0,
            bytes_recv_this_second: 0,
            last_throughput_update: Instant::now(),
            current_upload_speed: 0,
            current_download_speed: 0,
            filter_text: String::new(),
            active_filter: String::from("None"),
            is_paused: false,
            lan_devices: HashMap::new(),
        }
    }

    pub fn on_tick(&mut self) {
        let now = Instant::now();
        self.nodes.retain(|_, node| now.duration_since(node.last_seen).as_secs() < 300);
        
        if !self.is_paused {
            self.pulse_frame = self.pulse_frame.wrapping_add(1);
            
            // Advance per-node animation frames
            for node in self.nodes.values_mut() {
                node.animation_frame += 0.25; // Base speed
            }
        }
        
        // Update throughput every 1 second
        if now.duration_since(self.last_throughput_update).as_secs() >= 1 {
            let kb_ps = self.bytes_this_second / 1024;
            if self.throughput_history.len() >= 500 {
                self.throughput_history.pop_front();
            }
            self.throughput_history.push_back(kb_ps);
            
            self.current_upload_speed = self.bytes_sent_this_second / 1024;
            self.current_download_speed = self.bytes_recv_this_second / 1024;
            
            self.bytes_this_second = 0;
            self.bytes_sent_this_second = 0;
            self.bytes_recv_this_second = 0;
            self.last_throughput_update = now;
        }
    }

    pub fn add_event(&mut self, event: PacketEvent) {
        if self.is_paused {
            return;
        }

        self.total_packets += 1;
        self.bytes_this_second += event.bytes as u64;
        
        if event.direction == TrafficDirection::Outgoing {
            self.bytes_sent_this_second += event.bytes as u64;
        } else {
            self.bytes_recv_this_second += event.bytes as u64;
        }
        
        if self.events.len() >= config::MAX_HISTORY_EVENTS {
            self.events.pop_back();
        }
        self.events.push_front(event.clone());

        self.update_node(event.source, true, event.bytes, event.sni.clone(), event.direction, event.service_name.clone());
        self.update_node(event.dest, false, event.bytes, event.sni, event.direction, event.service_name);
    }

    pub fn add_alert(&mut self, alert: SecurityAlert) {
        if self.alerts.len() >= 50 {
            self.alerts.pop_back();
        }
        self.alerts.push_front(alert);
    }

    pub fn update_path(&mut self, target: IpAddr, path: Vec<Hop>) {
        if let Some(node) = self.nodes.get_mut(&target) {
            node.path = path;
        }
    }

    pub fn add_lan_device(&mut self, device: LanDevice) {
        self.lan_devices.insert(device.ip, device);
    }

    fn update_node(&mut self, ip: IpAddr, is_source: bool, bytes: usize, sni: Option<String>, direction: TrafficDirection, service: Option<String>) {
        let node = self.nodes.entry(ip).or_insert(Node {
            ip,
            hostname: None,
            sni: sni.clone(),
            service_name: service.clone(),
            asn: None,
            organization: None,
            geo_loc: None,
            is_local: crate::network::utils::is_local_ip(&ip),
            bytes_sent: 0,
            bytes_recv: 0,
            last_seen: Instant::now(),
            path: Vec::new(),
            process_name: None,
            last_direction: direction,
            animation_frame: 0.0,
        });

        node.last_seen = Instant::now();
        node.last_direction = direction;
        
        let boost = (bytes as f64 / 1500.0).min(2.0);
        node.animation_frame += boost;

        if sni.is_some() {
            node.sni = sni;
        }
        if service.is_some() {
            node.service_name = service;
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
        self.alerts.clear();
        self.total_packets = 0;
        self.traffic_list_state.select(Some(0));
        self.bytes_this_second = 0;
    }

    pub fn next_traffic_item(&mut self) {
        let i = match self.traffic_list_state.selected() {
            Some(i) => {
                if i >= self.events.len().saturating_sub(1) {
                    0
                } else {
                    i + 1
                }
            }
            None => 0,
        };
        self.traffic_list_state.select(Some(i));
    }

    pub fn previous_traffic_item(&mut self) {
        let i = match self.traffic_list_state.selected() {
            Some(i) => {
                if i == 0 {
                    self.events.len().saturating_sub(1)
                } else {
                    i - 1
                }
            }
            None => 0,
        };
        self.traffic_list_state.select(Some(i));
    }

    pub fn toggle_view(&mut self) {
        self.view_mode = match self.view_mode {
            AppView::GlobalMap => AppView::LocalLAN,
            AppView::LocalLAN => AppView::GlobalMap,
        };
    }

    pub fn toggle_pause(&mut self) {
        self.is_paused = !self.is_paused;
    }
}
