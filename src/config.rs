pub const APP_TITLE: &str = "TraceFlow - Terminal Internet Map";
pub const TICK_RATE_MS: u64 = 50; // 20 FPS
pub const MAX_PACKET_BUFFER_SIZE: usize = 65536; // 64KB Max IP packet
pub const MAX_NODES_DISPLAY: usize = 50; // Max connection nodes to show
pub const MAX_HISTORY_EVENTS: usize = 100;
pub const MAP_WIDTH: u16 = 120;
pub const MAP_HEIGHT: u16 = 40;
pub const DEFAULT_INTERFACE: &str = "any";

// Layout percentages
pub const MAP_LAYOUT_PERCENT: u16 = 60;
pub const GRAPH_LAYOUT_PERCENT: u16 = 40;
pub const SIDEBAR_LAYOUT_PERCENT: u16 = 25;

pub const FALLBACK_USER: &str = "nobody";
pub const FALLBACK_GROUP: &str = "nobody";
