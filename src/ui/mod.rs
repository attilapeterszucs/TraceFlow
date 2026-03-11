pub mod map;
pub mod graph;
pub mod sanitize;

use std::io;
use ratatui::{
    layout::{Layout, Direction, Constraint},
    widgets::{Block, Borders, List, ListItem},
    style::{Style, Color},
    Frame,
};
use crate::app::App;
use crate::config;

pub fn draw_ui(f: &mut Frame, app: &mut App) {
    let chunks = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Percentage(100 - config::SIDEBAR_LAYOUT_PERCENT),
            Constraint::Percentage(config::SIDEBAR_LAYOUT_PERCENT),
        ])
        .split(f.size());

    let left_chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Percentage(config::MAP_LAYOUT_PERCENT),
            Constraint::Percentage(config::GRAPH_LAYOUT_PERCENT),
        ])
        .split(chunks[0]);

    map::draw(f, left_chunks[0], app);
    graph::draw(f, left_chunks[1], app);
    
    // Sidebar for history/events
    let sidebar_title = format!("Traffic [Iface: {} | Pkts: {}]", app.active_interface, app.total_packets);
    let items: Vec<ListItem> = app.events.iter().take(20).map(|e| {
        let content = format!("{:<15} -> {:<15} [{}] {}b", e.source, e.dest, e.protocol, e.bytes);
        ListItem::new(content)
    }).collect();

    let history_list = List::new(items)
        .block(Block::default().borders(Borders::ALL).title(sidebar_title))
        .style(Style::default().fg(Color::White));

    f.render_widget(history_list, chunks[1]);
}
