use ratatui::{
    layout::{Layout, Direction, Constraint, Rect},
    widgets::{Block, Borders, List, ListItem, Clear, Paragraph},
    style::{Style, Color, Modifier},
    Frame,
};
use crate::app::{App, InputMode};
use crate::config;

pub mod map;
pub mod graph;

pub fn get_protocol_color(proto: &str) -> Color {
    match proto.to_uppercase().as_str() {
        "TCP" | "HTTPS" | "HTTP" => Color::Blue,
        "UDP" | "DNS" => Color::Yellow,
        "ICMP" | "ICMPV6" => Color::Red,
        _ => Color::Green,
    }
}

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
            Constraint::Percentage(config::GRAPH_LAYOUT_PERCENT - 5),
            Constraint::Length(3), // Controls bar
        ])
        .split(chunks[0]);

    map::draw(f, left_chunks[0], app);
    graph::draw(f, left_chunks[1], app);
    draw_controls(f, left_chunks[2]);
    
    // Sidebar for history/events
    let sidebar_area = chunks[1];
    let max_items = sidebar_area.height.saturating_sub(2) as usize;
    
    let sidebar_title = format!("Traffic [Iface: {} | Pkts: {}]", app.active_interface, app.total_packets);
    let items: Vec<ListItem> = app.events.iter().take(max_items).map(|e| {
        let target_name = app.nodes.get(&e.dest)
            .and_then(|n| n.sni.clone().or_else(|| n.hostname.clone()))
            .unwrap_or_else(|| e.dest.to_string());
        
        let content = format!("{:<15} -> {:<20} [{}] {}b", e.source, target_name, e.protocol, e.bytes);
        let color = get_protocol_color(&e.protocol);
        ListItem::new(content).style(Style::default().fg(color))
    }).collect();

    let history_list = List::new(items)
        .block(Block::default().borders(Borders::ALL).title(sidebar_title))
        .highlight_style(Style::default().bg(Color::DarkGray).add_modifier(Modifier::BOLD))
        .highlight_symbol(">> ");

    f.render_stateful_widget(history_list, sidebar_area, &mut app.traffic_list_state);

    if app.input_mode == InputMode::InterfaceSelection {
        draw_interface_selection(f, app);
    } else if app.input_mode == InputMode::Inspection {
        draw_inspection_panel(f, app);
    }
}

fn draw_controls(f: &mut Frame, area: Rect) {
    let text = " [Q] Quit | [I] Iface | [C] Clear | [↑/↓] Nav Traffic | [Enter] Inspect ";
    let p = Paragraph::new(text)
        .block(Block::default().borders(Borders::ALL).title("Controls"))
        .style(Style::default().fg(Color::Yellow));
    f.render_widget(p, area);
}

fn draw_interface_selection(f: &mut Frame, app: &mut App) {
    let area = centered_rect(60, 40, f.size());
    f.render_widget(Clear, area);

    let items: Vec<ListItem> = app.available_interfaces.iter().enumerate().map(|(i, name)| {
        let style = if i == app.selected_interface_index {
            Style::default().fg(Color::Black).bg(Color::White).add_modifier(Modifier::BOLD)
        } else {
            Style::default().fg(Color::White)
        };
        ListItem::new(name.as_str()).style(style)
    }).collect();

    let list = List::new(items)
        .block(Block::default().borders(Borders::ALL).title("Select Interface"))
        .style(Style::default().fg(Color::White));

    f.render_widget(list, area);
}

fn draw_inspection_panel(f: &mut Frame, app: &mut App) {
    let area = centered_rect(70, 60, f.size());
    f.render_widget(Clear, area);

    let selected_idx = app.traffic_list_state.selected().unwrap_or(0);
    let event = match app.events.get(selected_idx) {
        Some(e) => e,
        None => return,
    };

    let node = app.nodes.get(&event.dest);
    
    let mut details = format!("CONNECTION DETAILS\n");
    details.push_str(&format!("Source:      {}\n", event.source));
    details.push_str(&format!("Destination: {}\n", event.dest));
    details.push_str(&format!("Protocol:    {}\n", event.protocol));
    details.push_str(&format!("Size:        {} bytes\n\n", event.bytes));

    if let Some(n) = node {
        details.push_str("INFRASTRUCTURE\n");
        let name = n.sni.clone().or_else(|| n.hostname.clone()).unwrap_or_else(|| "Unknown".to_string());
        details.push_str(&format!("Identity:    {}\n", name));
        
        let asn_str = n.asn.map(|a| format!("AS{}", a)).unwrap_or_else(|| "Unknown".to_string());
        let org_str = n.organization.clone().unwrap_or_else(|| "Unknown".to_string());
        details.push_str(&format!("Network:     {} ({})\n", asn_str, org_str));
        
        if let Some((lat, lon)) = n.geo_loc {
            details.push_str(&format!("Location:    {:.4}, {:.4}\n", lat, lon));
        }
        
        details.push_str("\nTRACEROUTE PATH\n");
        if n.path.is_empty() {
            details.push_str("  (No path data available yet)\n");
        } else {
            for (i, hop) in n.path.iter().enumerate() {
                details.push_str(&format!("  {:>2}. {}\n", i + 1, hop));
            }
        }
    }

    let p = Paragraph::new(details)
        .block(Block::default().borders(Borders::ALL).title("Deep Node Inspection"))
        .style(Style::default().fg(Color::Cyan));

    f.render_widget(p, area);
}

fn centered_rect(percent_x: u16, percent_y: u16, r: Rect) -> Rect {
    let popup_layout = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Percentage((100 - percent_y) / 2),
            Constraint::Percentage(percent_y),
            Constraint::Percentage((100 - percent_y) / 2),
        ])
        .split(r);

    Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Percentage((100 - percent_x) / 2),
            Constraint::Percentage(percent_x),
            Constraint::Percentage((100 - percent_x) / 2),
        ])
        .split(popup_layout[1])[1]
}
