use ratatui::{
    layout::{Layout, Direction, Constraint, Rect},
    widgets::{Block, Borders, List, ListItem, Clear, Paragraph, Sparkline},
    style::{Style, Color, Modifier},
    Frame,
};
use crate::app::{App, InputMode, AppView};
use crate::config;

pub mod map;
pub mod graph;
pub mod lan;

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
            Constraint::Length(3), // Sparkline
            Constraint::Percentage(config::MAP_LAYOUT_PERCENT),
            Constraint::Percentage(config::GRAPH_LAYOUT_PERCENT - 5),
            Constraint::Length(3), // Controls bar
        ])
        .split(chunks[0]);

    let right_chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Percentage(70), // Live Traffic
            Constraint::Percentage(30), // Security Alerts
        ])
        .split(chunks[1]);

    draw_throughput_sparkline(f, left_chunks[0], app);
    
    match app.view_mode {
        AppView::GlobalMap => map::draw(f, left_chunks[1], app),
        AppView::LocalLAN => lan::draw(f, left_chunks[1], app),
    }
    
    graph::draw(f, left_chunks[2], app);
    draw_controls(f, left_chunks[3], app);
    
    draw_traffic_sidebar(f, right_chunks[0], app);
    draw_alert_sidebar(f, right_chunks[1], app);

    // Overlays
    if app.input_mode == InputMode::InterfaceSelection {
        draw_interface_selection(f, app);
    } else if app.input_mode == InputMode::Inspection {
        draw_inspection_panel(f, app);
    } else if app.input_mode == InputMode::Filter {
        draw_filter_bar(f, app);
    }
}

fn draw_traffic_sidebar(f: &mut Frame, area: Rect, app: &mut App) {
    let max_items = area.height.saturating_sub(2) as usize;
    
    let sidebar_title = format!(" Traffic [If: {} | Fltr: {}] ", app.active_interface, app.active_filter);
    let items: Vec<ListItem> = app.events.iter().take(max_items).map(|e| {
        let target_name = app.nodes.get(&e.dest)
            .and_then(|n| n.sni.clone().or_else(|| n.service_name.clone()).or_else(|| n.hostname.clone()))
            .unwrap_or_else(|| e.dest.to_string());
        
        let mut content = format!("{:<15} -> {:<20} [{}] {}b", e.source, target_name, e.protocol, e.bytes);
        if e.is_flagged {
            content.push_str(" [!] ");
        }
        
        let color = if e.is_flagged { Color::LightRed } else { get_protocol_color(&e.protocol) };
        let mut style = Style::default().fg(color);
        if e.is_flagged {
            style = style.add_modifier(Modifier::BOLD);
        }
        
        ListItem::new(content).style(style)
    }).collect();

    let history_list = List::new(items)
        .block(Block::default().borders(Borders::ALL).title(sidebar_title))
        .highlight_style(Style::default().bg(Color::DarkGray).add_modifier(Modifier::BOLD))
        .highlight_symbol(">> ");

    f.render_stateful_widget(history_list, area, &mut app.traffic_list_state);
}

fn draw_alert_sidebar(f: &mut Frame, area: Rect, app: &App) {
    let items: Vec<ListItem> = app.alerts.iter().take(area.height as usize).map(|a| {
        let content = format!("! {}", a.message);
        ListItem::new(content).style(Style::default().fg(Color::LightRed).add_modifier(Modifier::BOLD))
    }).collect();

    let alert_list = List::new(items)
        .block(Block::default().borders(Borders::ALL).title(" Security Alerts ").style(Style::default().fg(Color::Red)));

    f.render_widget(alert_list, area);
}

fn draw_throughput_sparkline(f: &mut Frame, area: Rect, app: &App) {
    let current_kbps = app.throughput_history.back().cloned().unwrap_or(0);
    let title = format!(
        " Throughput: {} KB/s | ↓ {} KB/s | ↑ {} KB/s {} ", 
        current_kbps, 
        app.current_download_speed, 
        app.current_upload_speed,
        if app.is_paused { "[PAUSED]" } else { "" }
    );
    
    let max_data_points = area.width.saturating_sub(2) as usize;
    let data: Vec<u64> = app.throughput_history.iter()
        .skip(app.throughput_history.len().saturating_sub(max_data_points))
        .cloned()
        .collect();
        
    let sparkline = Sparkline::default()
        .block(Block::default().title(title).borders(Borders::ALL))
        .data(&data)
        .style(Style::default().fg(if app.is_paused { Color::Gray } else { Color::Magenta }));
    f.render_widget(sparkline, area);
}

fn draw_controls(f: &mut Frame, area: Rect, app: &App) {
    let text = match app.input_mode {
        InputMode::Normal => " [Q] Quit | [I] Iface | [L] Map/LAN | [/] Filter | [P] Pause | [C] Clear | [Ctrl+S] Pcap | [↑/↓] Nav | [Enter] Inspect ",
        InputMode::Filter => " TYPE FILTER (e.g. 'tcp', 'port 443', 'host 1.1.1.1') | [Enter] Apply | [Esc] Cancel ",
        _ => " [Esc] Back ",
    };
    let p = Paragraph::new(text)
        .block(Block::default().borders(Borders::ALL).title("Controls"))
        .style(Style::default().fg(Color::Yellow));
    f.render_widget(p, area);
}

fn draw_filter_bar(f: &mut Frame, app: &App) {
    let area = centered_rect(60, 10, f.size());
    f.render_widget(Clear, area);
    let p = Paragraph::new(app.filter_text.as_str())
        .block(Block::default().borders(Borders::ALL).title("Enter BPF Filter (tokens: tcp, udp, icmp, port N, host IP)"))
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
    let area = centered_rect(80, 80, f.size());
    f.render_widget(Clear, area);

    let selected_idx = app.traffic_list_state.selected().unwrap_or(0);
    let event = match app.events.get(selected_idx) {
        Some(e) => e,
        None => return,
    };

    let node = app.nodes.get(&event.dest);
    
    let mut details = format!("CONNECTION DETAILS\n");
    details.push_str(&format!("Source:      {:<15} Port: {:?}\n", event.source, event.src_port));
    details.push_str(&format!("Destination: {:<15} Port: {:?}\n", event.dest, event.dst_port));
    details.push_str(&format!("Protocol:    {:<15} Size: {} bytes\n\n", event.protocol, event.bytes));

    if let Some(n) = node {
        details.push_str("INFRASTRUCTURE & SYSTEM\n");
        let name = n.sni.clone().or_else(|| n.service_name.clone()).or_else(|| n.hostname.clone()).unwrap_or_else(|| "Unknown".to_string());
        details.push_str(&format!("Identity:    {}\n", name));
        
        let proc = n.process_name.as_deref().unwrap_or("Unknown Process");
        details.push_str(&format!("Local App:   {}\n", proc));

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
                details.push_str(&format!("  {:>2}. {:<15} [{}ms]\n", i + 1, hop.ip, hop.rtt.as_millis()));
            }
        }
    }

    details.push_str("\nPAYLOAD HEX DUMP (First 256 bytes)\n");
    details.push_str(&format_hex_dump(&event.raw_payload));

    let p = Paragraph::new(details)
        .block(Block::default().borders(Borders::ALL).title("Deep Node Inspection"))
        .style(Style::default().fg(Color::Cyan));

    f.render_widget(p, area);
}

fn format_hex_dump(data: &[u8]) -> String {
    let mut result = String::new();
    for chunk in data.chunks(16) {
        for b in chunk {
            result.push_str(&format!("{:02X} ", b));
        }
        if chunk.len() < 16 {
            for _ in 0..(16 - chunk.len()) {
                result.push_str("   ");
            }
        }
        result.push_str(" | ");
        for &b in chunk {
            if b >= 32 && b <= 126 {
                result.push(b as char);
            } else {
                result.push('.');
            }
        }
        result.push('\n');
    }
    result
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
