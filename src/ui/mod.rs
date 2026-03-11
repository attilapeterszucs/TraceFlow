use ratatui::{
    layout::{Layout, Direction, Constraint},
    widgets::{Block, Borders, List, ListItem, Clear, Paragraph},
    style::{Style, Color, Modifier},
    Frame,
};
use crate::app::{App, InputMode};
use crate::config;

pub mod map;
pub mod graph;

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
    let sidebar_title = format!("Traffic [Iface: {} | Pkts: {}]", app.active_interface, app.total_packets);
    let items: Vec<ListItem> = app.events.iter().take(20).map(|e| {
        let target_name = app.nodes.get(&e.dest)
            .and_then(|n| n.sni.clone().or_else(|| n.hostname.clone()))
            .unwrap_or_else(|| e.dest.to_string());
        
        let content = format!("{:<15} -> {:<20} [{}] {}b", e.source, target_name, e.protocol, e.bytes);
        ListItem::new(content)
    }).collect();

    let history_list = List::new(items)
        .block(Block::default().borders(Borders::ALL).title(sidebar_title))
        .style(Style::default().fg(Color::White));

    f.render_widget(history_list, chunks[1]);

    if app.input_mode == InputMode::InterfaceSelection {
        draw_interface_selection(f, app);
    }
}

fn draw_controls(f: &mut Frame, area: ratatui::layout::Rect) {
    let text = " [Q] Quit | [I] Switch Interface | [C] Clear State | [Up/Down] Select Iface | [Enter] Confirm Iface | [Esc] Cancel ";
    let p = Paragraph::new(text)
        .block(Block::default().borders(Borders::ALL).title("Controls"))
        .style(Style::default().fg(Color::Yellow));
    f.render_widget(p, area);
}

fn draw_interface_selection(f: &mut Frame, app: &mut App) {
    let area = centered_rect(60, 40, f.size());
    f.render_widget(Clear, area); // Clear the background

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

fn centered_rect(percent_x: u16, percent_y: u16, r: ratatui::layout::Rect) -> ratatui::layout::Rect {
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
