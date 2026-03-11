use ratatui::{
    layout::Rect,
    widgets::{Block, Borders, Paragraph},
    style::{Style, Color},
    Frame,
};
use crate::app::{App, TrafficDirection};

pub fn draw(f: &mut Frame, area: Rect, app: &mut App) {
    let mut graph_text = String::new();
    
    let max_nodes = (area.height.saturating_sub(2) / 2) as usize;

    let nodes: Vec<_> = app.nodes.values()
        .filter(|n| !n.is_local)
        .take(max_nodes)
        .collect();

    if nodes.is_empty() {
        graph_text.push_str("Listening for connections...\n");
    } else {
        for node in nodes {
            let target_name = node.sni.clone()
                .or_else(|| node.hostname.clone())
                .unwrap_or_else(|| node.ip.to_string());

            let proc_name = node.process_name.as_deref().unwrap_or("Unknown Process");
            graph_text.push_str(&format!("Your PC ({})", proc_name));
            
            // Draw path hops
            if node.path.is_empty() {
                let pulse_char = if node.last_direction == TrafficDirection::Outgoing { ">>>" } else { "<<<" };
                graph_text.push_str(&format!(" {} ", pulse_char));
                graph_text.push_str(&target_name);
            } else {
                for (i, hop) in node.path.iter().enumerate() {
                    // Use per-node animation frame
                    let is_active_pulse = (node.animation_frame as u32 % (node.path.len() as u32 + 1)) == i as u32;
                    
                    if is_active_pulse {
                        let pulse_char = if node.last_direction == TrafficDirection::Outgoing { ">>>" } else { "<<<" };
                        graph_text.push_str(&format!(" {} ", pulse_char));
                    } else {
                        graph_text.push_str(" --- ");
                    }

                    if hop == &node.ip {
                        graph_text.push_str(&target_name);
                    } else {
                        graph_text.push_str(&format!("{}", hop));
                    }
                }
            }
            graph_text.push_str("\n\n");
        }
    }

    let graph = Paragraph::new(graph_text)
        .block(Block::default().title("Connection Graph (Live Traceroute)").borders(Borders::ALL))
        .style(Style::default().fg(Color::Cyan));

    f.render_widget(graph, area);
}
