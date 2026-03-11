use ratatui::{
    layout::Rect,
    widgets::{Block, Borders, Paragraph},
    style::{Style, Color},
    Frame,
    text::{Span, Line},
};
use crate::app::{App, TrafficDirection};

pub fn draw(f: &mut Frame, area: Rect, app: &mut App) {
    let mut lines = Vec::new();
    
    let max_nodes = (area.height.saturating_sub(2) / 2) as usize;

    let nodes: Vec<_> = app.nodes.values()
        .filter(|n| !n.is_local)
        .take(max_nodes)
        .collect();

    if nodes.is_empty() {
        lines.push(Line::from("Listening for connections..."));
    } else {
        for node in nodes {
            let target_name = node.sni.clone()
                .or_else(|| node.hostname.clone())
                .unwrap_or_else(|| node.ip.to_string());

            let proc_name = node.process_name.as_deref().unwrap_or("Unknown Process");
            let mut line_spans = vec![
                Span::styled(format!("Your PC ({})", proc_name), Style::default().fg(Color::White)),
            ];
            
            if node.path.is_empty() {
                let pulse_char = if node.last_direction == TrafficDirection::Outgoing { ">>>" } else { "<<<" };
                line_spans.push(Span::raw(format!(" {} ", pulse_char)));
                line_spans.push(Span::styled(target_name, Style::default().fg(Color::Cyan)));
            } else {
                for (i, hop) in node.path.iter().enumerate() {
                    let is_active_pulse = (node.animation_frame as u32 % (node.path.len() as u32 + 1)) == i as u32;
                    
                    if is_active_pulse {
                        let pulse_char = if node.last_direction == TrafficDirection::Outgoing { ">>>" } else { "<<<" };
                        line_spans.push(Span::raw(format!(" {} ", pulse_char)));
                    } else {
                        line_spans.push(Span::raw(" --- "));
                    }

                    let rtt_ms = hop.rtt.as_millis();
                    let rtt_color = if rtt_ms < 50 {
                        Color::Green
                    } else if rtt_ms < 150 {
                        Color::Yellow
                    } else {
                        Color::Red
                    };

                    if hop.ip == node.ip {
                        line_spans.push(Span::styled(target_name.clone(), Style::default().fg(Color::Cyan)));
                    } else {
                        line_spans.push(Span::raw(format!("{}", hop.ip)));
                    }
                    line_spans.push(Span::styled(format!(" [{}ms]", rtt_ms), Style::default().fg(rtt_color)));
                }
            }
            lines.push(Line::from(line_spans));
            lines.push(Line::from("")); // Spacer
        }
    }

    let graph = Paragraph::new(lines)
        .block(Block::default().title("Connection Graph (Live Traceroute)").borders(Borders::ALL))
        .style(Style::default().fg(Color::Cyan));

    f.render_widget(graph, area);
}
