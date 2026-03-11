use ratatui::{
    layout::Rect,
    widgets::{Block, Borders, Paragraph},
    style::{Style, Color},
    Frame,
};
use crate::app::App;

pub fn draw(f: &mut Frame, area: Rect, app: &mut App) {
    let mut graph_text = String::new();
    
    // We render some active nodes in a tree structure
    let nodes: Vec<_> = app.nodes.values()
        .filter(|n| !n.is_local)
        .take(5)
        .collect();

    if nodes.is_empty() {
        graph_text.push_str("Listening for connections...\n");
    } else {
        for node in nodes {
            let target_name = node.sni.clone()
                .or_else(|| node.hostname.clone())
                .unwrap_or_else(|| node.ip.to_string());

            graph_text.push_str("Your PC");
            
            // Draw path hops
            if node.path.is_empty() {
                graph_text.push_str(" ---> ");
                graph_text.push_str(&target_name);
            } else {
                for (i, hop) in node.path.iter().enumerate() {
                    graph_text.push_str(" --- ");
                    
                    // Animation logic: show a pulse '*' moving along the path
                    let pulse_pos = (app.pulse_frame / 4) % (node.path.len() as u32 + 1);
                    if i as u32 == pulse_pos {
                        graph_text.push_str("*");
                    }

                    // Display hop name if it matches destination, otherwise brief IP
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
