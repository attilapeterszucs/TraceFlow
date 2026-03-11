use ratatui::{
    layout::Rect,
    widgets::{Block, Borders, Paragraph},
    style::{Style, Color},
    Frame,
};
use crate::app::App;

pub fn draw(f: &mut Frame, area: Rect, app: &mut App) {
    let mut graph_text = String::from("Live Traceroute Graph:\n");
    graph_text.push_str("Your PC\n");
    graph_text.push_str("   |\n");
    
    // We render some active nodes in a tree structure
    let nodes: Vec<_> = app.nodes.values().take(5).collect();
    if nodes.is_empty() {
        graph_text.push_str("Listening for connections...\n");
    } else {
        graph_text.push_str("Gateway / ISP\n");
        for (i, node) in nodes.iter().enumerate() {
            let indent = " ".repeat((i + 1) * 3);
            graph_text.push_str(&format!("{}|--- {}\n", indent, node.ip));
        }
    }

    let graph = Paragraph::new(graph_text)
        .block(Block::default().title("Connection Graph").borders(Borders::ALL))
        .style(Style::default().fg(Color::Cyan));

    f.render_widget(graph, area);
}
