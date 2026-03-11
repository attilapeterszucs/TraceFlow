use ratatui::{
    layout::Rect,
    widgets::{Block, Borders, Paragraph},
    style::{Style, Color},
    Frame,
};
use crate::app::App;

pub fn draw(f: &mut Frame, area: Rect, app: &mut App) {
    let mut lan_text = String::from("Local LAN Topology Map:\n\n");
    
    lan_text.push_str("       [ Your PC ]\n");
    lan_text.push_str("            |\n");
    
    if app.lan_devices.is_empty() {
        lan_text.push_str("     Scanning for local devices...\n");
    } else {
        let devices: Vec<_> = app.lan_devices.values().collect();
        for (i, device) in devices.iter().enumerate() {
            let connector = if i == devices.len() - 1 { "    └── " } else { "    ├── " };
            lan_text.push_str(&format!("{}{:<15} [{}]\n", connector, device.ip, device.mac));
        }
    }

    let lan_map = Paragraph::new(lan_text)
        .block(Block::default().title("Local Network (ARP Scan)").borders(Borders::ALL))
        .style(Style::default().fg(Color::Green));

    f.render_widget(lan_map, area);
}
