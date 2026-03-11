use ratatui::{
    layout::Rect,
    widgets::{Block, Borders, Paragraph},
    style::{Style, Color},
    Frame,
};
use crate::app::App;

pub fn draw(f: &mut Frame, area: Rect, _app: &mut App) {
    // Simplified ASCII Map for the prototype
    let map_text = r#"
        .    ..      .        .         .      .        .  .
     .         .         .           .           .    .
   .       ___      .           .        _   .        .
    .   .-'   `-.       .         .   .-' `-.    .       .
  .    /         \  .       .        /       \       .     .
      /           \      .      .   /         \   .      .
  .  |             |  .      .     |           |     .
     |             |       .       |           |  .      .
 .    \           /    .       .    \         /      .
       `-._____.-'       .           `-.___.-'    .      .
    .        .        .       .         .          .
 "#;

    let map = Paragraph::new(map_text)
        .block(Block::default().title("World Map (GeoIP)").borders(Borders::ALL))
        .style(Style::default().fg(Color::Green));

    f.render_widget(map, area);
}
