use ratatui::{
    layout::Rect,
    widgets::{Block, Borders, canvas::{Canvas, Map, MapResolution, Points}},
    style::Color,
    Frame,
};
use crate::app::App;

pub fn draw(f: &mut Frame, area: Rect, app: &mut App) {
    let canvas = Canvas::default()
        .block(Block::default().title("World Map (Live Traffic)").borders(Borders::ALL))
        .x_bounds([-180.0, 180.0])
        .y_bounds([-90.0, 90.0])
        .paint(|ctx| {
            // Draw high-resolution world map geometry
            ctx.draw(&Map {
                color: Color::Green,
                resolution: MapResolution::High,
            });

            // Draw nodes as points on the map
            for node in app.nodes.values() {
                if let Some((lat, lon)) = node.geo_loc {
                    // Coordinate system for Canvas: x is Longitude, y is Latitude
                    ctx.draw(&Points {
                        coords: &[(lon, lat)],
                        color: Color::Cyan,
                    });
                }
            }
        });

    f.render_widget(canvas, area);
}
