use ratatui::{
    layout::Rect,
    widgets::{Block, Borders, Paragraph},
    style::{Style, Color},
    Frame,
};
use crate::app::App;

// High-quality ASCII World Map (approx 120x40)
const WORLD_MAP: &str = r#"
                                     . _..-''-._
           .==.       .              .' ._      '.
     _..-'      '-._.' \             |   '.       |
    /                   |            \_    '._   /
    |                   |_..-''-._     '._    '-'
    \_                _/          '-._    '-._
      '-._        _.-'                '-._    '-._
          '-.__.-'                        '-._    '-._
                                              '-._    '-.
      .-------------------------------------------.      |
     /                                             \     /
    |        THE WORLD AS SEEN BY TRACEFLOW         |   /
     \                                             /  -'
      '-------------------------------------------'
"#;

// We'll use a more complete ASCII map for the final version
const ASCII_MAP: &[&str] = &[
    "                                               _.._          ",
    "      _.-'''-._        _          _..-'''-._  /    \\         ",
    "    /          \\      / \\       /           \\|      |        ",
    "    |           |_..-'   '-._..-|            |      |        ",
    "    \\_      _.-'             /   \\_        _/       /        ",
    "      '-..-'                |      '-.__.-'      _.-'         ",
    "                            \\_                 _/            ",
    "                              '-.._______...--'              ",
    "            .-----------.                                    ",
    "           /             \\         _..-'''-._                ",
    "           |   AFRICA    |       /           \\               ",
    "           \\             /       |   ASIA    |               ",
    "            '-----------'        \\           /               ",
    "                                  '-..___..-'                ",
];

// Simple fallback map if we can't get a better one
const FALLBACK_MAP: &str = r#"
       _..-'''-._                     _..-'''-._
     /           \                  /           \
    |  AMERICAS   |                |   EURASIA   |
    |             |       _        |             |
     \           /      /   \       \           /
      '-..___..-'      |AFRICA|      '-..___..-'
                        \ _ /
                               _..-'''-._
                             /           \
                            | AUSTRALIA   |
                             \           /
                              '-..___..-'
"#;

pub fn draw(f: &mut Frame, area: Rect, app: &mut App) {
    let mut map_buffer = vec![vec![' '; area.width as usize]; area.height as usize];

    // 1. Draw the world map base (simplified for now)
    let map_lines = FALLBACK_MAP.lines().collect::<Vec<_>>();
    for (y, line) in map_lines.iter().enumerate() {
        if y < area.height as usize {
            for (x, c) in line.chars().enumerate() {
                if x < area.width as usize {
                    map_buffer[y][x] = c;
                }
            }
        }
    }

    // 2. Plot nodes as blips
    for node in app.nodes.values() {
        if let Some((lat, lon)) = node.geo_loc {
            let (x, y) = project_lat_lon(lat, lon, area.width, area.height);
            if x < area.width as usize && y < area.height as usize {
                map_buffer[y][x] = 'X';
            }
        }
    }

    let mut map_string = String::new();
    for row in map_buffer {
        map_string.push_str(&row.iter().collect::<String>());
        map_string.push('\n');
    }

    let map_widget = Paragraph::new(map_string)
        .block(Block::default().title("World Map (Live Traffic)").borders(Borders::ALL))
        .style(Style::default().fg(Color::Green));

    f.render_widget(map_widget, area);
}

fn project_lat_lon(lat: f64, lon: f64, width: u16, height: u16) -> (usize, usize) {
    // Equirectangular projection
    let x = ((lon + 180.0) * (width as f64 / 360.0)) as usize;
    let y = ((90.0 - lat) * (height as f64 / 180.0)) as usize;
    (x, y)
}
