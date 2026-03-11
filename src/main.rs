mod app;
mod config;
mod ui;
mod network;
mod geo;

use std::error::Error;
use crossbeam_channel::{unbounded, Receiver};
use clap::Parser;
use pnet::datalink;

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// Network interface to sniff on
    #[arg(short, long)]
    interface: Option<String>,

    /// List all available network interfaces
    #[arg(short, long)]
    list: bool,
}

fn main() -> Result<(), Box<dyn Error>> {
    let args = Args::parse();

    if args.list {
        println!("Available Interfaces:");
        for iface in datalink::interfaces() {
            if iface.is_up() && !iface.is_loopback() {
                println!(" - {}", iface.name);
            }
        }
        return Ok(());
    }

    let initial_interface = args.interface.unwrap_or_else(|| config::DEFAULT_INTERFACE.to_string());

    // Main event channel
    let (event_tx, event_rx) = unbounded::<app::AppEvent>();
    // Handshake channel for sniffer
    let (ready_tx, ready_rx) = unbounded::<String>();

    // Start Sniffer Manager
    let sniffer_manager = crate::network::sniffer::SnifferManager::new(
        event_tx.clone(),
        initial_interface,
        ready_tx
    );

    let detected_iface = ready_rx.recv().unwrap_or_else(|_| String::from("Unknown"));

    // Start Traceroute Manager
    let traceroute_manager = crate::network::traceroute::TracerouteManager::new(event_tx.clone());

    let mut app = app::App::new();
    app.active_interface = detected_iface;
    app.available_interfaces = datalink::interfaces().into_iter()
        .filter(|iface| iface.is_up() && !iface.is_loopback())
        .map(|iface| iface.name)
        .collect();

    let dns_resolver = crate::geo::resolver::DnsResolver::new();
    let geo_resolver = crate::geo::GeoResolver::new();

    // TUI main loop
    if let Err(e) = run_app_with_events(app, event_rx, dns_resolver, geo_resolver, traceroute_manager, sniffer_manager) {
        eprintln!("TUI error: {}", e);
    }

    Ok(())
}

fn run_app_with_events(
    mut app: app::App, 
    rx: Receiver<app::AppEvent>,
    dns: crate::geo::resolver::DnsResolver,
    geo: crate::geo::GeoResolver,
    traceroute: crate::network::traceroute::TracerouteManager,
    sniffer: crate::network::sniffer::SnifferManager,
) -> std::io::Result<()> {
    use ratatui::{backend::CrosstermBackend, Terminal};
    use crossterm::{
        event::{self, DisableMouseCapture, EnableMouseCapture, Event, KeyCode},
        execute,
        terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
    };
    use std::time::{Duration, Instant};

    enable_raw_mode()?;
    let mut stdout = std::io::stdout();
    execute!(stdout, EnterAlternateScreen, EnableMouseCapture)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    let tick_rate = Duration::from_millis(config::TICK_RATE_MS);
    let mut last_tick = Instant::now();

    loop {
        // Drain events
        while let Ok(event) = rx.try_recv() {
            match event {
                app::AppEvent::Packet(pkt) => {
                    let dest = pkt.dest;
                    let is_new = !app.nodes.contains_key(&dest);
                    app.add_event(pkt);
                    
                    if is_new && !crate::network::utils::is_local_ip(&dest) {
                        traceroute.trace(dest);
                    }
                }
                app::AppEvent::TracerouteUpdate(target, path) => {
                    app.update_path(target, path);
                }
                app::AppEvent::SwitchInterface(name) => {
                    app.active_interface = name;
                    app.clear_state();
                }
            }
        }

        // Perform DNS, Geo, and ASN lookups
        let unresolved_ips: Vec<_> = app.nodes.values()
            .filter(|n| !n.is_local && (n.hostname.is_none() || n.geo_loc.is_none() || n.asn.is_none()))
            .map(|n| n.ip)
            .take(5)
            .collect();

        for ip in unresolved_ips {
            if let Some(node) = app.nodes.get_mut(&ip) {
                if node.hostname.is_none() {
                    node.hostname = dns.resolve_ip(ip);
                }
                if node.geo_loc.is_none() {
                    node.geo_loc = geo.lookup(ip);
                }
                if node.asn.is_none() {
                    let (asn, org) = geo.lookup_asn(ip);
                    node.asn = asn;
                    node.organization = org;
                }
            }
        }

        terminal.draw(|f| crate::ui::draw_ui(f, &mut app))?;

        let timeout = tick_rate
            .checked_sub(last_tick.elapsed())
            .unwrap_or_else(|| Duration::from_secs(0));

        if crossterm::event::poll(timeout)? {
            if let Event::Key(key) = event::read()? {
                match app.input_mode {
                    app::InputMode::Normal => match key.code {
                        KeyCode::Char('q') => app.quit(),
                        KeyCode::Char('i') => app.input_mode = app::InputMode::InterfaceSelection,
                        KeyCode::Char('c') => app.clear_state(),
                        KeyCode::Char('p') => app.toggle_pause(),
                        KeyCode::Char('/') => app.input_mode = app::InputMode::Filter,
                        KeyCode::Down => app.next_traffic_item(),
                        KeyCode::Up => app.previous_traffic_item(),
                        KeyCode::Enter => app.input_mode = app::InputMode::Inspection,
                        _ => {}
                    },
                    app::InputMode::InterfaceSelection => match key.code {
                        KeyCode::Esc => app.input_mode = app::InputMode::Normal,
                        KeyCode::Up => {
                            if app.selected_interface_index > 0 {
                                app.selected_interface_index -= 1;
                            }
                        }
                        KeyCode::Down => {
                            if app.selected_interface_index < app.available_interfaces.len().saturating_sub(1) {
                                app.selected_interface_index += 1;
                            }
                        }
                        KeyCode::Enter => {
                            if let Some(name) = app.available_interfaces.get(app.selected_interface_index) {
                                let name = name.clone();
                                sniffer.switch_interface(name.clone());
                                app.active_interface = format!("Switching to {}...", name);
                                app.clear_state();
                                app.input_mode = app::InputMode::Normal;
                            }
                        }
                        _ => {}
                    },
                    app::InputMode::Inspection => match key.code {
                        KeyCode::Esc | KeyCode::Enter | KeyCode::Char('q') => {
                            app.input_mode = app::InputMode::Normal;
                        }
                        _ => {}
                    },
                    app::InputMode::Filter => match key.code {
                        KeyCode::Enter => {
                            app.active_filter = if app.filter_text.is_empty() { String::from("None") } else { app.filter_text.clone() };
                            sniffer.update_filter(app.filter_text.clone());
                            app.input_mode = app::InputMode::Normal;
                        }
                        KeyCode::Esc => {
                            app.filter_text.clear();
                            app.input_mode = app::InputMode::Normal;
                        }
                        KeyCode::Char(c) => app.filter_text.push(c),
                        KeyCode::Backspace => { app.filter_text.pop(); }
                        _ => {}
                    }
                }
            }
        }

        if last_tick.elapsed() >= tick_rate {
            app.on_tick();
            last_tick = Instant::now();
        }

        if app.should_quit {
            break;
        }
    }

    disable_raw_mode()?;
    execute!(
        terminal.backend_mut(),
        LeaveAlternateScreen,
        DisableMouseCapture
    )?;
    terminal.show_cursor()?;

    Ok(())
}
