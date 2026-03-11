use std::error::Error;
use std::io::{BufRead, BufReader, Write};
use std::process::{Command, Stdio};
use std::thread;
use crossbeam_channel::{unbounded, Receiver};
use clap::Parser;
use pnet::datalink;
use traceflow::app::{App, AppEvent, HelperCommand, InputMode, SecurityAlert};

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

    let initial_interface = args.interface.unwrap_or_else(|| String::from("any"));

    // Main event channel for UI
    let (event_tx, event_rx) = unbounded::<AppEvent>();

    // Spawn helper process
    let mut child = Command::new("traceflow-helper")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()
        .map_err(|e| format!("Failed to spawn traceflow-helper. Make sure it's in your PATH and has capabilities set. Error: {}", e))?;

    let mut stdin = child.stdin.take().ok_or("Failed to open helper stdin")?;
    let stdout = child.stdout.take().ok_or("Failed to open helper stdout")?;

    // Send initial interface command
    let init_cmd = HelperCommand::SwitchInterface(initial_interface);
    writeln!(stdin, "{}", serde_json::to_string(&init_cmd)?)?;

    // Thread to read events from helper stdout
    let event_tx_clone = event_tx.clone();
    thread::spawn(move || {
        let reader = BufReader::new(stdout);
        for line in reader.lines() {
            if let Ok(line) = line {
                if let Ok(event) = serde_json::from_str::<AppEvent>(&line) {
                    let _ = event_tx_clone.send(event);
                }
            }
        }
    });

    // We'll wrap stdin in a thread-safe way so UI can send commands
    let (cmd_tx, cmd_rx) = unbounded::<HelperCommand>();
    thread::spawn(move || {
        while let Ok(cmd) = cmd_rx.recv() {
            if let Ok(json) = serde_json::to_string(&cmd) {
                let _ = writeln!(stdin, "{}", json);
                let _ = stdin.flush();
            }
        }
    });

    let mut app = App::new();
    app.available_interfaces = datalink::interfaces().into_iter()
        .filter(|iface| iface.is_up() && !iface.is_loopback())
        .map(|iface| iface.name)
        .collect();

    let dns_resolver = traceflow::geo::resolver::DnsResolver::new();
    let geo_resolver = traceflow::geo::GeoResolver::new();

    // TUI main loop
    if let Err(e) = run_app_with_events(app, event_rx, dns_resolver, geo_resolver, cmd_tx) {
        eprintln!("TUI error: {}", e);
    }

    // Clean up child
    let _ = child.kill();

    Ok(())
}

fn run_app_with_events(
    mut app: App, 
    rx: Receiver<AppEvent>,
    dns: traceflow::geo::resolver::DnsResolver,
    geo: traceflow::geo::GeoResolver,
    cmd_tx: crossbeam_channel::Sender<HelperCommand>,
) -> std::io::Result<()> {
    use ratatui::{backend::CrosstermBackend, Terminal};
    use crossterm::{
        event::{self, DisableMouseCapture, EnableMouseCapture, Event, KeyCode, KeyModifiers},
        execute,
        terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
    };
    use std::time::{Duration, Instant};

    enable_raw_mode()?;
    let mut stdout = std::io::stdout();
    execute!(stdout, EnterAlternateScreen, EnableMouseCapture)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    let tick_rate = Duration::from_millis(traceflow::config::TICK_RATE_MS);
    let mut last_tick = Instant::now();

    loop {
        // Drain events
        while let Ok(event) = rx.try_recv() {
            match event {
                AppEvent::Packet(mut pkt) => {
                    if let Some(msg) = traceflow::security::SecurityHeuristics::scan(&mut pkt) {
                        app.add_alert(SecurityAlert {
                            message: msg,
                            protocol: pkt.protocol.clone(),
                            target: pkt.dest,
                        });
                    }

                    let dest = pkt.dest;
                    let is_new = !app.nodes.contains_key(&dest);
                    
                    app.add_event(pkt);
                    
                    // Note: Process mapping will be handled by UI thread periodically or by helper
                    // For now, let's keep it in UI thread but we could move it to helper.
                    
                    if is_new && !traceflow::network::utils::is_local_ip(&dest) {
                        let _ = cmd_tx.send(HelperCommand::Trace(dest));
                    }
                }
                AppEvent::TracerouteUpdate(target, path) => {
                    app.update_path(target, path);
                }
                AppEvent::SwitchInterface(name) => {
                    app.active_interface = name;
                    app.clear_state();
                }
                AppEvent::LanDeviceFound(device) => {
                    app.add_lan_device(device);
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

        terminal.draw(|f| traceflow::ui::draw_ui(f, &mut app))?;

        let timeout = tick_rate
            .checked_sub(last_tick.elapsed())
            .unwrap_or_else(|| Duration::from_secs(0));

        if crossterm::event::poll(timeout)? {
            if let Event::Key(key) = event::read()? {
                // Global hotkeys
                if key.modifiers.contains(KeyModifiers::CONTROL) && key.code == KeyCode::Char('s') {
                    let filename = format!("traceflow_{}.pcap", Instant::now().elapsed().as_secs());
                    let _ = cmd_tx.send(HelperCommand::SavePcap(filename));
                    continue;
                }

                match app.input_mode {
                    InputMode::Normal => match key.code {
                        KeyCode::Char('q') => app.quit(),
                        KeyCode::Char('i') => app.input_mode = InputMode::InterfaceSelection,
                        KeyCode::Char('c') => app.clear_state(),
                        KeyCode::Char('p') => app.toggle_pause(),
                        KeyCode::Char('l') => app.toggle_view(),
                        KeyCode::Char('/') => app.input_mode = InputMode::Filter,
                        KeyCode::Down => app.next_traffic_item(),
                        KeyCode::Up => app.previous_traffic_item(),
                        KeyCode::Enter => app.input_mode = InputMode::Inspection,
                        _ => {}
                    },
                    InputMode::InterfaceSelection => match key.code {
                        KeyCode::Esc => app.input_mode = InputMode::Normal,
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
                                let _ = cmd_tx.send(HelperCommand::SwitchInterface(name.clone()));
                                app.active_interface = format!("Switching to {}...", name);
                                app.clear_state();
                                app.input_mode = InputMode::Normal;
                            }
                        }
                        _ => {}
                    },
                    InputMode::Inspection => match key.code {
                        KeyCode::Esc | KeyCode::Enter | KeyCode::Char('q') => {
                            app.input_mode = InputMode::Normal;
                        }
                        _ => {}
                    },
                    InputMode::Filter => match key.code {
                        KeyCode::Enter => {
                            app.active_filter = if app.filter_text.is_empty() { String::from("None") } else { app.filter_text.clone() };
                            let _ = cmd_tx.send(HelperCommand::UpdateFilter(app.filter_text.clone()));
                            app.input_mode = InputMode::Normal;
                        }
                        KeyCode::Esc => {
                            app.filter_text.clear();
                            app.input_mode = InputMode::Normal;
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
