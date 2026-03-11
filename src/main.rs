mod app;
mod config;
mod ui;
mod network;
mod geo;

use std::error::Error;
use std::thread;
use crossbeam_channel::{unbounded, Receiver};
use nix::unistd::{setgid, setuid, Uid, User};
use clap::Parser;
use pnet::datalink;

fn drop_privileges() -> Result<(), Box<dyn Error>> {
    let current_uid = Uid::current();
    if current_uid.is_root() {
        let nobody = User::from_name(config::FALLBACK_USER)?
            .ok_or("Could not find fallback user")?;
        
        setgid(nobody.gid)?;
        setuid(nobody.uid)?;
        println!("Privileges dropped successfully.");
    }
    Ok(())
}

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

    let selected_interface = match args.interface {
        Some(name) => name,
        None => {
            let interfaces = datalink::interfaces();
            let auto = interfaces.into_iter()
                .find(|e| e.is_up() && !e.is_loopback() && (e.name.starts_with('e') || e.name.starts_with('w')))
                .map(|e| e.name);
            
            match auto {
                Some(name) => {
                    eprintln!("Auto-detected interface: {}. Use -i <iface> to specify manually.", name);
                    name
                }
                None => {
                    eprintln!("Error: No interface specified and could not auto-detect. Use -l to list interfaces.");
                    std::process::exit(1);
                }
            }
        }
    };

    // Main event channel
    let (event_tx, event_rx) = unbounded::<app::AppEvent>();
    // Handshake channel for sniffer
    let (ready_tx, ready_rx) = unbounded::<String>();

    // Start sniffer
    let sniffer_tx = event_tx.clone();
    let thread_iface = selected_interface.clone();
    thread::spawn(move || {
        let (pkt_tx, pkt_rx) = unbounded::<app::PacketEvent>();
        let sniffer_event_tx = sniffer_tx.clone();
        
        thread::spawn(move || {
            while let Ok(pkt) = pkt_rx.recv() {
                let _ = sniffer_event_tx.send(app::AppEvent::Packet(pkt));
            }
        });

        network::sniffer::start_sniffing(pkt_tx, &thread_iface, ready_tx);
    });

    let detected_iface = ready_rx.recv().unwrap_or_else(|_| String::from("Unknown"));

    // Start Traceroute Manager
    let traceroute_manager = crate::network::traceroute::TracerouteManager::new(event_tx.clone());

    let _ = drop_privileges();

    let mut app = app::App::new();
    app.active_interface = detected_iface;

    let dns_resolver = crate::geo::resolver::DnsResolver::new();
    let geo_resolver = crate::geo::GeoResolver::new();

    // TUI main loop
    if let Err(e) = run_app_with_events(app, event_rx, dns_resolver, geo_resolver, traceroute_manager) {
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
            }
        }

        // Perform DNS and Geo lookups
        let unresolved_ips: Vec<_> = app.nodes.values()
            .filter(|n| !n.is_local && (n.hostname.is_none() || n.geo_loc.is_none()))
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
            }
        }

        terminal.draw(|f| crate::ui::draw_ui(f, &mut app))?;

        let timeout = tick_rate
            .checked_sub(last_tick.elapsed())
            .unwrap_or_else(|| Duration::from_secs(0));

        if crossterm::event::poll(timeout)? {
            if let Event::Key(key) = event::read()? {
                if let KeyCode::Char('q') = key.code {
                    app.quit();
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
