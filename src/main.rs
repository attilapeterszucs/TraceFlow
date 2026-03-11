mod app;
mod config;
mod ui;
mod network;
mod geo;

use std::error::Error;
use std::thread;
use crossbeam_channel::unbounded;
use nix::unistd::{setgid, setuid, Uid, User};

fn drop_privileges() -> Result<(), Box<dyn Error>> {
    let current_uid = Uid::current();
    if current_uid.is_root() {
        let nobody = User::from_name(config::FALLBACK_USER)?
            .ok_or("Could not find fallback user")?;
        
        // Change group
        setgid(nobody.gid)?;
        // Change user
        setuid(nobody.uid)?;
        println!("Privileges dropped successfully.");
    }
    Ok(())
}

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

    let selected_interface = match args.interface {
        Some(name) => name,
        None => {
            // Auto-detect as a fallback, but inform the user.
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

    // Channel for packet events from the sniffer thread to the main app thread
    let (tx, rx) = unbounded();
    // Handshake channel to ensure sniffer binds root socket before dropping privileges
    let (ready_tx, ready_rx) = unbounded::<String>();

    // Start sniffer on a separate thread (needs privileges initially if run as root)
    let thread_iface = selected_interface.clone();
    thread::spawn(move || {
        network::sniffer::start_sniffing(tx, &thread_iface, ready_tx);
    });

    // WAIT FOR SNIFFER READY: Handshake ensures the socket is bound as root.
    let detected_iface = ready_rx.recv().unwrap_or_else(|_| String::from("Unknown"));

    // Now safe to drop privileges
    let _ = drop_privileges();

    let mut app = app::App::new();
    app.active_interface = detected_iface;

    let dns_resolver = crate::geo::resolver::DnsResolver::new();
    let geo_resolver = crate::geo::GeoResolver::new();

    // TUI main loop
    if let Err(e) = run_app_with_rx(app, rx, dns_resolver, geo_resolver) {
        eprintln!("TUI error: {}", e);
    }

    Ok(())
}

fn run_app_with_rx(
    mut app: app::App, 
    rx: crossbeam_channel::Receiver<app::PacketEvent>,
    dns: crate::geo::resolver::DnsResolver,
    geo: crate::geo::GeoResolver,
) -> std::io::Result<()> {
    // Wrapper around ui::run_app that drains the receiver every tick
    
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
            app.add_event(event);
        }

        // Perform DNS and Geo lookups for nodes missing them (one at a time to stay responsive)
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
