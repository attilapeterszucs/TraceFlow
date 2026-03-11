use std::io::{self, BufRead, Write};
use crossbeam_channel::unbounded;
use traceflow::app::{AppEvent, HelperCommand};
use std::thread;
use traceflow::network::sniffer::SnifferManager;
use traceflow::network::traceroute::TracerouteManager;
use traceflow::network::lan::LanScanner;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let (event_tx, event_rx) = unbounded::<AppEvent>();
    let (cmd_tx, cmd_rx) = unbounded::<HelperCommand>();

    // Thread to read commands from stdin
    let cmd_tx_clone = cmd_tx.clone();
    thread::spawn(move || {
        let stdin = io::stdin();
        for line in stdin.lock().lines() {
            if let Ok(line) = line {
                if let Ok(cmd) = serde_json::from_str::<HelperCommand>(&line) {
                    let _ = cmd_tx_clone.send(cmd);
                }
            }
        }
    });

    // Thread to write events to stdout
    thread::spawn(move || {
        let mut stdout = io::stdout();
        while let Ok(event) = event_rx.recv() {
            if let Ok(json) = serde_json::to_string(&event) {
                let _ = writeln!(stdout, "{}", json);
                let _ = stdout.flush();
            }
        }
    });

    // Sniffer Manager
    let (ready_tx, _ready_rx) = unbounded::<String>();
    let sniffer = SnifferManager::new(event_tx.clone(), "any".to_string(), ready_tx);
    
    // Traceroute Manager
    let traceroute = TracerouteManager::new(event_tx.clone());
    
    // LAN Scanner
    let _lan = LanScanner::new(event_tx.clone());

    // Process commands from main app
    while let Ok(cmd) = cmd_rx.recv() {
        match cmd {
            HelperCommand::SwitchInterface(name) => {
                sniffer.switch_interface(name);
            }
            HelperCommand::UpdateFilter(filter) => {
                sniffer.update_filter(filter);
            }
            HelperCommand::Trace(target) => {
                traceroute.trace(target);
            }
            HelperCommand::SavePcap(filename) => {
                sniffer.save_pcap(filename);
            }
        }
    }
    
    Ok(())
}
