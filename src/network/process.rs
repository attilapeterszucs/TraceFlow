use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use std::thread;
use procfs::process::{all_processes, FDTarget};
use notify::{Watcher, RecursiveMode, Config};

pub struct ProcessMapper {
    cache: Arc<Mutex<HashMap<(String, u16), String>>>,
}

impl ProcessMapper {
    pub fn new() -> Self {
        let cache = Arc::new(Mutex::new(HashMap::new()));
        let cache_clone = Arc::clone(&cache);

        thread::spawn(move || {
            // Initial build
            if let Ok(new_map) = build_process_map() {
                let mut lock = cache_clone.lock().unwrap();
                *lock = new_map;
            }

            // Set up watch on /proc/net
            let (tx, rx) = std::sync::mpsc::channel();
            let mut watcher = notify::RecommendedWatcher::new(tx, Config::default()).unwrap();
            
            // Note: On Linux, watching /proc directly might be tricky depending on the kernel version.
            // Some systems don't support inotify on procfs well.
            // If it fails, we fallback to polling.
            
            if watcher.watch(std::path::Path::new("/proc/net"), RecursiveMode::Recursive).is_ok() {
                for _ in rx {
                    if let Ok(new_map) = build_process_map() {
                        let mut lock = cache_clone.lock().unwrap();
                        *lock = new_map;
                    }
                }
            } else {
                // Fallback to polling every 2s
                loop {
                    if let Ok(new_map) = build_process_map() {
                        let mut lock = cache_clone.lock().unwrap();
                        *lock = new_map;
                    }
                    thread::sleep(Duration::from_secs(2));
                }
            }
        });

        Self { cache }
    }

    pub fn get_process(&self, protocol: &str, port: u16) -> Option<String> {
        let lock = self.cache.lock().unwrap();
        lock.get(&(protocol.to_string(), port)).cloned()
    }
}

fn build_process_map() -> Result<HashMap<(String, u16), String>, Box<dyn std::error::Error>> {
    let mut inode_to_proc = HashMap::new();

    for process in all_processes()? {
        if let Ok(p) = process {
            let comm = p.stat().map(|s| s.comm).unwrap_or_default();
            if let Ok(fds) = p.fd() {
                for fd in fds.flatten() {
                    if let FDTarget::Socket(inode) = fd.target {
                        inode_to_proc.insert(inode, comm.clone());
                    }
                }
            }
        }
    }

    let mut result = HashMap::new();

    if let Ok(tcp) = procfs::net::tcp() {
        for entry in tcp {
            if let Some(comm) = inode_to_proc.get(&entry.inode) {
                result.insert(("TCP".to_string(), entry.local_address.port()), comm.clone());
            }
        }
    }
    if let Ok(tcp6) = procfs::net::tcp6() {
        for entry in tcp6 {
            if let Some(comm) = inode_to_proc.get(&entry.inode) {
                result.insert(("TCP".to_string(), entry.local_address.port()), comm.clone());
            }
        }
    }
    if let Ok(udp) = procfs::net::udp() {
        for entry in udp {
            if let Some(comm) = inode_to_proc.get(&entry.inode) {
                result.insert(("UDP".to_string(), entry.local_address.port()), comm.clone());
            }
        }
    }
    if let Ok(udp6) = procfs::net::udp6() {
        for entry in udp6 {
            if let Some(comm) = inode_to_proc.get(&entry.inode) {
                result.insert(("UDP".to_string(), entry.local_address.port()), comm.clone());
            }
        }
    }

    Ok(result)
}
