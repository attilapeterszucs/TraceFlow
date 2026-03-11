use crate::app::PacketEvent;

pub struct SecurityHeuristics;

impl SecurityHeuristics {
    pub fn scan(event: &mut PacketEvent) -> Option<String> {
        let mut flagged = false;
        let mut message = String::new();

        // 1. Cleartext Protocol Checks
        if let Some(port) = event.dst_port.or(event.src_port) {
            match port {
                21 => { flagged = true; message = "Insecure FTP Connection".to_string(); }
                23 => { flagged = true; message = "Insecure Telnet Session".to_string(); }
                80 => { flagged = true; message = "Cleartext HTTP Traffic".to_string(); }
                110 => { flagged = true; message = "Cleartext POP3 Email".to_string(); }
                143 => { flagged = true; message = "Cleartext IMAP Email".to_string(); }
                _ => {}
            }
        }

        // 2. Darknet / Privacy Tools (Common ports)
        if !flagged {
            if let Some(port) = event.dst_port.or(event.src_port) {
                match port {
                    9001 | 9030 => { flagged = true; message = "Tor Relay Traffic Detected".to_string(); }
                    1194 | 51820 => { flagged = true; message = "VPN Tunnel Activity".to_string(); }
                    _ => {}
                }
            }
        }

        // 3. Payload inspection (Sample cleartext signatures)
        if !flagged && !event.raw_payload.is_empty() {
            let payload_str = String::from_utf8_lossy(&event.raw_payload).to_uppercase();
            if payload_str.contains("USER ") || payload_str.contains("PASS ") || payload_str.contains("LOGIN") {
                flagged = true;
                message = "Possible Credential Leakage".to_string();
            }
        }

        event.is_flagged = flagged;
        if flagged {
            Some(message)
        } else {
            None
        }
    }
}
