use crate::app::PacketEvent;

pub struct SecurityHeuristics;

impl SecurityHeuristics {
    pub fn scan(event: &mut PacketEvent) {
        let mut flagged = false;

        // 1. Cleartext Protocol Checks
        if let Some(port) = event.dst_port.or(event.src_port) {
            match port {
                80 => flagged = true,   // HTTP
                21 => flagged = true,   // FTP
                23 => flagged = true,   // Telnet
                110 => flagged = true,  // POP3
                143 => flagged = true,  // IMAP (Cleartext)
                _ => {}
            }
        }

        // 2. Darknet / Privacy Tools (Common ports)
        if let Some(port) = event.dst_port.or(event.src_port) {
            match port {
                9001 | 9030 => flagged = true, // Tor
                1194 | 51820 => flagged = true, // VPN (OpenVPN/WireGuard)
                _ => {}
            }
        }

        // 3. Payload inspection (Sample cleartext signatures)
        if !flagged && !event.raw_payload.is_empty() {
            let payload_str = String::from_utf8_lossy(&event.raw_payload).to_uppercase();
            if payload_str.contains("USER ") || payload_str.contains("PASS ") || payload_str.contains("LOGIN") {
                flagged = true;
            }
        }

        event.is_flagged = flagged;
    }
}
