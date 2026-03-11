use std::collections::HashMap;

pub fn lookup_service(port: u16) -> Option<String> {
    let mut db = HashMap::new();
    
    // System Ports
    db.insert(20, "FTP-Data");
    db.insert(21, "FTP-Control");
    db.insert(22, "SSH");
    db.insert(23, "Telnet");
    db.insert(25, "SMTP");
    db.insert(53, "DNS");
    db.insert(67, "DHCP-Server");
    db.insert(68, "DHCP-Client");
    db.insert(69, "TFTP");
    db.insert(80, "HTTP");
    db.insert(110, "POP3");
    db.insert(123, "NTP");
    db.insert(143, "IMAP");
    db.insert(161, "SNMP");
    db.insert(179, "BGP");
    db.insert(389, "LDAP");
    db.insert(443, "HTTPS");
    db.insert(445, "SMB");
    db.insert(514, "Syslog");
    db.insert(587, "SMTP-Submit");
    db.insert(636, "LDAPS");
    db.insert(993, "IMAPS");
    db.insert(995, "POP3S");

    // Registered Ports
    db.insert(1433, "MSSQL");
    db.insert(1521, "Oracle");
    db.insert(2049, "NFS");
    db.insert(3306, "MySQL");
    db.insert(3389, "RDP");
    db.insert(5060, "SIP");
    db.insert(5061, "SIPS");
    db.insert(5432, "PostgreSQL");
    db.insert(5900, "VNC");
    db.insert(6379, "Redis");
    db.insert(8080, "HTTP-Alt");
    db.insert(8443, "HTTPS-Alt");
    db.insert(9001, "Tor-Relay");
    db.insert(9030, "Tor-Dir");
    db.insert(51820, "WireGuard");

    db.get(&port).map(|s| s.to_string())
}
