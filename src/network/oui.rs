use std::collections::HashMap;

pub fn lookup_vendor(mac: &str) -> Option<String> {
    let prefix = mac.replace(':', "").to_uppercase();
    if prefix.len() < 6 { return None; }
    let oui = &prefix[0..6];

    let mut db = HashMap::new();
    // Top 50 Common OUIs (Sample)
    db.insert("00000C", "Cisco Systems");
    db.insert("0005CD", "Apple");
    db.insert("000C29", "VMware");
    db.insert("0010FA", "Apple");
    db.insert("001422", "Dell");
    db.insert("00163E", "Xen");
    db.insert("001C42", "Parallels");
    db.insert("002170", "Dell");
    db.insert("0024D7", "Intel");
    db.insert("002590", "Super Micro");
    db.insert("0026BB", "Apple");
    db.insert("005056", "VMware");
    db.insert("0090F5", "Apple");
    db.insert("080027", "Oracle (VirtualBox)");
    db.insert("186024", "HP");
    db.insert("28D244", "Apple");
    db.insert("34159E", "Apple");
    db.insert("3C5282", "Apple");
    db.insert("406C8F", "Apple");
    db.insert("44D832", "Apple");
    db.insert("482C6A", "Apple");
    db.insert("50BC8F", "Apple");
    db.insert("54E43A", "Apple");
    db.insert("5855CA", "Apple");
    db.insert("600308", "Apple");
    db.insert("640980", "Apple");
    db.insert("685B35", "Apple");
    db.insert("701124", "Apple");
    db.insert("784F43", "Apple");
    db.insert("804971", "Apple");
    db.insert("843835", "Apple");
    db.insert("8866A5", "Apple");
    db.insert("90B21F", "Apple");
    db.insert("9801A7", "Apple");
    db.insert("A45E60", "Apple");
    db.insert("AC87A3", "Apple");
    db.insert("B03495", "Apple");
    db.insert("B8F6B1", "Apple");
    db.insert("BC926B", "Apple");
    db.insert("C42C03", "Apple");
    db.insert("CC08E0", "Apple");
    db.insert("D022BE", "Apple");
    db.insert("D49A20", "Apple");
    db.insert("D83062", "Apple");
    db.insert("E0ACCB", "Apple");
    db.insert("E425E7", "Apple");
    db.insert("E8040B", "Apple");
    db.insert("EC3586", "Apple");
    db.insert("F01898", "Apple");
    db.insert("F40F24", "Apple");
    db.insert("F82793", "Apple");
    db.insert("FC253F", "Apple");
    db.insert("D83873", "Tesla");
    db.insert("000142", "Cisco");
    db.insert("00040D", "Avaya");
    db.insert("0007E9", "Intel");
    db.insert("000B82", "Avaya");
    db.insert("000CE7", "Avaya");
    db.insert("001143", "Dell");
    db.insert("001372", "Dell");
    db.insert("0015C5", "Dell");
    db.insert("00188B", "Dell");
    db.insert("001A4B", "Hewlett Packard");
    db.insert("001B78", "Hewlett Packard");
    db.insert("001E0B", "Hewlett Packard");
    db.insert("00219B", "Dell");
    db.insert("0023AE", "Dell");
    db.insert("002564", "Dell");
    db.insert("0026B9", "Dell");

    db.get(oui).map(|s| s.to_string())
}
