pub struct ScanResult {
    pub urls: Vec<String>,
    pub ips: Vec<String>,
    
    // (Original, Descodificado)
    pub base64_strings: Vec<(String, String)>,
    pub reversed_strings: Vec<(String, String)>,

    pub array_strings: Vec<String>,
    pub plaintext_iocs: Vec<String>,
}

impl ScanResult {
    pub fn new() -> Self {
        ScanResult {
            urls: Vec::new(),
            ips: Vec::new(),
            base64_strings: Vec::new(),
            reversed_strings: Vec::new(),
            array_strings: Vec::new(),
            plaintext_iocs: Vec::new(),
        }
    }
}