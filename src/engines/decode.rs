use base64::{Engine, prelude::BASE64_STANDARD};
use std::collections::HashSet;
use regex::Regex;

use crate::models::ScanResult;
use crate::network_iocs;
use crate::utils::is_threat;

pub fn hunt_plaintext_threats(content: &str, results: &mut ScanResult) {
    let mut seen_threats = HashSet::new();

    println!("\n--- [ PLAINTEXT THREAT SCAN ] ---");

    for line in content.lines() {
        let clean_line = line.trim();

        if is_threat(clean_line) && seen_threats.insert(clean_line.to_string()) {
            println!("[!] Plaintext IOC Detected: {}", clean_line);

            results.plaintext_iocs.push(clean_line.to_string());

            network_iocs(clean_line, results);
        }
    }
}

pub fn b64_decode_strings(content: &str, results: &mut ScanResult) {
    let b64_regex = Regex::new(r"[a-zA-Z0-9+/]{8,}=*").unwrap();

    for cap in b64_regex.captures_iter(content) {
        let candidate = &cap[0];

        if let Ok(decoded_bytes) = BASE64_STANDARD.decode(candidate) {
            let decoded_string = String::from_utf8_lossy(&decoded_bytes);
            let is_printable = decoded_bytes
                .iter()
                .all(|&b| (32..=126).contains(&b) || b == 10 || b == 13);

            if decoded_string.chars().any(|c| c.is_alphanumeric())
                && decoded_string.len() > 4
                && is_printable
            {
                let trimmed_string = decoded_string.trim().to_string();

                println!("[!] Base64 Detected: {}", candidate);
                println!("    ↳ Decoded: {}", trimmed_string);

                results
                    .base64_strings
                    .push((candidate.to_string(), trimmed_string.clone()));

                network_iocs(&trimmed_string, results);
            }
        }
    }
}
