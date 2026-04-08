use base64::{Engine, prelude::BASE64_STANDARD};
use goblin::Object;
use regex::Regex;
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::collections::HashSet;
use std::env;
use std::fs;

struct ScanResult {
    urls: Vec<String>,
    ips: Vec<String>,
    // (Original, Descodificado)
    base64_strings: Vec<(String, String)>,
    reversed_strings: Vec<(String, String)>,
    array_strings: Vec<String>,
}

impl ScanResult {
    fn new() -> Self {
        ScanResult {
            urls: Vec::new(),
            ips: Vec::new(),
            base64_strings: Vec::new(),
            reversed_strings: Vec::new(),
            array_strings: Vec::new(),
        }
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let app_name = env!("CARGO_PKG_NAME");
    let base_path = dirs::data_local_dir()
        .ok_or("Can't find local data directory")?
        .join(app_name);

    let evidence_dir = base_path.join("evidences");
    fs::create_dir_all(&evidence_dir)?;

    let arguments: Vec<String> = env::args().collect();
    let target = arguments.get(1).ok_or("Use: kovacs <file_path>")?;
    let pwd = env::current_dir()?;
    let artifact_path = pwd.join(target);
    let buffer = fs::read(&artifact_path)?;

    // Fingerprint - No compromises.
    let mut hasher = Sha256::new();
    hasher.update(&buffer);
    let hash_string = hex::encode(hasher.finalize());
    let hash_result = hash_string.to_string();

    let temp_evidence = evidence_dir.join("finger_evidence.tmp");
    let evidence_path = evidence_dir.join(format!("{}.evidence", hash_result));

    // Hunt for IOCs
    let scan_results = hunt_iocs(&buffer);

    let mut evidence_content = format!(
        "--- [ KOVACS EVIDENCE REPORT ] ---\n\
         - Target: {:?}\n\
         - SHA256: {}\n\n",
        artifact_path.file_name().unwrap(),
        hash_result
    );

    evidence_content.push_str("--- [ NETWORK IOCs ] ---\n");
    for ip in &scan_results.ips {
        evidence_content.push_str(&format!("IP: {}\n", ip));
    }
    for url in &scan_results.urls {
        evidence_content.push_str(&format!("URL: {}\n", url));
    }

    evidence_content.push_str("\n--- [ DECODED BASE64 ] ---\n");
    for (orig, dec) in &scan_results.base64_strings {
        evidence_content.push_str(&format!("Original: {}\n↳ Decoded: {}\n", orig, dec));
    }

    evidence_content.push_str("\n--- [ OBFUSCATED STRINGS (StrReverse) ] ---\n");
    for (orig, dec) in &scan_results.reversed_strings {
        evidence_content.push_str(&format!("Original: {}\n↳ Reversed: {}\n", orig, dec));
    }

    // Save evidence
    fs::write(&temp_evidence, &evidence_content)?;
    fs::rename(&temp_evidence, &evidence_path)?;
    println!("Evidence saved: {:?}", evidence_path);

    // Binary analysis with goblin
    match Object::parse(&buffer)? {
        Object::PE(pe) => {
            println!("    Format: Windows PE");
            println!("     - Sections:");

            for import in pe.imports {
                if import.dll.contains("wininet") || import.dll.contains("advapi32") {
                    println!("    [!] Alert: {}", import.name);
                    println!("    [!] Suspicious DLL: {}", import.dll);
                }
            }
        }

        Object::Elf(elf) => {
            println!("    Format: Linux ELF");
            println!("     - Sections:");
            for section in elf.section_headers {
                println!(
                    "    - {} (Type: {}, Flags: {}, Address: {}, Offset: {}, Size: {})",
                    section.sh_name,
                    section.sh_type,
                    section.sh_flags,
                    section.sh_addr,
                    section.sh_offset,
                    section.sh_size
                );
            }
        }
        _ => println!("    Unknown format."),
    }

    Ok(())
}

fn hunt_iocs(buffer: &[u8]) -> ScanResult {
    let content = String::from_utf8_lossy(buffer);
    let mut results = ScanResult::new();

    network_iocs(&content, &mut results);
    b64_decode_strings(&content, &mut results);
    hunt_plaintext_threats(&content, &mut results);
    hunt_script_obfuscation(&content, &mut results);
    hunt_stateful_obfuscation(&content, &mut results);
    hunt_array_obfuscation(&content, &mut results);

    results
}

fn network_iocs(content: &str, results: &mut ScanResult) {
    let url_regex = Regex::new(r"https?://[^\s/$.?#].[^\s]*").unwrap();
    let ip_regex = Regex::new(r"\b(?:\d{1,3}\.){3}\d{1,3}\b").unwrap();

    for url in url_regex.find_iter(content) {
        let found_url = url.as_str().to_string();
        println!("[!] URL Detected: {}", found_url);
        if !results.urls.contains(&found_url) {
            results.urls.push(found_url);
        }
    }

    for ip in ip_regex.find_iter(content) {
        let found_ip = ip.as_str().to_string();
        println!("[!] IP Detected: {}", found_ip);
        if !results.ips.contains(&found_ip) {
            results.ips.push(found_ip);
        }
    }
}

fn b64_decode_strings(content: &str, results: &mut ScanResult) {
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

// (?i) - Case-insensitive
// (\w+) - Var name
// \s*=\s* - Equals sign
// "([^"]+)" - String obfuscated
// [\s\S]{1,200}? - Limit to 200 chars
// StrReverse\(\1\) - StrReverse with a backreference to the variable name
fn hunt_script_obfuscation(content: &str, results: &mut ScanResult) {
    let reverse_pattern =
        Regex::new(r#"(?i)(\w+)\s*=\s*"([^"]+)"[\s\S]{1,200}?StrReverse\((\w+)\)"#).unwrap();

    for cap in reverse_pattern.captures_iter(content) {
        let var_decl = &cap[1];
        let original_obfuscated = &cap[2];
        let var_reversed = &cap[3];

        if var_decl == var_reversed {
            let decoded: String = original_obfuscated.chars().rev().collect();

            if is_threat(&decoded) {
                println!("[!] StrReverse Threat: {}", decoded);
                results
                    .reversed_strings
                    .push((original_obfuscated.to_string(), decoded.clone()));
                network_iocs(&decoded.to_lowercase(), results);
            }
        }
    }
}

// Memory to storage var and strings definition
fn hunt_stateful_obfuscation(content: &str, results: &mut ScanResult) {
    let mut memory: HashMap<String, String> = HashMap::new();

    // Var declaration
    let assignment_regex = Regex::new(r"(?i)([a-z_][a-z0-9_]*)\s*=\s*(.+)").unwrap();
    let string_literal_regex = Regex::new(r#""([^"]*)""#).unwrap();

    // Chr(119)
    let chr_regex = Regex::new(r"(?i)chr\s*\(\s*(\d+)\s*\)").unwrap();

    for chunk in content.split(['\n', '\r', ':']) {
        let clean_chunk = chunk.trim();
        if clean_chunk.is_empty() {
            continue;
        }

        if let Some(cap) = assignment_regex.captures(clean_chunk) {
            let var_name = cap[1].to_lowercase();
            let expression = &cap[2];

            let mut resolved_value = String::new();

            // Concat
            let parts: Vec<&str> = expression.split(['&', '+']).collect();

            for part in parts {
                let part_trimmed = part.trim();

                if part_trimmed.starts_with('"') && part_trimmed.ends_with('"') {
                    if let Some(str_cap) = string_literal_regex.captures(part_trimmed) {
                        resolved_value.push_str(&str_cap[1]);
                    } else if let Some(chr_cap) = chr_regex.captures(part_trimmed)
                        && let Ok(ascii_num) = chr_cap[1].parse::<u8>() {
                            resolved_value.push(ascii_num as char);
                        }
                } else {
                    let var_key = part_trimmed.to_lowercase();
                    if let Some(known_value) = memory.get(&var_key) {
                        resolved_value.push_str(known_value);
                    }
                }
            }

            if !resolved_value.is_empty() {
                memory.insert(var_name.clone(), resolved_value.clone());

                if !resolved_value.is_empty() {
                    memory.insert(var_name.clone(), resolved_value.clone());

                    if is_threat(&resolved_value) {
                        println!("\n--- [ OBFUSCATION DETECTED (Stateful) ] ---");
                        println!("[!] Resolved Concatenation!");
                        println!("    ↳ Variable: {}", var_name);
                        println!("    ↳ Payload:  {}", resolved_value);

                        network_iocs(&resolved_value.to_lowercase(), results);
                    }
                }
            }
        }
    }
}

fn hunt_array_obfuscation(content: &str, results: &mut ScanResult) {
    let array_regex = Regex::new(r"(?i)Array\s*\(([^)]+)\)").unwrap();

    let mut extracted_arrays: Vec<Vec<i32>> = Vec::new();

    for cap in array_regex.captures_iter(content) {
        let inner_content = &cap[1];
        let mut numbers = Vec::new();

        for part in inner_content.split(',') {
            let clean_part = part.trim().to_uppercase().replace("&H", ""); // Remove espaços e o &H

            if let Ok(num) = i32::from_str_radix(&clean_part, 16) {
                numbers.push(num);
            } else if let Ok(num) = clean_part.parse::<i32>() {
                numbers.push(num);
            }
        }

        if numbers.len() >= 5 {
            extracted_arrays.push(numbers);
        }
    }

    for i in 0..extracted_arrays.len() {
        if i + 1 < extracted_arrays.len() {
            let arr1 = &extracted_arrays[i];
            let arr2 = &extracted_arrays[i + 1];

            let mut shifted_str = String::new();
            let min_len = arr1.len().min(arr2.len());

            for j in 0..min_len {
                let val = arr1[j] + arr2[j];

                if (32..=126).contains(&val) {
                    shifted_str.push(val as u8 as char);
                }
            }

            if is_threat(&shifted_str) {
                println!("\n--- [ OBFUSCATION DETECTED (Array Math) ] ---");
                println!("[!] Array Shift Decoded: {}", shifted_str);

                results.array_strings.push(shifted_str.clone());

                network_iocs(&shifted_str.to_lowercase(), results);
            }
        }
    }
}

fn hunt_plaintext_threats(content: &str, results: &mut ScanResult) {
    let mut seen_threats = HashSet::new();

    println!("\n--- [ PLAINTEXT THREAT SCAN ] ---");

    for line in content.lines() {
        let clean_line = line.trim();

        if is_threat(clean_line)
            && seen_threats.insert(clean_line.to_string()) {
                println!("[!] Plaintext IOC Detected: {}", clean_line);

                // results.plaintext_iocs.push(clean_line.to_string());

                network_iocs(clean_line, results);
            }
    }
}

fn is_threat(text: &str) -> bool {
    let text_lower = text.to_lowercase();

    let suspicious_keywords = [
        "http",
        "wscript",
        "powershell",
        "winmgmts",
        "select *",
        "shell",
        "xmlhttp",
        "root\\cimv2",
        "cmd.exe",
        "eval",
        "execute",
        "scripting.filesystemobject",
        "wmic",
        "certutil",
        "bitsadmin",
        "exec",
        "schtasks",
    ];

    text.len() >= 5 && suspicious_keywords.iter().any(|&k| text_lower.contains(k))
}
