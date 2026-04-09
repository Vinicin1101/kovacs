use goblin::Object;
use sha2::{Digest, Sha256};
use std::env;
use std::fs;

// Declara os módulos do projeto
mod models;
mod utils;
mod engines;

// Importa o que precisa usar
use models::ScanResult;
use engines::network::network_iocs;
use engines::decode::{b64_decode_strings, hunt_plaintext_threats};
use engines::obfus::{hunt_script_obfuscation, hunt_stateful_obfuscation, hunt_array_obfuscation};

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

    evidence_content.push_str("\n--- [ OBFUSCATION DETECTED (StrReverse) ] ---\n");
    for (orig, dec) in &scan_results.reversed_strings {
        evidence_content.push_str(&format!("Original: {}\n↳ Reversed: {}\n", orig, dec));
    }

    evidence_content.push_str("\n--- [ OBFUSCATION DETECTED (Array Math) ] ---\n");
    for str in &scan_results.array_strings {
        evidence_content.push_str(&format!("Array Shift Decoded: {}\\n", str));
    }

    evidence_content.push_str("\n--- [ PLAINTEXT THREAT SCAN ] ---\n");
    for str in &scan_results.plaintext_iocs {
        evidence_content.push_str(&format!("Plaintext IOC Detected: {}\n", str));
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

pub fn hunt_iocs(buffer: &[u8]) -> ScanResult {
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