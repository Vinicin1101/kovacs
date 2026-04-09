use regex::Regex;
use std::collections::HashMap;

use crate::models::ScanResult;
use crate::network_iocs;
use crate::utils::is_threat;

// (?i) - Case-insensitive
// (\w+) - Var name
// \s*=\s* - Equals sign
// "([^"]+)" - String obfuscated
// [\s\S]{1,200}? - Limit to 200 chars
// StrReverse\(\1\) - StrReverse with a backreference to the variable name
pub fn hunt_script_obfuscation(content: &str, results: &mut ScanResult) {
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
pub fn hunt_stateful_obfuscation(content: &str, results: &mut ScanResult) {
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
                        && let Ok(ascii_num) = chr_cap[1].parse::<u8>()
                    {
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

pub fn hunt_array_obfuscation(content: &str, results: &mut ScanResult) {
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
