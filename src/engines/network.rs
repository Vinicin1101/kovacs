use regex::Regex;

use crate::models::ScanResult;

pub fn network_iocs(content: &str, results: &mut ScanResult) {
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