pub fn is_threat(text: &str) -> bool {
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
