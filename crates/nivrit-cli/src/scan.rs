//! Client-side secret scanning. Walks a directory tree and flags hard-coded
//! credentials with a curated set of high-signal regexes.
//!
//! ponytail: regex-only over the working tree. No entropy heuristics and no git
//! history walk — add those (or the `ignore` crate for .gitignore support) if the
//! false-negative rate proves too high in practice.

use regex::Regex;
use std::path::Path;

pub struct Finding {
    pub path: String,
    pub line: usize,
    pub rule: String,
    pub masked: String,
}

struct Rule {
    name: &'static str,
    re: Regex,
}

// High-signal patterns: each has a distinctive prefix/structure, so false
// positives are rare. Deliberately omits "generic API key" assignment matching,
// which is noisy without entropy scoring.
fn rules() -> Vec<Rule> {
    let pats: &[(&str, &str)] = &[
        (
            "Private Key",
            r"-----BEGIN (?:RSA |EC |OPENSSH |PGP |DSA )?PRIVATE KEY-----",
        ),
        ("AWS Access Key", r"\bAKIA[0-9A-Z]{16}\b"),
        ("GitHub Token", r"\bgh[pousr]_[0-9A-Za-z]{36,}\b"),
        ("Slack Token", r"\bxox[baprs]-[0-9A-Za-z-]{10,}\b"),
        ("Google API Key", r"\bAIza[0-9A-Za-z_\-]{35}\b"),
        ("Stripe Secret Key", r"\b(?:sk|rk)_live_[0-9A-Za-z]{24,}\b"),
        (
            "SendGrid API Key",
            r"\bSG\.[0-9A-Za-z_\-]{22}\.[0-9A-Za-z_\-]{43}\b",
        ),
        (
            "JWT",
            r"\beyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\b",
        ),
    ];
    pats.iter()
        .map(|(name, p)| Rule {
            name,
            re: Regex::new(p).expect("static scan pattern must compile"),
        })
        .collect()
}

const SKIP_DIRS: &[&str] = &[
    ".git",
    "node_modules",
    "target",
    "dist",
    "build",
    "vendor",
    ".venv",
    "venv",
];
const MAX_FILE_BYTES: u64 = 5 * 1024 * 1024;

/// Reveal only the first 4 chars so findings are actionable without printing the
/// full secret into terminal/CI logs.
fn mask(m: &str) -> String {
    let head: String = m.chars().take(4).collect();
    format!("{}{}", head, "*".repeat(m.len().saturating_sub(4).min(20)))
}

fn scan_text(path: &str, content: &str, rules: &[Rule], out: &mut Vec<Finding>) {
    for (i, line) in content.lines().enumerate() {
        for rule in rules {
            if let Some(m) = rule.re.find(line) {
                out.push(Finding {
                    path: path.to_string(),
                    line: i + 1,
                    rule: rule.name.to_string(),
                    masked: mask(m.as_str()),
                });
            }
        }
    }
}

fn walk(dir: &Path, rules: &[Rule], out: &mut Vec<Finding>) {
    let entries = match std::fs::read_dir(dir) {
        Ok(e) => e,
        Err(_) => return,
    };
    for entry in entries.flatten() {
        let path = entry.path();
        let name = entry.file_name();
        let name = name.to_string_lossy();
        if path.is_dir() {
            if !SKIP_DIRS.contains(&name.as_ref()) {
                walk(&path, rules, out);
            }
            continue;
        }
        // Skip oversized or unreadable files.
        if path
            .metadata()
            .map(|m| m.len() > MAX_FILE_BYTES)
            .unwrap_or(true)
        {
            continue;
        }
        let bytes = match std::fs::read(&path) {
            Ok(b) => b,
            Err(_) => continue,
        };
        // Binary heuristic: a NUL byte in the first 8 KiB.
        if bytes.iter().take(8192).any(|&b| b == 0) {
            continue;
        }
        let content = String::from_utf8_lossy(&bytes);
        scan_text(&path.to_string_lossy(), &content, rules, out);
    }
}

pub fn scan_path(root: &Path) -> Vec<Finding> {
    let rules = rules();
    let mut out = Vec::new();
    if root.is_dir() {
        walk(root, &rules, &mut out);
    } else if root.is_file() {
        if let Ok(bytes) = std::fs::read(root) {
            let content = String::from_utf8_lossy(&bytes);
            scan_text(&root.to_string_lossy(), &content, &rules, &mut out);
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_and_masks() {
        let mut out = Vec::new();
        let text = "let key = \"AKIAIOSFODNN7EXAMPLE\";\nlet x = 1;";
        scan_text("f.rs", text, &rules(), &mut out);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].rule, "AWS Access Key");
        assert_eq!(out[0].line, 1);
        assert!(out[0].masked.starts_with("AKIA"));
        assert!(!out[0].masked.contains("IOSFODNN")); // body masked
    }

    #[test]
    fn clean_text_no_findings() {
        let mut out = Vec::new();
        scan_text(
            "f.rs",
            "let port = 8080;\nlet host = \"localhost\";",
            &rules(),
            &mut out,
        );
        assert!(out.is_empty());
    }
}
