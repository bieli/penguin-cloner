//! Extract printable strings from dumped memory (config / path recovery).

use anyhow::{Context, Result};
use serde::Serialize;
use std::fs::{self, File};
use std::io::{BufWriter, Write};
use std::path::Path;

#[derive(Debug, Serialize)]
pub struct StringHit {
    pub source: String,
    pub offset: u64,
    pub text: String,
}

pub struct StringOptions {
    pub min_len: usize,
    pub interesting_only: bool,
}

const INTERESTING_MARKERS: &[&str] = &[
    "config",
    "CONFIG",
    "password",
    "passwd",
    "secret",
    "token",
    "api_key",
    "API_KEY",
    "http://",
    "https://",
    "jdbc:",
    "postgres",
    "mysql",
    "mongodb",
    "redis",
    "amqp",
    "/",
    "=",
    ".conf",
    ".ini",
    ".yaml",
    ".yml",
    ".json",
    ".xml",
    ".properties",
    "HOME=",
    "PATH=",
    "LD_",
];

pub fn extract_from_dir(mem_dir: &Path, out_path: &Path, opts: &StringOptions) -> Result<usize> {
    let mut hits = Vec::new();
    if !mem_dir.is_dir() {
        return Ok(0);
    }
    let mut entries: Vec<_> = fs::read_dir(mem_dir)?.filter_map(|e| e.ok()).collect();
    entries.sort_by_key(|e| e.file_name());

    for entry in entries {
        let path = entry.path();
        if !path.is_file() {
            continue;
        }
        let data = fs::read(&path).with_context(|| format!("read {}", path.display()))?;
        let source = path
            .file_name()
            .map(|s| s.to_string_lossy().into_owned())
            .unwrap_or_default();
        hits.extend(extract_strings(&data, &source, opts));
    }

    let file = File::create(out_path).with_context(|| format!("create {}", out_path.display()))?;
    let mut w = BufWriter::new(file);
    for hit in &hits {
        writeln!(
            w,
            "{}\t{:#x}\t{}",
            hit.source,
            hit.offset,
            hit.text.replace('\n', "\\n").replace('\r', "\\r")
        )?;
    }
    w.flush()?;

    // Also JSON for tooling.
    let json_path = out_path.with_extension("json");
    fs::write(json_path, serde_json::to_string_pretty(&hits)?)?;
    Ok(hits.len())
}

/// Extract printable strings from a raw memory blob.
pub fn extract_strings(data: &[u8], source: &str, opts: &StringOptions) -> Vec<StringHit> {
    let mut out = Vec::new();
    extract_bytes(data, source, opts, &mut out);
    out
}

fn extract_bytes(data: &[u8], source: &str, opts: &StringOptions, out: &mut Vec<StringHit>) {
    let mut i = 0usize;
    while i < data.len() {
        if is_printable(data[i]) {
            let start = i;
            i += 1;
            while i < data.len() && is_printable(data[i]) {
                i += 1;
            }
            let len = i - start;
            if len >= opts.min_len {
                let text = String::from_utf8_lossy(&data[start..i]).into_owned();
                if !opts.interesting_only || looks_interesting(&text) {
                    out.push(StringHit {
                        source: source.to_string(),
                        offset: start as u64,
                        text,
                    });
                }
            }
        } else {
            i += 1;
        }
    }
}

pub fn is_printable(b: u8) -> bool {
    (0x20..=0x7e).contains(&b) || b == b'\t'
}

pub fn looks_interesting(s: &str) -> bool {
    INTERESTING_MARKERS.iter().any(|m| s.contains(m))
}
