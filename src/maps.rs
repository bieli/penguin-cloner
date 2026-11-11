//! Parse `/proc/<pid>/maps` into dumpable memory regions.

use anyhow::{Context, Result};
use serde::Serialize;
use std::fs;
use std::path::PathBuf;

#[derive(Debug, Clone, Serialize)]
pub struct Region {
    pub start: u64,
    pub end: u64,
    pub perms: String,
    pub offset: u64,
    pub device: String,
    pub inode: u64,
    pub pathname: String,
    pub readable: bool,
    pub writable: bool,
    pub executable: bool,
    pub private: bool,
}

impl Region {
    pub fn size(&self) -> u64 {
        self.end.saturating_sub(self.start)
    }

    pub fn dump_name(&self) -> String {
        let tag = if self.pathname.is_empty() {
            "anon".to_string()
        } else {
            self.pathname
                .replace('/', "_")
                .replace(['[', ']'], "")
                .chars()
                .map(|c| {
                    if c.is_ascii_alphanumeric() || c == '_' || c == '-' || c == '.' {
                        c
                    } else {
                        '_'
                    }
                })
                .collect::<String>()
        };
        format!(
            "{:016x}-{:016x}_{}_{}",
            self.start, self.end, self.perms, tag
        )
    }
}

pub fn parse_maps(pid: i32) -> Result<Vec<Region>> {
    let path = PathBuf::from(format!("/proc/{pid}/maps"));
    let text = fs::read_to_string(&path).with_context(|| format!("read {}", path.display()))?;
    parse_maps_text(&text)
}

/// Parse the textual contents of a `/proc/<pid>/maps` file.
pub fn parse_maps_text(text: &str) -> Result<Vec<Region>> {
    let mut regions = Vec::new();

    for (lineno, line) in text.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        // address           perms offset  dev   inode       pathname
        // 00400000-00452000 r-xp 00000000 08:02 173521      /usr/bin/dbus-daemon
        let mut parts = line.split_whitespace();
        let range = parts
            .next()
            .with_context(|| format!("maps line {}: missing range", lineno + 1))?;
        let perms = parts
            .next()
            .with_context(|| format!("maps line {}: missing perms", lineno + 1))?
            .to_string();
        let offset = u64::from_str_radix(
            parts
                .next()
                .with_context(|| format!("maps line {}: missing offset", lineno + 1))?,
            16,
        )
        .unwrap_or(0);
        let device = parts.next().unwrap_or("00:00").to_string();
        let inode = parts.next().and_then(|s| s.parse().ok()).unwrap_or(0);
        let pathname = parts.collect::<Vec<_>>().join(" ");

        let (start_s, end_s) = range
            .split_once('-')
            .with_context(|| format!("maps line {}: bad range {range}", lineno + 1))?;
        let start = u64::from_str_radix(start_s, 16)
            .with_context(|| format!("maps line {}: bad start", lineno + 1))?;
        let end = u64::from_str_radix(end_s, 16)
            .with_context(|| format!("maps line {}: bad end", lineno + 1))?;

        let bytes = perms.as_bytes();
        regions.push(Region {
            start,
            end,
            readable: bytes.first() == Some(&b'r'),
            writable: bytes.get(1) == Some(&b'w'),
            executable: bytes.get(2) == Some(&b'x'),
            private: bytes.get(3) == Some(&b'p'),
            perms,
            offset,
            device,
            inode,
            pathname,
        });
    }

    Ok(regions)
}

/// Decide whether a region should be dumped.
pub fn should_dump(region: &Region, include_file_backed: bool, heap_stack_only: bool) -> bool {
    if !region.readable {
        return false;
    }
    // Skip vsyscall / vvar / vdso noise unless they somehow matter (usually not for config).
    if matches!(
        region.pathname.as_str(),
        "[vdso]" | "[vvar]" | "[vsyscall]" | "[vvar_vclock]"
    ) {
        return false;
    }
    if heap_stack_only {
        return matches!(region.pathname.as_str(), "[heap]" | "[stack]")
            || region.pathname.starts_with("[stack:");
    }
    if !include_file_backed && region.inode != 0 && !region.pathname.is_empty() {
        // Keep anonymous + heap/stack; skip mapped libraries/binaries (exe is copied separately).
        // Still dump writable file-backed mappings (often mmapped config / data files).
        if !region.writable {
            return false;
        }
    }
    true
}
