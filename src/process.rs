//! Process metadata collected from `/proc/<pid>/`.

use anyhow::{bail, Context, Result};
use serde::Serialize;
use std::fs;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};

#[derive(Debug, Serialize)]
pub struct ProcessInfo {
    pub pid: i32,
    pub cmdline: Vec<String>,
    pub exe_path: Option<String>,
    pub cwd: Option<String>,
    pub root: Option<String>,
    pub status_name: Option<String>,
    pub uid: Option<u32>,
    pub gid: Option<u32>,
    pub environ: Vec<String>,
    pub open_fds: Vec<FdInfo>,
}

#[derive(Debug, Serialize)]
pub struct FdInfo {
    pub fd: i32,
    pub target: String,
}

pub fn collect(pid: i32) -> Result<ProcessInfo> {
    let proc = PathBuf::from(format!("/proc/{pid}"));
    if !proc.exists() {
        bail!("process {pid} not found (/proc/{pid} missing)");
    }

    let cmdline = read_nul_split(&proc.join("cmdline")).unwrap_or_default();
    let environ = read_nul_split(&proc.join("environ")).unwrap_or_default();
    let exe_path = fs::read_link(proc.join("exe"))
        .ok()
        .map(|p| p.to_string_lossy().into_owned());
    let cwd = fs::read_link(proc.join("cwd"))
        .ok()
        .map(|p| p.to_string_lossy().into_owned());
    let root = fs::read_link(proc.join("root"))
        .ok()
        .map(|p| p.to_string_lossy().into_owned());

    let status = fs::read_to_string(proc.join("status")).unwrap_or_default();
    let status_name = field_from_status(&status, "Name");
    let uid =
        field_from_status(&status, "Uid").and_then(|s| s.split_whitespace().next()?.parse().ok());
    let gid =
        field_from_status(&status, "Gid").and_then(|s| s.split_whitespace().next()?.parse().ok());

    Ok(ProcessInfo {
        pid,
        cmdline,
        exe_path,
        cwd,
        root,
        status_name,
        uid,
        gid,
        environ,
        open_fds: list_fds(pid)?,
    })
}

/// Read a `Key:\tvalue` field from `/proc/<pid>/status` text.
pub fn field_from_status(status: &str, key: &str) -> Option<String> {
    for line in status.lines() {
        if let Some(rest) = line.strip_prefix(key) {
            let rest = rest.trim_start_matches(|c: char| c == ':' || c.is_whitespace());
            return Some(rest.to_string());
        }
    }
    None
}

/// Split a NUL-delimited buffer (cmdline / environ style) into strings.
pub fn split_nul_bytes(bytes: &[u8]) -> Vec<String> {
    bytes
        .split(|b| *b == 0)
        .filter(|s| !s.is_empty())
        .map(|s| String::from_utf8_lossy(s).into_owned())
        .collect()
}

fn read_nul_split(path: &Path) -> Result<Vec<String>> {
    let bytes = fs::read(path).with_context(|| format!("read {}", path.display()))?;
    Ok(split_nul_bytes(&bytes))
}

fn list_fds(pid: i32) -> Result<Vec<FdInfo>> {
    let fd_dir = PathBuf::from(format!("/proc/{pid}/fd"));
    let mut out = Vec::new();
    let entries = match fs::read_dir(&fd_dir) {
        Ok(e) => e,
        Err(_) => return Ok(out),
    };
    for entry in entries.flatten() {
        let name = entry.file_name();
        let Ok(fd) = name.to_string_lossy().parse::<i32>() else {
            continue;
        };
        let target = fs::read_link(entry.path())
            .map(|p| p.to_string_lossy().into_owned())
            .unwrap_or_else(|_| "<unreadable>".into());
        out.push(FdInfo { fd, target });
    }
    out.sort_by_key(|f| f.fd);
    Ok(out)
}

/// Copy `/proc/<pid>/exe` into `dest` (best-effort recovery of the on-disk binary image).
pub fn copy_exe(pid: i32, dest: &Path) -> Result<u64> {
    let src = PathBuf::from(format!("/proc/{pid}/exe"));
    let meta = fs::metadata(&src).with_context(|| format!("stat {}", src.display()))?;
    fs::copy(&src, dest).with_context(|| {
        format!(
            "copy {} -> {} (size hint {})",
            src.display(),
            dest.display(),
            meta.size()
        )
    })?;
    Ok(meta.size())
}
