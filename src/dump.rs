//! Attach, freeze, and dump process memory regions.

use crate::maps::{self, Region};
use anyhow::{bail, Context, Result};
use nix::sys::ptrace;
use nix::sys::signal::Signal;
use nix::sys::uio::{process_vm_readv, RemoteIoVec};
use nix::sys::wait::{waitpid, WaitStatus};
use nix::unistd::Pid;
use serde::Serialize;
use std::fs::{self, File, OpenOptions};
use std::io::{IoSliceMut, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::time::Duration;

#[derive(Debug, Serialize)]
pub struct DumpReport {
    pub pid: i32,
    pub attached: bool,
    pub regions_total: usize,
    pub regions_dumped: usize,
    pub bytes_dumped: u64,
    pub files: Vec<DumpedFile>,
    pub skipped: Vec<SkippedRegion>,
}

#[derive(Debug, Serialize)]
pub struct DumpedFile {
    pub path: String,
    pub start: u64,
    pub end: u64,
    pub size: u64,
    pub perms: String,
    pub pathname: String,
}

#[derive(Debug, Serialize)]
pub struct SkippedRegion {
    pub start: u64,
    pub end: u64,
    pub pathname: String,
    pub reason: String,
}

pub struct DumpOptions {
    pub include_file_backed: bool,
    pub heap_stack_only: bool,
    pub max_region_bytes: u64,
    pub freeze: bool,
}

struct Attached {
    pid: Pid,
}

impl Attached {
    fn attach(pid: i32) -> Result<Self> {
        let pid = Pid::from_raw(pid);
        ptrace::attach(pid).with_context(|| {
            format!(
                "ptrace(ATTACH) pid={pid} failed — need root / CAP_SYS_PTRACE, or be a parent \
                 of the target (Yama ptrace_scope often blocks unrelated same-uid attach)"
            )
        })?;

        // Wait until the tracee stops.
        loop {
            match waitpid(pid, None)? {
                WaitStatus::Stopped(_, _) => break,
                WaitStatus::Signaled(_, sig, _) => {
                    bail!("process {pid} died with signal {sig:?} while attaching");
                }
                WaitStatus::Exited(_, code) => {
                    bail!("process {pid} exited with code {code} while attaching");
                }
                _ => continue,
            }
        }

        Ok(Self { pid })
    }
}

/// Try to freeze; on permission errors return `Ok(None)` so the caller can continue racy.
pub fn try_attach(pid: i32) -> Result<Option<AttachedGuard>> {
    match Attached::attach(pid) {
        Ok(g) => Ok(Some(AttachedGuard(g))),
        Err(err) => {
            let msg = format!("{err:#}");
            if msg.contains("EPERM") || msg.contains("Operation not permitted") {
                eprintln!("[!] freeze unavailable ({msg}); continuing without ptrace attach");
                Ok(None)
            } else {
                Err(err)
            }
        }
    }
}

pub struct AttachedGuard(#[allow(dead_code)] Attached);

impl Drop for Attached {
    fn drop(&mut self) {
        let _ = ptrace::detach(self.pid, Some(Signal::SIGCONT));
    }
}

pub fn dump_process(pid: i32, out_dir: &Path, opts: &DumpOptions) -> Result<DumpReport> {
    fs::create_dir_all(out_dir).with_context(|| format!("mkdir {}", out_dir.display()))?;
    let mem_dir = out_dir.join("memory");
    fs::create_dir_all(&mem_dir)?;

    let regions = maps::parse_maps(pid)?;
    let maps_raw = fs::read_to_string(format!("/proc/{pid}/maps"))?;
    fs::write(out_dir.join("maps.txt"), &maps_raw)?;

    let guard = if opts.freeze { try_attach(pid)? } else { None };

    let mut report = DumpReport {
        pid,
        attached: guard.is_some(),
        regions_total: regions.len(),
        regions_dumped: 0,
        bytes_dumped: 0,
        files: Vec::new(),
        skipped: Vec::new(),
    };

    // Prefer process_vm_readv; fall back to /proc/<pid>/mem.
    let mut mem_file = open_proc_mem(pid).ok();

    for region in &regions {
        if !maps::should_dump(region, opts.include_file_backed, opts.heap_stack_only) {
            report.skipped.push(SkippedRegion {
                start: region.start,
                end: region.end,
                pathname: region.pathname.clone(),
                reason: "filtered".into(),
            });
            continue;
        }
        let size = region.size();
        if size == 0 {
            continue;
        }
        if size > opts.max_region_bytes {
            report.skipped.push(SkippedRegion {
                start: region.start,
                end: region.end,
                pathname: region.pathname.clone(),
                reason: format!("region too large ({size} > max {})", opts.max_region_bytes),
            });
            continue;
        }

        let mut buf = vec![0u8; size as usize];
        match read_region(pid, region, &mut buf, mem_file.as_mut()) {
            Ok(()) => {
                let name = region.dump_name();
                let path = mem_dir.join(&name);
                fs::write(&path, &buf).with_context(|| format!("write {}", path.display()))?;
                report.regions_dumped += 1;
                report.bytes_dumped += size;
                report.files.push(DumpedFile {
                    path: format!("memory/{name}"),
                    start: region.start,
                    end: region.end,
                    size,
                    perms: region.perms.clone(),
                    pathname: region.pathname.clone(),
                });
            }
            Err(err) => {
                report.skipped.push(SkippedRegion {
                    start: region.start,
                    end: region.end,
                    pathname: region.pathname.clone(),
                    reason: format!("read failed: {err:#}"),
                });
            }
        }
    }

    // Give the kernel a moment if we just detached (Drop runs at end of scope).
    drop(guard);
    std::thread::sleep(Duration::from_millis(10));

    Ok(report)
}

fn open_proc_mem(pid: i32) -> Result<File> {
    OpenOptions::new()
        .read(true)
        .open(format!("/proc/{pid}/mem"))
        .with_context(|| format!("open /proc/{pid}/mem"))
}

fn read_region(
    pid: i32,
    region: &Region,
    buf: &mut [u8],
    mem_file: Option<&mut File>,
) -> Result<()> {
    if process_vm_read(pid, region.start, buf).is_ok() {
        return Ok(());
    }
    if let Some(file) = mem_file {
        return read_proc_mem(file, region.start, buf);
    }
    // Last resort: open fresh /proc/pid/mem
    let mut file = open_proc_mem(pid)?;
    read_proc_mem(&mut file, region.start, buf)
}

fn process_vm_read(pid: i32, remote_addr: u64, buf: &mut [u8]) -> Result<()> {
    let mut local = [IoSliceMut::new(buf)];
    let remote = [RemoteIoVec {
        base: remote_addr as usize,
        len: local[0].len(),
    }];
    let expected = remote[0].len;
    let n = process_vm_readv(Pid::from_raw(pid), &mut local, &remote)
        .with_context(|| format!("process_vm_readv @ {remote_addr:#x}"))?;
    if n != expected {
        bail!("short process_vm_readv: got {n}, expected {expected} @ {remote_addr:#x}");
    }
    Ok(())
}

fn read_proc_mem(file: &mut File, addr: u64, buf: &mut [u8]) -> Result<()> {
    file.seek(SeekFrom::Start(addr))
        .with_context(|| format!("seek /proc/mem @ {addr:#x}"))?;
    file.read_exact(buf)
        .with_context(|| format!("read /proc/mem @ {addr:#x} len={}", buf.len()))?;
    Ok(())
}

/// Write a simple ELF-like note: concatenated memory with an index (for offline analysis).
pub fn write_index(out_dir: &Path, report: &DumpReport) -> Result<()> {
    let path = out_dir.join("memory_index.json");
    let json = serde_json::to_string_pretty(report)?;
    fs::write(&path, json)?;
    Ok(())
}

pub fn write_combined_blob(out_dir: &Path, report: &DumpReport) -> Result<PathBuf> {
    let path = out_dir.join("memory_combined.bin");
    let mut out = File::create(&path)?;
    let mut cursor: u64 = 0;
    let mut meta = Vec::new();

    for file in &report.files {
        let data = fs::read(out_dir.join(&file.path))?;
        out.write_all(&data)?;
        meta.push(serde_json::json!({
            "file": file.path,
            "va_start": file.start,
            "va_end": file.end,
            "blob_offset": cursor,
            "size": file.size,
            "pathname": file.pathname,
        }));
        cursor += file.size;
    }

    fs::write(
        out_dir.join("memory_combined.json"),
        serde_json::to_string_pretty(&meta)?,
    )?;
    Ok(path)
}
