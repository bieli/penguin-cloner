//! `variables.json` — a typed dictionary of a running program's variables.
//!
//! Turns raw process memory into `name -> value` pairs:
//!   * integers and floats become JSON numbers,
//!   * C strings (`char[]`, and `char *` followed to its target) become finite JSON strings.
//!
//! How it works (no DWARF needed):
//!   1. Parse the executable's ELF symbol table (`.symtab`, or `.dynsym` as a fallback) and keep
//!      data objects (`STT_OBJECT`): global/static variables with their name, address and size.
//!   2. Compute the load bias (PIE/ASLR) from `/proc/<pid>/maps`.
//!   3. Read each object's *current* bytes from the live process and infer a type from size + content.
//!   4. Also type the process environment (`KEY=VALUE`) into the same kind of dictionary.
//!
//! Automatic discovery (no symbols, no declarations) — see the `discover` submodule:
//!   * `xref`: the program's own machine code is scanned for RIP-relative data references; every
//!     data address the code touches is a variable, and the instruction (width, SSE float ops, `lea`)
//!     tells its type. Works on stripped binaries (x86_64, needs the `xrefs` feature).
//!   * `watch` (opt-in): the live process is sampled; slots that behave like counters, flags or
//!     floats are variables, including fields of heap objects reachable from a global pointer.
//!
//! Honest limits:
//!   * Real names exist only if the binary has symbols (or you pass an unstripped build / `.debug`
//!     file of the *same* build; build-ids are verified). Otherwise names are synthesized (`g_4020`).
//!   * Types are inferred (no debug info): symbols give the size, code gives the access width and
//!     float use, content decides the rest. `char[4]` is an `i32`, an unsigned value above
//!     `i32::MAX` shows as negative (the unsigned reading is kept in `details.<name>.as_unsigned`),
//!     and a struct the code never reads field by field is a `blob`.
//!   * Structs, pointer arrays and other composites are listed as `blob`, never as a value.
//!   * ELF64 little-endian only (x86_64, aarch64, ...). Main executable only, not shared libraries.
//!
//! Only `std` is used, plus the optional `iced-x86` decoder behind the `xrefs` cargo feature
//! (code-reference discovery). Without the feature the module has no dependencies.
//! MSRV: Rust 1.70.

// The module exposes a small public API (RegionsMem, Report::dictionary, ...) that the CLI may not use yet.
#![allow(dead_code)]

use std::collections::{BTreeMap, HashSet};
use std::fs::{self, File, OpenOptions};
use std::io::{self, Write};
use std::os::unix::fs::{FileExt, OpenOptionsExt};
use std::path::{Path, PathBuf};

pub mod discover;
pub use discover::WatchOptions;

// ───────────────────────────── public data model ─────────────────────────────

/// A dictionary value: numbers stay numbers, text stays text.
#[derive(Debug, Clone, PartialEq)]
pub enum Value {
    Int(i64),
    Float(f64),
    Float32(f32),
    Str(String),
}

/// Human-readable form: numbers as-is, strings as JSON-quoted text.
impl std::fmt::Display for Value {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut s = String::new();
        self.write_json(&mut s);
        f.write_str(&s)
    }
}

impl Value {
    fn write_json(&self, out: &mut String) {
        match self {
            Value::Int(i) => out.push_str(&i.to_string()),
            // `{:?}` keeps a decimal point or exponent ("2.0", "1e21"), so floats stay floats in JSON.
            Value::Float(f) => out.push_str(&format!("{f:?}")),
            Value::Float32(f) => out.push_str(&format!("{f:?}")),
            Value::Str(s) => push_json_str(out, s),
        }
    }
}

#[derive(Debug, Clone)]
pub struct VarOptions {
    /// Objects bigger than this are only inspected through their first `max_object_size` bytes.
    pub max_object_size: usize,
    /// Longest string followed through a `char *`.
    pub max_string: usize,
    /// Keep compiler/runtime bookkeeping symbols (`__dso_handle`, `_end`, ...).
    pub include_runtime_noise: bool,
    /// Include read-only data (`.rodata`: constants, version banners).
    pub include_rodata: bool,
    /// Also produce the typed `environment` dictionary.
    pub include_environment: bool,
    /// Also list objects that did not become a plain value (pointers, blobs, zeroed buffers).
    pub keep_opaque: bool,
    /// Replace values of variables/env vars whose name looks secret (`password`, `token`, ...) by "***".
    pub redact_secrets: bool,
    /// Discover variables that have no symbol from the program's code references (x86_64, `xrefs` feature).
    pub discover: bool,
    /// Also discover read-only constants (`.rodata`) from code references (noisy: every literal).
    pub discover_rodata: bool,
    /// Pretend the binary is stripped: ignore its symbol table (names are then synthesized).
    pub ignore_symbols: bool,
    /// Sample the *running* process to find mutable variables. Never use while the target is frozen.
    pub watch: Option<WatchOptions>,
}

impl Default for VarOptions {
    fn default() -> Self {
        VarOptions {
            max_object_size: 4096,
            max_string: 1024,
            include_runtime_noise: false,
            include_rodata: true,
            include_environment: true,
            keep_opaque: false,
            redact_secrets: false,
            discover: true,
            discover_rodata: false,
            ignore_symbols: false,
            watch: None,
        }
    }
}

/// One discovered variable.
#[derive(Debug, Clone)]
pub struct VarEntry {
    pub name: String,
    /// Runtime address (load bias already applied).
    pub addr: u64,
    pub size: u64,
    /// Inferred type: `i32`, `f64`, `char[32]`, `char*`, `ptr`, `blob`, `zeroed`, ...
    pub ty: String,
    pub section: String,
    pub binding: &'static str,
    /// `Some` => the entry appears in the `variables` dictionary.
    pub value: Option<Value>,
    pub aliases: Vec<String>,
    pub as_unsigned: Option<u64>,
    pub points_to: Option<u64>,
    pub hex_preview: Option<String>,
    pub truncated: bool,
    pub redacted: bool,
    /// How the variable was found: `symbol`, `xref` (code reference) or `watch` (observed).
    pub source: &'static str,
    /// Human-readable proof: reference counts, SSE accesses, observed changes, ...
    pub evidence: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct Report {
    pub pid: u32,
    pub exe: String,
    pub elf_type: &'static str,
    pub load_bias: u64,
    pub symbols_from: &'static str,
    pub symbols_seen: usize,
    pub entries: Vec<VarEntry>,
    pub environment: BTreeMap<String, Value>,
    pub notes: Vec<String>,
}

impl Report {
    /// The flat `name -> value` dictionary.
    pub fn dictionary(&self) -> BTreeMap<&str, &Value> {
        let mut m = BTreeMap::new();
        for e in &self.entries {
            if let Some(v) = &e.value {
                m.insert(e.name.as_str(), v);
            }
        }
        m
    }

    /// Pretty, deterministic JSON (hand-written: no serde needed).
    pub fn to_json(&self) -> String {
        let mut o = String::with_capacity(4096);
        o.push_str("{\n");
        o.push_str("  \"schema\": \"penguin-cloner/variables@1\",\n");
        o.push_str(&format!("  \"pid\": {},\n", self.pid));
        o.push_str("  \"exe\": ");
        push_json_str(&mut o, &self.exe);
        o.push_str(",\n");
        o.push_str(&format!(
            "  \"elf\": {{\"type\": \"{}\", \"load_bias\": \"{:#x}\", \"symbols_from\": \"{}\", \"symbols_seen\": {}}},\n",
            self.elf_type, self.load_bias, self.symbols_from, self.symbols_seen
        ));

        // variables: the dictionary itself
        o.push_str("  \"variables\": {");
        let mut first = true;
        for e in &self.entries {
            if let Some(v) = &e.value {
                o.push_str(if first { "\n    " } else { ",\n    " });
                first = false;
                push_json_str(&mut o, &e.name);
                o.push_str(": ");
                v.write_json(&mut o);
            }
        }
        o.push_str(if first { "},\n" } else { "\n  },\n" });

        // environment: typed KEY=VALUE pairs
        o.push_str("  \"environment\": {");
        let mut first = true;
        for (k, v) in &self.environment {
            o.push_str(if first { "\n    " } else { ",\n    " });
            first = false;
            push_json_str(&mut o, k);
            o.push_str(": ");
            v.write_json(&mut o);
        }
        o.push_str(if first { "},\n" } else { "\n  },\n" });

        // details: where each value came from
        o.push_str("  \"details\": {");
        let mut first = true;
        for e in &self.entries {
            o.push_str(if first { "\n    " } else { ",\n    " });
            first = false;
            push_json_str(&mut o, &e.name);
            o.push_str(": {");
            o.push_str(&format!(
                "\"addr\": \"{:#x}\", \"size\": {}, \"type\": ",
                e.addr, e.size
            ));
            push_json_str(&mut o, &e.ty);
            o.push_str(", \"section\": ");
            push_json_str(&mut o, &e.section);
            o.push_str(&format!(", \"binding\": \"{}\"", e.binding));
            o.push_str(&format!(", \"in_dictionary\": {}", e.value.is_some()));
            o.push_str(&format!(", \"source\": \"{}\"", e.source));
            if !e.evidence.is_empty() {
                o.push_str(", \"evidence\": [");
                for (i, ev) in e.evidence.iter().enumerate() {
                    if i > 0 {
                        o.push_str(", ");
                    }
                    push_json_str(&mut o, ev);
                }
                o.push(']');
            }
            if let Some(u) = e.as_unsigned {
                o.push_str(&format!(", \"as_unsigned\": {u}"));
            }
            if let Some(p) = e.points_to {
                o.push_str(&format!(", \"points_to\": \"{p:#x}\""));
            }
            if let Some(h) = &e.hex_preview {
                o.push_str(", \"hex_preview\": \"");
                o.push_str(h);
                o.push('"');
            }
            if e.truncated {
                o.push_str(", \"truncated\": true");
            }
            if e.redacted {
                o.push_str(", \"redacted\": true");
            }
            if !e.aliases.is_empty() {
                o.push_str(", \"aliases\": [");
                for (i, a) in e.aliases.iter().enumerate() {
                    if i > 0 {
                        o.push_str(", ");
                    }
                    push_json_str(&mut o, a);
                }
                o.push(']');
            }
            o.push('}');
        }
        o.push_str(if first { "},\n" } else { "\n  },\n" });

        o.push_str("  \"notes\": [");
        for (i, n) in self.notes.iter().enumerate() {
            o.push_str(if i == 0 { "\n    " } else { ",\n    " });
            push_json_str(&mut o, n);
        }
        o.push_str(if self.notes.is_empty() {
            "]\n}"
        } else {
            "\n  ]\n}"
        });
        o
    }

    /// Write `<dir>/variables.json` with mode 0600 (dumped values can contain secrets).
    pub fn write_to(&self, dir: &Path) -> io::Result<PathBuf> {
        fs::create_dir_all(dir)?;
        let path = dir.join("variables.json");
        let mut f = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(&path)?;
        f.write_all(self.to_json().as_bytes())?;
        f.write_all(b"\n")?;
        Ok(path)
    }
}

pub fn push_json_str(out: &mut String, s: &str) {
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out.push('"');
}

// ─────────────────────────────── memory sources ───────────────────────────────

/// Where variable values are read from.
pub trait MemSource {
    /// Read up to `len` bytes at `addr`. May return fewer bytes (end of mapping); `None` if nothing is readable.
    fn read(&self, addr: u64, len: usize) -> Option<Vec<u8>>;
}

/// Live process memory through `/proc/<pid>/mem`.
/// Call it while the target is frozen by the dumper's ptrace attach, so values match the snapshot.
pub struct ProcMem {
    file: File,
}

impl ProcMem {
    pub fn open(pid: u32) -> io::Result<ProcMem> {
        Ok(ProcMem {
            file: File::open(format!("/proc/{pid}/mem"))?,
        })
    }
}

impl MemSource for ProcMem {
    fn read(&self, addr: u64, len: usize) -> Option<Vec<u8>> {
        if len == 0 {
            return Some(Vec::new());
        }
        let mut buf = vec![0u8; len];
        let mut got = 0usize;
        while got < len {
            let at = match addr.checked_add(got as u64) {
                Some(a) => a,
                None => break,
            };
            match self.file.read_at(&mut buf[got..], at) {
                Ok(0) => break,
                Ok(n) => got += n,
                Err(_) => break,
            }
        }
        if got == 0 {
            None
        } else {
            buf.truncate(got);
            Some(buf)
        }
    }
}

/// Memory made of `(start_address, bytes)` regions, e.g. regions already held by the dumper.
pub struct RegionsMem {
    regions: Vec<(u64, Vec<u8>)>,
}

impl RegionsMem {
    pub fn new(mut regions: Vec<(u64, Vec<u8>)>) -> RegionsMem {
        regions.sort_by_key(|r| r.0);
        RegionsMem { regions }
    }
}

impl MemSource for RegionsMem {
    fn read(&self, addr: u64, len: usize) -> Option<Vec<u8>> {
        for (start, data) in &self.regions {
            if addr >= *start {
                let off = (addr - *start) as usize;
                if off < data.len() {
                    let end = off.saturating_add(len).min(data.len());
                    return Some(data[off..end].to_vec());
                }
            }
        }
        None
    }
}

// ─────────────────────────────── /proc/<pid>/maps ───────────────────────────────

#[derive(Debug, Clone)]
pub struct MapEntry {
    pub start: u64,
    pub end: u64,
    pub perms: String,
    pub offset: u64,
    pub path: String,
}

impl MapEntry {
    fn readable(&self) -> bool {
        self.perms.starts_with('r')
    }
}

/// Parse the text of `/proc/<pid>/maps` (also the `maps.txt` of a dump).
pub fn parse_maps(text: &str) -> Vec<MapEntry> {
    let mut out = Vec::new();
    for line in text.lines() {
        let mut rest = line;
        let mut fields: Vec<&str> = Vec::with_capacity(5);
        for _ in 0..5 {
            rest = rest.trim_start();
            let end = rest.find(char::is_whitespace).unwrap_or(rest.len());
            fields.push(&rest[..end]);
            rest = &rest[end..];
        }
        let path = rest.trim().to_string();
        let (a, b) = match fields[0].split_once('-') {
            Some(p) => p,
            None => continue,
        };
        let start = match u64::from_str_radix(a, 16) {
            Ok(v) => v,
            Err(_) => continue,
        };
        let end = match u64::from_str_radix(b, 16) {
            Ok(v) => v,
            Err(_) => continue,
        };
        let offset = u64::from_str_radix(fields[2], 16).unwrap_or(0);
        out.push(MapEntry {
            start,
            end,
            perms: fields[1].to_string(),
            offset,
            path,
        });
    }
    out
}

fn find_map(maps: &[MapEntry], addr: u64) -> Option<&MapEntry> {
    maps.iter().find(|m| addr >= m.start && addr < m.end)
}

// ───────────────────────────────── ELF64 parser ─────────────────────────────────

fn sl(data: &[u8], off: u64, len: u64) -> Option<&[u8]> {
    let end = off.checked_add(len)?;
    if end > data.len() as u64 {
        return None;
    }
    Some(&data[off as usize..end as usize])
}

fn u16_at(d: &[u8], off: u64) -> Option<u16> {
    let s = sl(d, off, 2)?;
    Some(u16::from_le_bytes([s[0], s[1]]))
}

fn u32_at(d: &[u8], off: u64) -> Option<u32> {
    let s = sl(d, off, 4)?;
    let mut a = [0u8; 4];
    a.copy_from_slice(s);
    Some(u32::from_le_bytes(a))
}

fn u64_at(d: &[u8], off: u64) -> Option<u64> {
    let s = sl(d, off, 8)?;
    let mut a = [0u8; 8];
    a.copy_from_slice(s);
    Some(u64::from_le_bytes(a))
}

fn le_u16(b: &[u8]) -> u16 {
    let mut a = [0u8; 2];
    a.copy_from_slice(&b[..2]);
    u16::from_le_bytes(a)
}

fn le_u32(b: &[u8]) -> u32 {
    let mut a = [0u8; 4];
    a.copy_from_slice(&b[..4]);
    u32::from_le_bytes(a)
}

fn le_u64(b: &[u8]) -> u64 {
    let mut a = [0u8; 8];
    a.copy_from_slice(&b[..8]);
    u64::from_le_bytes(a)
}

fn cstr_at(tab: &[u8], off: usize) -> String {
    if off >= tab.len() {
        return String::new();
    }
    let end = match tab[off..].iter().position(|&b| b == 0) {
        Some(p) => off + p,
        None => tab.len(),
    };
    String::from_utf8_lossy(&tab[off..end]).into_owned()
}

pub struct Section {
    pub name_off: u32,
    pub name: String,
    pub typ: u32,
    pub flags: u64,
    /// `sh_addr`: link-time virtual address of the section.
    pub addr: u64,
    pub offset: u64,
    pub size: u64,
    pub link: u32,
}

struct RawSym {
    name: String,
    bind: u8,
    shndx: u16,
    value: u64,
    size: u64,
}

pub struct Elf<'a> {
    pub data: &'a [u8],
    pub etype: u16,
    /// `e_machine` (62 = x86_64).
    pub machine: u16,
    /// `p_vaddr` of every PT_LOAD segment.
    pub loads: Vec<u64>,
    pub sections: Vec<Section>,
}

const SHT_NOBITS: u32 = 8;
const SHF_ALLOC: u64 = 0x2;
const SHF_EXECINSTR: u64 = 0x4;
const SHF_TLS: u64 = 0x400;
const STT_OBJECT: u8 = 1;

impl<'a> Elf<'a> {
    pub fn parse(data: &'a [u8]) -> Result<Elf<'a>, String> {
        if data.len() < 64 || &data[0..4] != b"\x7fELF" {
            return Err("not an ELF image".to_string());
        }
        if data[4] != 2 {
            return Err("only 64-bit ELF is supported".to_string());
        }
        if data[5] != 1 {
            return Err("only little-endian ELF is supported".to_string());
        }
        let etype = u16_at(data, 16).ok_or("truncated ELF header")?;
        let machine = u16_at(data, 18).ok_or("truncated ELF header")?;
        let phoff = u64_at(data, 32).ok_or("truncated ELF header")?;
        let shoff = u64_at(data, 40).ok_or("truncated ELF header")?;
        let phentsize = u16_at(data, 54).ok_or("truncated ELF header")? as u64;
        let phnum = u16_at(data, 56).ok_or("truncated ELF header")? as u64;
        let shentsize = u16_at(data, 58).ok_or("truncated ELF header")? as u64;
        let shnum = u16_at(data, 60).ok_or("truncated ELF header")? as u64;
        let shstrndx = u16_at(data, 62).ok_or("truncated ELF header")? as usize;

        let mut loads = Vec::new();
        if phentsize >= 56 {
            for i in 0..phnum {
                let o = match phoff.checked_add(i * phentsize) {
                    Some(v) => v,
                    None => break,
                };
                let ph = match sl(data, o, 56) {
                    Some(p) => p,
                    None => break,
                };
                if le_u32(ph) == 1 {
                    loads.push(le_u64(&ph[16..]));
                }
            }
        }

        let mut sections: Vec<Section> = Vec::new();
        if shoff != 0 && shentsize >= 64 {
            for i in 0..shnum {
                let o = match shoff.checked_add(i * shentsize) {
                    Some(v) => v,
                    None => break,
                };
                let sh = match sl(data, o, 64) {
                    Some(s) => s,
                    None => break,
                };
                sections.push(Section {
                    name_off: le_u32(sh),
                    name: String::new(),
                    typ: le_u32(&sh[4..]),
                    flags: le_u64(&sh[8..]),
                    addr: le_u64(&sh[16..]),
                    offset: le_u64(&sh[24..]),
                    size: le_u64(&sh[32..]),
                    link: le_u32(&sh[40..]),
                });
            }
        }
        if shstrndx < sections.len() {
            let (off, size) = (sections[shstrndx].offset, sections[shstrndx].size);
            if let Some(tab) = sl(data, off, size) {
                for s in sections.iter_mut() {
                    s.name = cstr_at(tab, s.name_off as usize);
                }
            }
        }
        Ok(Elf {
            data,
            etype,
            machine,
            loads,
            sections,
        })
    }

    /// `.symtab` if present, else `.dynsym`. Returns (label, total symbols, data-object symbols).
    fn symbols(&self) -> (&'static str, usize, Vec<RawSym>) {
        for &(want, label) in [(2u32, "symtab"), (11u32, "dynsym")].iter() {
            let sec = match self.sections.iter().find(|s| s.typ == want) {
                Some(s) => s,
                None => continue,
            };
            let strtab = match self.sections.get(sec.link as usize) {
                Some(s) => s,
                None => continue,
            };
            let tab = match sl(self.data, strtab.offset, strtab.size) {
                Some(t) => t,
                None => continue,
            };
            let body = match sl(self.data, sec.offset, sec.size) {
                Some(b) => b,
                None => continue,
            };
            let mut syms = Vec::new();
            for rec in body.chunks_exact(24) {
                let info = rec[4];
                if (info & 0xf) != STT_OBJECT {
                    continue;
                }
                syms.push(RawSym {
                    name: cstr_at(tab, le_u32(rec) as usize),
                    bind: info >> 4,
                    shndx: le_u16(&rec[6..]),
                    value: le_u64(&rec[8..]),
                    size: le_u64(&rec[16..]),
                });
            }
            return (label, body.len() / 24, syms);
        }
        ("none", 0, Vec::new())
    }

    /// GNU build-id bytes, if the note is present with contents.
    fn build_id(&self) -> Option<Vec<u8>> {
        let sec = self
            .sections
            .iter()
            .find(|s| s.name == ".note.gnu.build-id")?;
        if sec.typ == SHT_NOBITS {
            return None;
        }
        let body = sl(self.data, sec.offset, sec.size)?;
        let namesz = u32_at(body, 0)? as u64;
        let descsz = u32_at(body, 4)? as u64;
        let desc_off = 12 + ((namesz + 3) & !3u64);
        sl(body, desc_off, descsz).map(|d| d.to_vec())
    }
}

fn hex(bytes: &[u8]) -> String {
    let mut h = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        h.push_str(&format!("{b:02x}"));
    }
    h
}

/// Difference between link-time addresses and runtime addresses (0 for non-PIE executables).
fn load_bias(elf: &Elf, maps: &[MapEntry], exe_path: &str) -> Result<u64, String> {
    const ET_DYN: u16 = 3;
    if elf.etype != ET_DYN {
        return Ok(0);
    }
    let min_vaddr = match elf.loads.iter().min() {
        Some(v) => *v & !0xfffu64,
        None => return Err("ELF has no PT_LOAD segments".to_string()),
    };
    let first = maps
        .iter()
        .filter(|m| m.path == exe_path)
        .map(|m| m.start)
        .min();
    match first {
        Some(start) => start
            .checked_sub(min_vaddr)
            .ok_or_else(|| "inconsistent load address".to_string()),
        None => Err(format!(
            "executable '{exe_path}' not found in maps (cannot compute the PIE load bias)"
        )),
    }
}

// ───────────────────────────── type inference ─────────────────────────────

pub struct Classified {
    pub ty: String,
    pub value: Option<Value>,
    pub as_unsigned: Option<u64>,
    pub points_to: Option<u64>,
    pub hex_preview: Option<String>,
}

impl Classified {
    fn num(ty: &str, v: Value) -> Classified {
        Classified {
            ty: ty.to_string(),
            value: Some(v),
            as_unsigned: None,
            points_to: None,
            hex_preview: None,
        }
    }

    fn none(ty: &str) -> Classified {
        Classified {
            ty: ty.to_string(),
            value: None,
            as_unsigned: None,
            points_to: None,
            hex_preview: None,
        }
    }
}

/// Valid UTF-8 text up to the first NUL, with no control characters (tab/newline allowed).
fn text_prefix(bytes: &[u8], min_len: usize, require_nul: bool) -> Option<String> {
    let nul = bytes.iter().position(|&b| b == 0);
    let terminated = nul.is_some();
    let prefix = match nul {
        Some(i) => &bytes[..i],
        None => bytes,
    };
    if prefix.len() < min_len || (require_nul && !terminated) {
        return None;
    }
    let s: &str = match std::str::from_utf8(prefix) {
        Ok(s) => s,
        Err(e) => {
            // an unterminated buffer may end in the middle of a multi-byte character
            if !terminated && e.error_len().is_none() {
                match std::str::from_utf8(&prefix[..e.valid_up_to()]) {
                    Ok(s) => s,
                    Err(_) => return None,
                }
            } else {
                return None;
            }
        }
    };
    if s.chars()
        .any(|c| c.is_control() && c != '\t' && c != '\n' && c != '\r')
    {
        return None;
    }
    if s.chars().count() < min_len {
        return None;
    }
    Some(s.to_string())
}

fn blob(bytes: &[u8]) -> Classified {
    let mut c = Classified::none("blob");
    c.hex_preview = Some(hex(&bytes[..bytes.len().min(32)]));
    c
}

/// `u` lies in readable mapping `m`: it is a pointer. If it leads to text it is a `char *`.
fn follow_pointer(u: u64, m: &MapEntry, mem: &dyn MemSource, opts: &VarOptions) -> Classified {
    let avail = m.end - u;
    let want = if avail > opts.max_string as u64 {
        opts.max_string
    } else {
        avail as usize
    };
    if let Some(raw) = mem.read(u, want) {
        if let Some(s) = text_prefix(&raw, 1, true) {
            let mut c = Classified::num("char*", Value::Str(s));
            c.points_to = Some(u);
            return c;
        }
    }
    let mut c = Classified::none("ptr");
    c.points_to = Some(u);
    c
}

/// Infer what `bytes` (the content of a `declared`-byte object) most likely is.
pub fn classify(
    bytes: &[u8],
    declared: u64,
    truncated: bool,
    maps: &[MapEntry],
    mem: &dyn MemSource,
    opts: &VarOptions,
) -> Classified {
    let n = bytes.len();

    if bytes.iter().all(|&b| b == 0) {
        return match n {
            1 => Classified::num("u8", Value::Int(0)),
            2 => Classified::num("i16", Value::Int(0)),
            4 => Classified::num("i32", Value::Int(0)),
            8 => Classified::num("i64", Value::Int(0)),
            _ => Classified::none("zeroed"),
        };
    }

    // 1. A first word that points into readable memory wins over text detection:
    //    pointer bytes can be accidentally printable. A lone pointer is followed; anything
    //    bigger that starts with a pointer is a struct/array of pointers, so it stays a blob.
    if n >= 8 {
        let u = le_u64(bytes);
        if u != 0 {
            if let Some(m) = find_map(maps, u) {
                if m.readable() {
                    return if n == 8 {
                        follow_pointer(u, m, mem, opts)
                    } else {
                        blob(bytes)
                    };
                }
            }
        }
    }

    // 2. Text: short objects need >= 4 chars, so small integers are not mistaken for strings.
    let min_len = if n <= 8 { 4 } else { 2 };
    let require_nul = n < 8 || truncated;
    if let Some(s) = text_prefix(bytes, min_len, require_nul) {
        return Classified::num(&format!("char[{declared}]"), Value::Str(s));
    }

    // 3. Numbers by size.
    match n {
        8 => {
            let u = le_u64(bytes);
            let i = u as i64;
            if i.unsigned_abs() >= (1u64 << 40) {
                let f = f64::from_bits(u);
                if f.is_finite() && (1e-9..=1e15).contains(&f.abs()) {
                    return Classified::num("f64", Value::Float(f));
                }
            }
            let mut c = Classified::num("i64", Value::Int(i));
            if i < 0 {
                c.as_unsigned = Some(u);
            }
            c
        }
        4 => {
            let raw = le_u32(bytes);
            let i = raw as i32;
            if i.unsigned_abs() >= (1u32 << 20) {
                let f = f32::from_bits(raw);
                if f.is_finite() && (1e-6f32..=1e9f32).contains(&f.abs()) {
                    return Classified::num("f32", Value::Float32(f));
                }
            }
            let mut c = Classified::num("i32", Value::Int(i as i64));
            if i < 0 {
                c.as_unsigned = Some(raw as u64);
            }
            c
        }
        2 => {
            let raw = le_u16(bytes);
            let i = raw as i16;
            let mut c = Classified::num("i16", Value::Int(i as i64));
            if i < 0 {
                c.as_unsigned = Some(raw as u64);
            }
            c
        }
        1 => Classified::num("u8", Value::Int(bytes[0] as i64)),
        _ => blob(bytes),
    }
}

fn is_digits(s: &str) -> bool {
    !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit())
}

/// Type a text value (environment): a number only if its spelling is canonical,
/// so `0644`, `007`, `1.10`, `+5`, `1e5` stay strings.
pub fn scalar(s: &str) -> Value {
    let t = s.trim();
    if let Ok(i) = t.parse::<i64>() {
        if i.to_string() == t {
            return Value::Int(i);
        }
    }
    if let Some((a, b)) = t.strip_prefix('-').unwrap_or(t).split_once('.') {
        if is_digits(a) && is_digits(b) {
            if let Ok(f) = t.parse::<f64>() {
                if f.is_finite() && format!("{f:?}") == t {
                    return Value::Float(f);
                }
            }
        }
    }
    Value::Str(s.to_string())
}

fn is_noise(name: &str) -> bool {
    const EXACT: &[&str] = &[
        "__dso_handle",
        "_IO_stdin_used",
        "__TMC_END__",
        "__data_start",
        "data_start",
        "_edata",
        "_end",
        "__bss_start",
        "__FRAME_END__",
        "_GLOBAL_OFFSET_TABLE_",
        "_DYNAMIC",
        "completed.0",
        "__abi_tag",
        "__GNU_EH_FRAME_HDR",
        "__EH_FRAME_BEGIN__",
    ];
    const PREFIX: &[&str] = &[
        "__libc_",
        "_nl_",
        "_IO_",
        "__static_",
        "__init_array",
        "__fini_array",
        "__preinit_array",
        "__TMC",
        "__FRAME",
        "__bss",
        "__data",
        "__GNU",
        "__abi",
        "__EH",
        "__cxa",
        "__gcc",
        "__gxx",
        "__dso",
        "__do_global",
        "__frame_dummy",
    ];
    EXACT.contains(&name) || PREFIX.iter().any(|p| name.starts_with(p))
}

fn is_secret_name(name: &str) -> bool {
    const KEYS: &[&str] = &[
        "secret",
        "passw",
        "pwd",
        "token",
        "api_key",
        "apikey",
        "private_key",
        "privkey",
        "credential",
    ];
    let l = name.to_ascii_lowercase();
    KEYS.iter().any(|k| l.contains(k))
}

// ─────────────────────────────────── collection ───────────────────────────────────

/// Everything `collect` needs besides the memory itself.
pub struct Input<'a> {
    pub pid: u32,
    /// Path of the executable exactly as `/proc/<pid>/maps` shows it (`readlink /proc/<pid>/exe`).
    pub exe_path: &'a str,
    /// The running executable image (`/proc/<pid>/exe`, or `exe.bin` of a dump).
    pub elf: &'a [u8],
    /// Text of `/proc/<pid>/maps` (or `maps.txt`).
    pub maps: &'a str,
    /// Raw `/proc/<pid>/environ` (NUL separated; newline separated also works).
    pub environ: Option<&'a [u8]>,
    /// Unstripped build / `.debug` file of the same build, when the running binary is stripped.
    pub symbols_elf: Option<&'a [u8]>,
}

struct Cand {
    name: String,
    value: u64,
    size: u64,
    bind: u8,
    section: String,
}

fn rank(c: &Cand) -> (usize, u8, String) {
    let lead = c.name.len() - c.name.trim_start_matches('_').len();
    let b = match c.bind {
        1 => 0u8,
        2 => 1,
        0 => 2,
        _ => 3,
    };
    (lead, b, c.name.clone())
}

/// Build the typed variable dictionary.
///
/// Sources, strongest first: ELF symbols (`symbol`), data addresses touched by the program's own
/// code (`xref`), and, when `opts.watch` is set, observed behaviour of the running process (`watch`).
pub fn collect(input: &Input, mem: &dyn MemSource, opts: &VarOptions) -> Result<Report, String> {
    let run_elf = Elf::parse(input.elf)?;
    let maps = parse_maps(input.maps);
    let bias = load_bias(&run_elf, &maps, input.exe_path)?;

    let sym_owned: Option<Elf> = match input.symbols_elf {
        Some(b) => Some(Elf::parse(b).map_err(|e| format!("symbols file: {e}"))?),
        None => None,
    };
    let sym_elf: &Elf = sym_owned.as_ref().unwrap_or(&run_elf);

    let mut notes: Vec<String> = Vec::new();

    if sym_owned.is_some() {
        match (run_elf.build_id(), sym_elf.build_id()) {
            (Some(a), Some(b)) if a != b => {
                return Err(format!(
                    "symbols file does not match the running binary (build-id {} vs {})",
                    hex(&b),
                    hex(&a)
                ));
            }
            (Some(_), Some(_)) => {
                notes.push("symbols file build-id matches the running binary".to_string())
            }
            _ => notes.push(
                "build-id missing: could not verify that the symbols file matches the running binary"
                    .to_string(),
            ),
        }
    }

    let (symbols_from, symbols_seen, objs) = if opts.ignore_symbols {
        ("ignored", 0usize, Vec::new())
    } else {
        sym_elf.symbols()
    };
    if opts.ignore_symbols {
        notes.push(
            "symbols ignored by option: every name below is synthesized from code references and observation"
                .to_string(),
        );
    } else if symbols_from != "symtab" {
        notes.push(
            "no .symtab: the binary is stripped; variables without a symbol are discovered automatically from code references (names g_<offset>); pass an unstripped build or a .debug file of the same build to get the real names"
                .to_string(),
        );
    }

    // 1. symbol candidates: named, sized, allocated, non-TLS data objects
    let mut cands: Vec<Cand> = Vec::new();
    let mut covered: Vec<(u64, u64)> = Vec::new(); // link-time ranges owned by a symbol
    let mut noise = 0usize;
    for s in objs {
        if s.size > 0 {
            covered.push((s.value, s.value.saturating_add(s.size)));
        }
        let idx = s.shndx as usize;
        if s.size == 0
            || s.name.is_empty()
            || s.shndx == 0
            || s.shndx >= 0xff00
            || idx >= sym_elf.sections.len()
        {
            continue;
        }
        let sec = &sym_elf.sections[idx];
        if (sec.flags & SHF_ALLOC) == 0 || (sec.flags & SHF_TLS) != 0 {
            continue;
        }
        if !opts.include_rodata && sec.name.starts_with(".rodata") {
            continue;
        }
        if !opts.include_runtime_noise && is_noise(&s.name) {
            noise += 1;
            continue;
        }
        cands.push(Cand {
            name: s.name,
            value: s.value,
            size: s.size,
            bind: s.bind,
            section: sec.name.clone(),
        });
    }
    cands.sort_by(|a, b| (a.value, a.size).cmp(&(b.value, b.size)));

    // 2. group aliases (same address + size), pick one canonical name, read and classify
    let mut entries: Vec<VarEntry> = Vec::new();
    let mut used: HashSet<String> = HashSet::new();
    let mut pointer_globals: Vec<(String, u64)> = Vec::new();
    let mut unreadable = 0usize;
    let mut opaque = 0usize;
    let mut i = 0usize;
    while i < cands.len() {
        let mut j = i + 1;
        while j < cands.len() && cands[j].value == cands[i].value && cands[j].size == cands[i].size
        {
            j += 1;
        }
        let (start, end) = (i, j);
        i = j;

        let group = &mut cands[start..end];
        group.sort_by_key(rank);
        let canon_value = group[0].value;
        let canon_size = group[0].size;
        let canon_bind = group[0].bind;
        let canon_section = group[0].section.clone();
        let aliases: Vec<String> = group[1..].iter().map(|c| c.name.clone()).collect();

        let mut name = group[0].name.clone();
        if used.contains(&name) {
            name = format!("{name}@{canon_value:#x}");
        }
        used.insert(name.clone());

        let addr = match bias.checked_add(canon_value) {
            Some(a) => a,
            None => {
                unreadable += 1;
                continue;
            }
        };
        let want_u64 = canon_size.min(opts.max_object_size as u64);
        let want = want_u64 as usize;
        let truncated = canon_size > want_u64;
        let bytes = match mem.read(addr, want) {
            Some(b) if b.len() == want => b,
            _ => {
                unreadable += 1;
                continue;
            }
        };

        let c = classify(&bytes, canon_size, truncated, &maps, mem, opts);
        if let Some(p) = c.points_to {
            pointer_globals.push((name.clone(), p));
        }
        let mut value = c.value.clone();
        let mut redacted = false;
        if opts.redact_secrets && value.is_some() && is_secret_name(&name) {
            value = Some(Value::Str("***".to_string()));
            redacted = true;
        }
        if value.is_none() {
            opaque += 1;
            if !opts.keep_opaque {
                continue;
            }
        }
        entries.push(VarEntry {
            name,
            addr,
            size: canon_size,
            ty: c.ty,
            section: canon_section,
            binding: match canon_bind {
                0 => "local",
                1 => "global",
                2 => "weak",
                _ => "other",
            },
            value,
            aliases,
            as_unsigned: c.as_unsigned,
            points_to: c.points_to,
            hex_preview: c.hex_preview,
            truncated,
            redacted,
            source: "symbol",
            evidence: vec![format!("symbol in .{symbols_from}")],
        });
    }

    // 3. automatic discovery of everything the symbols do not cover (stripped binaries)
    if opts.discover {
        match discover::static_entries(&run_elf, bias, &covered, &maps, mem, opts, &mut used) {
            Ok(found) => {
                let mut kept = 0usize;
                for e in found {
                    if let Some(p) = e.points_to {
                        pointer_globals.push((e.name.clone(), p));
                    }
                    if e.value.is_some() || opts.keep_opaque {
                        kept += 1;
                        entries.push(e);
                    } else {
                        opaque += 1;
                    }
                }
                if kept > 0 {
                    notes.push(format!(
                        "{kept} variables discovered automatically from code references (no symbols needed)"
                    ));
                }
            }
            Err(e) => notes.push(format!("automatic discovery from code skipped: {e}")),
        }
    }

    // 4. optional: observe the running process
    if let Some(w) = &opts.watch {
        let res = discover::watch(mem, &maps, input.exe_path, &pointer_globals, w);
        let covered_rt: Vec<(u64, u64)> = covered
            .iter()
            .map(|&(lo, hi)| (bias.wrapping_add(lo), bias.wrapping_add(hi)))
            .collect();
        discover::merge_watch(&mut entries, &covered_rt, bias, &res, &mut used);
        notes.push(format!(
            "watch: {} samples every {} ms over {} windows ({} heap blocks reached through global pointers): {} changed 4-byte slots, {} accepted as variables",
            w.samples.max(3),
            w.interval_ms,
            res.windows.len(),
            res.windows.iter().filter(|x| x.is_block()).count(),
            res.changed_slots,
            res.observed.len()
        ));
    }
    entries.sort_by(|a, b| a.name.cmp(&b.name));

    // 5. environment: KEY=VALUE -> typed dictionary
    let mut environment: BTreeMap<String, Value> = BTreeMap::new();
    if opts.include_environment {
        if let Some(raw) = input.environ {
            for chunk in raw.split(|&b| b == 0 || b == b'\n') {
                if chunk.is_empty() {
                    continue;
                }
                let text = String::from_utf8_lossy(chunk);
                if let Some((k, v)) = text.split_once('=') {
                    if k.is_empty() {
                        continue;
                    }
                    let mut val = scalar(v);
                    if opts.redact_secrets && is_secret_name(k) {
                        val = Value::Str("***".to_string());
                    }
                    environment.insert(k.to_string(), val);
                }
            }
        }
    }

    if noise > 0 {
        notes.push(format!("{noise} runtime/bookkeeping symbols skipped"));
    }
    if opaque > 0 {
        let hint = if opts.keep_opaque {
            "listed in details"
        } else {
            "use keep_opaque to list them"
        };
        notes.push(format!(
            "{opaque} objects are pointers, structs/blobs or zeroed buffers and are not in the dictionary ({hint})"
        ));
    }
    if unreadable > 0 {
        notes.push(format!(
            "{unreadable} symbols could not be read from memory"
        ));
    }
    notes.push(
        "types are inferred (symbols give size, code gives access width and float use, content decides the rest); there is no debug info, so treat details.type as a strong hint"
            .to_string(),
    );

    Ok(Report {
        pid: input.pid,
        exe: input.exe_path.to_string(),
        elf_type: match run_elf.etype {
            2 => "EXEC",
            3 => "DYN",
            _ => "OTHER",
        },
        load_bias: bias,
        symbols_from,
        symbols_seen,
        entries,
        environment,
        notes,
    })
}

/// Collect from a live process. Run it inside the dump, while the target is still frozen.
pub fn collect_live(
    pid: u32,
    symbols_elf: Option<&[u8]>,
    opts: &VarOptions,
) -> Result<Report, String> {
    let exe_path = fs::read_link(format!("/proc/{pid}/exe"))
        .map_err(|e| format!("readlink /proc/{pid}/exe: {e}"))?
        .to_string_lossy()
        .into_owned();
    let elf =
        fs::read(format!("/proc/{pid}/exe")).map_err(|e| format!("read /proc/{pid}/exe: {e}"))?;
    let maps = fs::read_to_string(format!("/proc/{pid}/maps"))
        .map_err(|e| format!("read /proc/{pid}/maps: {e}"))?;
    let environ = fs::read(format!("/proc/{pid}/environ")).ok();
    let mem = ProcMem::open(pid).map_err(|e| format!("open /proc/{pid}/mem: {e}"))?;
    let input = Input {
        pid,
        exe_path: &exe_path,
        elf: &elf,
        maps: &maps,
        environ: environ.as_deref(),
        symbols_elf,
    };
    collect(&input, &mem, opts)
}

/// One-call entry point for the CLI: collect from `pid` and write `<out_dir>/variables.json`.
/// `symbols_path` is an optional unstripped build / `.debug` file of the same build.
pub fn dump_variables(
    pid: u32,
    out_dir: &Path,
    symbols_path: Option<&Path>,
    opts: &VarOptions,
) -> Result<(PathBuf, Report), String> {
    let sym_bytes = match symbols_path {
        Some(p) => {
            Some(fs::read(p).map_err(|e| format!("read symbols file {}: {e}", p.display()))?)
        }
        None => None,
    };
    let report = collect_live(pid, sym_bytes.as_deref(), opts)?;
    let path = report
        .write_to(out_dir)
        .map_err(|e| format!("write variables.json: {e}"))?;
    Ok((path, report))
}
