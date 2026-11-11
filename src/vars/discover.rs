//! Automatic variable discovery: no symbols, no declarations.
//!
//! Two independent sources of evidence, both working on a *stripped* program:
//!
//! 1. **Code references (`xref`, static).** Compilers address every global variable through the
//!    program counter (`mov eax, [rip+disp]`). Decoding the executable sections and collecting the
//!    RIP-relative data addresses therefore lists the variables the program really uses, and the
//!    instruction tells the type: the access width (1/2/4/8), SSE scalar instructions (float or
//!    double), `lea` (the address is taken: array, string or struct). x86_64 only; needs the
//!    `xrefs` cargo feature (iced-x86).
//!
//! 2. **Observation (`watch`, dynamic, opt-in).** The running process is sampled. Slots that behave
//!    like a counter (constant or small steps), a flag (two values) or a float (smooth) are
//!    variables. Only two kinds of memory are watched, because everything else (allocator
//!    metadata, stack frames) is noise that looks like variables:
//!      * the executable's own `.data`/`.bss`, and
//!      * heap blocks reachable from a global pointer found by (1) or by symbols; the block size
//!        comes from the glibc chunk header (64 bytes if there is none).
//!
//! Everything found here carries `source` and `evidence` so the reader can judge how sure to be.

use super::*;
use std::collections::HashMap;
use std::time::Duration;

// ───────────────────────────── static: code references ─────────────────────────────

/// What the program's code does with one data address.
#[derive(Default, Clone, Debug)]
pub struct Refs {
    pub count: u32,
    pub lea: u32,
    pub w1: u32,
    pub w2: u32,
    pub w4: u32,
    pub w8: u32,
    pub w16: u32,
    pub f32s: u32,
    pub f64s: u32,
}

impl Refs {
    /// Most frequent access width (ties go to the wider one); 0 if the address is only taken with `lea`.
    pub fn width(&self) -> usize {
        let counts = [
            (1usize, self.w1),
            (2, self.w2),
            (4, self.w4),
            (8, self.w8),
            (16, self.w16),
        ];
        let mut best = (0usize, 0u32);
        for &(w, n) in counts.iter() {
            if n > 0 && n >= best.1 {
                best = (w, n);
            }
        }
        best.0
    }
}

struct TargetSec {
    lo: u64,
    hi: u64,
    name: String,
}

fn is_target_name(n: &str, rodata: bool) -> bool {
    if n == ".data" || n == ".bss" || n.starts_with(".bss.") {
        return true;
    }
    if n.starts_with(".data.") {
        return !n.starts_with(".data.rel.ro");
    }
    rodata && n.starts_with(".rodata")
}

/// Allocated, non-executable, non-TLS sections that can hold variables.
fn target_sections(elf: &Elf, rodata: bool) -> Vec<TargetSec> {
    elf.sections
        .iter()
        .filter(|s| {
            (s.flags & SHF_ALLOC) != 0
                && (s.flags & SHF_EXECINSTR) == 0
                && (s.flags & SHF_TLS) == 0
                && s.size > 0
                && is_target_name(&s.name, rodata)
        })
        .map(|s| TargetSec {
            lo: s.addr,
            hi: s.addr.saturating_add(s.size),
            name: s.name.clone(),
        })
        .collect()
}

/// (single, double) for a legacy-encoded scalar SSE mnemonic (lowercase, no `v` prefix).
fn is_scalar_sse(m: &str) -> (bool, bool) {
    const SINGLE: &[&str] = &[
        "movss",
        "addss",
        "subss",
        "mulss",
        "divss",
        "sqrtss",
        "maxss",
        "minss",
        "comiss",
        "ucomiss",
        "cvtss2sd",
        "cvtss2si",
        "cvttss2si",
        "cmpss",
        "rcpss",
        "rsqrtss",
        "roundss",
    ];
    const DOUBLE: &[&str] = &[
        "movsd",
        "addsd",
        "subsd",
        "mulsd",
        "divsd",
        "sqrtsd",
        "maxsd",
        "minsd",
        "comisd",
        "ucomisd",
        "cvtsd2ss",
        "cvtsd2si",
        "cvttsd2si",
        "cmpsd",
        "roundsd",
    ];
    (SINGLE.contains(&m), DOUBLE.contains(&m))
}

/// Decode every executable section and count RIP-relative references into data sections.
#[cfg(feature = "xrefs")]
fn scan_xrefs(elf: &Elf, targets: &[TargetSec]) -> Result<BTreeMap<u64, Refs>, String> {
    use iced_x86::{Decoder, DecoderOptions, Instruction, Mnemonic};

    const EM_X86_64: u16 = 62;
    if elf.machine != EM_X86_64 {
        return Err(format!(
            "code-reference discovery supports x86_64 only (e_machine = {})",
            elf.machine
        ));
    }
    let mut out: BTreeMap<u64, Refs> = BTreeMap::new();
    let mut scanned = 0usize;
    for sec in elf.sections.iter() {
        if (sec.flags & SHF_EXECINSTR) == 0 || sec.typ == SHT_NOBITS || sec.size == 0 {
            continue;
        }
        if matches!(
            sec.name.as_str(),
            ".plt" | ".plt.got" | ".plt.sec" | ".init" | ".fini"
        ) {
            continue;
        }
        let code = match sl(elf.data, sec.offset, sec.size) {
            Some(c) => c,
            None => continue,
        };
        scanned += 1;
        let mut decoder = Decoder::with_ip(64, code, sec.addr, DecoderOptions::NONE);
        let mut instr = Instruction::default();
        while decoder.can_decode() {
            decoder.decode_out(&mut instr);
            if instr.is_invalid() || !instr.is_ip_rel_memory_operand() {
                continue;
            }
            let target = instr.ip_rel_memory_address();
            if !targets.iter().any(|t| target >= t.lo && target < t.hi) {
                continue;
            }
            let r = out.entry(target).or_default();
            r.count += 1;
            if instr.mnemonic() == Mnemonic::Lea {
                r.lea += 1;
                continue;
            }
            // scalar SSE: the mnemonic says float (ss) or double (sd), whatever the operand size
            // says. VEX forms (vmovss, vcomisd, ... as emitted with -mavx / x86-64-v3 builds) are
            // the same operations with a `v` prefix.
            let name = format!("{:?}", instr.mnemonic()).to_ascii_lowercase();
            let base = match name.strip_prefix('v') {
                Some(rest) if is_scalar_sse(rest) != (false, false) => rest,
                _ => name.as_str(),
            };
            let (single, double) = is_scalar_sse(base);
            if single {
                r.f32s += 1;
                r.w4 += 1;
            } else if double {
                r.f64s += 1;
                r.w8 += 1;
            } else {
                match instr.memory_size().size() {
                    1 => r.w1 += 1,
                    2 => r.w2 += 1,
                    4 => r.w4 += 1,
                    8 => r.w8 += 1,
                    16 => r.w16 += 1,
                    _ => {}
                }
            }
        }
    }
    if scanned == 0 {
        return Err("no executable sections to scan (section headers stripped?)".to_string());
    }
    Ok(out)
}

#[cfg(not(feature = "xrefs"))]
fn scan_xrefs(_elf: &Elf, _targets: &[TargetSec]) -> Result<BTreeMap<u64, Refs>, String> {
    Err("built without the `xrefs` cargo feature".to_string())
}

/// Type one referenced address from the evidence in `r` plus the bytes found there.
fn classify_static(
    bytes: &[u8],
    r: &Refs,
    width: usize,
    maps: &[MapEntry],
    mem: &dyn MemSource,
    opts: &VarOptions,
) -> (Classified, usize) {
    let n = bytes.len();

    // 1. a pointer-sized object holding a pointer into readable memory (followed to a string if any)
    if width == 8 && r.f64s == 0 && n >= 8 {
        let u = le_u64(bytes);
        if u != 0 {
            if let Some(m) = find_map(maps, u) {
                if m.readable() {
                    return (follow_pointer(u, m, mem, opts), 8);
                }
            }
        }
    }

    // 2. text: the object reaches past the access width, or it is only touched byte-wise / via lea
    if n > width || width <= 1 {
        let min_len = if width <= 1 { 2 } else { 4 };
        if let Some(s) = text_prefix(bytes, min_len, true) {
            return (Classified::num(&format!("char[{n}]"), Value::Str(s)), n);
        }
    }

    // 3. numbers, by the access width the code uses
    match width {
        0 => {
            // address taken, content is not text: a scalar if the object is that small, else a blob
            if matches!(n, 1 | 2 | 4 | 8) {
                (classify(bytes, n as u64, false, maps, mem, opts), n)
            } else if bytes.iter().all(|&b| b == 0) {
                (Classified::none("zeroed"), n)
            } else {
                (blob(bytes), n)
            }
        }
        1 => (Classified::num("u8", Value::Int(bytes[0] as i64)), 1),
        2 => {
            let raw = le_u16(bytes);
            let i = raw as i16;
            let mut c = Classified::num("i16", Value::Int(i as i64));
            if i < 0 {
                c.as_unsigned = Some(raw as u64);
            }
            (c, 2)
        }
        4 => {
            let raw = le_u32(bytes);
            let f = f32::from_bits(raw);
            if r.f32s > 0 && f.is_finite() {
                return (Classified::num("f32", Value::Float32(f)), 4);
            }
            let i = raw as i32;
            let mut c = Classified::num("i32", Value::Int(i as i64));
            if i < 0 {
                c.as_unsigned = Some(raw as u64);
            }
            (c, 4)
        }
        8 => {
            let raw = le_u64(bytes);
            let f = f64::from_bits(raw);
            if r.f64s > 0 && f.is_finite() {
                return (Classified::num("f64", Value::Float(f)), 8);
            }
            let i = raw as i64;
            let mut c = Classified::num("i64", Value::Int(i));
            if i < 0 {
                c.as_unsigned = Some(raw);
            }
            (c, 8)
        }
        _ => (blob(bytes), width),
    }
}

/// Variables that no symbol covers, found from the program's own code references.
/// `covered` holds link-time `[lo, hi)` ranges that belong to symbols.
pub fn static_entries(
    elf: &Elf,
    bias: u64,
    covered: &[(u64, u64)],
    maps: &[MapEntry],
    mem: &dyn MemSource,
    opts: &VarOptions,
    used: &mut HashSet<String>,
) -> Result<Vec<VarEntry>, String> {
    let targets = target_sections(elf, opts.discover_rodata);
    let refs = scan_xrefs(elf, &targets)?;
    let keys: Vec<u64> = refs.keys().copied().collect();

    let mut out: Vec<VarEntry> = Vec::new();
    for (i, &a) in keys.iter().enumerate() {
        if covered.iter().any(|&(lo, hi)| a >= lo && a < hi) {
            continue;
        }
        let r = &refs[&a];
        let tsec = match targets.iter().find(|t| a >= t.lo && a < t.hi) {
            Some(t) => t,
            None => continue,
        };
        // the object extends to the next referenced address (or the end of its section)
        let next = if i + 1 < keys.len() {
            keys[i + 1]
        } else {
            tsec.hi
        };
        let extent = (next.min(tsec.hi) - a).min(256) as usize;
        let width = r.width();
        let runtime = bias.wrapping_add(a);
        let bytes = match mem.read(runtime, extent) {
            Some(b) if b.len() >= width.max(1) => b,
            _ => continue,
        };

        let (c, size) = classify_static(&bytes, r, width, maps, mem, opts);
        // a pointer to itself is the C runtime's __dso_handle, not a program variable
        if c.ty == "ptr" && c.points_to == Some(runtime) {
            continue;
        }

        let prefix = if tsec.name.starts_with(".rodata") {
            "ro"
        } else {
            "g"
        };
        let mut name = format!("{prefix}_{a:x}");
        if used.contains(&name) {
            name = format!("{name}@{runtime:#x}");
        }
        used.insert(name.clone());

        let mut ev = vec![format!("{} code references", r.count)];
        if r.f32s + r.f64s > 0 {
            ev.push("read or written with SSE float instructions".to_string());
        }
        if r.lea > 0 {
            ev.push(format!("address taken {}x (lea)", r.lea));
        }
        if width > 0 {
            ev.push(format!("accessed as {} byte(s)", width));
        }
        out.push(VarEntry {
            name,
            addr: runtime,
            size: size as u64,
            ty: c.ty,
            section: tsec.name.clone(),
            binding: "unknown",
            value: c.value,
            aliases: Vec::new(),
            as_unsigned: c.as_unsigned,
            points_to: c.points_to,
            hex_preview: c.hex_preview,
            truncated: false,
            redacted: false,
            source: "xref",
            evidence: ev,
        });
    }
    Ok(out)
}

// ─────────────────────────────── dynamic: observation ───────────────────────────────

/// How the running process is sampled.
#[derive(Debug, Clone)]
pub struct WatchOptions {
    /// Number of snapshots (at least 3).
    pub samples: usize,
    /// Pause between snapshots.
    pub interval_ms: u64,
    /// Largest heap block followed behind a global pointer.
    pub max_block: usize,
    /// Upper bound for the memory read per snapshot.
    pub max_scan_bytes: usize,
}

impl Default for WatchOptions {
    fn default() -> Self {
        WatchOptions {
            samples: 6,
            interval_ms: 120,
            max_block: 4096,
            max_scan_bytes: 64 << 20,
        }
    }
}

#[derive(Clone, Copy, PartialEq)]
pub enum WinKind {
    Exe,
    Block,
}

pub struct Window {
    pub start: u64,
    pub len: usize,
    pub kind: WinKind,
    /// Name of the global pointer that leads to this block (blocks only).
    pub owner: String,
}

impl Window {
    pub fn is_block(&self) -> bool {
        self.kind == WinKind::Block
    }
}

pub struct Observed {
    pub addr: u64,
    pub width: usize,
    pub kind: &'static str,
    pub values: Vec<u64>,
}

pub struct WatchResult {
    pub windows: Vec<Window>,
    pub changed_slots: usize,
    pub observed: Vec<Observed>,
    /// (owner pointer name, address, offset inside the block, text)
    pub strings: Vec<(String, u64, u64, String)>,
}

fn is_rw_private(m: &MapEntry) -> bool {
    let p = m.perms.as_bytes();
    p.len() >= 4 && p[0] == b'r' && p[1] == b'w' && p[3] == b'p'
}

/// Usable size of the heap block at `target`, from the glibc chunk header; 64 if there is none.
fn chunk_window(mem: &dyn MemSource, target: u64, avail: u64, cap: usize) -> usize {
    let mut win = 64usize;
    if (target & 0xf) == 0 && target >= 8 {
        if let Some(h) = mem.read(target - 8, 8) {
            if h.len() == 8 {
                let size = le_u64(&h) & !7u64;
                if (0x20..=(1u64 << 20)).contains(&size) {
                    win = (size - 8) as usize;
                }
            }
        }
    }
    win.min(cap).min(avail as usize)
}

fn build_windows(
    mem: &dyn MemSource,
    maps: &[MapEntry],
    exe_path: &str,
    pointer_globals: &[(String, u64)],
    w: &WatchOptions,
) -> Vec<Window> {
    let mut wins: Vec<Window> = Vec::new();
    let mut budget = w.max_scan_bytes;

    // the executable's own writable data
    let mut exe_ends: Vec<u64> = Vec::new();
    for m in maps.iter() {
        if m.path == exe_path && is_rw_private(m) {
            let len = (m.end - m.start) as usize;
            if len <= budget {
                budget -= len;
                exe_ends.push(m.end);
                wins.push(Window {
                    start: m.start,
                    len,
                    kind: WinKind::Exe,
                    owner: String::new(),
                });
            }
        }
    }
    // the .bss tail is an anonymous mapping right behind the executable's data mapping
    for m in maps.iter() {
        if m.path.is_empty() && is_rw_private(m) && exe_ends.contains(&m.start) {
            let len = (m.end - m.start) as usize;
            if len <= budget {
                budget -= len;
                wins.push(Window {
                    start: m.start,
                    len,
                    kind: WinKind::Exe,
                    owner: String::new(),
                });
            }
        }
    }

    // heap blocks behind global pointers
    let mut seen: HashSet<u64> = HashSet::new();
    for (name, target) in pointer_globals.iter() {
        if !seen.insert(*target) {
            continue;
        }
        let m = match find_map(maps, *target) {
            Some(m) => m,
            None => continue,
        };
        if !is_rw_private(m) || !(m.path == "[heap]" || m.path.is_empty()) {
            continue;
        }
        if wins
            .iter()
            .any(|x| *target >= x.start && *target < x.start + x.len as u64)
        {
            continue; // already inside a watched window
        }
        let len = chunk_window(mem, *target, m.end - *target, w.max_block);
        if len < 4 || len > budget {
            continue;
        }
        budget -= len;
        wins.push(Window {
            start: *target,
            len,
            kind: WinKind::Block,
            owner: name.clone(),
        });
    }
    wins
}

/// Per-sample values of a sparse change list.
fn dense(s: &[(usize, u32)], samples: usize) -> Vec<u32> {
    let mut out = Vec::with_capacity(samples);
    let mut idx = 0usize;
    let mut cur = s[0].1;
    for k in 0..samples {
        while idx < s.len() && s[idx].0 <= k {
            cur = s[idx].1;
            idx += 1;
        }
        out.push(cur);
    }
    out
}

/// Join two 4-byte halves into one 8-byte series (consecutive duplicates removed).
pub fn merge_halves(lo: &[(usize, u32)], hi: &[(usize, u32)], samples: usize) -> Vec<u64> {
    let l = dense(lo, samples);
    let h = dense(hi, samples);
    let mut out: Vec<u64> = Vec::new();
    for (a, b) in l.iter().zip(h.iter()) {
        let v = (*a as u64) | ((*b as u64) << 32);
        if out.last() != Some(&v) {
            out.push(v);
        }
    }
    out
}

/// What a series of distinct consecutive values looks like. `varying` means: not a variable we trust.
pub fn classify_series(width: usize, vals: &[u64]) -> &'static str {
    if vals.len() < 3 {
        return "varying";
    }
    let ch = vals.len() - 1;
    let lim: i128 = if width == 4 { 1 << 24 } else { 1 << 32 };
    let to_i = |v: u64| -> i128 {
        if width == 4 {
            v as u32 as i32 as i128
        } else {
            v as i64 as i128
        }
    };
    let ints: Vec<i128> = vals.iter().map(|&v| to_i(v)).collect();
    let deltas: Vec<i128> = ints.windows(2).map(|w| w[1] - w[0]).collect();
    let all_pos = deltas.iter().all(|&d| d > 0);
    let all_neg = deltas.iter().all(|&d| d < 0);
    let maxabs = deltas.iter().map(|d| d.abs()).max().unwrap_or(0);
    let same = deltas.iter().all(|&d| d == deltas[0]);

    // counters step by a fixed or small amount; allocator garbage jumps around
    if ch >= 3 && same && deltas[0] != 0 && deltas[0].abs() <= lim {
        return "counter";
    }
    if ch >= 2 && (all_pos || all_neg) && maxabs <= lim {
        return "counter";
    }
    let mut distinct: Vec<u64> = vals.to_vec();
    distinct.sort_unstable();
    distinct.dedup();
    if distinct.len() == 2 {
        return "toggle";
    }

    let (lo, hi, big) = if width == 4 {
        (1e-6, 1e9, 1u64 << 20)
    } else {
        (1e-9, 1e15, 1u64 << 40)
    };
    let mut fs: Vec<f64> = Vec::with_capacity(vals.len());
    for &v in vals {
        let f = if width == 4 {
            f32::from_bits(v as u32) as f64
        } else {
            f64::from_bits(v)
        };
        let mag = if width == 4 {
            (v as u32 as i32).unsigned_abs() as u64
        } else {
            (v as i64).unsigned_abs()
        };
        if !f.is_finite() || !(lo..=hi).contains(&f.abs()) || mag < big {
            return "varying";
        }
        fs.push(f);
    }
    let smooth = fs
        .windows(2)
        .all(|w| (w[1] - w[0]).abs() <= 0.5 * w[0].abs().max(w[1].abs()));
    if smooth {
        return "float";
    }
    "varying"
}

/// Sample the running process and report slots that behave like variables.
pub fn watch(
    mem: &dyn MemSource,
    maps: &[MapEntry],
    exe_path: &str,
    pointer_globals: &[(String, u64)],
    w: &WatchOptions,
) -> WatchResult {
    let samples = w.samples.max(3);
    let windows = build_windows(mem, maps, exe_path, pointer_globals, w);

    let read_all = |wins: &[Window]| -> Vec<Option<Vec<u8>>> {
        wins.iter()
            .map(|x| match mem.read(x.start, x.len) {
                Some(b) if b.len() == x.len => Some(b),
                _ => None,
            })
            .collect()
    };

    // address -> (sample index, value) for every change of a 4-byte slot
    let mut series: HashMap<u64, Vec<(usize, u32)>> = HashMap::new();
    let mut prev = read_all(&windows);
    for s in 1..samples {
        std::thread::sleep(Duration::from_millis(w.interval_ms));
        let cur = read_all(&windows);
        for (idx, win) in windows.iter().enumerate() {
            let (a, b) = match (&prev[idx], &cur[idx]) {
                (Some(a), Some(b)) => (a, b),
                _ => continue,
            };
            if a == b {
                continue;
            }
            for i in 0..win.len / 4 {
                let o = i * 4;
                let x = le_u32(&a[o..]);
                let y = le_u32(&b[o..]);
                if x != y {
                    series
                        .entry(win.start + o as u64)
                        .or_insert_with(|| vec![(s - 1, x)])
                        .push((s, y));
                }
            }
        }
        prev = cur;
    }

    let mut addrs: Vec<u64> = series.keys().copied().collect();
    addrs.sort_unstable();
    let mut done: HashSet<u64> = HashSet::new();
    let mut observed: Vec<Observed> = Vec::new();
    for &addr in addrs.iter() {
        if done.contains(&addr) {
            continue;
        }
        let lo: Vec<u64> = series[&addr].iter().map(|&(_, v)| v as u64).collect();
        let k4 = classify_series(4, &lo);
        if (addr & 7) == 0 {
            if let Some(hs) = series.get(&(addr + 4)) {
                let hi: Vec<u64> = hs.iter().map(|&(_, v)| v as u64).collect();
                // a half that looks random hints at one wider value (double, 64-bit counter)
                if k4 == "varying" || classify_series(4, &hi) == "varying" {
                    done.insert(addr + 4);
                    let merged = merge_halves(&series[&addr], hs, samples);
                    let k8 = classify_series(8, &merged);
                    if k8 != "varying" {
                        observed.push(Observed {
                            addr,
                            width: 8,
                            kind: k8,
                            values: merged,
                        });
                        continue;
                    }
                }
            }
        }
        if k4 != "varying" {
            observed.push(Observed {
                addr,
                width: 4,
                kind: k4,
                values: lo,
            });
        }
    }

    // text inside the watched heap blocks (names, labels), skipping pointer-looking words
    let mut strings: Vec<(String, u64, u64, String)> = Vec::new();
    for win in windows.iter().filter(|x| x.kind == WinKind::Block) {
        let blk = match mem.read(win.start, win.len) {
            Some(b) => b,
            None => continue,
        };
        let mut off = 0usize;
        while off + 4 <= blk.len() {
            let word_is_pointer = blk.len() >= off + 8
                && find_map(maps, le_u64(&blk[off..])).is_some()
                && le_u64(&blk[off..]) != 0;
            let end = (off + 64).min(blk.len());
            let text = if word_is_pointer {
                None
            } else {
                text_prefix(&blk[off..end], 3, true)
            };
            match text {
                Some(t) => {
                    strings.push((
                        win.owner.clone(),
                        win.start + off as u64,
                        off as u64,
                        t.clone(),
                    ));
                    off += ((t.len() + 1 + 7) & !7usize).max(8);
                }
                None => off += 8,
            }
        }
    }

    WatchResult {
        windows,
        changed_slots: series.len(),
        observed,
        strings,
    }
}

fn show(ob: &Observed, v: u64) -> String {
    match (ob.kind, ob.width) {
        ("float", 4) => format!("{}", f32::from_bits(v as u32)),
        ("float", _) => format!("{}", f64::from_bits(v)),
        (_, 4) => format!("{}", v as u32 as i32),
        _ => format!("{}", v as i64),
    }
}

/// Add what the observation found: evidence for known variables, new entries for the rest.
pub fn merge_watch(
    entries: &mut Vec<VarEntry>,
    covered_rt: &[(u64, u64)],
    bias: u64,
    res: &WatchResult,
    used: &mut HashSet<String>,
) {
    for ob in res.observed.iter() {
        let first = ob.values[0];
        let last = ob.values[ob.values.len() - 1];
        let ev = format!(
            "changed {}x while watched ({}): {} -> {}",
            ob.values.len() - 1,
            ob.kind,
            show(ob, first),
            show(ob, last)
        );

        // 1. a variable we already know: this is proof that it is live state
        if let Some(e) = entries
            .iter_mut()
            .find(|e| ob.addr >= e.addr && ob.addr < e.addr + e.size.max(1))
        {
            e.evidence.push(ev);
            continue;
        }
        // 2. inside a symbol's range whose value we chose not to list
        if covered_rt
            .iter()
            .any(|&(lo, hi)| ob.addr >= lo && ob.addr < hi)
        {
            continue;
        }
        // 3. a new variable
        let win = match res
            .windows
            .iter()
            .find(|x| ob.addr >= x.start && ob.addr < x.start + x.len as u64)
        {
            Some(x) => x,
            None => continue,
        };
        let (mut name, section) = match win.kind {
            WinKind::Exe => (
                format!("g_{:x}", ob.addr.wrapping_sub(bias)),
                "exe data".to_string(),
            ),
            WinKind::Block => (
                format!("{}->+{:#x}", win.owner, ob.addr - win.start),
                format!("heap block behind {}", win.owner),
            ),
        };
        if used.contains(&name) {
            name = format!("{name}@{:#x}", ob.addr);
        }
        used.insert(name.clone());

        let (ty, value) = match (ob.kind, ob.width) {
            ("float", 4) => ("f32", Value::Float32(f32::from_bits(last as u32))),
            ("float", _) => ("f64", Value::Float(f64::from_bits(last))),
            (_, 4) => ("i32", Value::Int(last as u32 as i32 as i64)),
            _ => ("i64", Value::Int(last as i64)),
        };
        entries.push(VarEntry {
            name,
            addr: ob.addr,
            size: ob.width as u64,
            ty: ty.to_string(),
            section,
            binding: "unknown",
            value: Some(value),
            aliases: Vec::new(),
            as_unsigned: None,
            points_to: None,
            hex_preview: None,
            truncated: false,
            redacted: false,
            source: "watch",
            evidence: vec![ev],
        });
    }

    for (owner, addr, off, text) in res.strings.iter() {
        if entries
            .iter()
            .any(|e| *addr >= e.addr && *addr < e.addr + e.size.max(1))
        {
            continue;
        }
        let mut name = format!("{owner}->+{off:#x}");
        if used.contains(&name) {
            name = format!("{name}@{addr:#x}");
        }
        used.insert(name.clone());
        entries.push(VarEntry {
            name,
            addr: *addr,
            size: text.len() as u64 + 1,
            ty: "char[]".to_string(),
            section: format!("heap block behind {owner}"),
            binding: "unknown",
            value: Some(Value::Str(text.clone())),
            aliases: Vec::new(),
            as_unsigned: None,
            points_to: None,
            hex_preview: None,
            truncated: false,
            redacted: false,
            source: "watch",
            evidence: vec!["text inside a heap block reached through a global pointer".to_string()],
        });
    }
}
