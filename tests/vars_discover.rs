//! Tests for automatic discovery (code references, live watching).

use penguin_cloner::vars::discover::*;
use penguin_cloner::vars::*;
use std::cell::Cell;
use std::collections::HashSet;

#[test]
fn series_classification() {
    assert_eq!(classify_series(4, &[6000, 7000, 8000, 9000]), "counter");
    assert_eq!(classify_series(4, &[6, 7, 8, 10]), "counter"); // jittery step, still small
    assert_eq!(classify_series(4, &[0, 1, 0, 1]), "toggle");
    let floats: Vec<u64> = [0.9f64, 0.85, 0.7, 0.62]
        .iter()
        .map(|f| f.to_bits())
        .collect();
    assert_eq!(classify_series(8, &floats), "float");
    // allocator-like garbage: huge jumps, many distinct values, not float-like
    assert_eq!(classify_series(4, &[3, 900_000_000, 5, 77_000]), "varying");
    assert_eq!(classify_series(4, &[1, 2]), "varying"); // too short to trust
}

#[test]
fn halves_are_joined_by_sample_index() {
    let lo = vec![(0usize, 5u32), (1, 6)];
    let hi = vec![(0usize, 9u32), (2, 10)];
    let m = merge_halves(&lo, &hi, 4);
    assert_eq!(
        m,
        vec![(9u64 << 32) | 5, (9u64 << 32) | 6, (10u64 << 32) | 6]
    );
}

/// Memory whose first words change on every snapshot, like a live program.
struct Ticking {
    start: u64,
    reads: Cell<u64>,
}

impl MemSource for Ticking {
    fn read(&self, addr: u64, len: usize) -> Option<Vec<u8>> {
        if addr != self.start {
            return None;
        }
        let k = self.reads.get();
        self.reads.set(k + 1);
        let mut b = vec![0u8; len];
        b[0..4].copy_from_slice(&((100 + 7 * k) as u32).to_le_bytes()); // counter, step 7
        let load = 0.9f64 - 0.05 * k as f64;
        b[8..16].copy_from_slice(&load.to_bits().to_le_bytes()); // smooth double
        b[16..20].copy_from_slice(&((k % 2) as u32).to_le_bytes()); // flag
        Some(b)
    }
}

#[test]
fn watch_finds_counter_float_and_flag() {
    let maps = parse_maps("1000-2000 rw-p 00000000 08:01 7   /bin/target\n");
    let mem = Ticking {
        start: 0x1000,
        reads: Cell::new(0),
    };
    let w = WatchOptions {
        samples: 6,
        interval_ms: 0,
        ..Default::default()
    };
    let res = watch(&mem, &maps, "/bin/target", &[], &w);
    let find = |addr: u64| res.observed.iter().find(|o| o.addr == addr);

    let c = find(0x1000).expect("counter");
    assert_eq!((c.width, c.kind), (4, "counter"));
    let f = find(0x1008).expect("float");
    assert_eq!((f.width, f.kind), (8, "float"));
    let t = find(0x1010).expect("flag");
    assert_eq!((t.width, t.kind), (4, "toggle"));
}

#[test]
fn merge_adds_evidence_and_new_entries() {
    let maps = parse_maps("1000-2000 rw-p 00000000 08:01 7   /bin/target\n");
    let mem = Ticking {
        start: 0x1000,
        reads: Cell::new(0),
    };
    let w = WatchOptions {
        samples: 6,
        interval_ms: 0,
        ..Default::default()
    };
    let res = watch(&mem, &maps, "/bin/target", &[], &w);
    let mut entries: Vec<VarEntry> = Vec::new();
    let mut used: HashSet<String> = HashSet::new();
    merge_watch(&mut entries, &[], 0x1000, &res, &mut used);
    let names: Vec<&str> = entries.iter().map(|e| e.name.as_str()).collect();
    assert!(names.contains(&"g_0"), "{names:?}"); // counter at link-time offset 0
    let counter = entries.iter().find(|e| e.name == "g_0").unwrap();
    assert_eq!(counter.source, "watch");
    assert_eq!(counter.ty, "i32");
    let load = entries.iter().find(|e| e.name == "g_8").unwrap();
    assert_eq!(load.ty, "f64");
}

#[cfg(feature = "xrefs")]
mod xrefs {
    use super::*;

    fn le32(v: &mut Vec<u8>, x: u32) {
        v.extend_from_slice(&x.to_le_bytes());
    }
    fn le64(v: &mut Vec<u8>, x: u64) {
        v.extend_from_slice(&x.to_le_bytes());
    }

    /// Hand-assembled x86_64 code that touches four data addresses, in a minimal ELF image:
    ///   mov  eax, [rip+..]    -> 0x4000 (i32)
    ///   movss xmm0, [rip+..]  -> 0x4004 (f32)
    ///   movsd xmm0, [rip+..]  -> 0x4008 (f64)
    ///   lea  rdi, [rip+..]    -> 0x4010 (string)
    fn image() -> Vec<u8> {
        image_with(&[0xF3, 0x0F, 0x10, 0x05], &[0xF2, 0x0F, 0x10, 0x05])
    }

    /// Same program as `image`, with the float/double loads given as raw opcode prefixes
    /// (legacy SSE: `movss`/`movsd`; VEX: `vmovss`/`vmovsd`, both 4 bytes before the disp32).
    fn image_with(movss: &[u8; 4], movsd: &[u8; 4]) -> Vec<u8> {
        let mut code: Vec<u8> = Vec::new();
        code.extend_from_slice(&[0x8B, 0x05]);
        le32(&mut code, 0x4000 - 0x1006);
        code.extend_from_slice(movss);
        le32(&mut code, 0x4004 - 0x100E);
        code.extend_from_slice(movsd);
        le32(&mut code, 0x4008 - 0x1016);
        code.extend_from_slice(&[0x48, 0x8D, 0x3D]);
        le32(&mut code, 0x4010 - 0x101D);
        code.push(0xC3);

        let shstr: &[u8] = b"\0.text\0.data\0.shstrtab\0";
        let text_off = 0x40usize;
        let data_off = 0x100usize;
        let str_off = 0x140usize;
        let sh_off = 0x180usize;

        let mut img = vec![0u8; sh_off];
        img[..4].copy_from_slice(b"\x7fELF");
        img[4] = 2; // 64-bit
        img[5] = 1; // little-endian
        img[6] = 1;
        img[16..18].copy_from_slice(&3u16.to_le_bytes()); // ET_DYN
        img[18..20].copy_from_slice(&62u16.to_le_bytes()); // x86_64
        img[40..48].copy_from_slice(&(sh_off as u64).to_le_bytes()); // e_shoff
        img[52..54].copy_from_slice(&64u16.to_le_bytes()); // e_ehsize
        img[58..60].copy_from_slice(&64u16.to_le_bytes()); // e_shentsize
        img[60..62].copy_from_slice(&4u16.to_le_bytes()); // e_shnum
        img[62..64].copy_from_slice(&3u16.to_le_bytes()); // e_shstrndx
        img[text_off..text_off + code.len()].copy_from_slice(&code);
        img[str_off..str_off + shstr.len()].copy_from_slice(shstr);

        // section headers: null, .text (AX), .data (WA), .shstrtab
        let mut sh: Vec<u8> = vec![0u8; 64];
        let mut add = |name: u32, typ: u32, flags: u64, addr: u64, off: usize, size: usize| {
            le32(&mut sh, name);
            le32(&mut sh, typ);
            le64(&mut sh, flags);
            le64(&mut sh, addr);
            le64(&mut sh, off as u64);
            le64(&mut sh, size as u64);
            le32(&mut sh, 0);
            le32(&mut sh, 0);
            le64(&mut sh, 1);
            le64(&mut sh, 0);
        };
        add(1, 1, 0x6, 0x1000, text_off, code.len());
        add(7, 1, 0x3, 0x4000, data_off, 0x20);
        add(13, 3, 0, 0, str_off, shstr.len());
        img.extend_from_slice(&sh);
        img
    }

    fn data() -> Vec<u8> {
        let mut d = vec![0u8; 0x20];
        d[0..4].copy_from_slice(&512i32.to_le_bytes());
        d[4..8].copy_from_slice(&2.5f32.to_le_bytes());
        d[8..16].copy_from_slice(&7.25f64.to_le_bytes());
        d[16..22].copy_from_slice(b"hello\0");
        d
    }

    #[test]
    fn code_references_reveal_typed_variables_without_symbols() {
        let img = image();
        let elf = Elf::parse(&img).expect("synthetic ELF");
        let mem = RegionsMem::new(vec![(0x4000, data())]);
        let opts = VarOptions::default();
        let mut used: HashSet<String> = HashSet::new();
        let found = static_entries(&elf, 0, &[], &[], &mem, &opts, &mut used).expect("scan");

        let by = |n: &str| found.iter().find(|e| e.name == n);
        let i = by("g_4000").expect("i32");
        assert_eq!(
            (i.ty.as_str(), i.value.clone()),
            ("i32", Some(Value::Int(512)))
        );
        let f = by("g_4004").expect("f32");
        assert_eq!(
            (f.ty.as_str(), f.value.clone()),
            ("f32", Some(Value::Float32(2.5)))
        );
        let d = by("g_4008").expect("f64");
        assert_eq!(
            (d.ty.as_str(), d.value.clone()),
            ("f64", Some(Value::Float(7.25)))
        );
        let s = by("g_4010").expect("string");
        assert_eq!(s.value, Some(Value::Str("hello".to_string())));
        assert!(s.evidence.iter().any(|e| e.contains("lea")));
        assert!(found.iter().all(|e| e.source == "xref"));
    }

    #[test]
    fn vex_encoded_scalar_sse_is_typed_like_legacy_sse() {
        // vmovss xmm0, [rip+d] = C5 FA 10 05 ; vmovsd xmm0, [rip+d] = C5 FB 10 05
        let img = image_with(&[0xC5, 0xFA, 0x10, 0x05], &[0xC5, 0xFB, 0x10, 0x05]);
        let elf = Elf::parse(&img).expect("synthetic ELF");
        let mem = RegionsMem::new(vec![(0x4000, data())]);
        let mut used: HashSet<String> = HashSet::new();
        let found = static_entries(&elf, 0, &[], &[], &mem, &VarOptions::default(), &mut used)
            .expect("scan");
        let ty = |n: &str| found.iter().find(|e| e.name == n).map(|e| e.ty.clone());
        assert_eq!(ty("g_4004").as_deref(), Some("f32"));
        assert_eq!(ty("g_4008").as_deref(), Some("f64"));
    }

    #[test]
    fn symbol_ranges_are_not_rediscovered() {
        let img = image();
        let elf = Elf::parse(&img).expect("synthetic ELF");
        let mem = RegionsMem::new(vec![(0x4000, data())]);
        let opts = VarOptions::default();
        let mut used: HashSet<String> = HashSet::new();
        let covered = [(0x4000u64, 0x4008u64)]; // a symbol owns the i32 and the f32
        let found = static_entries(&elf, 0, &covered, &[], &mem, &opts, &mut used).expect("scan");
        assert!(found
            .iter()
            .all(|e| e.name != "g_4000" && e.name != "g_4004"));
        assert!(found.iter().any(|e| e.name == "g_4008"));
    }
}
