//! Tests for the variable dictionary (symbols, classification, JSON shape, live self-dump).

use penguin_cloner::vars::*;
use std::collections::BTreeMap;
use std::sync::atomic::{AtomicBool, AtomicI32, AtomicPtr, AtomicU32, AtomicU64, Ordering};

const fn padded<const N: usize>(s: &[u8]) -> [u8; N] {
    let mut a = [0u8; N];
    let mut i = 0;
    while i < s.len() && i < N {
        a[i] = s[i];
        i += 1;
    }
    a
}

// Real variables of this very test binary, found by name through its own symbol table.
static PC_T_MAX_CONN: AtomicI32 = AtomicI32::new(512);
static PC_T_RATIO_BITS: AtomicU32 = AtomicU32::new(0x4020_0000); // 2.5f32
static PC_T_TIMEOUT_BITS: AtomicU64 = AtomicU64::new(0x401D_0000_0000_0000); // 7.25f64
static PC_T_ZERO: AtomicI32 = AtomicI32::new(0);
static PC_T_PTR: AtomicPtr<u8> = AtomicPtr::new(std::ptr::null_mut());
static PC_T_NAME: [u8; 32] = padded(b"legacy-01.example");
static PC_T_TARGET: [u8; 16] = padded(b"pointed string");

#[test]
fn live_self_dump_maps_typed_globals() {
    PC_T_PTR.store(PC_T_TARGET.as_ptr() as *mut u8, Ordering::SeqCst);
    std::hint::black_box((
        &PC_T_MAX_CONN,
        &PC_T_RATIO_BITS,
        &PC_T_TIMEOUT_BITS,
        &PC_T_ZERO,
        &PC_T_PTR,
        &PC_T_NAME,
        &PC_T_TARGET,
    ));

    let report =
        collect_live(std::process::id(), None, &VarOptions::default()).expect("collect_live");
    let get = |needle: &str| -> Option<Value> {
        report
            .entries
            .iter()
            .find(|e| e.name.contains(needle))
            .and_then(|e| e.value.clone())
    };
    assert_eq!(get("PC_T_MAX_CONN"), Some(Value::Int(512)));
    assert_eq!(get("PC_T_RATIO_BITS"), Some(Value::Float32(2.5)));
    assert_eq!(get("PC_T_TIMEOUT_BITS"), Some(Value::Float(7.25)));
    assert_eq!(get("PC_T_ZERO"), Some(Value::Int(0)));
    assert_eq!(
        get("PC_T_NAME"),
        Some(Value::Str("legacy-01.example".to_string()))
    );
    assert_eq!(
        get("PC_T_PTR"),
        Some(Value::Str("pointed string".to_string()))
    );

    let json = report.to_json();
    assert!(json.contains("\"variables\": {"));
    assert!(json.contains("penguin-cloner/variables@1"));
}

static PC_W_TICKS: AtomicU64 = AtomicU64::new(0);
static PC_W_STOP: AtomicBool = AtomicBool::new(false);

#[test]
fn live_watch_sees_a_counter_change() {
    PC_W_STOP.store(false, Ordering::SeqCst);
    let worker = std::thread::spawn(|| {
        while !PC_W_STOP.load(Ordering::SeqCst) {
            PC_W_TICKS.fetch_add(1000, Ordering::SeqCst);
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
    });
    let opts = VarOptions {
        discover: false,
        watch: Some(WatchOptions {
            samples: 6,
            interval_ms: 60,
            ..Default::default()
        }),
        ..Default::default()
    };
    let report = collect_live(std::process::id(), None, &opts).expect("collect_live");
    PC_W_STOP.store(true, Ordering::SeqCst);
    worker.join().expect("worker thread");

    let e = report
        .entries
        .iter()
        .find(|e| e.name.contains("PC_W_TICKS"))
        .expect("symbol entry for the counter");
    assert!(
        e.evidence.iter().any(|x| x.contains("counter")),
        "no watch evidence: {:?}",
        e.evidence
    );
}

#[test]
fn classify_numbers_strings_and_zero_buffers() {
    let maps: Vec<MapEntry> = Vec::new();
    let mem = RegionsMem::new(Vec::new());
    let o = VarOptions::default();
    let c = |b: &[u8]| classify(b, b.len() as u64, false, &maps, &mem, &o).value;

    assert_eq!(c(&512i32.to_le_bytes()), Some(Value::Int(512)));
    assert_eq!(c(&(-7i16).to_le_bytes()), Some(Value::Int(-7)));
    assert_eq!(c(&2.5f32.to_le_bytes()), Some(Value::Float32(2.5)));
    assert_eq!(c(&7.25f64.to_le_bytes()), Some(Value::Float(7.25)));
    assert_eq!(
        c(&(-123456789012i64).to_le_bytes()),
        Some(Value::Int(-123456789012))
    );
    assert_eq!(c(&[1u8]), Some(Value::Int(1)));
    assert_eq!(
        c(b"hello world\0\0\0\0\0"),
        Some(Value::Str("hello world".to_string()))
    );
    assert_eq!(c(b"abcdefg\0"), Some(Value::Str("abcdefg".to_string())));
    assert_eq!(c(&[0u8; 64]), None); // a zeroed buffer is not claimed to be an empty string
    assert_eq!(c(&[0u8; 4]), Some(Value::Int(0)));
}

#[test]
fn unsigned_reading_is_kept_for_big_values() {
    let maps: Vec<MapEntry> = Vec::new();
    let mem = RegionsMem::new(Vec::new());
    let o = VarOptions::default();
    let c = classify(&4_000_000_000u32.to_le_bytes(), 4, false, &maps, &mem, &o);
    assert_eq!(c.value, Some(Value::Int(-294_967_296)));
    assert_eq!(c.as_unsigned, Some(4_000_000_000));
}

#[test]
fn pointers_follow_to_strings_and_struct_starting_with_pointer_is_a_blob() {
    let text_addr = 0x7000u64;
    let maps = parse_maps("7000-8000 r--p 00000000 00:00 0 [anon]\n");
    let mem = RegionsMem::new(vec![(text_addr, b"/etc/legacyd.conf\0rest".to_vec())]);
    let o = VarOptions::default();

    let c = classify(&text_addr.to_le_bytes(), 8, false, &maps, &mem, &o);
    assert_eq!(c.value, Some(Value::Str("/etc/legacyd.conf".to_string())));
    assert_eq!(c.ty, "char*");
    assert_eq!(c.points_to, Some(text_addr));

    // struct { const char *host; int port; } must not be read as a string or a number
    let mut st = text_addr.to_le_bytes().to_vec();
    st.extend_from_slice(&5432i32.to_le_bytes());
    st.extend_from_slice(&[0u8; 4]);
    let c = classify(&st, 16, false, &maps, &mem, &o);
    assert_eq!(c.value, None);
    assert_eq!(c.ty, "blob");
}

#[test]
fn environment_values_keep_exact_spelling() {
    assert_eq!(scalar("8080"), Value::Int(8080));
    assert_eq!(scalar("-3"), Value::Int(-3));
    assert_eq!(scalar("2.5"), Value::Float(2.5));
    assert_eq!(scalar("-0.75"), Value::Float(-0.75));
    assert_eq!(scalar("0644"), Value::Str("0644".to_string()));
    assert_eq!(scalar("1.10"), Value::Str("1.10".to_string()));
    assert_eq!(scalar("+5"), Value::Str("+5".to_string()));
    assert_eq!(scalar("1e5"), Value::Str("1e5".to_string()));
    assert_eq!(scalar("0x1f"), Value::Str("0x1f".to_string()));
    assert_eq!(scalar(""), Value::Str(String::new()));
}

#[test]
fn maps_parsing_handles_spaces_and_empty_paths() {
    let txt = "55d0c8a00000-55d0c8a2a000 r--p 00000000 08:01 131090                     /usr/sbin/my daemon\n\
               7ffd5c2f1000-7ffd5c312000 rw-p 00000000 00:00 0                          [stack]\n\
               7f3a14000000-7f3a14021000 rw-p 00000000 00:00 0 \n";
    let m = parse_maps(txt);
    assert_eq!(m.len(), 3);
    assert_eq!(m[0].path, "/usr/sbin/my daemon");
    assert_eq!(m[0].start, 0x55d0c8a00000);
    assert_eq!(m[1].path, "[stack]");
    assert_eq!(m[2].path, "");
}

#[test]
fn json_escaping_and_shape() {
    let mut s = String::new();
    push_json_str(&mut s, "a\"b\\c\nd\u{1}");
    assert_eq!(s, "\"a\\\"b\\\\c\\nd\\u0001\"");

    let mut env = BTreeMap::new();
    env.insert("PORT".to_string(), Value::Int(8080));
    let r = Report {
        pid: 1,
        exe: "/bin/x".to_string(),
        elf_type: "DYN",
        load_bias: 0x1000,
        symbols_from: "symtab",
        symbols_seen: 3,
        entries: vec![VarEntry {
            name: "ratio".to_string(),
            addr: 0x5000,
            size: 4,
            ty: "f32".to_string(),
            section: ".data".to_string(),
            binding: "global",
            value: Some(Value::Float32(2.0)),
            aliases: vec![],
            as_unsigned: None,
            points_to: None,
            hex_preview: None,
            truncated: false,
            redacted: false,
            source: "symbol",
            evidence: vec!["symbol in .symtab".to_string()],
        }],
        environment: env,
        notes: vec![],
    };
    let j = r.to_json();
    assert!(j.contains("\"ratio\": 2.0")); // a float stays a float
    assert!(j.contains("\"PORT\": 8080"));
    assert!(j.contains("\"addr\": \"0x5000\""));
    assert!(j.trim_end().ends_with('}'));
}
