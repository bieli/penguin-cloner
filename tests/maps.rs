mod common;

use common::region;
use penguin_cloner::maps::{parse_maps_text, should_dump};

const SAMPLE_MAPS: &str = "\
00400000-00452000 r-xp 00000000 08:02 173521      /usr/bin/app
00651000-00652000 rw-p 00051000 08:02 173521      /usr/bin/app
00652000-00673000 rw-p 00000000 00:00 0          [heap]
7ffd12345000-7ffd12366000 rw-p 00000000 00:00 0  [stack]
7ffd12368000-7ffd1236c000 r--p 00000000 00:00 0  [vvar]
7ffd1236c000-7ffd1236e000 r-xp 00000000 00:00 0  [vdso]
ffffffffff600000-ffffffffff601000 --xp 00000000 00:00 0  [vsyscall]
7f0000000000-7f0000001000 rw-p 00000000 00:00 0
7f1000000000-7f1000002000 r--p 00000000 08:01 999 /usr/lib/libc.so
7f2000000000-7f2000003000 rw-s 00001000 08:01 42  /var/lib/app/config.dat
";

#[test]
fn parse_maps_text_reads_fields_and_path_with_spaces() {
    let text = "\
08048000-08056000 r-xp 00000000 03:0c 64593      /usr/sbin/my app
08056000-08058000 rw-p 00000000 00:00 0
";
    let regions = parse_maps_text(text).unwrap();
    assert_eq!(regions.len(), 2);
    assert_eq!(regions[0].start, 0x0804_8000);
    assert_eq!(regions[0].end, 0x0805_6000);
    assert_eq!(regions[0].perms, "r-xp");
    assert!(regions[0].readable && regions[0].executable && !regions[0].writable);
    assert!(regions[0].private);
    assert_eq!(regions[0].offset, 0);
    assert_eq!(regions[0].device, "03:0c");
    assert_eq!(regions[0].inode, 64593);
    assert_eq!(regions[0].pathname, "/usr/sbin/my app");
    assert_eq!(regions[0].size(), 0x0805_6000 - 0x0804_8000);
    assert!(regions[1].pathname.is_empty());
    assert_eq!(regions[1].inode, 0);
}

#[test]
fn parse_maps_text_skips_blank_lines() {
    let regions = parse_maps_text("\n\n00400000-00401000 r--p 00000000 00:00 0\n\n").unwrap();
    assert_eq!(regions.len(), 1);
}

#[test]
fn parse_maps_text_rejects_bad_range() {
    let err = parse_maps_text("not-a-range r--p 00000000 00:00 0").unwrap_err();
    let msg = format!("{err:#}");
    assert!(msg.contains("bad range") || msg.contains("bad start"));
}

#[test]
fn dump_name_sanitizes_pathname() {
    let r = region(0x1000, 0x2000, "rw-p", 0, "/tmp/weird name[1].bin");
    let name = r.dump_name();
    assert!(name.starts_with("0000000000001000-0000000000002000_rw-p_"));
    assert!(!name.contains('['));
    assert!(!name.contains(' '));
    assert!(name.contains("weird"));
}

#[test]
fn dump_name_uses_anon_for_empty_path() {
    let r = region(0, 0x1000, "rw-p", 0, "");
    assert!(r.dump_name().ends_with("_anon"));
}

#[test]
fn should_dump_skips_kernel_helpers_and_unreadable() {
    assert!(!should_dump(
        &region(0, 1, "r--p", 0, "[vdso]"),
        true,
        false
    ));
    assert!(!should_dump(
        &region(0, 1, "r--p", 0, "[vvar]"),
        true,
        false
    ));
    assert!(!should_dump(
        &region(0, 1, "--xp", 0, "[vsyscall]"),
        true,
        false
    ));
    assert!(!should_dump(
        &region(0, 1, "-w-p", 0, "[heap]"),
        false,
        false
    ));
}

#[test]
fn should_dump_heap_stack_only_filter() {
    let heap = region(0, 0x1000, "rw-p", 0, "[heap]");
    let stack = region(0, 0x1000, "rw-p", 0, "[stack]");
    let thread_stack = region(0, 0x1000, "rw-p", 0, "[stack:1234]");
    let anon = region(0, 0x1000, "rw-p", 0, "");
    assert!(should_dump(&heap, false, true));
    assert!(should_dump(&stack, false, true));
    assert!(should_dump(&thread_stack, false, true));
    assert!(!should_dump(&anon, false, true));
}

#[test]
fn should_dump_skips_readonly_file_backed_unless_requested() {
    let ro_lib = region(0, 0x1000, "r-xp", 99, "/usr/lib/libc.so");
    let rw_cfg = region(0, 0x1000, "rw-p", 42, "/etc/app.conf");
    let anon = region(0, 0x1000, "rw-p", 0, "");

    assert!(!should_dump(&ro_lib, false, false));
    assert!(should_dump(&ro_lib, true, false));
    assert!(should_dump(&rw_cfg, false, false));
    assert!(should_dump(&anon, false, false));
}

#[test]
fn sample_maps_filter_matrix() {
    let regions = parse_maps_text(SAMPLE_MAPS).unwrap();
    assert_eq!(regions.len(), 10);

    let dumped: Vec<_> = regions
        .iter()
        .filter(|r| should_dump(r, false, false))
        .map(|r| r.pathname.as_str())
        .collect();
    assert!(dumped.contains(&"[heap]"));
    assert!(dumped.contains(&"[stack]"));
    assert!(dumped.contains(&""));
    assert!(dumped.contains(&"/usr/bin/app"));
    assert!(dumped.contains(&"/var/lib/app/config.dat"));
    assert!(!dumped
        .iter()
        .any(|p| *p == "[vdso]" || *p == "[vvar]" || *p == "[vsyscall]"));
    assert!(!dumped.contains(&"/usr/lib/libc.so"));
}
