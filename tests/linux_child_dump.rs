//! Integration check: dump a child process we own (allowed under Yama ptrace_scope=1).

#![cfg(target_os = "linux")]

use penguin_cloner::dump::{dump_process, DumpOptions};
use penguin_cloner::process;
use std::fs;
use std::path::PathBuf;
use std::process::{Command, Stdio};

#[test]
fn dump_child_sleep_heap_or_stack() {
    let mut child = Command::new("sleep")
        .arg("20")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn sleep");
    let pid = child.id() as i32;

    let out = std::env::temp_dir().join(format!("penguin-cloner-child-dump-{pid}"));
    let _ = fs::remove_dir_all(&out);
    fs::create_dir_all(&out).unwrap();

    let info = process::collect(pid).expect("collect process info");
    assert_eq!(info.pid, pid);
    assert!(
        info.cmdline
            .first()
            .map(|s| s.contains("sleep"))
            .unwrap_or(false),
        "cmdline={:?}",
        info.cmdline
    );

    let report = dump_process(
        pid,
        &out,
        &DumpOptions {
            include_file_backed: false,
            heap_stack_only: true,
            max_region_bytes: 16 * 1024 * 1024,
            freeze: true,
        },
    );

    let _ = child.kill();
    let _ = child.wait();

    let report = report.expect("dump_process");
    assert!(
        report.regions_dumped > 0,
        "expected heap/stack dump; skipped={:?}",
        report.skipped
    );
    assert!(report.bytes_dumped > 0);
    assert!(PathBuf::from(&out).join("maps.txt").is_file());

    let _ = fs::remove_dir_all(&out);
}
