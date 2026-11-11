use penguin_cloner::dump::{write_combined_blob, write_index, DumpReport, DumpedFile};
use std::fs;
use std::path::{Path, PathBuf};

fn tmp_dir(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "penguin-cloner-dump-{}-{}",
        name,
        std::process::id()
    ));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).unwrap();
    dir
}

fn sample_report(out: &Path) -> DumpReport {
    let mem = out.join("memory");
    fs::create_dir_all(&mem).unwrap();
    fs::write(mem.join("a.bin"), b"AAAA").unwrap();
    fs::write(mem.join("b.bin"), b"BBBBBB").unwrap();

    DumpReport {
        pid: 42,
        attached: false,
        regions_total: 2,
        regions_dumped: 2,
        bytes_dumped: 10,
        files: vec![
            DumpedFile {
                path: "memory/a.bin".into(),
                start: 0x1000,
                end: 0x1004,
                size: 4,
                perms: "rw-p".into(),
                pathname: "[heap]".into(),
            },
            DumpedFile {
                path: "memory/b.bin".into(),
                start: 0x2000,
                end: 0x2006,
                size: 6,
                perms: "rw-p".into(),
                pathname: "[stack]".into(),
            },
        ],
        skipped: vec![],
    }
}

#[test]
fn write_index_emits_json_report() {
    let out = tmp_dir("index");
    let report = sample_report(&out);
    write_index(&out, &report).unwrap();
    let text = fs::read_to_string(out.join("memory_index.json")).unwrap();
    assert!(text.contains("\"pid\": 42"));
    assert!(text.contains("memory/a.bin"));
    let _ = fs::remove_dir_all(&out);
}

#[test]
fn write_combined_blob_concatenates_regions() {
    let out = tmp_dir("combined");
    let report = sample_report(&out);
    let blob = write_combined_blob(&out, &report).unwrap();
    assert_eq!(fs::read(&blob).unwrap(), b"AAAABBBBBB");

    let meta: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(out.join("memory_combined.json")).unwrap())
            .unwrap();
    assert_eq!(meta.as_array().unwrap().len(), 2);
    assert_eq!(meta[0]["blob_offset"], 0);
    assert_eq!(meta[1]["blob_offset"], 4);
    assert_eq!(meta[1]["size"], 6);

    let _ = fs::remove_dir_all(&out);
}
