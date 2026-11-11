use penguin_cloner::strings::{
    extract_from_dir, extract_strings, is_printable, looks_interesting, StringOptions,
};
use std::fs;
use std::path::PathBuf;

fn tmp_dir(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "penguin-cloner-strings-{}-{}",
        name,
        std::process::id()
    ));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).unwrap();
    dir
}

#[test]
fn is_printable_accepts_ascii_and_tab() {
    assert!(is_printable(b'A'));
    assert!(is_printable(b' '));
    assert!(is_printable(b'\t'));
    assert!(is_printable(b'~'));
    assert!(!is_printable(0));
    assert!(!is_printable(0x1f));
    assert!(!is_printable(0x7f));
    assert!(!is_printable(b'\n'));
}

#[test]
fn looks_interesting_matches_config_markers() {
    assert!(looks_interesting("password=secret"));
    assert!(looks_interesting("https://example.com"));
    assert!(looks_interesting("/etc/app.conf"));
    assert!(looks_interesting("HOME=/root"));
    assert!(!looks_interesting("abcdef"));
}

#[test]
fn extract_strings_respects_min_len_and_offsets() {
    let data = b"\0\0short\0hello-config\0\xffPASSWORD=x\0ab";
    let hits = extract_strings(
        data,
        "heap.bin",
        &StringOptions {
            min_len: 6,
            interesting_only: false,
        },
    );
    let texts: Vec<_> = hits.iter().map(|h| h.text.as_str()).collect();
    assert!(texts.contains(&"hello-config"));
    assert!(texts.contains(&"PASSWORD=x"));
    assert!(!texts.contains(&"short"));
    assert!(!texts.contains(&"ab"));

    let hello = hits.iter().find(|h| h.text == "hello-config").unwrap();
    assert_eq!(hello.source, "heap.bin");
    assert_eq!(hello.offset, 8);
}

#[test]
fn extract_strings_interesting_only_filters() {
    let data = b"zzzzzz\0https://api.example/token\0yyyyyy";
    let hits = extract_strings(
        data,
        "anon",
        &StringOptions {
            min_len: 4,
            interesting_only: true,
        },
    );
    assert_eq!(hits.len(), 1);
    assert!(hits[0].text.contains("https://"));
}

#[test]
fn extract_from_dir_writes_txt_and_json() {
    let dir = tmp_dir("dir");
    let mem = dir.join("memory");
    fs::create_dir_all(&mem).unwrap();
    fs::write(mem.join("region1"), b"\0foo=/etc/app.conf\0bar\0").unwrap();

    let out = dir.join("strings.txt");
    let n = extract_from_dir(
        &mem,
        &out,
        &StringOptions {
            min_len: 3,
            interesting_only: true,
        },
    )
    .unwrap();
    assert!(n >= 1);
    let txt = fs::read_to_string(&out).unwrap();
    assert!(txt.contains("/etc/app.conf"));
    assert!(dir.join("strings.json").is_file());

    let _ = fs::remove_dir_all(&dir);
}
