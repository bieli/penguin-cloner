use penguin_cloner::process::{field_from_status, split_nul_bytes};

#[test]
fn field_from_status_parses_name_uid_gid() {
    let status = "\
Name:\tsleep
Umask:\t0022
State:\tS (sleeping)
Uid:\t1000\t1000\t1000\t1000
Gid:\t1000\t1000\t1000\t1000
";
    assert_eq!(field_from_status(status, "Name").as_deref(), Some("sleep"));
    assert_eq!(
        field_from_status(status, "Uid").as_deref(),
        Some("1000\t1000\t1000\t1000")
    );
    assert_eq!(
        field_from_status(status, "Gid")
            .unwrap()
            .split_whitespace()
            .next(),
        Some("1000")
    );
    assert!(field_from_status(status, "NoSuch").is_none());
}

#[test]
fn split_nul_bytes_splits_cmdline_style() {
    let bytes = b"sleep\x00120\0";
    assert_eq!(split_nul_bytes(bytes), vec!["sleep", "120"]);
}

#[test]
fn split_nul_bytes_ignores_empty_segments() {
    assert!(split_nul_bytes(b"").is_empty());
    assert!(split_nul_bytes(b"\0\0").is_empty());
    assert_eq!(split_nul_bytes(b"\0a\0\0b\0"), vec!["a", "b"]);
}

#[test]
fn split_nul_bytes_lossy_for_invalid_utf8() {
    let bytes = [b'o', b'k', 0xff, 0];
    let parts = split_nul_bytes(&bytes);
    assert_eq!(parts.len(), 1);
    assert!(parts[0].starts_with("ok"));
}
