use penguin_cloner::maps::Region;

pub fn region(start: u64, end: u64, perms: &str, inode: u64, pathname: &str) -> Region {
    let bytes = perms.as_bytes();
    Region {
        start,
        end,
        perms: perms.to_string(),
        offset: 0,
        device: "00:00".into(),
        inode,
        pathname: pathname.to_string(),
        readable: bytes.first() == Some(&b'r'),
        writable: bytes.get(1) == Some(&b'w'),
        executable: bytes.get(2) == Some(&b'x'),
        private: bytes.get(3) == Some(&b'p'),
    }
}
