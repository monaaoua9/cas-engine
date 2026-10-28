#![no_main]

use cas::segment;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let dir = tempfile::tempdir().unwrap();
    let p = dir.path().join("seg");
    std::fs::write(&p, data).unwrap();
    let s = segment::scan(&p).unwrap();
    assert!(s.valid_end <= s.file_len);
});
