#![no_main]

use cas::Manifest;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // anything that decodes must re-encode to the same bytes
    if let Ok(m) = Manifest::decode(data) {
        assert_eq!(m.encode(), data);
    }
});
