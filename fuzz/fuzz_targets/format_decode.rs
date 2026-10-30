#![no_main]

use cas::format::Format;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(f) = Format::decode(data) {
        assert!(Format::decode(&f.encode()).is_ok());
    }
});
