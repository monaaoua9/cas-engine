#![no_main]

use cas::Tree;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(t) = Tree::decode(data) {
        assert_eq!(Tree::decode(&t.encode()).unwrap(), t);
    }
});
