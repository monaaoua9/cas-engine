#![no_main]

use cas::wire::read_frame;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let mut r = data;
    // keep reading until the input runs out or a frame is refused
    while let Ok(Some(_)) = read_frame(&mut r) {}
});
