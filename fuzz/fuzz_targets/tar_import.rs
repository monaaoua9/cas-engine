#![no_main]

use std::sync::{Mutex, OnceLock};

use cas::{Store, StoreConfig};
use libfuzzer_sys::fuzz_target;

// one store for the whole run; opening a fresh one per input would dominate the time
static STORE: OnceLock<Mutex<(tempfile::TempDir, Store, u64)>> = OnceLock::new();

fuzz_target!(|data: &[u8]| {
    let m = STORE.get_or_init(|| {
        let d = tempfile::tempdir().unwrap();
        let s = Store::open(d.path(), StoreConfig::default()).unwrap();
        Mutex::new((d, s, 0))
    });
    let mut g = m.lock().unwrap();
    let (_, st, n) = &mut *g;
    *n += 1;
    let name = format!("f{n}");

    if st.import_tar(data, Some(&name)).is_ok() {
        // whatever was accepted has to be a sound snapshot that exports again
        st.snapshot_verify(&name).unwrap();
        st.export_tar(&name, std::io::sink()).unwrap();
        st.snapshot_forget(&name).unwrap();
    }
    if *n % 500 == 0 {
        st.gc().unwrap();
    }
});
