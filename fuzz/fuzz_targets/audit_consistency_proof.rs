#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    vmr_fuzz_targets::audit_consistency_proof(data);
});
