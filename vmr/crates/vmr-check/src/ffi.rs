//! The module's exports: plain C functions over its own memory.
// ============================================================================
//  ffi.rs — the only unsafe code in vmr-check
//
//  js/vmr-check.js and the module share one linear memory. The script asks
//  for a buffer (`vmr_alloc`), writes a request into it, and hands it to
//  `vmr_call`, which takes it back, answers through `api::call`, and returns
//  a new buffer holding a u32 little-endian length and that many bytes of
//  JSON. The script copies the answer out and returns that buffer
//  (`vmr_free`). The streaming hasher is a boxed `FileHasher` the script
//  holds as an opaque pointer until `vmr_hasher_finish` consumes it.
//
//  Every buffer is a `Box<[u8]>` made here, and every pointer the script
//  passes back is one this module returned, with the length it returned it
//  with: that is the contract each `// SAFETY:` comment relies on, and the
//  script (js/vmr-check.js) is the only caller. A script that broke it could
//  corrupt the module's own memory, never anything outside it: a wasm module
//  reaches nothing but its memory and its imports, and it imports nothing.
//
//  wasm32-unknown-unknown also needs a getrandom source, because p256's
//  elliptic-curve takes crypto-bigint with its default features, which pull
//  in rand_core's getrandom; getrandom 0.2 refuses to build for this target
//  without one. The source registered here always fails: nothing in this
//  module reads randomness (verification needs none; ES256 verification is
//  deterministic), and if anything ever asked, it would get an error.
// ============================================================================

use crate::api;
use crate::hasher::FileHasher;

/// The getrandom source of the wasm build: always `UNSUPPORTED`.
pub fn no_randomness(_dest: &mut [u8]) -> Result<(), getrandom::Error> {
    Err(getrandom::Error::UNSUPPORTED)
}

#[cfg(all(target_arch = "wasm32", target_os = "unknown"))]
getrandom::register_custom_getrandom!(no_randomness);

/// `bytes` as a buffer the script owns: its pointer, the buffer prefixed
/// with the u32 little-endian length of `bytes`. The script frees it with
/// `vmr_free(ptr, 4 + length)`.
fn handed_out(bytes: &[u8]) -> *mut u8 {
    // An answer longer than u32::MAX cannot be framed. None comes close
    // (records, stores and packs are bounded at 16 MiB); were one longer, the
    // script would read an empty answer and report the call as broken.
    let length = u32::try_from(bytes.len()).unwrap_or(0);
    let mut out = Vec::with_capacity(4 + bytes.len());
    out.extend_from_slice(&length.to_le_bytes());
    if length > 0 {
        out.extend_from_slice(bytes);
    }
    Box::into_raw(out.into_boxed_slice()).cast::<u8>()
}

/// A new zeroed buffer of `len` bytes for the script to write a request or a
/// chunk into.
#[no_mangle]
pub extern "C" fn vmr_alloc(len: usize) -> *mut u8 {
    Box::into_raw(vec![0u8; len].into_boxed_slice()).cast::<u8>()
}

/// Return a buffer: one `vmr_alloc` made with `len`, or an answer with
/// `len` = 4 + its length.
///
/// # Safety
/// `ptr` and `len` must be exactly a buffer this module handed out and the
/// script has not returned yet.
#[no_mangle]
pub unsafe extern "C" fn vmr_free(ptr: *mut u8, len: usize) {
    // SAFETY: by this function's contract `ptr`/`len` are a `Box<[u8]>` of
    // exactly `len` bytes made by `vmr_alloc` or `handed_out`, still live, so
    // rebuilding the box and dropping it frees it once with its own layout.
    drop(unsafe { Box::from_raw(std::ptr::slice_from_raw_parts_mut(ptr, len)) });
}

/// Answer request `op` held in the buffer `ptr`/`len`, which this call takes
/// back (the script must not free it); the answer is a new buffer.
///
/// # Safety
/// `ptr` and `len` must be exactly a buffer `vmr_alloc(len)` handed out and
/// the script has not returned yet.
#[no_mangle]
pub unsafe extern "C" fn vmr_call(op: u32, ptr: *mut u8, len: usize) -> *mut u8 {
    // SAFETY: by this function's contract the buffer is a live `Box<[u8]>`
    // of `len` bytes from `vmr_alloc`; taking it back here makes this call
    // its only owner, and it is dropped when the call returns.
    let request = unsafe { Box::from_raw(std::ptr::slice_from_raw_parts_mut(ptr, len)) };
    handed_out(&api::call(op, &request))
}

/// A new streaming SHA-256 (`fileHasher()`).
#[no_mangle]
pub extern "C" fn vmr_hasher_new() -> *mut FileHasher {
    Box::into_raw(Box::new(FileHasher::new()))
}

/// Add the chunk `ptr`/`len` to the hasher `hasher`. The chunk stays the
/// script's.
///
/// # Safety
/// `hasher` must be a pointer `vmr_hasher_new` returned that
/// `vmr_hasher_finish` has not consumed, and `ptr`/`len` a live buffer from
/// `vmr_alloc(len)`.
#[no_mangle]
pub unsafe extern "C" fn vmr_hasher_update(hasher: *mut FileHasher, ptr: *const u8, len: usize) {
    // SAFETY: by this function's contract `hasher` points to a live boxed
    // `FileHasher` no other reference reaches (the module is single-threaded
    // and keeps none), and `ptr`/`len` are `len` initialised bytes of a live
    // buffer that nothing writes during this call.
    let (hasher, chunk) = unsafe { (&mut *hasher, std::slice::from_raw_parts(ptr, len)) };
    hasher.update(chunk);
}

/// The hasher's digest as an answer buffer (`sha256:` and 64 hex digits);
/// consumes the hasher.
///
/// # Safety
/// `hasher` must be a pointer `vmr_hasher_new` returned that this function
/// has not consumed.
#[no_mangle]
pub unsafe extern "C" fn vmr_hasher_finish(hasher: *mut FileHasher) -> *mut u8 {
    // SAFETY: by this function's contract `hasher` is the live box
    // `vmr_hasher_new` made; taking it back consumes it exactly once.
    let hasher = unsafe { Box::from_raw(hasher) };
    handed_out(hasher.finish().as_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The answer buffer `ptr` as the script reads it, then returned.
    fn take_answer(ptr: *mut u8) -> Vec<u8> {
        // SAFETY: `ptr` is an answer `handed_out` made: 4 length bytes, then
        // that many bytes; it is freed with exactly that length.
        unsafe {
            let length = u32::from_le_bytes(*ptr.cast::<[u8; 4]>()) as usize;
            let bytes = std::slice::from_raw_parts(ptr.add(4), length).to_vec();
            vmr_free(ptr, 4 + length);
            bytes
        }
    }

    #[test]
    fn a_request_goes_in_and_its_answer_comes_back_through_the_exports() {
        let header = br#"{}"#;
        let mut request = Vec::new();
        request.extend_from_slice(&(header.len() as u32).to_le_bytes());
        request.extend_from_slice(header);
        let ptr = vmr_alloc(request.len());
        // SAFETY: `ptr` is a fresh buffer of `request.len()` bytes.
        unsafe { std::ptr::copy_nonoverlapping(request.as_ptr(), ptr, request.len()) };
        // SAFETY: `ptr`/`len` are the buffer just allocated; vmr_call takes it.
        let answer = take_answer(unsafe { vmr_call(api::OP_VERSION, ptr, request.len()) });
        let value: serde_json::Value = serde_json::from_slice(&answer).unwrap();
        assert_eq!(value["vmr"], crate::VERSION);
        // An empty buffer, allocated and returned.
        // SAFETY: a zero-length buffer from vmr_alloc, freed with length 0.
        unsafe { vmr_free(vmr_alloc(0), 0) };
    }

    #[test]
    fn the_hasher_exports_give_the_one_shot_digest() {
        let h = vmr_hasher_new();
        for chunk in [&b"ab"[..], b"", b"c"] {
            let ptr = vmr_alloc(chunk.len());
            // SAFETY: `ptr` is a fresh buffer of `chunk.len()` bytes; `h` is
            // live; the chunk buffer is returned with its own length.
            unsafe {
                std::ptr::copy_nonoverlapping(chunk.as_ptr(), ptr, chunk.len());
                vmr_hasher_update(h, ptr, chunk.len());
                vmr_free(ptr, chunk.len());
            }
        }
        // SAFETY: `h` is live and consumed here once.
        let digest = take_answer(unsafe { vmr_hasher_finish(h) });
        assert_eq!(digest, vmr_record::hash::format_hash(&vmr_record::hash::sha256(b"abc")).into_bytes());
    }

    #[test]
    fn the_randomness_source_always_fails() {
        let mut buf = [7u8; 16];
        assert_eq!(no_randomness(&mut buf), Err(getrandom::Error::UNSUPPORTED));
        assert_eq!(buf, [7u8; 16]);
    }
}
