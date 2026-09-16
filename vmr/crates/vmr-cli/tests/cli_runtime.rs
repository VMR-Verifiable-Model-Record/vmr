// tests/cli_runtime.rs — what the `vmr` binary needs from the machine it runs
// on (QA P5-01; docs/dev/phase5.md C1, docs/CLI.md §1).
//
// The demo's strongest form copies the verifier binary to a second, unrelated
// machine. A Rust program for x86_64-pc-windows-msvc links the C runtime
// dynamically by default, so it needs VCRUNTIME140.dll - the Visual C++
// Redistributable, which a clean Windows does not have: the binary would not
// start, before printing a word. The repository's .cargo/config.toml links
// the CRT statically (+crt-static). This test reads the built binary's PE
// import tables - the DLLs Windows must find before main runs - and fails on
// any DLL of the Visual C++ runtime.

#[cfg(all(windows, target_env = "msvc"))]
mod pe {
    use std::path::PathBuf;

    fn u16_at(b: &[u8], at: usize) -> Option<u16> {
        Some(u16::from_le_bytes(b.get(at..at + 2)?.try_into().ok()?))
    }

    fn u32_at(b: &[u8], at: usize) -> Option<u32> {
        Some(u32::from_le_bytes(b.get(at..at + 4)?.try_into().ok()?))
    }

    /// A section's (virtual address, virtual size, raw size, raw offset).
    type Section = (u32, u32, u32, u32);

    /// The file offset of a relative virtual address.
    fn offset_of(sections: &[Section], rva: u32) -> Option<usize> {
        sections.iter().find_map(|&(va, vsize, rsize, raw)| {
            let size = vsize.max(rsize);
            (rva >= va && rva < va.checked_add(size)?).then(|| (rva - va + raw) as usize)
        })
    }

    /// The NUL-terminated ASCII name at a relative virtual address.
    fn name_at(b: &[u8], sections: &[Section], rva: u32) -> Option<String> {
        let start = offset_of(sections, rva)?;
        let len = b.get(start..)?.iter().position(|&c| c == 0)?;
        Some(String::from_utf8_lossy(b.get(start..start + len)?).into_owned())
    }

    /// Every DLL the image imports at load time (the import directory) or
    /// on first use (the delay-load directory).
    pub fn imported_dlls(b: &[u8]) -> Option<Vec<String>> {
        let pe = u32_at(b, 0x3c)? as usize;
        if b.get(pe..pe + 4)? != b"PE\0\0" {
            return None;
        }
        let sections_count = u16_at(b, pe + 6)? as usize;
        let optional_size = u16_at(b, pe + 20)? as usize;
        let optional = pe + 24;
        // The data directories: after 112 bytes of a PE32+ optional header,
        // 96 of a PE32 one.
        let directories = match u16_at(b, optional)? {
            0x20b => optional + 112,
            0x10b => optional + 96,
            _ => return None,
        };
        let mut sections = Vec::new();
        for i in 0..sections_count {
            let s = optional + optional_size + 40 * i;
            sections.push((u32_at(b, s + 12)?, u32_at(b, s + 8)?, u32_at(b, s + 16)?, u32_at(b, s + 20)?));
        }
        let mut dlls = Vec::new();
        // Directory 1: IMAGE_IMPORT_DESCRIPTORs (20 bytes, the name's RVA at
        // 12), ended by an all-zero one.
        let imports = u32_at(b, directories + 8)?;
        if imports != 0 {
            let mut at = offset_of(&sections, imports)?;
            loop {
                let name = u32_at(b, at + 12)?;
                if name == 0 {
                    break;
                }
                dlls.push(name_at(b, &sections, name)?);
                at += 20;
            }
        }
        // Directory 13: IMAGE_DELAYLOAD_DESCRIPTORs (32 bytes, the name's RVA
        // at 4), ended by an all-zero one.
        let delayed = u32_at(b, directories + 13 * 8)?;
        if delayed != 0 {
            let mut at = offset_of(&sections, delayed)?;
            loop {
                let name = u32_at(b, at + 4)?;
                if name == 0 {
                    break;
                }
                dlls.push(name_at(b, &sections, name)?);
                at += 32;
            }
        }
        Some(dlls)
    }

    /// DLLs of the Visual C++ Redistributable: not part of Windows. (The
    /// UCRT's api-ms-win-crt-* set is - Windows 10 and later ship it - but a
    /// statically linked CRT needs none of it either.)
    pub fn is_visual_cpp_runtime(dll: &str) -> bool {
        let dll = dll.to_ascii_lowercase();
        ["vcruntime", "msvcp", "concrt", "vccorlib", "vcomp", "msvcr1"].iter().any(|p| dll.starts_with(p))
    }

    #[test]
    fn the_vmr_binary_needs_no_visual_cpp_runtime_dll() {
        let exe = PathBuf::from(env!("CARGO_BIN_EXE_vmr"));
        let bytes = std::fs::read(&exe).expect("read the vmr binary");
        let dlls = imported_dlls(&bytes).expect("a PE image with readable import tables");
        assert!(
            dlls.iter().any(|d| d.eq_ignore_ascii_case("kernel32.dll")),
            "the import tables were not read correctly: {dlls:?}"
        );
        let runtime: Vec<&String> = dlls.iter().filter(|d| is_visual_cpp_runtime(d)).collect();
        assert!(
            runtime.is_empty(),
            "{} needs {runtime:?} at load time: a machine without the Visual C++ Redistributable \
             cannot start it. Build from vmr/ (vmr/.cargo/config.toml links the C runtime \
             statically) with no RUSTFLAGS overriding it. All imports: {dlls:?}",
            exe.display()
        );
    }

    #[test]
    fn the_runtime_dll_names_are_recognised() {
        for dll in ["VCRUNTIME140.dll", "vcruntime140_1.dll", "MSVCP140.dll", "msvcp140_atomic_wait.dll", "CONCRT140.dll", "MSVCR120.dll"] {
            assert!(is_visual_cpp_runtime(dll), "{dll}");
        }
        for dll in ["KERNEL32.dll", "bcrypt.dll", "ntdll.dll", "api-ms-win-crt-runtime-l1-1-0.dll", "msvcrt.dll", "nvcuda.dll"] {
            assert!(!is_visual_cpp_runtime(dll), "{dll}");
        }
    }
}
