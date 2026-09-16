//! Reading input files with a bound (docs/dev/phase5.md C13).
// ============================================================================
//  files.rs — the CLI's file reads
//
//  Every input is read with a size bound before anything parses it: a file
//  larger than the bound is refused without being read into memory. The
//  bound is generous for records (16 MiB, while a v0.1 record is at
//  most 1 MiB): anything up to it reaches the verifier, which reports an
//  oversized record as a verification failure (`input.size`) with an
//  exact report; beyond it the file cannot be a record and is not read.
// ============================================================================

use crate::error::CliError;
use crate::names::TOOL;
use std::io::Read;
use std::path::Path;

/// The most any record, predecessor or trust-store file may be: 16 MiB,
/// the trust-store limit (`specs/trust-store-format-v0.1.md` §2).
pub const MAX_DOCUMENT_BYTES: u64 = 16 * 1024 * 1024;

/// Why a bounded read failed.
#[derive(Debug)]
pub enum ReadError {
    /// The file is larger than the bound: its size.
    TooLarge(u64),
    /// It could not be opened or read.
    Io(std::io::Error),
}

/// Read `path` if it is at most `limit` bytes.
pub fn read_bounded(path: &Path, limit: u64) -> Result<Vec<u8>, ReadError> {
    let file = std::fs::File::open(path).map_err(ReadError::Io)?;
    let size = file.metadata().map_err(ReadError::Io)?.len();
    if size > limit {
        return Err(ReadError::TooLarge(size));
    }
    // The file may grow between the size check and the read: never read
    // more than the limit plus one byte, and check again.
    let mut bytes = Vec::new();
    file.take(limit.saturating_add(1)).read_to_end(&mut bytes).map_err(ReadError::Io)?;
    let read = bytes.len() as u64;
    if read > limit {
        return Err(ReadError::TooLarge(read));
    }
    Ok(bytes)
}

/// Read a record, predecessor or trust-store file (`what` names it in
/// errors), at most [`MAX_DOCUMENT_BYTES`].
pub fn read_document(path: &Path, what: &str) -> Result<Vec<u8>, CliError> {
    read_bounded(path, MAX_DOCUMENT_BYTES).map_err(|e| match e {
        ReadError::TooLarge(size) => CliError::input(format!(
            "{what} {} is {size} bytes; {TOOL} reads at most {MAX_DOCUMENT_BYTES} bytes (16 MiB) \
             from such a file, and did not read it",
            shown(path)
        )),
        ReadError::Io(e) => CliError::input(format!("cannot read {what} {}: {e}", shown(path))),
    })
}

/// What a JSON file's first bytes say, when they say it is not plain UTF-8
/// (QA P5-07): a UTF-8 byte order mark, or UTF-16 text. Windows PowerShell
/// 5.1 writes the first with `Set-Content -Encoding UTF8` and with `Out-File`
/// on some hosts, the second with a stock `Out-File`. Such a file stays
/// refused - the formats are UTF-8 JSON (RFC 8259 §8.1 lets a parser refuse a
/// BOM) - but the message says why, and [`SAVE_WITHOUT_BOM`] what to do.
pub fn byte_order_mark(bytes: &[u8]) -> Option<&'static str> {
    if bytes.starts_with(&[0xef, 0xbb, 0xbf]) {
        Some("the file starts with a UTF-8 byte order mark (EF BB BF)")
    } else if bytes.starts_with(&[0xff, 0xfe]) || bytes.starts_with(&[0xfe, 0xff]) {
        Some("the file is UTF-16 text (it starts with a UTF-16 byte order mark)")
    } else {
        None
    }
}

/// The hint for a file [`byte_order_mark`] recognises.
pub const SAVE_WITHOUT_BOM: &str = "save it as UTF-8 without a byte order mark: in Windows PowerShell 5.1, \
    Set-Content -Encoding UTF8 and Out-File add one and [IO.File]::WriteAllText(\"$PWD\\<file>\", $text) does \
    not (docs/CLI.md §3.6); PowerShell 7's Set-Content does not either";

/// A path as it appears in every message and output line, in quotes. It is
/// the operator's own argument, so it is shown as given — a Windows path
/// keeps its single backslashes — with only what a terminal would act on or
/// hide escaped (a file name is text the user may not have chosen, e.g. one
/// received with a record): vmr-verify's `escape_controls`, the table of
/// `display_safe` without its doubled backslash.
pub fn shown(path: &Path) -> String {
    format!("'{}'", vmr_verify::escape_controls(path.display().to_string()))
}

/// Refuse an output vmr must not write, whatever `--force` says, before
/// anything is opened (QA P5-02): `what` names the file in the message
/// ("private key", ...), `flag` the option that gave it ("--output", ...).
///
/// - On Windows, by name: a reserved device name as the file name (CON,
///   PRN, AUX, NUL, COM0-9, LPT0-9, the superscript COM/LPT digits,
///   CONIN$, CONOUT$ - in any case, with or without an extension, a
///   trailing colon or spaces), which opens the device instead of a file
///   (`--output CON` printed the private key on the console; COM1 sent it
///   to a serial port and reported success; LPT1 hung); a device-namespace
///   path (`\\.\`, `\\?\GLOBALROOT`, `\??\`); and a name Windows would
///   silently alter (a trailing dot or space: 'k.pem.' creates 'k.pem').
/// - Everywhere: an existing target that is not a regular file - a
///   directory, a device (`/dev/stdout`), a pipe (a FIFO would block).
/// - Everywhere: the same file as one of the command's `inputs` (each with
///   the option that named it), however it is spelled (QA P5-11: `key
///   export --key k.pem --output k.pem --force` destroyed the private key).
///   `--force` replaces an old output, never an input.
pub fn check_output(path: &Path, what: &str, flag: &str, inputs: &[(&Path, &str)]) -> Result<(), CliError> {
    if let Some(why) = output_problem(path) {
        return Err(CliError::input(format!("{what} {} {why}; nothing was written", shown(path)))
            .with_hint(format!("give {flag} the name of a regular file")));
    }
    if let Some((_, input_flag)) = inputs.iter().find(|(input, _)| same_file(path, input)) {
        return Err(CliError::input(format!(
            "{what} {} is the file this command reads as {input_flag}: writing it would destroy that input; \
             nothing was written",
            shown(path)
        ))
        .with_hint(format!("give {flag} another file: --force replaces an old output, never an input")));
    }
    Ok(())
}

/// Whether `a` and `b` are one existing file: on Unix the same device and
/// inode (hard links included); elsewhere the same canonical path (links
/// resolved; on Windows also any spelling of the name - case, `.\`, 8.3
/// short names - though not a second hard link). A path that does not
/// exist is no file at all.
#[cfg(unix)]
fn same_file(a: &Path, b: &Path) -> bool {
    use std::os::unix::fs::MetadataExt;
    match (std::fs::metadata(a), std::fs::metadata(b)) {
        (Ok(x), Ok(y)) => x.dev() == y.dev() && x.ino() == y.ino(),
        _ => false,
    }
}

/// See the Unix variant.
#[cfg(not(unix))]
fn same_file(a: &Path, b: &Path) -> bool {
    match (std::fs::canonicalize(a), std::fs::canonicalize(b)) {
        (Ok(x), Ok(y)) => x == y,
        _ => false,
    }
}

/// Why `path` must not be written, or None (see [`check_output`]).
fn output_problem(path: &Path) -> Option<String> {
    #[cfg(windows)]
    if let Some(why) = windows_name_problem(path) {
        return Some(why);
    }
    if path.file_name().is_none() {
        return Some("does not name a file".into());
    }
    match std::fs::metadata(path) {
        Ok(meta) if meta.is_dir() => Some("exists and is not a regular file (a directory)".into()),
        Ok(meta) if !meta.is_file() => Some("exists and is not a regular file (a device, a pipe or a socket)".into()),
        // A regular file (--force decides), or nothing there yet (the open
        // reports anything else).
        _ => None,
    }
}

/// Whether `base` - a file name up to its first `.` or `:`, trailing
/// spaces removed - is one of the names Windows reserves for devices.
#[cfg_attr(not(windows), allow(dead_code))]
fn is_windows_device_name(base: &str) -> bool {
    let upper = base.to_uppercase();
    if ["CON", "PRN", "AUX", "NUL", "CONIN$", "CONOUT$"].contains(&upper.as_str()) {
        return true;
    }
    // COM0-COM9, LPT0-LPT9, and COM/LPT with a superscript 1, 2 or 3.
    ["COM", "LPT"].iter().any(|prefix| match upper.strip_prefix(prefix) {
        Some(rest) => {
            let mut chars = rest.chars();
            matches!((chars.next(), chars.next()),
                (Some(c), None) if c.is_ascii_digit() || matches!(c, '\u{b9}' | '\u{b2}' | '\u{b3}'))
        }
        None => false,
    })
}

/// Why Windows would not create a regular file of exactly this name, or
/// None. A pure function of the path's text, read with Windows' separators
/// (`\` and `/`) on every platform so that its tests run everywhere; it is
/// applied on Windows only.
#[cfg_attr(not(windows), allow(dead_code))]
fn windows_name_problem(path: &Path) -> Option<String> {
    let text = path.to_string_lossy().replace('/', "\\");
    let lower = text.to_ascii_lowercase();
    if lower.starts_with(r"\\.\") || lower.starts_with(r"\??\") || lower.starts_with(r"\\?\globalroot") {
        return Some("is a Windows device path (\\\\.\\, \\\\?\\GLOBALROOT or \\??\\), not a file".into());
    }
    let mut name = text.rsplit('\\').next().unwrap_or_default();
    // A drive-relative path ("C:CON") names CON on drive C.
    let bytes = name.as_bytes();
    if !text.contains('\\') && bytes.first().is_some_and(u8::is_ascii_alphabetic) && bytes.get(1) == Some(&b':') {
        name = name.get(2..).unwrap_or_default();
    }
    if name.is_empty() || name == "." || name == ".." {
        return None; // not a file name at all: output_problem says so
    }
    if let Some(last) = name.chars().last().filter(|c| matches!(c, '.' | ' ')) {
        let which = if last == '.' { "dot" } else { "space" };
        return Some(format!("ends with a {which}: Windows would create the file without it"));
    }
    let base = name.split(['.', ':']).next().unwrap_or_default().trim_end_matches(' ');
    if is_windows_device_name(base) {
        return Some(
            "is a Windows device name (CON, PRN, AUX, NUL, COM0-COM9, LPT0-LPT9, CONIN$, CONOUT$ - with \
             or without an extension): writing to it would reach the device, not a file"
                .into(),
        );
    }
    None
}

/// Write public content (a public key file, a record) to a NEW file at
/// `path`, with the platform's default permissions. See [`create_file`].
pub fn write_public_new(path: &Path, bytes: &[u8], force: bool, what: &str) -> Result<(), CliError> {
    create_file(path, bytes, force, what, false)
}

/// Write a private key to a NEW file at `path`, readable by its owner only
/// on Unix (mode 0600); on Windows it inherits the directory's ACL
/// (docs/CLI.md says so). See [`create_file`].
pub fn write_private_new(path: &Path, bytes: &[u8], force: bool, what: &str) -> Result<(), CliError> {
    create_file(path, bytes, force, what, true)
}

/// Write `bytes` to a NEW file at `path`. An existing file is refused —
/// never silently overwritten — unless `force` (the user's explicit
/// `--force`); a path that is not, or would not be, a regular file is
/// refused even then ([`check_output`]; the commands check it first, before
/// any other work, and it is checked again here, before the open, and
/// after it). `what` names the file in errors ("private key", …).
fn create_file(path: &Path, bytes: &[u8], force: bool, what: &str, owner_only: bool) -> Result<(), CliError> {
    use std::io::Write;
    if let Some(why) = output_problem(path) {
        return Err(CliError::input(format!("{what} {} {why}; nothing was written", shown(path))));
    }
    let mut options = std::fs::OpenOptions::new();
    options.write(true);
    if force {
        options.create(true).truncate(true);
    } else {
        // Atomic: the check and the creation are one system call, so no
        // file can appear in between and be clobbered.
        options.create_new(true);
    }
    if owner_only {
        owner_only::on_create(&mut options);
    }
    let mut file = options.open(path).map_err(|e| {
        if e.kind() == std::io::ErrorKind::AlreadyExists {
            CliError::input(format!("{what} {} already exists; it was not overwritten", shown(path)))
                .with_hint("choose another --output, or pass --force to replace the file")
        } else {
            CliError::input(format!("cannot create {what} {}: {e}", shown(path)))
        }
    })?;
    // What was opened must be a regular file before a byte is written: a
    // device or pipe put there after the check above is refused too.
    if !file.metadata().map(|m| m.is_file()).unwrap_or(false) {
        return Err(CliError::input(format!(
            "{what} {} is not a regular file; nothing was written",
            shown(path)
        )));
    }
    if owner_only {
        owner_only::after_open(&file)
            .map_err(|e| CliError::input(format!("cannot restrict {what} {}: {e}", shown(path))))?;
    }
    file.write_all(bytes)
        .and_then(|()| file.sync_all())
        .map_err(|e| CliError::input(format!("cannot write {what} {}: {e}", shown(path))))
}

/// Replace the file at `path` with `bytes` (or create it) atomically: the
/// bytes go to a new temporary file in the same directory, which is then
/// renamed over `path`. A crash or a full disk leaves either the old file
/// or the new one, never half of either.
pub fn replace_file(path: &Path, bytes: &[u8], what: &str) -> Result<(), CliError> {
    let name = path
        .file_name()
        .ok_or_else(|| CliError::input(format!("{what} {} is not a file name", shown(path))))?;
    let dir = path.parent().filter(|d| !d.as_os_str().is_empty()).unwrap_or(Path::new("."));
    let temp = dir.join(format!(".{}.vmr-{}.tmp", name.to_string_lossy(), std::process::id()));
    create_file(&temp, bytes, false, what, false)?;
    std::fs::rename(&temp, path).map_err(|e| {
        // The temporary file is ours and useless now; if even removing it
        // fails, the rename error is still the one to report.
        if std::fs::remove_file(&temp).is_err() {
            return CliError::input(format!(
                "cannot replace {what} {}: {e} (and the temporary file {} remains)",
                shown(path),
                shown(&temp)
            ));
        }
        CliError::input(format!("cannot replace {what} {}: {e}", shown(path)))
    })
}

/// Owner-only files on Unix: created with mode 0600, and set to 0600 again
/// after opening (with --force an existing file keeps its old mode
/// otherwise).
#[cfg(unix)]
mod owner_only {
    use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};

    pub fn on_create(options: &mut std::fs::OpenOptions) {
        options.mode(0o600);
    }

    pub fn after_open(file: &std::fs::File) -> std::io::Result<()> {
        file.set_permissions(std::fs::Permissions::from_mode(0o600))
    }
}

/// Elsewhere (Windows) a new file inherits its directory's ACL; vmr does
/// not edit ACLs - that needs unsafe code or a new crate, neither of which
/// this crate takes - and says so instead ([`private_key_permissions_note`]).
#[cfg(not(unix))]
mod owner_only {
    pub fn on_create(_options: &mut std::fs::OpenOptions) {}

    pub fn after_open(_file: &std::fs::File) -> std::io::Result<()> {
        Ok(())
    }
}

/// What `key generate` says about a new private key file's permissions, if
/// anything: nothing on Unix, where the file is mode 0600; on Windows, that
/// it inherits its folder's permissions - silently, before QA P5-06: under a
/// folder made at a drive root that grants "Authenticated Users" modify -
/// and the command that leaves it to its owner alone (S-1-3-4 is OWNER
/// RIGHTS: the file's owner, whoever that is, so the command runs as it
/// stands in cmd and PowerShell alike). No key material, ever.
pub fn private_key_permissions_note(path: &Path) -> Option<String> {
    if cfg!(unix) {
        return None;
    }
    Some(format!(
        "on Windows the file inherits its folder's permissions; to let only its owner read it, run: \
         icacls \"{}\" /inheritance:r /grant:r *S-1-3-4:F",
        vmr_verify::escape_controls(path.display().to_string())
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_missing_file_is_an_io_error_naming_the_file() {
        let e = read_document(Path::new("no/such/dir/record.json"), "record").unwrap_err();
        assert_eq!(e.code, 1);
        assert!(e.message.starts_with("cannot read record 'no"), "{}", e.message);
    }

    #[test]
    fn paths_are_shown_terminal_safe() {
        assert_eq!(shown(Path::new("a\u{1b}[2Jb")), "'a\\u{001b}[2Jb'");
        assert_eq!(shown(Path::new("model\u{202e}gpj.vmr")), "'model\\u{202e}gpj.vmr'");
        assert_eq!(shown(Path::new("a\u{200b}b\rc")), "'a\\u{200b}b\\u{000d}c'");
    }

    #[test]
    fn windows_device_names_are_recognised_in_every_spelling() {
        // The rule is a pure function of the name, so it is tested on every
        // platform (it is applied on Windows only).
        for name in [
            "CON", "con", "Con.key", "PRN", "AUX", "aux.json", "NUL", "nul.pem", "COM0", "COM1", "com9.pem", "LPT0",
            "LPT1", "lpt9.vmr", "COM1:", "LPT1:x", "CON .txt", "NUL . pem", "CONIN$", "conout$", "COM\u{b9}",
            "com\u{b2}.key", "LPT\u{b3}.key", r"C:\dir\CON", r"..\nul.json", "a/b/COM3", "C:CON", "d:nul.txt",
        ] {
            let why = windows_name_problem(Path::new(name)).unwrap_or_default();
            assert!(why.contains("is a Windows device name"), "{name:?}: {why:?}");
        }
        for path in [r"\\.\COM1", r"\\.\pipe\x", r"\\?\GLOBALROOT\Device\Null", r"\\?\globalroot\x", "//./NUL", r"\??\C:\x"] {
            let why = windows_name_problem(Path::new(path)).unwrap_or_default();
            assert!(why.contains("is a Windows device path"), "{path:?}: {why:?}");
        }
        for name in ["k.pem.", "k.pem ", "a..", "b. "] {
            let why = windows_name_problem(Path::new(name)).unwrap_or_default();
            assert!(why.contains("Windows would create the file without it"), "{name:?}: {why:?}");
        }
        // Ordinary names that merely contain one.
        for name in [
            "console.key", "comet.pem", "com10.key", "lpt10.key", "a.con", "CONX", "nul_", "factory.key",
            r"C:\CON\k.pem", r"\\?\C:\long\k.pem", r"\\server\share\ts.json", "COM", "C:k.pem", ".", "..", r"C:\",
        ] {
            assert_eq!(windows_name_problem(Path::new(name)), None, "{name:?}");
        }
    }

    #[test]
    fn a_directory_is_never_an_output() {
        let dir = std::env::temp_dir();
        let why = output_problem(&dir).unwrap_or_default();
        assert!(why.contains("exists and is not a regular file (a directory)"), "{why}");
        assert_eq!(output_problem(Path::new("no/such/dir/k.pem")), None, "the open reports that");
        assert!(output_problem(Path::new("..")).is_some());
    }

    #[test]
    fn a_windows_path_keeps_its_single_backslashes() {
        // A path is the operator's own argument: shown as typed, with only
        // what a terminal would act on escaped - not 'C:\\Users\\...'.
        assert_eq!(shown(Path::new(r"C:\Users\demo\vmr-demo\model.vmr")), r"'C:\Users\demo\vmr-demo\model.vmr'");
        assert_eq!(shown(Path::new(r"\\server\share\ts.json")), r"'\\server\share\ts.json'");
        assert_eq!(shown(Path::new("C:\\demo\\\u{1b}[2J.vmr")), "'C:\\demo\\\\u{001b}[2J.vmr'");
    }
}
