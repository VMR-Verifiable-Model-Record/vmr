//! Naming and hashing a model's files, from a folder or one file (spec §7.2).
// ============================================================================
//  files.rs — the walk
//
//  Spec §7.2, as settled on main (task 10.13a, plan §12):
//  - a model given as one file is named by the file's own name; a model given
//    as a folder names every file by its path in that folder, with `/`
//    between the parts on every operating system, even when it holds one file;
//  - names are taken as the file system stores them: no Unicode
//    normalisation, no case folding. A folder's names come from its listing.
//    A model given as one file is named as its folder lists it, not as the
//    path was typed: on a case-insensitive file system `WEIGHTS.BIN` opens
//    `weights.bin`, and the name is `weights.bin` (QA QM-01);
//  - a file whose name is not a sequence of Unicode scalar values (bytes that
//    are not UTF-8, an unpaired surrogate in an NTFS name), itself or through
//    a folder on its path, refuses the folder; a folder with such a name that
//    holds no file contributes nothing (§7.2's text, QA QM-03);
//  - a model's files are its regular files; a directory is not an entry;
//  - a link (a symbolic link, or on Windows a directory junction or another
//    name-surrogate reparse point) that resolves to a regular file is hashed
//    as that file under the link's own name; a link that resolves to a
//    directory, to nothing, or through a loop refuses the folder, and so does
//    a link Windows cannot follow, such as one WSL made on NTFS (QA QM-04);
//  - no file is excluded by name.
//
//  Every file is read once, through SHA-256, in 1 MiB pieces, in §7.2's order
//  of names: memory is one buffer and one entry per file, whatever the size.
//  A file whose size changes while it is read refuses the folder. Nothing
//  about a file but its name and bytes is read: no time, owner, permission or
//  attribute (except to confirm that a name found with case ignored is the
//  file opened, and each file's size, for an observer that asks for a
//  folder's total before the files are read).
//
//  An observer (WalkObserver; a loading bar) is told the file count and total
//  size, each file as it starts and every piece read. It receives names,
//  counts and sizes only, returns nothing, and cannot change, skip or reorder
//  a file; the walk reads no clock for it. Pipes, sockets and devices are not regular files and refuse
//  the folder (a pipe would block the read).
// ============================================================================

use crate::general::{DigestSource, FileEntry, FileSet};
use sha2::{Digest, Sha256};
use std::fs;
use std::io::{self, Read};
use std::path::{Path, PathBuf};
use vmr_record::hash::DIGEST_LEN;

/// The size of one read.
const BUFFER: usize = 1 << 20;

/// The largest size a record states exactly: 2^53 - 1.
const MAX_SAFE_INTEGER: u64 = (1 << 53) - 1;

/// What a walk tells an observer as it names and hashes a model's files. Every
/// method does nothing unless the observer overrides it.
pub trait WalkObserver {
    /// The walk has named `files` files, to be read in its order;
    /// `total_bytes` is their size, or `None` when a size could not be read
    /// (the walk then reads each file, and refuses what it must, as always).
    fn listed(&mut self, _files: u64, _total_bytes: Option<u64>) {}

    /// File `index` (from 0, in the walk's order), named `name`, `size` bytes
    /// when opened, is about to be read.
    fn file_started(&mut self, _index: u64, _name: &str, _size: u64) {}

    /// `n` more bytes of the current file were read.
    fn bytes_read(&mut self, _n: u64) {}

    /// Whether the observer wants a folder's total size in [`WalkObserver::listed`].
    /// It costs a read of every file's size before the files are hashed, so
    /// an observer is told `None` unless it asks.
    fn wants_total(&self) -> bool {
        false
    }
}

/// An observer that acts on nothing it is told.
struct NoObserver;

impl WalkObserver for NoObserver {}

/// Windows' `ERROR_CANT_ACCESS_FILE`: what following a symbolic link WSL made
/// on an NTFS disk (an `LX_SYMLINK` reparse point) gives on Windows.
const WINDOWS_CANT_ACCESS_FILE: i32 = 1920;

/// Why a folder or file cannot be named and hashed as a model's files.
#[derive(Debug)]
pub enum WalkError {
    /// A folder, file or directory entry could not be read.
    Unreadable {
        /// The path.
        path: PathBuf,
        /// The system's reason.
        detail: String,
    },
    /// A folder was needed (training records) and this is not one.
    NotAFolder {
        /// The path.
        path: PathBuf,
    },
    /// A pipe, socket or device: not a regular file.
    NotRegular {
        /// The path.
        path: PathBuf,
    },
    /// A link that resolves to a directory.
    LinkToDirectory {
        /// The link.
        path: PathBuf,
    },
    /// A link that resolves to nothing.
    LinkToNothing {
        /// The link.
        path: PathBuf,
    },
    /// A link that cannot be resolved, for instance through a loop.
    LinkUnresolved {
        /// The link.
        path: PathBuf,
        /// The system's reason.
        detail: String,
    },
    /// A link Windows cannot follow: a symbolic link that WSL or another Linux
    /// tool made on an NTFS disk.
    LinkNotFollowable {
        /// The link.
        path: PathBuf,
    },
    /// A file whose name, or the name of a folder on its path, is not a
    /// sequence of Unicode scalar values.
    NameNotUnicode {
        /// The entry.
        path: PathBuf,
    },
    /// A model given as one file whose final component its folder does not
    /// list, as typed or, with case ignored, as one name of the same file.
    NotListed {
        /// The path given.
        path: PathBuf,
    },
    /// A model given as one file whose final component matches several names
    /// its folder lists when case is ignored.
    AmbiguousName {
        /// The path given.
        path: PathBuf,
        /// The names it matches, in order.
        names: Vec<String>,
    },
    /// A file whose size changed while it was read.
    Changed {
        /// The file.
        path: PathBuf,
        /// Its size when opened.
        before: u64,
        /// The bytes read.
        read: u64,
        /// Its size after the read.
        after: u64,
    },
    /// A file larger than a record can state.
    TooLarge {
        /// The file.
        path: PathBuf,
        /// Its size.
        size: u64,
    },
    /// The names do not form a set of spec §7.2.
    Names {
        /// Why.
        detail: String,
    },
}

impl WalkError {
    /// The path the refusal names, when it names one.
    pub fn path(&self) -> Option<&Path> {
        match self {
            WalkError::Unreadable { path, .. }
            | WalkError::NotAFolder { path }
            | WalkError::NotRegular { path }
            | WalkError::LinkToDirectory { path }
            | WalkError::LinkToNothing { path }
            | WalkError::LinkUnresolved { path, .. }
            | WalkError::LinkNotFollowable { path }
            | WalkError::NameNotUnicode { path }
            | WalkError::NotListed { path }
            | WalkError::AmbiguousName { path, .. }
            | WalkError::Changed { path, .. }
            | WalkError::TooLarge { path, .. } => Some(path),
            WalkError::Names { .. } => None,
        }
    }

    /// What is wrong, in words, without the path (a caller shows the path its
    /// own way). Names are quoted as they are: a caller escapes them once.
    pub fn reason(&self) -> String {
        match self {
            WalkError::Unreadable { detail, .. } => format!("cannot be read: {detail}"),
            WalkError::NotAFolder { .. } => "is not a folder: training records are the files of a folder".into(),
            WalkError::NotRegular { .. } => {
                "is not a regular file (a pipe, a socket or a device): a model's files are regular files (spec §7.2)"
                    .into()
            }
            WalkError::LinkToDirectory { .. } => {
                "is a link that resolves to a directory: spec §7.2 refuses a folder that holds one".into()
            }
            WalkError::LinkToNothing { .. } => {
                "is a link that resolves to nothing: spec §7.2 refuses a folder that holds one".into()
            }
            WalkError::LinkUnresolved { detail, .. } => format!(
                "is a link that cannot be resolved, for instance through a loop ({detail}): spec §7.2 refuses a \
                 folder that holds one"
            ),
            WalkError::LinkNotFollowable { .. } => {
                "is a link Windows cannot follow (a symbolic link made by WSL or another Linux tool on this disk): \
                 spec §7.2 refuses a folder that holds one; read the folder from Linux, or replace the links with \
                 copies of their files"
                    .into()
            }
            WalkError::NameNotUnicode { .. } => "is a file whose name, or the name of a folder on its path, is not a \
                 sequence of Unicode scalar values (bytes that are not UTF-8, or an unpaired surrogate): spec §7.2 \
                 refuses a folder that holds one"
                .into(),
            WalkError::NotListed { .. } => "is not a name its folder lists: the file system opened the file under \
                 another spelling, such as a short 8.3 name; give the path as its folder lists it (spec §7.2 names a \
                 file as the file system stores it)"
                .into(),
            WalkError::AmbiguousName { names, .. } => {
                let listed: Vec<String> = names.iter().map(|n| format!("\"{n}\"")).collect();
                format!(
                    "matches several names its folder lists when case is ignored ({}): give the path as its folder \
                     lists it (spec §7.2 names a file as the file system stores it)",
                    listed.join(", ")
                )
            }
            WalkError::Changed { before, read, after, .. } => format!(
                "changed while it was read ({before} bytes when opened, {read} read, {after} after): nothing is \
                 signed over a file that changes"
            ),
            WalkError::TooLarge { size, .. } => {
                format!("is {size} bytes, more than a record can state (2^53 - 1)")
            }
            WalkError::Names { detail } => detail.clone(),
        }
    }
}

impl std::fmt::Display for WalkError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.path() {
            Some(path) => write!(f, "{} {}", path.display(), self.reason()),
            None => f.write_str(&self.reason()),
        }
    }
}

impl std::error::Error for WalkError {}

fn unreadable(path: &Path, e: io::Error) -> WalkError {
    WalkError::Unreadable { path: path.to_path_buf(), detail: e.to_string() }
}

/// Whether `e` is Windows' refusal to follow a link it cannot resolve, such as
/// a symbolic link WSL made on NTFS.
fn is_unfollowable_link(e: &io::Error) -> bool {
    cfg!(windows) && e.raw_os_error() == Some(WINDOWS_CANT_ACCESS_FILE)
}

/// The refusal for a link that did not resolve to anything readable.
fn link_error(path: PathBuf, e: io::Error) -> WalkError {
    if e.kind() == io::ErrorKind::NotFound {
        WalkError::LinkToNothing { path }
    } else if is_unfollowable_link(&e) {
        WalkError::LinkNotFollowable { path }
    } else {
        WalkError::LinkUnresolved { path, detail: e.to_string() }
    }
}

/// The metadata of the path a caller gave, links followed; a link Windows
/// cannot follow is named as such.
fn given_metadata(path: &Path) -> Result<fs::Metadata, WalkError> {
    fs::metadata(path).map_err(|e| {
        let is_link = fs::symlink_metadata(path).map(|m| m.file_type().is_symlink()).unwrap_or(false);
        if is_link && is_unfollowable_link(&e) {
            WalkError::LinkNotFollowable { path: path.to_path_buf() }
        } else {
            unreadable(path, e)
        }
    })
}

/// The files of a model given as `path`: a folder, whose every file is named
/// by its path in it, or one file, named by its own name as its folder lists
/// it (spec §7.2). A link given as `path` itself is the caller's own argument
/// and is followed; a model given as a link to one file is named by the link's
/// own name.
pub fn read_model(path: &Path) -> Result<FileSet, WalkError> {
    read_model_observed(path, &mut NoObserver)
}

/// [`read_model`], telling `observer` what the walk does: the same files,
/// names, order and digests.
pub fn read_model_observed(path: &Path, observer: &mut dyn WalkObserver) -> Result<FileSet, WalkError> {
    let path = std::path::absolute(path).map_err(|e| unreadable(path, e))?;
    let meta = given_metadata(&path)?;
    if meta.is_dir() {
        return read_tree(&path, observer);
    }
    if !meta.is_file() {
        return Err(WalkError::NotRegular { path });
    }
    let name = stored_file_name(&path, &meta)?;
    let through_link = fs::symlink_metadata(&path).map(|m| m.file_type().is_symlink()).unwrap_or(false);
    observer.listed(1, Some(meta.len()));
    let (digest, size_bytes) = hash_file(&path, 0, &name, observer)?;
    FileSet::from_entries(vec![FileEntry { name, digest, size_bytes, source: DigestSource::Read { through_link } }])
        .map_err(|e| WalkError::Names { detail: e.to_string() })
}

/// The files of the folder `path`, each named by its path in it (spec §7.2):
/// how training records are given. A path that is not a folder is refused.
pub fn read_folder(path: &Path) -> Result<FileSet, WalkError> {
    read_folder_observed(path, &mut NoObserver)
}

/// [`read_folder`], telling `observer` what the walk does.
pub fn read_folder_observed(path: &Path, observer: &mut dyn WalkObserver) -> Result<FileSet, WalkError> {
    let path = std::path::absolute(path).map_err(|e| unreadable(path, e))?;
    let meta = given_metadata(&path)?;
    if !meta.is_dir() {
        return Err(WalkError::NotAFolder { path });
    }
    read_tree(&path, observer)
}

/// The name of the file at `path`, which `opened` describes, as its folder
/// lists it (spec §7.2: a name as the file system stores it; QA QM-01).
///
/// The path's final component, when the folder lists that name. Otherwise a
/// case-insensitive file system opened the file under another spelling (NTFS,
/// or drvfs from WSL, opens `WEIGHTS.BIN` stored as `weights.bin`): the one
/// name the folder lists that equals it with case ignored as NTFS ignores it
/// ([`case_key`]) and is the file opened. No such name, or several, is
/// refused: a name is never guessed. (Windows drops a final component's
/// trailing dots and spaces when it opens a path, and `std::path::absolute`
/// drops them the same way, so `weights.bin.` is the listed `weights.bin`.)
fn stored_file_name(path: &Path, opened: &fs::Metadata) -> Result<String, WalkError> {
    let no_name = || WalkError::Unreadable { path: path.to_path_buf(), detail: "the path names no file".into() };
    let typed = path.file_name().ok_or_else(no_name)?;
    let parent = path.parent().ok_or_else(no_name)?;
    let mut listed = Vec::new();
    for entry in fs::read_dir(parent).map_err(|e| unreadable(parent, e))? {
        let name = entry.map_err(|e| unreadable(parent, e))?.file_name();
        if name.as_os_str() == typed {
            return name.into_string().map_err(|_| WalkError::NameNotUnicode { path: path.to_path_buf() });
        }
        if let Ok(text) = name.into_string() {
            listed.push(text);
        }
    }
    let typed = typed.to_str().ok_or_else(|| WalkError::NameNotUnicode { path: path.to_path_buf() })?;
    match listed_match(typed, listed) {
        ListedMatch::One(name) if same_file(&parent.join(&name), opened) => Ok(name),
        ListedMatch::One(_) | ListedMatch::None => Err(WalkError::NotListed { path: path.to_path_buf() }),
        ListedMatch::Several(names) => Err(WalkError::AmbiguousName { path: path.to_path_buf(), names }),
    }
}

/// How a typed name matches the names a folder lists, with case ignored.
#[derive(Debug, PartialEq, Eq)]
enum ListedMatch {
    /// No listed name.
    None,
    /// Exactly one listed name.
    One(String),
    /// Several listed names, in order.
    Several(Vec<String>),
}

/// The listed names equal to `typed` with case ignored ([`case_key`]).
fn listed_match(typed: &str, listed: Vec<String>) -> ListedMatch {
    let key = case_key(typed);
    let mut found: Vec<String> = listed.into_iter().filter(|name| case_key(name) == key).collect();
    found.sort();
    match found.len() {
        0 => ListedMatch::None,
        1 => found.pop().map_or(ListedMatch::None, ListedMatch::One),
        _ => ListedMatch::Several(found),
    }
}

/// `name` with case ignored as NTFS ignores it: each character of the Basic
/// Multilingual Plane whose upper case is one such character is upper-cased;
/// nothing else changes (no character becomes two, nothing is normalised).
fn case_key(name: &str) -> Vec<char> {
    name.chars()
        .map(|c| {
            if u32::from(c) > 0xFFFF {
                return c;
            }
            let mut upper = c.to_uppercase();
            match (upper.next(), upper.next()) {
                (Some(u), None) if u32::from(u) <= 0xFFFF => u,
                _ => c,
            }
        })
        .collect()
}

/// Whether `candidate` is the file `opened` describes. On Unix, the same
/// device and inode.
#[cfg(unix)]
fn same_file(candidate: &Path, opened: &fs::Metadata) -> bool {
    use std::os::unix::fs::MetadataExt;
    fs::metadata(candidate).map(|m| m.dev() == opened.dev() && m.ino() == opened.ino()).unwrap_or(false)
}

/// Whether `candidate` is the file `opened` describes. Windows has no stable
/// file id in `std` without unsafe code, so the same size, attributes,
/// creation time and last write time stand in for it: a different file would
/// have to share all four.
#[cfg(windows)]
fn same_file(candidate: &Path, opened: &fs::Metadata) -> bool {
    use std::os::windows::fs::MetadataExt;
    fs::metadata(candidate)
        .map(|m| {
            m.file_size() == opened.file_size()
                && m.file_attributes() == opened.file_attributes()
                && m.creation_time() == opened.creation_time()
                && m.last_write_time() == opened.last_write_time()
        })
        .unwrap_or(false)
}

/// Elsewhere no file identity is checked, so a name found with case ignored is
/// refused.
#[cfg(not(any(unix, windows)))]
fn same_file(_candidate: &Path, _opened: &fs::Metadata) -> bool {
    false
}

/// Name every file under `root`, then hash them in §7.2's order, telling
/// `observer` as they go.
fn read_tree(root: &Path, observer: &mut dyn WalkObserver) -> Result<FileSet, WalkError> {
    let mut found: Vec<(String, PathBuf, bool)> = Vec::new();
    // Each folder to read, with its path in the model: `None` when the name of
    // a folder on that path is not a sequence of Unicode scalar values. Spec
    // §7.2 refuses a folder that holds a file with such a name, so a file below
    // it refuses, and holding no file it contributes nothing (QA QM-03).
    let mut pending: Vec<(PathBuf, Option<String>)> = vec![(root.to_path_buf(), Some(String::new()))];
    while let Some((dir, prefix)) = pending.pop() {
        let entries = fs::read_dir(&dir).map_err(|e| unreadable(&dir, e))?;
        for entry in entries {
            let entry = entry.map_err(|e| unreadable(&dir, e))?;
            let path = entry.path();
            let os_name = entry.file_name();
            let name = match (prefix.as_deref(), os_name.to_str()) {
                (Some(""), Some(part)) => Some(part.to_string()),
                (Some(prefix), Some(part)) => Some(format!("{prefix}/{part}")),
                _ => None,
            };
            let file_type = entry.file_type().map_err(|e| unreadable(&path, e))?;
            if file_type.is_symlink() {
                // Resolve the link: a regular file is hashed under the link's
                // own name; anything else refuses the folder (spec §7.2).
                match fs::metadata(&path) {
                    Ok(m) if m.is_file() => match name {
                        Some(name) => found.push((name, path, true)),
                        None => return Err(WalkError::NameNotUnicode { path }),
                    },
                    Ok(m) if m.is_dir() => return Err(WalkError::LinkToDirectory { path }),
                    Ok(_) => return Err(WalkError::NotRegular { path }),
                    Err(e) => return Err(link_error(path, e)),
                }
            } else if file_type.is_dir() {
                pending.push((path, name));
            } else if file_type.is_file() {
                match name {
                    Some(name) => found.push((name, path, false)),
                    None => return Err(WalkError::NameNotUnicode { path }),
                }
            } else {
                return Err(WalkError::NotRegular { path });
            }
        }
    }
    found.sort_by(|a, b| a.0.as_bytes().cmp(b.0.as_bytes()));
    let total = if observer.wants_total() {
        found.iter().try_fold(0u64, |sum, (_, path, _)| fs::metadata(path).ok().map(|m| sum.saturating_add(m.len())))
    } else {
        None
    };
    observer.listed(found.len() as u64, total);
    let mut entries = Vec::with_capacity(found.len());
    for (index, (name, path, through_link)) in found.into_iter().enumerate() {
        let (digest, size_bytes) = hash_file(&path, index as u64, &name, observer)?;
        entries.push(FileEntry { name, digest, size_bytes, source: DigestSource::Read { through_link } });
    }
    FileSet::from_entries(entries).map_err(|e| WalkError::Names { detail: e.to_string() })
}

/// The SHA-256 and size of the regular file at `path`, read once: file
/// `index` of the walk, named `name`, as `observer` is told.
fn hash_file(
    path: &Path,
    index: u64,
    name: &str,
    observer: &mut dyn WalkObserver,
) -> Result<([u8; DIGEST_LEN], u64), WalkError> {
    let mut file = fs::File::open(path).map_err(|e| unreadable(path, e))?;
    let opened = file.metadata().map_err(|e| unreadable(path, e))?;
    if !opened.is_file() {
        return Err(WalkError::NotRegular { path: path.to_path_buf() });
    }
    let before = opened.len();
    if before > MAX_SAFE_INTEGER {
        return Err(WalkError::TooLarge { path: path.to_path_buf(), size: before });
    }
    observer.file_started(index, name, before);
    let (digest, read) = hash_observed(&mut file, observer).map_err(|e| unreadable(path, e))?;
    let after = file.metadata().map_err(|e| unreadable(path, e))?.len();
    check_unchanged(path, before, read, after)?;
    Ok((digest, read))
}

/// SHA-256 over everything `reader` yields, in pieces of [`BUFFER`] bytes.
#[cfg(test)]
fn hash_reader(reader: &mut impl Read) -> io::Result<([u8; DIGEST_LEN], u64)> {
    hash_observed(reader, &mut NoObserver)
}

/// SHA-256 over everything `reader` yields, in pieces of [`BUFFER`] bytes,
/// `observer` told of each piece.
fn hash_observed(reader: &mut impl Read, observer: &mut dyn WalkObserver) -> io::Result<([u8; DIGEST_LEN], u64)> {
    let mut buffer = vec![0u8; BUFFER];
    let mut hasher = Sha256::new();
    let mut read: u64 = 0;
    loop {
        let n = match reader.read(&mut buffer) {
            Ok(0) => break,
            Ok(n) => n,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e),
        };
        hasher.update(buffer.get(..n).unwrap_or_default());
        read = read.saturating_add(n as u64);
        observer.bytes_read(n as u64);
    }
    Ok((hasher.finalize().into(), read))
}

/// The size when opened, the bytes read and the size after must agree.
fn check_unchanged(path: &Path, before: u64, read: u64, after: u64) -> Result<(), WalkError> {
    if before != read || after != read {
        return Err(WalkError::Changed { path: path.to_path_buf(), before, read, after });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_reader_is_hashed_in_pieces_to_the_digest_of_its_bytes() {
        for len in [0usize, 1, BUFFER - 1, BUFFER, BUFFER + 1, 2 * BUFFER + 3] {
            let bytes: Vec<u8> = (0..len).map(|i| (i % 251) as u8).collect();
            let (digest, read) = hash_reader(&mut io::Cursor::new(&bytes)).unwrap();
            assert_eq!((digest, read), (vmr_record::hash::sha256(&bytes), len as u64), "{len}");
        }
    }

    #[test]
    fn a_file_that_grows_or_shrinks_while_it_is_read_is_refused() {
        let p = Path::new("weights.bin");
        assert!(check_unchanged(p, 10, 10, 10).is_ok());
        for (before, read, after) in [(10, 12, 12), (10, 10, 12), (12, 10, 10), (10, 8, 8)] {
            let err = check_unchanged(p, before, read, after).unwrap_err();
            assert!(matches!(err, WalkError::Changed { .. }), "{err}");
            assert!(err.to_string().contains("changed while it was read"), "{err}");
        }
    }

    #[test]
    fn a_typed_name_matches_the_listed_names_with_case_ignored_as_ntfs_does() {
        // QA QM-01: one listed name equal with case ignored is the name; none is
        // refused; several are refused as ambiguous, never guessed.
        let listed = |names: &[&str]| names.iter().map(|n| n.to_string()).collect::<Vec<_>>();
        assert_eq!(listed_match("WEIGHTS.BIN", listed(&["config.json", "weights.bin"])), ListedMatch::One("weights.bin".into()));
        assert_eq!(listed_match("MODEL-~1.SAF", listed(&["model-00001-of-00002.safetensors"])), ListedMatch::None);
        assert_eq!(
            listed_match("weights.BIN", listed(&["WEIGHTS.bin", "Weights.bin", "other.bin"])),
            ListedMatch::Several(listed(&["WEIGHTS.bin", "Weights.bin"]))
        );
        // Letters beyond ASCII upper-case one to one; no character becomes two
        // (ß stays ß, as NTFS keeps it), and nothing is normalised.
        assert_eq!(listed_match("DONNÉES.BIN", listed(&["données.bin"])), ListedMatch::One("données.bin".into()));
        assert_eq!(listed_match("STRASSE.BIN", listed(&["straße.bin"])), ListedMatch::None);
        assert_eq!(listed_match("E\u{301}.BIN", listed(&["\u{e9}.bin"])), ListedMatch::None);
    }

    #[test]
    fn a_link_windows_cannot_follow_is_named_as_such_and_a_missing_target_as_nothing() {
        // QA QM-04: following a symbolic link WSL made on NTFS gives Windows'
        // error 1920; the refusal says so, not "a loop".
        let path = || PathBuf::from("snapshots/rev/model.safetensors");
        let followable = link_error(path(), io::Error::from_raw_os_error(WINDOWS_CANT_ACCESS_FILE));
        if cfg!(windows) {
            assert!(matches!(followable, WalkError::LinkNotFollowable { .. }), "{followable}");
            assert!(followable.reason().contains("Windows cannot follow"), "{followable}");
            assert!(followable.reason().contains("WSL"), "{followable}");
            assert!(!followable.reason().contains("loop"), "{followable}");
        } else {
            assert!(matches!(followable, WalkError::LinkUnresolved { .. }), "1920 is Windows' code only: {followable}");
        }
        let missing = link_error(path(), io::Error::from(io::ErrorKind::NotFound));
        assert!(matches!(missing, WalkError::LinkToNothing { .. }), "{missing}");
    }
}
