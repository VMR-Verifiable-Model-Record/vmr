//! `vmr model hash` (task 10.13a), and what it shares with `record emit`.
// ============================================================================
//  model_cmd.rs — a model's files, named and hashed, and nothing signed
//
//  The files of --model are named and hashed by vmr-builder's walk, exactly
//  as `record emit` reads them (spec §7.2; docs/dev/task-10.13a.md §12): a
//  folder names every file by its path in it with `/`, one file is named by
//  its own name, no file is left out by name, a link to a regular file is
//  hashed as that file under its own name, and anything §7.2 refuses refuses
//  the folder. The command prints the named-set digest of every file (a
//  record's model_hash), then every name with its size and SHA-256: what the
//  specification's SHOULD asks a tool to show an issuer before signing, and
//  a base model's model_hash for a manifest's derived_from. It signs nothing
//  and writes no file.
// ============================================================================

use crate::cli::ModelHashArgs;
use crate::error::CliError;
use crate::files::shown;
use crate::names::TOOL;
use crate::output::Output;
use crate::render::plural;
use std::path::Path;
use crate::progress::StderrBar;
use vmr_builder::files::{read_model_observed, WalkError};
use vmr_builder::general::FileSet;
use vmr_record::hash::format_hash;

/// Run `vmr model hash`, `bar` shown while the files are read.
pub fn hash(args: &ModelHashArgs, bar: &mut StderrBar) -> Result<Output, CliError> {
    let files = read_model_observed(&args.model, bar);
    bar.finish();
    let files = files.map_err(|e| walk_refusal(&e))?;
    if files.is_empty() {
        return Err(no_files(&args.model));
    }
    if args.json {
        return Ok(Output::ok(json(&files)));
    }
    Ok(Output::ok(format!("{}\n{}", headline("Model hash:", &files, &args.model), file_lines(&files)))
        .with_rich(crate::screens::model_hash(&files, &args.model, args.full)))
}

/// A walk's refusal as the CLI says it: the path shown as every path is,
/// then the reason; exit 1.
pub(crate) fn walk_refusal(e: &WalkError) -> CliError {
    let what = match e.path() {
        Some(path) => format!("{} {}", shown(path), e.reason()),
        None => e.reason(),
    };
    CliError::input(format!("{what}; nothing was written")).with_hint(format!(
        "a model's files are read by specs/record-format-v0.1.md §7.2; `{TOOL} model hash --model <DIR|FILE>` shows \
         what {TOOL} reads, and signs nothing",
    ))
}

/// The refusal of a folder that holds no regular file.
pub(crate) fn no_files(path: &Path) -> CliError {
    CliError::input(format!(
        "model folder {} holds no regular file: a record describes at least one file; nothing was written",
        shown(path)
    ))
}

/// `<label> <model_hash> (N files read, B bytes, from '<path>')`.
fn headline(label: &str, files: &FileSet, path: &Path) -> String {
    format!("{label} {}", hash_value(files, path))
}

/// `<model_hash> (N files read, B bytes, from '<path>')`.
pub(crate) fn hash_value(files: &FileSet, path: &Path) -> String {
    format!(
        "{} ({} read, {} bytes, from {})",
        format_hash(&files.named_set_digest()),
        plural(files.len() as u64, "file", "files"),
        files.total_bytes(),
        shown(path)
    )
}

/// Every name hashed, in the order hashed: `  <64 hex>  <size>  <name>`, each
/// name escaped as every file-derived string is and never shortened.
pub(crate) fn file_lines(files: &FileSet) -> String {
    let mut out = String::new();
    for e in files.entries() {
        let hash = format_hash(&e.digest);
        let hex = hash.strip_prefix("sha256:").unwrap_or(&hash);
        out.push_str(&format!("  {hex}  {}  {}\n", e.size_bytes, vmr_verify::display_safe(&e.name)));
    }
    out
}

/// `{"files": [{"hash", "name", "size_bytes"}, ...], "model_hash": ...}` (the
/// members sorted, as serde_json writes them) and a newline: each file as a
/// record's component would carry it. A model's file names are text its
/// issuer did not choose, so every character a terminal acts on or hides is
/// written as a JSON `\u` escape, exactly as `record verify --json` writes
/// its claims (`vmr_verify::json_escape_unsafe`): the JSON parses to the
/// stored names (QA QM-02).
fn json(files: &FileSet) -> String {
    let listed: Vec<serde_json::Value> = files
        .entries()
        .iter()
        .map(|e| serde_json::json!({ "name": e.name, "hash": format_hash(&e.digest), "size_bytes": e.size_bytes }))
        .collect();
    let v = serde_json::json!({ "model_hash": format_hash(&files.named_set_digest()), "files": listed });
    format!("{}\n", vmr_verify::json_escape_unsafe(v.to_string()))
}
