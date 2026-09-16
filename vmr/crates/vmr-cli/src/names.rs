//! The tool's and the software's names, each in one place
//! (docs/dev/cli-polish.md CP-10).
// ============================================================================
//  names.rs — what the tool, the software and a record file are called
//
//  Every help text, screen caption, suggested command and example takes these
//  names from here, so that renaming them is one edit. A macro serves text
//  built with `concat!` (clap's help strings are constants); its const serves
//  everything else.
// ============================================================================

/// The command's name, as a user types it.
#[macro_export]
macro_rules! tool_name {
    () => {
        "vmr"
    };
}

/// The software's name.
#[macro_export]
macro_rules! software_name {
    () => {
        "KHALM-VMR"
    };
}

/// The extension an example record file takes, without its dot.
#[macro_export]
macro_rules! record_extension {
    () => {
        "vmr"
    };
}

/// The command's name, as a user types it.
pub const TOOL: &str = tool_name!();

/// The software's name.
pub const SOFTWARE: &str = software_name!();

/// The extension an example record file takes, without its dot.
pub const RECORD_EXTENSION: &str = record_extension!();
