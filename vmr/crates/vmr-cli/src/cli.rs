//! The command tree (docs/dev/phase5.md §2).
// ============================================================================
//  cli.rs — clap definitions only: names, arguments, help text
//
//  No behaviour lives here; each command's module does the work. Every
//  command documents its arguments, defaults and exit codes in --help
//  (TLM_LAYER.md §8.2). The tree grows by one command per task (5.2-5.6);
//  no command is listed before it works.
//
//  Task 10.13a: `record emit` takes a model's files (--model), and `model
//  hash` shows them. This tree names no engine input: a build that adds one
//  extends it from outside this crate, with clap's builder API (D13a-3).
// ============================================================================

use crate::error::{EXIT_CODES_DONE, EXIT_CODES_HELP, EXIT_CODES_VERIFY};
use crate::names::TOOL;
use clap::{Args, Parser, Subcommand};
use std::path::PathBuf;
use vmr_record::timestamp::Timestamp;

// Help text names the tool through `crate::tool_name!()` and cites the
// standard's documents by name, never a path in this repository
// (docs/dev/cli-polish.md CP-3, CP-10).

/// `--version`: the version (C1, D11f-5). It names no build: this tool makes
/// and verifies records of any model's files (task 10.13a). The parenthetical
/// names the software, this build's reference status and the record format
/// it implements, so that `0.1.0` is not read as the standard's own version.
const VERSION: &str = concat!(
    env!("CARGO_PKG_VERSION"),
    " (",
    crate::software_name!(),
    ", a reference implementation of the Verifiable Model Record standard; record format v0.1)"
);

/// What this build's `--version` adds after its number (D11f-5): a build
/// that extends this tree (`screens::wordmark`) is told apart by comparing
/// its own words against this, not by whether it has any.
pub(crate) const REFERENCE_WORDS: &str = concat!(
    "(",
    crate::software_name!(),
    ", a reference implementation of the Verifiable Model Record standard; record format v0.1)"
);

/// What a record is and how it is verified, in every build's long description.
macro_rules! record_about {
    () => {
        " A record is a signed record of what a model learned, from what, and under which declared policy. \
         Verification is offline: it needs only the record and a trust store provisioned beforehand - no network, \
         no contact with the issuer. Records made by any conforming tool are equally valid."
    };
}

/// The top-level long description: what the tool is, and claims no more.
const LONG_ABOUT: &str = concat!(
    "Emit, verify and inspect Verifiable Model Records (VMR).\n\n",
    crate::tool_name!(),
    " is a reference implementation of the Verifiable Model Record standard.",
    record_about!()
);

/// The top-level long description for a build that extends this tree (QA
/// QPB-11): it implements the standard, and claims no reference status.
pub const EXTENDED_LONG_ABOUT: &str = concat!(
    "Emit, verify and inspect Verifiable Model Records (VMR).\n\n",
    crate::tool_name!(),
    " implements the Verifiable Model Record standard.",
    record_about!()
);

/// The top-level command.
#[derive(Debug, Parser)]
#[command(
    name = TOOL,
    bin_name = TOOL,
    version = VERSION,
    about = "Emit, verify and inspect Verifiable Model Records (VMR)",
    long_about = LONG_ABOUT,
    after_help = EXIT_CODES_HELP,
    arg_required_else_help = true
)]
pub struct Cli {
    /// What to do.
    #[command(subcommand)]
    pub command: Command,

    /// Use colour on a terminal: auto, always or never. `always` also draws
    /// the terminal screens into a pipe or a file.
    #[arg(long, value_name = "WHEN", value_enum, default_value = "auto", global = true)]
    pub color: ColorArg,

    /// Draw the terminal screens' boxes and tables with plain ASCII characters.
    #[arg(long, global = true)]
    pub ascii: bool,
}

/// When the terminal screens are coloured (docs/dev/cli-polish.md CP-4).
#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
pub enum ColorArg {
    /// On a terminal, unless NO_COLOR, CLICOLOR=0 or TERM=dumb says otherwise.
    Auto,
    /// Always, and the screens are drawn into a pipe or a file too.
    Always,
    /// Never; a terminal still gets its boxes and tables.
    Never,
}

/// The command groups.
#[derive(Debug, Subcommand)]
pub enum Command {
    /// Emit, verify and inspect records.
    #[command(subcommand)]
    Record(RecordCommand),
    /// Name and hash a model's files as a record carries them; signs nothing.
    #[command(subcommand)]
    Model(ModelCommand),
    /// Make and export signing keys.
    #[command(subcommand)]
    Key(KeyCommand),
    /// Provision a trust store: the keys a verifier trusts, and for whom.
    #[command(subcommand)]
    TrustStore(TrustStoreCommand),
}

/// `vmr model ...`
#[derive(Debug, Subcommand)]
pub enum ModelCommand {
    /// Show every file of a model with its size and hash, and its model_hash; signs nothing.
    #[command(long_about = MODEL_HASH_LONG)]
    Hash(ModelHashArgs),
}

const MODEL_HASH_LONG: &str = concat!(
    "Show every file of a model with its size and hash, and its model_hash; signs nothing.\n\n",
    crate::tool_name!(),
    " names the files of --model exactly as `",
    crate::tool_name!(),
    " record emit` does, by the record format's rules (§7.2): a folder names every file by its path in it, with /, \
     and one file is named by its own name; no file is left out by name, hidden files included; a link to a regular \
     file is hashed as that file under the link's own name, and a link to a directory, to nothing or through a loop, \
     a pipe, a socket, a device, or a file whose name is not Unicode refuses the folder; one file given is named as \
     its folder lists it. It prints the named-set digest of every file - a record's model_hash - then each name with \
     its size and SHA-256, in the order hashed. Run it before emitting, to see every name a record will carry, or on \
     a base model, to state its model_hash in a manifest's derived_from. This command signs nothing and writes no \
     file."
);

/// `vmr model hash`
#[derive(Debug, Args)]
#[command(after_help = EXIT_CODES_DONE)]
pub struct ModelHashArgs {
    /// The model: a folder of its files, or one file.
    #[arg(long, value_name = "DIR|FILE")]
    pub model: PathBuf,

    /// Print {"model_hash", "files": [{"name", "hash", "size_bytes"}]} as JSON instead of text.
    #[arg(long)]
    pub json: bool,

    /// On a terminal screen, show each file's whole SHA-256; the text and --json always show it whole.
    #[arg(long)]
    pub full: bool,
}

/// `vmr trust-store ...`
#[derive(Debug, Subcommand)]
pub enum TrustStoreCommand {
    /// Trust a public key for an issuer: add it to a trust store (created if missing).
    #[command(long_about = TRUST_STORE_ADD_LONG)]
    Add(TrustStoreAddArgs),
}

const TRUST_STORE_ADD_LONG: &str = concat!(
    "Trust a public key for an issuer: add it to a trust store (created if missing).\n\n\
     A trust store is the verifier's own list of whom it trusts, provisioned beforehand and out of band (the \
     trust-store format). This command is that decision, made explicit: the key (a public key file from `",
    crate::tool_name!(),
    " key export`, received from the issuer - compare its key id with the issuer by a second channel), the DID it \
     may sign for, the name to show for that issuer, the highest attestation level its records may declare, and the \
     first second (and optionally the last) at which it may sign. None of these has a default. It never reads a \
     record: a key is never trusted because a record carries it. The store is validated before it is written, and \
     written atomically."
);

/// The attestation levels, as the trust-store format names them.
#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
pub enum AttestationArg {
    /// The issuer vouches for its own key.
    #[value(name = "self")]
    SelfAttested,
    /// A software-held key.
    Software,
    /// A hardware-held key.
    Hardware,
}

/// `vmr trust-store add`
#[derive(Debug, Args)]
#[command(after_help = EXIT_CODES_DONE)]
pub struct TrustStoreAddArgs {
    /// The trust store to add to; created if it does not exist.
    #[arg(long, value_name = "FILE")]
    pub trust_store: PathBuf,

    // The issuer's public key file.
    #[arg(long, value_name = "FILE", help = concat!("The issuer's public key file (from `", crate::tool_name!(), " key export`)"))]
    pub public_key: PathBuf,

    /// The DID this key may sign records for, e.g. did:web:factory-operator.ph.
    #[arg(long, value_name = "DID")]
    pub issuer_id: String,

    /// The name verification shows for this issuer (the record's own name is only a claim).
    #[arg(long, value_name = "NAME")]
    pub issuer_name: String,

    /// The highest attestation level a record signed by this key may declare.
    #[arg(long, value_name = "LEVEL", value_enum)]
    pub attestation_level: AttestationArg,

    /// The first second at which the key may sign (UTC, YYYY-MM-DDTHH:MM:SSZ).
    #[arg(long, value_name = "T", value_parser = parse_timestamp)]
    pub valid_from: Timestamp,

    /// The key may sign only before this second (UTC); without it, no end.
    #[arg(long, value_name = "T", value_parser = parse_timestamp)]
    pub valid_until: Option<Timestamp>,
}

/// `vmr key ...`
#[derive(Debug, Subcommand)]
pub enum KeyCommand {
    /// Generate a new P-256 signing key and write it as a PKCS#8 PEM file.
    #[command(long_about = KEY_GENERATE_LONG)]
    Generate(KeyGenerateArgs),
    /// Export the public key of a private key file, for trust stores.
    #[command(long_about = KEY_EXPORT_LONG)]
    Export(KeyExportArgs),
}

const KEY_EXPORT_LONG: &str = "Export the public key of a private key file, for trust stores.\n\n\
    Writes the public key as JSON with exactly two members, `key_id` (the RFC 7638 thumbprint \
    URN) and `public_key` (the JWK) - the two members a trust-store key entry carries under \
    the same names, so the file drops into a trust store as it stands. Give it to the \
    verifiers who should trust your records: the private key never leaves the key file and \
    is never printed. Without --output the JSON goes to standard output.";

/// `vmr key export`
#[derive(Debug, Args)]
#[command(after_help = EXIT_CODES_DONE)]
pub struct KeyExportArgs {
    // The private key file.
    #[arg(long, value_name = "FILE", help = concat!("The private key file (as `", crate::tool_name!(), " key generate` writes it)"))]
    pub key: PathBuf,

    /// Write the public key file here (a new file) instead of to standard output.
    #[arg(long, value_name = "FILE")]
    pub output: Option<PathBuf>,

    /// Replace the --output file if it exists.
    #[arg(long, requires = "output")]
    pub force: bool,
}

const KEY_GENERATE_LONG: &str = "Generate a new P-256 signing key and write it as a PKCS#8 PEM file.\n\n\
    The key comes from the operating system's cryptographic random-number generator; every \
    run makes a different key. The file is a PKCS#8 PEM (\"-----BEGIN PRIVATE KEY-----\"), \
    not encrypted, readable by its owner only on Unix; on Windows it inherits its folder's \
    permissions - keep it in a folder only you can read, or restrict it with the icacls \
    command the output prints. This version has no passphrase protection and no hardware key store. \
    The private key is never printed; the command prints the key's id (its RFC 7638 \
    thumbprint URN), which is how records and trust stores name it.";

/// `vmr key generate`
#[derive(Debug, Args)]
#[command(after_help = EXIT_CODES_DONE)]
pub struct KeyGenerateArgs {
    /// Where to write the private key (a new file).
    #[arg(long, value_name = "FILE")]
    pub output: PathBuf,

    /// Replace the file if it exists (the key it held is lost).
    #[arg(long)]
    pub force: bool,
}

/// `vmr record ...`
///
/// (A long description goes on the variant: clap derive lets a variant's
/// doc comment reset the `long_about` of the arguments struct.)
#[derive(Debug, Subcommand)]
pub enum RecordCommand {
    /// Emit a signed record of a model from its files.
    #[command(about = EMIT_ABOUT, long_about = EMIT_LONG)]
    Emit(EmitArgs),
    /// Verify a record against a trust store, offline.
    #[command(long_about = VERIFY_LONG)]
    Verify(VerifyArgs),
    /// Print what a record claims, without verifying anything.
    #[command(long_about = INSPECT_LONG)]
    Inspect(InspectArgs),
}

/// `record emit`'s long description. Public, so that a build that extends
/// this tree adds to it instead of restating it (task 10.13a, D13a-3).
pub const EMIT_LONG: &str = concat!(
    "Emit a signed record of a model from its files: for any AI model, from any vendor, whose weights you hold. ",
    crate::tool_name!(),
    " hashes each file under its path in the folder and signs your manifest's statements about the model, its \
     training and its declared policy with --key. Only a party that holds a model's files can compute its hashes: \
     sign a record only for files you hold. ",
    crate::tool_name!(),
    " reads no model format and checks none of the manifest's statements. The policy section is your declaration; ",
    crate::tool_name!(),
    " evaluates no policy pack here.\n\n\
     Every output labels the policy as declared, not evaluated. The files are read by the record format's rules \
     (§7.2): a folder names each file by its path in it, with /, and one file is named by its own name; no file is \
     left out by name, hidden files included; a link to a regular file is hashed as that file under the link's own \
     name; a link to a directory, to nothing or through a loop, a pipe, a socket, a device, or a file whose name is \
     not Unicode refuses the folder; one file given is named as its folder lists it. `",
    crate::tool_name!(),
    " model hash` shows every name ",
    crate::tool_name!(),
    " will hash before anything is signed, and this command's output lists them too.\n\n\
     The record is reproducible: the same files, manifest, key and --issued-at give the same bytes. Without \
     --issued-at the current UTC second is used (an --issued-at in the future is refused); without --record-id the \
     id is derived from the record's content. The output says which. A record that would fail verification at the \
     moment it is written, by a verifier whose trust store trusts the signing key, is never written."
);

const EMIT_ABOUT: &str = "Emit a signed record of a model from its files";

const VERIFY_LONG: &str = "Verify a record against a trust store, offline.\n\n\
    Answers one question: is this a well-formed v0.1 record, signed by a key that this \
    trust store trusts for the issuer the record names? Nothing is fetched and the issuer \
    is never contacted: the only inputs are the record, the trust store (provisioned \
    beforehand, out of band), the evaluation time and any predecessor records you supply. \
    The key the signature is checked with comes from the trust store, never from the \
    record.\n\n\
    The record's policy section is always shown as the ISSUER's declaration. With \
    --policy-pack this verifier also evaluates the record itself, against that pack, and \
    reports what IT found on a line of its own: the two are never merged, and a \
    disagreement between them is called out. An evaluation here is stamped with this \
    verifier's time (--at, else the clock), which is long after the record was issued \
    and is meant to be. The pack's own authority signature is checked against the policy \
    authorities of the trust store, or of --authority-store when given: a signature that does \
    not verify is exit code 1 before anything is verified, and an unsigned pack, or one signed \
    by a key no trusted authority holds, is evaluated and labelled as such \
    (--require-signed-pack refuses both). Exit code 4 means the record verified but the \
    evaluation did not accept it, an undecidable (indeterminate) result included.";

const INSPECT_LONG: &str = concat!(
    "Print what a record claims, without verifying anything.\n\n\
     This command does not verify: it parses the record (either form) and prints every section under an \
     UNVERIFIED banner. A forged record inspects exactly like a genuine one. To find out who signed it, use `",
    crate::tool_name!(),
    " record verify` with a trust store."
);

/// The two forms of a record file.
#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
pub enum FormatArg {
    /// COSE_Sign1 (binary): the distribution form.
    Cose,
    /// The JSON document (text).
    Json,
}

/// `vmr record emit`
#[derive(Debug, Args)]
#[command(after_help = EXIT_CODES_DONE)]
pub struct EmitArgs {
    /// The model: a folder of its files (each named by its path in it), or one file (named by its own name).
    // Required here, and still an Option: a build that adds another input
    // mode makes it optional (task 10.13a, D13a-3).
    #[arg(long, value_name = "DIR|FILE", required = true)]
    pub model: Option<PathBuf>,

    /// A file of the model that you name as its learned state; repeat for each. Without it, every file is a component.
    #[arg(long, value_name = "NAME")]
    pub component: Vec<String>,

    /// The training records: every file of this folder, committed as named-set-v1 (count, digest, Merkle root).
    /// Without it, the manifest's training.input_disclosure says the records are not held or not disclosed.
    #[arg(long, value_name = "DIR")]
    pub training_records: Option<PathBuf>,

    /// The manifest: the issuer's statements about the model, its training and its declared policy (JSON).
    #[arg(long, value_name = "MANIFEST")]
    pub manifest: PathBuf,

    // The signing key.
    #[arg(long, value_name = "KEY", help = concat!("The signing key: a PKCS#8 PEM private key (`", crate::tool_name!(), " key generate`)"))]
    pub key: PathBuf,

    /// Where to write the record (a new file).
    #[arg(long, value_name = "FILE")]
    pub output: PathBuf,

    /// The record's issued_at (UTC, YYYY-MM-DDTHH:MM:SSZ); default: now.
    #[arg(long, value_name = "T", value_parser = parse_timestamp)]
    pub issued_at: Option<Timestamp>,

    /// The record's id (urn:uuid:, lower case); default: derived from the
    /// record's content.
    #[arg(long, value_name = "URN")]
    pub record_id: Option<String>,

    /// The output form.
    #[arg(long, value_name = "FORMAT", value_enum, default_value = "cose")]
    pub format: FormatArg,

    /// Replace the output file if it exists.
    #[arg(long)]
    pub force: bool,

    /// On a terminal screen, show each file's whole SHA-256; the text always shows it whole.
    #[arg(long)]
    pub full: bool,
}

/// `vmr record inspect`
#[derive(Debug, Args)]
#[command(after_help = EXIT_CODES_DONE)]
pub struct InspectArgs {
    // The record, in either form.
    #[arg(long, value_name = "FILE", help = concat!("The record: its COSE form (e.g. model.", crate::record_extension!(), ") or its JSON form"))]
    pub record: PathBuf,
}

/// `vmr record verify`
#[derive(Debug, Args)]
#[command(after_help = EXIT_CODES_VERIFY)]
pub struct VerifyArgs {
    // The record, in either form.
    #[arg(
        long,
        value_name = "FILE",
        help = concat!(
            "The record: its COSE form (e.g. model.",
            crate::record_extension!(),
            ") or its JSON form; the form is detected from the bytes"
        )
    )]
    pub record: PathBuf,

    /// The trust store: the issuers and keys you trust, provisioned beforehand
    /// (the trust-store format).
    #[arg(long, value_name = "FILE")]
    pub trust_store: PathBuf,

    /// Judge the record at this UTC time (YYYY-MM-DDTHH:MM:SSZ) instead of
    /// now - for reproducible runs. The output says which was used.
    #[arg(long, value_name = "T", value_parser = parse_timestamp)]
    pub at: Option<Timestamp>,

    /// A predecessor of the record, immediate predecessor first; repeat the
    /// option for each. Each is verified in full and linked to its successor.
    #[arg(long, value_name = "FILE")]
    pub previous: Vec<PathBuf>,

    /// Fail unless the predecessors given reach an initial record (without
    /// it, an unverified lineage is reported, not failed).
    #[arg(long)]
    pub require_lineage: bool,

    /// Also evaluate the record against this policy pack (JSON, in the
    /// policy-pack format). What this verifier finds is reported next to -
    /// never merged with - the issuer's own declaration; exit code 4 says it
    /// was not accepted.
    #[arg(long, value_name = "FILE")]
    pub policy_pack: Option<PathBuf>,

    /// Take the policy authorities whose keys may sign the pack from this
    /// file instead of --trust-store: a trust store listing only
    /// policy_authorities, with "issuers": [] (the trust-store format, §4.2).
    #[arg(long, value_name = "FILE", requires = "policy_pack")]
    pub authority_store: Option<PathBuf>,

    /// Refuse (exit code 1) a policy pack that is unsigned, or signed by a key
    /// no trusted policy authority holds, instead of evaluating it and saying so.
    #[arg(long, requires = "policy_pack")]
    pub require_signed_pack: bool,

    /// Print the verifier's full report as JSON instead of the summary.
    #[arg(long)]
    pub json: bool,
}

/// A command-line timestamp: the record's UTC-seconds profile.
fn parse_timestamp(text: &str) -> Result<Timestamp, String> {
    Timestamp::parse(text).map_err(|v| v.detail)
}
