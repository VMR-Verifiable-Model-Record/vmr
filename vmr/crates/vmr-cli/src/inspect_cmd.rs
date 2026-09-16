//! `vmr record inspect` (TASKS 5.4).
// ============================================================================
//  inspect_cmd.rs — parse a record and print its claims, verifying nothing
//
//  Inspect answers "what does this record say?", never "is it genuine?".
//  It parses either form under the format's own strict rules (the same
//  structure the verifier's json.structure / cose.* checks require) and
//  prints every section under an UNVERIFIED banner (render.rs). A file that
//  is not a v0.1 record is an input error (exit 1); a forged record
//  inspects like a genuine one, because nothing is checked — which is why
//  the banner comes first.
// ============================================================================

use crate::cli::InspectArgs;
use crate::error::CliError;
use crate::files::{self, shown};
use crate::output::Output;
use crate::render;
use vmr_record::Record;
use vmr_verify::MAX_RECORD_BYTES;

/// The two forms of a record (spec §1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Form {
    /// The JSON document (spec §2).
    Json,
    /// The COSE_Sign1 envelope (spec §4.4).
    Cose,
}

impl Form {
    /// Which form `bytes` are in, by the verifier's own rule (spec §6.2,
    /// check 2): first byte 0x84 is the COSE form; a first byte that is not
    /// JSON whitespace being `{` is the JSON form; anything else is neither.
    pub fn detect(bytes: &[u8]) -> Option<Form> {
        if bytes.first() == Some(&0x84) {
            return Some(Form::Cose);
        }
        match bytes.iter().copied().find(|b| !matches!(b, b' ' | b'\t' | b'\n' | b'\r')) {
            Some(b'{') => Some(Form::Json),
            _ => None,
        }
    }

    /// How the output names it.
    pub fn label(self) -> &'static str {
        match self {
            Form::Json => "JSON",
            Form::Cose => "COSE_Sign1",
        }
    }
}

/// Run `record inspect`.
pub fn run(args: &InspectArgs) -> Result<Output, CliError> {
    let bytes = files::read_document(&args.record, "record")?;
    let (record, form) = parse(&bytes).map_err(|why| {
        let e = CliError::input(format!(
            "record {} is not a v0.1 record: {}",
            shown(&args.record),
            render::bounded(&why)
        ));
        match files::byte_order_mark(&bytes) {
            Some(_) => e.with_hint(files::SAVE_WITHOUT_BOM),
            None => e,
        }
    })?;
    let file = shown(&args.record);
    Ok(Output::ok(render::inspection(&record, form, &file, &bytes))
        .with_rich(crate::screens::inspection(&record, form, &file, &bytes)))
}

/// Parse a record in either form, under the format's strict rules.
fn parse(bytes: &[u8]) -> Result<(Record, Form), String> {
    if bytes.len() > MAX_RECORD_BYTES {
        return Err(format!(
            "it is {} bytes; a v0.1 record is at most {MAX_RECORD_BYTES} bytes (1 MiB)",
            bytes.len()
        ));
    }
    // Named, as the verifier's input.form names it (QA P5-07).
    if let Some(bom) = files::byte_order_mark(bytes) {
        return Err(format!("{bom}, which a v0.1 record may not have"));
    }
    match Form::detect(bytes) {
        Some(Form::Cose) => Record::from_cose(bytes).map(|p| (p, Form::Cose)).map_err(|e| e.to_string()),
        Some(Form::Json) => {
            let text = std::str::from_utf8(bytes).map_err(|e| format!("not UTF-8: {e}"))?;
            Record::from_json(text).map(|p| (p, Form::Json)).map_err(|e| e.to_string())
        }
        None if bytes.is_empty() => Err("the file is empty".into()),
        None => Err("it starts with neither '{' (the JSON form) nor 0x84 (the COSE form)".into()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn form_detection_is_the_verifiers() {
        // The same bytes the verifier's own detection sorts (its report's
        // input.form), so inspect and verify never disagree about a file.
        let store = vmr_verify::TrustStore::from_json(br#"{"trust_store_version":"0.1","issuers":[]}"#).unwrap();
        let verifier = vmr_verify::Verifier::new(store);
        let opts = vmr_verify::VerifyOptions::new(
            vmr_record::timestamp::Timestamp::parse("2026-09-11T00:00:00Z").unwrap(),
        );
        for bytes in [&b"{}"[..], b" \n{", b"\x84", b"\x84garbage", b"", b"  ", b"\xef\xbb\xbf{", b"\xd2\x84", b"[", b"x{"] {
            let verifier_form = serde_json::to_value(verifier.verify(bytes, &opts).input.form).unwrap();
            let ours = match Form::detect(bytes) {
                Some(Form::Json) => "json",
                Some(Form::Cose) => "cose",
                None => "unknown",
            };
            assert_eq!(verifier_form, ours, "{bytes:?}");
        }
    }

    #[test]
    fn inspections_of_mutated_records_never_panic_and_are_terminal_safe() {
        use crate::mutate::{mutate, terminal_safe, Lcg};
        let json = crate::render::tests::vector_json();
        let cose = Record::from_json(std::str::from_utf8(&json).unwrap()).unwrap().to_cose().unwrap();
        let mut rng = Lcg::new(0x5EED_5004);
        let mut inspected = 0;
        for seed in [&json, &cose] {
            let mut current = seed.clone();
            for i in 0..2000 {
                if i % 8 == 0 {
                    current = seed.clone();
                }
                current = mutate(&mut rng, &current);
                match parse(&current) {
                    Ok((p, form)) => {
                        let out = crate::render::inspection(&p, form, "'x'", &current);
                        assert!(terminal_safe(&out), "{out}");
                        assert!(out.starts_with(crate::render::UNVERIFIED_BANNER));
                        inspected += 1;
                    }
                    Err(why) => assert!(terminal_safe(&crate::render::bounded(&why))),
                }
            }
        }
        assert!(inspected > 100, "the harness reaches the inspection rendering ({inspected} times)");
    }
}
