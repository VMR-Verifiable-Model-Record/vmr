// tests/common/generate.rs — the generator of specs/test-vectors/policy/
// (docs/dev/phase7.md P7-6, task 7.4). Included by tests/vectors.rs; written
// only by
//
//     VMR_WRITE_VECTORS=1 cargo test -p vmr-policy --test vectors -- --ignored
//
// What is declared by hand, and what is computed:
//
//   * every rule's STATUS and every case's OVERALL status are written here by
//     hand, from specs/policy-pack-format-v0.1.md §5, §6 and §8 and the case's
//     inputs. Nothing here runs vmr-policy's evaluator;
//   * every evidence hash and pack payload hash is computed here by §7 and §4
//     of that document, with this file's own table of the pointers each rule
//     type reads, its own context slot and the record format's JCS and
//     SHA-256 - not through vmr_policy::evidence or vmr_policy::signing;
//   * the policy_compliance section is built here by §8's mapping, and the
//     hand-declared overall status is checked against §8's aggregation of the
//     hand-declared rule statuses (a typo in a case fails the generator).
//
// tests/vectors.rs then holds vmr-policy to the committed file. An
// independent replay of these vectors is the reviewer's (docs/dev/phase7.md
// G7-6).
//
// Every document text in a case is in its JCS form, so a case does not
// depend on how a file was laid out or checked out (line endings included).
// The one exception is a record text whose case spells one number as JCS
// would not (`Case::spelled`), which its description says. The evidence of
// every case is computed from the record text as written, parsed back.
//
// Records with predecessors are real chains: each successor names its
// predecessor by id and by recomputed signed-payload hash (record format
// §6.5), and every record of a chain is signed with the conformance
// record's key (key A), so a verifier replays a case with its predecessors
// as they stand.

#![allow(dead_code)] // tests/vectors.rs uses part of this

use crate::common::*;
use serde_json::{json, Value};
use vmr_policy::vmr_record::canonical::jcs;
use vmr_policy::vmr_record::hash::{format_hash, sha256};
use vmr_policy::vmr_record::record::{Record, SignatureSection};

/// Every generated file: (path relative to specs/test-vectors/, contents).
pub fn generate() -> Vec<(String, String)> {
    let cases: Vec<Value> = cases().iter().map(case_json).collect();
    let doc = json!({
        "vector_version": "0.1",
        "description": "VMR policy-pack evaluation vectors v0.1 (policy-pack format v0.1). Each case gives a pack, a record, an evaluation time and, where a rule reads it, a verification context, and the evaluation a conforming evaluator must produce.",
        "cases": cases,
    });
    vec![
        ("policy/cases.json".to_string(), format!("{}\n", serde_json::to_string_pretty(&doc).unwrap())),
        ("policy/pack-loader.json".to_string(), format!("{}\n", serde_json::to_string_pretty(&pack_loader_file()).unwrap())),
    ]
}

/// The label whose SHA-256 is the secret scalar of the key the signed vector
/// pack is signed with: derived, test-only, worthless outside tests.
pub const PACK_KEY_LABEL: &[u8] = b"khalm v0.1 policy-vector pack authority key (test-only)";

/// The label whose SHA-256 is the secret scalar of the conformance record's
/// signing key (record format §9): key A of the verification vectors. Every
/// record of a lineage here is signed with it.
pub const RECORD_KEY_LABEL: &[u8] = b"khalm v0.1 test-vector signing key";

// ---------------------------------------------------------------------------
//  The pack-loader vectors: specs/test-vectors/policy/pack-loader.json (the
//  format document's §3 and §4; docs/TASKS.md 6.16, docs/dev/task-6.16.md
//  A16-20, A16-21, A16-23)
//
//  Each case is a pack text and what a loader does with it: loads it, with its
//  payload hash (§4, computed here with the format crate's JCS and SHA-256,
//  not through vmr_policy), or refuses it with the identifier of §3 written
//  here by hand. Nothing here runs the loader.
//
//  Every refused text breaks exactly one rule of §3, except those §3's two
//  fixed orders decide: the texts nested 128 levels deep, which can hold that
//  depth only in a member the format lacks and §3 refuses for their depth
//  first (A16-21, QA16-02), and one of them over the size bound, which §3
//  refuses for its size before that. New cases go at the end of
//  `loader_cases`, after its section of one loadable pack per rule type,
//  which comes from `loadable_rules`. The seventh rule type,
//  documentation_declared (docs/TASKS.md 10.11a), reached these vectors after
//  cases had been appended to that section, so its loadable pack is at the
//  end with its other cases, and no earlier case moved.
//
//  A pack whose bytes are not UTF-8, or start with a byte order mark, is
//  written as `hex`, so no vector text holds such bytes raw.
// ---------------------------------------------------------------------------

/// The format document's §3 refusals, by hand: (number, identifier).
const REFUSALS: [(u8, &str); 12] = [
    (1, "policy_pack.size"),
    (2, "policy_pack.structure"),
    (3, "policy_pack.duplicate_member"),
    (4, "policy_pack.integer_spelling"),
    (5, "policy_pack.integer_range"),
    (6, "policy_pack.version"),
    (7, "policy_pack.value"),
    (8, "policy_pack.jurisdiction"),
    (9, "policy_pack.empty_rules"),
    (10, "policy_pack.duplicate_rule_id"),
    (11, "policy_pack.no_requirement"),
    (12, "policy_pack.nesting"),
];

/// The largest pack text the reference loader reads (§2): 1 MiB.
const LOADER_BOUND: usize = 1_048_576;

/// The placeholder a case's text replaces with a literal JCS would not write.
const LITERAL: &str = "\"__LITERAL__\"";

/// A rule that loads of each of the six types the pack-loader vectors began
/// with, in the schema's order. The seventh's is appended at the end of
/// `loader_cases`.
fn loadable_rules() -> Vec<(&'static str, Value)> {
    vec![
        ("data_residency", json!({"allowed_jurisdictions": ["PH", "SG"]})),
        ("source_screening", json!({"restricted_list": ["web_crawl"]})),
        ("export_control", json!({"require_air_gapped": true})),
        ("audit_integrity", json!({"minimum_chain_length": 1, "require_tamper_evident": true})),
        ("execution_integrity", json!({"require_environment_pinned": true})),
        ("attestation_level", json!({"minimum_level": "software"})),
    ]
}

/// What a loader does with a case's text, by hand.
enum Loading {
    Loads,
    Refuses(&'static str),
}

struct LoaderCase {
    id: String,
    description: String,
    text: String,
    /// The pack's bytes, when they are not a text a vector may hold raw (not
    /// UTF-8, or starting with a byte order mark): written as `hex`, and
    /// `text` is unused.
    bytes: Option<Vec<u8>>,
    append_spaces: usize,
    loading: Loading,
}

fn loads(id: impl Into<String>, description: impl Into<String>, text: String) -> LoaderCase {
    LoaderCase { id: id.into(), description: description.into(), text, bytes: None, append_spaces: 0, loading: Loading::Loads }
}

fn refuses(id: &str, description: &str, text: String, identifier: &'static str) -> LoaderCase {
    assert!(REFUSALS.iter().any(|(_, known)| *known == identifier), "{identifier} is not a refusal of §3");
    LoaderCase {
        id: id.to_string(),
        description: description.to_string(),
        text,
        bytes: None,
        append_spaces: 0,
        loading: Loading::Refuses(identifier),
    }
}

/// [`refuses`] for a pack given as bytes, written as `hex`.
fn refuses_bytes(id: &str, description: &str, bytes: Vec<u8>, identifier: &'static str) -> LoaderCase {
    LoaderCase { bytes: Some(bytes), ..refuses(id, description, String::new(), identifier) }
}

impl LoaderCase {
    /// Followed by spaces, to `total` bytes in all.
    fn padded_to(mut self, total: usize) -> Self {
        self.append_spaces = total - self.text.len();
        self
    }
}

/// A pack of the loader vectors around `rules`.
fn loader_pack(rules: Vec<Value>) -> Value {
    json!({
        "version": "0.1",
        "pack_id": "policy-loader-vector",
        "pack_version": "1.0.0",
        "jurisdiction": "test",
        "description": "A pack of a KHALM pack-loader vector.",
        "disclaimer": "A test vector, not legal advice.",
        "authority": {"authority_id": "khalm-policy-vectors", "authority_name": "KHALM policy vectors"},
        "rules": rules,
    })
}

/// `document` in JCS form, its one [`LITERAL`] placeholder written as
/// `literal`: a spelling JCS would not write.
fn with_literal(document: &Value, literal: &str) -> String {
    let text = jcs(document);
    assert_eq!(text.matches(LITERAL).count(), 1, "one placeholder in {text}");
    text.replacen(LITERAL, literal, 1)
}

fn loader_cases() -> Vec<LoaderCase> {
    let rule_of = |rule_type: &str, parameters: Value| {
        rule(rule_type, &format!("vector-{}", rule_type.replace('_', "-")), "mandatory", parameters)
    };
    let one = |rule_type: &str, parameters: Value| loader_pack(vec![rule_of(rule_type, parameters)]);
    let attest = || one("attestation_level", json!({"minimum_level": "software"}));
    let audit = |chain: Value| one("audit_integrity", json!({"minimum_chain_length": chain, "require_tamper_evident": true}));
    let edited = |mut document: Value, edit: &dyn Fn(&mut Value)| {
        edit(&mut document);
        document
    };
    let base = jcs(&attest());
    let backslash = '\u{5c}';
    // The pack object is level 1: `arrays` arrays in a member reach arrays + 1.
    let nested = |arrays: usize| {
        with_literal(
            &edited(attest(), &|d| d["surprise"] = json!("__LITERAL__")),
            &format!("{}{}", "[".repeat(arrays), "]".repeat(arrays)),
        )
    };
    let chain_length = |literal: &str| with_literal(&audit(json!("__LITERAL__")), literal);
    let signed_edited = |edit: &dyn Fn(&mut Value)| {
        let mut document: Value = serde_json::from_str(&signed(&base)).unwrap();
        edit(&mut document);
        jcs(&document)
    };

    let mut all = vec![
        // Packs that load.
        loads("ok-signed", "ok-attestation-level's pack with an authority signature: a loader does not check a signature (§4).", signed(&base)),
        loads("ok-pretty-printed", "ok-attestation-level's pack, pretty-printed: the same payload hash as its JCS form (§4).", serde_json::to_string_pretty(&attest()).unwrap()),
        loads("ok-chain-length-2-53-minus-1", "minimum_chain_length 9007199254740991 (2^53 - 1), the largest allowed (§2).", chain_length("9007199254740991")),
        loads("ok-size-at-the-bound", "ok-attestation-level's pack followed by spaces to exactly 1 048 576 bytes, the reference loader's bound.", base.clone())
            .padded_to(LOADER_BOUND),
        // 1
        refuses("error-size", "ok-attestation-level's pack followed by spaces to 1 048 577 bytes.", base.clone(), "policy_pack.size")
            .padded_to(LOADER_BOUND + 1),
        // 2
        refuses("error-structure-not-json", "Not JSON: an object that is never closed.", "{".to_string(), "policy_pack.structure"),
        refuses("error-structure-data-after-the-value", "ok-attestation-level's pack followed by a second value.", format!("{base} []"), "policy_pack.structure"),
        refuses("error-structure-unknown-member", "A member the format does not define.",
            jcs(&edited(attest(), &|d| d["surprise"] = json!(true))), "policy_pack.structure"),
        refuses("error-structure-unknown-member-in-a-rule", "A rule member the format does not define.",
            jcs(&edited(attest(), &|d| d["rules"][0]["surprise"] = json!(true))), "policy_pack.structure"),
        refuses("error-structure-missing-member", "No disclaimer.",
            jcs(&edited(attest(), &|d| drop(d.as_object_mut().unwrap().remove("disclaimer")))), "policy_pack.structure"),
        refuses("error-structure-null-member", "signature: null (an optional member is omitted, never null).",
            jcs(&edited(attest(), &|d| d["signature"] = Value::Null)), "policy_pack.structure"),
        refuses("error-structure-wrong-type", "require_tamper_evident written as the string \"true\".",
            jcs(&edited(audit(json!(1)), &|d| d["rules"][0]["require_tamper_evident"] = json!("true"))), "policy_pack.structure"),
        refuses("error-structure-unknown-rule-type", "A rule of type thermal_limits, which is not one of the six.",
            jcs(&edited(attest(), &|d| d["rules"][0]["type"] = json!("thermal_limits"))), "policy_pack.structure"),
        refuses("error-structure-parameter-of-another-type", "require_tee, an execution_integrity parameter, on an attestation_level rule.",
            jcs(&edited(attest(), &|d| d["rules"][0]["require_tee"] = json!(true))), "policy_pack.structure"),
        refuses("error-structure-chain-length-string", "minimum_chain_length written as the string \"5\": the wrong JSON type, not an integer's spelling.",
            jcs(&audit(json!("5"))), "policy_pack.structure"),
        refuses("error-structure-lone-surrogate", "A description holding the escape \\ud800, which denotes no Unicode scalar value.",
            with_literal(&edited(attest(), &|d| d["description"] = json!("__LITERAL__")), &format!("\"An unpaired surrogate: {backslash}ud800.\"")),
            "policy_pack.structure"),
        refuses("error-structure-nesting-127-levels", "A member the format lacks holding 126 nested arrays: 127 levels, within the bound, so the text is read and refused for its member.",
            nested(126), "policy_pack.structure"),
        // 3
        refuses("error-duplicate-member", "version written twice, with one value.",
            base.replacen("\"version\":\"0.1\"", "\"version\":\"0.1\",\"version\":\"0.1\"", 1), "policy_pack.duplicate_member"),
        refuses("error-duplicate-member-in-a-rule", "rule_id written twice in the rule, with one value.",
            base.replacen("\"rule_id\":\"vector-attestation-level\"", "\"rule_id\":\"vector-attestation-level\",\"rule_id\":\"vector-attestation-level\"", 1),
            "policy_pack.duplicate_member"),
        refuses("error-duplicate-member-escaped", "pack_id written twice, once as pack_\\u0069d: one name once its escape is decoded.",
            base.replacen("\"pack_id\":", &format!("\"pack_{backslash}u0069d\":\"policy-loader-vector\",\"pack_id\":"), 1),
            "policy_pack.duplicate_member"),
        // 4
        refuses("error-integer-spelling-fraction", "minimum_chain_length written 1.0.", chain_length("1.0"), "policy_pack.integer_spelling"),
        refuses("error-integer-spelling-exponent", "minimum_chain_length written 1e0.", chain_length("1e0"), "policy_pack.integer_spelling"),
        refuses("error-integer-spelling-negative-zero", "minimum_chain_length written -0.", chain_length("-0"), "policy_pack.integer_spelling"),
        refuses("error-integer-spelling-negative", "minimum_chain_length -1.", chain_length("-1"), "policy_pack.integer_spelling"),
        // 5
        refuses("error-integer-range-2-53", "minimum_chain_length 9007199254740992 (2^53).", chain_length("9007199254740992"), "policy_pack.integer_range"),
        refuses("error-integer-range-2-64", "minimum_chain_length 18446744073709551616 (2^64), written as a plain integer.",
            chain_length("18446744073709551616"), "policy_pack.integer_range"),
        // 6
        refuses("error-version", "version 0.2.", jcs(&edited(attest(), &|d| d["version"] = json!("0.2"))), "policy_pack.version"),
        // 7
        refuses("error-value-pack-version", "pack_version 1.0, which is not N.N.N.",
            jcs(&edited(attest(), &|d| d["pack_version"] = json!("1.0"))), "policy_pack.value"),
        refuses("error-value-empty-string", "An empty description.",
            jcs(&edited(attest(), &|d| d["description"] = json!(""))), "policy_pack.value"),
        refuses("error-value-severity", "severity critical, outside its enum.",
            jcs(&edited(attest(), &|d| d["rules"][0]["severity"] = json!("critical"))), "policy_pack.value"),
        refuses("error-value-minimum-level", "minimum_level quantum, outside its enum.",
            jcs(&edited(attest(), &|d| d["rules"][0]["minimum_level"] = json!("quantum"))), "policy_pack.value"),
        refuses("error-value-empty-list", "A source_screening rule with an empty restricted_list.",
            jcs(&one("source_screening", json!({"restricted_list": []}))), "policy_pack.value"),
        refuses("error-value-signature-algorithm", "ok-signed's signature section with algorithm ES384.",
            signed_edited(&|d| d["signature"]["algorithm"] = json!("ES384")), "policy_pack.value"),
        refuses("error-value-signature-encoding", "ok-signed's signature section with a signature too short to be 64 bytes.",
            signed_edited(&|d| d["signature"]["signature"] = json!("base64url:AAAA")), "policy_pack.value"),
        // 8
        refuses("error-jurisdiction-lower-case", "allowed_jurisdictions [\"ph\"].",
            jcs(&one("data_residency", json!({"allowed_jurisdictions": ["ph"]}))), "policy_pack.jurisdiction"),
        refuses("error-jurisdiction-three-letters", "allowed_jurisdictions [\"PH\", \"PHL\"].",
            jcs(&one("data_residency", json!({"allowed_jurisdictions": ["PH", "PHL"]}))), "policy_pack.jurisdiction"),
        // 9
        refuses("error-empty-rules", "rules [].", jcs(&loader_pack(vec![])), "policy_pack.empty_rules"),
        // 10
        refuses("error-duplicate-rule-id", "Two attestation_level rules with one rule_id.",
            jcs(&loader_pack(vec![
                rule_of("attestation_level", json!({"minimum_level": "software"})),
                rule_of("attestation_level", json!({"minimum_level": "hardware"})),
            ])),
            "policy_pack.duplicate_rule_id"),
        // 11
        refuses("error-no-requirement-export-control", "An export_control rule that requires neither an air gap nor denied egress.",
            jcs(&one("export_control", json!({}))), "policy_pack.no_requirement"),
        refuses("error-no-requirement-verified-lineage-alone", "An audit_integrity rule whose only setting is require_verified_lineage, which never fails.",
            jcs(&one("audit_integrity", json!({"require_verified_lineage": true}))), "policy_pack.no_requirement"),
        refuses("error-no-requirement-minimum-level-self", "minimum_level self, which every record that declares a level meets.",
            jcs(&one("attestation_level", json!({"minimum_level": "self"}))), "policy_pack.no_requirement"),
        // 12
        refuses("error-nesting-128-levels", "A member the format lacks holding 127 nested arrays: 128 levels. Refused for its depth, which §3 decides before any member; such a text also breaks refusal 2, as every text nested that deep must.",
            nested(127), "policy_pack.nesting"),
    ];
    // One loadable pack per rule type: the last section (see above).
    for (rule_type, parameters) in loadable_rules() {
        all.push(loads(
            format!("ok-{}", rule_type.replace('_', "-")),
            format!("One {rule_type} rule."),
            jcs(&one(rule_type, parameters)),
        ));
    }
    // Appended after that section, as every new case is (A16-23): the task
    // 6.16 QA's findings. §3 decides refusal 1 first, then refusal 12 on the
    // bytes, whatever else they break (QA16-02); a chain length no double
    // holds is refused for how it is written (QA16-03); a lone surrogate
    // escape is refusal 2 wherever it is (QA16-04).
    let deep = nested(127);
    let bom = [&[0xef, 0xbb, 0xbf][..], deep.as_bytes()].concat();
    let mut not_utf8 = deep.clone().into_bytes();
    not_utf8[deep.find("\"jurisdiction\":\"test\"").expect("a jurisdiction member") + "\"jurisdiction\":\"t".len()] = 0xff;
    let four_hundred_digits = format!("1{}", "0".repeat(399));
    all.extend([
        refuses_bytes("error-nesting-128-levels-after-a-byte-order-mark", "The bytes EF BB BF, a UTF-8 byte order mark, then error-nesting-128-levels's text; given as hex. §3 counts the depth over the bytes before anything else, so the pack is refused for its depth, not for the byte order mark.",
            bom, "policy_pack.nesting"),
        refuses_bytes("error-nesting-128-levels-after-a-byte-that-is-not-utf-8", "error-nesting-128-levels's text with the e of the jurisdiction test replaced by the byte FF, which is not UTF-8, before the nested arrays open; given as hex. Refused for its depth (§3).",
            not_utf8, "policy_pack.nesting"),
        refuses("error-nesting-128-levels-after-a-syntax-error", "error-nesting-128-levels's text with the jurisdiction written tru, a syntax error, before the nested arrays open. Refused for its depth, which §3 counts over the bytes whatever else they break.",
            deep.replacen("\"jurisdiction\":\"test\"", "\"jurisdiction\":tru", 1), "policy_pack.nesting"),
        refuses("error-size-and-nesting-128-levels", "error-nesting-128-levels's text followed by spaces to 1 048 577 bytes: refused for its size, which §3 decides first.",
            deep.clone(), "policy_pack.size")
            .padded_to(LOADER_BOUND + 1),
        loads("ok-brackets-inside-a-string", "ok-attestation-level's pack whose description is a quotation mark followed by 200 [. Inside a string no bracket counts toward refusal 12, and the escaped quotation mark does not close the string (§3), so the pack loads.",
            jcs(&edited(attest(), &|d| d["description"] = json!(format!("\"{}", "[".repeat(200)))))),
        refuses("error-integer-spelling-beyond-a-double", "minimum_chain_length written 1e400, which no double holds: refused for how it is written (§3 refusal 4).",
            chain_length("1e400"), "policy_pack.integer_spelling"),
        refuses("error-integer-spelling-negative-beyond-a-double", "minimum_chain_length written -1e400.",
            chain_length("-1e400"), "policy_pack.integer_spelling"),
        refuses("error-integer-range-beyond-a-double", "minimum_chain_length written as a plain integer of 400 digits, a 1 and 399 zeros, which no double holds: refused as above 2^53 - 1 (§3 refusal 5).",
            chain_length(four_hundred_digits.as_str()), "policy_pack.integer_range"),
        refuses("error-structure-lone-low-surrogate-in-a-rule", "A rule's reference holding the escape \\udc00, a low surrogate with no high surrogate before it, which denotes no Unicode scalar value: refusal 2, as for error-structure-lone-surrogate's description (§3).",
            with_literal(&edited(attest(), &|d| d["rules"][0]["reference"] = json!("__LITERAL__")), &format!("\"A lone low surrogate: {backslash}udc00.\"")),
            "policy_pack.structure"),
    ]);
    // Appended after every case above: the seventh rule type,
    // documentation_declared (§6.7; docs/TASKS.md 10.11a), which reached these
    // vectors after the nine cases above. A row of `loadable_rules` would put
    // its loadable pack before them and move them, so it comes here, with the
    // refusals of its one parameter: `document` missing (§3 refusal 2) and
    // outside its enum (§3 refusal 7).
    let documentation = |document: &str| one("documentation_declared", json!({"document": document}));
    all.extend([
        loads("ok-documentation-declared", "One documentation_declared rule.", jcs(&documentation("data_governance"))),
        refuses("error-structure-missing-document", "A documentation_declared rule without document, its one required parameter.",
            jcs(&one("documentation_declared", json!({}))), "policy_pack.structure"),
        refuses("error-value-document", "document risk_management, outside its enum (data_governance, human_oversight).",
            jcs(&documentation("risk_management")), "policy_pack.value"),
    ]);
    // Appended after every case above (QA QT-01; §3 refusal 2, a member of the
    // wrong JSON type at any level): an object written as the array of its
    // values, in its members' declaration order, the order serde's derive
    // reads a struct in. One case per object kind: the pack itself, its
    // authority, its signature section, and a rule of each of the seven types,
    // written as its type followed by its members' values, the array serde's
    // derive for an internally tagged enum read as the rule.
    let as_array = |document: &Value, pointer: &str, fields: &[&str]| {
        let mut d = document.clone();
        let object = d.pointer_mut(pointer).expect("the object");
        assert_eq!(object.as_object().expect("an object").len(), fields.len(), "{pointer}: every member, in declaration order");
        let values: Vec<Value> = fields.iter().map(|f| object[*f].clone()).collect();
        *object = Value::Array(values);
        d
    };
    let signed_document: Value = serde_json::from_str(&signed(&base)).unwrap();
    all.extend([
        refuses("error-structure-pack-as-array", "ok-attestation-level's pack written as the array of its members' values: [version, pack_id, pack_version, jurisdiction, description, disclaimer, authority, rules].",
            jcs(&as_array(&attest(), "", &["version", "pack_id", "pack_version", "jurisdiction", "description", "disclaimer", "authority", "rules"])),
            "policy_pack.structure"),
        refuses("error-structure-authority-as-array", "ok-attestation-level's pack with its authority written as [authority_id, authority_name].",
            jcs(&as_array(&attest(), "/authority", &["authority_id", "authority_name"])), "policy_pack.structure"),
        refuses("error-structure-signature-as-array", "ok-signed's pack with its signature section written as [algorithm, signature, signed_payload_hash, signing_key_id].",
            jcs(&as_array(&signed_document, "/signature", &["algorithm", "signature", "signed_payload_hash", "signing_key_id"])), "policy_pack.structure"),
    ]);
    let every_member: [(&str, &[&str], Value); 7] = [
        ("data_residency", &["allowed_jurisdictions"], json!({"allowed_jurisdictions": ["PH", "SG"]})),
        ("source_screening", &["restricted_list"], json!({"restricted_list": ["web_crawl"]})),
        ("export_control", &["require_air_gapped", "require_egress_denied"], json!({"require_air_gapped": true, "require_egress_denied": false})),
        ("audit_integrity", &["minimum_chain_length", "require_tamper_evident", "require_input_committed", "require_ordered_record", "require_verified_lineage"],
            json!({"minimum_chain_length": 1, "require_tamper_evident": true, "require_input_committed": false, "require_ordered_record": false, "require_verified_lineage": false})),
        ("execution_integrity", &["require_learned_state_components", "require_environment_pinned", "require_tee", "require_state_kept"],
            json!({"require_learned_state_components": false, "require_environment_pinned": true, "require_tee": false, "require_state_kept": false})),
        ("attestation_level", &["minimum_level"], json!({"minimum_level": "software"})),
        ("documentation_declared", &["document"], json!({"document": "data_governance"})),
    ];
    for (rule_type, members, parameters) in every_member {
        let document = one(rule_type, parameters);
        let rule = &document["rules"][0];
        assert_eq!(rule.as_object().unwrap().len(), 5 + members.len(), "{rule_type}: every member written");
        let values: Vec<Value> =
            ["type", "rule_id", "description", "severity", "reference"].iter().chain(members).map(|m| rule[*m].clone()).collect();
        all.push(refuses(
            &format!("error-structure-{}-rule-as-array", rule_type.replace('_', "-")),
            &format!("A pack whose one {rule_type} rule, holding every member of its type, is written as its type followed by its members' values in declaration order."),
            jcs(&edited(document.clone(), &|d| d["rules"][0] = Value::Array(values.clone()))),
            "policy_pack.structure",
        ));
    }
    // Appended after every case above (QA QT-01 QJ-02; §3 refusal 2, a
    // missing member): the three rule types whose one required parameter no
    // earlier case leaves out (error-structure-missing-document is the
    // fourth), each without it. A loader that defaulted the parameter would
    // refuse the rule for its value (refusal 7), or load it.
    all.extend([
        refuses("error-structure-missing-allowed-jurisdictions", "A data_residency rule without allowed_jurisdictions, its one required parameter.",
            jcs(&one("data_residency", json!({}))), "policy_pack.structure"),
        refuses("error-structure-missing-restricted-list", "A source_screening rule without restricted_list, its one required parameter.",
            jcs(&one("source_screening", json!({}))), "policy_pack.structure"),
        refuses("error-structure-missing-minimum-level", "An attestation_level rule without minimum_level, its one required parameter.",
            jcs(&one("attestation_level", json!({}))), "policy_pack.structure"),
    ]);
    all
}

fn loader_case_json(c: &LoaderCase) -> Value {
    let mut pack = match &c.bytes {
        None => json!({"text": c.text}),
        Some(bytes) => json!({"hex": bytes.iter().map(|b| format!("{b:02x}")).collect::<String>()}),
    };
    if c.append_spaces > 0 {
        pack["append_spaces"] = json!(c.append_spaces);
    }
    let expected = match c.loading {
        Loading::Loads => json!({
            "result": "ok",
            "pack_payload_hash": payload_hash(&serde_json::from_str::<Value>(&c.text).expect("a pack that loads is JSON")),
        }),
        Loading::Refuses(identifier) => json!({"result": "error", "refusal": identifier}),
    };
    json!({"id": c.id, "description": c.description, "pack": pack, "expected": expected})
}

/// The whole of pack-loader.json.
fn pack_loader_file() -> Value {
    let cases = loader_cases();
    let mut ids = std::collections::BTreeSet::new();
    for c in &cases {
        assert!(ids.insert(c.id.clone()), "duplicate case id {}", c.id);
    }
    json!({
        "vector_version": "0.1",
        "description": "VMR policy-pack loader vectors v0.1 (policy-pack format v0.1, §3, §4, §9). Each case is a pack, given as text or, where its bytes are not UTF-8 or start with a byte order mark, as their lower-case hex, then append_spaces ASCII spaces if present. A conforming loader loads each ok pack, whose payload hash is expected.pack_payload_hash, and refuses each error pack; a loader that reports refusal identifiers reports expected.refusal, one of the refusals listed here. Generated by the vmr-policy crate's vector generator (VMR_WRITE_VECTORS=1 cargo test -p vmr-policy --test vectors -- --ignored) - never hand-edited.",
        "refusals": REFUSALS.iter().map(|(number, id)| json!({"number": number, "id": id})).collect::<Vec<_>>(),
        "cases": cases.iter().map(loader_case_json).collect::<Vec<_>>(),
    })
}

// ---------------------------------------------------------------------------
//  §4, §5, §6 and §7 of the format document, as this generator reads them
// ---------------------------------------------------------------------------

const DATA_RESIDENCY: &str = "/learning_provenance/training_input_provenance/data_residency";
const COUNTRIES: &str = "/learning_provenance/training_input_provenance/data_residency_countries";
const DISCLOSURE: &str = "/learning_provenance/training_input_disclosure";
const SOURCE_TYPE: &str = "/learning_provenance/training_input_provenance/source_type";
const BOUNDARY: &str = "/deployment_context/inference_boundary";
const BOUNDARY_TYPE: &str = "/deployment_context/inference_boundary/type";
const EGRESS_ALLOWED: &str = "/deployment_context/inference_boundary/egress_allowed";
const DESTINATIONS: &str = "/deployment_context/inference_boundary/allowed_egress_destinations";
const CHAIN_LENGTH: &str = "/lineage/lineage_chain_length";
const PREVIOUS_HASH: &str = "/lineage/previous_record_hash";
const MERKLE_ROOT: &str = "/learning_provenance/training_input_merkle_root";
const INPUT_COUNT: &str = "/learning_provenance/training_input_count";
const STARTED: &str = "/learning_provenance/training_started_at";
const ENDED: &str = "/learning_provenance/training_ended_at";
const COLLECTION_START: &str = "/learning_provenance/training_input_provenance/collection_period/start";
const COLLECTION_END: &str = "/learning_provenance/training_input_provenance/collection_period/end";
const ISSUED_AT: &str = "/issued_at";
const STATE_HASH: &str = "/model_identity/learned_state_hash";
const MODEL_HASH: &str = "/model_identity/model_hash";
const COMPONENTS: &str = "/model_identity/learned_state_components";
const TRAINING_SOFTWARE: &str = "/learning_provenance/training_environment/training_software";
const SOFTWARE_HASH: &str = "/learning_provenance/training_environment/software_hash";
const TEE: &str = "/learning_provenance/training_environment/tee_measurement";
const LINEAGE_TYPE: &str = "/lineage/lineage_type";
const ATTESTATION: &str = "/issuer/attestation_level";
const DATA_GOVERNANCE: &str = "/data_governance";
const HUMAN_OVERSIGHT: &str = "/human_oversight";

/// The reads of a rule type, in hash order (§6).
fn reads(rule_type: &str) -> Vec<&'static str> {
    match rule_type {
        "documentation_declared" => vec![DATA_GOVERNANCE, HUMAN_OVERSIGHT],
        "data_residency" => vec![DATA_RESIDENCY, COUNTRIES],
        "source_screening" => vec![SOURCE_TYPE, DATA_RESIDENCY, COUNTRIES],
        "export_control" => vec![BOUNDARY_TYPE, EGRESS_ALLOWED, DESTINATIONS],
        "audit_integrity" => vec![
            CHAIN_LENGTH, PREVIOUS_HASH, MERKLE_ROOT, INPUT_COUNT, STARTED, ENDED, COLLECTION_START, COLLECTION_END, ISSUED_AT,
            DISCLOSURE,
        ],
        "execution_integrity" => vec![STATE_HASH, COMPONENTS, TRAINING_SOFTWARE, SOFTWARE_HASH, TEE, LINEAGE_TYPE, MODEL_HASH],
        "attestation_level" => vec![ATTESTATION],
        other => panic!("no rule type {other}"),
    }
}

/// A verification context (§5): the lineage outcome, and the verified
/// predecessors, immediate predecessor first.
#[derive(Clone)]
struct Context {
    outcome: &'static str,
    predecessors: Vec<Value>,
}

/// §5: a count is a JSON integer from 0 to 2^53 - 1.
fn count(value: Option<&Value>) -> Option<u64> {
    value.and_then(Value::as_u64).filter(|n| *n <= 9_007_199_254_740_991)
}

/// §5: a context applies when its outcome is not `initial` and the chain
/// length is a count of 2 or more.
fn applies<'c>(context: Option<&'c Context>, record: &Value) -> Option<&'c Context> {
    context.filter(|c| c.outcome != "initial" && count(record.pointer(CHAIN_LENGTH)).is_some_and(|n| n >= 2))
}

/// §7: the context slot of a rule type that has one.
fn slot(rule_type: &str, record: &Value, context: Option<&Context>) -> Option<Value> {
    let applied = applies(context, record);
    match rule_type {
        "audit_integrity" => Some(match applied {
            None => Value::Null,
            Some(c) => Value::Array(
                std::iter::once(json!(c.outcome)).chain(c.predecessors.iter().map(|p| json!(signed_payload_hash(p)))).collect(),
            ),
        }),
        "execution_integrity" => Some(
            applied.and_then(|c| c.predecessors.first()).and_then(|p| p.pointer(MODEL_HASH)).cloned().unwrap_or(Value::Null),
        ),
        _ => None,
    }
}

/// §7: the value at one read, or the array of the values of several followed
/// by the context slot, `null` for an absent pointer; `sha256:` + the hex of
/// the SHA-256 of its JCS form.
fn evidence_hash(record: &Value, rule_type: &str, context: Option<&Context>) -> String {
    let at = |p: &&str| record.pointer(p).cloned().unwrap_or(Value::Null);
    let r = reads(rule_type);
    let value = match (r.as_slice(), slot(rule_type, record, context)) {
        ([only], None) => at(only),
        (many, slot) => Value::Array(many.iter().map(at).chain(slot).collect()),
    };
    format_hash(&sha256(jcs(&value).as_bytes()))
}

/// §4: the JCS form of the document without its top-level `signature`.
fn payload_hash(pack: &Value) -> String {
    let mut document = pack.clone();
    document.as_object_mut().unwrap().remove("signature");
    format_hash(&sha256(jcs(&document).as_bytes()))
}

/// Record format §3: a record's signed-payload hash, recomputed from the
/// record without its `signature` member, never read from it.
fn signed_payload_hash(record: &Value) -> String {
    payload_hash(record)
}

// ---------------------------------------------------------------------------
//  Inputs
// ---------------------------------------------------------------------------

/// The conformance vector's record (specs/test-vectors/record/): an
/// initial record, with no previous_record_hash, signed with key A.
fn conformance() -> Value {
    conformance_record()
}

/// The committed Gate 5 artifact's record: the demo record, emitted by the
/// engine build from docs/demo/ (vmr/crates/vmr-cli/tests/data/gate5/).
fn demo() -> Value {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../vmr-cli/tests/data/gate5/model.vmr");
    let bytes = std::fs::read(&path).unwrap_or_else(|e| panic!("{}: {e}", path.display()));
    serde_json::to_value(Record::from_cose(&bytes).expect("the Gate 5 artifact is a record")).unwrap()
}

/// The general description's conformance record
/// (specs/test-vectors/record/example-general-v0.1.json; task 10.11b): a
/// model of four synthetic files, not-held training records, signed with
/// key A.
fn general() -> Value {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../../specs/test-vectors/record/example-general-v0.1.json");
    let text = std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("{}: {e}", path.display()));
    let file: Value = serde_json::from_str(&text).unwrap();
    file["record"].clone()
}

/// The conformance record described GENERALLY: the same record, its
/// `model_format` a value that selects no registered profile and its
/// `learned_state_hash` recomputed as the named-set digest of its three
/// components (record format §7.2, §7.3), re-signed with key A. Every other
/// byte is the conformance record's (QA QR-09 / D-1.5, the owner,
/// 2026-09-16).
///
/// Why it is built this way, and not from another model: the profile governs
/// `model_format` and the meaning of the state hashes, and nothing else
/// (record format §7.4). A rule of the general format therefore reads exactly
/// the same values in this record as in the conformance record, so a case
/// copied onto it keeps its expected statuses BY CONSTRUCTION, not because
/// an evaluator was run to find out. `model_hash` is left as it is: under the
/// general description it covers files a record need not carry, so no
/// verifier recomputes it (§7.3).
fn general_twin() -> Value {
    use vmr_policy::vmr_record::named_set::named_set_digest;
    let mut record = conformance();
    let components = record["model_identity"]["learned_state_components"].as_array().expect("components").clone();
    let parts: Vec<(String, [u8; 32])> = components
        .iter()
        .map(|c| {
            let name = c["name"].as_str().expect("a component name").to_string();
            let hex = c["hash"].as_str().expect("a component hash").trim_start_matches("sha256:");
            let mut digest = [0u8; 32];
            for (i, byte) in digest.iter_mut().enumerate() {
                *byte = u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16).expect("lower-case hex");
            }
            (name, digest)
        })
        .collect();
    let borrowed: Vec<(&str, [u8; 32])> = parts.iter().map(|(n, d)| (n.as_str(), *d)).collect();
    record["model_identity"]["model_format"] = json!(GENERAL_TWIN_FORMAT);
    record["model_identity"]["learned_state_hash"] = json!(format_hash(&named_set_digest(&borrowed).expect("a named set")));
    // The one member the general description needs that the profile implies:
    // a record that commits training records names their format (record
    // format §8.2). No rule of this document reads it.
    record["learning_provenance"]["training_input_format"] = json!("khalmtrn-frame-v1");
    signed_with_key_a(record)
}

/// The `model_format` the twin carries: any value that is not a registered
/// profile selects the general description (record format §7.1).
const GENERAL_TWIN_FORMAT: &str = "tensor-files";
/// What the twin ids end with, and what `specs/conformance/build_suite.py`
/// tags `core`.
const GENERAL_TWIN_SUFFIX: &str = "-general-record";

/// Whether any record of the case names the engine profile, compared as
/// `build_suite.py` compares it: as a JSON string anywhere in the record's
/// text.
fn names_profile(c: &Case) -> bool {
    let mut texts = vec![jcs(&c.record)];
    if let Some(context) = &c.context {
        texts.extend(context.predecessors.iter().map(jcs));
    }
    texts.iter().any(|t| t.contains("snn-compact-v1"))
}

/// `record` signed as it stands with key A ([`RECORD_KEY_LABEL`]),
/// deterministically (RFC 6979, low-s). Its issuer already names key A.
fn signed_with_key_a(record: Value) -> Value {
    use vmr_policy::vmr_record::sign;
    let mut p: Record = serde_json::from_value(record).expect("a well-formed record");
    let key = sign::signing_key_from_secret(&sha256(RECORD_KEY_LABEL)).unwrap();
    let signature = sign::sign(&key, &p.signature_tbs().unwrap()).unwrap();
    p.signature.algorithm = "ES256".into();
    p.signature.signature = SignatureSection::signature_field(&signature);
    p.signature.signed_payload_hash = p.signed_payload_hash().unwrap();
    let value = serde_json::to_value(&p).unwrap();
    assert_eq!(value["signature"]["signed_payload_hash"], signed_payload_hash(&value), "record format §3, read two ways");
    value
}

/// A record with `base`'s members that follows `predecessor` in its chain
/// (record format §6.5): the id `id`, a `lineage_type` step, the
/// predecessor named by its id and its recomputed signed-payload hash, the
/// same root, one more in length; signed with key A.
fn successor_of(predecessor: &Value, base: Value, id: &str, lineage_type: &str) -> Value {
    let mut p = with(base, "/record_id", json!(id));
    p["lineage"] = json!({
        "previous_record_id": predecessor["record_id"],
        "previous_record_hash": signed_payload_hash(predecessor),
        "lineage_chain_length": predecessor["lineage"]["lineage_chain_length"].as_u64().unwrap() + 1,
        "root_record_id": predecessor["lineage"]["root_record_id"],
        "lineage_type": lineage_type,
    });
    signed_with_key_a(p)
}

/// The next record of `predecessor`'s chain, with its members.
fn successor(predecessor: &Value, id: &str, lineage_type: &str) -> Value {
    successor_of(predecessor, predecessor.clone(), id, lineage_type)
}

/// `record` as the second record of its chain, a training update.
fn second_in_chain(record: Value) -> Value {
    successor(&record, "urn:uuid:00000000-0000-4000-8000-0000000000b2", "training-update")
}

/// The conformance vector's evaluation time: the day after its issued_at.
const T_CONFORMANCE: &str = "2026-09-11T00:00:00Z";
/// The demo record's: twelve hours after its issued_at, as Gate 5 verifies.
const T_DEMO: &str = "2026-09-11T12:00:00Z";
/// A year after T_CONFORMANCE, for the time-independence pair.
const T_LATER: &str = "2027-09-11T00:00:00Z";

/// `record` with the member at `pointer` replaced by `value`.
fn with(mut record: Value, pointer: &str, value: Value) -> Value {
    *record.pointer_mut(pointer).unwrap_or_else(|| panic!("no member {pointer}")) = value;
    record
}

/// `record` with the member at `pointer` removed.
fn without(mut record: Value, pointer: &str) -> Value {
    let (parent, member) = pointer.rsplit_once('/').unwrap();
    record
        .pointer_mut(parent)
        .and_then(Value::as_object_mut)
        .and_then(|object| object.remove(member))
        .unwrap_or_else(|| panic!("no member {pointer}"));
    record
}

/// A rule of a vector pack.
fn rule(rule_type: &str, rule_id: &str, severity: &str, parameters: Value) -> Value {
    let mut r = json!({
        "type": rule_type,
        "rule_id": rule_id,
        "description": format!("A {rule_type} rule of a KHALM policy vector."),
        "severity": severity,
        "reference": "KHALM policy vectors (a test fixture, not a clause of any standard)",
    });
    for (name, value) in parameters.as_object().unwrap() {
        r[name] = value.clone();
    }
    r
}

/// A vector pack around `rules` with this `description`, as JCS text.
fn pack_described(rules: Vec<Value>, description: &str) -> String {
    jcs(&json!({
        "version": "0.1",
        "pack_id": "policy-vector-pack",
        "pack_version": "1.0.0",
        "jurisdiction": "test",
        "description": description,
        "disclaimer": "A test vector, not legal advice.",
        "authority": {"authority_id": "khalm-policy-vectors", "authority_name": "KHALM policy vectors"},
        "rules": rules,
    }))
}

/// A vector pack around `rules`, as JCS text.
fn pack(rules: Vec<Value>) -> String {
    pack_described(rules, "A pack of a KHALM policy vector.")
}

/// One mandatory rule, as a pack.
fn one(rule_type: &str, parameters: Value) -> String {
    pack(vec![rule(rule_type, &format!("vector-{}", rule_type.replace('_', "-")), "mandatory", parameters)])
}

/// A committed reference pack, as JCS text.
fn reference(pack_id: &str) -> String {
    jcs(&serde_json::from_str::<Value>(&pack_text(pack_id)).unwrap())
}

/// `pack_text` with an authority signature over its §4 payload, by the key
/// [`PACK_KEY_LABEL`] derives (ES256, RFC 6979, so it regenerates byte for
/// byte).
fn signed(pack_text: &str) -> String {
    use vmr_policy::vmr_record::{jwk, sign};
    let mut document: Value = serde_json::from_str(pack_text).unwrap();
    assert!(document.get("signature").is_none(), "an unsigned pack");
    let key = sign::signing_key_from_secret(&sha256(PACK_KEY_LABEL)).unwrap();
    let payload = jcs(&document);
    let signature = sign::sign(&key, payload.as_bytes()).unwrap();
    document["signature"] = json!({
        "algorithm": "ES256",
        "signature": format!("base64url:{}", sign::signature_to_b64url(&signature)),
        "signed_payload_hash": format_hash(&sha256(payload.as_bytes())),
        "signing_key_id": jwk::key_id(key.verifying_key()),
    });
    jcs(&document)
}

// ---------------------------------------------------------------------------
//  The cases
// ---------------------------------------------------------------------------

#[derive(Clone)]
struct Case {
    id: String,
    description: String,
    pack: String,
    record: Value,
    /// The record is a well-formed v0.1 record and, for a record with
    /// predecessors, the context is the one a verifier establishes from the
    /// case's predecessors: re-signed by a trusted key, it verifies, so a
    /// verifier with a pack replays the case exactly.
    verifiable: bool,
    t: &'static str,
    /// The verification context the evaluation is given, if any.
    context: Option<Context>,
    /// One number of the record text spelled as JCS would not: (pointer,
    /// the literal written there).
    spelling: Option<(&'static str, &'static str)>,
    /// Per rule, in the pack's order: written by hand.
    statuses: Vec<&'static str>,
    /// Written by hand; checked against §8.
    overall: &'static str,
}

fn case(id: &str, description: &str, pack: String, record: Value, statuses: &[&'static str], overall: &'static str) -> Case {
    Case {
        id: id.to_string(),
        description: description.to_string(),
        pack,
        record,
        verifiable: true,
        t: T_CONFORMANCE,
        context: None,
        spelling: None,
        statuses: statuses.to_vec(),
        overall,
    }
}

impl Case {
    /// The case is not replayable by a verifier: its record is not a
    /// well-formed v0.1 record, or its context is not one a verifier gives.
    fn unverifiable(mut self) -> Self {
        self.verifiable = false;
        self
    }

    fn at(mut self, t: &'static str) -> Self {
        self.t = t;
        self
    }

    /// Evaluated in the context `outcome` with these predecessors.
    fn in_context(mut self, outcome: &'static str, predecessors: Vec<Value>) -> Self {
        self.context = Some(Context { outcome, predecessors });
        self
    }

    /// The record text writes the number at `pointer` as `literal`.
    fn spelled(mut self, pointer: &'static str, literal: &'static str) -> Self {
        self.spelling = Some((pointer, literal));
        self
    }
}

const P: &str = "pass";
const F: &str = "fail";
const I: &str = "indeterminate";

/// Every case over one base record: `conformance` for the committed vectors,
/// `general_twin` for the general-description copies (QA QR-09 / D-1.5).
fn cases_from(b: fn() -> Value) -> Vec<Case> {
    let a_hash = |label: &str| format_hash(&sha256(label.as_bytes()));
    let another_state = a_hash("khalm policy vectors: another learned state");
    let empty_tree_root = format_hash(&vmr_policy::vmr_record::merkle::empty_root());
    // The conformance record's software_hash with its hex digits upper-cased,
    // and with every second one upper-cased.
    let software_hex = b().pointer(SOFTWARE_HASH).unwrap().as_str().unwrap().trim_start_matches("sha256:").to_string();
    let upper_software_hash = format!("sha256:{}", software_hex.to_ascii_uppercase());
    let mixed_software_hash = format!(
        "sha256:{}",
        software_hex.chars().enumerate().map(|(i, c)| if i % 2 == 0 { c.to_ascii_uppercase() } else { c }).collect::<String>()
    );
    // Text RFC 8785 writes differently from a naive serialisation (QA Q7-01):
    // non-ASCII characters, a quotation mark and a backslash.
    let (quote, backslash) = ('\u{22}', '\u{5c}');
    let non_ascii_engine = format!("khalm-tlm \u{e9}t\u{e9} \u{a7}7 \u{4e2d}\u{6587} {quote}0.1.0{quote} {backslash}build");
    // The records of real chains, each signed with key A.
    let second = second_in_chain(b());
    let third = successor(&second, "urn:uuid:00000000-0000-4000-8000-0000000000b3", "training-update");
    let deployment = successor(&b(), "urn:uuid:00000000-0000-4000-8000-0000000000d2", "deployment");
    let changed_state = with(with(b(), STATE_HASH, json!(another_state)), MODEL_HASH, json!(another_state));
    let policy_change_with_another_state =
        successor_of(&b(), changed_state.clone(), "urn:uuid:00000000-0000-4000-8000-0000000000c2", "policy-change");
    let training_update_with_another_state =
        successor_of(&b(), changed_state, "urn:uuid:00000000-0000-4000-8000-0000000000e2", "training-update");
    let lineage_rule = || one("audit_integrity", json!({"require_tamper_evident": true, "require_verified_lineage": true}));
    let state_kept_rule = || one("execution_integrity", json!({"require_state_kept": true}));

    let mut all = vec![
        // §6.1 data_residency
        case("data-residency-pass", "The declared residency PH is allowed.",
            one("data_residency", json!({"allowed_jurisdictions": ["SG", "PH"]})), b(), &[P], P),
        case("data-residency-fail", "The declared residency PH is not allowed.",
            one("data_residency", json!({"allowed_jurisdictions": ["SG"]})), b(), &[F], F),
        case("data-residency-absent", "No residency is declared: indeterminate, and the absent pointer contributes null to the evidence.",
            one("data_residency", json!({"allowed_jurisdictions": ["PH"]})), without(b(), DATA_RESIDENCY), &[I], I).unverifiable(),
        case("data-residency-null", "A member present with the value null is not declared, and it hashes as the absent member of data-residency-absent.",
            one("data_residency", json!({"allowed_jurisdictions": ["PH"]})), with(b(), DATA_RESIDENCY, Value::Null), &[I], I).unverifiable(),
        case("data-residency-empty-string", "An empty string is not a declaration.",
            one("data_residency", json!({"allowed_jurisdictions": ["PH"]})), with(b(), DATA_RESIDENCY, json!("")), &[I], I).unverifiable(),
        case("data-residency-wrong-type", "A number where a string is needed: indeterminate, never fail.",
            one("data_residency", json!({"allowed_jurisdictions": ["PH"]})), with(b(), DATA_RESIDENCY, json!(7)), &[I], I).unverifiable(),
        // §6.2 source_screening
        case("source-screening-pass", "Neither sensor_stream nor PH is restricted.",
            one("source_screening", json!({"restricted_list": ["web_crawl", "KP"]})), b(), &[P], P),
        case("source-screening-fail-source-type", "The source type is restricted.",
            one("source_screening", json!({"restricted_list": ["sensor_stream"]})), b(), &[F], F),
        case("source-screening-fail-residency", "The residency is restricted.",
            one("source_screening", json!({"restricted_list": ["PH"]})), b(), &[F], F),
        case("source-screening-source-type-absent", "No source type is declared.",
            one("source_screening", json!({"restricted_list": ["KP"]})), without(b(), SOURCE_TYPE), &[I], I).unverifiable(),
        case("source-screening-residency-absent", "A source type is declared and no residency is: step 2 is indeterminate.",
            one("source_screening", json!({"restricted_list": ["KP"]})), without(b(), DATA_RESIDENCY), &[I], I).unverifiable(),
        // §6.3 export_control
        case("export-control-pass", "An air-gapped boundary, egress denied, no destination.",
            one("export_control", json!({"require_air_gapped": true, "require_egress_denied": true})), b(), &[P], P),
        case("export-control-fail-not-air-gapped", "The boundary is on-premises, and an air-gapped one is required.",
            one("export_control", json!({"require_air_gapped": true})), with(b(), BOUNDARY_TYPE, json!("on-premises")), &[F], F),
        case("export-control-fail-egress-allowed", "Egress is allowed, and it must be denied.",
            one("export_control", json!({"require_egress_denied": true})), with(b(), EGRESS_ALLOWED, json!(true)), &[F], F),
        case("export-control-fail-exception-list", "Egress is denied with a destination still allowed: not a denial.",
            one("export_control", json!({"require_egress_denied": true})), with(b(), DESTINATIONS, json!(["egress.example"])), &[F], F),
        case("export-control-egress-absent", "egress_allowed is not declared.",
            one("export_control", json!({"require_egress_denied": true})), without(b(), EGRESS_ALLOWED), &[I], I).unverifiable(),
        case("export-control-first-requirement-decides", "The boundary type is absent and egress is allowed: the air-gap step runs first, so indeterminate, not fail.",
            one("export_control", json!({"require_air_gapped": true, "require_egress_denied": true})),
            without(with(b(), EGRESS_ALLOWED, json!(true)), BOUNDARY_TYPE), &[I], I).unverifiable(),
        case("export-control-boundary-type-wrong-type", "A boolean where the boundary type is needed.",
            one("export_control", json!({"require_air_gapped": true})), with(b(), BOUNDARY_TYPE, json!(true)), &[I], I).unverifiable(),
        case("export-control-egress-wrong-type", "The string \"false\" is not a boolean.",
            one("export_control", json!({"require_egress_denied": true})), with(b(), EGRESS_ALLOWED, json!("false")), &[I], I).unverifiable(),
        case("export-control-destinations-wrong-type", "A string where the destination array is needed.",
            one("export_control", json!({"require_egress_denied": true})), with(b(), DESTINATIONS, json!("none")), &[I], I).unverifiable(),
        case("export-control-boundary-absent", "The whole inference_boundary object is absent: each of the three reads contributes null.",
            one("export_control", json!({"require_air_gapped": true})), without(b(), BOUNDARY), &[I], I).unverifiable(),
        case("export-control-boundary-not-an-object", "inference_boundary is a string: a pointer through a member that is not an object is absent (§5), so each read contributes null, as in export-control-boundary-absent.",
            one("export_control", json!({"require_air_gapped": true})), with(b(), BOUNDARY, json!("air-gapped")), &[I], I).unverifiable(),
        // §6.4 audit_integrity: chain length and tamper-evidence
        case("audit-integrity-pass", "An initial record: a chain of one, a Merkle root that is a hash, no predecessor to link; its absent previous_record_hash contributes null, and so does the context slot.",
            one("audit_integrity", json!({"minimum_chain_length": 1, "require_tamper_evident": true})), b(), &[P], P),
        case("audit-integrity-pass-with-predecessor", "The second record of a chain, naming its predecessor by a hash, in the context a verifier gives when that predecessor is supplied: complete.",
            one("audit_integrity", json!({"minimum_chain_length": 2, "require_tamper_evident": true})), second.clone(), &[P], P)
            .in_context("complete", vec![b()]),
        case("audit-integrity-fail-short-chain", "A chain of one, and two are required.",
            one("audit_integrity", json!({"minimum_chain_length": 2})), b(), &[F], F),
        case("audit-integrity-fail-root-not-a-hash", "The Merkle root is declared and is not a hash.",
            one("audit_integrity", json!({"require_tamper_evident": true})), with(b(), MERKLE_ROOT, json!("not-a-hash")), &[F], F).unverifiable(),
        case("audit-integrity-root-absent", "No Merkle root is declared: tamper-evidence is indeterminate.",
            one("audit_integrity", json!({"require_tamper_evident": true})), without(b(), MERKLE_ROOT), &[I], I).unverifiable(),
        case("audit-integrity-fail-predecessor-hash-not-a-hash", "A chain of two whose predecessor hash is declared and is not a hash; evaluated without context.",
            one("audit_integrity", json!({"require_tamper_evident": true})),
            with(second.clone(), PREVIOUS_HASH, json!("not-a-hash")), &[F], F).unverifiable(),
        case("audit-integrity-predecessor-hash-absent", "A chain of two without a predecessor hash.",
            one("audit_integrity", json!({"require_tamper_evident": true})), with(b(), CHAIN_LENGTH, json!(2)), &[I], I).unverifiable(),
        case("audit-integrity-chain-length-absent", "No chain length is declared.",
            one("audit_integrity", json!({"require_tamper_evident": true})), without(b(), CHAIN_LENGTH), &[I], I).unverifiable(),
        case("audit-integrity-chain-length-wrong-type", "A string of digits is not a count.",
            one("audit_integrity", json!({"require_tamper_evident": true})), with(b(), CHAIN_LENGTH, json!("1")), &[I], I).unverifiable(),
        case("audit-integrity-chain-length-float-spelling", "The chain length is written 1.0 in the record text: not an integer token, so not a count (§5); JCS writes its evidence as 1.",
            one("audit_integrity", json!({"require_tamper_evident": true})), b(), &[I], I).spelled(CHAIN_LENGTH, "1.0").unverifiable(),
        case("audit-integrity-chain-length-2-53-minus-1", "A chain length of 2^53 - 1, the largest count: it meets a minimum of 2.",
            one("audit_integrity", json!({"minimum_chain_length": 2})), with(b(), CHAIN_LENGTH, json!(9_007_199_254_740_991u64)), &[P], P).unverifiable(),
        case("audit-integrity-chain-length-2-53", "A chain length of 2^53 is above 2^53 - 1, so not a count (§5): indeterminate.",
            one("audit_integrity", json!({"minimum_chain_length": 2})), with(b(), CHAIN_LENGTH, json!(9_007_199_254_740_992u64)), &[I], I).unverifiable(),
        case("audit-integrity-chain-length-2-53-plus-1", "The record text writes the chain length 9007199254740993: not a count, and JCS writes its evidence as 9007199254740992, so its evidence hash is audit-integrity-chain-length-2-53's.",
            one("audit_integrity", json!({"minimum_chain_length": 2})), b(), &[I], I).spelled(CHAIN_LENGTH, "9007199254740993").unverifiable(),
        case("audit-integrity-chain-length-1e21", "The record text writes the chain length 1e21: a number with an exponent is not a count, and JCS writes its evidence as 1e+21.",
            one("audit_integrity", json!({"minimum_chain_length": 2})), b(), &[I], I).spelled(CHAIN_LENGTH, "1e21").unverifiable(),
        case("audit-integrity-chain-length-zero", "A chain length of 0 is a count that meets a minimum of 0, and a chain of no predecessor has none to link: tamper-evidence passes. The twin of audit-integrity-chain-length-minus-zero.",
            one("audit_integrity", json!({"require_tamper_evident": true})), with(b(), CHAIN_LENGTH, json!(0)), &[P], P).unverifiable(),
        case("audit-integrity-chain-length-minus-zero", "The record text writes the chain length -0: not written as an integer, so not a count (§5), although it equals 0. JCS writes its evidence as 0, so its evidence hash is audit-integrity-chain-length-zero's.",
            one("audit_integrity", json!({"require_tamper_evident": true})), b(), &[I], I).spelled(CHAIN_LENGTH, "-0").unverifiable(),
        // §6.4 audit_integrity: require_input_committed
        case("audit-integrity-input-committed-pass", "Sixteen training input frames under a Merkle root that is not the empty tree's.",
            one("audit_integrity", json!({"require_input_committed": true})), b(), &[P], P),
        case("audit-integrity-input-committed-fail-no-input", "training_input_count is 0: the record commits to no training input.",
            one("audit_integrity", json!({"require_input_committed": true})), with(b(), INPUT_COUNT, json!(0)), &[F], F),
        case("audit-integrity-input-committed-fail-empty-tree-root", "Sixteen frames under the root of the empty tree: the commitment contradicts its count.",
            one("audit_integrity", json!({"require_input_committed": true})), with(b(), MERKLE_ROOT, json!(empty_tree_root)), &[F], F),
        case("audit-integrity-input-committed-count-wrong-type", "A training input count written as a string is not a count.",
            one("audit_integrity", json!({"require_input_committed": true})), with(b(), INPUT_COUNT, json!("16")), &[I], I).unverifiable(),
        case("audit-integrity-input-count-above-2-53", "A training input count of 2^53 is not a count (§5).",
            one("audit_integrity", json!({"require_input_committed": true})), with(b(), INPUT_COUNT, json!(9_007_199_254_740_992u64)), &[I], I).unverifiable(),
        case("audit-integrity-input-count-minus-zero", "The record text writes training_input_count -0: not a count (§5), so indeterminate, where audit-integrity-input-committed-fail-no-input, whose text writes 0, fails. JCS writes the evidence of both as 0.",
            one("audit_integrity", json!({"require_input_committed": true})), b(), &[I], I).spelled(INPUT_COUNT, "-0").unverifiable(),
        // §6.4 audit_integrity: require_ordered_record
        case("audit-integrity-ordered-record-pass", "Collection ends before training starts, training ends before issuance.",
            one("audit_integrity", json!({"require_ordered_record": true})), b(), &[P], P),
        case("audit-integrity-ordered-record-fail-training-ends-before-it-starts", "training_ended_at is before training_started_at.",
            one("audit_integrity", json!({"require_ordered_record": true})), with(b(), ENDED, json!("2026-08-31T00:00:00Z")), &[F], F),
        case("audit-integrity-ordered-record-fail-collection-ends-before-it-starts", "The collection period ends before it starts.",
            one("audit_integrity", json!({"require_ordered_record": true})), with(b(), COLLECTION_END, json!("2026-07-31T00:00:00Z")), &[F], F),
        case("audit-integrity-ordered-record-fail-training-ends-after-issuance", "Training ends after the record's issued_at.",
            one("audit_integrity", json!({"require_ordered_record": true})), with(b(), ENDED, json!("2026-09-10T12:00:00Z")), &[F], F),
        case("audit-integrity-ordered-record-not-a-timestamp", "training_started_at is 30 February: in the profile's shape, but not a calendar date, so not a timestamp.",
            one("audit_integrity", json!({"require_ordered_record": true})), with(b(), STARTED, json!("2026-02-30T00:00:00Z")), &[I], I).unverifiable(),
        // §6.4 audit_integrity: require_verified_lineage, and the context
        case("audit-integrity-verified-lineage-initial-pass", "An initial record, without context: a chain of one has no lineage to verify.",
            lineage_rule(), b(), &[P], P),
        case("audit-integrity-verified-lineage-complete-pass", "A successor whose predecessor, the initial record, is supplied: the context is complete, and the slot holds the outcome and the predecessor's signed payload hash.",
            lineage_rule(), second.clone(), &[P], P).in_context("complete", vec![b()]),
        case("audit-integrity-verified-lineage-partial", "The third record of a chain with only its immediate predecessor supplied: the context is partial, and the lineage is not shown to its origin.",
            lineage_rule(), third, &[I], I).in_context("partial", vec![second.clone()]),
        case("audit-integrity-verified-lineage-not-checked", "A successor with no predecessor supplied: the context is not_checked.",
            lineage_rule(), second.clone(), &[I], I).in_context("not_checked", vec![]),
        case("audit-integrity-verified-lineage-no-context", "A successor evaluated without any context: missing context is indeterminate, and the slot is null. A verifier always gives a context, so it does not replay this case.",
            lineage_rule(), second.clone(), &[I], I).unverifiable(),
        case("context-initial-on-an-initial-record-adds-nothing", "The context a verifier gives an initial record does not apply: the evaluation, evidence hash included, is audit-integrity-verified-lineage-initial-pass's.",
            lineage_rule(), b(), &[P], P).in_context("initial", vec![]),
        case("context-initial-on-a-successor-is-not-read", "An initial outcome on a chain of two does not apply, so the evaluation is the one without context; no verifier gives it.",
            lineage_rule(), second.clone(), &[I], I).in_context("initial", vec![b()]).unverifiable(),
        case("context-complete-on-a-chain-of-one-is-not-read", "A complete outcome on a chain of one does not apply, so the evaluation is the one without context; no verifier gives it.",
            lineage_rule(), b(), &[P], P).in_context("complete", vec![]).unverifiable(),
        // §6.5 execution_integrity: learned state
        case("execution-integrity-pass", "The learned state and its three components are pinned, and the environment is.",
            one("execution_integrity", json!({"require_learned_state_components": true, "require_environment_pinned": true})), b(), &[P], P),
        case("execution-integrity-fail-state-hash-not-a-hash", "learned_state_hash is declared and is not a hash.",
            one("execution_integrity", json!({"require_learned_state_components": true})), with(b(), STATE_HASH, json!("not-a-hash")), &[F], F).unverifiable(),
        case("execution-integrity-state-hash-absent", "No learned_state_hash is declared.",
            one("execution_integrity", json!({"require_learned_state_components": true})), without(b(), STATE_HASH), &[I], I).unverifiable(),
        case("execution-integrity-fail-zero-size", "A component declares size_bytes 0.",
            one("execution_integrity", json!({"require_learned_state_components": true})),
            with(b(), "/model_identity/learned_state_components/2/size_bytes", json!(0)), &[F], F).unverifiable(),
        case("execution-integrity-components-wrong-type", "learned_state_components is an object, not an array.",
            one("execution_integrity", json!({"require_learned_state_components": true})), with(b(), COMPONENTS, json!({})), &[I], I).unverifiable(),
        case("execution-integrity-components-empty", "learned_state_components is an empty array: nothing is pinned, and nothing is declared.",
            one("execution_integrity", json!({"require_learned_state_components": true})), with(b(), COMPONENTS, json!([])), &[I], I).unverifiable(),
        case("execution-integrity-components-member-order", "learned_state_components is an object whose member names are U+E000 and U+1F600: RFC 8785 orders them by UTF-16 code units, U+1F600 first, where code-point order puts U+E000 first.",
            one("execution_integrity", json!({"require_learned_state_components": true})),
            with(b(), COMPONENTS, json!({"\u{e000}": 1, "\u{1f600}": 2})), &[I], I).unverifiable(),
        case("execution-integrity-component-not-an-object", "The first component is a string: it has no members, so no hash.",
            one("execution_integrity", json!({"require_learned_state_components": true})),
            with(b(), "/model_identity/learned_state_components/0", json!("afferent_H")), &[I], I).unverifiable(),
        case("execution-integrity-component-without-hash", "A component with no hash: indeterminate, not fail.",
            one("execution_integrity", json!({"require_learned_state_components": true})),
            without(b(), "/model_identity/learned_state_components/0/hash"), &[I], I).unverifiable(),
        case("execution-integrity-size-absent", "A component with no size_bytes.",
            one("execution_integrity", json!({"require_learned_state_components": true})),
            without(b(), "/model_identity/learned_state_components/0/size_bytes"), &[I], I).unverifiable(),
        case("execution-integrity-size-wrong-type", "A size written as a string is not a count.",
            one("execution_integrity", json!({"require_learned_state_components": true})),
            with(b(), "/model_identity/learned_state_components/0/size_bytes", json!("8192")), &[I], I).unverifiable(),
        case("execution-integrity-size-above-2-53", "A size of 2^53 bytes is not a count (§5).",
            one("execution_integrity", json!({"require_learned_state_components": true})),
            with(b(), "/model_identity/learned_state_components/0/size_bytes", json!(9_007_199_254_740_992u64)), &[I], I).unverifiable(),
        case("execution-integrity-size-minus-zero", "The record text writes the third component's size_bytes -0: not a count (§5), so indeterminate, where execution-integrity-fail-zero-size, whose text writes 0, fails. JCS writes the evidence of both as 0.",
            one("execution_integrity", json!({"require_learned_state_components": true})), b(), &[I], I)
            .spelled("/model_identity/learned_state_components/2/size_bytes", "-0").unverifiable(),
        // §6.5 execution_integrity: the environment, and the empty string
        case("execution-integrity-training-software-non-ascii", "training_software holds non-ASCII characters, a quotation mark and a backslash; RFC 8785 writes the characters as they are, and escapes only the quotation mark and the backslash.",
            one("execution_integrity", json!({"require_environment_pinned": true})), with(b(), TRAINING_SOFTWARE, json!(non_ascii_engine)), &[P], P),
        case("execution-integrity-training-software-empty", "training_software is the empty string: a signed declaration that the record names no training software, so require_environment_pinned fails.",
            one("execution_integrity", json!({"require_environment_pinned": true})), with(b(), TRAINING_SOFTWARE, json!("")), &[F], F),
        case("execution-integrity-training-software-absent", "No training_software: not declared, indeterminate.",
            one("execution_integrity", json!({"require_environment_pinned": true})), without(b(), TRAINING_SOFTWARE), &[I], I).unverifiable(),
        case("execution-integrity-training-software-wrong-type", "training_software is a number: not a string, indeterminate.",
            one("execution_integrity", json!({"require_environment_pinned": true})), with(b(), TRAINING_SOFTWARE, json!(7)), &[I], I).unverifiable(),
        case("execution-integrity-software-hash-empty", "software_hash is the empty string: a signed declaration that no software hash is attested, so require_environment_pinned fails.",
            one("execution_integrity", json!({"require_environment_pinned": true})), with(b(), SOFTWARE_HASH, json!("")), &[F], F),
        case("execution-integrity-software-hash-absent", "No software_hash: not declared, indeterminate.",
            one("execution_integrity", json!({"require_environment_pinned": true})), without(b(), SOFTWARE_HASH), &[I], I).unverifiable(),
        case("execution-integrity-software-hash-wrong-type", "software_hash is a number: not a string, indeterminate.",
            one("execution_integrity", json!({"require_environment_pinned": true})), with(b(), SOFTWARE_HASH, json!(7)), &[I], I).unverifiable(),
        case("execution-integrity-software-hash-not-a-hash", "software_hash is a non-empty string that is not a hash.",
            one("execution_integrity", json!({"require_environment_pinned": true})), with(b(), SOFTWARE_HASH, json!("sha256:not-hex")), &[F], F).unverifiable(),
        case("execution-integrity-upper-case-hex-is-a-hash", "A hash may be written with upper-case hex digits (§5).",
            one("execution_integrity", json!({"require_environment_pinned": true})), with(b(), SOFTWARE_HASH, json!(upper_software_hash)), &[P], P).unverifiable(),
        case("execution-integrity-mixed-case-hash", "One hash may mix upper-case and lower-case hex digits (§5).",
            one("execution_integrity", json!({"require_environment_pinned": true})), with(b(), SOFTWARE_HASH, json!(mixed_software_hash)), &[P], P).unverifiable(),
        case("execution-integrity-no-tee", "tee_measurement is empty: a record emitted without a TEE fails require_tee; the evidence still covers all six reads and the context slot.",
            one("execution_integrity", json!({"require_tee": true})), b(), &[F], F),
        case("execution-integrity-tee-pass", "tee_measurement is a hash.",
            one("execution_integrity", json!({"require_tee": true})), with(b(), TEE, json!(a_hash("khalm policy vectors: a TEE measurement"))), &[P], P),
        case("execution-integrity-tee-not-a-hash", "tee_measurement is a non-empty string that is not a hash.",
            one("execution_integrity", json!({"require_tee": true})), with(b(), TEE, json!("not-a-hash")), &[F], F).unverifiable(),
        case("execution-integrity-tee-absent", "No tee_measurement: not declared, indeterminate.",
            one("execution_integrity", json!({"require_tee": true})), without(b(), TEE), &[I], I).unverifiable(),
        case("execution-integrity-tee-wrong-type", "tee_measurement is a boolean: not a string, indeterminate.",
            one("execution_integrity", json!({"require_tee": true})), with(b(), TEE, json!(true)), &[I], I).unverifiable(),
        // §6.5 execution_integrity: require_state_kept
        case("execution-integrity-state-kept-pass", "A deployment keeps its verified immediate predecessor's model; the slot holds that predecessor's model_hash.",
            state_kept_rule(), deployment.clone(), &[P], P).in_context("complete", vec![b()]),
        case("execution-integrity-state-kept-fail", "A policy change whose model_hash, in this profile equal to its learned_state_hash, differs from its verified immediate predecessor's.",
            state_kept_rule(), policy_change_with_another_state, &[F], F).in_context("complete", vec![b()]),
        case("execution-integrity-state-kept-not-checked", "A deployment whose predecessor was not supplied: no verified immediate predecessor to compare with.",
            state_kept_rule(), deployment.clone(), &[I], I).in_context("not_checked", vec![]),
        case("execution-integrity-state-kept-not-a-keeping-step", "A training update may change the model, whatever its predecessor's.",
            state_kept_rule(), training_update_with_another_state, &[P], P).in_context("complete", vec![b()]),
        case("execution-integrity-state-kept-no-context", "A deployment evaluated without any context: indeterminate. A verifier always gives a context, so it does not replay this case.",
            state_kept_rule(), deployment, &[I], I).unverifiable(),
        // §6.6 attestation_level
        case("attestation-level-pass", "software is at least software.",
            one("attestation_level", json!({"minimum_level": "software"})), b(), &[P], P),
        case("attestation-level-fail", "software is weaker than hardware.",
            one("attestation_level", json!({"minimum_level": "hardware"})), b(), &[F], F),
        case("attestation-level-hardware-pass", "hardware is at least hardware. The verification vectors' ts-basic store grants key A only software, so a verifier refuses this record.",
            one("attestation_level", json!({"minimum_level": "hardware"})), with(b(), ATTESTATION, json!("hardware")), &[P], P).unverifiable(),
        case("attestation-level-self-below-software", "The issuer declares self, which is below software.",
            one("attestation_level", json!({"minimum_level": "software"})), with(b(), ATTESTATION, json!("self")), &[F], F),
        case("attestation-level-absent", "No attestation level is declared.",
            one("attestation_level", json!({"minimum_level": "software"})), without(b(), ATTESTATION), &[I], I).unverifiable(),
        case("attestation-level-unknown-word", "A level that is not one of the three is indeterminate, never the weakest.",
            one("attestation_level", json!({"minimum_level": "software"})), with(b(), ATTESTATION, json!("firmware")), &[I], I).unverifiable(),
        case("attestation-level-wrong-type", "A number where a level is needed.",
            one("attestation_level", json!({"minimum_level": "software"})), with(b(), ATTESTATION, json!(2)), &[I], I).unverifiable(),
        // §4 packs: a signed pack, and text RFC 8785 writes as it is
        case("signed-pack-evaluates-as-unsigned", "attestation-level-pass's pack with an authority signature: the same payload hash and the same evaluation.",
            signed(&one("attestation_level", json!({"minimum_level": "software"}))), b(), &[P], P),
        case("attestation-level-pack-text-non-ascii", "attestation-level-pass's rule in a pack whose description and rule reference hold non-ASCII characters: its payload hash is over their UTF-8 bytes, unescaped.",
            pack_described(
                vec![{
                    let mut r = rule("attestation_level", "vector-attestation-level", "mandatory", json!({"minimum_level": "software"}));
                    r["reference"] = json!("Politique d\u{2019}essai \u{a7}4 (\u{8a66}\u{9a13})");
                    r
                }],
                "Un paquet d\u{2019}essai \u{e9}crit en fran\u{e7}ais, \u{a7}2, \u{6e2c}\u{8a66}.",
            ),
            b(), &[P], P),
        // §5 independence from the evaluation time
        case("time-independence-first", "A pack of three rule types, evaluated at the conformance vector's time.",
            pack(vec![
                rule("audit_integrity", "vector-audit", "mandatory", json!({"require_tamper_evident": true, "require_ordered_record": true})),
                rule("execution_integrity", "vector-execution", "mandatory", json!({"require_learned_state_components": true, "require_environment_pinned": true})),
                rule("attestation_level", "vector-attestation", "mandatory", json!({"minimum_level": "software"})),
            ]), b(), &[P, P, P], P),
        case("time-independence-later", "time-independence-first's pack and record a year later: the same results and evidence hashes, another evaluated_at.",
            pack(vec![
                rule("audit_integrity", "vector-audit", "mandatory", json!({"require_tamper_evident": true, "require_ordered_record": true})),
                rule("execution_integrity", "vector-execution", "mandatory", json!({"require_learned_state_components": true, "require_environment_pinned": true})),
                rule("attestation_level", "vector-attestation", "mandatory", json!({"minimum_level": "software"})),
            ]), b(), &[P, P, P], P).at(T_LATER),
        // §8 the overall status
        case("overall-mandatory-fail-over-indeterminate", "A mandatory failure decides over a mandatory indeterminate (a successor with no predecessor supplied); the indeterminate rule is omitted from policy_compliance.",
            pack(vec![
                rule("attestation_level", "vector-attestation-hardware", "mandatory", json!({"minimum_level": "hardware"})),
                rule("audit_integrity", "vector-verified-lineage", "mandatory", json!({"require_tamper_evident": true, "require_verified_lineage": true})),
                rule("data_residency", "vector-residency", "recommended", json!({"allowed_jurisdictions": ["PH"]})),
            ]), second.clone(), &[F, I, P], F).in_context("not_checked", vec![]),
        case("overall-recommended-and-informational-failures", "Failures of recommended and informational rules are carried and do not move the overall status.",
            pack(vec![
                rule("audit_integrity", "vector-audit", "mandatory", json!({"minimum_chain_length": 1})),
                rule("attestation_level", "vector-attestation-hardware", "recommended", json!({"minimum_level": "hardware"})),
                rule("data_residency", "vector-residency-sg", "informational", json!({"allowed_jurisdictions": ["SG"]})),
            ]), b(), &[P, F, F], P),
        case("overall-mandatory-indeterminate", "A mandatory indeterminate with no failure (a successor with no predecessor supplied): the overall status is indeterminate, and the rule is omitted.",
            pack(vec![
                rule("audit_integrity", "vector-verified-lineage", "mandatory", json!({"require_tamper_evident": true, "require_verified_lineage": true})),
                rule("attestation_level", "vector-attestation-software", "recommended", json!({"minimum_level": "software"})),
            ]), second, &[I, P], I).in_context("not_checked", vec![]),
        case("overall-no-mandatory-rule", "A pack with no mandatory rule passes overall, whatever its other rules say.",
            pack(vec![
                rule("execution_integrity", "vector-tee", "informational", json!({"require_tee": true})),
                rule("attestation_level", "vector-attestation-hardware", "recommended", json!({"minimum_level": "hardware"})),
            ]), b(), &[F, F], P),
    ];

    // The five reference packs against the conformance record, and against
    // the demo record (the Gate 5 artifact). Both records sign an empty
    // tee_measurement, which fails every require_tee. The conformance
    // record declares no documentation member, which fails the EU pack's
    // two recommended documentation_declared rules (§6.7, task 10.11a). The
    // demo record (task 7.6) pins its software environment by hash, so it
    // passes every require_environment_pinned, and pins a data governance
    // document but no human oversight document, so of those two rules only
    // the oversight rule fails. No recommended failure moves an overall
    // status. (pack id, statuses on the conformance record, its overall
    // status, statuses on the demo record, its overall status)
    type Reference = (&'static str, &'static [&'static str], &'static str, &'static [&'static str], &'static str);
    let references: [Reference; 5] = [
        ("khalm-reading-eu-ai-act-2026", &[P, P, P, P, F, F], P, &[P, P, P, P, P, F], P),
        ("khalm-reading-nist-ai-rmf-1.0", &[P, P, P], P, &[P, P, P], P),
        ("khalm-reading-iso-42001-2023", &[P, P, P], P, &[P, P, P], P),
        ("khalm-reading-c2pa-ai-disclosure-2.2", &[P, P, P], P, &[P, P, P], P),
        ("khalm-reading-rats-rfc9334-v0.1", &[P, P, F, P, P], P, &[P, P, F, P, P], P),
    ];
    for (pack_id, on_conformance, overall_conformance, on_demo, overall_demo) in references {
        all.push(case(
            &format!("reference-{pack_id}-conformance-record"),
            "A reference pack against the conformance vector's record.",
            reference(pack_id), b(), on_conformance, overall_conformance,
        ));
        all.push(
            case(
                &format!("reference-{pack_id}-demo-record"),
                "A reference pack against the demo record, the payload of the demo artifact the engine build emits.",
                reference(pack_id), demo(), on_demo, overall_demo,
            )
            .at(T_DEMO),
        );
    }

    // §6.7 documentation_declared (task 10.11a, D11-4), after every earlier
    // case. The conformance record declares neither optional member; the
    // records declaring one are re-signed with key A, and a record whose
    // member is malformed keeps the conformance record's signature, which
    // does not hold.
    let data_document = json!({"documentation_hash": a_hash("khalm policy vectors: a data governance document")});
    let oversight_document = json!({"documentation_hash": a_hash("khalm policy vectors: a human oversight document")});
    let declaring = |data: Option<&Value>, oversight: Option<&Value>| {
        let mut record = b();
        if let Some(d) = data {
            record["data_governance"] = d.clone();
        }
        if let Some(o) = oversight {
            record["human_oversight"] = o.clone();
        }
        signed_with_key_a(record)
    };
    let with_data_governance = |value: Value| {
        let mut record = b();
        record["data_governance"] = value;
        record
    };
    let data_rule = || one("documentation_declared", json!({"document": "data_governance"}));
    let oversight_rule = || one("documentation_declared", json!({"document": "human_oversight"}));
    let upper_hash = data_document["documentation_hash"].as_str().unwrap().replacen("sha256:", "", 1).to_ascii_uppercase();
    all.extend([
        case("documentation-declared-data-governance-pass", "The conformance record declaring both optional documentation members, re-signed: its data governance documentation is pinned by a hash.",
            data_rule(), declaring(Some(&data_document), Some(&oversight_document)), &[P], P),
        case("documentation-declared-human-oversight-pass", "The same record and a rule naming the human oversight documentation: pass, with documentation-declared-data-governance-pass's evidence hash.",
            oversight_rule(), declaring(Some(&data_document), Some(&oversight_document)), &[P], P),
        case("documentation-declared-data-governance-absent", "The conformance record has no data_governance member: an absent optional member is the record's signed statement that it pins no such document, so fail (§6.7), where every other rule type is indeterminate.",
            data_rule(), b(), &[F], F),
        case("documentation-declared-human-oversight-absent", "The conformance record has no human_oversight member: fail.",
            oversight_rule(), b(), &[F], F),
        case("documentation-declared-other-document-only", "The record pins only its human oversight documentation, re-signed, and the rule names data governance: fail. The steps look only at the document the rule names; the evidence covers both.",
            data_rule(), declaring(None, Some(&oversight_document)), &[F], F),
        case("documentation-declared-not-an-object-record", "The record text is a JSON array, not an object: step 1, indeterminate; both reads are absent and contribute null.",
            data_rule(), json!(["not", "a", "record"]), &[I], I).unverifiable(),
        case("documentation-declared-null", "data_governance is present with the value null: of the wrong JSON type, not absent, so indeterminate (step 3). It hashes as the absent member of documentation-declared-data-governance-absent, which fails.",
            data_rule(), with_data_governance(Value::Null), &[I], I).unverifiable(),
        case("documentation-declared-not-an-object", "data_governance is its hash string rather than an object: indeterminate.",
            data_rule(), with_data_governance(data_document["documentation_hash"].clone()), &[I], I).unverifiable(),
        case("documentation-declared-hash-missing", "data_governance is {}, without a documentation_hash: indeterminate.",
            data_rule(), with_data_governance(json!({})), &[I], I).unverifiable(),
        case("documentation-declared-hash-empty", "data_governance's documentation_hash is the empty string, which is not a declared string: indeterminate.",
            data_rule(), with_data_governance(json!({"documentation_hash": ""})), &[I], I).unverifiable(),
        case("documentation-declared-hash-wrong-type", "data_governance's documentation_hash is a number: indeterminate.",
            data_rule(), with_data_governance(json!({"documentation_hash": 7})), &[I], I).unverifiable(),
        case("documentation-declared-hash-not-a-hash", "data_governance's documentation_hash is a declared string that is not a hash: fail (step 4).",
            data_rule(), with_data_governance(json!({"documentation_hash": "sha256:not-hex"})), &[F], F).unverifiable(),
        case("documentation-declared-upper-case-hash", "data_governance's documentation_hash in upper-case hex is a hash (§5): pass. A verifier refuses the record, whose schema wants lower case.",
            data_rule(), with_data_governance(json!({"documentation_hash": format!("sha256:{upper_hash}")})), &[P], P).unverifiable(),
        case("documentation-declared-two-rules-one-evidence-hash", "Two recommended rules, one per document, on a record pinning only its human oversight documentation, re-signed: one evidence hash for both, the data governance rule fails and the oversight rule passes, and recommended rules leave the overall status a pass (§8).",
            pack(vec![
                rule("documentation_declared", "vector-data-governance", "recommended", json!({"document": "data_governance"})),
                rule("documentation_declared", "vector-human-oversight", "recommended", json!({"document": "human_oversight"})),
            ]),
            declaring(None, Some(&oversight_document)), &[F, P], P),
    ]);

    // QA QT-03 (QA/QA_REPORT_TASK_10_11A.md), after every earlier case: §5's
    // "A hash" at each of its edges, and §6.7 step 3, which reads no member
    // of the object but documentation_hash. Each case is unverifiable and
    // sets data_governance; its status is written by hand from §5 and §6.7.
    let lower_hex = data_document["documentation_hash"].as_str().unwrap().replacen("sha256:", "", 1);
    let mixed_hex: String =
        lower_hex.chars().enumerate().map(|(i, ch)| if i % 2 == 0 { ch.to_ascii_uppercase() } else { ch }).collect();
    assert!(
        mixed_hex.chars().any(|ch| ch.is_ascii_uppercase()) && mixed_hex.chars().any(|ch| ch.is_ascii_lowercase()),
        "a hash in mixed case: {mixed_hex}"
    );
    let with_hash = |hash: String| with_data_governance(json!({"documentation_hash": hash}));
    all.extend([
        case("documentation-declared-hash-prefix-upper-case", "data_governance's documentation_hash is SHA256: and 64 hex digits: the prefix of a hash is sha256: in lower case (§5), so it is not a hash: fail (step 4).",
            data_rule(), with_hash(format!("SHA256:{lower_hex}")), &[F], F).unverifiable(),
        case("documentation-declared-hash-63-digits", "data_governance's documentation_hash is sha256: and 63 hex digits: a hash has exactly 64, so fail.",
            data_rule(), with_hash(format!("sha256:{}", &lower_hex[..63])), &[F], F).unverifiable(),
        case("documentation-declared-hash-65-digits", "data_governance's documentation_hash is sha256: and 65 hex digits: a hash has exactly 64, so fail.",
            data_rule(), with_hash(format!("sha256:{lower_hex}0")), &[F], F).unverifiable(),
        case("documentation-declared-hash-trailing-newline", "data_governance's documentation_hash is a hash followed by a line feed: nothing may surround the hash, and white space is not trimmed, so fail.",
            data_rule(), with_hash(format!("sha256:{lower_hex}\n")), &[F], F).unverifiable(),
        case("documentation-declared-hash-leading-space", "data_governance's documentation_hash is a space followed by a hash: nothing may surround the hash, so fail.",
            data_rule(), with_hash(format!(" sha256:{lower_hex}")), &[F], F).unverifiable(),
        case("documentation-declared-hash-fullwidth-digits", "data_governance's documentation_hash is sha256: and 64 FULLWIDTH DIGIT ONE (U+FF11): the digits of a hash are ASCII (§5), so fail.",
            data_rule(), with_hash(format!("sha256:{}", "\u{ff11}".repeat(64))), &[F], F).unverifiable(),
        case("documentation-declared-mixed-case-hash", "data_governance's documentation_hash mixes upper-case and lower-case hex digits: one hash may mix cases (§5), so pass.",
            data_rule(), with_hash(format!("sha256:{mixed_hex}")), &[P], P).unverifiable(),
        case("documentation-declared-extra-member", "data_governance holds a hash and a title member: §6.7 reads no member of the object but documentation_hash, so pass, and the evidence covers the whole member. A verifier refuses the record, whose objects are closed.",
            data_rule(), with_data_governance(json!({"documentation_hash": data_document["documentation_hash"].clone(), "title": "x"})), &[P], P).unverifiable(),
    ]);

    // Task 10.11b (docs/dev/task-10.11b.md §4.5), after every earlier case:
    // records of any kind of model. The general conformance record
    // commits no training records (not-held), states no training times,
    // environment or residency, and has a deployment. No rule type, read list
    // or evidence-hash rule changed; each status is written by hand from §6.
    let with_countries = || {
        let mut record = general();
        record["learning_provenance"]["training_input_provenance"]["data_residency_countries"] = json!(["DE", "FR"]);
        signed_with_key_a(record)
    };
    let general_deployment = successor(&general(), "urn:uuid:00000000-0000-4000-8000-0000000000d1", "deployment");
    // Task 10.12a (D12a-3): the same deployment listing other components of
    // the same model, and naming another model; neither is re-signed.
    let other_components = with(general_deployment.clone(), STATE_HASH, json!(another_state));
    let other_components_for_compare = other_components.clone();
    let other_model = with(general_deployment.clone(), MODEL_HASH, json!(another_state));
    all.extend([
        case("general-not-held-input-committed", "The general conformance record commits no training records (record format §8.4: training_input_disclosure not-held, \"\" digest and root, count 0). Its declared training_input_disclosure says so, so require_input_committed fails at read 10: withholding the records is a signed statement, not silence.",
            one("audit_integrity", json!({"require_input_committed": true})), general(), &[F], F),
        case("general-not-held-tamper-evident", "The general conformance record declares its training input not-held, so nothing commits it: require_tamper_evident fails at read 10 (§6.4 step 3).",
            one("audit_integrity", json!({"require_tamper_evident": true})), general(), &[F], F),
        case("general-not-held-ordered-record", "The general conformance record states no training times and no collection period (record format §2 rule 3): reads 5 to 8 are absent, so require_ordered_record is indeterminate.",
            one("audit_integrity", json!({"require_ordered_record": true})), general(), &[I], I),
        case("general-learned-state-components", "The general conformance record's components are its four files, each with a hash and a positive size, and its learned_state_hash is their named-set digest (record format §7.3): require_learned_state_components passes for a model that is not the engine's.",
            one("execution_integrity", json!({"require_learned_state_components": true})), general(), &[P], P),
        case("general-not-held-environment-pinned", "The general conformance record's training_software and software_hash are \"\", the signed none: require_environment_pinned fails.",
            one("execution_integrity", json!({"require_environment_pinned": true})), general(), &[F], F),
        case("general-residency-countries-data-residency", "The general conformance record naming its data's countries, DE and FR, in data_residency_countries, re-signed: both are allowed, so the rule passes (§6.1).",
            one("data_residency", json!({"allowed_jurisdictions": ["DE", "FR"]})), with_countries(), &[P], P),
        case("general-residency-countries-source-screening", "The same record and a source screening that restricts CN: its source_type is \"\", so the rule is indeterminate at step 1, whatever its countries (§6.2).",
            one("source_screening", json!({"restricted_list": ["CN"]})), with_countries(), &[I], I),
        case("general-no-deployment-export-control", "The general conformance record without deployment_context, re-signed: a record for a model its issuer does not deploy has no inference boundary, so require_air_gapped is indeterminate (§6.3).",
            one("export_control", json!({"require_air_gapped": true})), signed_with_key_a(without(general(), "/deployment_context")), &[I], I),
        case("general-deployment-state-kept", "A deployment record following the general conformance record, evaluated with it as the verified predecessor: its model_hash, the model's identity (record format §7.3), is kept, so require_state_kept passes for a model that is not the engine's.",
            state_kept_rule(), general_deployment, &[P], P).in_context("complete", vec![general()]),
        case("reference-khalm-reading-eu-ai-act-2026-general-record", "The EU AI Act reference pack against the general conformance record. Record keeping fails: the record declares its training input not-held, so nothing commits it. Accuracy and robustness passes: the learned state is pinned, and an initial record keeps no predecessor's model. Technical documentation fails on the \"\" training software. Cybersecurity attestation passes (software), and both documentation rules fail (neither member). A mandatory failure: non-compliant.",
            reference("khalm-reading-eu-ai-act-2026"), general(), &[F, P, F, P, F, F], F),
    ]);

    // Task 10.12a (docs/dev/task-10.12a.md), after every earlier case: data
    // kept in several countries (D12a-4), a declared withholding (D12a-5)
    // and the model kept by model_hash (D12a-3). Each status is written by
    // hand from §6.
    let with_countries_and_source = || {
        let mut record = general();
        record["learning_provenance"]["training_input_provenance"]["source_type"] = json!("licensed_corpus");
        record["learning_provenance"]["training_input_provenance"]["data_residency_countries"] = json!(["DE", "FR"]);
        signed_with_key_a(record)
    };
    let mut disclosure_wrong_type = b();
    disclosure_wrong_type["learning_provenance"]["training_input_disclosure"] = json!(7);
    all.extend([
        case("general-residency-countries-data-residency-fail", "The general conformance record naming DE and FR in data_residency_countries, re-signed, against a rule allowing only DE: FR is not allowed, so the rule fails (§6.1).",
            one("data_residency", json!({"allowed_jurisdictions": ["DE"]})), with_countries(), &[F], F),
        case("data-residency-countries-not-a-list-of-codes", "data_residency_countries holds DE and the number 7: a list with an element that is not a declared string said nothing checkable, so the rule is indeterminate, never a pass on DE alone (§6.1).",
            one("data_residency", json!({"allowed_jurisdictions": ["DE", "FR"]})), with(with_countries(), COUNTRIES, json!(["DE", 7])), &[I], I).unverifiable(),
        case("general-residency-countries-source-screening-pass", "The general conformance record with the source type licensed_corpus and its data in DE and FR, re-signed, against a screening that restricts CN: neither the source type nor a country is restricted, so the rule passes (§6.2).",
            one("source_screening", json!({"restricted_list": ["CN"]})), with_countries_and_source(), &[P], P),
        case("general-residency-countries-source-screening-fail", "The same record against a screening that restricts FR: one of its countries is restricted, so the rule fails (§6.2).",
            one("source_screening", json!({"restricted_list": ["FR"]})), with_countries_and_source(), &[F], F),
        case("general-not-disclosed-input-committed", "The general conformance record with training_input_disclosure not-disclosed, re-signed: the issuer holds its training records and declares that it does not commit to them, so require_input_committed fails (§6.4 step 4, record format §8.4).",
            one("audit_integrity", json!({"require_input_committed": true})), signed_with_key_a(with(general(), DISCLOSURE, json!("not-disclosed"))), &[F], F),
        case("audit-integrity-disclosure-wrong-type", "The conformance record, which commits sixteen frames, with training_input_disclosure the number 7: not a declared string, so it declares no withholding, and the committed root and count pass both requirements (§6.4).",
            one("audit_integrity", json!({"require_tamper_evident": true, "require_input_committed": true})), disclosure_wrong_type, &[P], P).unverifiable(),
        case("general-deployment-other-components-model-kept", "The deployment of general-deployment-state-kept with another learned_state_hash, as an issuer listing other components of the same model would sign, not re-signed: its model_hash equals its verified predecessor's, so require_state_kept passes (§6.5 step 4).",
            state_kept_rule(), other_components, &[P], P).in_context("complete", vec![general()]).unverifiable(),
        case("general-deployment-model-hash-changed", "The same deployment with another model_hash and its predecessor's learned_state_hash, not re-signed: it names another model, so require_state_kept fails.",
            state_kept_rule(), other_model, &[F], F).in_context("complete", vec![general()]).unverifiable(),
    ]);

    // The two pack parameters the owner added on 2026-09-16 (the release
    // QA's QR-04 and QR-05). Each status is written by hand from §6.4 and
    // §6.5; the default of each is the behaviour of every case above, which
    // is why none of them moved.
    let withheld = |setting: &str| {
        one("audit_integrity", json!({"require_input_committed": true, "withheld": setting}))
    };
    all.extend([
        case("audit-integrity-withheld-fail", "The general conformance record, whose training_input_disclosure is not-held, against a rule that states withheld fail: the declared withholding fails require_input_committed, which is what the rule says with or without the parameter (§6.4 step 4).",
            withheld("fail"), general(), &[F], F),
        case("audit-integrity-withheld-indeterminate", "The same record and rule with withheld indeterminate: the record declared that it withholds, which is not a wrong answer, so the requirement is indeterminate (§6.4 step 4). A pack that tolerates a model whose corpus is not published states this.",
            withheld("indeterminate"), general(), &[I], I),
        case("execution-integrity-compare-model-hash", "The deployment of general-deployment-state-kept with another learned_state_hash, against require_state_kept with compare model_hash stated: the model's identity is kept, so the rule passes, as it does with the parameter absent (§6.5 step 4).",
            one("execution_integrity", json!({"require_state_kept": true, "compare": "model_hash"})),
            other_components_for_compare.clone(), &[P], P).in_context("complete", vec![general()]).unverifiable(),
        case("execution-integrity-compare-learned-state-hash", "The same record and context with compare learned_state_hash: the declared learned state moved, and that is the member a holder of the components recomputes (record format §7.3), so the rule fails (§6.5 step 4).",
            one("execution_integrity", json!({"require_state_kept": true, "compare": "learned_state_hash"})),
            other_components_for_compare, &[F], F).in_context("complete", vec![general()]).unverifiable(),
    ]);
    all
}

/// The committed cases, then a copy of each case of a general rule that the
/// committed set tests only on an engine record, over [`general_twin`] (the
/// owner, 2026-09-16: the engine profile is optional, so the general core
/// must keep the failure coverage it has today - `suite.json`'s
/// `general_checks_on_engine_records`).
///
/// A copy is kept only when the original names the profile and the copy does
/// not, so a case over the committed engine artifact (`-demo-record`), which
/// cannot be described generally without ceasing to be that artifact, brings
/// none. Every kept copy's expected statuses are the original's, which
/// [`general_twin`] makes correct by construction.
fn cases() -> Vec<Case> {
    let base = cases_from(conformance);
    let twins = cases_from(general_twin);
    assert_eq!(base.len(), twins.len(), "the two passes build the same cases");
    let mut all = Vec::with_capacity(base.len() + twins.len());
    let mut copied = Vec::new();
    for (original, mut twin) in base.iter().cloned().zip(twins) {
        all.push(original.clone());
        if !names_profile(&original) || names_profile(&twin) {
            continue;
        }
        assert_eq!(twin.id, original.id, "the two passes build the same case ids");
        twin.description = format!(
            "{} The same check on a general-description record: the conformance record's \
             model_format and learned_state_hash are the general description's (record format §7.1, \
             §7.3) and every other byte is unchanged, so the rule reads the same values and the \
             expected statuses are this case's.",
            original.description
        );
        // Under the general description learned_state_hash IS checked against
        // the components (record format §7.3); under the profile it is not
        // (§7.4). A copy whose case edited either is therefore not a record a
        // verifier replays, however its original was: it is marked
        // unverifiable, and its evaluation is unchanged - no rule of the
        // policy-pack format reads whether a record verifies.
        let described = general_twin();
        let edited = twin.record["model_identity"]["learned_state_hash"]
            != described["model_identity"]["learned_state_hash"]
            || twin.record["model_identity"]["learned_state_components"]
                != described["model_identity"]["learned_state_components"];
        if edited {
            twin.verifiable = false;
        }
        twin.id = format!("{}{GENERAL_TWIN_SUFFIX}", original.id);
        copied.push(twin);
    }
    assert!(copied.len() >= 100, "{} general-description copies", copied.len());
    all.extend(copied);
    all
}

// ---------------------------------------------------------------------------
//  The expected evaluation (§7, §8)
// ---------------------------------------------------------------------------

/// The record text of a case: its JCS form, with the one number the case
/// spells written as it says.
fn record_text(c: &Case) -> String {
    match c.spelling {
        None => jcs(&c.record),
        Some((pointer, literal)) => {
            const MARK: &str = "khalm-policy-vector-spelled-number";
            let text = jcs(&with(c.record.clone(), pointer, json!(MARK)));
            let quoted = format!("\"{MARK}\"");
            assert_eq!(text.matches(&quoted).count(), 1, "{}: one spelled number", c.id);
            text.replace(&quoted, literal)
        }
    }
}

fn case_json(c: &Case) -> Value {
    let mut v = json!({
        "id": c.id,
        "description": c.description,
        "pack": {"text": c.pack},
        "record": {"text": record_text(c)},
        "verifiable": c.verifiable,
        "evaluation_time": c.t,
        "expected": expected(c),
    });
    if let Some(context) = &c.context {
        v["context"] = json!({
            "lineage_outcome": context.outcome,
            "predecessors": context
                .predecessors
                .iter()
                .map(|p| json!({"signed_payload_hash": signed_payload_hash(p), "text": jcs(p)}))
                .collect::<Vec<_>>(),
        });
    }
    v
}

fn expected(c: &Case) -> Value {
    let pack: Value = serde_json::from_str(&c.pack).unwrap();
    // The evidence is the record text's, as an evaluator parses it.
    let record: Value = serde_json::from_str(&record_text(c)).unwrap();
    let rules = pack["rules"].as_array().unwrap();
    assert_eq!(rules.len(), c.statuses.len(), "{}: one status per rule", c.id);
    let mut results = Vec::new();
    let mut indeterminate = Vec::new();
    let mut carried = Vec::new();
    let mut mandatory = Vec::new();
    for (r, status) in rules.iter().zip(&c.statuses) {
        let rule_type = r["type"].as_str().unwrap();
        let rule_id = r["rule_id"].as_str().unwrap();
        let hash = evidence_hash(&record, rule_type, c.context.as_ref());
        results.push(json!({
            "rule_id": rule_id,
            "rule_type": rule_type,
            "severity": r["severity"],
            "status": status,
            "evidence_hash": hash,
        }));
        if *status == I {
            indeterminate.push(rule_id);
        } else {
            carried.push(json!({"rule_id": rule_id, "status": status, "evidence_hash": hash}));
        }
        if r["severity"] == "mandatory" {
            mandatory.push(*status);
        }
    }
    let aggregated = if mandatory.contains(&F) {
        F
    } else if mandatory.contains(&I) {
        I
    } else {
        P
    };
    assert_eq!(c.overall, aggregated, "{}: the declared overall status contradicts §8", c.id);
    let overall_status = match c.overall {
        P => "compliant",
        F => "non-compliant",
        _ => "indeterminate",
    };
    json!({
        "pack_payload_hash": payload_hash(&pack),
        "results": results,
        "indeterminate": indeterminate,
        "overall": c.overall,
        "policy_compliance": {
            "policy_pack_id": pack["pack_id"],
            "evaluated_at": c.t,
            "results": carried,
            "overall_status": overall_status,
        },
    })
}
