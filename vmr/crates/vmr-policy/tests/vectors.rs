// tests/vectors.rs — the policy evaluation vectors (docs/dev/phase7.md P7-6,
// task 7.4; Doctrine Refusal 6: no format without test vectors). The committed
// file specs/test-vectors/policy/cases.json is the cross-implementation
// contract of specs/policy-pack-format-v0.1.md §9: per case, the pack's
// payload hash, every rule's type, severity, status and evidence hash, the
// indeterminate list, the overall status and the policy_compliance section,
// for a pack, a record, an evaluation time and, where a case gives one, a
// verification context. It is written only by tests/common/generate.rs:
//
//     VMR_WRITE_VECTORS=1 cargo test -p vmr-policy --test vectors -- --ignored
//
// and policy_vectors_are_reproducible fails if the committed bytes differ
// from a fresh generation. The same cases go through the `vmr` binary in
// vmr/crates/vmr-cli/tests/cross_impl/policy_vectors.rs (task 7.5).

mod common;
#[path = "common/generate.rs"]
mod generate;

use common::{specs_dir, REFERENCE_PACKS};
use serde_json::Value;
use std::collections::BTreeSet;
use vmr_policy::vmr_record::canonical::jcs;
use vmr_policy::vmr_record::hash::{format_hash, sha256};
use vmr_policy::vmr_record::timestamp::Timestamp;
use vmr_policy::{EvaluationContext, LineageContext, LineageOutcome, VerifiedPredecessor};

fn read(rel: &str) -> String {
    let path = specs_dir().join("test-vectors").join(rel);
    std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("{}: {e} (regenerate with VMR_WRITE_VECTORS=1)", path.display()))
}

fn cases() -> Vec<Value> {
    let doc: Value = serde_json::from_str(&read("policy/cases.json")).unwrap();
    assert_eq!(doc["vector_version"], "0.1");
    doc["cases"].as_array().unwrap().clone()
}

fn text<'a>(case: &'a Value, member: &str) -> &'a str {
    case[member]["text"].as_str().unwrap_or_else(|| panic!("{}: no {member}.text", case["id"]))
}

/// The verification context a case gives (the format document's §5 and §9):
/// its lineage outcome, and its verified predecessors, immediate predecessor
/// first, each a signed payload hash and a record text. `None` when the
/// case is evaluated without context.
fn context(case: &Value) -> Option<EvaluationContext> {
    let c = case.get("context")?;
    let id = &case["id"];
    let outcome = match c["lineage_outcome"].as_str() {
        Some("initial") => LineageOutcome::Initial,
        Some("complete") => LineageOutcome::Complete,
        Some("partial") => LineageOutcome::Partial,
        Some("not_checked") => LineageOutcome::NotChecked,
        other => panic!("{id}: lineage_outcome {other:?}"),
    };
    let predecessors = c["predecessors"]
        .as_array()
        .unwrap_or_else(|| panic!("{id}: context.predecessors"))
        .iter()
        .map(|p| VerifiedPredecessor {
            signed_payload_hash: p["signed_payload_hash"].as_str().unwrap().to_string(),
            record: serde_json::from_str(p["text"].as_str().unwrap()).unwrap(),
        })
        .collect();
    Some(EvaluationContext { lineage: LineageContext { outcome, predecessors } })
}

#[test]
fn policy_vectors_are_reproducible() {
    for (rel, contents) in generate::generate() {
        let committed = read(&rel);
        assert!(
            committed == contents,
            "{rel} differs from a fresh generation at {}: regenerate with VMR_WRITE_VECTORS=1, in its own commit",
            first_difference(&committed, &contents)
        );
    }
}

/// Where a committed vector file first differs from a fresh generation, so
/// that the reproducibility failure names it: the first differing case's id
/// and member (a JSON pointer into the case), or a top-level member; the
/// first differing line when either text does not parse, or when both hold
/// the same JSON written differently.
fn first_difference(committed: &str, fresh: &str) -> String {
    let line = || {
        let (a, b) = (committed.lines().collect::<Vec<_>>(), fresh.lines().collect::<Vec<_>>());
        let n = a.iter().zip(&b).position(|(x, y)| x != y).unwrap_or(a.len().min(b.len()));
        format!("line {}", n + 1)
    };
    let (Ok(a), Ok(b)) = (serde_json::from_str::<Value>(committed), serde_json::from_str::<Value>(fresh)) else {
        return format!("{} (not both JSON)", line());
    };
    let id = |case: &Value| case["id"].as_str().unwrap_or("<no id>").to_string();
    let none = Vec::new();
    let (was, now) = (a["cases"].as_array().unwrap_or(&none), b["cases"].as_array().unwrap_or(&none));
    for i in 0..was.len().max(now.len()) {
        match (was.get(i), now.get(i)) {
            (Some(x), Some(y)) if x == y => {}
            (Some(x), Some(y)) if x["id"] == y["id"] => return format!("case {}, member {}", id(x), pointer(x, y)),
            (Some(x), Some(y)) => return format!("case {i}: {} committed, {} generated", id(x), id(y)),
            (Some(x), None) => return format!("case {} (committed, not generated)", id(x)),
            (None, Some(y)) => return format!("case {} (generated, not committed)", id(y)),
            (None, None) => {}
        }
    }
    match pointer(&a, &b) {
        p if p.is_empty() => format!("{} (the same JSON, written differently)", line()),
        p => format!("member {p}"),
    }
}

/// The JSON pointer (RFC 6901) of the first place two values differ; empty
/// when they are equal or differ only as a whole scalar.
fn pointer(a: &Value, b: &Value) -> String {
    let step = |token: String, x: Option<&Value>, y: Option<&Value>| {
        let rest = match (x, y) {
            (Some(x), Some(y)) => pointer(x, y),
            _ => String::new(),
        };
        format!("/{}{rest}", token.replace('~', "~0").replace('/', "~1"))
    };
    match (a, b) {
        (Value::Object(x), Value::Object(y)) => match x.keys().chain(y.keys()).find(|k| x.get(*k) != y.get(*k)) {
            Some(k) => step(k.clone(), x.get(k), y.get(k)),
            None => String::new(),
        },
        (Value::Array(x), Value::Array(y)) => match (0..x.len().max(y.len())).find(|&i| x.get(i) != y.get(i)) {
            Some(i) => step(i.to_string(), x.get(i), y.get(i)),
            None => String::new(),
        },
        _ => String::new(),
    }
}

#[test]
fn every_policy_vector_gives_its_expected_evaluation() {
    let all = cases();
    assert!(all.len() >= 40, "{} cases", all.len());
    let mut ids = BTreeSet::new();
    for case in &all {
        let id = case["id"].as_str().unwrap();
        assert!(ids.insert(id.to_string()), "duplicate case id {id}");
        let expected = &case["expected"];

        let pack = vmr_policy::load_pack(text(case, "pack")).unwrap_or_else(|e| panic!("{id}: {e}"));
        assert_eq!(pack.payload_hash(), expected["pack_payload_hash"], "{id}: pack payload hash");

        let record: Value = serde_json::from_str(text(case, "record")).unwrap();
        let t = Timestamp::parse(case["evaluation_time"].as_str().unwrap()).unwrap();
        let evaluation = match context(case) {
            Some(c) => pack.evaluate_in_context(&record, &c, t),
            None => pack.evaluate(&record, t),
        };

        let results = expected["results"].as_array().unwrap();
        assert_eq!(evaluation.results.len(), results.len(), "{id}: one result per rule");
        for (got, want) in evaluation.results.iter().zip(results) {
            let rule = &got.rule_id;
            assert_eq!(*rule, want["rule_id"], "{id}: rule order");
            assert_eq!(got.rule_type, want["rule_type"], "{id}/{rule}");
            assert_eq!(got.severity.id(), want["severity"], "{id}/{rule}");
            assert_eq!(got.status.id(), want["status"], "{id}/{rule}: {}", got.detail);
            assert_eq!(got.evidence_hash, want["evidence_hash"], "{id}/{rule}: evidence hash");
        }
        let indeterminate: Vec<&str> =
            expected["indeterminate"].as_array().unwrap().iter().map(|v| v.as_str().unwrap()).collect();
        assert_eq!(evaluation.indeterminate, indeterminate, "{id}: indeterminate list");
        assert_eq!(evaluation.overall.id(), expected["overall"], "{id}: overall status");
        assert_eq!(
            serde_json::to_value(evaluation.to_policy_compliance()).unwrap(),
            expected["policy_compliance"],
            "{id}: policy_compliance"
        );
    }
}

#[test]
fn the_policy_vectors_cover_every_rule_type_outcome_and_reference_pack() {
    let all = cases();
    let mut single: BTreeSet<(String, String)> = BTreeSet::new();
    let mut overall: BTreeSet<String> = BTreeSet::new();
    let mut ids: BTreeSet<String> = BTreeSet::new();
    let mut verifiable = 0;
    for case in &all {
        let results = case["expected"]["results"].as_array().unwrap();
        if results.len() == 1 {
            let r = &results[0];
            single.insert((r["rule_type"].as_str().unwrap().into(), r["status"].as_str().unwrap().into()));
        }
        overall.insert(case["expected"]["overall"].as_str().unwrap().into());
        ids.insert(case["id"].as_str().unwrap().into());
        if case["verifiable"] == true {
            verifiable += 1;
        }
    }
    for rule_type in vmr_policy::pack::RULE_TYPES {
        for status in ["pass", "fail", "indeterminate"] {
            assert!(
                single.contains(&(rule_type.to_string(), status.to_string())),
                "no one-rule case where {rule_type} is {status}"
            );
        }
    }
    assert_eq!(overall, ["fail", "indeterminate", "pass"].map(String::from).into_iter().collect());
    for pack_id in REFERENCE_PACKS {
        for record in ["conformance-record", "demo-record"] {
            let id = format!("reference-{pack_id}-{record}");
            assert!(ids.contains(&id), "no case {id}");
        }
    }
    assert!(verifiable >= 20, "{verifiable} verifiable cases");
}

#[test]
fn the_policy_vectors_reach_every_step_outcome() {
    // QA Q7-02: covering each rule type's three outcomes left step outcomes
    // of the format document's §6 without a case, and mutations G1-G6 broke
    // six of those steps unnoticed. This table names a one-rule case for each
    // step outcome, with the status the step yields, including the P6-17
    // settings, the empty string (E2), every verification context outcome and
    // the points of QA Q7-05. Each case must exist and reach that status.
    const P: &str = "pass";
    const F: &str = "fail";
    const I: &str = "indeterminate";
    const STEPS: &[(&str, &str)] = &[
        // §6.2 step 2
        ("source-screening-residency-absent", I),
        // §6.3, a pointer through a member that is not an object (Q7-05 S4)
        ("export-control-boundary-not-an-object", I),
        // §6.4 steps 1-3
        ("audit-integrity-root-absent", I),
        ("audit-integrity-chain-length-float-spelling", I),
        ("audit-integrity-chain-length-2-53-minus-1", P),
        ("audit-integrity-chain-length-2-53", I),
        ("audit-integrity-chain-length-2-53-plus-1", I),
        ("audit-integrity-chain-length-1e21", I),
        ("audit-integrity-chain-length-zero", P),
        ("audit-integrity-chain-length-minus-zero", I),
        // §6.4 step 4, require_input_committed
        ("audit-integrity-input-count-minus-zero", I),
        ("audit-integrity-input-committed-pass", P),
        ("audit-integrity-input-committed-fail-no-input", F),
        ("audit-integrity-input-committed-fail-empty-tree-root", F),
        ("audit-integrity-input-committed-count-wrong-type", I),
        ("audit-integrity-input-count-above-2-53", I),
        // §6.4 step 5, require_ordered_record
        ("audit-integrity-ordered-record-pass", P),
        ("audit-integrity-ordered-record-fail-training-ends-before-it-starts", F),
        ("audit-integrity-ordered-record-fail-collection-ends-before-it-starts", F),
        ("audit-integrity-ordered-record-fail-training-ends-after-issuance", F),
        ("audit-integrity-ordered-record-not-a-timestamp", I),
        // §6.4 step 6, require_verified_lineage, in every context
        ("audit-integrity-verified-lineage-initial-pass", P),
        ("audit-integrity-verified-lineage-complete-pass", P),
        ("audit-integrity-verified-lineage-partial", I),
        ("audit-integrity-verified-lineage-not-checked", I),
        ("audit-integrity-verified-lineage-no-context", I),
        ("context-initial-on-an-initial-record-adds-nothing", P),
        ("context-initial-on-a-successor-is-not-read", I),
        ("context-complete-on-a-chain-of-one-is-not-read", P),
        // §6.5 step 1
        ("execution-integrity-state-hash-absent", I),
        ("execution-integrity-components-empty", I),
        ("execution-integrity-component-not-an-object", I),
        ("execution-integrity-size-absent", I),
        ("execution-integrity-size-above-2-53", I),
        ("execution-integrity-size-minus-zero", I),
        // §6.5 steps 2-3: the empty string against absent against wrong-typed
        ("execution-integrity-training-software-empty", F),
        ("execution-integrity-training-software-absent", I),
        ("execution-integrity-training-software-wrong-type", I),
        ("execution-integrity-software-hash-empty", F),
        ("execution-integrity-software-hash-absent", I),
        ("execution-integrity-software-hash-wrong-type", I),
        ("execution-integrity-software-hash-not-a-hash", F),
        ("execution-integrity-mixed-case-hash", P),
        ("execution-integrity-no-tee", F),
        ("execution-integrity-tee-absent", I),
        ("execution-integrity-tee-wrong-type", I),
        ("execution-integrity-tee-pass", P),
        ("execution-integrity-tee-not-a-hash", F),
        // §6.5 step 4, require_state_kept
        ("execution-integrity-state-kept-pass", P),
        ("execution-integrity-state-kept-fail", F),
        ("execution-integrity-state-kept-not-checked", I),
        ("execution-integrity-state-kept-not-a-keeping-step", P),
        ("execution-integrity-state-kept-no-context", I),
        // Task 10.12a (D12a-3, D12a-4, D12a-5): the countries, a declared
        // withholding, and the model kept by model_hash
        ("general-residency-countries-data-residency", P),
        ("general-residency-countries-data-residency-fail", F),
        ("data-residency-countries-not-a-list-of-codes", I),
        ("general-residency-countries-source-screening-pass", P),
        ("general-residency-countries-source-screening-fail", F),
        ("general-not-held-input-committed", F),
        ("general-not-held-tamper-evident", F),
        ("general-not-disclosed-input-committed", F),
        ("audit-integrity-disclosure-wrong-type", P),
        ("general-deployment-other-components-model-kept", P),
        ("general-deployment-model-hash-changed", F),
        // §6.6
        ("attestation-level-hardware-pass", P),
        ("attestation-level-self-below-software", F),
        // RFC 8785 (QA Q7-01)
        ("execution-integrity-training-software-non-ascii", P),
        ("execution-integrity-components-member-order", I),
        ("attestation-level-pack-text-non-ascii", P),
        // §6.7 documentation_declared (task 10.11a, D11-4): steps 1-5 for
        // each document, an absent member failing while a null one abstains
        // (§5), and a hash in either case.
        ("documentation-declared-data-governance-pass", P),
        ("documentation-declared-human-oversight-pass", P),
        ("documentation-declared-data-governance-absent", F),
        ("documentation-declared-human-oversight-absent", F),
        ("documentation-declared-other-document-only", F),
        ("documentation-declared-not-an-object-record", I),
        ("documentation-declared-null", I),
        ("documentation-declared-not-an-object", I),
        ("documentation-declared-hash-missing", I),
        ("documentation-declared-hash-empty", I),
        ("documentation-declared-hash-wrong-type", I),
        ("documentation-declared-hash-not-a-hash", F),
        ("documentation-declared-upper-case-hash", P),
        // QA QT-03: §5's "A hash" at its edges (the prefix's case, 63 and 65
        // digits, surrounding white space, digits that are not ASCII, mixed
        // case), and §6.7 step 3 reading no member but documentation_hash.
        ("documentation-declared-hash-prefix-upper-case", F),
        ("documentation-declared-hash-63-digits", F),
        ("documentation-declared-hash-65-digits", F),
        ("documentation-declared-hash-trailing-newline", F),
        ("documentation-declared-hash-leading-space", F),
        ("documentation-declared-hash-fullwidth-digits", F),
        ("documentation-declared-mixed-case-hash", P),
        ("documentation-declared-extra-member", P),
    ];
    let all = cases();
    let find = |id: &str| all.iter().find(|c| c["id"] == id).unwrap_or_else(|| panic!("no case {id}"));
    let evidence = |id: &str| find(id)["expected"]["results"][0]["evidence_hash"].clone();
    let (mut missing, mut wrong) = (Vec::new(), Vec::new());
    for (id, status) in STEPS {
        match all.iter().find(|c| c["id"] == *id) {
            None => missing.push(*id),
            Some(case) => {
                let results = case["expected"]["results"].as_array().unwrap();
                if results.len() != 1 || results[0]["status"] != *status {
                    wrong.push(format!("{id} (expected one rule, {status})"));
                }
            }
        }
    }
    assert!(
        missing.is_empty() && wrong.is_empty(),
        "{} of {} step outcomes have no case: {missing:?}; {} do not reach their status: {wrong:?}",
        missing.len(),
        STEPS.len(),
        wrong.len()
    );

    // §5: the evaluation time enters no status and no evidence hash.
    let (first, later) = (find("time-independence-first"), find("time-independence-later"));
    assert_ne!(first["evaluation_time"], later["evaluation_time"]);
    assert_eq!(first["expected"]["results"], later["expected"]["results"], "the same results at another time");
    for case in [first, later] {
        assert_eq!(case["expected"]["policy_compliance"]["evaluated_at"], case["evaluation_time"], "{}", case["id"]);
    }
    // §7: 2^53 and 2^53 + 1 share one evidence hash (Q7-05 S2), and a
    // context that does not apply is not hashed.
    assert_eq!(evidence("audit-integrity-chain-length-2-53"), evidence("audit-integrity-chain-length-2-53-plus-1"));
    // A number written -0 is not a count, and JCS writes its evidence as 0
    // (QA Q7-12, Q7-13 S11): each -0 case has its 0 twin's evidence hash and
    // another status.
    for (minus_zero, zero) in [
        ("audit-integrity-chain-length-minus-zero", "audit-integrity-chain-length-zero"),
        ("audit-integrity-input-count-minus-zero", "audit-integrity-input-committed-fail-no-input"),
        ("execution-integrity-size-minus-zero", "execution-integrity-fail-zero-size"),
    ] {
        assert_eq!(evidence(minus_zero), evidence(zero), "{minus_zero} and {zero}");
        assert_ne!(
            find(minus_zero)["expected"]["results"][0]["status"],
            find(zero)["expected"]["results"][0]["status"],
            "{minus_zero} and {zero}"
        );
    }
    // §6.7 and §7: a null documentation member hashes as an absent one and
    // abstains where the absent one fails; two rules naming different
    // documents carry one evidence hash and answer for their own document.
    assert_eq!(evidence("documentation-declared-null"), evidence("documentation-declared-data-governance-absent"));
    assert_ne!(
        find("documentation-declared-null")["expected"]["results"][0]["status"],
        find("documentation-declared-data-governance-absent")["expected"]["results"][0]["status"]
    );
    let both = &find("documentation-declared-two-rules-one-evidence-hash")["expected"]["results"];
    assert_eq!(both[0]["evidence_hash"], both[1]["evidence_hash"], "one evidence hash for both documents");
    assert_eq!((both[0]["status"].as_str(), both[1]["status"].as_str()), (Some(F), Some(P)));
    assert_eq!(evidence("context-initial-on-an-initial-record-adds-nothing"), evidence("audit-integrity-verified-lineage-initial-pass"));
    assert_eq!(evidence("context-complete-on-a-chain-of-one-is-not-read"), evidence("audit-integrity-verified-lineage-initial-pass"));
    assert_eq!(evidence("context-initial-on-a-successor-is-not-read"), evidence("audit-integrity-verified-lineage-no-context"));
    // Every outcome that fills the slot is replayed by a verifier.
    for outcome in ["complete", "partial", "not_checked"] {
        assert!(
            all.iter().any(|c| c["verifiable"] == true && c["context"]["lineage_outcome"] == outcome),
            "no verifiable case in a {outcome} context"
        );
    }
}

#[test]
fn the_policy_vectors_tell_rfc_8785_from_a_naive_canonical_form() {
    // QA Q7-01: a naive canonical form (serde_json's sorted, compact output,
    // and the same with non-ASCII escaped) reproduced every case, so nothing
    // pinned RFC 8785. For every rule of every case, and for every pack, this
    // recomputes the evidence value and the payload; where RFC 8785 gives the
    // committed hash, it counts the places the naive forms do not.
    const BACKSLASH: char = '\u{5c}';
    let hash = |text: &str| format_hash(&sha256(text.as_bytes()));
    let naive = |v: &Value| serde_json::to_string(v).unwrap();
    let escaped = |v: &Value| {
        let mut out = String::new();
        for c in naive(v).chars() {
            if c.is_ascii() {
                out.push(c);
            } else {
                for unit in c.encode_utf16(&mut [0; 2]) {
                    out.push_str(&format!("{BACKSLASH}u{unit:04x}"));
                }
            }
        }
        out
    };
    let (mut naive_evidence, mut escaped_verifiable_evidence, mut escaped_payload) = (Vec::new(), Vec::new(), Vec::new());
    for case in cases() {
        let id = case["id"].as_str().unwrap().to_string();
        let record: Value = serde_json::from_str(text(&case, "record")).unwrap();
        let context = context(&case);
        let pack: Value = serde_json::from_str(text(&case, "pack")).unwrap();
        let results = case["expected"]["results"].as_array().unwrap();
        for (rule, want) in pack["rules"].as_array().unwrap().iter().zip(results) {
            let value = vmr_policy::evidence::value_in_context(rule["type"].as_str().unwrap(), &record, context.as_ref());
            if hash(&jcs(&value)) != want["evidence_hash"] {
                continue; // not reproducible by RFC 8785: the replay test reports it
            }
            if hash(&naive(&value)) != want["evidence_hash"] {
                naive_evidence.push(id.clone());
            }
            if case["verifiable"] == true && hash(&escaped(&value)) != want["evidence_hash"] {
                escaped_verifiable_evidence.push(id.clone());
            }
        }
        let mut payload = pack.clone();
        payload.as_object_mut().unwrap().remove("signature");
        if hash(&jcs(&payload)) == case["expected"]["pack_payload_hash"]
            && hash(&escaped(&payload)) != case["expected"]["pack_payload_hash"]
        {
            escaped_payload.push(id);
        }
    }
    assert!(
        !naive_evidence.is_empty(),
        "serde_json's plain serialization reproduces every evidence hash RFC 8785 does: no case pins member order by \
         UTF-16 code units or ECMAScript number form"
    );
    assert!(
        !escaped_verifiable_evidence.is_empty(),
        "escaping non-ASCII reproduces every verifiable case's evidence hash: no verifiable record holds non-ASCII text"
    );
    assert!(
        !escaped_payload.is_empty(),
        "escaping non-ASCII reproduces every pack payload hash: no pack holds non-ASCII text"
    );
}

#[test]
fn the_signed_vector_pack_verifies_and_shares_its_unsigned_twins_payload_hash() {
    // Format document §4: the signature section is not part of what is
    // signed, so a signed pack and the same pack unsigned have one payload
    // hash, and the case's signature verifies under its documented key.
    use vmr_policy::vmr_record::sign::signing_key_from_secret;
    let all = cases();
    let find = |id: &str| all.iter().find(|c| c["id"] == id).unwrap_or_else(|| panic!("no case {id}"));
    let signed = find("signed-pack-evaluates-as-unsigned");
    let unsigned = find("attestation-level-pass");
    let pack = vmr_policy::load_pack(text(signed, "pack")).unwrap();
    assert!(pack.signature.is_some(), "the case's pack is signed");
    let key = signing_key_from_secret(&sha256(generate::PACK_KEY_LABEL)).unwrap();
    pack.verify_signature(key.verifying_key()).expect("the vector pack's signature verifies under its documented key");
    assert_eq!(signed["expected"]["pack_payload_hash"], unsigned["expected"]["pack_payload_hash"]);
    assert_eq!(signed["expected"]["results"], unsigned["expected"]["results"]);
}

#[test]
fn every_pack_loader_vector_gives_its_expected_result() {
    // docs/TASKS.md 6.16 (docs/dev/task-6.16.md A16-23): the committed
    // specs/test-vectors/policy/pack-loader.json, through vmr-policy's
    // loader. A pack that loads has the payload hash given; a refused one is
    // named by its refusal's identifier (the format document's §3).
    let doc: Value = serde_json::from_str(&read("policy/pack-loader.json")).unwrap();
    assert_eq!(doc["vector_version"], "0.1");
    let table: Vec<(u64, &str)> = doc["refusals"]
        .as_array()
        .unwrap()
        .iter()
        .map(|r| (r["number"].as_u64().unwrap(), r["id"].as_str().unwrap()))
        .collect();
    let ours: Vec<(u64, &str)> = vmr_policy::Refusal::ALL.iter().map(|r| (u64::from(r.number()), r.id())).collect();
    assert_eq!(table, ours, "the file's refusals are §3's, as vmr-policy names them");
    let (mut loaded, mut refused, mut ids) = (0usize, BTreeSet::new(), BTreeSet::new());
    for case in doc["cases"].as_array().unwrap() {
        let id = case["id"].as_str().unwrap();
        assert!(ids.insert(id), "duplicate case id {id}");
        // The pack's bytes: its text, or its hex where the bytes are not UTF-8
        // or start with a byte order mark; then its spaces.
        let mut bytes = match (case["pack"].get("text"), case["pack"].get("hex")) {
            (Some(text), None) => text.as_str().unwrap().as_bytes().to_vec(),
            (None, Some(hex)) => hex_bytes(hex.as_str().unwrap()),
            other => panic!("{id}: a pack has exactly one of text and hex: {other:?}"),
        };
        if let Some(n) = case["pack"]["append_spaces"].as_u64() {
            bytes.resize(bytes.len() + usize::try_from(n).unwrap(), b' ');
        }
        let expected = &case["expected"];
        let outcome = vmr_policy::load_pack_bytes(&bytes);
        // The loader on text gives the same answer for every text it can take
        // (the format document's §3, QA16-02).
        if let Ok(text) = std::str::from_utf8(&bytes) {
            match (&outcome, vmr_policy::load_pack(text)) {
                (Ok(by_bytes), Ok(by_text)) => assert_eq!(by_bytes.payload_hash(), by_text.payload_hash(), "{id}: load_pack"),
                (Err(by_bytes), Err(by_text)) => assert_eq!(by_bytes.refusal_id(), by_text.refusal_id(), "{id}: load_pack"),
                (by_bytes, by_text) => {
                    panic!("{id}: load_pack_bytes gives {:?}, load_pack {:?}", by_bytes.as_ref().err(), by_text.err())
                }
            }
        }
        match (expected["result"].as_str().unwrap(), outcome) {
            ("ok", Ok(pack)) => {
                assert_eq!(pack.payload_hash(), expected["pack_payload_hash"], "{id}");
                loaded += 1;
            }
            ("error", Err(e)) => {
                assert_eq!(e.refusal_id(), expected["refusal"], "{id}: {e}");
                refused.insert(e.refusal_id());
            }
            (want, got) => panic!("{id}: expected {want}, got {:?}", got.map(|p| p.payload_hash().to_string())),
        }
    }
    assert_eq!(refused.len(), vmr_policy::Refusal::ALL.len(), "a case for every refusal: {refused:?}");
    assert!(loaded >= 7, "{loaded} packs that load: one per rule type and more");
}

/// The bytes a vector's lower-case `hex` stands for.
fn hex_bytes(hex: &str) -> Vec<u8> {
    assert!(hex.len() % 2 == 0 && hex.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')), "not lower-case hex");
    (0..hex.len()).step_by(2).map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap()).collect()
}

/// Where `text` cites work outside the published documents, matched as QA
/// QC-03's fix map matches it: `\bQA\b`, `\btask [0-9]`, `\bGate [0-9]`,
/// `docs/`, `vmr/crates`, or a finding id `\b[PQ][0-9A-Z]*-[0-9]{2}\b`. The
/// first match, with what follows it.
fn internal_citation(text: &str) -> Option<String> {
    let b = text.as_bytes();
    let word = |i: usize| b.get(i).is_some_and(|c| c.is_ascii_alphanumeric() || *c == b'_');
    let digit = |i: usize| b.get(i).is_some_and(u8::is_ascii_digit);
    for i in 0..b.len() {
        let at_word = i == 0 || !word(i - 1);
        let rest = &b[i..];
        let finding_id = at_word && matches!(b[i], b'P' | b'Q') && {
            let mut j = i + 1;
            while b.get(j).is_some_and(|c| c.is_ascii_digit() || c.is_ascii_uppercase()) {
                j += 1;
            }
            b.get(j) == Some(&b'-') && digit(j + 1) && digit(j + 2) && !word(j + 3)
        };
        if rest.starts_with(b"docs/")
            || rest.starts_with(b"vmr/crates")
            || (at_word && rest.starts_with(b"QA") && !word(i + 2))
            || (at_word && (rest.starts_with(b"task ") || rest.starts_with(b"Gate ")) && digit(i + 5))
            || finding_id
        {
            return Some(String::from_utf8_lossy(&b[i..(i + 24).min(b.len())]).into_owned());
        }
    }
    None
}

/// Every `description` string in a vector file, with its JSON pointer.
fn descriptions(value: &Value, pointer: &str, out: &mut Vec<(String, String)>) {
    match value {
        Value::Object(map) => {
            for (key, member) in map {
                let here = format!("{pointer}/{key}");
                if let Some(text) = member.as_str().filter(|_| key == "description") {
                    out.push((here.clone(), text.to_string()));
                }
                descriptions(member, &here, out);
            }
        }
        Value::Array(items) => {
            for (i, item) in items.iter().enumerate() {
                descriptions(item, &format!("{pointer}/{i}"), out);
            }
        }
        _ => {}
    }
}

#[test]
fn no_vector_description_cites_internal_work() {
    // QA QC-03 (D11cd-14): a published vector says what a case is. It cites
    // no QA probe or report, no task, no gate, no repository path and no
    // finding id, none of which a reader of the published files can resolve.
    // Every description in the policy, pack-loader and pack-signature files,
    // each file's own included.
    let mut cited = Vec::new();
    for rel in ["policy/cases.json", "policy/pack-loader.json", "policy/pack-signature.json"] {
        let doc: Value = serde_json::from_str(&read(rel)).unwrap();
        let mut all = Vec::new();
        descriptions(&doc, "", &mut all);
        assert!(all.len() > 1, "{rel}: no descriptions found");
        for (pointer, text) in all {
            if let Some(hit) = internal_citation(&text) {
                cited.push(format!("{rel}{pointer}: {hit:?} in {text:?}"));
            }
        }
    }
    assert!(cited.is_empty(), "vector descriptions cite internal work:\n{}", cited.join("\n"));
}

#[test]
#[ignore = "writes specs/test-vectors/policy/; run with VMR_WRITE_VECTORS=1 to regenerate"]
#[allow(clippy::disallowed_methods)] // reading the opt-in switch is this generator's whole job
fn write_policy_vectors() {
    if std::env::var("VMR_WRITE_VECTORS").as_deref() != Ok("1") {
        eprintln!("VMR_WRITE_VECTORS is not 1: nothing written");
        return;
    }
    for (rel, contents) in generate::generate() {
        let path = specs_dir().join("test-vectors").join(rel);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, contents).unwrap();
    }
}
