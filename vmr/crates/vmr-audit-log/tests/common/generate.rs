// tests/common/generate.rs — the audit-log vector generator (task 10.13).
//
// It writes specs/test-vectors/audit-log/cases.json: a fixed environment (a
// two-entry log and a signed checkpoint) and cases whose expected result is
// declared BY HAND, with every signed byte computed from the derived test
// keys. The cases of the four moved sections are the sovereignty vectors'
// (task 10.13's split), byte for byte; the rest were added with this crate.
//
//   VMR_WRITE_VECTORS=1 cargo test -p vmr-audit-log --test vectors -- --ignored

use super::*;
use serde_json::{json, Value};
use vmr_audit_log::vmr_record::hash::{format_hash, sha256};
use vmr_audit_log::{checkpoint, proof};

/// The relative path (under specs/test-vectors/) and the bytes of every vector
/// file this generator owns.
pub fn generate() -> Vec<(String, String)> {
    let value = build();
    let mut text = serde_json::to_string_pretty(&value).unwrap();
    text.push('\n');
    vec![("audit-log/cases.json".to_string(), text)]
}

fn signed_checkpoint(log: &vmr_audit_log::log::LogBuilder, at: &str) -> Value {
    checkpoint::build_signed(log.log_id(), log.len(), &log.root(), t(at), &key(AUDIT_KEY)).unwrap()
}

fn build() -> Value {
    let (log, log_lines) = seeded_log();
    let (inclusion_proofs, consistency_proofs) = build_proof_cases();
    let checkpoint_doc = signed_checkpoint(&log, "2026-09-14T09:50:00Z");
    let good = file_of(&log_lines);

    // --- log cases (moved from the sovereignty vectors, unchanged) ---
    let flip_first = {
        let mut lines = log_lines.clone();
        // reserialise line 0 with whitespace: valid JSON, not JCS.
        let v: Value = serde_json::from_str(&lines[0]).unwrap();
        lines[0] = serde_json::to_string_pretty(&v).unwrap().replace('\n', " ");
        lines.join("\n") + "\n"
    };
    let swapped = {
        let mut lines = log_lines.clone();
        lines.swap(0, 1);
        lines.join("\n") + "\n"
    };
    let wrong_prev = {
        let mut lines = log_lines.clone();
        let mut v: Value = serde_json::from_str(&lines[1]).unwrap();
        v["previous_root"] = json!(format_hash(&sha256(b"not the root")));
        lines[1] = vmr_audit_log::vmr_record::canonical::jcs(&v);
        lines.join("\n") + "\n"
    };
    let torn = good.clone() + "{\"log_version\":\"0.1\",\"index\":2,\"partial";
    let repeated_in_line = {
        let mut lines = log_lines.clone();
        lines[0] = lines[0].replacen('{', "{\"index\":0,", 1);
        lines.join("\n") + "\n"
    };
    let logs = json!([
        { "id": "log-ok", "description": "a valid two-entry log", "raw": good, "expect": "accept" },
        { "id": "log-not-canonical", "description": "a line that is not JCS", "raw": flip_first, "expect": "audit_entry.not_canonical" },
        { "id": "log-swapped", "description": "two lines swapped", "raw": swapped, "expect": "audit_log.index" },
        { "id": "log-wrong-previous-root", "description": "a wrong previous_root", "raw": wrong_prev, "expect": "audit_log.previous_root" },
        { "id": "log-torn-tail", "description": "a torn last line", "raw": torn, "expect": "audit_log.torn_tail" },
        { "id": "log-repeated-member", "description": "a line repeats a member: not the JCS form of its JSON (§2 rule 4, §4.4 row 3)", "raw": repeated_in_line, "expect": "audit_entry.not_canonical" },
    ]);

    json!({
        "vector_version": "0.1",
        "note": "VMR audit-log vectors (audit-log format v0.1). Keys are derived from fixed labels, for tests only. The environment (a two-entry log of the khalm-vmr.enforcer profile and a signed checkpoint) is fixed; each case's expected result was declared by hand and every signed byte computed. A case with a profile member is for a reader that has that profile; the others are the core's. Regenerate with VMR_WRITE_VECTORS=1 cargo test -p vmr-audit-log --test vectors -- --ignored.",
        "environment": {
            "audit_key_id": key_id(AUDIT_KEY),
            "log_lines": log_lines,
            "checkpoint": checkpoint_doc,
        },
        "logs": logs,
        "entries": build_entry_cases(&log_lines),
        "checkpoints": build_checkpoint_cases(&checkpoint_doc),
        "inclusion_proofs": inclusion_proofs,
        "consistency_proofs": consistency_proofs,
    })
}

/// One entry read on its own (§4.4 refusals 1 to 5), under the core profile or
/// the one the case names. Added with this crate: the sovereignty vectors had
/// no entry cases.
fn build_entry_cases(log_lines: &[String]) -> Value {
    let line = &log_lines[0];
    let foreign = vmr_audit_log::vmr_record::canonical::jcs(&json!({
        "log_version": "0.1",
        "index": 0,
        "previous_root": format_hash(&vmr_audit_log::vmr_record::merkle::empty_root()),
        "recorded_at": "2026-09-14T09:30:00Z",
        "kind": "acme.request_denied",
        "detail": { "why": "another vendor's kind, of another vendor's profile" },
    }));
    let bad_kind = foreign.replace("acme.request_denied", "Request.Denied");
    let no_dot = foreign.replace("acme.request_denied", "started");
    let detail_not_object = vmr_audit_log::vmr_record::canonical::jcs(&json!({
        "log_version": "0.1",
        "index": 0,
        "previous_root": format_hash(&vmr_audit_log::vmr_record::merkle::empty_root()),
        "recorded_at": "2026-09-14T09:30:00Z",
        "kind": "acme.request_denied",
        "detail": 3,
    }));
    let unknown_member = {
        // canonical, so the line is refused for its member, not its form
        let mut v: Value = serde_json::from_str(line).unwrap();
        v["log"] = json!("other");
        vmr_audit_log::vmr_record::canonical::jcs(&v)
    };
    let version = line.replace("\"log_version\":\"0.1\"", "\"log_version\":\"0.2\"");
    let oversize = format!("{}{}", "x".repeat(65537), "");
    let broken = line.replacen('}', "", 1);
    let started_without_model = {
        let mut v: Value = serde_json::from_str(line).unwrap();
        v["detail"].as_object_mut().unwrap().remove("model_hash");
        vmr_audit_log::vmr_record::canonical::jcs(&v)
    };
    json!([
        { "id": "entry-accept", "description": "the environment's first entry, read under the core profile", "raw": line, "expect": "accept" },
        { "id": "entry-accept-foreign-kind", "description": "a kind of a profile this reader does not have: the core accepts every kind its grammar allows (§5.1)", "raw": foreign, "expect": "accept" },
        { "id": "entry-kind-not-lower-case", "description": "a kind that breaks §4.1's grammar", "raw": bad_kind, "expect": "audit_entry.structure" },
        { "id": "entry-kind-one-label", "description": "a kind of one label: §4.1 needs two or more", "raw": no_dot, "expect": "audit_entry.structure" },
        { "id": "entry-detail-not-object", "description": "detail is a number (§4.1)", "raw": detail_not_object, "expect": "audit_entry.structure" },
        { "id": "entry-unknown-member", "description": "an entry member this format does not name (§2 rule 4)", "raw": unknown_member, "expect": "audit_entry.structure" },
        { "id": "entry-version", "description": "log_version is not \"0.1\" (§4.4 row 4)", "raw": version, "expect": "audit_entry.version" },
        { "id": "entry-size", "description": "a line longer than 65 536 bytes, refused before it is parsed (§4.4 row 1)", "raw": oversize, "expect": "audit_entry.size" },
        { "id": "entry-syntax", "description": "a line that is not JSON (§4.4 row 2)", "raw": broken, "expect": "audit_entry.syntax" },
        { "id": "profile-entry-accept", "description": "the environment's first entry under the profile that wrote it", "profile": "khalm-vmr.enforcer", "raw": line, "expect": "accept" },
        { "id": "profile-entry-unknown-kind", "description": "a kind the khalm-vmr.enforcer profile does not know: the core accepts it, the profile does not (§5)", "profile": "khalm-vmr.enforcer", "raw": foreign, "expect": "audit_entry.structure" },
        { "id": "profile-entry-detail-missing-member", "description": "an enforcer.started without model_hash (§5.2)", "profile": "khalm-vmr.enforcer", "raw": started_without_model, "expect": "audit_entry.structure" },
    ])
}

/// Checkpoints verified on their own (§6), under the environment's audit key.
/// The first three cases are the sovereignty vectors', unchanged.
fn build_checkpoint_cases(environment_checkpoint: &Value) -> Value {
    let empty_tree = vmr_audit_log::signing::sign_document(&key(AUDIT_KEY), &json!({
        "checkpoint_version": "0.1",
        "checkpoint_type": "vmr.audit-checkpoint",
        "log_id": key_id(AUDIT_KEY),
        "tree_size": 0,
        "root_hash": format_hash(&vmr_audit_log::vmr_record::merkle::empty_root()),
        "issued_at": "2026-09-14T09:50:00Z",
    })).unwrap();
    let text = serde_json::to_string(environment_checkpoint).unwrap();
    // Added with this crate: one case for each refusal of §6 no case covered.
    let stranger = {
        let mut v = environment_checkpoint.clone();
        v.as_object_mut().unwrap().remove("signature");
        v["log_id"] = json!(key_id(STRANGER_KEY));
        vmr_audit_log::signing::sign_document(&key(STRANGER_KEY), &v).unwrap()
    };
    let flipped = {
        let mut v = environment_checkpoint.clone();
        let sig = v["signature"]["signature"].as_str().unwrap().to_string();
        let last = sig.chars().last().unwrap();
        let other = if last == 'A' { 'B' } else { 'A' };
        v["signature"]["signature"] = json!(format!("{}{}", &sig[..sig.len() - 1], other));
        v
    };
    let bad_algorithm = {
        let mut v = environment_checkpoint.clone();
        v["signature"]["algorithm"] = json!("ES384");
        v
    };
    json!([
        { "id": "checkpoint-accept", "description": "the environment's checkpoint", "checkpoint": environment_checkpoint, "expect": "accept" },
        { "id": "checkpoint-empty-tree", "description": "a checkpoint the audit key signed for tree_size 0 (§6 check 5)", "checkpoint": empty_tree, "expect": "checkpoint.empty_tree" },
        { "id": "checkpoint-repeated-member", "description": "tree_size appears twice; the last is the signed checkpoint's (§2 rule 4)", "raw": text.replacen('{', "{\"tree_size\":2,", 1), "expect": "checkpoint.structure" },
        { "id": "checkpoint-size", "description": "a checkpoint larger than 16 384 bytes, refused before it is parsed (§6 check 1)", "raw": format!("{}{}", text, " ".repeat(16_385 - text.len())), "expect": "checkpoint.size" },
        { "id": "checkpoint-syntax", "description": "not JSON (§6 check 2)", "raw": text.replacen('}', "", 1), "expect": "checkpoint.syntax" },
        { "id": "checkpoint-version", "description": "checkpoint_version is not \"0.1\" (§6 check 3)", "raw": text.replace("\"checkpoint_version\":\"0.1\"", "\"checkpoint_version\":\"0.2\""), "expect": "checkpoint.version" },
        { "id": "checkpoint-signature-section", "description": "the signature names another algorithm (§6 check 6)", "checkpoint": bad_algorithm, "expect": "checkpoint.signature_section" },
        { "id": "checkpoint-wrong-key", "description": "a well-formed checkpoint of another log, signed by another key (§6 check 7)", "checkpoint": stranger, "expect": "checkpoint.wrong_key" },
        { "id": "checkpoint-signature-invalid", "description": "the last character of the signature changed (§6 check 8)", "checkpoint": flipped, "expect": "checkpoint.signature_invalid" },
    ])
}

/// The proofs (§7, §8), over a five-entry log of `events.dropped` entries. The
/// first cases of each are the sovereignty vectors', unchanged.
fn build_proof_cases() -> (Value, Value) {
    let mut log = vmr_audit_log::log::LogBuilder::new(key_id(AUDIT_KEY));
    let mut texts: Vec<String> = Vec::new();
    for i in 0..5u64 {
        texts.push(
            log.append(t("2026-09-14T10:00:00Z"), "events.dropped", json!({ "count": i + 1 }), &PROFILE)
                .unwrap()
                .canonical,
        );
    }
    let cp3 = signed_checkpoint(&log, "2026-09-14T10:10:00Z"); // tree of 5
    let incl = proof::build_inclusion_proof(log.leaves(), 2, &texts[2], &cp3, key(AUDIT_KEY).verifying_key()).unwrap();

    // A padded inclusion proof.
    let mut padded = incl.clone();
    padded["audit_path"].as_array_mut().unwrap().push(json!(format_hash(&sha256(b"x"))));
    // A moved index.
    let mut moved = incl.clone();
    moved["leaf_index"] = json!(3);
    // An altered entry.
    let mut altered = incl.clone();
    let mut e: Value = serde_json::from_str(altered["entry"].as_str().unwrap()).unwrap();
    e["detail"]["count"] = json!(999);
    altered["entry"] = json!(vmr_audit_log::vmr_record::canonical::jcs(&e));

    let incl_text = serde_json::to_string(&incl).unwrap();
    let mut inclusion = vec![
        json!({ "id": "inclusion-accept", "description": "a valid inclusion proof for leaf 2 of 5", "proof": incl, "expect": "accept" }),
        json!({ "id": "inclusion-padded", "description": "an extra path hash", "proof": padded, "expect": "audit_proof.path" }),
        json!({ "id": "inclusion-moved", "description": "the entry's index is not leaf_index", "proof": moved, "expect": "audit_proof.entry_index" }),
        json!({ "id": "inclusion-altered", "description": "an altered entry", "proof": altered, "expect": "audit_proof.path" }),
        json!({ "id": "inclusion-repeated-member", "description": "leaf_index appears twice in the proof (§2 rule 4)", "raw": incl_text.replacen('{', "{\"leaf_index\":2,", 1), "expect": "audit_proof.structure" }),
        json!({ "id": "inclusion-checkpoint-repeated-member", "description": "tree_size appears twice in the checkpoint the proof carries: the checkpoint's refusal (§2 rule 4, §7)", "raw": incl_text.replacen("\"checkpoint\":{", "\"checkpoint\":{\"tree_size\":5,", 1), "expect": "checkpoint.structure" }),
    ];
    // Added with this crate: the rows of §7 no case covered. Not §7 row 1:
    // an inclusion proof over its 262 144-byte limit would be a quarter of a
    // megabyte of padding in this file, so the crate's own test covers it
    // (tests/limits.rs), as the README says.
    let mut out_of_range = incl.clone();
    out_of_range["leaf_index"] = json!(5);
    inclusion.push(json!({ "id": "inclusion-syntax", "description": "not JSON (§7 row 2)", "raw": incl_text.replacen('}', "", 1), "expect": "audit_proof.syntax" }));
    inclusion.push(json!({ "id": "inclusion-version", "description": "proof_type is not this document's (§7 row 3)", "raw": incl_text.replace("vmr.audit-inclusion-proof", "vmr.audit-other-proof"), "expect": "audit_proof.version" }));
    inclusion.push(json!({ "id": "inclusion-index", "description": "leaf_index is not below the checkpoint's tree_size (§7 row 5)", "proof": out_of_range, "expect": "audit_proof.index" }));
    // QA QR-06: the array cap of §7 is normative, and the schema's maxItems.
    // It is read before the path is walked, so an over-long path is refused
    // for its structure, not for the root it fails to recompute.
    let over_long_path = {
        let mut v = incl.clone();
        let pad = format_hash(&sha256(b"khalm audit vectors: path padding"));
        v["audit_path"] = Value::Array(vec![json!(pad); vmr_audit_log::MAX_AUDIT_PATH_ELEMENTS + 1]);
        v
    };
    inclusion.push(json!({ "id": "inclusion-path-above-64", "description": "audit_path holds 65 hashes, above the 64 of §7: refused for its structure before the path is walked", "proof": over_long_path, "expect": "audit_proof.structure" }));

    // Consistency: from a 2-entry checkpoint to the 5-entry one, and a
    // rewritten-prefix case from a second, diverging log.
    let mut small = vmr_audit_log::log::LogBuilder::new(key_id(AUDIT_KEY));
    for i in 0..2u64 {
        small.append(t("2026-09-14T10:00:00Z"), "events.dropped", json!({ "count": i + 1 }), &PROFILE).unwrap();
    }
    let cp2 = signed_checkpoint(&small, "2026-09-14T10:05:00Z");
    let consistent = proof::build_consistency_proof(log.leaves(), &cp2, &cp3, key(AUDIT_KEY).verifying_key()).unwrap();

    // A diverging log (entry 1 = count 30), whose 2-checkpoint is not a prefix.
    let mut diverged = vmr_audit_log::log::LogBuilder::new(key_id(AUDIT_KEY));
    diverged.append(t("2026-09-14T10:00:00Z"), "events.dropped", json!({ "count": 1 }), &PROFILE).unwrap();
    diverged.append(t("2026-09-14T10:00:00Z"), "events.dropped", json!({ "count": 30 }), &PROFILE).unwrap();
    let cp2_div = signed_checkpoint(&diverged, "2026-09-14T10:05:00Z");
    let inconsistent = proof::build_consistency_proof(log.leaves(), &cp2_div, &cp3, key(AUDIT_KEY).verifying_key()).unwrap();

    let mut padded_consistency = consistent.clone();
    padded_consistency["proof"].as_array_mut().unwrap().push(json!(format_hash(&sha256(b"x"))));
    let mut truncated_consistency = consistent.clone();
    truncated_consistency["proof"].as_array_mut().unwrap().pop();
    // A checkpoint the audit key signed for 5 entries with the root of the
    // first 4, and the genuine PROOF(2, D[4]): the hashes recompute that root,
    // but the proof is one hash shorter than size 5 requires.
    let mut four = vmr_audit_log::log::LogBuilder::new(key_id(AUDIT_KEY));
    for i in 0..4u64 {
        four.append(t("2026-09-14T10:00:00Z"), "events.dropped", json!({ "count": i + 1 }), &PROFILE).unwrap();
    }
    let cp4 = signed_checkpoint(&four, "2026-09-14T10:05:00Z");
    let proof_2_4 = proof::build_consistency_proof(four.leaves(), &cp2, &cp4, key(AUDIT_KEY).verifying_key()).unwrap()["proof"].clone();
    let five_with_root_of_four = vmr_audit_log::signing::sign_document(&key(AUDIT_KEY), &json!({
        "checkpoint_version": "0.1",
        "checkpoint_type": "vmr.audit-checkpoint",
        "log_id": key_id(AUDIT_KEY),
        "tree_size": 5,
        "root_hash": format_hash(&four.root()),
        "issued_at": "2026-09-14T10:10:00Z",
    })).unwrap();
    let short = json!({
        "proof_version": "0.1",
        "proof_type": "vmr.audit-consistency-proof",
        "from": cp2,
        "to": five_with_root_of_four,
        "proof": proof_2_4,
    });
    let consistency_text = serde_json::to_string(&consistent).unwrap();
    let mut consistency = vec![
        json!({ "id": "consistency-accept", "description": "a 2-entry tree is a prefix of the 5-entry tree", "proof": consistent, "expect": "accept" }),
        json!({ "id": "consistency-diverged", "description": "a 2-entry tree that is not a prefix (a rewritten entry)", "proof": inconsistent, "expect": "audit_proof.consistency" }),
        json!({ "id": "consistency-padded", "description": "an extra hash after the proof", "proof": padded_consistency, "expect": "audit_proof.consistency" }),
        json!({ "id": "consistency-truncated", "description": "the proof's last hash removed", "proof": truncated_consistency, "expect": "audit_proof.consistency" }),
        json!({ "id": "consistency-short-for-size", "description": "to claims 5 entries with the root of the first 4 (signed by the audit key) and the proof is PROOF(2, D[4]): its hashes recompute that root, but it is one hash shorter than size 5 requires (RFC 9162 §2.1.4.2's final sn == 0)", "proof": short, "expect": "audit_proof.consistency" }),
        json!({ "id": "consistency-to-repeated-member", "description": "tree_size appears twice in the to checkpoint: the checkpoint's refusal (§2 rule 4, §8)", "raw": consistency_text.replacen("\"to\":{", "\"to\":{\"tree_size\":5,", 1), "expect": "checkpoint.structure" }),
    ];
    // Added with this crate: the rows of §8 no case covered.
    let reversed = {
        let mut v: Value = serde_json::from_str(&consistency_text).unwrap();
        let from = v["from"].clone();
        v["from"] = v["to"].clone();
        v["to"] = from;
        v
    };
    consistency.push(json!({ "id": "consistency-size", "description": "a proof larger than 32 768 bytes, refused before it is parsed (§8 with §7 row 1)", "raw": format!("{}{}", consistency_text, " ".repeat(32_769 - consistency_text.len())), "expect": "audit_proof.size" }));
    consistency.push(json!({ "id": "consistency-version", "description": "proof_type is not this document's (§8 with §7 row 3)", "raw": consistency_text.replace("vmr.audit-consistency-proof", "vmr.audit-other-proof"), "expect": "audit_proof.version" }));
    consistency.push(json!({ "id": "consistency-order", "description": "from covers more entries than to (§8 row 8)", "proof": reversed, "expect": "audit_proof.order" }));
    // QA QR-06: §8's array cap, as above.
    let over_long_proof = {
        let mut v: Value = serde_json::from_str(&consistency_text).unwrap();
        let pad = format_hash(&sha256(b"khalm audit vectors: proof padding"));
        v["proof"] = Value::Array(vec![json!(pad); vmr_audit_log::MAX_CONSISTENCY_PROOF_ELEMENTS + 1]);
        v
    };
    consistency.push(json!({ "id": "consistency-proof-above-128", "description": "proof holds 129 hashes, above the 128 of §8: refused for its structure before the proof is walked", "proof": over_long_proof, "expect": "audit_proof.structure" }));
    (Value::Array(inclusion), Value::Array(consistency))
}
