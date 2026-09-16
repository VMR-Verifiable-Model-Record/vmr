//! The KHALM-VMR adapter for the open VMR conformance test
//! (`specs/conformance/README.md`, task 10.12c): one request (JSON) on standard
//! input, one answer on standard output, through the Community libraries
//! vmr-verify, vmr-record and vmr-policy. It speaks the same protocol as any
//! other implementation's adapter; the runner gives it nothing it gives no one
//! else.
//!
//! ```text
//! cargo build --offline --locked -p vmr-cli --example conformance_adapter
//! VMR_CONFORMANCE_ADAPTER=<target>/debug/examples/conformance_adapter \
//!   python specs/conformance/run.py vmr/crates/vmr-cli/examples/conformance_adapter.json
//! ```

use std::io::{Read, Write};

use serde_json::{json, Map, Value};
use vmr_cli::policy_pack::{NOT_CHECKED_REFUSED, UNSIGNED_REFUSED};
use vmr_cli::verify_cmd::{AUTHORITY_STORE_ISSUERS, AUTHORITY_STORE_ISSUER_KEY};
use vmr_policy::{EvaluationContext, LineageContext, LineageOutcome, VerifiedPredecessor};
use vmr_record::encoding::b64url_decode;
use vmr_record::hash::{format_hash, sha256};
use vmr_record::merkle::MerkleStream;
use vmr_record::named_set::{member_encoding, validate_name, NameError, NamedSetDigest};
use vmr_record::record::{JwkPublicKey, SignatureSection};
use vmr_record::sign::{sign, signing_key_from_secret};
use vmr_record::timestamp::Timestamp;
use vmr_record::Record;
use vmr_verify::report::Verdict;
use vmr_verify::{TrustStore, Verifier, VerifyOptions};

type Answer = Result<Value, String>;
type Member = (String, [u8; 32]);

fn main() {
    let mut request = Vec::new();
    let answer = match std::io::stdin().read_to_end(&mut request) {
        Err(e) => json!({ "adapter_error": format!("cannot read standard input: {e}") }),
        Ok(_) => match serde_json::from_slice::<Value>(&request) {
            Err(e) => json!({ "adapter_error": format!("the request is not JSON: {e}") }),
            Ok(request) => answer(&request).unwrap_or_else(|e| json!({ "adapter_error": e })),
        },
    };
    let _ = writeln!(std::io::stdout().lock(), "{answer}");
}

fn answer(request: &Value) -> Answer {
    let input = &request["input"];
    match request["operation"].as_str().unwrap_or("") {
        "record.verify" => verify(input),
        "record.signed_payload" => signed_payload(input),
        "trust_store.load" => Ok(trust_store_load(&bytes(&input["store"])?)),
        "model_hash" => model_hash(input),
        "record.issue" => issue(input),
        "policy.evaluate" => policy_evaluate(input),
        "policy_pack.load" => Ok(pack_load(&bytes(&input["pack"])?)),
        "policy_pack.signature" => pack_signature(input),
        other => Ok(json!({ "unsupported": true, "reason": format!("no operation {other:?}") })),
    }
}

fn text<'a>(v: &'a Value, what: &str) -> Result<&'a str, String> {
    v.as_str().ok_or_else(|| format!("no {what}"))
}

fn bytes(v: &Value) -> Result<Vec<u8>, String> {
    let hex = text(&v["bytes_hex"], "bytes_hex")?;
    if hex.len() % 2 != 0 {
        return Err("bytes_hex has an odd length".into());
    }
    (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(hex.get(i..i + 2).ok_or("bytes_hex is not ASCII")?, 16).map_err(|e| e.to_string()))
        .collect()
}

fn utf8(data: Vec<u8>) -> Result<String, String> {
    String::from_utf8(data).map_err(|e| e.to_string())
}

fn time(v: &Value) -> Result<Timestamp, String> {
    let t = text(v, "evaluation_time")?;
    Timestamp::parse(t).map_err(|_| format!("evaluation_time {t:?} is not a timestamp"))
}

fn verify(input: &Value) -> Answer {
    let store = TrustStore::from_json(&bytes(&input["trust_store"])?)
        .map_err(|e| format!("the trust store is refused: {}", e.kind.id()))?;
    let record = bytes(&input["record"])?;
    let previous =
        input["previous"].as_array().ok_or("no previous")?.iter().map(bytes).collect::<Result<Vec<_>, _>>()?;
    let refs: Vec<&[u8]> = previous.iter().map(Vec::as_slice).collect();
    let require = input["require_complete_lineage"].as_bool().ok_or("no require_complete_lineage")?;
    let opts = VerifyOptions::new(time(&input["evaluation_time"])?).with_previous(&refs).require_complete_lineage(require);
    let verifier = Verifier::new(store);
    let report = match text(&input["record"]["form"], "form")? {
        "json" => verifier.verify_json(&record, &opts),
        "cose" => verifier.verify_cose(&record, &opts),
        other => return Err(format!("form {other:?}")),
    };
    let lineage = match &report.lineage {
        Some(l) => serde_json::to_value(l.status).map_err(|e| e.to_string())?,
        None => Value::Null,
    };
    Ok(json!({
        "verdict": match report.verdict { Verdict::Pass => "pass", Verdict::Fail => "fail" },
        "check": report.failure.as_ref().map(|f| f.check.id()),
        "lineage": lineage,
    }))
}

fn signed_payload(input: &Value) -> Answer {
    let record = Record::from_json(&utf8(bytes(&input["record"])?)?).map_err(|e| e.to_string())?;
    Ok(json!({
        "signed_payload": utf8(record.signed_payload().map_err(|e| e.to_string())?)?,
        "signed_payload_hash": record.signed_payload_hash().map_err(|e| e.to_string())?,
        "key_id": record.issuer.public_key.key_id(),
    }))
}

fn trust_store_load(data: &[u8]) -> Value {
    match TrustStore::from_json(data) {
        Ok(store) => json!({ "result": "ok", "sha256": store.sha256() }),
        Err(e) => json!({ "result": "error", "kind": e.kind.id() }),
    }
}

fn reason_id(e: NameError) -> &'static str {
    match e {
        NameError::Empty => "empty",
        NameError::EmptySegment => "empty-segment",
        NameError::DotSegment => "dot-segment",
        NameError::DotDotSegment => "dotdot-segment",
        NameError::NotAscending => "not-ascending",
    }
}

fn members(v: &Value) -> Result<Vec<Member>, String> {
    v.as_array()
        .ok_or("no members")?
        .iter()
        .map(|m| Ok((text(&m["name"], "name")?.to_string(), sha256(&bytes(m)?))))
        .collect()
}

fn digest(members: &[Member]) -> Result<String, String> {
    let mut d = NamedSetDigest::new();
    for (name, hash) in members {
        d.push(name, hash).map_err(|e| reason_id(e).to_string())?;
    }
    Ok(format_hash(&d.finish()))
}

fn merkle_root(members: &[Member]) -> String {
    let mut stream = MerkleStream::new();
    for (name, hash) in members {
        stream.push(&member_encoding(name, hash));
    }
    format_hash(&stream.finish())
}

fn model_hash(input: &Value) -> Answer {
    match text(&input["kind"], "kind")? {
        "named-set-digest" => Ok(json!({ "digest": digest(&members(&input["members"])?)? })),
        "named-set-digests" => {
            let mut out = Map::new();
            for (set, m) in input["sets"].as_object().ok_or("no sets")? {
                out.insert(set.clone(), json!(digest(&members(m)?)?));
            }
            Ok(Value::Object(out))
        }
        "name" => Ok(match validate_name(text(&input["name"], "name")?) {
            Ok(()) => json!({ "accepted": true, "reason": null }),
            Err(e) => json!({ "accepted": false, "reason": reason_id(e) }),
        }),
        "set-refused" => {
            let mut d = NamedSetDigest::new();
            for (i, name) in input["names"].as_array().ok_or("no names")?.iter().enumerate() {
                let name = text(name, "name")?;
                if let Err(e) = d.push(name, &sha256(name.as_bytes())) {
                    return Ok(json!({ "refused_at": i, "reason": reason_id(e) }));
                }
            }
            Ok(json!({ "refused_at": null, "reason": null }))
        }
        "named-set-records" => {
            let m = members(&input["members"])?;
            Ok(json!({
                "training_input_count": m.len(),
                "training_input_digest": digest(&m)?,
                "training_input_merkle_root": merkle_root(&m),
            }))
        }
        other => Ok(json!({ "unsupported": true, "reason": format!("no model-hash kind {other:?}") })),
    }
}

/// A record of the general description (spec §7.3) from the declared members,
/// the files and the key.
fn issue(input: &Value) -> Answer {
    let secret: [u8; 32] = b64url_decode(text(&input["signing_key"]["d"], "signing_key.d")?)
        .map_err(|e| e.to_string())?
        .try_into()
        .map_err(|_| "signing_key.d is not 32 bytes".to_string())?;
    let key = signing_key_from_secret(&secret).map_err(|e| e.to_string())?;
    let jwk = JwkPublicKey::from_verifying_key(key.verifying_key());
    let key_id = jwk.key_id();

    let mut files = input["model_files"]
        .as_array()
        .ok_or("no model_files")?
        .iter()
        .map(|f| Ok((text(&f["name"], "name")?.to_string(), bytes(f)?)))
        .collect::<Result<Vec<(String, Vec<u8>)>, String>>()?;
    files.sort_by(|a, b| a.0.cmp(&b.0));
    let every_file: Vec<Member> = files.iter().map(|(n, b)| (n.clone(), sha256(b))).collect();
    let mut names = input["learned_state_components"]
        .as_array()
        .ok_or("no learned_state_components")?
        .iter()
        .map(|n| text(n, "component name"))
        .collect::<Result<Vec<_>, _>>()?;
    names.sort_unstable();
    let (mut components, mut state) = (Vec::new(), Vec::new());
    for name in names {
        let (_, data) = files.iter().find(|(n, _)| n == name).ok_or_else(|| format!("no file named {name:?}"))?;
        let hash = sha256(data);
        components.push(json!({ "name": name, "hash": format_hash(&hash), "size_bytes": data.len() }));
        state.push((name.to_string(), hash));
    }

    let mut record = input["declared"].clone();
    let identity = record["model_identity"].as_object_mut().ok_or("no model_identity")?;
    identity.insert("learned_state_components".into(), Value::Array(components));
    identity.insert("learned_state_hash".into(), json!(digest(&state)?));
    identity.insert("model_hash".into(), json!(digest(&every_file)?));
    let provenance = record["learning_provenance"].as_object_mut().ok_or("no learning_provenance")?;
    let (count, training_digest, root) = match &input["training_records"] {
        Value::Null if provenance.get("training_input_disclosure") == Some(&json!("not-held")) => {
            (0, String::new(), String::new())
        }
        Value::Null => return Err("training_records null for a disclosure other than not-held".into()),
        records => {
            let m = members(records)?;
            (m.len(), digest(&m)?, merkle_root(&m))
        }
    };
    provenance.insert("training_input_count".into(), json!(count));
    provenance.insert("training_input_digest".into(), json!(training_digest));
    provenance.insert("training_input_merkle_root".into(), json!(root));
    let issuer = record["issuer"].as_object_mut().ok_or("no issuer")?;
    issuer.insert("public_key".into(), serde_json::to_value(&jwk).map_err(|e| e.to_string())?);
    issuer.insert("key_id".into(), json!(key_id));
    record.as_object_mut().ok_or("declared is not an object")?.insert(
        "signature".into(),
        json!({ "algorithm": "ES256", "signature": "", "signed_payload_hash": "", "signing_key_id": key_id }),
    );

    let mut record = Record::from_json(&record.to_string()).map_err(|e| e.to_string())?;
    let signature = sign(&key, &record.signature_tbs().map_err(|e| e.to_string())?).map_err(|e| e.to_string())?;
    record.signature.signature = SignatureSection::signature_field(&signature);
    record.signature.signed_payload_hash = record.signed_payload_hash().map_err(|e| e.to_string())?;
    let text = record.to_json().map_err(|e| e.to_string())?;
    Ok(json!({ "form": "json", "bytes_hex": text.bytes().map(|b| format!("{b:02x}")).collect::<String>() }))
}

fn policy_evaluate(input: &Value) -> Answer {
    let pack = vmr_policy::load_pack(&utf8(bytes(&input["pack"])?)?)
        .map_err(|e| format!("the pack is refused: {}", e.refusal_id()))?;
    let record: Value = serde_json::from_slice(&bytes(&input["record"])?).map_err(|e| e.to_string())?;
    let t = time(&input["evaluation_time"])?;
    let evaluation = match &input["context"] {
        Value::Null => pack.evaluate(&record, t),
        context => {
            let id = text(&context["lineage_outcome"], "lineage_outcome")?;
            let outcome = [LineageOutcome::Initial, LineageOutcome::Complete, LineageOutcome::Partial, LineageOutcome::NotChecked]
                .into_iter()
                .find(|o| o.id() == id)
                .ok_or_else(|| format!("lineage_outcome {id:?}"))?;
            let predecessors = context["predecessors"]
                .as_array()
                .ok_or("no predecessors")?
                .iter()
                .map(|p| {
                    Ok(VerifiedPredecessor {
                        signed_payload_hash: text(&p["signed_payload_hash"], "signed_payload_hash")?.to_string(),
                        record: serde_json::from_slice(&bytes(&p["record"])?).map_err(|e| e.to_string())?,
                    })
                })
                .collect::<Result<Vec<_>, String>>()?;
            pack.evaluate_in_context(&record, &EvaluationContext { lineage: LineageContext { outcome, predecessors } }, t)
        }
    };
    let results: Vec<Value> = evaluation
        .results
        .iter()
        .map(|r| {
            json!({
                "rule_id": r.rule_id, "rule_type": r.rule_type, "severity": r.severity.id(),
                "status": r.status.id(), "evidence_hash": r.evidence_hash,
            })
        })
        .collect();
    Ok(json!({
        "pack_payload_hash": pack.payload_hash(),
        "results": results,
        "indeterminate": evaluation.indeterminate,
        "overall": evaluation.overall.id(),
        "policy_compliance": serde_json::to_value(evaluation.to_policy_compliance()).map_err(|e| e.to_string())?,
    }))
}

fn pack_load(data: &[u8]) -> Value {
    match vmr_policy::load_pack_bytes(data) {
        Ok(pack) => json!({ "result": "ok", "pack_payload_hash": pack.payload_hash() }),
        Err(e) => json!({ "result": "error", "refusal": e.refusal_id() }),
    }
}

fn pack_signature(input: &Value) -> Answer {
    let pack_text = utf8(bytes(&input["pack"])?)?;
    let payload_hash = vmr_policy::load_pack(&pack_text).ok().map(|p| p.payload_hash().to_string());
    let mut out = Map::new();
    out.insert("pack_payload_hash".into(), json!(payload_hash));
    match pack_signature_state(input, &pack_text)? {
        Ok(state) => out.insert("pack_signature".into(), state),
        Err(refusal) => out.insert("refusal".into(), json!(refusal)),
    };
    Ok(Value::Object(out))
}

/// Trust-store format §4.2's steps, in order: `Ok(state)`, or `Err(refusal id)`.
fn pack_signature_state(input: &Value, pack_text: &str) -> Result<Result<Value, String>, String> {
    let require = input["require_signed_pack"].as_bool().ok_or("no require_signed_pack")?;
    let t = time(&input["evaluation_time"])?;
    let trust = match TrustStore::from_json(&bytes(&input["trust_store"])?) {
        Ok(store) => store,
        Err(e) => return Ok(Err(e.kind.id().to_string())),
    };
    let authorities = if input["authority_store"].is_null() {
        trust
    } else {
        let store = match TrustStore::from_json(&bytes(&input["authority_store"])?) {
            Ok(store) => store,
            Err(e) => return Ok(Err(e.kind.id().to_string())),
        };
        if store.issuer_count() > 0 {
            return Ok(Err(AUTHORITY_STORE_ISSUERS.into()));
        }
        let document = store.to_document();
        if document.policy_authorities.iter().flat_map(|a| &a.keys).any(|k| trust.lookup(&k.key_id).is_some()) {
            return Ok(Err(AUTHORITY_STORE_ISSUER_KEY.into()));
        }
        store
    };
    let pack = match vmr_policy::load_pack(pack_text) {
        Ok(pack) => pack,
        Err(e) => return Ok(Err(e.refusal_id().to_string())),
    };
    let Some(section) = &pack.pack().signature else {
        return Ok(if require { Err(UNSIGNED_REFUSED.into()) } else { Ok(json!({ "state": "unsigned" })) });
    };
    if let Err(e) = pack.check_payload_hash() {
        return Ok(Err(e.refusal_id().to_string()));
    }
    let Some(key) = authorities.lookup_authority(&section.signing_key_id) else {
        return Ok(if require {
            Err(NOT_CHECKED_REFUSED.into())
        } else {
            Ok(json!({ "state": "not_checked", "signing_key_id": section.signing_key_id }))
        });
    };
    if let Err(e) = pack.verify_signature(key.verifying_key) {
        return Ok(Err(e.refusal_id().to_string()));
    }
    if let Err(refusal) = key.may_sign_for(&pack.authority.authority_id, t) {
        return Ok(Err(refusal.id().to_string()));
    }
    Ok(Ok(json!({
        "state": "valid",
        "signing_key_id": section.signing_key_id,
        "authority_id": key.authority_id,
        "authority_name": key.authority_name,
    })))
}
