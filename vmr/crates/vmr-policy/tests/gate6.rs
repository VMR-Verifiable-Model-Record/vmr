// tests/gate6.rs — Gate 6, as P6-11 defines it: the committed conformance
// vector (specs/test-vectors/record/example-v0.1.json) and the demo
// record evaluate against the EU AI Act reference pack, and both outcomes
// are recorded (here, and in the phase's handoff note).
//
// The demo record is the committed Gate 5 artifact
// (vmr/crates/vmr-cli/tests/data/gate5/model.vmr), emitted by the engine from
// the demo inputs in docs/demo/. It declared khalm-reading-eu-ai-act-2026, "indeterminate"
// and no results (QA P5-09) until task 7.6 re-emitted it with its issuer's
// evaluation of that pack (docs/dev/task-7.6.md). This file only READS it.
//
// Every expected status below is written by hand from the pack and the
// record, not read back from the evaluator.

mod common;

use common::*;
use serde_json::Value;
use vmr_policy::vmr_record::record::Record;
use vmr_policy::Status::{Fail, Pass};
use vmr_policy::{Evaluation, Status};

/// The Gate 5 artifact, which is the demo record in its COSE form.
fn demo_record() -> Value {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../vmr-cli/tests/data/gate5/model.vmr");
    let bytes = std::fs::read(&path).unwrap_or_else(|e| panic!("{}: {e}", path.display()));
    let record = Record::from_cose(&bytes).expect("the Gate 5 artifact is a record");
    serde_json::to_value(&record).expect("a record is JSON")
}

/// (rule id, status) for every rule, in the pack's order.
fn outcomes(evaluation: &Evaluation) -> Vec<(&str, Status)> {
    evaluation.results.iter().map(|r| (r.rule_id.as_str(), r.status)).collect()
}

#[test]
fn gate6_the_conformance_vector_evaluates_against_the_eu_ai_act_pack() {
    let pack = eu_pack();
    let record = conformance_record();
    // The vector's own issued_at; an evaluation may not post-date it (P6-6).
    let evaluation = pack.evaluate(&record, at("2026-09-10T00:00:00Z"));

    assert_eq!(evaluation.pack_id, "khalm-reading-eu-ai-act-2026");
    assert_eq!(evaluation.jurisdiction, "eu");
    assert_eq!(
        outcomes(&evaluation),
        [
            // lineage_chain_length 1 >= 1, the Merkle root parses, and an
            // initial record has no predecessor to link.
            ("eu-ai-act-record-keeping", Pass),
            // learned_state_hash and the three components all parse, with
            // sizes 8192, 16384 and 512.
            ("eu-ai-act-accuracy-robustness", Pass),
            // training_software "0.1.0" and software_hash sha256:74c309cc... .
            ("eu-ai-act-technical-documentation", Pass),
            // issuer.attestation_level "software" >= "software".
            ("eu-ai-act-cybersecurity-attestation", Pass),
            // The vector declares neither optional documentation member,
            // which is how a record says that it pins no such document
            // (task 10.11a, D11-4): both recommended rules fail, and the
            // overall status, computed from the mandatory rules, does not
            // move.
            ("eu-ai-act-data-governance", Fail),
            ("eu-ai-act-human-oversight", Fail),
        ]
    );
    assert!(evaluation.indeterminate.is_empty());
    assert_eq!(evaluation.overall, Pass);

    let section = evaluation.to_policy_compliance();
    assert_eq!(section.policy_pack_id, "khalm-reading-eu-ai-act-2026");
    assert_eq!(section.overall_status, "compliant");
    assert_eq!(section.results.len(), 6, "no rule was indeterminate, so none is omitted");
    assert_eq!(section.evaluated_at, "2026-09-10T00:00:00Z");
}

#[test]
fn gate6_the_demo_record_evaluates_against_the_eu_ai_act_pack() {
    let pack = eu_pack();
    let record = demo_record();
    // The demo record's own issued_at.
    let evaluation = pack.evaluate(&record, at("2026-09-11T00:00:00Z"));

    assert_eq!(
        outcomes(&evaluation),
        [
            ("eu-ai-act-record-keeping", Pass),
            ("eu-ai-act-accuracy-robustness", Pass),
            // training_software "khalm-tlm 0.1.0", and since task 7.6 a
            // software_hash: the SHA-256 of docs/demo/software-environment.json.
            // Before, the demo signed "" there, which is what an issuer signs
            // to say "none" (P6-17, E2), and this rule failed.
            ("eu-ai-act-technical-documentation", Pass),
            ("eu-ai-act-cybersecurity-attestation", Pass),
            // Task 7.6 pins docs/demo/data-governance.md by hash, and no
            // human oversight document (task 10.11a, D11-7): the governance
            // rule passes, and the oversight rule fails.
            ("eu-ai-act-data-governance", Pass),
            ("eu-ai-act-human-oversight", Fail),
        ]
    );
    assert!(evaluation.indeterminate.is_empty());
    // Only mandatory rules decide the overall status, and all three pass.
    assert_eq!(evaluation.overall, Pass);
    let detail = &evaluation.result("eu-ai-act-human-oversight").unwrap().detail;
    assert!(detail.contains("pins no human oversight documentation"), "{detail}");

    let section = evaluation.to_policy_compliance();
    assert_eq!(section.overall_status, "compliant");
    let carried: Vec<&str> = section.results.iter().map(|r| r.rule_id.as_str()).collect();
    assert_eq!(
        carried,
        [
            "eu-ai-act-record-keeping",
            "eu-ai-act-accuracy-robustness",
            "eu-ai-act-technical-documentation",
            "eu-ai-act-cybersecurity-attestation",
            "eu-ai-act-data-governance",
            "eu-ai-act-human-oversight"
        ],
        "every rule was decided, so every result is carried (P6-1)"
    );
}

#[test]
fn gate6_the_demo_record_declares_what_the_eu_ai_act_pack_finds() {
    // P6-11 kept the Gate 5 artifact, declaring khalm-reading-eu-ai-act-2026 /
    // indeterminate / no results (QA P5-09), through Phase 6. Task 7.6
    // re-emitted it with its issuer's evaluation of this pack, made at the
    // record's own issued_at (docs/dev/task-7.6.md §4). Evaluated again at
    // that time, the pack gives exactly the section the record declares,
    // every evidence hash included.
    let record = demo_record();
    let declared = &record["policy_compliance"];
    assert_eq!(declared["policy_pack_id"], "khalm-reading-eu-ai-act-2026");
    assert_eq!(declared["overall_status"], "compliant");
    assert_eq!(declared["results"].as_array().map(Vec::len), Some(6));
    assert_eq!(record["issued_at"], "2026-09-11T00:00:00Z");
    let evaluation = eu_pack().evaluate(&record, at("2026-09-11T00:00:00Z"));
    assert_eq!(&serde_json::to_value(evaluation.to_policy_compliance()).unwrap(), declared);
    // And the relation P6-6 settled holds in the committed artifact.
    assert!(
        declared["evaluated_at"].as_str().unwrap() <= record["issued_at"].as_str().unwrap(),
        "evaluated_at must not post-date issued_at"
    );
}

#[test]
fn gate6_every_reference_pack_answers_both_records() {
    // Not required by the gate, but the five packs are shipped together: a
    // pack that panicked or returned nothing on a real record would be
    // found here rather than by its first reader.
    for pack_id in REFERENCE_PACKS {
        let pack = reference_pack(pack_id);
        for (what, record, t) in [
            ("conformance vector", conformance_record(), "2026-09-10T00:00:00Z"),
            ("demo record", demo_record(), "2026-09-11T00:00:00Z"),
        ] {
            let evaluation = pack.evaluate(&record, at(t));
            assert_eq!(evaluation.results.len(), pack.rules.len(), "{pack_id} on the {what}");
            assert!(
                evaluation.results.iter().all(|r| !r.evidence_hash.is_empty()),
                "{pack_id} on the {what}"
            );
            // Where either record fails a rule of a reference pack, it is
            // because it signed an empty environment member (P6-17, E2):
            // both records' tee_measurement (and, before task 7.6, the
            // demo's software_hash); or because it declares no documentation
            // member the EU pack asks for (task 10.11a, D11-4): neither on the
            // conformance vector, no human oversight document on the demo.
            // Nothing else they declare breaks a rule.
            for result in &evaluation.results {
                let empty_member = result.detail.contains(" is empty: ");
                let no_document =
                    result.rule_type == "documentation_declared" && result.detail.contains("declares that it pins no");
                assert!(
                    result.status != Status::Fail || empty_member || no_document,
                    "{pack_id}/{} on the {what}: {}",
                    result.rule_id,
                    result.detail
                );
            }
        }
    }
}
