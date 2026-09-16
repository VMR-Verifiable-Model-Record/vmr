// tests/reference_packs.rs — the five committed reference packs (P6-4,
// P6-11, Gate 6). They are reference implementations of the format, so the
// bar is: every one loads and validates; every rule names the clause it
// encodes; every pack says what it is not; and no pack is written for a
// single industrial corridor.

mod common;

use common::*;
use serde_json::Value;
use vmr_policy::pack::{Rule, Severity};
use vmr_policy::vmr_record::record::Record;
use vmr_policy::{EvaluationContext, LineageContext, LineageOutcome, VerifiedPredecessor};

#[test]
fn all_five_reference_packs_load_and_validate() {
    for pack_id in REFERENCE_PACKS {
        let pack = reference_pack(pack_id);
        assert!(!pack.rules.is_empty(), "{pack_id} has no rules");
        assert_eq!(pack.version, "0.1", "{pack_id}");
        assert!(pack.payload_hash().starts_with("sha256:"), "{pack_id}");
    }
    // The directory holds these five and nothing else, so a sixth pack
    // cannot ship untested.
    let mut on_disk: Vec<String> = std::fs::read_dir(specs_dir().join("policy-packs"))
        .expect("specs/policy-packs")
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    on_disk.sort();
    let mut expected: Vec<String> =
        REFERENCE_PACKS.iter().map(|p| format!("{p}.json")).collect();
    expected.sort();
    assert_eq!(on_disk, expected);
}

#[test]
fn every_rule_of_every_reference_pack_names_a_clause() {
    // P6-4: "a rule that cannot name a clause does not belong in a reference
    // pack". A reference that is only the standard's name is not a clause,
    // so each one must carry something more specific.
    for pack_id in REFERENCE_PACKS {
        let pack = reference_pack(pack_id);
        for rule in &pack.rules {
            let c = rule.common();
            assert!(!c.reference.trim().is_empty(), "{pack_id}/{}", c.rule_id);
            assert!(
                c.reference.len() > 12,
                "{pack_id}/{}: {:?} is not specific enough to be a clause",
                c.rule_id,
                c.reference
            );
            assert!(!c.description.trim().is_empty(), "{pack_id}/{}", c.rule_id);
        }
    }
}

#[test]
fn every_reference_pack_says_it_is_not_legal_advice() {
    for pack_id in REFERENCE_PACKS {
        let pack = reference_pack(pack_id);
        let disclaimer = pack.disclaimer.to_lowercase();
        assert!(disclaimer.contains("not legal advice"), "{pack_id}: {}", pack.disclaimer);
        assert!(
            disclaimer.contains("reference implementation"),
            "{pack_id}: {}",
            pack.disclaimer
        );
    }
}

#[test]
fn every_rule_of_every_reference_pack_states_what_it_does_not_check() {
    // The owner, 2026-09-16: a rule that says only what it checks lets a
    // reader take a pass for more than it is. Every rule of a reference pack
    // says, in its own description, what a pass does not establish, so a
    // sixth pack cannot be added without one. The clause is spelled exactly
    // "Does not check:" and says something after it.
    const CLAUSE: &str = "Does not check:";
    let mut silent = Vec::new();
    for pack_id in REFERENCE_PACKS {
        let pack = reference_pack(pack_id);
        for rule in &pack.rules {
            let c = rule.common();
            match c.description.find(CLAUSE) {
                Some(at) if c.description[at + CLAUSE.len()..].trim().len() > 20 => {}
                _ => silent.push(format!("{pack_id}/{}", c.rule_id)),
            }
        }
    }
    assert!(
        silent.is_empty(),
        "these rules do not say what a pass does not establish (\"{CLAUSE} …\"): {silent:#?}"
    );
}

#[test]
fn every_reference_pack_id_names_its_author_not_the_standard_alone() {
    // The owner, 2026-09-16: a pack id that is only the standard's name reads
    // as the standard's own instrument. These are one author's reading of a
    // public document, and the id says so before any disclaimer does.
    for pack_id in REFERENCE_PACKS {
        assert!(
            pack_id.starts_with("khalm-reading-"),
            "{pack_id}: a reference pack's id names its author"
        );
        let pack = reference_pack(pack_id);
        assert_eq!(pack.pack_id, pack_id, "the id inside the pack is its file name");
    }
}

#[test]
fn no_reference_pack_claims_an_authority_it_does_not_have() {
    // A pack that named a real body as its `authority` would put words in
    // that body's mouth; these packs are this project's reading of public
    // documents, and say so.
    for pack_id in REFERENCE_PACKS {
        let pack = reference_pack(pack_id);
        assert_eq!(pack.authority.authority_id, "khalm-reference-packs", "{pack_id}");
        assert_eq!(pack.authority.authority_name, "KHALM reference packs", "{pack_id}");
    }
}

#[test]
fn no_reference_pack_is_written_for_a_single_corridor() {
    // Gate 6: "no reference to any single industrial corridor". The five
    // packs encode standards that already govern AI deployments worldwide;
    // a corridor-specific pack is one authority among many, authored
    // elsewhere.
    let forbidden = ["pax silica", "pax-silica", "new clark", "corridor", "luzon"];
    for pack_id in REFERENCE_PACKS {
        let text = pack_text(pack_id).to_lowercase();
        for word in forbidden {
            assert!(!text.contains(word), "{pack_id} mentions {word:?}");
        }
    }
}

#[test]
fn every_reference_pack_has_at_least_one_mandatory_rule() {
    // A pack of none would report "compliant" whatever the record said,
    // because the overall status is computed from the mandatory rules.
    for pack_id in REFERENCE_PACKS {
        let pack = reference_pack(pack_id);
        assert!(
            pack.rules.iter().any(|r| r.common().severity == Severity::Mandatory),
            "{pack_id} has no mandatory rule"
        );
    }
}

/// The conformance record, changed by `edit`, and still a record a
/// verifier accepts on its own members: its schema, its §7 consistency and
/// its §6.5 lineage rules all hold.
fn valid_variant(what: &str, edit: impl FnOnce(&mut Record)) -> Value {
    let mut p: Record = serde_json::from_value(conformance_record()).expect("the conformance record");
    edit(&mut p);
    p.validate_format().unwrap_or_else(|v| panic!("{what}: breaks the schema: {v}"));
    p.check_consistency().unwrap_or_else(|v| panic!("{what}: breaks §7: {v}"));
    p.check_lineage_consistency().unwrap_or_else(|v| panic!("{what}: breaks §6.5: {v}"));
    serde_json::to_value(&p).expect("a record is JSON")
}

#[test]
fn every_mandatory_rule_of_a_reference_pack_can_fail_on_a_valid_record() {
    // QA Q6-01 (the owner, 2026-09-13, option c): a mandatory rule that no
    // record a verifier accepts can fail is a restatement of verification,
    // not policy. For every mandatory rule of every reference pack, some
    // valid variant of the conformance record must fail it, in a
    // verification context where the rule reads one (P6-17).
    let mut variants: Vec<(&str, Value, Option<EvaluationContext>)> = vec![
        (
            "training ends after issuance",
            valid_variant("times", |p| p.learning_provenance.training_ended_at = Some("2026-09-11T00:00:00Z".into())),
            None,
        ),
        ("no training input", valid_variant("count", |p| p.learning_provenance.training_input_count = 0), None),
        (
            "an empty software hash",
            valid_variant("software", |p| p.learning_provenance.training_environment.software_hash = String::new()),
            None,
        ),
        ("a self attestation", valid_variant("self", |p| p.issuer.attestation_level = "self".into()), None),
        (
            "a model with no inputs",
            valid_variant("zero input", |p| {
                let m = &mut p.model_identity;
                let afferent = m.learned_state_components[0].size_bytes;
                m.learned_state_components[0].size_bytes = 0;
                *m.parameter_count.as_mut().unwrap() -= afferent;
            }),
            None,
        ),
    ];
    // A deployment whose learned state is not that of its verified immediate
    // predecessor, the conformance record itself (P6-17). In v0.1
    // model_hash is learned_state_hash, so both move.
    let predecessor: Record = serde_json::from_value(conformance_record()).expect("the conformance record");
    let deployment = valid_variant("state not kept", |p| {
        p.record_id = "urn:uuid:00000000-0000-4000-8000-00000000d001".into();
        p.lineage.lineage_type = "deployment".into();
        p.lineage.lineage_chain_length = 2;
        p.lineage.previous_record_id = Some(predecessor.record_id.clone());
        p.lineage.previous_record_hash = Some(predecessor.signature.signed_payload_hash.clone());
        p.lineage.root_record_id = predecessor.record_id.clone();
        let other = format!("sha256:{}", "d".repeat(64));
        p.model_identity.learned_state_hash = other.clone();
        p.model_identity.model_hash = other;
    });
    let verified_back_to_it = EvaluationContext {
        lineage: LineageContext {
            outcome: LineageOutcome::Complete,
            predecessors: vec![VerifiedPredecessor {
                signed_payload_hash: predecessor.signature.signed_payload_hash.clone(),
                record: conformance_record(),
            }],
        },
    };
    variants.push(("a deployment that changed its learned state", deployment, Some(verified_back_to_it)));

    let mut cannot_fail = Vec::new();
    for pack_id in REFERENCE_PACKS {
        let pack = reference_pack(pack_id);
        for rule in pack.rules.iter().filter(|r| r.common().severity == Severity::Mandatory) {
            let fails = variants.iter().any(|(_, record, context)| {
                vmr_policy::rules::evaluate_one_in_context(rule, record, context.as_ref()).status
                    == vmr_policy::Status::Fail
            });
            if !fails {
                cannot_fail.push(format!("{pack_id}/{}", rule.rule_id()));
            }
        }
    }
    assert!(cannot_fail.is_empty(), "no valid record fails these mandatory rules: {cannot_fail:#?}");
}

#[test]
fn the_eu_ai_act_pack_asks_for_art_10_and_art_14_documentation_by_recommended_rules() {
    // Task 10.11a (D11-5): two recommended documentation_declared rules,
    // each citing its article and saying what a pinned hash does not
    // establish. The claim stays "declared", never "compliant". The other
    // reference packs gain no such rule (the reviewer, 2026-09-13: Q2
    // considered and deferred).
    let pack = reference_pack("khalm-reading-eu-ai-act-2026");
    let documentation: Vec<_> = pack
        .rules
        .iter()
        .filter_map(|r| match r {
            Rule::DocumentationDeclared(d) => Some(d),
            _ => None,
        })
        .collect();
    let named: Vec<(&str, &str, &str)> =
        documentation.iter().map(|d| (d.rule_id.as_str(), d.document.as_str(), d.reference.as_str())).collect();
    assert_eq!(
        named,
        [
            ("eu-ai-act-data-governance", "data_governance", "Regulation (EU) 2024/1689 (AI Act) Art. 10(2) and Annex IV(2)(d)"),
            ("eu-ai-act-human-oversight", "human_oversight", "Regulation (EU) 2024/1689 (AI Act) Art. 14(3) and Annex IV(2)(e)"),
        ]
    );
    for d in &documentation {
        assert_eq!(d.severity, Severity::Recommended, "{}", d.rule_id);
        for phrase in ["Checks:", "Does not check:", "can be obtained", "not that it complies", "recommended rather than mandatory"] {
            assert!(d.description.contains(phrase), "{}: no {phrase:?} in {}", d.rule_id, d.description);
        }
        assert!(!d.description.to_lowercase().contains("compliant with"), "{}", d.rule_id);
    }
    assert!(!pack.description.contains("deliberately not encoded"), "{}", pack.description);
    assert!(pack.description.contains("not that the article is met"), "{}", pack.description);
    for pack_id in REFERENCE_PACKS.iter().filter(|p| **p != "khalm-reading-eu-ai-act-2026") {
        let other = reference_pack(pack_id);
        assert!(other.rules.iter().all(|r| r.rule_type() != "documentation_declared"), "{pack_id}");
    }
}

#[test]
fn rule_ids_are_unique_across_the_reference_packs() {
    // Not required by the format - ids are scoped to their pack - but a
    // result quoted without its pack is far easier to trace this way.
    let mut seen: Vec<(String, String)> = Vec::new();
    for pack_id in REFERENCE_PACKS {
        for rule in &reference_pack(pack_id).rules {
            let id = rule.rule_id().to_string();
            if let Some((other, _)) = seen.iter().find(|(_, other_id)| *other_id == id) {
                panic!("{pack_id} and {other} both use rule_id {id:?}");
            }
            seen.push((pack_id.to_string(), id));
        }
    }
    assert!(seen.len() >= 15, "{} rules across five packs", seen.len());
}

#[test]
fn the_committed_files_are_the_documents_the_packs_carry() {
    for pack_id in REFERENCE_PACKS {
        let committed: Value = serde_json::from_str(&pack_text(pack_id)).unwrap();
        assert_eq!(reference_pack(pack_id).document(), &committed, "{pack_id}");
    }
}
