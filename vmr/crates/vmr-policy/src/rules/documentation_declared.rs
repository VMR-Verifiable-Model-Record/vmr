//! `documentation_declared`: the record pins, by hash, the document a rule
//! names.
// ============================================================================
//  documentation_declared.rs (task 10.11a, docs/dev/task-10.11a.md D11-4)
//
//  Reads:          /data_governance
//                  /human_oversight
//                  Both are hashed, whichever one `document` names: a rule
//                  type's read list is fixed (P6-2). The steps look only at
//                  the member the rule names.
//  Steps, in order; the first that yields a status ends the rule:
//    1. The record is not a JSON object: Indeterminate.
//    2. The named member is absent: Fail.
//    3. It is not an object, or its documentation_hash is not a declared
//       string: Indeterminate.
//    4. The documentation_hash is not a hash (`sha256:` and 64 hexadecimal
//       digits in either case): Fail.
//    5. Pass.
//
//  Why absence fails here while P6-3 makes a missing member Indeterminate
//  everywhere else (D11-4, the reviewer, 2026-09-13): P6-3 protects a
//  record that did not say, and only a document that is not a record
//  lacks a REQUIRED member. `data_governance` and `human_oversight` are
//  optional (record format §2 rule 3), so an absent one is a record's
//  only signed way to say that it pins no such document - what E2's signed
//  "" says in a required member, which fails a requirement for it.
//  Indeterminate would leave a rule that no record can fail, which P6-17
//  exists to prevent. A `null` member is not absent: it is a member of the
//  wrong JSON type, and Indeterminate.
//
//  What a pass does not establish: that the document exists, that anyone can
//  obtain it, what it says, or that it meets any requirement. The hash says
//  which document the issuer relied on; nothing here reads the document.
// ============================================================================

use super::{declared_string, fail, indeterminate, not_declared, pass, Verdict};
use crate::pack::DocumentationDeclaredRule;
use crate::schema::{quote, DOCUMENTS};
use serde_json::Value;
use vmr_record::hash::parse_hash;

pub fn evaluate(rule: &DocumentationDeclaredRule, record: &Value) -> Verdict {
    let Some(members) = record.as_object() else {
        return indeterminate("the record is not a JSON object, so it declares no member");
    };
    // A loaded pack names one of DOCUMENTS (the schema's enum). A word this
    // build does not know is answered Indeterminate, never guessed at.
    let Some(document) = DOCUMENTS.iter().copied().find(|d| *d == rule.document) else {
        return indeterminate(format!(
            "the pack names document {}, which is not one of {DOCUMENTS:?}",
            quote(&rule.document)
        ));
    };
    let subject = document.replace('_', " ");
    if !members.contains_key(document) {
        return fail(format!(
            "the record has no /{document} member: it declares that it pins no {subject} documentation"
        ));
    }
    let hash_pointer = format!("/{document}/documentation_hash");
    let Some(hash) = declared_string(record, &hash_pointer) else {
        return not_declared(&hash_pointer);
    };
    if parse_hash(hash).is_err() {
        return fail(format!("{hash_pointer} is {}, which is not a hash", quote(hash)));
    }
    pass(format!(
        "{hash_pointer} pins the issuer's {subject} documentation by hash; the hash names the document, not its \
         adequacy"
    ))
}
