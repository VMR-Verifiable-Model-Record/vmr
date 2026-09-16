//! `export_control`: the declared inference boundary satisfies the rule.
// ============================================================================
//  export_control.rs (P6-3)
//
//  Reads:          /deployment_context/inference_boundary/type
//                  /deployment_context/inference_boundary/egress_allowed
//                  /deployment_context/inference_boundary/allowed_egress_destinations
//  Pass:           require_air_gapped  => type == "air-gapped"
//                  require_egress_denied => egress_allowed == false AND
//                                           allowed_egress_destinations is empty
//  Fail:           a requirement is contradicted by a declared value
//  Indeterminate:  a member a set requirement needs is absent or of the
//                  wrong JSON type
//
//  A denial with an exception list is not a denial, which is why
//  `require_egress_denied` reads the destination list as well (P6-3). The §5
//  sketch's `require_key_gated_egress` is deleted: the record describes the
//  boundary, not the key that gates it.
// ============================================================================

use super::{declared_string, fail, indeterminate, not_declared, pass, Verdict};
use crate::evidence::pointer::{ALLOWED_EGRESS_DESTINATIONS, BOUNDARY_TYPE, EGRESS_ALLOWED};
use crate::pack::ExportControlRule;
use crate::schema::quote;
use serde_json::Value;

const AIR_GAPPED: &str = "air-gapped";

pub fn evaluate(rule: &ExportControlRule, record: &Value) -> Verdict {
    let mut met: Vec<String> = Vec::new();

    if rule.require_air_gapped {
        let Some(kind) = declared_string(record, BOUNDARY_TYPE) else {
            return not_declared(BOUNDARY_TYPE);
        };
        if kind != AIR_GAPPED {
            return fail(format!(
                "inference_boundary.type is {}, and an air-gapped boundary is required",
                quote(kind)
            ));
        }
        met.push("the boundary is air-gapped".into());
    }

    if rule.require_egress_denied {
        let Some(allowed) = record.pointer(EGRESS_ALLOWED).and_then(Value::as_bool) else {
            return not_declared(EGRESS_ALLOWED);
        };
        if allowed {
            return fail("inference_boundary.egress_allowed is true, and egress must be denied");
        }
        let Some(destinations) = record.pointer(ALLOWED_EGRESS_DESTINATIONS).and_then(Value::as_array)
        else {
            return not_declared(ALLOWED_EGRESS_DESTINATIONS);
        };
        if !destinations.is_empty() {
            return fail(format!(
                "egress is denied but {} destination(s) are still allowed: a denial with an \
                 exception list is not a denial",
                destinations.len()
            ));
        }
        met.push("egress is denied and no destination is allowed".into());
    }

    if met.is_empty() {
        // Unreachable through a loaded pack: `validate` refuses an
        // export_control rule that sets neither requirement (P6-9).
        return indeterminate("the rule sets no export requirement");
    }
    pass(met.join("; "))
}
