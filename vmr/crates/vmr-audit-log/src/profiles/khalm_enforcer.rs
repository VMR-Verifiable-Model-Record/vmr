// ============================================================================
//  khalm_enforcer.rs — the `khalm-vmr.enforcer` profile
//  (`specs/audit-log-format-v0.1.md` §5.2).
//
//  The kinds KHALM's sovereignty enforcer writes, the detail each carries, and
//  the destination object those kinds name. One profile of many: nothing else
//  in this crate knows these kinds, and another writer's profile sits beside
//  this one.
// ============================================================================

//! KHALM's enforcer profile: its kinds, their detail, and the destination
//! object (§5.2).

use crate::entry::structure;
use crate::error::Error;
use crate::profile::EntryProfile;
use crate::entry::is_key_id_urn;
use serde_json::{Map, Value};
use vmr_record::hash::parse_hash;
use vmr_record::timestamp::Timestamp;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// KHALM's enforcer profile, `khalm-vmr.enforcer` (§5.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EnforcerProfile;

impl EntryProfile for EnforcerProfile {
    fn name(&self) -> &str {
        "khalm-vmr.enforcer"
    }

    fn check(&self, kind: &str, detail: &Value) -> Result<(), Error> {
        validate_kind_detail(kind, detail)
    }
}

/// The `khalm-vmr.enforcer` profile ([`EnforcerProfile`]).
pub const PROFILE: EnforcerProfile = EnforcerProfile;

fn is_hash(v: &Value) -> bool {
    v.as_str().is_some_and(|s| parse_hash(s).is_ok())
}
fn is_timestamp(v: &Value) -> bool {
    v.as_str().is_some_and(|s| Timestamp::parse(s).is_ok())
}
fn is_uuid(v: &Value) -> bool {
    v.as_str().is_some_and(is_uuid_urn)
}
fn is_key_id(v: &Value) -> bool {
    v.as_str().is_some_and(is_key_id_urn)
}
fn is_refusal(v: &Value) -> bool {
    v.as_str().is_some_and(is_refusal_id)
}
fn is_text(v: &Value) -> bool {
    v.as_str().is_some_and(|s| s.len() <= 4096)
}
fn is_u32(v: &Value) -> bool {
    v.as_u64().is_some_and(|n| n <= u64::from(u32::MAX))
}
fn is_u64_string(v: &Value) -> bool {
    v.as_str().is_some_and(is_decimal_u64)
}
fn is_pos_int(v: &Value) -> bool {
    v.as_u64().is_some_and(|n| (1..=vmr_record::canonical::MAX_SAFE_INTEGER).contains(&n))
}
fn is_safe_int(v: &Value) -> bool {
    v.as_u64().is_some_and(|n| n <= vmr_record::canonical::MAX_SAFE_INTEGER)
}
fn is_port(v: &Value) -> bool {
    v.as_u64().is_some_and(|n| n <= 65535)
}
fn is_mechanism(v: &Value) -> bool {
    v.as_str().is_some_and(|s| {
        (1..=64).contains(&s.len()) && s.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
    })
}
fn is_boot_id(v: &Value) -> bool {
    v.as_str().is_some_and(|s| {
        (1..=64).contains(&s.len()) && s.bytes().all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase() || b == b'-')
    })
}
fn is_boot_time(v: &Value) -> bool {
    let Some(o) = v.as_object() else { return false };
    let names_ok = o.len() == 2 && o.contains_key("seconds") && o.contains_key("nanoseconds");
    let seconds_ok = o.get("seconds").is_some_and(is_safe_int);
    let nanos_ok = o.get("nanoseconds").and_then(Value::as_u64).is_some_and(|n| n <= 999_999_999);
    names_ok && seconds_ok && nanos_ok
}
fn is_destination(v: &Value) -> bool {
    Destination::from_value(v).is_ok()
}
fn is_enum(v: &Value, allowed: &[&str]) -> bool {
    v.as_str().is_some_and(|s| allowed.contains(&s))
}
fn is_uuid_urn(s: &str) -> bool {
    let Some(rest) = s.strip_prefix("urn:uuid:") else { return false };
    let groups = [8usize, 4, 4, 4, 12];
    let parts: Vec<&str> = rest.split('-').collect();
    parts.len() == groups.len()
        && parts.iter().zip(groups).all(|(p, n)| p.len() == n && p.bytes().all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase()))
}
fn is_refusal_id(s: &str) -> bool {
    match s.split_once('.') {
        Some((ns, name)) => {
            !ns.is_empty()
                && !name.is_empty()
                && ns.bytes().all(|b| b.is_ascii_lowercase() || b == b'_')
                && name.bytes().all(|b| b.is_ascii_lowercase() || b == b'_')
        }
        None => false,
    }
}
fn is_decimal_u64(s: &str) -> bool {
    if s == "0" {
        return true;
    }
    !s.is_empty() && !s.starts_with('0') && s.bytes().all(|b| b.is_ascii_digit()) && s.parse::<u64>().is_ok()
}

/// A member's checker and whether it is required.
struct Spec {
    name: &'static str,
    required: bool,
    ok: fn(&Value) -> bool,
}
const fn req(name: &'static str, ok: fn(&Value) -> bool) -> Spec {
    Spec { name, required: true, ok }
}
const fn opt(name: &'static str, ok: fn(&Value) -> bool) -> Spec {
    Spec { name, required: false, ok }
}

/// Check a detail object against its member specs: every member is named, every
/// required member is present, and each present member passes its checker.
fn check_detail(obj: &Map<String, Value>, specs: &[Spec]) -> Result<(), Error> {
    for key in obj.keys() {
        if !specs.iter().any(|s| s.name == key.as_str()) {
            return Err(structure(format!("unknown detail member {key:?}")));
        }
    }
    for spec in specs {
        match obj.get(spec.name) {
            None if spec.required => return Err(structure(format!("detail is missing {:?}", spec.name))),
            Some(value) if !(spec.ok)(value) => {
                return Err(structure(format!("detail member {:?} has a bad value", spec.name)))
            }
            _ => {}
        }
    }
    Ok(())
}

/// The kinds an entry may carry (§5.2).
pub const KINDS: [&str; 17] = [
    "enforcer.started",
    "enforcer.refused",
    "enforcer.stopped",
    "bundle.loaded",
    "bundle.refused",
    "key.operation",
    "egress.denied",
    "egress.allowed",
    "socket.create_denied",
    "socket.listen_denied",
    "file.open_denied",
    "export.granted",
    "export.refused",
    "export.install_failed",
    "events.dropped",
    "events.malformed",
    "log.recovered",
];

fn validate_kind_detail(kind: &str, detail: &Value) -> Result<(), Error> {
    let obj = detail.as_object().ok_or_else(|| structure("detail must be an object"))?;
    let hook2 = |v: &Value| is_enum(v, &["socket_connect", "socket_sendmsg"]);
    match kind {
        "enforcer.started" => check_detail(obj, &[
            req("audit_key_id", is_key_id),
            req("bundle_id", is_uuid),
            req("bundle_payload_hash", is_hash),
            req("record_id", is_uuid),
            req("model_hash", is_hash),
            req("mechanism", is_mechanism),
            req("object_version", is_u32),
            req("boot_id", is_boot_id),
        ]),
        "enforcer.refused" | "bundle.refused" => check_detail(obj, &[
            req("refusal", is_refusal),
            req("detail", is_text),
        ]),
        "enforcer.stopped" => check_detail(obj, &[]),
        "bundle.loaded" => check_detail(obj, &[
            req("bundle_id", is_uuid),
            req("bundle_payload_hash", is_hash),
            req("signing_key_id", is_key_id),
        ]),
        "key.operation" => check_detail(obj, &[
            req("operation", |v| is_enum(v, &["load_audit_key", "load_policy_key"])),
            req("result", |v| is_enum(v, &["ok", "failed"])),
            opt("key_id", is_key_id),
            opt("detail", is_text),
        ]),
        "egress.denied" => {
            check_detail(obj, &[
                req("hook", hook2),
                req("family", is_u32),
                req("protocol", is_u32),
                opt("address", |v| v.as_str().is_some_and(|s| (2..=39).contains(&s.len()))),
                opt("port", is_port),
                req("boot_time", is_boot_time),
                req("cgroup_id", is_u64_string),
                req("tgid", is_u32),
                req("uid", is_u32),
            ])?;
            // address and port are both present or both absent (§5.2).
            if obj.contains_key("address") != obj.contains_key("port") {
                return Err(structure("egress.denied: address and port must both be present or both absent"));
            }
            Ok(())
        }
        "egress.allowed" => check_detail(obj, &[
            req("hook", hook2),
            req("destination", is_destination),
            req("grant", is_u32),
            req("boot_time", is_boot_time),
            req("cgroup_id", is_u64_string),
            req("tgid", is_u32),
            req("uid", is_u32),
        ]),
        "socket.create_denied" => check_detail(obj, &[
            req("family", is_u32),
            req("protocol", is_u32),
            req("boot_time", is_boot_time),
            req("cgroup_id", is_u64_string),
            req("tgid", is_u32),
            req("uid", is_u32),
        ]),
        "socket.listen_denied" => check_detail(obj, &[
            req("family", is_u32),
            req("boot_time", is_boot_time),
            req("cgroup_id", is_u64_string),
            req("tgid", is_u32),
            req("uid", is_u32),
        ]),
        "file.open_denied" => check_detail(obj, &[
            req("device", is_u64_string),
            req("inode", is_u64_string),
            req("boot_time", is_boot_time),
            req("cgroup_id", is_u64_string),
            req("tgid", is_u32),
            req("uid", is_u32),
        ]),
        "export.granted" => check_detail(obj, &[
            req("token_id", is_uuid),
            req("token_payload_hash", is_hash),
            req("signing_key_id", is_key_id),
            req("destination", is_destination),
            req("not_before", is_timestamp),
            req("not_after", is_timestamp),
            req("deadline", is_boot_time),
            req("grant", is_u32),
        ]),
        "export.refused" => check_detail(obj, &[
            req("refusal", is_refusal),
            req("detail", is_text),
            opt("token_id", is_uuid),
            opt("signing_key_id", is_key_id),
            opt("destination", is_destination),
        ]),
        "export.install_failed" => check_detail(obj, &[
            req("token_id", is_uuid),
            req("grant", is_u32),
            req("detail", is_text),
        ]),
        "events.dropped" => check_detail(obj, &[req("count", is_pos_int)]),
        "events.malformed" => check_detail(obj, &[
            req("length", is_safe_int),
            req("refusal", is_refusal),
        ]),
        "log.recovered" => check_detail(obj, &[
            req("offset", is_safe_int),
            req("length", is_pos_int),
            req("sha256", is_hash),
        ]),
        other => Err(structure(format!("unknown kind {other:?}"))),
    }
}
/// A transport protocol a destination names.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Protocol {
    /// TCP.
    Tcp,
    /// UDP.
    Udp,
}

impl Protocol {
    /// The lower-case name used in a destination object and its text form.
    pub fn as_str(self) -> &'static str {
        match self {
            Protocol::Tcp => "tcp",
            Protocol::Udp => "udp",
        }
    }

    /// Parse `"tcp"` or `"udp"`.
    pub fn parse(text: &str) -> Option<Protocol> {
        match text {
            "tcp" => Some(Protocol::Tcp),
            "udp" => Some(Protocol::Udp),
            _ => None,
        }
    }
}

/// A destination: a protocol, an IP address and a port (§5.2). Kept in
/// canonical form, so [`Destination::text`] is its one text form (§5.2).
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct Destination {
    /// The transport protocol.
    pub protocol: Protocol,
    /// The address (IPv4 or IPv6), canonical.
    pub address: IpAddr,
    /// The port, 1 to 65535.
    pub port: u16,
}

impl Destination {
    /// Build a destination from its parts, refusing a non-canonical address,
    /// the unspecified addresses, an IPv4-mapped IPv6 address, or port 0. The
    /// caller (a bundle, a token, an audit entry) wraps the message in its own
    /// structure refusal.
    pub fn new(protocol: Protocol, address: &str, port: u64) -> Result<Destination, String> {
        if port == 0 || port > 65535 {
            return Err(format!("port {port} is not 1 to 65535"));
        }
        let addr = canonical_address(address)?;
        Ok(Destination { protocol, address: addr, port: port as u16 })
    }

    /// Parse a destination object `{protocol, address, port}` (§5.2). Every
    /// other member, a missing member, or a member of the wrong type is a
    /// message the caller turns into its structure refusal.
    pub fn from_value(value: &serde_json::Value) -> Result<Destination, String> {
        let object = value.as_object().ok_or("a destination must be an object")?;
        const MEMBERS: [&str; 3] = ["protocol", "address", "port"];
        for key in object.keys() {
            if !MEMBERS.contains(&key.as_str()) {
                return Err(format!("unknown destination member {key:?}"));
            }
        }
        let protocol_text = object
            .get("protocol")
            .and_then(serde_json::Value::as_str)
            .ok_or("a destination needs a string protocol")?;
        let protocol = Protocol::parse(protocol_text)
            .ok_or_else(|| format!("protocol {protocol_text:?} is not \"tcp\" or \"udp\""))?;
        let address = object
            .get("address")
            .and_then(serde_json::Value::as_str)
            .ok_or("a destination needs a string address")?;
        let port = object
            .get("port")
            .and_then(serde_json::Value::as_u64)
            .ok_or("a destination needs an integer port")?;
        Destination::new(protocol, address, port)
    }

    /// This destination as a JSON object.
    pub fn to_value(&self) -> serde_json::Value {
        serde_json::json!({
            "protocol": self.protocol.as_str(),
            "address": self.address.to_string(),
            "port": self.port,
        })
    }

    /// The one text form (§5.2): `tcp://203.0.113.7:443`,
    /// `udp://[2001:db8::1]:53`.
    pub fn text(&self) -> String {
        match self.address {
            IpAddr::V4(v4) => format!("{}://{}:{}", self.protocol.as_str(), v4, self.port),
            IpAddr::V6(v6) => format!("{}://[{}]:{}", self.protocol.as_str(), v6, self.port),
        }
    }
}
/// Parse an address and require its canonical form (§5.2). Rejects a
/// non-canonical spelling, the unspecified addresses `0.0.0.0` and `::`, and
/// every IPv4-mapped IPv6 address (which must be written as its IPv4 form).
fn canonical_address(text: &str) -> Result<IpAddr, String> {
    if let Ok(v4) = text.parse::<Ipv4Addr>() {
        if v4.is_unspecified() {
            return Err("0.0.0.0 is not a destination".to_string());
        }
        // A canonical IPv4 address is its own Display; leading zeros and the
        // like differ.
        if v4.to_string() != text {
            return Err(format!("address {text:?} is not canonical ({v4})"));
        }
        return Ok(IpAddr::V4(v4));
    }
    if let Ok(v6) = text.parse::<Ipv6Addr>() {
        if v6.is_unspecified() {
            return Err(":: is not a destination".to_string());
        }
        if v6.to_ipv4_mapped().is_some() {
            return Err(format!("address {text:?} is an IPv4-mapped IPv6 address; write it as its IPv4 form"));
        }
        if v6.to_string() != text {
            return Err(format!("address {text:?} is not canonical ({v6})"));
        }
        return Ok(IpAddr::V6(v6));
    }
    Err(format!("address {text:?} is not an IPv4 or IPv6 address"))
}
