// tests/model_hash_vectors.rs — the generator and the replay of
// specs/test-vectors/model-hash/cases.json (task 10.11b, plan §4.5).
//
// The cases: named-set digests (spec §7.2), whose member encoding binds each
// name; names and sets the rule refuses; and the digest and Merkle root of
// `named-set-v1` training records (§8.2, §8.3). A case's expected digest and
// root are computed in this file from their definitions (the encodings
// concatenated by hand, and the level-by-level `merkle_root`), never through
// `NamedSetDigest`, `member_encoding` or `MerkleStream`, which the replay
// checks. Refusal reasons are written by hand. No engine, no randomness: the
// file regenerates byte for byte anywhere, and is written only by
//     VMR_WRITE_VECTORS=1 cargo test -p vmr-record --test model_hash_vectors -- --ignored
// in its own commit.

use serde_json::{json, Value};
use std::collections::BTreeSet;
use vmr_record::hash::{format_hash, parse_hash, sha256};
use vmr_record::merkle::{merkle_root, MerkleStream};
use vmr_record::named_set::{member_encoding, validate_name, NameError, NamedSetDigest};

fn vectors_path() -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../../specs/test-vectors/model-hash/cases.json")
}

/// One member: its name and its bytes.
type Member = (String, Vec<u8>);

fn m(name: &str, bytes: &[u8]) -> Member {
    (name.to_string(), bytes.to_vec())
}

fn member_json((name, bytes): &Member) -> Value {
    json!({"name": name, "bytes_hex": hex::encode(bytes), "sha256": hex::encode(sha256(bytes))})
}

fn members_json(members: &[Member]) -> Value {
    Value::Array(members.iter().map(member_json).collect())
}

/// A member's encoding, by its definition in spec §7.2.
fn encoding_by_definition((name, bytes): &Member) -> Vec<u8> {
    let mut e = (name.len() as u64).to_be_bytes().to_vec();
    e.extend_from_slice(name.as_bytes());
    e.extend_from_slice(&sha256(bytes));
    e
}

/// The named-set digest, by its definition in spec §7.2.
fn digest_by_definition(members: &[Member]) -> String {
    format_hash(&sha256(&members.iter().flat_map(encoding_by_definition).collect::<Vec<u8>>()))
}

fn digest_case(id: &str, description: &str, members: Vec<Member>) -> Value {
    json!({
        "id": id,
        "description": description,
        "kind": "named-set-digest",
        "members": members_json(&members),
        "expected": {"digest": digest_by_definition(&members)},
    })
}

fn rename_versus_swap() -> Value {
    let (x, y) = (b"X".as_slice(), b"Y".as_slice());
    let original = vec![m("a", x), m("b", y)];
    let renamed = vec![m("b", y), m("c", x)];
    let swapped = vec![m("a", y), m("b", x)];
    json!({
        "id": "digest-rename-versus-swap",
        "description": "{a: X, b: Y} renamed to {b: Y, c: X}, and swapped to {a: Y, b: X}. A digest over the members' SHA-256s alone would give the renamed and the swapped set one value, SHA-256(SHA-256(Y) || SHA-256(X)); the member encoding binds the names, so the three digests differ (spec §7.2).",
        "kind": "named-set-digests",
        "sets": {"original": members_json(&original), "renamed": members_json(&renamed), "swapped": members_json(&swapped)},
        "expected": {
            "original": digest_by_definition(&original),
            "renamed": digest_by_definition(&renamed),
            "swapped": digest_by_definition(&swapped),
        },
    })
}

fn name_case(id: &str, description: &str, name: &str, reason: Option<&str>) -> Value {
    json!({
        "id": id,
        "description": description,
        "kind": "name",
        "name": name,
        "expected": {"accepted": reason.is_none(), "reason": reason},
    })
}

fn set_case(id: &str, description: &str, names: &[&str], refused_at: usize, reason: &str) -> Value {
    json!({
        "id": id,
        "description": description,
        "kind": "set-refused",
        "names": names,
        "expected": {"refused_at": refused_at, "reason": reason},
    })
}

fn records_case(n: usize) -> Value {
    let members: Vec<Member> = (0..n).map(|i| (format!("record-{i:05}"), format!("record {i}\n").into_bytes())).collect();
    let leaves: Vec<Vec<u8>> = members.iter().map(encoding_by_definition).collect();
    json!({
        "id": format!("merkle-named-set-{n}"),
        "description": format!("{n} named-set-v1 records, record-00000 onwards, each the bytes \"record <i>\\n\": their count, their named-set digest (training_input_digest) and the Merkle root whose leaf data is each record's member encoding (training_input_merkle_root; spec §8.2, §8.3)."),
        "kind": "named-set-records",
        "record_format": "named-set-v1",
        "members": members_json(&members),
        "expected": {
            "training_input_count": n,
            "training_input_digest": digest_by_definition(&members),
            "training_input_merkle_root": format_hash(&merkle_root(&leaves)),
        },
    })
}

/// The whole file.
fn file() -> Value {
    let zero4 = [0u8; 4];
    let mut cases = vec![
        digest_case(
            "digest-one-file",
            "A model of one file, weights.bin, four zero bytes. Its digest is not the file's own SHA-256: a one-file model follows the same rule as any other (spec §7.2).",
            vec![m("weights.bin", &zero4)],
        ),
        digest_case(
            "digest-two-files",
            "Spec §7.2's example: config.json, the two bytes {}, and weights.bin, four zero bytes.",
            vec![m("config.json", b"{}"), m("weights.bin", &zero4)],
        ),
        digest_case(
            "digest-nested-paths",
            "A layout in directories: names of several segments joined by /, in the order of their UTF-8 bytes.",
            vec![
                m("model_index.json", b"{}"),
                m("text_encoder/model.safetensors", b"text encoder"),
                m("unet/diffusion_pytorch_model.safetensors", b"unet"),
                m("vae/diffusion_pytorch_model.safetensors", b"vae"),
            ],
        ),
        digest_case(
            "digest-empty-file",
            "An empty file is a member, with the SHA-256 of no bytes.",
            vec![m("empty.bin", b""), m("weights.bin", &zero4)],
        ),
        digest_case("digest-empty-set", "No members: the SHA-256 of no bytes.", vec![]),
        digest_case(
            "digest-code-point-order",
            "Names U+FF5E and U+1F600. U+FF5E comes first by Unicode scalar value, which is UTF-8 byte order (spec §7.2); UTF-16 code unit order, which JCS uses for member names (spec §3), would put U+1F600 first.",
            vec![m("\u{ff5e}", b"first"), m("\u{1f600}", b"second")],
        ),
        rename_versus_swap(),
        name_case("name-accepted-leading-dot", "A segment that starts with a dot is not the segment \".\".", ".hidden", None),
        name_case("name-accepted-dots-inside", "A segment with dots inside is not the segment \"..\".", "model..v2.bin", None),
        name_case("name-accepted-three-dots", "The segment \"...\" is neither \".\" nor \"..\".", "...", None),
        name_case("name-refused-empty", "The empty name.", "", Some("empty")),
        name_case("name-refused-leading-slash", "A name starting with / has an empty first segment.", "/weights.bin", Some("empty-segment")),
        name_case("name-refused-trailing-slash", "A name ending with / has an empty last segment: a directory is not a member.", "unet/", Some("empty-segment")),
        name_case("name-refused-double-slash", "A name holding // has an empty segment.", "unet//model.safetensors", Some("empty-segment")),
        name_case("name-refused-dot-segment", "The segment \".\".", "./weights.bin", Some("dot-segment")),
        name_case("name-refused-dotdot-segment", "The segment \"..\".", "unet/../weights.bin", Some("dotdot-segment")),
        set_case(
            "set-refused-repeated",
            "A name repeated: the second does not come after the first.",
            &["weights.bin", "weights.bin"],
            1,
            "not-ascending",
        ),
        set_case(
            "set-refused-unordered",
            "Names out of order: config.json does not come after weights.bin.",
            &["weights.bin", "config.json"],
            1,
            "not-ascending",
        ),
    ];
    for n in [0, 1, 2, 3, 5, 7, 11, 13, 1025] {
        cases.push(records_case(n));
    }
    // After the task 10.11b QA (QB-01): a name is taken as the file system
    // stores it, and one folder gives one digest only with the same names
    // (spec §7.2). Appended after every earlier case, which stays as it was.
    let digests = |id: &str, description: &str, sets: Vec<(&str, Vec<Member>)>| {
        let mut given = serde_json::Map::new();
        let mut expected = serde_json::Map::new();
        for (set, members) in &sets {
            given.insert(set.to_string(), members_json(members));
            expected.insert(set.to_string(), json!(digest_by_definition(members)));
        }
        json!({"id": id, "description": description, "kind": "named-set-digests", "sets": given, "expected": expected})
    };
    cases.extend([
        name_case(
            "name-accepted-backslash",
            "A \\ inside a name is a name character, kept as stored: unet\\config.json is one segment (spec §7.2). A tool converts a separator \\ to /, never a \\ that is part of a file's name.",
            "unet\\config.json",
            None,
        ),
        name_case(
            "name-accepted-nfd",
            "A name in NFD, mode\u{300}le.bin (e followed by U+0300), is accepted as stored: a tool does not normalise a name (spec §7.2).",
            "mode\u{300}le.bin",
            None,
        ),
        digests(
            "digest-nfc-versus-nfd",
            "One byte string under mod\u{e8}le.bin in NFC (U+00E8) and under the same name in NFD (e, U+0300): two names, two digests (spec §7.2). A copy that rewrites one spelling into the other, as macOS HFS+ does, describes another set of files.",
            vec![("nfc", vec![m("mod\u{e8}le.bin", b"weights")]), ("nfd", vec![m("mode\u{300}le.bin", b"weights")])],
        ),
        digests(
            "digest-case-twins",
            "Tokenizer.json and tokenizer.json are two members (spec §7.2); the one file a case-insensitive file system keeps of them is another set, with another digest.",
            vec![
                ("twins", vec![m("Tokenizer.json", b"{\"version\":\"2.0\"}"), m("tokenizer.json", b"{\"version\":\"1.0\"}")]),
                ("one_kept", vec![m("tokenizer.json", b"{\"version\":\"1.0\"}")]),
            ],
        ),
        digest_case(
            "digest-separator-order",
            "a-b.bin, a.bin, a/x.bin: - and . come before / in UTF-8 byte order (spec §7.2), so a converter from a manifest ordered by path parts, a/x.bin first, re-sorts the names.",
            vec![m("a-b.bin", b"one"), m("a.bin", b"two"), m("a/x.bin", b"three")],
        ),
        set_case(
            "set-refused-path-part-order",
            "The names of digest-separator-order in path-part order, a/x.bin first: a-b.bin does not come after a/x.bin.",
            &["a/x.bin", "a-b.bin", "a.bin"],
            1,
            "not-ascending",
        ),
    ]);
    json!({
        "vector_version": "0.1",
        "description": "Vectors for format v0.1: the named-set digest and name rules of the record format v0.1, §7.2, and the digest and Merkle root of named-set-v1 training records (§8.2, §8.3). A member's bytes are given in hex with their SHA-256. Written by the vmr-record crate's generator (VMR_WRITE_VECTORS=1 cargo test -p vmr-record --test model_hash_vectors -- --ignored); see README.md.",
        "cases": cases,
    })
}

fn pretty(v: &Value) -> String {
    format!("{}\n", serde_json::to_string_pretty(v).unwrap())
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

/// A case's members as (name, SHA-256), checking each stated SHA-256
/// against its bytes.
fn members_of(v: &Value) -> Vec<(String, [u8; 32])> {
    v.as_array()
        .unwrap()
        .iter()
        .map(|member| {
            let bytes = hex::decode(member["bytes_hex"].as_str().unwrap()).unwrap();
            assert_eq!(member["sha256"], hex::encode(sha256(&bytes)), "{member}");
            (member["name"].as_str().unwrap().to_string(), sha256(&bytes))
        })
        .collect()
}

fn library_digest(members: &[(String, [u8; 32])]) -> String {
    let mut digest = NamedSetDigest::new();
    for (name, hash) in members {
        digest.push(name, hash).unwrap();
    }
    format_hash(&digest.finish())
}

#[test]
fn model_hash_vectors_are_reproducible() {
    let committed = std::fs::read_to_string(vectors_path()).expect("specs/test-vectors/model-hash/cases.json");
    assert!(committed == pretty(&file()), "the committed model-hash vectors differ from what the generator writes");
}

#[test]
#[ignore = "writes specs/test-vectors/model-hash/cases.json; run with VMR_WRITE_VECTORS=1 to regenerate"]
#[allow(clippy::disallowed_methods)] // reading the opt-in switch is this generator's whole job
fn write_model_hash_vectors() {
    if std::env::var("VMR_WRITE_VECTORS").as_deref() != Ok("1") {
        eprintln!("VMR_WRITE_VECTORS is not 1: nothing written");
        return;
    }
    let path = vectors_path();
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(path, pretty(&file())).unwrap();
}

#[test]
fn every_model_hash_vector_gives_its_expected_result() {
    let doc: Value = serde_json::from_str(&std::fs::read_to_string(vectors_path()).unwrap()).unwrap();
    let mut kinds = BTreeSet::new();
    let mut ids = BTreeSet::new();
    for case in doc["cases"].as_array().unwrap() {
        let id = case["id"].as_str().unwrap();
        assert!(ids.insert(id.to_string()), "duplicate case id {id}");
        let expected = &case["expected"];
        let kind = case["kind"].as_str().unwrap();
        kinds.insert(kind.to_string());
        match kind {
            "named-set-digest" => {
                assert_eq!(library_digest(&members_of(&case["members"])), expected["digest"], "{id}");
            }
            "named-set-digests" => {
                // Two or more named sets, each with its digest, no two equal:
                // a rename never collides with a swap, and neither NFC with
                // NFD nor one case twin with both (QB-01).
                let sets = case["sets"].as_object().unwrap();
                assert!(sets.len() >= 2, "{id}");
                let mut seen = BTreeSet::new();
                for (set, members) in sets {
                    let digest = library_digest(&members_of(members));
                    assert_eq!(digest, expected[set.as_str()], "{id} {set}");
                    assert!(seen.insert(digest), "{id}: {set}'s digest collides with another set's");
                }
            }
            "name" => {
                let name = case["name"].as_str().unwrap();
                match validate_name(name) {
                    Ok(()) => assert_eq!((expected["accepted"].clone(), expected["reason"].clone()), (json!(true), Value::Null), "{id}"),
                    Err(e) => assert_eq!((expected["accepted"].clone(), expected["reason"].clone()), (json!(false), json!(reason_id(e))), "{id}"),
                }
            }
            "set-refused" => {
                let mut digest = NamedSetDigest::new();
                let mut refused = None;
                for (i, name) in case["names"].as_array().unwrap().iter().enumerate() {
                    if let Err(e) = digest.push(name.as_str().unwrap(), &sha256(name.as_str().unwrap().as_bytes())) {
                        refused = Some((i, reason_id(e)));
                        break;
                    }
                }
                let (at, reason) = refused.unwrap_or_else(|| panic!("{id}: the set was not refused"));
                assert_eq!((json!(at), json!(reason)), (expected["refused_at"].clone(), expected["reason"].clone()), "{id}");
            }
            "named-set-records" => {
                assert_eq!(case["record_format"], "named-set-v1", "{id}");
                let members = members_of(&case["members"]);
                assert_eq!(json!(members.len()), expected["training_input_count"], "{id}");
                assert_eq!(library_digest(&members), expected["training_input_digest"], "{id}");
                let mut stream = MerkleStream::new();
                for (name, hash) in &members {
                    stream.push(&member_encoding(name, hash));
                }
                let root = parse_hash(expected["training_input_merkle_root"].as_str().unwrap()).unwrap();
                assert_eq!(stream.count(), members.len() as u64, "{id}");
                assert_eq!(stream.finish(), root, "{id}");
            }
            other => panic!("{id}: unknown kind {other}"),
        }
    }
    let every_kind: BTreeSet<String> =
        ["named-set-digest", "named-set-digests", "name", "set-refused", "named-set-records"].iter().map(|k| k.to_string()).collect();
    assert_eq!(kinds, every_kind);
}
