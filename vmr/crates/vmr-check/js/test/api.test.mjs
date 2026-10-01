// The built module's interface (docs/BROWSER.md): what it imports, its
// randomness source, each call on good and bad input, the hasher, misuse,
// and mutated input that must never trap.
import { test } from "node:test";
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { baseCase, cases, checker, inputBytes, parity, unix, utf8, vectorStore, wasmBytes } from "./common.mjs";
import { load } from "../vmr-check.js";

const vmr = await checker();
const base = baseCase();
const record = inputBytes(base.input);
const at = unix(base.evaluation_time);
const decoder = new TextDecoder();

test("the module imports nothing: no route to a clock, the network or randomness", () => {
  const module = new WebAssembly.Module(wasmBytes());
  assert.deepEqual(WebAssembly.Module.imports(module), []);
});

test("the randomness source the module registers always fails", () => {
  const { exports } = new WebAssembly.Instance(new WebAssembly.Module(wasmBytes()), {});
  const ptr = exports.vmr_alloc(16);
  const code = exports.__getrandom_custom(ptr, 16);
  // getrandom's Error::UNSUPPORTED: its internal code 0, 0x80000000 as i32.
  assert.equal(code, -0x80000000);
  assert.deepEqual([...new Uint8Array(exports.memory.buffer, ptr, 16)], new Array(16).fill(0));
  exports.vmr_free(ptr, 16);
});

test("load takes bytes, an ArrayBuffer or a Response", async () => {
  const bytes = wasmBytes();
  const fromBuffer = await load(bytes.buffer.slice(bytes.byteOffset, bytes.byteOffset + bytes.length));
  const fromResponse = await load(new Response(bytes, { headers: { "content-type": "application/wasm" } }));
  assert.deepEqual(fromBuffer.version(), vmr.version());
  assert.deepEqual(fromResponse.version(), vmr.version());
  await assert.rejects(load(42), TypeError);
});

test("version names the build and the record format", () => {
  const v = vmr.version();
  assert.equal(v.record_format, "0.1");
  assert.match(v.vmr, /^0\.1\.\d+$/);
});

test("inspect: a valid record matches its embedded key; a tampered one does not", () => {
  const ok = vmr.inspect(record);
  assert.equal(ok.integrity_against_embedded_key, "matches");
  assert.equal(ok.fingerprint, "HyoP YysS FOQ5 d6x6 4H8_ pHdd");
  assert.deepEqual(ok.issuer, { name: "New Clark City Fab Operator", id: "did:web:factory-operator.ph" });
  assert.equal(ok.declared.issued_at, "2026-09-10T00:00:00Z");

  const doc = JSON.parse(decoder.decode(record));
  doc.issuer.issuer_name = "Evil \u{202e}Corp";
  const tampered = vmr.inspect(utf8(JSON.stringify(doc)));
  assert.equal(tampered.integrity_against_embedded_key, "does_not_match");
  assert.equal(tampered.issuer.name, "Evil \\u{202e}Corp");

  const refused = vmr.inspect(utf8("hello"));
  assert.equal(refused.refusal.id, "input.form");
  assert.equal(refused.refusal.input, "record");
});

const FINGERPRINT = "HyoP YysS FOQ5 d6x6 4H8_ pHdd";

test("storeForEmbeddedKey then verify passes; without a level the record cannot raise its own", () => {
  const store = vmr.storeForEmbeddedKey(record, { expectedFingerprint: FINGERPRINT, attestationLevel: "software" });
  assert.equal(typeof store, "string");
  const passed = vmr.verify({ record, trustStore: store, at });
  assert.equal(passed.report.verdict, "pass");
  assert.equal(passed.at_source, "caller");

  const conservative = vmr.storeForEmbeddedKey(record, { expectedFingerprint: FINGERPRINT });
  assert.match(conservative, /"attestation_level": "self"/);
  const failed = vmr.verify({ record, trustStore: conservative, at });
  assert.equal(failed.report.failure.check, "trust.attestation");

  assert.equal(vmr.storeForEmbeddedKey(record, { expectedFingerprint: FINGERPRINT, attestationLevel: "gold" }).refusal.id, "attestation_level.unknown");
  assert.equal(vmr.storeForEmbeddedKey(utf8("{"), { expectedFingerprint: FINGERPRINT }).refusal.input, "record");
});

test("storeForEmbeddedKey refuses a fingerprint that is not the key's and a record its key does not match", () => {
  // QA S4: the fingerprint the reader copied from the issuer's publication
  // is an input, compared with its spaces removed.
  assert.equal(typeof vmr.storeForEmbeddedKey(record, { expectedFingerprint: "HyoPYysSFOQ5d6x64H8_pHdd" }), "string");
  for (const wrong of ["", "HyoP YysS FOQ5 d6x6 4H8_ pHdD", "hyop yyss foq5 d6x6 4h8_ phdd", "x\u{d800}"]) {
    const out = vmr.storeForEmbeddedKey(record, { expectedFingerprint: wrong });
    assert.equal(out.refusal.id, "store.fingerprint_mismatch", wrong);
  }
  const doc = JSON.parse(decoder.decode(record));
  doc.issuer.issuer_name = "Someone else";
  const tampered = vmr.storeForEmbeddedKey(utf8(JSON.stringify(doc)), { expectedFingerprint: FINGERPRINT });
  assert.equal(tampered.refusal.id, "store.integrity");
  assert.throws(() => vmr.storeForEmbeddedKey(record), TypeError);
  assert.throws(() => vmr.storeForEmbeddedKey(record, { attestationLevel: "self" }), TypeError);
});

test("verify: the report as the library writes it and display-safe; refusals for unusable input", () => {
  const answer = vmr.verify({ record, trustStore: vectorStore("ts-basic"), at });
  assert.deepEqual(answer.report, JSON.parse(answer.report_json));
  assert.equal(answer.policy, null);
  assert.equal(vmr.verify({ record, trustStore: "{", at }).refusal.id, "trust_store.syntax");
  for (const bad of [NaN, Infinity, 1.5, 1e300, -1e12]) {
    assert.equal(vmr.verify({ record, trustStore: vectorStore("ts-basic"), at: bad }).refusal.id, "evaluation_time.range", `${bad}`);
  }
});

test("verify gives the outcome the CLI's exit code gives, and the trusted key's fingerprint", () => {
  // QA S3 and N5.
  const passed = vmr.verify({ record, trustStore: vectorStore("ts-basic"), at });
  assert.deepEqual([passed.accepted, passed.outcome, passed.fingerprint], [true, "verified", FINGERPRINT]);
  const untrusted = vmr.verify({ record, trustStore: vectorStore("ts-empty"), at });
  assert.deepEqual([untrusted.accepted, untrusted.outcome, untrusted.fingerprint], [false, "failed", null]);
  const c = cases("policy/cases.json").find((c) => c.verifiable && c.expected.overall === "fail" && !c.context);
  const notAccepted = vmr.verify({
    record: utf8(parity.policy[c.id].record), trustStore: vectorStore("ts-basic"), at: unix(c.evaluation_time), pack: c.pack.text,
  });
  assert.equal(notAccepted.report.verdict, "pass");
  assert.deepEqual([notAccepted.accepted, notAccepted.outcome], [false, "verified_not_accepted"]);
});

test("the streaming hasher equals a one-shot hash at any chunking, and is spent after finish", () => {
  const bytes = new Uint8Array(100_003).map((_, i) => (i * 2654435761) >>> 24);
  const oneShot = `sha256:${createHash("sha256").update(bytes).digest("hex")}`;
  for (const size of [1, 7, 64, 4096, 65_536, 100_003, 1_000_000]) {
    const h = vmr.fileHasher();
    for (let i = 0; i < bytes.length; i += size) h.update(bytes.subarray(i, i + size));
    h.update(new Uint8Array(0));
    assert.equal(h.finish(), oneShot, `chunks of ${size}`);
    assert.throws(() => h.finish(), /spent/);
    assert.throws(() => h.update(bytes), /spent/);
  }
  assert.equal(vmr.fileHasher().finish(), "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
});

test("a large chunk is hashed through a small buffer: the module's memory does not grow with it", async () => {
  // QA N2. The instance is captured to read its memory; the API exposes none.
  const instantiate = WebAssembly.instantiate;
  let instance;
  WebAssembly.instantiate = async (...args) => {
    const result = await instantiate(...args);
    instance = result.instance;
    return result;
  };
  let own;
  try {
    own = await load(wasmBytes());
  } finally {
    WebAssembly.instantiate = instantiate;
  }
  const chunk = new Uint8Array(64 * 1024 * 1024).fill(7);
  const h = own.fileHasher();
  const before = instance.exports.memory.buffer.byteLength;
  h.update(chunk);
  h.update(chunk);
  assert.equal(h.finish(), `sha256:${createHash("sha256").update(chunk).update(chunk).digest("hex")}`);
  const grown = instance.exports.memory.buffer.byteLength - before;
  assert.ok(grown <= 2 * 1024 * 1024, `memory grew by ${grown} bytes`);
});

function filesOf(base) {
  return JSON.parse(base).model_identity.learned_state_components.map((c) => ({ name: c.name, sha256: c.hash, size: c.size_bytes }));
}

test("checkFiles: an extra .gitattributes, a missing file, a mismatch and a refused name", () => {
  const model = utf8(parity.model_hash.base);
  const listed = JSON.parse(parity.model_hash.base).model_identity;
  const files = filesOf(parity.model_hash.base);

  const all = vmr.checkFiles({ record: model, files: [...files, { name: ".gitattributes", sha256: `sha256:${"ab".repeat(32)}`, size: 3 }] });
  assert.deepEqual(all.extra, [{ index: 4, name: ".gitattributes", shown: ".gitattributes" }]);
  assert.equal(all.learned_state_hash.computed, listed.learned_state_hash);
  assert.equal(all.learned_state_hash.matches, true);
  assert.equal(all.model_hash.matches, false, "an extra file is in every file given");
  const exact = vmr.checkFiles({ record: model, files });
  assert.equal(exact.model_hash.computed, listed.model_hash);
  assert.equal(exact.model_hash.matches, true);

  const missing = vmr.checkFiles({ record: model, files: files.slice(1) });
  assert.equal(missing.learned_state_hash.computed, null);
  assert.equal(missing.files[0].status, "missing");

  const changed = files.map((f, i) => (i === 0 ? { ...f, sha256: `sha256:${"cd".repeat(32)}` } : f));
  const mismatch = vmr.checkFiles({ record: model, files: changed });
  assert.equal(mismatch.files[0].status, "mismatch");
  assert.equal(mismatch.learned_state_hash.matches, false);

  const refused = vmr.checkFiles({ record: model, files: [...files, { name: "a/../b", sha256: `sha256:${"00".repeat(32)}`, size: 0 }] });
  assert.deepEqual(refused.refused_names, [{ index: 4, name: "a/../b", shown: "a/../b", reason: "dotdot-segment" }]);
  assert.equal(refused.learned_state_hash.matches, true);

  assert.equal(vmr.checkFiles({ record, files }).refusal.id, "check_files.unsupported_profile");
  assert.equal(vmr.checkFiles({ record: model, files: [{ ...files[0], size: -1 }] }).refusal.id, "check_files.size");
  assert.equal(vmr.checkFiles({ record: model, files: [{ ...files[0], sha256: "abc" }] }).refusal.id, "check_files.digest");
});

test("checkFiles entries carry the exact name, the shown name and their index", () => {
  // QA S1, N1, N4.
  const model = utf8(parity.model_hash.base);
  const files = filesOf(parity.model_hash.base);
  const zero = `sha256:${"00".repeat(32)}`;
  const given = [
    ...files,
    { name: "dir\\w.bin", sha256: zero, size: 0 },
    { name: "a\u{d800}", sha256: zero, size: 0 },
    { ...files[2], sha256: zero },
  ];
  const out = vmr.checkFiles({ record: model, files: given });
  assert.deepEqual(out.extra, [{ index: 4, name: "dir\\w.bin", shown: "dir\\\\w.bin" }]);
  assert.deepEqual(out.refused_names, [
    { index: 2, name: files[2].name, shown: files[2].name, reason: "not-ascending", indexes: [2, 6] },
    { index: 5, name: "a\u{d800}", shown: "a\\u{d800}", reason: "not-unicode" },
    { index: 6, name: files[2].name, shown: files[2].name, reason: "not-ascending", indexes: [2, 6] },
  ]);
  assert.deepEqual(out.files[2], { index: 2, name: files[2].name, shown: files[2].name, status: "duplicate", given_index: null });
  assert.equal(out.files[0].given_index, 0);
});

test("checkFiles hints at a missing file given under a name that differs only by case or Unicode form", () => {
  // QA N3: matching stays exact; the hint says why a file looks present.
  const base = JSON.parse(parity.model_hash.base);
  const files = filesOf(parity.model_hash.base);
  const caseOnly = files.map((f, i) => (i === 0 ? { ...f, name: f.name.toUpperCase() } : f));
  const out = vmr.checkFiles({ record: utf8(parity.model_hash.base), files: caseOnly });
  assert.equal(out.files[0].status, "missing");
  assert.deepEqual(out.near_miss, [{ index: 0, given_index: 0, why: "case" }]);

  base.model_identity.learned_state_components[0].name = "caf\u{e9}.bin";
  const nfd = files.map((f, i) => (i === 0 ? { ...f, name: "cafe\u{301}.bin" } : f));
  const out2 = vmr.checkFiles({ record: utf8(JSON.stringify(base)), files: nfd });
  assert.equal(out2.files[0].status, "missing");
  assert.deepEqual(out2.near_miss, [{ index: 0, given_index: 0, why: "unicode-form" }]);
  assert.deepEqual(vmr.checkFiles({ record: utf8(parity.model_hash.base), files }).near_miss, []);
});

test("load refuses a module whose SHA-256 is not the expected one", async () => {
  // QA N7: the hash is the page's own (Web Crypto), not the module's word.
  const bytes = wasmBytes();
  const hex = createHash("sha256").update(bytes).digest("hex");
  assert.deepEqual((await load(bytes, { expectedSha256: hex })).version(), vmr.version());
  assert.deepEqual((await load(bytes, { expectedSha256: `sha256:${hex.toUpperCase()}` })).version(), vmr.version());
  await assert.rejects(load(bytes, { expectedSha256: "00".repeat(32) }), /sha256_mismatch/);
  await assert.rejects(load(bytes, { expectedSha256: "not a hash" }), TypeError);
});

test("misuse throws; bad input never does", () => {
  const store = vectorStore("ts-basic");
  assert.throws(() => vmr.verify({ record: "text", trustStore: store, at }), TypeError);
  assert.throws(() => vmr.verify({ record, trustStore: 1, at }), TypeError);
  assert.throws(() => vmr.verify({ record, trustStore: store, at: "now" }), TypeError);
  assert.throws(() => vmr.verify({ record, trustStore: store, at, previous: ["x"] }), TypeError);
  assert.throws(() => vmr.verify({ record, trustStore: store, at, requireSignedPack: true }), TypeError);
  assert.throws(() => vmr.verify(null), TypeError);
  assert.throws(() => vmr.inspect([1, 2]), TypeError);
  assert.throws(() => vmr.storeForEmbeddedKey(record, { expectedFingerprint: FINGERPRINT, attestationLevel: 3 }), TypeError);
  assert.throws(() => vmr.checkFiles({ record, files: [{ name: "a", sha256: "b", size: "1" }] }), TypeError);
  assert.throws(() => vmr.fileHasher().update("text"), TypeError);
});

// The LCG and byte mutations of tests/robustness.rs.
function lcg(seed) {
  let state = BigInt(seed);
  return (n) => {
    state = (state * 6364136223846793005n + 1442695040888963407n) & 0xffffffffffffffffn;
    return n === 0 ? 0 : Number((state >> 11n) % BigInt(n));
  };
}
const INTERESTING = [0x00, 0xff, 0x22, 0x7b, 0x7d, 0x5b, 0x5d, 0x2c, 0x3a, 0x5c, 0x84, 0xd2, 0x5b, 0x9b, 0x7f, 0x80];
function mutate(below, b) {
  const out = [...b];
  const i = below(out.length + 1);
  switch (below(5)) {
    case 0: if (out.length) out[i % out.length] ^= 1 << below(8); break;
    case 1: out.splice(i, 0, INTERESTING[below(INTERESTING.length)]); break;
    case 2: out.splice(i, 1 + below(16)); break;
    case 3: out.length = i; break;
    default: out.splice(below(out.length + 1), 0, ...out.slice(i, i + 1 + below(32)));
  }
  return Uint8Array.from(out);
}

test("mutated records, stores and packs never trap: every call returns a result or a refusal", () => {
  const below = lcg(0x5eedc4ec);
  const store = vectorStore("ts-basic");
  const model = utf8(parity.model_hash.base);
  const files = [{ name: "weights.bin", sha256: `sha256:${"00".repeat(32)}`, size: 4 }];
  let current = record;
  let currentStore = store;
  let reports = 0;
  for (let i = 0; i < 1500; i++) {
    if (i % 10 === 0) {
      current = below(2) ? record : model;
      currentStore = store;
    }
    current = mutate(below, current);
    if (below(4) === 0) currentStore = mutate(below, currentStore);
    const v = vmr.verify({ record: current, trustStore: currentStore, at });
    assert.ok(v.report || v.refusal, JSON.stringify(v).slice(0, 200));
    if (v.report) reports++;
    const ins = vmr.inspect(current);
    assert.ok(ins.integrity_against_embedded_key || ins.refusal);
    const s = vmr.storeForEmbeddedKey(current, { expectedFingerprint: "HyoP YysS FOQ5 d6x6 4H8_ pHdd", attestationLevel: "software" });
    assert.ok(typeof s === "string" || s.refusal);
    const cf = vmr.checkFiles({ record: current, files });
    assert.ok(cf.model_hash || cf.refusal);
  }
  assert.ok(reports > 300, `${reports}`);
});

test("random bytes through the raw export never trap", () => {
  const { exports } = new WebAssembly.Instance(new WebAssembly.Module(wasmBytes()), {});
  const below = lcg(0xf4a3e5);
  for (let i = 0; i < 2000; i++) {
    const n = below(64);
    const bytes = Uint8Array.from({ length: n }, () => below(256));
    // Some requests are framed: a length that fits, then the bytes.
    if (n >= 4 && below(2)) new DataView(bytes.buffer).setUint32(0, n - 4, true);
    const ptr = exports.vmr_alloc(n);
    new Uint8Array(exports.memory.buffer, ptr, n).set(bytes);
    const out = exports.vmr_call(below(7), ptr, n);
    const length = new DataView(exports.memory.buffer).getUint32(out, true);
    const text = decoder.decode(new Uint8Array(exports.memory.buffer, out + 4, length));
    exports.vmr_free(out, 4 + length);
    assert.equal(typeof JSON.parse(text), "object");
  }
});
