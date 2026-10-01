// Every published vector through the built module (docs/BROWSER.md, "Proof"):
// the same report bytes as the native library (tests/data/parity.json, which
// tests/parity.rs generates and pins), the same refusal ids, and each
// vector's own expected answer.
import { test } from "node:test";
import assert from "node:assert/strict";
import {
  baseCase, cases, checker, hexBytes, inputBytes, json, outcome, parity, unix, utf8, vectorStore,
} from "./common.mjs";

const vmr = await checker();
const base = baseCase();
const baseRecord = inputBytes(base.input);
const baseAt = unix(base.evaluation_time);

test("every verification vector gives the native report, byte for byte", () => {
  const all = cases("verify/cases.json");
  for (const c of all) {
    const answer = vmr.verify({
      record: inputBytes(c.input),
      trustStore: vectorStore(c.trust_store),
      at: unix(c.evaluation_time),
      previous: c.previous.map(inputBytes),
      requireCompleteLineage: c.require_complete_lineage,
    });
    assert.deepEqual(outcome(answer), { report_sha256: parity.verify[c.id] }, c.id);
    assert.equal(answer.at_source, "caller");
    assert.equal(answer.policy, null);
    const report = JSON.parse(answer.report_json);
    assert.equal(report.verdict, c.expected.verdict, c.id);
    if (c.expected.check) assert.equal(report.failure.check, c.expected.check, c.id);
    if (c.expected.lineage) assert.equal(report.lineage.status, c.expected.lineage, c.id);
  }
  assert.ok(all.length >= 400);
});

test("every trust-store vector is loaded or refused as the native loader does", () => {
  for (const c of cases("trust-store/cases.json")) {
    const answer = vmr.verify({ record: baseRecord, trustStore: inputBytes(c.input), at: baseAt });
    assert.deepEqual(outcome(answer), parity.trust_store[c.id], c.id);
    if (c.expected.result === "ok") {
      assert.equal(JSON.parse(answer.report_json).trust_store.sha256, c.expected.sha256, c.id);
    } else {
      assert.equal(answer.refusal.id, c.expected.kind, c.id);
      assert.equal(answer.refusal.input, "trust_store", c.id);
    }
  }
});

test("every policy vector gives the native report and its expected evaluation", () => {
  const status = { pass: "compliant", fail: "non-compliant", indeterminate: "indeterminate" };
  let verifiable = 0;
  for (const c of cases("policy/cases.json")) {
    const entry = parity.policy[c.id];
    const record = utf8(entry.record ?? c.record.text);
    const previous = (c.context?.predecessors ?? []).map((p) => utf8(p.text));
    const answer = vmr.verify({
      record, trustStore: vectorStore("ts-basic"), at: unix(c.evaluation_time), pack: c.pack.text, previous,
    });
    const { record: _, ...expected } = entry;
    assert.deepEqual(outcome(answer), expected, c.id);
    if (c.verifiable) {
      verifiable++;
      assert.equal(answer.policy.state, "evaluated", c.id);
      assert.equal(answer.policy.status, status[c.expected.overall], c.id);
      assert.deepEqual(
        answer.policy.rules.map((r) => [r.rule_id, r.status, r.severity, r.evidence_hash]),
        c.expected.results.map((r) => [r.rule_id, r.status, r.severity, r.evidence_hash]),
        c.id,
      );
    }
  }
  assert.ok(verifiable >= 100, `${verifiable}`);
});

test("every pack-loader vector is loaded or refused as the native loader does", () => {
  for (const c of json("specs/test-vectors/policy/pack-loader.json").cases) {
    const answer = vmr.verify({
      record: baseRecord, trustStore: vectorStore("ts-basic"), at: baseAt, pack: inputBytes(c.pack),
    });
    assert.deepEqual(outcome(answer), parity.pack_loader[c.id], c.id);
    if (c.expected.result === "ok") {
      assert.equal(answer.policy.policy_pack_payload_hash, c.expected.pack_payload_hash, c.id);
    } else {
      assert.equal(answer.refusal.id, c.expected.refusal, c.id);
    }
  }
});

test("every pack-signature vector gives its state or its refusal", () => {
  for (const c of json("specs/test-vectors/policy/pack-signature.json").cases) {
    const answer = vmr.verify({
      record: baseRecord,
      trustStore: c.trust_store.text,
      at: unix(c.evaluation_time),
      pack: c.pack.text,
      authorityStore: c.authority_store?.text,
      requireSignedPack: c.require_signed_pack,
    });
    assert.deepEqual(outcome(answer), parity.pack_signature[c.id], c.id);
    if (c.expected.exit_code === 0) {
      assert.deepEqual(answer.policy.pack_signature, c.expected.pack_signature, c.id);
      assert.equal(answer.policy.policy_pack_payload_hash, c.expected.pack_payload_hash, c.id);
    } else {
      assert.equal(answer.refusal.id, c.expected.refusal, c.id);
    }
  }
});

test("every model-hash vector of files gives its digest or its refusal through checkFiles", () => {
  const zero = `sha256:${"00".repeat(32)}`;
  const baseModel = utf8(parity.model_hash.base);
  const seen = {};
  for (const c of cases("model-hash/cases.json")) {
    seen[c.kind] = (seen[c.kind] ?? 0) + 1;
    const files = (members) => members.map((m) => ({ name: m.name, sha256: `sha256:${m.sha256}`, size: m.bytes_hex.length / 2 }));
    if (c.kind === "named-set-digest" || c.kind === "named-set-digests") {
      const sets = c.kind === "named-set-digest" ? { [c.id]: [c.members, c.expected.digest] }
        : Object.fromEntries(Object.entries(c.sets).map(([k, s]) => [`${c.id}/${k}`, [s, c.expected[k]]]));
      for (const [key, [members, digest]] of Object.entries(sets)) {
        const out = vmr.checkFiles({ record: utf8(parity.model_hash[key]), files: files(members) });
        // The record lists every member, so the two digests are one (§7.3).
        for (const hash of ["learned_state_hash", "model_hash"]) {
          assert.equal(out[hash].computed, digest, `${key} ${hash}`);
          assert.equal(out[hash].matches, true, `${key} ${hash}`);
        }
        assert.ok(out.files.every((f) => f.status === "match"), key);
        // The streaming hasher, chunk by chunk, gives each member's SHA-256.
        for (const m of members) {
          const h = vmr.fileHasher();
          const b = hexBytes(m.bytes_hex);
          for (let i = 0; i < b.length; i += 3) h.update(b.subarray(i, i + 3));
          assert.equal(h.finish(), `sha256:${m.sha256}`, key);
        }
      }
    } else if (c.kind === "name") {
      const out = vmr.checkFiles({ record: baseModel, files: [{ name: c.name, sha256: zero, size: 0 }] });
      // Names come back through display_safe, which doubles a backslash
      // (these names hold no other character it escapes).
      const shown = c.name.replaceAll("\\", "\\\\");
      if (c.expected.accepted) {
        assert.deepEqual(out.refused_names, [], c.id);
        assert.deepEqual(out.extra, [{ index: 0, name: c.name, shown }], c.id);
      } else {
        assert.deepEqual(out.refused_names, [{ index: 0, name: c.name, shown, reason: c.expected.reason }], c.id);
      }
    } else if (c.kind === "set-refused") {
      // A record listing the names in the refused order has no digest of
      // its components.
      const given = c.names.map((name) => ({ name, sha256: zero, size: 0 }));
      const out = vmr.checkFiles({ record: utf8(parity.model_hash[c.id]), files: given });
      assert.equal(out.learned_state_hash.computed, null, c.id);
      // A name given twice is refused at both places, and the given files
      // have no digest either.
      if (new Set(c.names).size < c.names.length) {
        assert.deepEqual(out.refused_names.map((r) => r.reason), [c.expected.reason, c.expected.reason], c.id);
        assert.equal(out.model_hash.computed, null, c.id);
      }
    } else {
      // named-set-v1 training records (spec §8.2) are not a model's files.
      assert.equal(c.kind, "named-set-records", c.id);
    }
  }
  assert.ok(seen["named-set-digest"] >= 5 && seen.name >= 10 && seen["set-refused"] >= 3, JSON.stringify(seen));
});
