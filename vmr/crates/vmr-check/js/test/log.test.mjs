// logVerifier and checkItem through the built module (docs/BROWSER.md,
// "Audit logs"): the whole-log vectors give the results the native code gives
// (vmr/crates/vmr-check/tests/log.rs holds it to the same declared results),
// the example agent log verifies with the counts `vmr log verify` prints,
// whatever the chunking, one changed byte fails, and checkItem agrees with the
// example README's disclosure.
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { checker, json, repo, utf8 } from "./common.mjs";

const vmr = await checker();
const example = (name) => new Uint8Array(readFileSync(join(repo, "docs", "examples", "agent-log", name)));
const key = example("audit-key.pub.json");
const checkpoint = example("checkpoint.json");
const log = example("log.jsonl");

function run(args, bytes, chunk = 1024 * 1024) {
  const lv = vmr.logVerifier(args);
  for (let at = 0; at < bytes.length; at += chunk) {
    if (!lv.update(bytes.subarray(at, at + chunk))) break;
  }
  return lv.finish();
}

// Every whole-log case: the core vectors' logs and one-line entries, and the
// vmr.agent profile's entries, each read as a log of one entry.
function wholeLogCases() {
  const core = json("specs/test-vectors/audit-log/cases.json");
  const agent = json("specs/test-vectors/audit-profile-agent/cases.json");
  const out = core.logs.map((c) => ({ id: c.id, profile: "core", bytes: utf8(c.raw), expect: c.expect }));
  for (const c of core.entries) out.push({ id: c.id, profile: c.profile ?? "core", bytes: utf8(c.raw + "\n"), expect: c.expect });
  for (const c of agent.entries) out.push({ id: c.id, profile: "vmr.agent", bytes: utf8(c.raw + "\n"), expect: c.expect });
  return out;
}

test("every whole-log vector gives the native result", () => {
  const cases = wholeLogCases();
  assert.equal(cases.length, 6 + 12 + 74);
  for (const c of cases) {
    const answer = run({ profile: c.profile }, c.bytes);
    if (c.expect === "accept") {
      assert.equal(answer.outcome, "chain_only", c.id);
      assert.equal(answer.refusal, null, c.id);
    } else {
      assert.equal(answer.outcome, "failed", c.id);
      assert.equal(answer.refusal.id, c.expect, c.id);
    }
  }
});

test("the example agent log verifies with the counts vmr prints", () => {
  const answer = run({ profile: "vmr.agent", auditKey: key, checkpoints: [checkpoint] }, log);
  assert.equal(answer.outcome, "verified");
  assert.equal(answer.entries, 14);
  assert.equal(answer.headline, "14 entries; 1 checkpoint signed by the pinned audit key covers entries 0 to 13");
  assert.deepEqual(answer.checkpoints, [
    { source: "checkpoints[0]", tree_size: 14, issued_at: "2026-09-30T08:42:26Z", covers_whole_log: true },
  ]);
  assert.equal(answer.uncovered, null);
  assert.equal(answer.summary.statements_of, "the log's writer");
  assert.equal(answer.summary.sessions, 1);
  assert.equal(answer.summary.calls_proposed, 2);
  assert.deepEqual(answer.summary.refused_by_gate, { guard: 1 });
  assert.equal(answer.summary.approvals_granted, 1);
  assert.deepEqual(answer.notes, []);
  // The key's text works as its bytes do.
  const text = new TextDecoder().decode(key);
  assert.deepEqual(run({ profile: "vmr.agent", auditKey: text, checkpoints: [checkpoint] }, log), answer);
});

test("1-byte, 7-byte and 1 MiB chunks give the same result", () => {
  const args = { profile: "vmr.agent", auditKey: key, checkpointsJsonl: checkpoint };
  const whole = run(args, log);
  assert.equal(whole.outcome, "verified");
  for (const chunk of [1, 7, 1024 * 1024]) assert.deepEqual(run(args, log, chunk), whole, `chunks of ${chunk}`);
});

test("without a key or a checkpoint only the chain is checked, and the result says so", () => {
  const answer = run({}, log);
  assert.equal(answer.outcome, "chain_only");
  assert.equal(answer.profile, "core");
  assert.deepEqual(answer.uncovered, { from: 0, to: 13 });
  assert.ok(answer.checked.some((s) => s.endsWith("nothing about what the entries mean is checked")));
  assert.ok(answer.checked.some((s) => s.endsWith("no signature was checked")));
  assert.equal(run({ auditKey: key }, log).outcome, "chain_only");
});

test("one changed byte fails", () => {
  const changed = log.slice();
  changed[Math.floor(changed.length / 2)] ^= 1;
  const answer = run({ profile: "vmr.agent", auditKey: key, checkpoints: [checkpoint] }, changed);
  assert.equal(answer.outcome, "failed");
  assert.equal(typeof answer.refusal.id, "string");
  // A checkpoint that is not of the log: the reader's own id.
  const short = log.subarray(0, log.indexOf(10) + 1);
  assert.equal(run({ auditKey: key, checkpoints: [checkpoint] }, short).refusal.id, "log_verify.checkpoint_not_in_log");
});

test("checkItem agrees with the example README's disclosure", () => {
  const itemKey = "11200c6264981efb8fbbdcd4e3ce185d1db9dcda617e774843dff5c578b0cd3d";
  const content = example("arguments.txt");
  const answer = vmr.checkItem({ log, index: 4, member: "arguments_digest", itemKey, content });
  assert.equal(answer.matches, true);
  assert.equal(answer.label, "call.proposed/arguments_digest/4");
  const changed = content.slice();
  changed[0] ^= 1;
  assert.equal(vmr.checkItem({ log, index: 4, member: "arguments_digest", itemKey, content: changed }).matches, false);
  assert.equal(vmr.checkItem({ log, index: 4, member: "nope", itemKey, content }).refusal.id, "check_item.no_digest");
  assert.equal(vmr.checkItem({ log, index: 4, member: "arguments_digest", itemKey: "11zz", content }).refusal.id, "check_item.item_key");
});

test("bad input gives a refusal; misuse and a call after finish throw", () => {
  assert.equal(run({ profile: "acme.other" }, log).refusal.id, "profile.unknown");
  assert.equal(run({ auditKey: "{}" }, log).refusal.id, "audit_key.unusable");
  assert.equal(run({ auditKey: key, checkpointsJsonl: new Uint8Array() }, log).refusal.id, "checkpoint_history.empty");
  assert.throws(() => vmr.logVerifier({ checkpoints: [checkpoint] }), TypeError);
  assert.throws(() => vmr.logVerifier({ profile: 3 }), TypeError);
  const lv = vmr.logVerifier({});
  assert.throws(() => lv.update("text"), TypeError);
  lv.update(log);
  lv.finish();
  assert.throws(() => lv.update(log));
  assert.throws(() => lv.finish());
  assert.throws(() => vmr.checkItem({ log, index: -1, member: "m", itemKey: "k", content: log }), TypeError);
});
