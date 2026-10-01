// Shared support for the Node tests of the built module (node --test, the
// standard library only). VMR_CHECK_WASM names the built vmr-check.wasm:
//   cargo build --release -p vmr-check --target wasm32-unknown-unknown
//   VMR_CHECK_WASM=<target dir>/wasm32-unknown-unknown/release/vmr_check.wasm \
//     node --test vmr/crates/vmr-check/js/test/
import { readFileSync } from "node:fs";
import { createHash } from "node:crypto";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { load } from "../vmr-check.js";

const here = dirname(fileURLToPath(import.meta.url));
export const repo = join(here, "..", "..", "..", "..", "..");
export const crate = join(here, "..", "..");

export function wasmBytes() {
  const path = process.env.VMR_CHECK_WASM;
  if (!path) {
    throw new Error("set VMR_CHECK_WASM to the built vmr_check.wasm (see js/test/common.mjs)");
  }
  return new Uint8Array(readFileSync(path));
}

export async function checker() {
  return load(wasmBytes());
}

export function json(rel) {
  return JSON.parse(readFileSync(join(repo, rel), "utf8"));
}

export function cases(rel) {
  return json(join("specs", "test-vectors", rel)).cases;
}

export function vectorStore(name) {
  return new Uint8Array(readFileSync(join(repo, "specs", "test-vectors", "verify", "trust-stores", `${name}.json`)));
}

export const parity = JSON.parse(readFileSync(join(crate, "tests", "data", "parity.json"), "utf8"));

const encoder = new TextEncoder();

export function utf8(text) {
  return encoder.encode(text);
}

export function hexBytes(hex) {
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(hex.slice(2 * i, 2 * i + 2), 16);
  return out;
}

// A vector input's bytes: its text or hex, then append_spaces spaces.
export function inputBytes(input) {
  const body = input.text !== undefined ? utf8(input.text) : hexBytes(input.hex);
  const spaces = input.append_spaces ?? 0;
  if (spaces === 0) return body;
  const out = new Uint8Array(body.length + spaces);
  out.set(body);
  out.fill(0x20, body.length);
  return out;
}

// Unix seconds of a profile timestamp YYYY-MM-DDTHH:MM:SSZ.
export function unix(t) {
  const ms = Date.parse(t);
  if (Number.isNaN(ms)) throw new Error(`not a timestamp: ${t}`);
  return ms / 1000;
}

export function sha256Hex(text) {
  return createHash("sha256").update(text, "utf8").digest("hex");
}

// The report hash or the refusal id of a verify answer, as parity.json
// writes it.
export function outcome(answer) {
  return typeof answer.report_json === "string"
    ? { report_sha256: sha256Hex(answer.report_json) }
    : { refusal: answer.refusal.id };
}

export function baseCase() {
  return cases("verify/cases.json").find((c) => c.id === "pass-vector-json");
}
