// vmr-check.js — the browser checker's interface (docs/BROWSER.md)
//
// A hand-written ES module with no dependencies. It loads vmr-check.wasm,
// which imports nothing, and turns each call into one framed request to the
// module's plain C exports (vmr/crates/vmr-check/src/ffi.rs, api.rs).
// Everything after load() is synchronous, runs on this computer, and sends
// nothing anywhere.
//
// Bad input never throws: it returns { refusal: { id, input, detail } }.
// A call throws only on misuse: an argument of the wrong type, or a hasher
// or a log verifier used after finish().

const OP_VERSION = 1;
const OP_VERIFY = 2;
const OP_INSPECT = 3;
const OP_STORE_FOR_EMBEDDED_KEY = 4;
const OP_CHECK_FILES = 5;
const OP_CHECK_ITEM = 6;

// The hasher and the log verifier copy a chunk into the module through one
// buffer of this size, so a chunk of any size never grows the module's
// memory (QA N2).
const HASH_BUFFER = 1024 * 1024;

const encoder = new TextEncoder();
const decoder = new TextDecoder("utf-8", { fatal: true });

/**
 * Load the checker. `source` is the module's bytes (a Uint8Array or an
 * ArrayBuffer), a URL (a URL object or a string) to fetch them from, or a
 * fetch Response. With `options.expectedSha256` (64 hex digits, as a
 * SHA256SUMS line gives them, with or without "sha256:"), the bytes are
 * hashed here with Web Crypto, never by the module itself, and a module
 * whose SHA-256 differs is refused: the promise rejects with an error whose
 * code is "module.sha256_mismatch".
 */
export async function load(source, options = {}) {
  const expected = expectedSha256(options);
  let bytes;
  if (source instanceof Uint8Array) {
    bytes = source;
  } else if (source instanceof ArrayBuffer) {
    bytes = new Uint8Array(source);
  } else if (typeof Response !== "undefined" && source instanceof Response) {
    bytes = new Uint8Array(await source.arrayBuffer());
  } else if (source instanceof URL || typeof source === "string") {
    const response = await fetch(source);
    if (!response.ok) {
      throw new Error(`vmr-check: cannot load ${source}: HTTP ${response.status}`);
    }
    bytes = new Uint8Array(await response.arrayBuffer());
  } else {
    throw new TypeError("vmr-check: load() takes the module's bytes, a URL or a Response");
  }
  if (expected !== undefined) {
    const subtle = globalThis.crypto?.subtle;
    if (!subtle) {
      throw new Error("vmr-check: expectedSha256 needs Web Crypto (crypto.subtle), which this page does not have");
    }
    const actual = hex(new Uint8Array(await subtle.digest("SHA-256", bytes)));
    if (actual !== expected) {
      const error = new Error(`vmr-check: module.sha256_mismatch: the module's SHA-256 is ${actual}, not ${expected}`);
      error.code = "module.sha256_mismatch";
      throw error;
    }
  }
  const { instance } = await WebAssembly.instantiate(bytes, {});
  return checker(instance.exports);
}

function expectedSha256(options) {
  if (options === null || typeof options !== "object") {
    throw new TypeError("vmr-check: load() options must be an object");
  }
  const value = options.expectedSha256;
  if (value === undefined) return undefined;
  const digits = typeof value === "string" ? value.replace(/^sha256:/i, "").toLowerCase() : "";
  if (!/^[0-9a-f]{64}$/.test(digits)) {
    throw new TypeError("vmr-check: expectedSha256 must be 64 hex digits, with or without sha256:");
  }
  return digits;
}

function hex(bytes) {
  return Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");
}

function checker(ex) {
  // Copy the header and `blobs` into one framed request in the module's
  // memory: each part a u32 little-endian length and its bytes.
  function request(header, blobs) {
    const parts = [encoder.encode(JSON.stringify(header)), ...blobs];
    const total = parts.reduce((n, p) => n + 4 + p.length, 0);
    const ptr = ex.vmr_alloc(total);
    const memory = new Uint8Array(ex.memory.buffer, ptr, total);
    const view = new DataView(ex.memory.buffer, ptr, total);
    let at = 0;
    for (const part of parts) {
      view.setUint32(at, part.length, true);
      memory.set(part, at + 4);
      at += 4 + part.length;
    }
    return [ptr, total];
  }

  function call(op, header, blobs) {
    const [ptr, total] = request(header, blobs);
    // vmr_call takes the request buffer back; the answer is a new one.
    return JSON.parse(answer(ex.vmr_call(op, ptr, total)));
  }

  // Feed `chunk` to `update(ptr, len)` through the one buffer `state` holds,
  // a piece at a time; stop when `update` returns false.
  function feed(state, chunk, update) {
    if (state.buffer === 0) state.buffer = ex.vmr_alloc(HASH_BUFFER);
    for (let at = 0; at < chunk.length; at += HASH_BUFFER) {
      const piece = chunk.subarray(at, at + HASH_BUFFER);
      new Uint8Array(ex.memory.buffer, state.buffer, piece.length).set(piece);
      if (update(state.buffer, piece.length) === false) return false;
    }
    return true;
  }

  // Read an answer buffer (u32 little-endian length, then the bytes), return
  // it to the module, and give its text.
  function answer(ptr) {
    const length = new DataView(ex.memory.buffer).getUint32(ptr, true);
    const text = decoder.decode(new Uint8Array(ex.memory.buffer, ptr + 4, length).slice());
    ex.vmr_free(ptr, 4 + length);
    return text;
  }

  return {
    /** { vmr, record_format } */
    version() {
      return call(OP_VERSION, {}, []);
    },

    /**
     * Verify `record` against `trustStore` at `at` (Unix seconds, the
     * caller's clock), with a policy pack's evaluation when `pack` is given.
     * -> { accepted, outcome, fingerprint, report, report_json, policy,
     *      at_source: "caller" } or a refusal. A page's headline is
     * `outcome`, never `report.verdict` alone.
     */
    verify(args) {
      const a = object(args, "verify");
      const record = bytes(a.record, "record");
      const trustStore = document(a.trustStore, "trustStore");
      if (typeof a.at !== "number") {
        throw new TypeError("vmr-check: verify: at must be a number (Unix seconds)");
      }
      const pack = optional(a.pack, "pack", document);
      const authorityStore = optional(a.authorityStore, "authorityStore", document);
      const previous = a.previous === undefined ? [] : array(a.previous, "previous").map((p, i) => bytes(p, `previous[${i}]`));
      const requireSignedPack = flag(a.requireSignedPack, "requireSignedPack");
      const requireCompleteLineage = flag(a.requireCompleteLineage, "requireCompleteLineage");
      if (pack === undefined && (authorityStore !== undefined || requireSignedPack)) {
        throw new TypeError("vmr-check: verify: authorityStore and requireSignedPack apply only with a pack");
      }
      const header = {
        at: Number.isFinite(a.at) ? a.at : null,
        previous: previous.length,
        pack: pack !== undefined,
        authority_store: authorityStore !== undefined,
        require_signed_pack: requireSignedPack,
        require_complete_lineage: requireCompleteLineage,
      };
      const blobs = [record, trustStore];
      if (pack !== undefined) blobs.push(pack);
      if (authorityStore !== undefined) blobs.push(authorityStore);
      return call(OP_VERIFY, header, blobs.concat(previous));
    },

    /**
     * What `record` says about itself, its key's fingerprint, and whether its
     * signature matches the key it carries (integrity, not trust).
     */
    inspect(record) {
      return call(OP_INSPECT, {}, [bytes(record, "record")]);
    },

    /**
     * A trust store (JSON text) trusting `record`'s own key for the issuer it
     * names, from its issued_at, at `attestationLevel` ("self" when absent):
     * what `vmr trust-store add` writes. `expectedFingerprint` is the
     * fingerprint the reader typed or pasted from the issuer's own
     * publication; it must be the key's (spaces ignored), and the record's
     * signature must match the key. A refusal object when it cannot.
     */
    storeForEmbeddedKey(record, options) {
      const r = bytes(record, "record");
      const o = object(options, "storeForEmbeddedKey");
      if (typeof o.expectedFingerprint !== "string") {
        throw new TypeError("vmr-check: storeForEmbeddedKey: expectedFingerprint (the fingerprint the issuer publishes) is required");
      }
      if (o.attestationLevel !== undefined && typeof o.attestationLevel !== "string") {
        throw new TypeError("vmr-check: storeForEmbeddedKey: attestationLevel must be a string");
      }
      const result = call(
        OP_STORE_FOR_EMBEDDED_KEY,
        {
          // Text that is not Unicode cannot be sent as JSON; with its lone
          // surrogates replaced it can only fail to compare (QA N1).
          expected_fingerprint: wellFormed(o.expectedFingerprint),
          attestation_level: o.attestationLevel === undefined ? null : wellFormed(o.attestationLevel),
        },
        [r],
      );
      return typeof result.trust_store === "string" ? result.trust_store : result;
    },

    /** A streaming SHA-256: update(chunk) any number of times, then finish(). */
    fileHasher() {
      let hasher = ex.vmr_hasher_new();
      const state = { buffer: 0 };
      return {
        update(chunk) {
          if (hasher === null) throw new Error("vmr-check: the hasher is spent: finish() was called");
          const c = bytes(chunk, "chunk");
          feed(state, c, (ptr, len) => ex.vmr_hasher_update(hasher, ptr, len));
        },
        finish() {
          if (hasher === null) throw new Error("vmr-check: the hasher is spent: finish() was called");
          const h = hasher;
          hasher = null;
          if (state.buffer !== 0) ex.vmr_free(state.buffer, HASH_BUFFER);
          return answer(ex.vmr_hasher_finish(h));
        },
      };
    },

    /**
     * An audit log checked as it streams in, as `vmr log verify` checks it:
     * update(chunk) any number of times, then finish(). `auditKey` is the
     * audit key's public key file (string or Uint8Array), `checkpoints` an
     * array of checkpoint documents (Uint8Array), `checkpointsJsonl` a
     * checkpoint history (Uint8Array), `profile` "core" (the default),
     * "khalm-vmr.enforcer" or "vmr.agent". update() returns false once the
     * answer is known (a refusal), when the rest of the log need not be read.
     * finish() -> { outcome: "verified" | "chain_only" | "failed", entries,
     * root, checkpoints, uncovered, checked, refusal, summary, notes, ... },
     * or { refusal: { id, input, detail } } for an input it cannot use.
     */
    logVerifier(args = {}) {
      const a = object(args, "logVerifier");
      const auditKey = optional(a.auditKey, "auditKey", document);
      const checkpoints =
        a.checkpoints === undefined ? [] : array(a.checkpoints, "checkpoints").map((c, i) => bytes(c, `checkpoints[${i}]`));
      const history = optional(a.checkpointsJsonl, "checkpointsJsonl", bytes);
      if (a.profile !== undefined && typeof a.profile !== "string") {
        throw new TypeError("vmr-check: logVerifier: profile must be a string");
      }
      if (auditKey === undefined && (checkpoints.length > 0 || history !== undefined)) {
        throw new TypeError("vmr-check: logVerifier: checkpoints and checkpointsJsonl need the auditKey they are checked under");
      }
      const header = {
        profile: a.profile === undefined ? "core" : wellFormed(a.profile),
        audit_key: auditKey !== undefined,
        checkpoints: checkpoints.length,
        checkpoints_jsonl: history !== undefined,
      };
      const blobs = [];
      if (auditKey !== undefined) blobs.push(auditKey);
      blobs.push(...checkpoints);
      if (history !== undefined) blobs.push(history);
      const [ptr, total] = request(header, blobs);
      // vmr_log_new takes the request buffer back.
      let session = ex.vmr_log_new(ptr, total);
      let wanted = true;
      const state = { buffer: 0 };
      return {
        update(chunk) {
          if (session === null) throw new Error("vmr-check: the log verifier is spent: finish() was called");
          const c = bytes(chunk, "chunk");
          if (wanted) wanted = feed(state, c, (p, len) => ex.vmr_log_update(session, p, len) !== 0);
          return wanted;
        },
        finish() {
          if (session === null) throw new Error("vmr-check: the log verifier is spent: finish() was called");
          const s = session;
          session = null;
          if (state.buffer !== 0) ex.vmr_free(state.buffer, HASH_BUFFER);
          return JSON.parse(answer(ex.vmr_log_finish(s)));
        },
      };
    },

    /**
     * Whether `content` under `itemKey` (64 hex digits, as `vmr log disclose`
     * prints it) gives the digest entry `index` of `log` carries in `member`,
     * every line up to the entry checked: what `vmr log check-item` says.
     * -> { matches, index, kind, label, in_entry, computed, not_checked } or a
     * refusal. Whether a signed checkpoint covers the entry is logVerifier's.
     */
    checkItem(args) {
      const a = object(args, "checkItem");
      const log = bytes(a.log, "log");
      const content = bytes(a.content, "content");
      if (!Number.isSafeInteger(a.index) || a.index < 0) {
        throw new TypeError("vmr-check: checkItem: index must be a whole number from 0");
      }
      if (typeof a.member !== "string" || typeof a.itemKey !== "string") {
        throw new TypeError("vmr-check: checkItem: member and itemKey must be strings");
      }
      return call(OP_CHECK_ITEM, { index: a.index, member: wellFormed(a.member), item_key: wellFormed(a.itemKey) }, [log, content]);
    },

    /**
     * The files a reader holds, against the files `record` lists, and the
     * record's learned-state and model hashes over them (spec §7.2-7.3).
     * Every entry carries `name` (exact, for matching), `shown` (for showing)
     * and `index`; `near_miss` pairs a missing file with a given one whose
     * name differs only by case or Unicode form (matching stays exact).
     */
    checkFiles(args) {
      const a = object(args, "checkFiles");
      const record = bytes(a.record, "record");
      const given = array(a.files, "files").map((f, i) => {
        const file = object(f, `files[${i}]`);
        if (typeof file.name !== "string" || typeof file.sha256 !== "string" || typeof file.size !== "number") {
          throw new TypeError(`vmr-check: checkFiles: files[${i}] must be { name: string, sha256: string, size: number }`);
        }
        return file;
      });
      const files = given.map((file) => {
        const sent = { sha256: wellFormed(file.sha256), size: Number.isFinite(file.size) ? file.size : null };
        // A name that is not Unicode (a lone surrogate) goes as its UTF-16
        // code units and is refused as that one name (QA N1).
        if (isWellFormed(file.name)) sent.name = file.name;
        else sent.name_utf16 = Array.from({ length: file.name.length }, (_, i) => file.name.charCodeAt(i));
        return sent;
      });
      const out = call(OP_CHECK_FILES, { files }, [record]);
      if (out.refusal) return out;
      for (const refused of out.refused_names) {
        if (refused.name === null) refused.name = given[refused.index].name;
      }
      out.near_miss = nearMisses(out);
      return out;
    },
  };
}

// Each missing listed file paired with an extra given file whose name is the
// same under Unicode normalisation (NFC), or also under lower case (QA N3).
function nearMisses(out) {
  const near = [];
  for (const listed of out.files.filter((f) => f.status === "missing")) {
    const a = listed.name.normalize("NFC");
    for (const extra of out.extra) {
      const b = extra.name.normalize("NFC");
      const why = a === b ? "unicode-form" : a.toLowerCase() === b.toLowerCase() ? "case" : null;
      if (why) near.push({ index: listed.index, given_index: extra.index, why });
    }
  }
  return near;
}

function isWellFormed(text) {
  for (let i = 0; i < text.length; i++) {
    const unit = text.charCodeAt(i);
    if (unit >= 0xd800 && unit <= 0xdbff) {
      const next = text.charCodeAt(i + 1);
      if (!(next >= 0xdc00 && next <= 0xdfff)) return false;
      i++;
    } else if (unit >= 0xdc00 && unit <= 0xdfff) {
      return false;
    }
  }
  return true;
}

// `text` with each lone surrogate replaced by U+FFFD.
function wellFormed(text) {
  if (isWellFormed(text)) return text;
  let out = "";
  for (let i = 0; i < text.length; i++) {
    const unit = text.charCodeAt(i);
    const next = text.charCodeAt(i + 1);
    if (unit >= 0xd800 && unit <= 0xdbff && next >= 0xdc00 && next <= 0xdfff) {
      out += text[i] + text[i + 1];
      i++;
    } else if (unit >= 0xd800 && unit <= 0xdfff) {
      out += "\u{fffd}";
    } else {
      out += text[i];
    }
  }
  return out;
}

function object(value, what) {
  if (value === null || typeof value !== "object") {
    throw new TypeError(`vmr-check: ${what} takes an object`);
  }
  return value;
}

function array(value, what) {
  if (!Array.isArray(value)) throw new TypeError(`vmr-check: ${what} must be an array`);
  return value;
}

function bytes(value, what) {
  if (!(value instanceof Uint8Array)) throw new TypeError(`vmr-check: ${what} must be a Uint8Array`);
  return value;
}

// A JSON document: its text, or its exact bytes.
function document(value, what) {
  if (typeof value === "string") return encoder.encode(value);
  if (value instanceof Uint8Array) return value;
  throw new TypeError(`vmr-check: ${what} must be a string or a Uint8Array`);
}

function optional(value, what, read) {
  return value === undefined || value === null ? undefined : read(value, what);
}

function flag(value, what) {
  if (value === undefined) return false;
  if (typeof value !== "boolean") throw new TypeError(`vmr-check: ${what} must be a boolean`);
  return value;
}
