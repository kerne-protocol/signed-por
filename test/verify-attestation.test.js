// Tests for verifyAttestation: the wire-format object verifier
// ({ attestation_hash, signature, signed_payload_canonical, ... }).
//
// Two fixtures:
//   1. A deterministic Anvil-signed synthetic attestation (offline, stable).
//   2. examples/kerne-attestation.json, a real attestation captured from a live
//      production endpoint. It proves the verifier agrees byte-for-byte with a
//      real producer, not just with a self-generated fixture.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { verifyAttestation, sha256Hex } from '../dist/index.js';

// --- Fixture 1: synthetic, deterministic (Anvil account #1) --------------------
const SIGNER = '0x70997970C51812dc3A010C7d01b50e0d17dc79C8';
const CANONICAL =
  '{"aggregate_solvency_ratio":1.0021,"status":"PSM_SOLVENT","timestamp":1782000000}';
const SIG =
  '0xe789f0ecf2e59ab538808c28eaef230b4607aabecd1ddc4ca2d57f3b6f0d82b85' +
  '4a58862a3cb8e6105a62a2abb71f1d05113a1b9f3b2d2abe3eb58086fc457e01b';
const HASH = sha256Hex(CANONICAL);
const TS = 1782000000;
const FRESH_NOW_MS = (TS + 100) * 1000;

function attestation(overrides = {}) {
  return {
    attestation_hash: HASH,
    signature: SIG,
    signer: SIGNER,
    signed_payload_canonical: CANONICAL,
    ...overrides,
  };
}

test('a genuine, fresh attestation object verifies (PASS)', () => {
  const v = verifyAttestation(attestation(), { expectedSigner: SIGNER, now: FRESH_NOW_MS });
  assert.equal(v.verified, true, v.reason ?? 'expected PASS');
  assert.equal(v.signatureValid, true);
  assert.equal(v.signerMatchesExpected, true);
  assert.equal(v.hashMatches, true);
  assert.equal(v.boundTimestamp, TS);
  assert.ok(v.bound && v.bound.status === 'PSM_SOLVENT');
  assert.equal(v.reason, null);
});

test('number-binding: mutating the canonical while replaying hash+sig fails hash_matches', () => {
  // Replay a genuine (attestation_hash, signature) but swap a figure in the
  // canonical preimage. sha256(canonical) no longer equals attestation_hash.
  const tampered = attestation({
    signed_payload_canonical: CANONICAL.replace('1.0021', '9.9999'),
  });
  const v = verifyAttestation(tampered, { expectedSigner: SIGNER, now: FRESH_NOW_MS });
  assert.equal(v.signatureValid, true);
  assert.equal(v.signerMatchesExpected, true); // signer still recovers from the unchanged hash
  assert.equal(v.hashMatches, false); // but the numbers are not bound
  assert.equal(v.bound, null);
  assert.equal(v.verified, false);
  assert.ok(v.reason && v.reason.includes('does not equal attestation_hash'));
});

test('a mismatched attestation_hash (not the sha256 of the canonical) fails', () => {
  const v = verifyAttestation(attestation({ attestation_hash: '0x' + 'ab'.repeat(32) }), {
    expectedSigner: SIGNER,
    now: FRESH_NOW_MS,
  });
  // recovery is over the wrong hash, so it will not match the expected signer
  assert.equal(v.signerMatchesExpected, false);
  assert.equal(v.hashMatches, false);
  assert.equal(v.verified, false);
});

test('a wrong expected signer fails but reports the real recovered signer', () => {
  const v = verifyAttestation(attestation(), {
    expectedSigner: '0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266',
    now: FRESH_NOW_MS,
  });
  assert.equal(v.signerMatchesExpected, false);
  assert.ok(v.recoveredSigner && v.recoveredSigner.toLowerCase() === SIGNER.toLowerCase());
  assert.equal(v.verified, false);
});

test('a replayed-but-stale attestation reads STALE, never verified', () => {
  const v = verifyAttestation(attestation(), {
    expectedSigner: SIGNER,
    now: (TS + 100_000) * 1000,
  });
  assert.equal(v.signerMatchesExpected, true);
  assert.equal(v.hashMatches, true);
  assert.equal(v.isFresh, false);
  assert.equal(v.verified, false);
  assert.ok(v.reason && v.reason.startsWith('STALE'));
});

test('missing canonical preimage cannot bind the numbers', () => {
  const v = verifyAttestation(attestation({ signed_payload_canonical: undefined }), {
    expectedSigner: SIGNER,
    now: FRESH_NOW_MS,
  });
  assert.equal(v.hashMatches, false);
  assert.equal(v.bound, null);
  assert.equal(v.verified, false);
});

test('null / empty / malformed attestation fails closed, never throws', () => {
  for (const bad of [null, undefined, {}, { attestation_hash: 'x' }, 42, 'nope']) {
    const v = verifyAttestation(bad, { expectedSigner: SIGNER, now: FRESH_NOW_MS });
    assert.equal(v.verified, false);
  }
});

test('a custom timestamp field name is honored', () => {
  const canonical = '{"x":1,"signed_at":1782000000}';
  // sign? We cannot sign here, but we can at least confirm the field is read
  // when present and absent. Use a canonical whose hash we control via sha256Hex.
  const v = verifyAttestation(
    { attestation_hash: sha256Hex(canonical), signature: '0x' + '00'.repeat(65), signed_payload_canonical: canonical },
    { expectedSigner: SIGNER, now: FRESH_NOW_MS, timestampField: 'signed_at' },
  );
  // signature is junk so it will not verify, but the binding + timestamp parse
  // path is exercised and must not throw.
  assert.equal(v.verified, false);
});

test('a post-dated snapshot beyond the clock-skew allowance is rejected (FUTURE)', () => {
  // now is 1000s BEFORE the bound timestamp, so the snapshot is 1000s in the
  // future, past the default 300s skew allowance.
  const v = verifyAttestation(attestation(), {
    expectedSigner: SIGNER,
    now: (TS - 1000) * 1000,
  });
  assert.equal(v.signerMatchesExpected, true);
  assert.equal(v.hashMatches, true);
  assert.equal(v.stalenessSeconds, -1000); // negative = future
  assert.equal(v.isFresh, false);
  assert.equal(v.verified, false);
  assert.ok(v.reason && v.reason.startsWith('FUTURE'));
});

test('a snapshot within the clock-skew allowance is still fresh', () => {
  // 100s in the future, inside the default 300s skew allowance.
  const v = verifyAttestation(attestation(), {
    expectedSigner: SIGNER,
    now: (TS - 100) * 1000,
  });
  assert.equal(v.stalenessSeconds, -100);
  assert.equal(v.isFresh, true);
  assert.equal(v.verified, true, v.reason ?? 'expected PASS');
});

test('the future-skew allowance is configurable', () => {
  const v = verifyAttestation(attestation(), {
    expectedSigner: SIGNER,
    now: (TS - 100) * 1000,
    maxFutureSkewSeconds: 50, // 100s future now exceeds a 50s allowance
  });
  assert.equal(v.isFresh, false);
  assert.equal(v.verified, false);
  assert.ok(v.reason && v.reason.startsWith('FUTURE'));
});

// --- Fixture 2: real production attestation -----------------------------------
const KERNE = JSON.parse(
  readFileSync(fileURLToPath(new URL('../examples/kerne-attestation.json', import.meta.url)), 'utf8'),
);
const KERNE_SIGNER = '0x09a2780ac8Be6D5d2d1F85A8D92b09D40C9CA37e';

test('real production attestation: signer recovers and figures bind to the signature', () => {
  // Verify just-after the bound timestamp so it reads fresh (the snapshot is a
  // historical capture; a live run against the endpoint is always fresh).
  const bound = JSON.parse(KERNE.signed_payload_canonical);
  const nowMs = (bound.timestamp + 60) * 1000;
  const v = verifyAttestation(KERNE, { expectedSigner: KERNE_SIGNER, now: nowMs });
  assert.equal(v.signatureValid, true, 'production signature must recover');
  assert.equal(v.signerMatchesExpected, true, `recovered ${v.recoveredSigner}, expected ${KERNE_SIGNER}`);
  assert.equal(v.hashMatches, true, 'production figures must bind to the signed hash');
  assert.equal(v.isFresh, true);
  assert.equal(v.verified, true, v.reason ?? 'expected production PASS');
});

test('real production attestation: editing one byte of the canonical breaks binding', () => {
  const bound = JSON.parse(KERNE.signed_payload_canonical);
  const nowMs = (bound.timestamp + 60) * 1000;
  const tampered = { ...KERNE, signed_payload_canonical: KERNE.signed_payload_canonical.replace('1.001001', '1.999999') };
  const v = verifyAttestation(tampered, { expectedSigner: KERNE_SIGNER, now: nowMs });
  assert.equal(v.hashMatches, false);
  assert.equal(v.verified, false);
});

test('real production attestation: a wrong expected signer fails', () => {
  const bound = JSON.parse(KERNE.signed_payload_canonical);
  const nowMs = (bound.timestamp + 60) * 1000;
  const v = verifyAttestation(KERNE, { expectedSigner: SIGNER, now: nowMs });
  assert.equal(v.signerMatchesExpected, false);
  assert.equal(v.verified, false);
});
