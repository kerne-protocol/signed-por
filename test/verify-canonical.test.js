// Tests for verifyCanonical: the "paste three things" flow (canonical payload,
// signature, expected signer) with no separate attestation_hash field. The hash
// is DERIVED from the payload and the signer is recovered over it, so the number
// binding is inherent in the signer match.
//
// Deterministic offline fixture: Anvil account #1 signs EIP-191 over
// "0x" + sha256(CANONICAL). Regenerating must keep the three values in sync.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { verifyCanonical } from '../dist/index.js';

const SIGNER = '0x70997970C51812dc3A010C7d01b50e0d17dc79C8';
const CANONICAL =
  '{"aggregate_solvency_ratio":1.0021,"status":"PSM_SOLVENT","timestamp":1782000000}';
const SIG =
  '0xe789f0ecf2e59ab538808c28eaef230b4607aabecd1ddc4ca2d57f3b6f0d82b85' +
  '4a58862a3cb8e6105a62a2abb71f1d05113a1b9f3b2d2abe3eb58086fc457e01b';
const KNOWN_HASH =
  '0xf312bd2bd48a53fb8890dd974546f3a6ff390dde983e6713cc2a1c917469a70c';
const TS = 1782000000;
const FRESH_NOW_MS = (TS + 100) * 1000;

test('a genuine, fresh attestation verifies (PASS)', () => {
  const v = verifyCanonical(CANONICAL, SIG, SIGNER, { now: FRESH_NOW_MS });
  assert.equal(v.verified, true, v.reason ?? 'expected PASS');
  assert.equal(v.signatureValid, true);
  assert.equal(v.signerMatchesExpected, true);
  assert.ok(v.recoveredSigner && v.recoveredSigner.toLowerCase() === SIGNER.toLowerCase());
  assert.equal(v.derivedHash, KNOWN_HASH, 'derived hash must equal sha256(payload)');
  assert.equal(v.boundTimestamp, TS);
  assert.equal(v.stalenessSeconds, 100);
  assert.equal(v.isFresh, true);
  assert.equal(v.reason, null);
});

test('a different expected signer does not match (FAIL, but signature still valid)', () => {
  const other = '0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266'; // Anvil account #0
  const v = verifyCanonical(CANONICAL, SIG, other, { now: FRESH_NOW_MS });
  assert.equal(v.signatureValid, true);
  assert.equal(v.signerMatchesExpected, false);
  assert.equal(v.verified, false);
  assert.ok(v.reason && v.reason.startsWith('FAIL'));
});

test('a one-character-tampered payload no longer matches the signer (FAIL)', () => {
  const tampered = CANONICAL.replace('1.0021', '1.0031');
  assert.notEqual(tampered, CANONICAL);
  const v = verifyCanonical(tampered, SIG, SIGNER, { now: FRESH_NOW_MS });
  assert.equal(v.signatureValid, true);
  assert.equal(v.signerMatchesExpected, false);
  assert.equal(v.verified, false);
  assert.notEqual(v.derivedHash, KNOWN_HASH);
});

test('a genuine but old attestation is STALE (authentic, not fresh)', () => {
  const staleNowMs = (TS + 100_000) * 1000;
  const v = verifyCanonical(CANONICAL, SIG, SIGNER, { now: staleNowMs });
  assert.equal(v.signatureValid, true);
  assert.equal(v.signerMatchesExpected, true);
  assert.equal(v.isFresh, false);
  assert.equal(v.verified, false);
  assert.ok(v.reason && v.reason.startsWith('STALE'));
});

test('a custom freshness window is honored', () => {
  const v = verifyCanonical(CANONICAL, SIG, SIGNER, { now: FRESH_NOW_MS, maxAgeSeconds: 50 });
  assert.equal(v.isFresh, false);
  assert.equal(v.verified, false);
  assert.equal(v.freshnessThresholdSeconds, 50);
});

test('a malformed signature fails closed', () => {
  const v = verifyCanonical(CANONICAL, '0xdeadbeef', SIGNER, { now: FRESH_NOW_MS });
  assert.equal(v.signatureValid, false);
  assert.equal(v.recoveredSigner, null);
  assert.equal(v.verified, false);
});

test('an empty payload prompts rather than crashes', () => {
  const v = verifyCanonical('', SIG, SIGNER, { now: FRESH_NOW_MS });
  assert.equal(v.verified, false);
  assert.equal(v.derivedHash, null);
});

test('non-string inputs fail closed (mirror missing fields)', () => {
  assert.equal(verifyCanonical(123, SIG, SIGNER, { now: FRESH_NOW_MS }).verified, false);
  assert.equal(verifyCanonical(CANONICAL, undefined, SIGNER, { now: FRESH_NOW_MS }).verified, false);
  assert.equal(verifyCanonical(CANONICAL, SIG, null, { now: FRESH_NOW_MS }).signerMatchesExpected, false);
});

test('a non-JSON but otherwise present payload fails closed on parse', () => {
  const v = verifyCanonical('not json at all', SIG, SIGNER, { now: FRESH_NOW_MS });
  assert.equal(v.hashMatches, false);
  assert.equal(v.verified, false);
});

test('no expected signer yields a legible NO EXPECTED SIGNER verdict, not a false PASS', () => {
  const v = verifyCanonical(CANONICAL, SIG, null, { now: FRESH_NOW_MS });
  assert.equal(v.signatureValid, true);
  assert.equal(v.signerMatchesExpected, false);
  assert.equal(v.verified, false);
  assert.ok(v.reason && v.reason.startsWith('NO EXPECTED SIGNER'));
});
