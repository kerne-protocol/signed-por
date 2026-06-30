// Tests for EIP-191 personal_sign recovery (recoverPersonalSign, addressesEqual).
//
// The fixture is a deterministic EIP-191 personal_sign over a fixed 32-byte hash
// by the well-known Anvil/Hardhat account #1 key, so the test is fully offline
// and stable. Anvil account #1 is a public test key; embedding its signature is
// safe and reproducible.
//
// Run (after `npm run build`):  node --test test/

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { secp256k1 } from '@noble/curves/secp256k1';
import { bytesToHex, hexToBytes } from '@noble/hashes/utils';
import { recoverPersonalSign, addressesEqual } from '../dist/index.js';

const SIGNER = '0x70997970C51812dc3A010C7d01b50e0d17dc79C8';
const HASH = '0xa6b4ee128270283acddc958f4ab4b78e01df30d0785453d8b20730667c55ebca';
const SIG =
  '0x482c863c11e0459e517802e672365f9962fd932bd5c44556a16e754438d5736b' +
  '22771d5f325d3469ae3d79f264cf6ca81c2861cce706b94c814c48337cb277681b';

// Build the EIP-2 non-canonical (high-s) malleability twin of a low-s 65-byte
// signature: (r, s, v) -> (r, n-s, v^1). Without low-s enforcement this DISTINCT
// signature recovers to the SAME signer, so a verifier that accepts it is
// malleable. Computed offline from the curve order; no network.
function malleate(sigHex) {
  const raw = hexToBytes(sigHex.startsWith('0x') ? sigHex.slice(2) : sigHex);
  const r = raw.slice(0, 32);
  const s = BigInt('0x' + bytesToHex(raw.slice(32, 64)));
  const s2 = secp256k1.CURVE.n - s;
  const v2 = ((raw[64] - 27) ^ 1) + 27;
  return '0x' + bytesToHex(r) + s2.toString(16).padStart(64, '0') + v2.toString(16).padStart(2, '0');
}

test('recovers the fixture signature to the expected signer', () => {
  const recovered = recoverPersonalSign(HASH, SIG);
  assert.ok(recovered !== null, 'recovery should succeed');
  assert.ok(addressesEqual(recovered, SIGNER), `got ${recovered}`);
});

test('addressesEqual is case-insensitive and null-safe', () => {
  assert.equal(addressesEqual(SIGNER, SIGNER.toLowerCase()), true);
  assert.equal(addressesEqual(null, SIGNER), false);
  assert.equal(addressesEqual(undefined, undefined), false);
});

test('junk signature with out-of-range v returns null (fail closed)', () => {
  assert.equal(recoverPersonalSign(HASH, '0x' + '11'.repeat(65)), null);
});

test('a one-byte-tampered signature does not recover to the signer', () => {
  const tampered = '0x49' + SIG.slice(4); // flip first r byte 0x48 -> 0x49
  assert.equal(addressesEqual(recoverPersonalSign(HASH, tampered), SIGNER), false);
});

test('the signed hash is bound: a different hash does not recover to the signer', () => {
  const otherHash = '0x' + 'ab'.repeat(32);
  assert.equal(addressesEqual(recoverPersonalSign(otherHash, SIG), SIGNER), false);
});

test('rejects the malleated (high-s) twin of a valid signature (EIP-2 low-s)', () => {
  assert.ok(addressesEqual(recoverPersonalSign(HASH, SIG), SIGNER), 'genuine low-s must still verify');
  const twin = malleate(SIG);
  assert.notEqual(twin.toLowerCase(), SIG.toLowerCase());
  assert.equal(recoverPersonalSign(HASH, twin), null, 'high-s twin must be rejected');
});

test('malformed inputs return null', () => {
  assert.equal(recoverPersonalSign(HASH, '0xdeadbeef'), null); // wrong length
  assert.equal(recoverPersonalSign('', SIG), null); // empty hash
  assert.equal(recoverPersonalSign(HASH, 'not-hex-zzzz'), null); // non-hex
  assert.equal(recoverPersonalSign(123, SIG), null); // non-string
  assert.equal(recoverPersonalSign(HASH, undefined), null); // missing
});
