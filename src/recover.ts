// EIP-191 personal_sign signer recovery.
//
// A Signed Proof-of-Reserves attestation is signed with the standard EIP-191
// personal_sign scheme over the RAW 32 bytes of the attestation hash. In Python
// (eth_account) that is `encode_defunct(hexstr=attestation_hash)` followed by
// `sign_message`; in JS (ethers) it is `signMessage(getBytes(attestation_hash))`.
// Either way the signed digest is:
//
//   keccak256("\x19Ethereum Signed Message:\n32" || <32 hash bytes>)
//
// `recoverPersonalSign` recovers the Ethereum address that produced such a
// signature. It is implemented on @noble/curves (the same audited secp256k1
// implementation that ethers and viem build on) so that a verifier never has to
// pull in a full wallet SDK. The two @noble packages are independently audited
// and have zero transitive dependencies of their own.
//
// Fail closed: every malformed, wrong-length, non-canonical, or tampered input
// resolves to `null`. A caller that treats `null` (or a mismatch) as
// "unverified" can never be tricked into trusting a forged or malleated
// signature.

import { secp256k1 } from '@noble/curves/secp256k1';
import { keccak_256 } from '@noble/hashes/sha3';
import { bytesToHex, hexToBytes } from '@noble/hashes/utils';

function strip0x(h: string): string {
  return h.startsWith('0x') || h.startsWith('0X') ? h.slice(2) : h;
}

// EIP-191 personal_sign digest over a raw-bytes message.
function personalSignDigest(msgBytes: Uint8Array): Uint8Array {
  const prefix = new TextEncoder().encode(
    '\x19Ethereum Signed Message:\n' + msgBytes.length,
  );
  const full = new Uint8Array(prefix.length + msgBytes.length);
  full.set(prefix, 0);
  full.set(msgBytes, prefix.length);
  return keccak_256(full);
}

// address = last 20 bytes of keccak256(uncompressed pubkey without the 0x04 tag).
function addressFromPubUncompressed(pub: Uint8Array): string {
  const h = keccak_256(pub.slice(1));
  return '0x' + bytesToHex(h.slice(12));
}

/**
 * Recover the Ethereum address that produced an EIP-191 personal_sign signature
 * over the raw bytes of `attestationHashHex`. Returns the lowercase 0x address,
 * or `null` if inputs are malformed or recovery fails. Never throws.
 *
 * Security: EIP-2 canonical low-s is enforced. secp256k1 is malleable, so for
 * every signature `(r, s, v)` there is a distinct twin `(r, n - s, v ^ 1)` that
 * recovers to the SAME signer. Accepting high-s would admit a second valid
 * 65-byte signature for every message, which breaks any dedup or replay key
 * built on the signature bytes. A conformant producer always emits low-s, so
 * this rejects only malleated twins, never a genuine attestation signature.
 */
export function recoverPersonalSign(
  attestationHashHex: unknown,
  signatureHex: unknown,
): string | null {
  try {
    if (typeof attestationHashHex !== 'string' || typeof signatureHex !== 'string') {
      return null;
    }
    const msgBytes = hexToBytes(strip0x(attestationHashHex));
    if (msgBytes.length === 0) return null;
    const sig = hexToBytes(strip0x(signatureHex));
    if (sig.length !== 65) return null;
    let v = sig[64];
    if (v >= 27) v -= 27;
    if (v !== 0 && v !== 1) return null;
    const rs = sig.slice(0, 64);
    const signature = secp256k1.Signature.fromCompact(rs).addRecoveryBit(v);
    if (signature.hasHighS()) return null; // reject non-canonical high-s (EIP-2)
    const point = signature.recoverPublicKey(personalSignDigest(msgBytes));
    return addressFromPubUncompressed(point.toRawBytes(false)).toLowerCase();
  } catch {
    return null;
  }
}

/** Case-insensitive 0x-address equality, null-safe. */
export function addressesEqual(
  a: string | null | undefined,
  b: string | null | undefined,
): boolean {
  return (
    typeof a === 'string' &&
    typeof b === 'string' &&
    a.toLowerCase() === b.toLowerCase()
  );
}
