// SHA-256 of a UTF-8 string, as a 0x-prefixed hex digest.
//
// This is the exact hash a Signed Proof-of-Reserves producer applies to the
// canonical preimage to form the attestation hash. On the producer side
// (Python) that is `"0x" + hashlib.sha256(canonical.encode()).hexdigest()`.
// We hash the published STRING bytes directly, never a re-serialization, so
// there is no cross-language float-formatting hazard between Python's
// `json.dumps(..., separators=(",",":"))` and JavaScript's `JSON.stringify`.

import { sha256 } from '@noble/hashes/sha2';
import { bytesToHex } from '@noble/hashes/utils';

/**
 * `"0x" + sha256(utf8(s))`. Byte-for-byte equal to the producer's
 * `"0x" + hashlib.sha256(s.encode()).hexdigest()`.
 */
export function sha256Hex(s: string): string {
  return '0x' + bytesToHex(sha256(new TextEncoder().encode(s)));
}
