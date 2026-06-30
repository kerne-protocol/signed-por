// signed-por: a tiny, vendor-neutral verifier for Signed Proof-of-Reserves
// attestations. See SPEC.md for the format and README.md for the project intent.
//
// Public API:
//   verifyAttestation(attestation, options)  - verify a published attestation object
//   verifyCanonical(canonical, sig, signer)  - verify a pasted canonical + signature
//   recoverPersonalSign(hash, signature)     - low-level EIP-191 signer recovery
//   addressesEqual(a, b)                      - case-insensitive 0x-address equality
//   sha256Hex(s)                              - "0x" + sha256(utf8(s))

export {
  verifyAttestation,
  verifyCanonical,
  DEFAULT_MAX_AGE_SECONDS,
  DEFAULT_MAX_FUTURE_SKEW_SECONDS,
  DEFAULT_TIMESTAMP_FIELD,
  type SignedAttestation,
  type VerifyOptions,
  type Verdict,
} from './verify.js';

export { recoverPersonalSign, addressesEqual } from './recover.js';
export { sha256Hex } from './hash.js';
