// The Signed Proof-of-Reserves verifier.
//
// Given a published attestation it answers three independent questions and then
// the single AND of them:
//
//   1. Authenticity  - did the expected key sign this attestation hash?
//                      (EIP-191 personal_sign recovery, fail-closed, low-s.)
//   2. Number binding - do the published figures and the signed timestamp hash
//                      to the signed attestation hash?
//                      ("0x" + sha256(signed_payload_canonical) === attestation_hash)
//   3. Freshness     - is the BOUND (signed) timestamp within the freshness
//                      window? Measured from the timestamp inside the bound
//                      preimage, never from any unsigned top-level field. The
//                      window bounds both directions: too old is stale, and too
//                      far in the future (beyond a small clock-skew allowance) is
//                      rejected too.
//
//   verified = authenticity AND number-binding AND freshness
//
// The verifier is pure, dependency-light, and fail-closed: malformed, missing,
// tampered, replayed, stale, or post-dated inputs resolve to `verified: false`
// with a legible reason. It never throws and never returns a false `verified`.
//
// Why number-binding matters: a signature only proves WHO signed a hash. Without
// rehashing the canonical preimage to that hash, a relay could replay a genuine
// (attestation_hash, signature) pair while swapping every displayed number. By
// requiring sha256(signed_payload_canonical) === attestation_hash, the figures
// and the signed timestamp are bound to the signature, not merely the signer.

import { recoverPersonalSign, addressesEqual } from './recover.js';
import { sha256Hex } from './hash.js';

/** Default freshness window, in seconds. Two hours and ten minutes: a producer
 *  on a 1-hour cadence can miss a single cycle (a restart) without a genuine
 *  attestation flipping to stale. Override per producer cadence. */
export const DEFAULT_MAX_AGE_SECONDS = 7800;

/** Default clock-skew allowance for a bound timestamp in the future, in seconds.
 *  A genuine producer's snapshot timestamp is at or slightly before "now"; a
 *  timestamp more than this far ahead is treated as not fresh (a post-dated
 *  snapshot or a wrong clock), rather than being trusted as fresh forever. */
export const DEFAULT_MAX_FUTURE_SKEW_SECONDS = 300;

/** The default field name, inside the canonical preimage, that carries the
 *  signed unix-seconds timestamp freshness is measured from. */
export const DEFAULT_TIMESTAMP_FIELD = 'timestamp';

/** The on-the-wire shape of a Signed Proof-of-Reserves attestation. Only three
 *  fields are load-bearing; everything else a producer publishes is ignored by
 *  the verifier (the trusted figures live inside `signed_payload_canonical`). */
export interface SignedAttestation {
  /** "0x" + sha256(signed_payload_canonical). The signed message. */
  attestation_hash?: unknown;
  /** 65-byte EIP-191 personal_sign signature over the raw bytes of the hash. */
  signature?: unknown;
  /** The EXACT canonical JSON string the producer hashed. Hashing these bytes
   *  binds the figures and the signed timestamp inside them to the signature. */
  signed_payload_canonical?: unknown;
  /** Self-declared signer. NOT trusted: it is plaintext a tamperer can rewrite.
   *  The verifier reports the cryptographically recovered signer instead. */
  signer?: unknown;
  [key: string]: unknown;
}

export interface VerifyOptions {
  /** The address the attestation MUST be signed by. When omitted, the verifier
   *  still recovers and reports the signer, but `verified` is false because an
   *  unpinned signer is trust-on-first-use, not proof. */
  expectedSigner?: string | null;
  /** Current time, as an epoch-ms number or a Date. Defaults to now. Injectable
   *  for deterministic tests and for verifying historical snapshots. */
  now?: number | Date;
  /** Freshness window in seconds. Defaults to DEFAULT_MAX_AGE_SECONDS. */
  maxAgeSeconds?: number;
  /** Clock-skew allowance for a future-dated bound timestamp, in seconds.
   *  Defaults to DEFAULT_MAX_FUTURE_SKEW_SECONDS. */
  maxFutureSkewSeconds?: number;
  /** Name of the signed unix-seconds field inside the preimage. Default
   *  "timestamp". */
  timestampField?: string;
}

export interface Verdict {
  /** The signature recovered to SOME address (valid 65-byte low-s EIP-191). */
  signatureValid: boolean;
  /** The cryptographically recovered signer (lowercase 0x), or null. */
  recoveredSigner: string | null;
  /** The expected signer that was checked against, or null when none was given. */
  expectedSigner: string | null;
  /** The recovered signer equals the expected signer (case-insensitive). */
  signerMatchesExpected: boolean;
  /** sha256(signed_payload_canonical) === attestation_hash: the figures and the
   *  signed timestamp are bound to the signature. */
  hashMatches: boolean;
  /** "0x" + sha256(signed_payload_canonical), or null when it could not be
   *  computed. */
  derivedHash: string | null;
  /** The attestation_hash as published. */
  attestationHash: string | null;
  /** The signed unix-seconds timestamp read from the bound preimage, or null. */
  boundTimestamp: number | null;
  /** Seconds since the bound timestamp, measured from `now`: positive when the
   *  snapshot is in the past, negative when it is post-dated (in the future).
   *  null when no bound timestamp is available. */
  stalenessSeconds: number | null;
  /** True when the bound timestamp is within the freshness window and not more
   *  than the clock-skew allowance into the future. */
  isFresh: boolean;
  freshnessThresholdSeconds: number;
  /** True only when authenticity AND number-binding AND freshness all hold. */
  verified: boolean;
  /** A human-readable reason when not verified, or null on a clean PASS. */
  reason: string | null;
  /** The parsed canonical preimage, present ONLY when `hashMatches`. This is the
   *  bound source of truth for every displayed figure; when null, no published
   *  number is trustworthy. */
  bound: Record<string, unknown> | null;
}

function nowMsOf(now: number | Date | undefined): number {
  if (now instanceof Date) return now.getTime();
  if (typeof now === 'number' && Number.isFinite(now)) return now;
  return Date.now();
}

function hexEq(a: unknown, b: unknown): boolean {
  return (
    typeof a === 'string' &&
    typeof b === 'string' &&
    a.toLowerCase() === b.toLowerCase()
  );
}

function asTrimmedString(v: unknown): string | null {
  if (typeof v !== 'string') return null;
  const t = v.trim();
  return t.length > 0 ? t : null;
}

/**
 * Verify a published Signed Proof-of-Reserves attestation object (the wire
 * format: `attestation_hash`, `signature`, `signed_payload_canonical`).
 */
export function verifyAttestation(
  attestation: SignedAttestation | null | undefined,
  options: VerifyOptions = {},
): Verdict {
  const expectedSigner = asTrimmedString(options.expectedSigner ?? null);
  const threshold =
    typeof options.maxAgeSeconds === 'number' && Number.isFinite(options.maxAgeSeconds)
      ? options.maxAgeSeconds
      : DEFAULT_MAX_AGE_SECONDS;
  const futureSkew =
    typeof options.maxFutureSkewSeconds === 'number' && Number.isFinite(options.maxFutureSkewSeconds)
      ? options.maxFutureSkewSeconds
      : DEFAULT_MAX_FUTURE_SKEW_SECONDS;
  const tsField = options.timestampField ?? DEFAULT_TIMESTAMP_FIELD;
  const nowMs = nowMsOf(options.now);

  const attestationHash =
    typeof attestation?.attestation_hash === 'string' ? attestation.attestation_hash : null;
  const signature = attestation?.signature;
  const canonical =
    typeof attestation?.signed_payload_canonical === 'string'
      ? attestation.signed_payload_canonical
      : null;

  // 1. Authenticity: recover the signer over the published attestation hash.
  const recoveredSigner = recoverPersonalSign(attestationHash, signature);
  const signatureValid = recoveredSigner !== null;
  const signerMatchesExpected =
    expectedSigner !== null && addressesEqual(recoveredSigner, expectedSigner);

  // 2. Number binding: rehash the canonical preimage and require it to equal the
  //    signed attestation hash. Parse the figures ONLY after they are bound.
  let derivedHash: string | null = null;
  let hashMatches = false;
  let bound: Record<string, unknown> | null = null;
  if (canonical !== null && canonical.length > 0) {
    try {
      derivedHash = sha256Hex(canonical);
    } catch {
      derivedHash = null;
    }
  }
  if (derivedHash !== null && attestationHash !== null && hexEq(derivedHash, attestationHash)) {
    try {
      const parsed: unknown = JSON.parse(canonical as string);
      if (parsed !== null && typeof parsed === 'object' && !Array.isArray(parsed)) {
        bound = parsed as Record<string, unknown>;
        hashMatches = true;
      }
    } catch {
      bound = null;
      hashMatches = false;
    }
  }

  // 3. Freshness from the BOUND signed timestamp only. stalenessSeconds is
  //    positive in the past and negative when the snapshot is post-dated. The
  //    window bounds both directions: older than the threshold is stale, and
  //    more than the clock-skew allowance into the future is rejected (a genuine
  //    snapshot is never far ahead of real time).
  let boundTimestamp: number | null = null;
  let stalenessSeconds: number | null = null;
  const ts = bound?.[tsField];
  if (typeof ts === 'number' && Number.isFinite(ts)) {
    boundTimestamp = ts;
    stalenessSeconds = Math.floor(nowMs / 1000 - ts);
  }
  const isFresh =
    stalenessSeconds !== null &&
    stalenessSeconds < threshold &&
    stalenessSeconds >= -futureSkew;

  const verified = signatureValid && signerMatchesExpected && hashMatches && isFresh;

  const reason = buildReason({
    expectedSigner,
    signatureValid,
    signerMatchesExpected,
    recoveredSigner,
    hashMatches,
    canonicalPresent: canonical !== null && canonical.length > 0,
    boundTimestampPresent: boundTimestamp !== null,
    isFresh,
    stalenessSeconds,
    threshold,
    futureSkew,
    tsField,
  });

  return {
    signatureValid,
    recoveredSigner,
    expectedSigner,
    signerMatchesExpected,
    hashMatches,
    derivedHash,
    attestationHash,
    boundTimestamp,
    stalenessSeconds,
    isFresh,
    freshnessThresholdSeconds: threshold,
    verified,
    reason,
    bound,
  };
}

/**
 * Convenience verifier for the "paste three things" flow used by an in-browser
 * verify tool: the canonical payload, the signature, and the expected signer,
 * with no separate attestation_hash field. The hash is DERIVED from the payload
 * (sha256) and the signer is recovered over that derived hash, so a single
 * edited byte changes the hash, the recovered signer no longer matches, and the
 * verdict fails. The number-binding is inherent in the signer match.
 */
export function verifyCanonical(
  canonical: unknown,
  signature: unknown,
  expectedSigner: string | null | undefined,
  options: Omit<VerifyOptions, 'expectedSigner'> = {},
): Verdict {
  let attestation_hash: string | null = null;
  if (typeof canonical === 'string' && canonical.length > 0) {
    try {
      attestation_hash = sha256Hex(canonical);
    } catch {
      attestation_hash = null;
    }
  }
  return verifyAttestation(
    { attestation_hash: attestation_hash ?? undefined, signature, signed_payload_canonical: canonical },
    { ...options, expectedSigner: expectedSigner ?? null },
  );
}

function buildReason(s: {
  expectedSigner: string | null;
  signatureValid: boolean;
  signerMatchesExpected: boolean;
  recoveredSigner: string | null;
  hashMatches: boolean;
  canonicalPresent: boolean;
  boundTimestampPresent: boolean;
  isFresh: boolean;
  stalenessSeconds: number | null;
  threshold: number;
  futureSkew: number;
  tsField: string;
}): string | null {
  if (!s.signatureValid) {
    return 'FAIL: the signature does not recover to any address. It is missing, malformed, not 65 bytes, or not a canonical (low-s) EIP-191 signature.';
  }
  if (s.expectedSigner === null) {
    return `NO EXPECTED SIGNER: the signature is valid and recovered to ${s.recoveredSigner}, but no expected signer was provided to check it against. Pin ${s.recoveredSigner} as the expected signer to get a trusted verdict; an unpinned signer is trust-on-first-use, not proof.`;
  }
  if (!s.signerMatchesExpected) {
    return `FAIL: the signature is valid but recovered to ${s.recoveredSigner}, which does not match the expected signer. Either the attestation was signed by a different key, the signature belongs to a different payload, or the expected signer address is wrong.`;
  }
  if (!s.canonicalPresent) {
    return 'FAIL: the signer matches, but signed_payload_canonical is missing, so the published figures cannot be bound to the signature.';
  }
  if (!s.hashMatches) {
    return 'FAIL: the signer matches, but sha256(signed_payload_canonical) does not equal attestation_hash. The published figures do not match what was signed (canonical preimage tampered, malformed, or not the one that was hashed).';
  }
  if (!s.boundTimestampPresent) {
    return `FAIL: the figures are bound to the signature, but the preimage has no numeric "${s.tsField}" field, so freshness cannot be confirmed.`;
  }
  if (!s.isFresh && s.stalenessSeconds !== null && s.stalenessSeconds < 0) {
    return `FUTURE: the signature is authentic and the figures are bound to it, but the snapshot is post-dated ${-s.stalenessSeconds} seconds into the future, beyond the ${s.futureSkew} second clock-skew allowance. A clock is wrong or the snapshot was post-dated.`;
  }
  if (!s.isFresh) {
    return `STALE: the signature is authentic, from the expected signer, and the figures are bound to it, but the snapshot is ${s.stalenessSeconds} seconds old, beyond the ${s.threshold} second freshness window. The figures may be out of date.`;
  }
  return null;
}
