# Signed Proof-of-Reserves (Signed PoR)

**Attestation format and verification rules. Version 1.0.0 (draft).**

This document specifies a small, self-contained format that lets any party
publish a reserve snapshot that a reader can verify with no trusted third party:
no attestor, no oracle, no API key, no wallet. A reader recovers the signer,
confirms the published figures are the ones that were signed, and confirms the
snapshot is recent, using only a public key they already trust and a small
verifier that is short enough to audit by eye.

It is deliberately minimal. It standardizes the wire format and the verification
algorithm, nothing else. It does not define what reserves are, how to compute
solvency, or what a healthy ratio is. Those are the producer's concern; this
spec only makes the producer's published numbers checkable.

The key words MUST, MUST NOT, REQUIRED, SHOULD, SHOULD NOT, and MAY in this
document are to be interpreted as described in RFC 2119.

---

## 1. Motivation

Most "proof of reserves" pages ask the reader to trust the page. A signed
attestation inverts that: the reader checks the cryptography themselves. The
hard part is doing it without re-introducing trust through the back door. Three
properties have to hold together:

1. **Authenticity.** A specific, known key signed this attestation.
2. **Number-binding.** The displayed figures are the exact figures that key
   signed, not numbers swapped in afterward next to a replayed signature.
3. **Freshness.** The snapshot is recent, measured from a timestamp that is
   itself signed, not from an unsigned field a relay could backdate.

A signature alone gives you only the first. This format gives you all three, and
the verification is short enough to audit by eye.

---

## 2. The attestation object

An attestation is a JSON object. Three fields are load-bearing and REQUIRED.
Everything else a producer publishes is informational and is ignored by the
verifier.

| Field                       | Type   | Required | Meaning                                                                 |
| --------------------------- | ------ | -------- | ----------------------------------------------------------------------- |
| `signed_payload_canonical`  | string | yes      | The exact canonical JSON string that was hashed. The bound source of truth for every figure and for the signed timestamp. |
| `attestation_hash`          | string | yes      | `"0x"` + lowercase hex SHA-256 of the UTF-8 bytes of `signed_payload_canonical`. The signed message. |
| `signature`                 | string | yes      | `"0x"` + 65-byte EIP-191 `personal_sign` signature over the raw bytes of `attestation_hash`. |
| `signer`                    | string | no       | The producer's self-declared signer address. Informational only. It is plaintext a tamperer can rewrite, so a verifier MUST NOT trust it; it reports the cryptographically recovered signer instead. |

The trusted figures do not live at the top level of the object. They live inside
`signed_payload_canonical`, because only those bytes are bound to the signature.
A producer MAY also echo figures at the top level for convenience, but a verifier
MUST read trusted values only from the parsed canonical preimage, and only after
the hash check in section 6 passes.

### 2.1 The canonical preimage

`signed_payload_canonical` is a JSON object serialized to a string. It MUST
contain a numeric `timestamp` field (unix seconds, the moment the snapshot was
taken). It SHOULD contain whatever reserve figures the producer wants to make
checkable (collateral, liabilities, a backing ratio, per-venue balances, and so
on). The names and shapes of those figures are out of scope here.

Example preimage (abbreviated):

```json
{"aggregate_solvency_ratio":1.001001,"outstanding_kusd":117.735154,"psm_usdc_reserve":117.853006,"status":"PSM_SOLVENT","timestamp":1782834547}
```

---

## 3. Canonicalization

The producer MUST publish, as `signed_payload_canonical`, the **exact byte
string it hashed**. The verifier hashes those published bytes directly and never
re-serializes the object. This is the single most important design choice in the
format, and it removes an entire class of bug:

- There is no cross-language float-formatting hazard. Python's
  `json.dumps(..., separators=(",",":"))` and JavaScript's `JSON.stringify`
  format `1.001001` or `1e-17` differently, and a verifier that re-serialized the
  parsed object before hashing would compute a different hash and reject a
  genuine attestation. Hashing the published string sidesteps this entirely.
- The producer is free to choose any serialization, as long as it publishes the
  bytes it actually hashed. Producers SHOULD use a deterministic, reproducible
  canonicalization (for example, sorted keys with compact separators, as the
  reference deployment does:
  `json.dumps(data, sort_keys=True, separators=(",",":"))`) so that an
  independent observer can regenerate the same bytes from the same inputs. The
  verifier does not require this, but it makes the producer's claim reproducible
  rather than merely checkable.

A verifier MUST NOT canonicalize, normalize, re-order, or re-encode
`signed_payload_canonical` before hashing it.

---

## 4. Hashing

```
attestation_hash = "0x" + lowercase_hex( sha256( utf8_bytes(signed_payload_canonical) ) )
```

SHA-256 is used (not keccak-256) for the preimage hash. The result is a 32-byte
digest rendered as a 64-character lowercase hex string with a `0x` prefix.

---

## 5. Signing

The signature is a standard EIP-191 `personal_sign` over the **raw 32 bytes** of
`attestation_hash` (not over its hex string). Equivalently, the signed digest is:

```
keccak256( "\x19Ethereum Signed Message:\n32" || <32 bytes of attestation_hash> )
```

Producer references:

- Python (eth-account): `encode_defunct(hexstr=attestation_hash)` then
  `Account.sign_message(...)`.
- JavaScript (ethers): `wallet.signMessage(getBytes(attestation_hash))`.

The signature MUST be 65 bytes (`r` 32, `s` 32, `v` 1) and MUST be canonical
low-s per EIP-2 (see section 8.3). The recovery byte `v` MAY be encoded as 0/1 or
27/28; a verifier MUST accept both.

---

## 6. Verification

A conforming verifier takes an attestation object, an **expected signer**
address, the current time, and a freshness window, and computes four results.

```
1. AUTHENTICITY
   recovered := ecrecover_personal_sign(attestation_hash, signature)
   signatureValid        := recovered != null   (valid 65-byte, low-s signature)
   signerMatchesExpected := recovered == expectedSigner   (case-insensitive)

2. NUMBER-BINDING
   derivedHash := "0x" + sha256_hex(signed_payload_canonical)
   hashMatches := (derivedHash == attestation_hash)
                  AND signed_payload_canonical parses to a JSON object
   bound       := JSON.parse(signed_payload_canonical)  (only when hashMatches)

3. FRESHNESS
   ts               := bound.timestamp        (a finite number, unix seconds)
   stalenessSeconds := floor(now_seconds - ts) (positive in the past, negative if post-dated)
   isFresh          := ts present
                       AND stalenessSeconds < maxAgeSeconds
                       AND stalenessSeconds >= -maxFutureSkewSeconds

4. VERDICT
   verified := signatureValid AND signerMatchesExpected AND hashMatches AND isFresh
```

The freshness check bounds both directions. A snapshot older than `maxAgeSeconds`
is stale. A snapshot whose signed timestamp is more than `maxFutureSkewSeconds`
ahead of the current time is rejected as well: a genuine snapshot is never far
ahead of real time, so an unbounded future timestamp would otherwise read fresh
forever. `maxFutureSkewSeconds` is a small clock-skew allowance (the reference
verifier defaults to 300 seconds).

Rules:

- A verifier MUST recover the signer cryptographically and MUST NOT trust the
  `signer` field.
- A verifier MUST require an explicit expected signer for a positive verdict. If
  no expected signer is supplied, `verified` is false: an unpinned signer is
  trust-on-first-use, not proof. The verifier SHOULD still report the recovered
  signer so the caller can pin it.
- A verifier MUST read trusted figures only from `bound`, only when `hashMatches`
  is true.
- A verifier MUST measure freshness from the bound `timestamp`, never from an
  unsigned top-level field.
- A verifier MUST reject a bound `timestamp` more than `maxFutureSkewSeconds`
  into the future, so a post-dated snapshot does not read fresh forever.
- A verifier MUST be fail-closed: any malformed, missing, tampered, replayed,
  stale, or post-dated input yields `verified: false`, never a thrown error and
  never a false positive.
- `verified` is the single field a consumer should gate on.

The expected timestamp field name defaults to `timestamp` but MAY be overridden
by a verifier for producers that name it differently.

---

## 7. Freshness window

`maxAgeSeconds` is producer-defined and SHOULD be set from the producer's
publishing cadence. The reference deployment publishes hourly and uses 7800
seconds (two cadences plus a ten-minute grace), so a single missed cycle from a
restart does not flip a genuine attestation to stale. A verifier SHOULD let the
caller override the window.

The window also bounds the future. A genuine snapshot's timestamp is at or
slightly before the current time, never far ahead of it, so a verifier rejects a
bound timestamp more than `maxFutureSkewSeconds` into the future
(the reference verifier defaults to 300 seconds). Without this bound, a
post-dated timestamp would read fresh indefinitely. The allowance absorbs
ordinary clock skew between producer and verifier.

Freshness is a property of the snapshot, not of the signature. A correctly
signed, number-bound, but old attestation is reported as `STALE`, and a
post-dated one as `FUTURE`; both are authentic but not fresh, and both are
distinct from a `FAIL` (not authentic or not bound).

---

## 8. Security considerations

### 8.1 Transport threat model

This format assumes the attestation may travel over an untrusted channel (for
example, plaintext HTTP from a producer's host to a relay, or any cache or CDN in
between). The only security primitive is the signature. An attacker who fully
controls the channel can drop, delay, or replay attestations, and can rewrite any
unsigned field, but cannot forge a new signature because the signing key never
transits the channel. Every check below is designed against exactly this
attacker.

### 8.2 Why number-binding is separate from authenticity

A signature proves only *who signed a hash*. Without re-hashing the canonical
preimage to that hash, an attacker could replay a genuine
`(attestation_hash, signature)` pair while swapping every displayed figure, and a
naive consumer that rendered the swapped top-level numbers would show attacker
chosen values under a valid signature. Requiring
`sha256(signed_payload_canonical) == attestation_hash` binds the figures (and the
signed timestamp) to the signature, not merely the signer. Trusted figures are
therefore read only from the bound preimage.

### 8.3 Signature malleability (EIP-2 low-s)

secp256k1 is malleable: for every signature `(r, s, v)` there is a distinct twin
`(r, n - s, v xor 1)` that recovers to the same signer. A verifier that accepted
high-s signatures would admit a second valid 65-byte signature for every message,
which breaks any deduplication or replay key built on the signature bytes. A
conforming verifier MUST reject non-canonical high-s signatures. A conforming
producer always emits low-s, so this rejects only malleated twins, never a
genuine attestation.

### 8.4 Replay and freshness

Because freshness is measured from the *signed* timestamp inside the bound
preimage, replaying an old attestation does not make it look current: the bound
timestamp is old, so it reads stale. An attacker cannot backdate it without
breaking the hash match.

### 8.5 Key rotation

The expected signer is supplied by the verifier, out of band. On key rotation a
producer publishes attestations under the new key and consumers update the
expected signer they check against. A producer SHOULD make the current expected
signer easy to discover (for example, on a stable page or in onchain config), and
SHOULD treat the expected-signer source as part of its trust surface.

### 8.6 What a PASS does and does not prove

A PASS proves **authenticity** (a named key signed this exact payload) and
**freshness** (the signed timestamp is recent). It does **not** certify solvency,
bless the figures, or constitute an audit. A producer whose reserves were short
could still publish a perfectly valid, fresh, signed attestation; the shortfall
would show in the bound figures, not in the verdict. This format makes the
producer's numbers *tamper-evident and attributable*, which is a precondition for
trust, not a substitute for reading the numbers.

---

## 9. Conformance

A **conforming producer** MUST:

- publish `signed_payload_canonical`, `attestation_hash`, and `signature` as
  defined above;
- include a numeric `timestamp` (unix seconds) in the canonical preimage;
- hash the exact published bytes of the canonical preimage with SHA-256;
- sign the raw bytes of `attestation_hash` with EIP-191 `personal_sign`, low-s.

A **conforming verifier** MUST:

- recover the signer cryptographically and ignore the self-declared `signer`;
- reject high-s signatures (EIP-2);
- require `sha256(signed_payload_canonical) == attestation_hash` before trusting
  any figure;
- read trusted figures only from the parsed, bound preimage;
- measure freshness from the bound `timestamp`, bounding both the past
  (`maxAgeSeconds`) and the future (`maxFutureSkewSeconds`);
- require an explicit expected signer for a positive verdict;
- be fail-closed and never throw on malformed input.

---

## 10. Reference implementation

The `signed-por` repository (github.com/kerne-protocol/signed-por) is the
reference verifier for this spec: a dependency-light TypeScript implementation
(EIP-191 recovery on audited `@noble` primitives, SHA-256 binding, freshness), a
CLI, and a conformance test suite that includes verification of a live production
attestation. Install it with `npm install github:kerne-protocol/signed-por`.

The first production deployment of this format is Kerne
(`https://kerne.fi/api/por/signed`), which is the source of the
`examples/kerne-attestation.json` fixture in this repository. The format is
vendor-neutral; additional reference deployments are welcome.

---

## 11. Versioning

This spec uses semantic versioning. The wire format and the verification
algorithm are the stable surface. Clarifications that do not change verifier
behavior are patch releases; new optional fields are minor releases; any change
that would make a previously-passing attestation fail (or vice versa) is a major
release and will be called out explicitly.

- **1.0.0 (draft):** initial specification.
