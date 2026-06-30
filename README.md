# signed-por

**A tiny, vendor-neutral verifier for signed proof-of-reserves attestations.**

[![ci](https://github.com/kerne-protocol/signed-por/actions/workflows/ci.yml/badge.svg)](https://github.com/kerne-protocol/signed-por/actions/workflows/ci.yml)
[![license](https://img.shields.io/badge/license-MIT-blue.svg)](./LICENSE)
[![spec](https://img.shields.io/badge/spec-v1.0.0--draft-informational.svg)](./SPEC.md)

A stablecoin or synthetic-dollar issuer can sign a reserve snapshot so that
anyone can check it without trusting an intermediary: no attestor, no oracle, no
API key, no wallet. You only need the signer's public key, which you pin out of
band. `signed-por` is the open reference verifier for that format. It recovers
the signer, confirms the published figures are the ones that were signed, and
confirms the snapshot is recent, in a core small enough to audit by eye and with
no wallet SDK.

The format it verifies is written up as a short, citable spec: see
[SPEC.md](./SPEC.md).

This is a public good for the whole category. It is intentionally not branded to
any one protocol. Kerne is reference deployment number one; the format and this
verifier are vendor-neutral, and other issuers are invited to adopt both.

---

## Why this exists

Most "proof of reserves" pages ask you to trust the page. A signed attestation
inverts that: you check the cryptography yourself. Doing it correctly means
proving three things at once, and a signature alone only gives you the first:

1. **Authenticity.** A specific, known key signed this attestation.
2. **Number-binding.** The displayed figures are the exact figures that key
   signed, not numbers swapped in next to a replayed signature.
3. **Freshness.** The snapshot is recent, measured from a timestamp that is
   itself signed.

`signed-por` checks all three and is fail-closed: anything malformed, tampered,
replayed, or stale returns a clear, negative verdict, never a false pass.

A reusable verification format is stickier than any comparison page, because
adoption happens on other people's surfaces. The format is the asset; this
package is the reference implementation of it.

---

## Install

Install straight from this repository:

```sh
npm install github:kerne-protocol/signed-por
```

It installs under the package name `signed-por`, so you import it as
`from 'signed-por'` and the `signed-por` command is on your local path. No
registry account or configuration is needed.

Requires Node 18 or newer. Two direct dependencies, both audited:
[`@noble/curves`](https://github.com/paulmillr/noble-curves) (secp256k1 recovery)
and [`@noble/hashes`](https://github.com/paulmillr/noble-hashes) (SHA-256 and
keccak-256). The full installed tree is just these two packages: `@noble/hashes`
has no dependencies, and `@noble/curves`' only dependency is `@noble/hashes`,
which dedupes. There are no third-party transitive dependencies. These are the
same primitives ethers and viem build on. There is no wallet SDK, no network
access in the library, and no framework.

---

## Quickstart: the CLI

Verify a live endpoint over the network. This checks a real production
attestation end to end:

```sh
npx github:kerne-protocol/signed-por verify \
  --url https://kerne.fi/api/por/signed \
  --signer 0x09a2780ac8Be6D5d2d1F85A8D92b09D40C9CA37e
```

```
[PASS] signed proof-of-reserves

  OK  signature is a valid EIP-191 signature
  OK  recovered signer matches the expected signer
  OK  figures are bound to the signature (sha256 of canonical == attestation_hash)
  OK  snapshot is fresh (within 7800s)

  recovered signer : 0x09a2780ac8be6d5d2d1f85a8d92b09d40c9ca37e
  expected signer  : 0x09a2780ac8Be6D5d2d1F85A8D92b09D40C9CA37e
  signed timestamp : 1782834547 (312s ago)
```

Verify a saved attestation file, or pipe one on stdin:

```sh
signed-por verify attestation.json --signer 0xYourExpectedSigner
curl -s https://kerne.fi/api/por/signed | signed-por verify --signer 0x09a2780ac8Be6D5d2d1F85A8D92b09D40C9CA37e
```

The exit code is the machine signal: `0` verified, `1` not verified, `2` usage or
I/O error. Add `--json` for the full machine-readable verdict, `--allow-stale` to
accept an authentic, number-bound snapshot that is past its freshness window
(useful for checking a historical capture), and `--now <unixSeconds>` to verify
against a fixed time. Run `signed-por verify --help` for everything.

From a clone of this repo, verify the bundled real attestation offline (it is a
historical capture, so `--allow-stale` accepts the authentic, number-bound
snapshot past its freshness window):

```sh
signed-por verify examples/kerne-attestation.json \
  --signer 0x09a2780ac8Be6D5d2d1F85A8D92b09D40C9CA37e --allow-stale
```

---

## Quickstart: the library

```ts
import { verifyAttestation } from 'signed-por';

const attestation = await (await fetch('https://kerne.fi/api/por/signed')).json();

const verdict = verifyAttestation(attestation, {
  expectedSigner: '0x09a2780ac8Be6D5d2d1F85A8D92b09D40C9CA37e',
  // now: Date.now(),         // injectable for tests and historical checks
  // maxAgeSeconds: 7800,     // freshness window, default 7800
});

if (verdict.verified) {
  const bound = verdict.bound; // the figures proven to equal what was signed
  console.log('backing ratio:', bound.aggregate_solvency_ratio);
} else {
  console.warn('not verified:', verdict.reason);
}
```

`verifyAttestation` never throws and never returns a false `verified`. The full
`Verdict` exposes each step (`signatureValid`, `recoveredSigner`,
`signerMatchesExpected`, `hashMatches`, `boundTimestamp`, `stalenessSeconds`,
`isFresh`) so a caller can render exactly why a snapshot did or did not verify.

### API

| Export                              | Purpose                                                                   |
| ----------------------------------- | ------------------------------------------------------------------------- |
| `verifyAttestation(obj, opts)`      | Verify a published attestation object (the wire format).                  |
| `verifyCanonical(canonical, sig, signer, opts)` | Verify a pasted canonical payload + signature, deriving the hash from the payload (for an in-browser "paste three things" tool). |
| `recoverPersonalSign(hash, sig)`    | Low-level EIP-191 `personal_sign` signer recovery, fail-closed, low-s.    |
| `addressesEqual(a, b)`              | Case-insensitive, null-safe 0x-address equality.                          |
| `sha256Hex(s)`                      | `"0x" + sha256(utf8(s))`, the preimage hash.                              |

---

## What a PASS means

A PASS proves **authenticity** (a named key signed this exact payload) and
**freshness** (the signed timestamp is recent). It does **not** certify solvency,
bless the figures, or constitute an audit. A protocol whose reserves were short
could still produce a valid, fresh, signed attestation; the shortfall would show
in the signed figures, not in the verdict.

This is the honest scope, and it is the point. The format makes a producer's
numbers tamper-evident and attributable to a key, which is a precondition for
trust, not a replacement for reading the numbers.

---

## Adopt the format

If you issue a stablecoin or synthetic dollar and want self-verifiable reserves,
you do not need this package on the producer side. You need to publish three
fields, defined in [SPEC.md](./SPEC.md):

- `signed_payload_canonical`: the exact JSON string you hashed (include a numeric
  `timestamp`).
- `attestation_hash`: `"0x"` + SHA-256 of those bytes.
- `signature`: an EIP-191 `personal_sign` over the raw hash bytes, low-s.

Then your users, your auditors, and aggregators can verify you with this package
or any conforming verifier. The producer side is a few lines in whatever language
your reporting job already runs; the [spec](./SPEC.md) gives Python and
JavaScript references.

If you ship a deployment, open a PR adding it to the list below.

## Reference deployments

- **Kerne** (reference deployment #1): `https://kerne.fi/api/por/signed`

---

## Develop

```sh
npm install      # also builds dist via the prepare script
npm test         # builds, then runs the conformance suite (node --test)
npm run build    # tsc to dist/
```

The test suite includes verification of the real captured production attestation,
so it fails if a change ever breaks agreement with a live producer.

Contributions are welcome: additional conforming reference deployments, ports of
the verifier to other languages, and spec clarifications. Please keep the
verifier dependency-light and fail-closed.

## License

MIT. See [LICENSE](./LICENSE).
