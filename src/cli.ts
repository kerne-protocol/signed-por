#!/usr/bin/env node
// signed-por command-line verifier.
//
//   signed-por verify <file.json> --signer 0xABC...
//   signed-por verify --url https://example.com/api/por/signed --signer 0xABC...
//   cat attestation.json | signed-por verify --signer 0xABC...
//
// Exit codes: 0 = verified, 1 = not verified, 2 = usage or I/O error. The
// machine-readable verdict (--json) and the non-zero exit on failure make this
// safe to drop into CI or a monitoring cron.

import { readFileSync } from 'node:fs';
import {
  verifyAttestation,
  DEFAULT_MAX_AGE_SECONDS,
  DEFAULT_MAX_FUTURE_SKEW_SECONDS,
  type Verdict,
} from './verify.js';

interface Args {
  command: string | null;
  file: string | null;
  url: string | null;
  signer: string | null;
  now: number | null;
  maxAge: number | null;
  maxFutureSkew: number | null;
  field: string | null;
  allowStale: boolean;
  json: boolean;
  quiet: boolean;
  help: boolean;
  version: boolean;
}

function parseArgs(argv: string[]): Args {
  const a: Args = {
    command: null, file: null, url: null, signer: null, now: null,
    maxAge: null, maxFutureSkew: null, field: null, allowStale: false,
    json: false, quiet: false, help: false, version: false,
  };
  for (let i = 0; i < argv.length; i++) {
    const t = argv[i];
    switch (t) {
      case '-h': case '--help': a.help = true; break;
      case '-V': case '--version': a.version = true; break;
      case '--json': a.json = true; break;
      case '-q': case '--quiet': a.quiet = true; break;
      case '--allow-stale': a.allowStale = true; break;
      case '--signer': a.signer = argv[++i] ?? null; break;
      case '--url': a.url = argv[++i] ?? null; break;
      case '--now': a.now = toNum(argv[++i]); break;
      case '--max-age': a.maxAge = toNum(argv[++i]); break;
      case '--max-future-skew': a.maxFutureSkew = toNum(argv[++i]); break;
      case '--field': a.field = argv[++i] ?? null; break;
      default:
        if (t.startsWith('--signer=')) a.signer = t.slice(9);
        else if (t.startsWith('--url=')) a.url = t.slice(6);
        else if (t.startsWith('--now=')) a.now = toNum(t.slice(6));
        else if (t.startsWith('--max-age=')) a.maxAge = toNum(t.slice(10));
        else if (t.startsWith('--max-future-skew=')) a.maxFutureSkew = toNum(t.slice(18));
        else if (t.startsWith('--field=')) a.field = t.slice(8);
        else if (!t.startsWith('-') && a.command === null) a.command = t;
        else if (!t.startsWith('-') && a.file === null) a.file = t;
    }
  }
  return a;
}

function toNum(v: string | undefined): number | null {
  if (v === undefined) return null;
  const n = Number(v);
  return Number.isFinite(n) ? n : null;
}

const HELP = `signed-por - verify a Signed Proof-of-Reserves attestation

USAGE
  signed-por verify [file] [options]

INPUT (one of)
  file                 path to a JSON attestation file
  --url <url>          fetch the attestation JSON from a URL
  (stdin)              piped JSON when neither file nor --url is given

OPTIONS
  --signer <0xADDR>    the address the attestation MUST be signed by
  --now <unixSeconds>  override "now" (for historical or deterministic checks)
  --max-age <seconds>  freshness window (default ${DEFAULT_MAX_AGE_SECONDS})
  --max-future-skew <seconds>  allowance for a post-dated timestamp (default ${DEFAULT_MAX_FUTURE_SKEW_SECONDS})
  --field <name>       signed timestamp field inside the preimage (default "timestamp")
  --allow-stale        exit 0 if authentic and bound even when stale
  --json               print the machine-readable verdict
  -q, --quiet          print nothing; communicate only via exit code
  -h, --help           show this help
  -V, --version        show the version

EXIT CODES
  0  verified (or, with --allow-stale, authentic and number-bound)
  1  not verified
  2  usage or I/O error

A PASS proves authenticity (a named key signed this exact payload) and freshness.
It does NOT certify solvency or constitute an audit: a protocol whose reserves
were short would still produce a PASS. The figures inside the bound payload are
where a shortfall would show.`;

function readVersion(): string {
  try {
    const url = new URL('../package.json', import.meta.url);
    const pkg = JSON.parse(readFileSync(url, 'utf8')) as { version?: string };
    return pkg.version ?? '0.0.0';
  } catch {
    return '0.0.0';
  }
}

async function loadInput(a: Args): Promise<unknown> {
  if (a.url !== null) {
    const res = await fetch(a.url, { signal: AbortSignal.timeout(15_000) });
    if (!res.ok) throw new Error(`fetch ${a.url} returned ${res.status} ${res.statusText}`);
    return res.json();
  }
  if (a.file !== null) {
    return JSON.parse(readFileSync(a.file, 'utf8'));
  }
  // stdin
  const chunks: Buffer[] = [];
  for await (const c of process.stdin) chunks.push(c as Buffer);
  const text = Buffer.concat(chunks).toString('utf8').trim();
  if (text.length === 0) throw new Error('no input: pass a file, --url, or pipe JSON on stdin');
  return JSON.parse(text);
}

function short(addr: string | null): string {
  if (!addr) return 'none';
  return addr.length <= 20 ? addr : `${addr.slice(0, 10)}...${addr.slice(-8)}`;
}

function check(ok: boolean): string {
  return ok ? 'OK ' : 'x  ';
}

function printReport(v: Verdict, passForExit: boolean): void {
  const header = passForExit ? 'PASS' : (v.signerMatchesExpected && v.hashMatches && !v.isFresh ? 'STALE' : 'FAIL');
  const lines: string[] = [];
  lines.push(`[${header}] signed proof-of-reserves`);
  lines.push('');
  lines.push(`  ${check(v.signatureValid)} signature is a valid EIP-191 signature`);
  lines.push(`  ${check(v.signerMatchesExpected)} recovered signer matches the expected signer`);
  lines.push(`  ${check(v.hashMatches)} figures are bound to the signature (sha256 of canonical == attestation_hash)`);
  lines.push(`  ${check(v.isFresh)} snapshot is fresh (within ${v.freshnessThresholdSeconds}s)`);
  lines.push('');
  lines.push(`  recovered signer : ${v.recoveredSigner ?? 'none'}`);
  lines.push(`  expected signer  : ${v.expectedSigner ?? 'none (not checked)'}`);
  if (v.boundTimestamp !== null) {
    const age =
      v.stalenessSeconds === null
        ? ''
        : v.stalenessSeconds < 0
          ? ` (${-v.stalenessSeconds}s in the future)`
          : ` (${v.stalenessSeconds}s ago)`;
    lines.push(`  signed timestamp : ${v.boundTimestamp}${age}`);
  }
  if (v.reason) {
    lines.push('');
    lines.push(`  ${v.reason}`);
  }
  process.stdout.write(lines.join('\n') + '\n');
}

async function main(): Promise<number> {
  const a = parseArgs(process.argv.slice(2));
  if (a.version) { process.stdout.write(readVersion() + '\n'); return 0; }
  if (a.help || a.command === null) { process.stdout.write(HELP + '\n'); return a.help ? 0 : 2; }
  if (a.command !== 'verify') {
    process.stderr.write(`unknown command "${a.command}". Try: signed-por verify --help\n`);
    return 2;
  }

  let input: unknown;
  try {
    input = await loadInput(a);
  } catch (err) {
    process.stderr.write(`error: ${err instanceof Error ? err.message : String(err)}\n`);
    return 2;
  }

  const verdict = verifyAttestation(input as Record<string, unknown>, {
    expectedSigner: a.signer,
    now: a.now !== null ? a.now * 1000 : undefined,
    maxAgeSeconds: a.maxAge ?? undefined,
    maxFutureSkewSeconds: a.maxFutureSkew ?? undefined,
    timestampField: a.field ?? undefined,
  });

  const authenticAndBound = verdict.signatureValid && verdict.signerMatchesExpected && verdict.hashMatches;
  const passForExit = verdict.verified || (a.allowStale && authenticAndBound);

  if (a.json) {
    process.stdout.write(JSON.stringify(verdict, null, 2) + '\n');
  } else if (!a.quiet) {
    printReport(verdict, passForExit);
  }

  return passForExit ? 0 : 1;
}

// Set process.exitCode rather than calling process.exit(): the latter can race
// a still-closing keep-alive socket from a --url fetch and trip a libuv assertion
// on Windows, and can truncate piped stdout. Letting the loop drain is safe;
// undici unrefs idle sockets, so the process still exits promptly.
main().then(
  (code) => { process.exitCode = code; },
  (err) => {
    process.stderr.write(`fatal: ${err instanceof Error ? err.stack : String(err)}\n`);
    process.exitCode = 2;
  },
);
