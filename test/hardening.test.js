// Tests for the v2.3.0 hardening pass:
//   - cch attestation self-test (silent-degradation guard)
//   - URL-preserving reverse map for upstream error bodies
//   - foreign-tool detection by allowlist rather than by name shape
//   - model catalog context_length rules and lossless upstream merge
//
// Run with:  node --test test/hardening.test.js

const test = require('node:test');
const assert = require('node:assert');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const {
  rotateLogFiles,
  xxh64,
  CCH_XXH_OK,
  CCH_SEED,
  applyCch,
  reverseMap,
  reverseMapErrorBody,
  warnOnForeignTools,
  nativeToolAllowlist,
  contextLengthFor,
  buildModelList,
  mergeModelIds,
  FALLBACK_MODEL_IDS,
} = require('../proxy.js');

// The reverse map the proxy ships; enough for the error-body tests.
const CONFIG = {
  replacements: [],
  toolRenames: [['terminal', 'Bash'], ['read_file', 'Read'], ['search_files', 'mcp__ripgrep__search']],
  propRenames: [],
  reverseMap: [
    ['Claude Code', 'Hermes Agent'],
    ['claude-code', 'hermes-agent'],
    ['Claude', 'Hermes', 'word'],
    ['claude', 'hermes', 'word'],
  ],
};

// ─── log rotation (#1) ──────────────────────────────────────────────────────
// The first implementation used a WriteStream and renamed the file underneath
// the open handle, which throws on Windows; the error was swallowed, so the log
// silently grew forever. Pin the rename chain and the retention cap.

function tmpLogDir() {
  return fs.mkdtempSync(path.join(os.tmpdir(), 'obp-log-'));
}

test('rotation shifts generations and caps retention at `keep`', () => {
  const dir = tmpLogDir();
  const log = path.join(dir, 'p.log');
  try {
    for (let round = 1; round <= 5; round++) {
      fs.writeFileSync(log, `round-${round}\n`);
      rotateLogFiles(log, 3);
    }
    // Current file was just rotated away, so only the generations remain.
    assert.ok(!fs.existsSync(log), 'current log should have been moved to .1');
    assert.strictEqual(fs.readFileSync(`${log}.1`, 'utf8').trim(), 'round-5');
    assert.strictEqual(fs.readFileSync(`${log}.2`, 'utf8').trim(), 'round-4');
    assert.strictEqual(fs.readFileSync(`${log}.3`, 'utf8').trim(), 'round-3');
    assert.ok(!fs.existsSync(`${log}.4`), 'must never create a generation beyond keep');
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('rotation is safe when no log file exists yet', () => {
  const dir = tmpLogDir();
  try {
    assert.doesNotThrow(() => rotateLogFiles(path.join(dir, 'absent.log'), 3));
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('rotation overwrites the oldest generation rather than throwing', () => {
  // renameSync onto an existing target must replace it — the Windows failure
  // mode this whole helper exists to pin down.
  const dir = tmpLogDir();
  const log = path.join(dir, 'p.log');
  try {
    fs.writeFileSync(`${log}.3`, 'ancient\n');
    fs.writeFileSync(`${log}.2`, 'older\n');
    fs.writeFileSync(log, 'current\n');
    assert.doesNotThrow(() => rotateLogFiles(log, 3));
    assert.strictEqual(fs.readFileSync(`${log}.3`, 'utf8').trim(), 'older',
      '.2 should have replaced the ancient .3');
    assert.strictEqual(fs.readFileSync(`${log}.1`, 'utf8').trim(), 'current');
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

// ─── cch attestation (#7) ───────────────────────────────────────────────────
// Without these, a broken xxh64 degrades cch to "00000" and every request
// silently bills to extra usage — no test failure, no log, no health signal.

test('xxh64 matches canonical vectors (seed 0)', () => {
  assert.strictEqual(xxh64(Buffer.from('', 'utf8'), 0n), 0xEF46DB3751D8E999n);
  assert.strictEqual(
    xxh64(Buffer.from('Nobody inspects the spammish repetition', 'utf8'), 0n),
    0xFBCEA83C8A378BF1n);
});

test('xxh64 handles all tail lengths (8/4/1-byte drains)', () => {
  // Exercises each drain branch; a regression in any one corrupts the
  // attestation only for certain body sizes, which is the worst kind of bug.
  for (const len of [1, 3, 4, 7, 8, 15, 16, 31, 32, 33, 63, 64]) {
    const buf = Buffer.alloc(len, 0x61);
    const h = xxh64(buf, CCH_SEED);
    assert.strictEqual(typeof h, 'bigint');
    assert.ok(h >= 0n && h < (1n << 64n), `len ${len} produced out-of-range hash`);
  }
});

test('cch self-test flag is healthy in this build', () => {
  assert.strictEqual(CCH_XXH_OK, true,
    'CCH_XXH_OK false means cch stays 00000 and billing falls to extra usage');
});

test('applyCch replaces the placeholder with 5 lowercase hex, preserving length', () => {
  const body = '{"system":[{"type":"text","text":"x: cc_version=1.2.3.abc; cch=00000;"}]}';
  const out = applyCch(body);
  assert.strictEqual(out.length, body.length, 'cch replacement must be length-preserving');
  const m = out.match(/cch=([0-9a-f]{5});/);
  assert.ok(m, `expected a 5-hex cch, got: ${out}`);
  assert.notStrictEqual(m[1], '00000');
});

test('applyCch is deterministic for identical bodies', () => {
  const body = '{"a":1,"cch=00000":0,"t":"cch=00000"}';
  assert.strictEqual(applyCch(body), applyCch(body));
});

test('applyCch is a no-op when no placeholder is present', () => {
  const body = '{"messages":[]}';
  assert.strictEqual(applyCch(body), body);
});

// ─── error-body URL preservation (#6) ───────────────────────────────────────

test('error bodies keep claude.ai URLs intact', () => {
  const errBody = JSON.stringify({
    type: 'error',
    error: { type: 'invalid_request_error', message: "You're out of extra usage. Add more at claude.ai/settings/usage and keep going." },
  });
  const out = reverseMapErrorBody(errBody, CONFIG);
  assert.ok(out.includes('claude.ai/settings/usage'),
    `URL was mangled: ${out}`);
  assert.ok(!out.includes('hermes.ai'), 'must not invent a hermes.ai domain');
});

// Was: "the plain reverse map is what mangled it (documents the regression)",
// asserting reverseMap turned claude.ai into hermes.ai and noting the guard
// could be revisited once the bare-word swap changed. It has: the bare entries
// are now 'word'-scoped, so the URL survives everywhere, not just in the
// URL-masked error-body path.
test('the plain reverse map no longer mangles a claude.ai URL', () => {
  const errBody = "Add more at claude.ai/settings/usage";
  const out = reverseMap(errBody, CONFIG);
  assert.ok(out.includes('claude.ai/settings/usage'), `URL was mangled: ${out}`);
  assert.ok(!out.includes('hermes.ai'), 'must not invent a hermes.ai domain');
});

test('bare-word identity swap still fires in prose', () => {
  assert.strictEqual(reverseMap('I am Claude, running here.', CONFIG),
    'I am Hermes, running here.');
  assert.strictEqual(reverseMap('Ask Claude.', CONFIG), 'Ask Hermes.');
});

test('bare-word identity swap skips identifiers and paths', () => {
  for (const [input, why] of [
    ['the claude-api skill', 'hyphenated skill name'],
    ['cd /projects/claude-demo', 'path segment'],
    ['see docs.claude.com/en', 'domain'],
    ['open CLAUDE.md', 'filename (structural entry, unchanged)'],
  ]) {
    const out = reverseMap(input, CONFIG);
    if (input.includes('CLAUDE.md')) continue; // covered by its own structural pair
    assert.ok(!/hermes/i.test(out), `${why}: corrupted -> ${out}`);
  }
});

test('compound patterns still beat the bare-word swap', () => {
  assert.strictEqual(reverseMap('Claude Code and Claude', CONFIG),
    'Hermes Agent and Hermes');
});

test('error bodies still reverse-map prose outside URLs', () => {
  const errBody = JSON.stringify({ error: { message: 'Claude Code could not reach https://api.anthropic.com/v1/messages' } });
  const out = reverseMapErrorBody(errBody, CONFIG);
  assert.ok(out.includes('Hermes Agent'), `prose was not reversed: ${out}`);
  assert.ok(out.includes('https://api.anthropic.com/v1/messages'), `URL was mangled: ${out}`);
});

test('error bodies with no URLs behave exactly like reverseMap', () => {
  const errBody = JSON.stringify({ error: { message: 'Claude Code failed' } });
  assert.strictEqual(reverseMapErrorBody(errBody, CONFIG), reverseMap(errBody, CONFIG));
});

test('multiple URLs are each restored to their own value', () => {
  const errBody = 'see claude.ai/a and https://docs.claude.com/b and claude.ai/c';
  const out = reverseMapErrorBody(errBody, CONFIG);
  assert.ok(out.includes('claude.ai/a'), out);
  assert.ok(out.includes('https://docs.claude.com/b'), out);
  assert.ok(out.includes('claude.ai/c'), out);
});

test('URL masking does not disturb structural path reversal', () => {
  // .claude-ws/ is a proxy-created disguise that MUST still reverse; it is not
  // a URL span (no TLD), so masking must leave it alone.
  const cfg = { ...CONFIG, reverseMap: [...CONFIG.reverseMap, ['.claude-ws/', '.hermes/']] };
  const out = reverseMapErrorBody('path /home/u/.claude-ws/config at claude.ai/x', cfg);
  assert.ok(out.includes('.hermes/'), `structural reversal lost: ${out}`);
  assert.ok(out.includes('claude.ai/x'), `URL mangled: ${out}`);
});

// ─── foreign-tool allowlist (#10) ───────────────────────────────────────────

test('allowlist covers native rename targets and injected stubs', () => {
  const allow = nativeToolAllowlist(CONFIG);
  assert.ok(allow.has('Bash'), 'rename target missing');
  assert.ok(allow.has('Read'), 'rename target missing');
  assert.ok(allow.has('Grep'), 'injected CC stub missing');
  assert.ok(allow.has('TodoRead'), 'injected CC stub missing');
  assert.ok(!allow.has('mcp__ripgrep__search'), 'mcp__ targets are matched by prefix, not the allowlist');
});

// warnOnForeignTools dedupes for the process lifetime, so each test uses names
// no other test reuses.
function captureWarnings(fn) {
  const orig = console.error;
  const lines = [];
  console.error = (...a) => lines.push(a.join(' '));
  try { fn(); } finally { console.error = orig; }
  return lines.join('\n');
}

test('a PascalCase non-native tool is now flagged (old /^[A-Z]/ let it pass)', () => {
  const body = '{"tools":[{"name":"SearchTheWebZZ","description":"d"}]}';
  const out = captureWarnings(() => warnOnForeignTools(body, CONFIG));
  assert.ok(out.includes('SearchTheWebZZ'), `expected a warning, got: ${out}`);
});

test('genuine native and mcp__ names stay silent', () => {
  const body = '{"tools":[{"name":"Bash"},{"name":"Read"},{"name":"Grep"},{"name":"mcp__coingecko__execute"},{"name":"WebFetch"}]}';
  const out = captureWarnings(() => warnOnForeignTools(body, CONFIG));
  assert.strictEqual(out, '', `expected silence, got: ${out}`);
});

test('a bare snake_case tool is still flagged', () => {
  const body = '{"tools":[{"name":"some_new_hermes_tool_zz"}]}';
  const out = captureWarnings(() => warnOnForeignTools(body, CONFIG));
  assert.ok(out.includes('some_new_hermes_tool_zz'), `expected a warning, got: ${out}`);
});

test('warnings dedupe — a repeated name warns once', () => {
  const body = '{"tools":[{"name":"RepeatedForeignZZ"}]}';
  const first = captureWarnings(() => warnOnForeignTools(body, CONFIG));
  const second = captureWarnings(() => warnOnForeignTools(body, CONFIG));
  assert.ok(first.includes('RepeatedForeignZZ'));
  assert.strictEqual(second, '', 'second sighting should be suppressed');
});

test('a body with no tools array is a no-op', () => {
  const out = captureWarnings(() => warnOnForeignTools('{"messages":[]}', CONFIG));
  assert.strictEqual(out, '');
});

// ─── model catalog (#12) ────────────────────────────────────────────────────

test('context_length is assigned by rule, not by hand', () => {
  assert.strictEqual(contextLengthFor('claude-opus-5'), 1000000);
  assert.strictEqual(contextLengthFor('claude-sonnet-5'), 1000000);
  assert.strictEqual(contextLengthFor('claude-fable-5'), 1000000);
  assert.strictEqual(contextLengthFor('claude-haiku-4-5'), 200000);
});

test('an unreleased model id gets a sane default instead of being absent', () => {
  assert.strictEqual(contextLengthFor('claude-opus-6'), 1000000, 'future opus generations inherit 1M');
  assert.strictEqual(contextLengthFor('claude-sonnet-6'), 1000000, 'future sonnet generations inherit 1M');
  assert.strictEqual(contextLengthFor('claude-something-new'), 200000, 'unknown family falls back to 200K');
});

test('older generations the upstream catalog returns are NOT over-reported', () => {
  // Over-reporting is the dangerous direction: Hermes would pack a 1M window
  // into a 200K model and hard-400 on overflow. These ids come back from the
  // real /v1/models call, so the rule has to exclude them.
  assert.strictEqual(contextLengthFor('claude-sonnet-4-5-20250929'), 200000);
  assert.strictEqual(contextLengthFor('claude-opus-4-5-20251101'), 200000);
  assert.strictEqual(contextLengthFor('claude-opus-4-1-20250805'), 200000);
  assert.strictEqual(contextLengthFor('claude-haiku-4-5-20251001'), 200000);
});

test('the 4.6 threshold is a tuple compare, not a float compare', () => {
  // parseFloat("4.10") === 4.1, which would wrongly demote a future opus-4-10.
  assert.strictEqual(contextLengthFor('claude-opus-4-10'), 1000000);
  assert.strictEqual(contextLengthFor('claude-opus-4-6'), 1000000);
  assert.strictEqual(contextLengthFor('claude-opus-4-5'), 200000);
});

test('buildModelList emits the discovery shape Hermes parses', () => {
  const list = buildModelList(['claude-opus-5', 'claude-haiku-4-5']);
  assert.deepStrictEqual(list[0], {
    id: 'claude-opus-5', object: 'model', owned_by: 'anthropic', context_length: 1000000,
  });
  assert.strictEqual(list[1].context_length, 200000);
});

test('merging upstream ids never drops a curated model', () => {
  const merged = mergeModelIds(['claude-haiku-4-5', 'claude-brand-new-1']);
  for (const id of FALLBACK_MODEL_IDS) {
    assert.ok(merged.includes(id), `curated id ${id} was lost`);
  }
  assert.ok(merged.includes('claude-brand-new-1'), 'new upstream id should appear');
  assert.strictEqual(new Set(merged).size, merged.length, 'no duplicates');
});

test('curated ids keep priority ordering ahead of upstream extras', () => {
  const merged = mergeModelIds(['zzz-upstream-only']);
  assert.strictEqual(merged[0], FALLBACK_MODEL_IDS[0]);
  assert.strictEqual(merged[merged.length - 1], 'zzz-upstream-only');
});

test('a null upstream response degrades to the curated list', () => {
  assert.deepStrictEqual(mergeModelIds(null), FALLBACK_MODEL_IDS);
});
