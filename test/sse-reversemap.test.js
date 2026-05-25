// Tests for the streaming SSE reverseMap path. Mirrors the structure of
// upstream openclaw PR #56's test suite, adapted to Hermes patterns and the
// raw-string (no JSON.parse) helpers.
//
// Run with:  node --test test/sse-reversemap.test.js

const test = require('node:test');
const assert = require('node:assert');
const {
  applySseReverseMapChunks,
  createSseEventTransformer,
  reverseMap,
  findSseStringField,
  jsonStringDecode,
  jsonStringEncode,
  safeCut,
} = require('../proxy.js');

// A subset of DEFAULT_REVERSE_MAP covering the interesting cases:
// overlapping patterns (Claude / Claude Code), filesystem paths
// (.claude-ws/), and a long phrase that exercises maxPatternLen.
const CONFIG = {
  reverseMap: [
    ['Claude Code', 'Hermes Agent'],
    ['.claude-ws/', '.hermes/'],
    ['.claude-ws', '.hermes'],
    ['CLAUDE.md', 'HERMES.md'],
    ['Claude', 'Hermes'],
    ['claude', 'hermes'],
  ],
  toolRenames: [],
  propRenames: [],
};

const blockStart = (index, type = 'text') =>
  `event: content_block_start\ndata: {"type":"content_block_start","index":${index},"content_block":{"type":"${type}","text":""}}\n\n`;
const textDelta = (index, text) =>
  `event: content_block_delta\ndata: {"type":"content_block_delta","index":${index},"delta":{"type":"text_delta","text":${JSON.stringify(text)}}}\n\n`;
const blockStop = (index) =>
  `event: content_block_stop\ndata: {"type":"content_block_stop","index":${index}}\n\n`;

// Concatenate all text_delta `text` values from the rewritten output. The
// client sees this concatenation as the final assistant message, so it's
// what we assert against.
function reconstruct(out) {
  const events = out.split('\n\n').filter(Boolean);
  let result = '';
  for (const e of events) {
    if (!e.startsWith('event: content_block_delta')) continue;
    if (e.indexOf('"type":"text_delta"') === -1) continue;
    const start = findSseStringField(e, 'text');
    if (start === -1) continue;
    const { value } = jsonStringDecode(e, start);
    result += value;
  }
  return result;
}

// ─── Cross-delta split bug repro ────────────────────────────────────────────

test('text_delta: "Claude" split across deltas reverse-maps correctly', () => {
  const events = blockStart(0) + textDelta(0, 'I am Cla') + textDelta(0, 'ude here') + blockStop(0);
  const out = applySseReverseMapChunks([events], CONFIG);
  assert.strictEqual(reconstruct(out), 'I am Hermes here');
});

test('text_delta: ".claude-ws/" split across deltas reverse-maps correctly', () => {
  const events = blockStart(0) + textDelta(0, 'cd .clau') + textDelta(0, 'de-ws/foo') + blockStop(0);
  const out = applySseReverseMapChunks([events], CONFIG);
  assert.strictEqual(reconstruct(out), 'cd .hermes/foo');
});

// ─── Whole-text equivalence under every two-way split ───────────────────────

test('text_delta: every two-way split yields reverseMap(whole)', () => {
  const original = 'Run Claude with .claude-ws/foo and read CLAUDE.md please';
  const expected = reverseMap(original, CONFIG);
  for (let i = 0; i <= original.length; i++) {
    const a = original.slice(0, i);
    const b = original.slice(i);
    const events = blockStart(0) + textDelta(0, a) + textDelta(0, b) + blockStop(0);
    const out = applySseReverseMapChunks([events], CONFIG);
    assert.strictEqual(reconstruct(out), expected, `split at ${i}: a=${JSON.stringify(a)} b=${JSON.stringify(b)}`);
  }
});

test('text_delta: single-character splitting yields reverseMap(whole)', () => {
  const original = 'hello Claude in .claude-ws/x referencing CLAUDE.md';
  const expected = reverseMap(original, CONFIG);
  let events = blockStart(0);
  for (const ch of original) events += textDelta(0, ch);
  events += blockStop(0);
  const out = applySseReverseMapChunks([events], CONFIG);
  assert.strictEqual(reconstruct(out), expected);
});

test('text_delta: token split across raw TCP chunks (not event-aligned)', () => {
  const events = blockStart(0) + textDelta(0, 'I am Claude here') + blockStop(0);
  const chunks = [];
  for (let i = 0; i < events.length; i += 7) chunks.push(events.slice(i, i + 7));
  const out = applySseReverseMapChunks(chunks, CONFIG);
  assert.strictEqual(reconstruct(out), 'I am Hermes here');
});

// ─── Overlapping-pattern resolution (longer pattern wins) ───────────────────

test('text_delta: "Claude Code" wins over bare "Claude" even when split', () => {
  // Critical: emitting "Claude" early would map it to "Hermes" and the
  // " Code" arriving next couldn't retroactively form "Hermes Agent".
  const events = blockStart(0) + textDelta(0, 'Mention Claude') + textDelta(0, ' Code here') + blockStop(0);
  const out = applySseReverseMapChunks([events], CONFIG);
  assert.strictEqual(reconstruct(out), 'Mention Hermes Agent here');
});

// ─── Multi-block streams ────────────────────────────────────────────────────

test('text_delta: independent buffers across content blocks', () => {
  const events =
    blockStart(0) + textDelta(0, 'first Claude') + blockStop(0) +
    blockStart(1) + textDelta(1, 'second .claude-ws/') + blockStop(1);
  const out = applySseReverseMapChunks([events], CONFIG);
  assert.strictEqual(reconstruct(out), 'first Hermes' + 'second .hermes/');
});

// ─── Stream end without content_block_stop (flushAll) ───────────────────────

test('flushAll: held tail is emitted when stream ends without stop', () => {
  const events = blockStart(0) + textDelta(0, 'I am Claude');  // no stop
  const out = applySseReverseMapChunks([events], CONFIG);
  assert.strictEqual(reconstruct(out), 'I am Hermes');
});

// ─── Thinking pass-through (byte-identical) ─────────────────────────────────

test('thinking blocks pass through byte-identical', () => {
  const start = `event: content_block_start\ndata: {"type":"content_block_start","index":0,"content_block":{"type":"thinking","thinking":""}}\n\n`;
  const delta = `event: content_block_delta\ndata: {"type":"content_block_delta","index":0,"delta":{"type":"thinking_delta","thinking":"I should mention Claude here"}}\n\n`;
  const stop = blockStop(0);
  const input = start + delta + stop;
  const out = applySseReverseMapChunks([input], CONFIG);
  assert.strictEqual(out, input, 'thinking content must not be rewritten');
});

test('redacted_thinking passes through byte-identical', () => {
  const start = `event: content_block_start\ndata: {"type":"content_block_start","index":0,"content_block":{"type":"redacted_thinking","data":"opaque-Claude-blob"}}\n\n`;
  const stop = blockStop(0);
  const input = start + stop;
  const out = applySseReverseMapChunks([input], CONFIG);
  assert.strictEqual(out, input);
});

// ─── Tool-use buffering (pre-existing behavior must not regress) ────────────

test('tool_use input_json_delta still reverse-maps across delta splits', () => {
  const toolStart = `event: content_block_start\ndata: {"type":"content_block_start","index":0,"content_block":{"type":"tool_use","id":"t1","name":"Bash","input":{}}}\n\n`;
  const jsonDelta = (s) =>
    `event: content_block_delta\ndata: {"type":"content_block_delta","index":0,"delta":{"type":"input_json_delta","partial_json":${JSON.stringify(s)}}}\n\n`;
  const events = toolStart + jsonDelta('{"command":"ls .cla') + jsonDelta('ude-ws/foo"}') + blockStop(0);
  const out = applySseReverseMapChunks([events], CONFIG);
  assert.ok(out.indexOf('.hermes/foo') !== -1, 'reverse-mapped path missing from output: ' + out);
  assert.ok(out.indexOf('.claude-ws') === -1, 'sanitized form leaked in output: ' + out);
});

// ─── jsonString codec edge cases ────────────────────────────────────────────

test('jsonStringEncode: control chars and backslash/quote escapes', () => {
  assert.strictEqual(jsonStringEncode('a"b'), 'a\\"b');
  assert.strictEqual(jsonStringEncode('a\\b'), 'a\\\\b');
  assert.strictEqual(jsonStringEncode('a\nb'), 'a\\nb');
  assert.strictEqual(jsonStringEncode('a\tb'), 'a\\tb');
  assert.strictEqual(jsonStringEncode('a\rb'), 'a\\rb');
  assert.strictEqual(jsonStringEncode('a\bb'), 'a\\bb');
  assert.strictEqual(jsonStringEncode('a\fb'), 'a\\fb');
  assert.strictEqual(jsonStringEncode('\x01'), '\\u0001');
  assert.strictEqual(jsonStringEncode('\x1f'), '\\u001f');
});

test('jsonString codec roundtrip on tricky inputs', () => {
  const cases = [
    '',
    'plain',
    '"quoted"',
    'back\\slash',
    'new\nline',
    'tab\there',
    'cr\rlf',
    'bell\b',
    'form\ffeed',
    'astral 🎉 emoji',
    'high BMP あ char',
    'mixed "\\" and 🚀 stuff',
    '',
  ];
  for (const c of cases) {
    const encoded = jsonStringEncode(c);
    const wrapped = '"' + encoded + '"';
    const { value, end } = jsonStringDecode(wrapped, 1);
    assert.strictEqual(value, c, `roundtrip failed for ${JSON.stringify(c)}: got ${JSON.stringify(value)}`);
    assert.strictEqual(end, wrapped.length, `end mismatch for ${JSON.stringify(c)}`);
  }
});

test('jsonStringDecode: surrogate pair decodes to astral codepoint', () => {
  // U+1F389 PARTY POPPER = D83C DF89
  const input = '"\\uD83C\\uDF89"';
  const { value, end } = jsonStringDecode(input, 1);
  assert.strictEqual(value, '🎉');
  assert.strictEqual(end, input.length);
});

test('jsonStringDecode: lone high surrogate kept as single code unit', () => {
  const input = '"\\uD83C"';
  const { value, end } = jsonStringDecode(input, 1);
  assert.strictEqual(value.charCodeAt(0), 0xD83C);
  assert.strictEqual(end, input.length);
});

test('jsonStringDecode: \\uXXXX for BMP char', () => {
  const input = '"\\u3042"';
  const { value } = jsonStringDecode(input, 1);
  assert.strictEqual(value, 'あ');
});

// ─── findSseStringField string-awareness ───────────────────────────────────

test('findSseStringField: ignores fake "text":"..." embedded in another string', () => {
  // The OUTER string value contains the literal characters `"text":"fake"`.
  // A naive `indexOf('"text":"')` would match inside the value. The string-
  // aware scanner must skip that and find the real top-level `text` field.
  const json =
    '{"type":"content_block_delta","index":0,' +
    '"delta":{"type":"text_delta","text":"see \\"text\\":\\"fake\\" here"}}';
  const start = findSseStringField(json, 'text');
  assert.notStrictEqual(start, -1);
  const { value } = jsonStringDecode(json, start);
  assert.strictEqual(value, 'see "text":"fake" here');
});

test('findSseStringField: returns -1 when key absent', () => {
  assert.strictEqual(findSseStringField('{"other":"x"}', 'text'), -1);
});

test('findSseStringField: returns -1 when value is not a string', () => {
  assert.strictEqual(findSseStringField('{"text":42}', 'text'), -1);
});

// ─── safeCut behavior ──────────────────────────────────────────────────────

test('safeCut: with no straddling pattern, holds maxPatternLen-1 trailing bytes', () => {
  const patterns = [['xyz', 'XYZ']];
  const buf = 'abcdefghij'; // 10 chars
  // No occurrence of 'xyz'. Cut = 10 - (3-1) = 8.
  assert.strictEqual(safeCut(buf, 3, patterns), 8);
});

test('safeCut: pulls cut back to start of a complete straddling pattern', () => {
  const patterns = [['Claude', 'Hermes']];
  const buf = 'XClaudeY'; // 8 chars, maxPatternLen=6
  // Initial cut = 8 - 5 = 3. "Claude" at idx 1, end 7. 7 > 3 → straddle. Pull cut → 1.
  assert.strictEqual(safeCut(buf, 6, patterns), 1);
});

test('safeCut: pattern entirely before cut does not pull back', () => {
  const patterns = [['Claude', 'Hermes']];
  const buf = 'Claude XXXXXXXX'; // 15 chars
  // Initial cut = 15 - 5 = 10. "Claude" at idx 0, end 6. 6 <= 10, no straddle.
  assert.strictEqual(safeCut(buf, 6, patterns), 10);
});

test('safeCut: iterates when pulling cut back exposes another straddler', () => {
  const patterns = [['AB', 'X'], ['CD', 'Y']];
  // Want a buf where pulling cut back for 'CD' exposes 'AB' straddling the
  // new cut. Use buf "ABCDEF" with maxPatternLen=2: initial cut = 6 - 1 = 5.
  // 'AB' at 0, end 2 — no straddle. 'CD' at 2, end 4 — no straddle.
  // Try buf "ABCD": cut = 4-1=3. 'CD' at 2, end 4. 4>3 → pull cut to 2.
  // Now 'AB' at 0, end 2. 2 <= 2, no straddle.
  assert.strictEqual(safeCut('ABCD', 2, patterns), 2);
});
