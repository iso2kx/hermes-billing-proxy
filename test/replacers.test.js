// Tests for the single-pass replacer engine (compileReplacer), the tool/
// property/MCP reverse paths that the SSE suite's reverseMap-only config does
// not exercise, and the guarded JSON pass in processBody (Fix #2).
//
// Run with:  node --test test/replacers.test.js

const test = require('node:test');
const assert = require('node:assert');
const { compileReplacer, reverseMap, processBody } = require('../proxy.js');

// ─── compileReplacer: the shared single-pass engine ─────────────────────────

test('compileReplacer: longest find wins over a shared prefix', () => {
  // Sequential split/join order would let "ab" mangle "abc"; longest-first
  // alternation must match "abc" whole.
  const r = compileReplacer([['ab', 'X'], ['abc', 'Y']]);
  assert.strictEqual(r('abc'), 'Y');
  assert.strictEqual(r('abd'), 'Xd');
});

test('compileReplacer: find metacharacters are matched literally', () => {
  assert.strictEqual(compileReplacer([['.hermes/', '.claude/']])('cd .hermes/x'), 'cd .claude/x');
  // The dot must NOT act as a wildcard.
  assert.strictEqual(compileReplacer([['a.b', 'Z']])('axb'), 'axb');
  assert.strictEqual(compileReplacer([['CLAUDE.md', 'HERMES.md']])('see CLAUDEXmd'), 'see CLAUDEXmd');
});

test('compileReplacer: empty pattern list is the identity function', () => {
  assert.strictEqual(compileReplacer([])('abc'), 'abc');
  assert.strictEqual(compileReplacer(undefined)('abc'), 'abc');
});

test('compileReplacer: duplicate finds keep the first mapping', () => {
  assert.strictEqual(compileReplacer([['a', '1'], ['a', '2']])('a'), '1');
});

test('compileReplacer: replacement text is not re-scanned (no cascade)', () => {
  // "a"->"b" then a separate "b"->"c": a single pass must not turn a into c.
  const r = compileReplacer([['a', 'b'], ['b', 'c']]);
  assert.strictEqual(r('a'), 'b');
});

// ─── reverseMap: tool / property / MCP paths with escaped forms ──────────────

const CFG = {
  toolRenames: [['mcp_send_message', 'SendMessage'], ['mcp_terminal', 'Bash']],
  propRenames: [['session_id', 'thread_id']],
  reverseMap: [['Claude Code', 'Hermes Agent'], ['Claude', 'Hermes'], ['claude', 'hermes']],
};

test('reverseMap: plain tool name reverts', () => {
  assert.strictEqual(reverseMap('call "SendMessage" now', CFG), 'call "mcp_send_message" now');
});

test('reverseMap: escaped tool name (partial_json arg key) reverts', () => {
  // '\\"' in source is a backslash followed by a quote — the SSE escaped form.
  const out = reverseMap('{\\"SendMessage\\":\\"hi\\"}', CFG);
  assert.ok(out.indexOf('mcp_send_message') !== -1, 'escaped tool name not reverted: ' + out);
  assert.ok(out.indexOf('SendMessage') === -1, 'renamed form leaked: ' + out);
});

test('reverseMap: property name reverts in plain and escaped forms', () => {
  // Forward renames session_id -> thread_id, so reverse maps thread_id back.
  assert.strictEqual(reverseMap('"thread_id"', CFG), '"session_id"');
  assert.strictEqual(reverseMap('\\"thread_id\\"', CFG), '\\"session_id\\"');
});

test('reverseMap: dynamic Mcp* PascalCase reversal is removed (passes through)', () => {
  // The old "McpXxx" -> "mcp_xxx" dynamic rename was removed (it produced names
  // real Claude Code never sends, and would mangle genuine mcp__ tool names).
  // Unmapped Mcp* names now pass through untouched; tool disguise is static-only.
  assert.strictEqual(reverseMap('"McpFooBar"', CFG), '"McpFooBar"');
});

test('reverseMap: longer string pattern wins over the bare catch-all', () => {
  assert.strictEqual(reverseMap('Claude Code and Claude', CFG), 'Hermes Agent and Hermes');
});

// ─── processBody: Fix #2 guarded JSON pass ──────────────────────────────────

const PB = {
  replacements: [], toolRenames: [], propRenames: [], reverseMap: [],
  injectCCStubs: false, stripToolDescriptions: false,
  stripTrailingAssistantPrefill: true,
};

test('processBody: framework-prefixed model is still remapped (guard hits)', () => {
  const body = JSON.stringify({
    model: 'hermes-opus-4-7',
    system: [{ type: 'text', text: 'hi' }],
    messages: [{ role: 'user', content: 'hello world' }],
  });
  const parsed = JSON.parse(processBody(body, PB));
  assert.strictEqual(parsed.model, 'claude-opus-4-7');
});

test('processBody: a marker-bearing >2000 system block is still stripped', () => {
  const big = 'You have persistent memory across sessions ' + 'x'.repeat(2100) + '\n══ END';
  const body = JSON.stringify({
    model: 'claude-sonnet-4-6',
    system: [{ type: 'text', text: big }],
    messages: [{ role: 'user', content: 'hello' }],
  });
  const parsed = JSON.parse(processBody(body, PB));
  const joined = parsed.system.map((b) => b.text || '').join('\n');
  // The strip ran (guard let the parse through): boilerplate anchor and the
  // >2000 chars of filler it bounded are both gone.
  assert.ok(!joined.includes('You have persistent memory across sessions'), 'strip marker survived');
  assert.ok(!joined.includes('xxxxxxxxxx'), 'stripped block filler survived');
});

test('processBody: no-marker body skips the JSON pass but still injects billing + metadata', () => {
  const plain = 'You are a helpful assistant. '.repeat(100); // ~2900 chars, no Hermes markers
  const body = JSON.stringify({
    model: 'claude-sonnet-4-6',
    system: [{ type: 'text', text: plain }],
    messages: [{ role: 'user', content: 'hello' }],
  });
  const out = processBody(body, PB);
  const parsed = JSON.parse(out); // skip path must still emit valid JSON
  assert.ok(out.includes('x-anthropic-billing-header'), 'billing block not injected');
  assert.ok(parsed.metadata && parsed.metadata.user_id, 'metadata not injected');
  assert.strictEqual(parsed.model, 'claude-sonnet-4-6');
  const joined = parsed.system.map((b) => b.text || '').join('');
  assert.ok(joined.includes('You are a helpful assistant.'), 'non-Hermes system content was altered');
});
