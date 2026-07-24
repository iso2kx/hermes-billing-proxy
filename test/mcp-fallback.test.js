// Tests for the self-healing generic MCP tool disguise (Layer 3b) and the
// foreign-tool warning. Covers: unmapped single-underscore mcp_ names get the
// canonical mcp__server__tool shape on the way out, round-trip losslessly back
// to Hermes's mcp_server_tool on the way in, don't disturb already-mapped or
// already-canonical names, and that the full processBody -> reverseMap loop is
// stable for a newly-enabled MCP server.
//
// Run with:  node --test test/mcp-fallback.test.js

const test = require('node:test');
const assert = require('node:assert');
const {
  disguiseUnmappedMcpTools,
  reverseUnmappedMcpTools,
  recoverPrefixedNativeTools,
  processBody,
  reverseMap,
} = require('../proxy.js');

// ─── Forward: unmapped mcp_ -> canonical mcp__server__tool ──────────────────

test('forward: two-segment unmapped mcp_ tool is split on first underscore', () => {
  const { body, found } = disguiseUnmappedMcpTools('"mcp_coingecko_execute"');
  assert.strictEqual(body, '"mcp__coingecko__execute"');
  assert.deepStrictEqual(found, ['mcp_coingecko_execute']);
});

test('forward: multi-underscore tool keeps the remainder as the tool segment', () => {
  const { body } = disguiseUnmappedMcpTools('"mcp_coingecko_search_docs"');
  // server = coingecko, tool = search_docs (first-underscore split)
  assert.strictEqual(body, '"mcp__coingecko__search_docs"');
});

test('forward: degenerate single-segment name is left untouched (no real server/tool boundary)', () => {
  // Not a shape Hermes emits; disguising it would be un-reversible, so it is
  // left as-is and surfaced by warnOnForeignTools instead.
  const { body, found } = disguiseUnmappedMcpTools('"mcp_ping"');
  assert.strictEqual(body, '"mcp_ping"');
  assert.deepStrictEqual(found, []);
});

test('forward: already-canonical mcp__ names are left untouched', () => {
  const input = '"mcp__playwright__browser_navigate"';
  const { body, found } = disguiseUnmappedMcpTools(input);
  assert.strictEqual(body, input);
  assert.deepStrictEqual(found, []);
});

test('forward: rewrites both a tool def and a matching tool_use name', () => {
  // The definition and the historical assistant call must stay in agreement or
  // Anthropic 400s the request.
  const input = '{"tools":[{"name":"mcp_coingecko_execute"}],"messages":[{"role":"assistant","content":[{"type":"tool_use","name":"mcp_coingecko_execute"}]}]}';
  const { body } = disguiseUnmappedMcpTools(input);
  assert.ok(!body.includes('"mcp_coingecko_execute"'), 'raw single-underscore name survived');
  assert.strictEqual((body.match(/"mcp__coingecko__execute"/g) || []).length, 2);
});

// ─── Reverse: canonical mcp__server__tool -> Hermes mcp_server_tool ──────────

test('reverse: canonical name collapses back to single-underscore', () => {
  // Only names this process disguised are collapsed, so register them first —
  // which is exactly what the forward pass does on every real request.
  disguiseUnmappedMcpTools('"mcp_coingecko_execute" "mcp_coingecko_search_docs"');
  assert.strictEqual(reverseUnmappedMcpTools('"mcp__coingecko__execute"'), '"mcp_coingecko_execute"');
  assert.strictEqual(reverseUnmappedMcpTools('"mcp__coingecko__search_docs"'), '"mcp_coingecko_search_docs"');
});

test('reverse: handles SSE-escaped tool names', () => {
  disguiseUnmappedMcpTools('"mcp_coingecko_execute"');
  assert.strictEqual(reverseUnmappedMcpTools('\\"mcp__coingecko__execute\\"'), '\\"mcp_coingecko_execute\\"');
});

test('reverse: a canonical mcp__ name we never disguised is passed through intact', () => {
  // Hermes now emits mcp__server__tool itself. Collapsing that to a single
  // underscore hands its dispatcher a name it does not know. Regression guard
  // for the latent half of the 2026-07-25 todo failure.
  const untouched = '"mcp__linear__create_issue"';
  assert.strictEqual(reverseUnmappedMcpTools(untouched), untouched);
});

// ─── Model-invented mcp_ prefix on a natively-disguised tool ────────────────

const RECOVER_CFG = { toolRenames: [['todo', 'TodoWrite'], ['read_file', 'Read']] };

test('recover: model-invented mcp__todo resolves back to the real todo tool', () => {
  assert.strictEqual(recoverPrefixedNativeTools('"mcp__todo"', RECOVER_CFG), '"todo"');
  assert.strictEqual(recoverPrefixedNativeTools('"mcp_todo"', RECOVER_CFG), '"todo"');
  assert.strictEqual(recoverPrefixedNativeTools('\\"mcp__todo\\"', RECOVER_CFG), '\\"todo\\"');
});

test('recover: leaves genuine MCP names and unknown tools alone', () => {
  for (const name of ['"mcp__coingecko__execute"', '"mcp_coingecko_execute"', '"mcp__not_a_tool"']) {
    assert.strictEqual(recoverPrefixedNativeTools(name, RECOVER_CFG), name);
  }
});

test('recover: end-to-end, a tool_use naming mcp__todo comes back as todo', () => {
  const cfg = { ...PB, toolRenames: [['todo', 'TodoWrite']] };
  const upstream = '{"type":"tool_use","name":"mcp__todo","input":{"todos":[]}}';
  assert.ok(reverseMap(upstream, cfg).includes('"name":"todo"'),
    'mcp__todo did not resolve to the real tool');
});

test('stubs: a Grep/Glob/TodoRead call reverses onto a real Hermes tool', () => {
  const cfg = { ...PB, toolRenames: [['todo', 'TodoWrite'], ['search_files', 'mcp__ripgrep__search']] };
  const expect = { Grep: 'search_files', Glob: 'search_files', TodoRead: 'todo' };
  for (const [stub, real] of Object.entries(expect)) {
    const out = reverseMap(`{"type":"tool_use","name":"${stub}","input":{}}`, cfg);
    assert.ok(out.includes(`"name":"${real}"`), `${stub} did not map to ${real}: ${out}`);
  }
});

// ─── Round-trip: forward then reverse is the identity ───────────────────────

test('round-trip: forward(reverse) recovers every real unmapped shape', () => {
  for (const name of ['mcp_coingecko_execute', 'mcp_coingecko_search_docs', 'mcp_a_b_c_d']) {
    const fwd = disguiseUnmappedMcpTools(`"${name}"`).body;
    assert.ok(/"mcp__[A-Za-z0-9]+__[A-Za-z0-9_]+"/.test(fwd), `${name} did not gain canonical shape: ${fwd}`);
    assert.strictEqual(reverseUnmappedMcpTools(fwd), `"${name}"`, `round-trip failed for ${name}`);
  }
});

// ─── Integration: processBody (forward) <-> reverseMap (back) ────────────────

const PB = {
  replacements: [], toolRenames: [], propRenames: [], reverseMap: [],
  injectCCStubs: false, stripToolDescriptions: false,
  stripTrailingAssistantPrefill: true,
};

test('integration: a newly-enabled MCP tool is disguised by processBody and reversed by reverseMap', () => {
  const body = JSON.stringify({
    model: 'claude-opus-4-8',
    system: 'x',
    tools: [{ name: 'mcp_coingecko_execute', input_schema: { type: 'object' } }],
    messages: [{ role: 'user', content: 'hi' }],
  });
  const out = processBody(body, PB);
  assert.ok(out.includes('"mcp__coingecko__execute"'), 'processBody did not disguise the unmapped mcp_ tool');
  assert.ok(!/"mcp_coingecko_execute"/.test(out), 'raw foreign name leaked to upstream');
  // Anthropic echoes the disguised name back in a tool_use; reverseMap restores it.
  const upstreamToolUse = '{"type":"tool_use","name":"mcp__coingecko__execute","input":{}}';
  assert.ok(reverseMap(upstreamToolUse, PB).includes('"mcp_coingecko_execute"'), 'reverseMap did not restore the Hermes name');
});
