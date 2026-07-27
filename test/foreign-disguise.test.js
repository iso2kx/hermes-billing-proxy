// Tests for the generic FOREIGN tool disguise (Layer 3c) — the non-`mcp_` half
// of the self-healing fallback. Its sibling `disguiseUnmappedMcpTools` (Layer
// 3b) is covered by mcp-fallback.test.js; this suite covers the tools that pass
// carries no prefix for: core/plugin names like close_terminal or tool_search.
//
// Run with:  node --test test/foreign-disguise.test.js

const test = require('node:test');
const assert = require('node:assert');
const {
  loadConfig,
  disguiseForeignTools,
  reverseForeignTools,
  disguiseUnmappedMcpTools,
  processBody,
  reverseMap,
} = require('../proxy.js');

const config = loadConfig();
const toolsBody = (names) =>
  JSON.stringify({ tools: names.map((n) => ({ name: n, description: 'x' })) });

// ─── Forward: what gets disguised ───────────────────────────────────────────

test('foreign underscore name is canonicalised to mcp__a__b', () => {
  const { body, found } = disguiseForeignTools(toolsBody(['widget_frobnicate']), config);
  assert.ok(body.includes('"mcp__widget__frobnicate"'));
  assert.ok(!body.includes('"widget_frobnicate"'));
  assert.deepStrictEqual(found, ['widget_frobnicate']);
});

test('multi-underscore name splits on the FIRST underscore only', () => {
  const { body } = disguiseForeignTools(toolsBody(['zeta_alpha_beta']), config);
  assert.ok(body.includes('"mcp__zeta__alpha_beta"'));
});

test('single-word foreign name is LEFT ALONE (too generic to blind-replace)', () => {
  const { body, found } = disguiseForeignTools(toolsBody(['frobnicate']), config);
  assert.ok(body.includes('"frobnicate"'));
  assert.deepStrictEqual(found, []);
});

test('genuine native CC names are untouched', () => {
  const { body, found } = disguiseForeignTools(toolsBody(['Bash', 'ToolSearch']), config);
  assert.ok(body.includes('"Bash"') && body.includes('"ToolSearch"'));
  assert.deepStrictEqual(found, []);
});

test('already-canonical mcp__server__tool is untouched', () => {
  const { body, found } = disguiseForeignTools(toolsBody(['mcp__coingecko__execute']), config);
  assert.ok(body.includes('"mcp__coingecko__execute"'));
  assert.deepStrictEqual(found, []);
});

test('no tools array is a no-op', () => {
  const raw = JSON.stringify({ messages: [{ role: 'user', content: 'hi_there' }] });
  assert.strictEqual(disguiseForeignTools(raw, config).body, raw);
});

test('a name is only disguised when it appears in the TOOLS array', () => {
  // Same token as request data must not be rewritten when no such tool exists.
  const raw = JSON.stringify({
    tools: [{ name: 'Bash' }],
    messages: [{ role: 'user', content: 'the key is "some_setting"' }],
  });
  assert.ok(disguiseForeignTools(raw, config).body.includes('some_setting'));
});

// ─── Reversal ───────────────────────────────────────────────────────────────

test('round-trip restores the original name', () => {
  const { body } = disguiseForeignTools(toolsBody(['round_trip_probe']), config);
  assert.ok(body.includes('"mcp__round__trip_probe"'));
  assert.ok(reverseForeignTools(body).includes('"round_trip_probe"'));
});

test('reverse handles the SSE-escaped form', () => {
  disguiseForeignTools(toolsBody(['sse_probe']), config);
  const sse = 'data: {"name":\\"mcp__sse__probe\\"}';
  assert.ok(reverseForeignTools(sse).includes('\\"sse_probe\\"'));
});

test('reverse only undoes names THIS process disguised', () => {
  // Never registered — a genuine MCP name must survive reversal untouched.
  const untouched = '{"name":"mcp__stripe__create_charge"}';
  assert.strictEqual(reverseForeignTools(untouched), untouched);
});

test('assignment is stable across calls', () => {
  const a = disguiseForeignTools(toolsBody(['stable_probe']), config).body;
  const b = disguiseForeignTools(toolsBody(['stable_probe']), config).body;
  assert.strictEqual(a, b);
});

// ─── Collisions ─────────────────────────────────────────────────────────────

test('collision with the mcp_ pass takes a numeric suffix', () => {
  // 3b claims mcp__collide__probe for the real MCP tool mcp_collide_probe...
  disguiseUnmappedMcpTools('{"name":"mcp_collide_probe"}');
  // ...so the foreign tool `collide_probe` must NOT reuse that canonical name.
  const { body } = disguiseForeignTools(toolsBody(['collide_probe']), config);
  assert.ok(!body.includes('"mcp__collide__probe"'),
    'foreign tool stole a canonical name already owned by the mcp_ pass');
  assert.ok(/"mcp__collide__probe\d"/.test(body), `unexpected disguise: ${body}`);
  // And it still round-trips.
  assert.ok(reverseForeignTools(body).includes('"collide_probe"'));
});

// ─── Integration: tool defs and replayed history must agree ─────────────────

test('processBody disguises the tools array AND tool_use names in history', () => {
  const raw = JSON.stringify({
    model: 'hermes-4-opus',
    tools: [{ name: 'gizmo_launch', description: 'Launch a gizmo' }],
    messages: [
      { role: 'user', content: 'go' },
      { role: 'assistant', content: [{ type: 'tool_use', name: 'gizmo_launch', input: {} }] },
      { role: 'user', content: [{ type: 'tool_result', content: 'ok' }] },
    ],
  });
  const fwd = JSON.parse(processBody(raw, config, '/v1/messages'));
  const toolName = fwd.tools.find((t) => /gizmo/.test(t.name)).name;
  const histName = fwd.messages.find((m) => m.role === 'assistant').content[0].name;
  assert.strictEqual(toolName, 'mcp__gizmo__launch');
  assert.strictEqual(histName, toolName, 'tool def and replayed tool_use disagree');
});

test('a model response naming the disguise maps back to the real Hermes tool', () => {
  disguiseForeignTools(toolsBody(['gadget_spin']), config);
  const resp = JSON.stringify({
    content: [{ type: 'tool_use', name: 'mcp__gadget__spin', input: {} }],
  });
  assert.strictEqual(JSON.parse(reverseMap(resp, config)).content[0].name, 'gadget_spin');
});

// ─── The regression this whole layer exists to prevent ──────────────────────

test('the tool_search bridge and tui_gateway tools emit zero foreign names', () => {
  const raw = JSON.stringify({
    model: 'hermes-4-opus',
    tools: [
      // Static-map entries (belt) plus names no map has learned (braces).
      { name: 'tool_search' }, { name: 'tool_describe' }, { name: 'tool_call' },
      { name: 'close_terminal' }, { name: 'project_create' },
      { name: 'future_unmapped_tool' }, { name: 'mcp_brandnew_thing' },
    ],
  });
  const names = JSON.parse(processBody(raw, config, '/v1/messages')).tools.map((t) => t.name);
  const { nativeToolAllowlist } = require('../proxy.js');
  const allow = nativeToolAllowlist(config);
  const foreign = names.filter((n) => !/^mcp__/.test(n) && !allow.has(n));
  assert.deepStrictEqual(foreign, [], `foreign names still on the wire: ${foreign}`);
});
