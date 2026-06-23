// Tests for the response-side tool-argument scoping fix (the real ENOENT cause),
// model-aware betas, Haiku effort-stripping, tool-input masking, and orphaned
// tool-pair repair.
//
// Run with:  node --test test/tool-arg-reverse.test.js

const test = require('node:test');
const assert = require('node:assert');
const {
  reverseMap,
  reverseMapToolArgs,
  reverseMapResponse,
  maskToolUseInputs,
  unmaskToolUseInputs,
  repairOrphanedToolPairs,
  getModelBetas,
  stripEffortFromObject,
  applySseReverseMapChunks,
} = require('../proxy.js');

const CONFIG = {
  reverseMap: [
    ['Claude Code', 'Hermes Agent'],
    ['.claude-ws/', '.hermes/'],
    ['.claude-ws', '.hermes'],
    ['CLAUDE.md', 'HERMES.md'],
    ['Claude', 'Hermes'],
    ['claude', 'hermes'],
  ],
  toolRenames: [['read_file', 'Read'], ['browser_navigate', 'mcp__playwright__browser_navigate']],
  propRenames: [['session_id', 'thread_id']],
};

// ─── reverseMapToolArgs: structural reversals kept, identity swaps dropped ───

test('tool-arg reverse: bare "claude" in a path is NOT corrupted', () => {
  const input = '{"path":"/home/u/projects/claude-demo/main.py"}';
  assert.equal(reverseMapToolArgs(input, CONFIG), input);
});

test('tool-arg reverse: "claude" in a git url is NOT corrupted', () => {
  const input = '{"command":"git clone https://github.com/x/claude-utils"}';
  assert.equal(reverseMapToolArgs(input, CONFIG), input);
});

test('tool-arg reverse: structural .claude-ws/ IS restored to .hermes/', () => {
  assert.equal(
    reverseMapToolArgs('{"path":"/home/u/.claude-ws/x.md"}', CONFIG),
    '{"path":"/home/u/.hermes/x.md"}');
});

test('tool-arg reverse: renamed prop key thread_id is restored to session_id', () => {
  assert.equal(
    reverseMapToolArgs('{"thread_id":"abc","message":"hi"}', CONFIG),
    '{"session_id":"abc","message":"hi"}');
});

test('tool-arg reverse: disguised tool names revert via static map', () => {
  // Native-CC disguise and mcp__ disguise both round-trip to the real Hermes name.
  assert.equal(reverseMapToolArgs('{"tool":"Read"}', CONFIG), '{"tool":"read_file"}');
  assert.equal(
    reverseMapToolArgs('{"tool":"mcp__playwright__browser_navigate"}', CONFIG),
    '{"tool":"browser_navigate"}');
});

test('full reverseMap STILL corrupts the same path (documents the difference)', () => {
  assert.equal(
    reverseMap('{"path":"/home/u/projects/claude-demo/main.py"}', CONFIG),
    '{"path":"/home/u/projects/hermes-demo/main.py"}');
});

// ─── reverseMapResponse: scopes tool_use inputs, full-reverses the rest ──────

test('reverseMapResponse: visible text reversed, tool_use input path preserved', () => {
  const body = JSON.stringify({
    content: [
      { type: 'text', text: 'I used Claude to read CLAUDE.md' },
      { type: 'tool_use', id: 't1', name: 'Read',
        input: { path: '/home/u/projects/claude-demo/main.py', dir: '/home/u/.claude-ws/cfg' } },
    ],
  });
  const out = reverseMapResponse(body, CONFIG);
  // Visible text: identity swaps applied.
  assert.ok(out.includes('I used Hermes to read HERMES.md'), 'text not reversed: ' + out);
  // Tool input: legit "claude-demo" preserved, structural .claude-ws/ restored.
  assert.ok(out.includes('/home/u/projects/claude-demo/main.py'), 'tool path corrupted: ' + out);
  assert.ok(out.includes('/home/u/.hermes/cfg'), 'structural path not restored: ' + out);
  // Disguised tool name reverts to the real Hermes name.
  assert.ok(out.includes('"name":"read_file"'), 'tool name not reversed: ' + out);
  assert.doesNotThrow(() => JSON.parse(out), 'output is not valid JSON');
});

// ─── getModelBetas ──────────────────────────────────────────────────────────

test('getModelBetas: Haiku drops interleaved-thinking / effort / fast-mode', () => {
  const betas = getModelBetas('claude-haiku-4-5');
  assert.ok(!betas.includes('interleaved-thinking-2025-05-14'));
  assert.ok(!betas.includes('effort-2025-11-24'));
  assert.ok(!betas.includes('fast-mode-2026-02-01'));
  assert.ok(betas.includes('oauth-2025-04-20'));
});

test('getModelBetas: Opus keeps the full set', () => {
  const betas = getModelBetas('claude-opus-4-6');
  assert.ok(betas.includes('interleaved-thinking-2025-05-14'));
  assert.ok(betas.includes('effort-2025-11-24'));
});

test('getModelBetas: matches hermes-haiku-* too (pre-remap name)', () => {
  assert.ok(!getModelBetas('hermes-haiku-4-5').includes('effort-2025-11-24'));
});

// ─── stripEffortFromObject ──────────────────────────────────────────────────

test('stripEffortFromObject: removes effort, keeps siblings', () => {
  assert.equal(
    stripEffortFromObject('{"output_config":{"effort":"high","max":4}}', 'output_config'),
    '{"output_config":{"max":4}}');
  assert.equal(
    stripEffortFromObject('{"thinking":{"type":"enabled","effort":"low"}}', 'thinking'),
    '{"thinking":{"type":"enabled"}}');
});

test('stripEffortFromObject: no-op when key/field absent', () => {
  assert.equal(stripEffortFromObject('{"a":1}', 'output_config'), '{"a":1}');
  assert.equal(
    stripEffortFromObject('{"output_config":{"max":4}}', 'output_config'),
    '{"output_config":{"max":4}}');
});

// ─── maskToolUseInputs ──────────────────────────────────────────────────────

test('maskToolUseInputs: quoted placeholder keeps body valid JSON; round-trips', () => {
  const body = '{"type":"tool_use","id":"x","name":"Read","input":{"path":"/home/u/.hermes/x.json"}}';
  const { masked, masks } = maskToolUseInputs(body);
  assert.deepEqual(masks, ['{"path":"/home/u/.hermes/x.json"}']);
  assert.ok(/"input":"__OBP_TOOL_INPUT_MASK_0__"/.test(masked));
  assert.doesNotThrow(() => JSON.parse(masked), 'masked body must be valid JSON');
  assert.equal(unmaskToolUseInputs(masked, masks), body);
});

test('maskToolUseInputs: no tool_use -> untouched', () => {
  const body = '{"messages":[{"role":"user","content":"hi"}]}';
  assert.deepEqual(maskToolUseInputs(body), { masked: body, masks: [] });
});

// ─── repairOrphanedToolPairs ────────────────────────────────────────────────

test('repair: balanced tool_use/tool_result is untouched', () => {
  const body = JSON.stringify({ messages: [
    { role: 'assistant', content: [{ type: 'tool_use', id: 't1', name: 'R', input: {} }] },
    { role: 'user', content: [{ type: 'tool_result', tool_use_id: 't1', content: 'ok' }] },
  ]});
  assert.equal(repairOrphanedToolPairs(body), body);
});

test('repair: orphaned tool_use is removed', () => {
  const body = JSON.stringify({ messages: [
    { role: 'assistant', content: [
      { type: 'tool_use', id: 't1', name: 'R', input: {} },
      { type: 'tool_use', id: 't2', name: 'R', input: {} },
    ]},
    { role: 'user', content: [{ type: 'tool_result', tool_use_id: 't1', content: 'ok' }] },
  ]});
  const out = JSON.parse(repairOrphanedToolPairs(body));
  const ids = out.messages[0].content.map(b => b.id);
  assert.deepEqual(ids, ['t1']);
});

test('repair: non-tool body untouched (fast path)', () => {
  const body = '{"messages":[{"role":"user","content":"hi"}]}';
  assert.equal(repairOrphanedToolPairs(body), body);
});

// ─── streaming tool args via the SSE transformer ────────────────────────────

// ─── count_tokens skips metadata injection (avoids 400) ─────────────────────

test('processBody: count_tokens path skips metadata, normal path injects it', () => {
  process.env.OAUTH_TOKEN = 'sk-ant-test';
  const { loadConfig, processBody } = require('../proxy.js');
  const cfg = loadConfig();
  const body = JSON.stringify({
    model: 'claude-opus-4-8',
    system: [{ type: 'text', text: 'hi' }],
    messages: [{ role: 'user', content: 'hi' }],
  });
  const ct = processBody(body, cfg, '/v1/messages/count_tokens');
  assert.ok(!ct.includes('"metadata"'), 'metadata must NOT be injected for count_tokens: ' + ct);
  assert.doesNotThrow(() => JSON.parse(ct), 'count_tokens output must be valid JSON');
  const normal = processBody(body, cfg, '/v1/messages');
  assert.ok(normal.includes('"metadata"'), 'metadata SHOULD be injected for /v1/messages');
});

// ─── model remap survives thinking blocks (the Hermes 404 fix) ──────────────

test('processBody: model hermes-* -> claude-* even WITH a thinking block', () => {
  process.env.OAUTH_TOKEN = 'sk-ant-test';
  const { loadConfig, processBody } = require('../proxy.js');
  const cfg = loadConfig();
  const body = JSON.stringify({
    model: 'hermes-opus-4-8', max_tokens: 16,
    messages: [
      { role: 'user', content: 'hi' },
      { role: 'assistant', content: [
        { type: 'thinking', thinking: 'x', signature: 's' },
        { type: 'text', text: 'hello' },
      ]},
      { role: 'user', content: 'again' },
    ],
  });
  const out = processBody(body, cfg);
  assert.ok(/"model"\s*:\s*"claude-opus-4-8"/.test(out), 'model not remapped: ' + out.slice(0, 140));
  assert.ok(!out.includes('hermes-opus-4-8'), 'unremapped hermes model leaked to upstream');
  assert.ok(out.includes('"type":"thinking"'), 'thinking block must be preserved');
});

// ─── empty tools:[] stub-injection trailing-comma fix ───────────────────────

test('processBody: empty tools:[] with stub injection stays valid JSON', () => {
  process.env.OAUTH_TOKEN = 'sk-ant-test';
  const { loadConfig, processBody } = require('../proxy.js');
  const cfg = loadConfig();
  const body = JSON.stringify({
    model: 'claude-opus-4-6', max_tokens: 64,
    system: [{ type: 'text', text: 'hi' }],
    messages: [{ role: 'user', content: 'hi' }],
    tools: [],
  });
  const out = processBody(body, cfg);
  assert.doesNotThrow(() => JSON.parse(out), 'empty-tools output must be valid JSON: ' + out);
});

test('streaming: tool_use input args use the tool-arg-safe reverse', () => {
  const start = 'event: content_block_start\ndata: {"type":"content_block_start","index":1,"content_block":{"type":"tool_use","id":"t1","name":"McpTerminal"}}\n\n';
  const delta = 'event: content_block_delta\ndata: {"type":"content_block_delta","index":1,"delta":{"type":"input_json_delta","partial_json":"{\\"command\\":\\"cat .claude-ws/CLAUDE.md; cd claude-demo\\"}"}}\n\n';
  const stop = 'event: content_block_stop\ndata: {"type":"content_block_stop","index":1}\n\n';
  const out = applySseReverseMapChunks([start, delta, stop], CONFIG);
  // Structural .claude-ws/ + CLAUDE.md restored; bare "claude-demo" preserved.
  assert.ok(out.includes('cat .hermes/HERMES.md'), 'structural not restored: ' + out);
  assert.ok(out.includes('cd claude-demo'), 'bare claude corrupted in tool arg: ' + out);
});
