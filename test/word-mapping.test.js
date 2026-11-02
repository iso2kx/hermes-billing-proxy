'use strict';
// Word-mapping regressions found 2026-11-02 in a live Hermes session (the agent
// told the user to "Update Toolkit"). Every case runs through the REAL default
// tables via loadConfig(), not a hand-built config, so a future edit to
// DEFAULT_REPLACEMENTS / DEFAULT_REVERSE_MAP that reintroduces a leak fails here.
//
// Run with:  node --test test/word-mapping.test.js

const test = require('node:test');
const assert = require('node:assert');
const {
  loadConfig, processBody, reverseMap, reverseMapToolArgs,
  applySseReverseMapChunks, findSseStringField, jsonStringDecode,
  isLocalModelProbe, DEFAULT_REPLACEMENTS, DEFAULT_REVERSE_MAP,
} = require('../proxy.js');

const CFG = loadConfig();

function bodyWithSystem(sys) {
  return JSON.stringify({
    model: 'claude-opus-5-5',
    system: [{ type: 'text', text: sys }],
    messages: [{ role: 'user', content: 'hi' }],
  });
}
const FILLER = 'Follow the user instructions carefully and cite files. '.repeat(45);

// ─── forward: nothing one-way may reach the model ──────────────────────────

test('no forward replacement invents a name the reverse map cannot undo', () => {
  // A forward pair is safe only if the reverse map restores it, or its
  // replacement is a fixed platform-hint sentence (prompt-only sanitizing).
  const reverseKeys = new Set(DEFAULT_REVERSE_MAP.map(([from]) => from));
  const brandish = /toolkit|anthropic/i;
  for (const [from, to] of DEFAULT_REPLACEMENTS) {
    if (!brandish.test(to)) continue;
    assert.ok(reverseKeys.has(to), `one-way brand swap: '${from}' -> '${to}'`);
  }
});

test('the real name and maker reach the model unchanged', () => {
  const sys = 'You are Hermes, an agent made by Nous Research.\n' +
    'Docs: https://hermes-agent.nousresearch.com/docs\n' +
    'Repo: https://github.com/NousResearch/hermes-agent\n' + FILLER;
  const out = processBody(bodyWithSystem(sys), CFG);
  assert.ok(out.includes('You are Hermes'), 'bare Hermes was rewritten');
  assert.ok(out.includes('Nous Research'), 'Nous Research was rewritten');
  assert.ok(out.includes('nousresearch.com/docs'), 'docs URL was rewritten');
  assert.ok(out.includes('github.com/NousResearch/'), 'GitHub org was rewritten');
  assert.ok(!/\btoolkit\b/i.test(out), 'invented "Toolkit" reached the model');
  assert.ok(!/anthropic\.com\/docs|AnthropicAI/.test(out), 'invented Anthropic URL/org reached the model');
});

// ─── reverse: ordinary prose must come back untouched ──────────────────────

const PROSE = [
  'Session with Bob ended at 5pm.',
  'This is an interactive CLI session, so prompts block.',
  'Use markdown for formatting.',
  'You are in an interactive session right now.',
  'Open Claude Desktop and sign in.',
  'Claude is the model behind this agent.',
  'The claude.ai settings page has a usage tab.',
  'I use file tools to share files with you.',
];

test('reverse map leaves ordinary prose untouched', () => {
  for (const s of PROSE) assert.strictEqual(reverseMap(s, CFG), s, `rewrote prose: ${s}`);
});

test('streamed prose is untouched even when split mid-phrase', () => {
  const blockStart = '' +
    'event: content_block_start\ndata: {"type":"content_block_start","index":0,"content_block":{"type":"text","text":""}}\n\n';
  const delta = (t) =>
    `event: content_block_delta\ndata: {"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":${JSON.stringify(t)}}}\n\n`;
  const stop = 'event: content_block_stop\ndata: {"type":"content_block_stop","index":0}\n\n';
  for (const s of PROSE) {
    const mid = Math.floor(s.length / 2);
    const out = applySseReverseMapChunks([blockStart + delta(s.slice(0, mid)) + delta(s.slice(mid)) + stop], CFG);
    let text = '';
    for (const e of out.split('\n\n')) {
      if (!e.includes('"text_delta"')) continue;
      text += jsonStringDecode(e, findSseStringField(e, 'text')).value;
    }
    assert.strictEqual(text, s, `streamed prose rewritten: ${s}`);
  }
});

// ─── reverse: the proxy's own disguises still round-trip ───────────────────

test('disguised structural tokens are still restored', () => {
  assert.strictEqual(reverseMap('see .claude-ws/skills', CFG), 'see .hermes/skills');
  assert.strictEqual(reverseMap('set CLAUDE_HOME', CFG), 'set HERMES_HOME');
});

// Hermes renames its own hermes-agent skill/paths to claude-code before the
// request reaches the proxy (OAuth mode, agent/anthropic_adapter.py). The
// model then names that skill "claude-code"; the reverse must restore it in
// tool args or skill_view fails with "Skill not found".
test('Hermes-disguised identifiers resolve back in tool args', () => {
  assert.strictEqual(reverseMapToolArgs('{"name":"claude-code"}', CFG), '{"name":"hermes-agent"}');
  assert.strictEqual(reverseMap('I am Claude Code.', CFG), 'I am Hermes Agent.');
});

// The claude-code reverse is scoped to where Hermes's slug swap can produce it.
const SLUG_RESTORED = [
  ['{"name":"claude-code"}', '{"name":"hermes-agent"}'],                 // skill_view arg
  ['    - claude-code: Use, configure', '    - hermes-agent: Use, configure'], // skill index
  ['cd C:\\Users\\user\\AppData\\Local\\hermes\\claude-code', 'cd C:\\Users\\user\\AppData\\Local\\hermes\\hermes-agent'],
  ['cd C:/Users/user/AppData/Local/hermes/claude-code/agent', 'cd C:/Users/user/AppData/Local/hermes/hermes-agent/agent'],
  ['working on claude-code today.', 'working on hermes-agent today.'],
];
const SLUG_KEPT = [
  'npm i -g @anthropic-ai/claude-code',
  'gh repo view anthropics/claude-code',
  'https://docs.claude.com/en/docs/claude-code/overview',
  'anthropic-beta: claude-code-20250219',
  'cat claude-code.json',
  'ls ~/.claude-code',
  // Hermes never produces "<dir>/claude-code" (its swap skips '/'-joined
  // slugs), so a slash path outside a `hermes` folder is genuine.
  'git -C "$HOME/src/claude-code" log',
];

test('claude-code is restored only where Hermes could have produced it', () => {
  for (const [input, want] of SLUG_RESTORED) {
    assert.strictEqual(reverseMapToolArgs(input, CFG), want, `tool arg: ${input}`);
    assert.strictEqual(reverseMap(input, CFG), want, `prose: ${input}`);
  }
  for (const s of SLUG_KEPT) {
    assert.strictEqual(reverseMapToolArgs(s, CFG), s, `tool arg rewritten: ${s}`);
    assert.strictEqual(reverseMap(s, CFG), s, `prose rewritten: ${s}`);
  }
});

test('streamed tool call: package name kept, Hermes skill and path restored', () => {
  const start = 'event: content_block_start\ndata: {"type":"content_block_start","index":1,"content_block":{"type":"tool_use","id":"t1","name":"Bash"}}\n\n';
  const args = JSON.stringify({
    command: 'npm i -g @anthropic-ai/claude-code && cd C:\\Users\\V\\AppData\\Local\\hermes\\claude-code',
  });
  const delta = 'event: content_block_delta\ndata: ' + JSON.stringify({
    type: 'content_block_delta', index: 1, delta: { type: 'input_json_delta', partial_json: args },
  }) + '\n\n';
  const stop = 'event: content_block_stop\ndata: {"type":"content_block_stop","index":1}\n\n';
  const out = applySseReverseMapChunks([start, delta, stop], CFG);
  assert.ok(out.includes('@anthropic-ai/claude-code'), 'package name rewritten: ' + out);
  assert.ok(/hermes\\\\+hermes-agent/.test(out), 'Hermes checkout path not restored: ' + out);
  assert.ok(!/hermes-agent &&|@anthropic-ai\/hermes-agent/.test(out), 'over-restored: ' + out);
});

// The proxy itself adds no identity swap on top (Hermes already did it).
test('the proxy adds no Hermes Agent -> Claude Code swap of its own', () => {
  const sys = 'You are Hermes Agent, an intelligent AI assistant.\n' +
    'Checkout: C:/Users/user/AppData/Local/hermes/hermes-agent\n' + FILLER;
  const out = processBody(bodyWithSystem(sys), CFG);
  assert.ok(out.includes('You are Hermes Agent, an intelligent'), 'name rewritten');
  assert.ok(out.includes('hermes/hermes-agent'), 'checkout path rewritten');
  assert.ok(!/You are Claude Code, an intelligent|hermes\/claude-code/.test(out), 'identity or path disguised');
});

test('a parroted CC identity line is restored as a whole phrase', () => {
  assert.strictEqual(
    reverseMap("I'm Claude Code, Anthropic's official CLI for Claude.", CFG),
    "I'm Hermes Agent, the open-source agent by Nous Research.");
  assert.strictEqual(
    reverseMap("This runs Anthropic's official CLI for Claude.", CFG),
    'This runs the open-source agent by Nous Research.');
});

test('identity-phrase restores never touch tool arguments', () => {
  const arg = "echo \"Anthropic's official CLI for Claude\" > note.txt";
  assert.strictEqual(reverseMapToolArgs(arg, CFG), arg);
});

// ─── local-model probes ─────────────────────────────────────────────────────

test('local-model discovery probes are answered locally', () => {
  for (const [m, u] of [
    ['GET', '/version'], ['GET', '/props'], ['GET', '/v1/props'],
    ['GET', '/api/tags'], ['GET', '/api/v1/models'], ['GET', '/api/v1/models?x=1'],
    ['POST', '/api/show'],
  ]) assert.strictEqual(isLocalModelProbe(m, u), true, `${m} ${u}`);
});

test('real API paths are never treated as probes', () => {
  for (const [m, u] of [
    ['POST', '/v1/messages'], ['POST', '/v1/messages/count_tokens'],
    ['GET', '/v1/models'], ['GET', '/v1/models?limit=1000'], ['GET', '/v1/models/claude-opus-5-5'],
    ['POST', '/version'], ['GET', '/api/show'], ['GET', '/api/tags/x'], ['GET', '/'],
  ]) assert.strictEqual(isLocalModelProbe(m, u), false, `${m} ${u}`);
});
