const test = require('node:test');
const assert = require('node:assert');
const { adaptDisabledThinking, isAdaptiveOnlyModel, envOAuthToken, loadConfig, processBody, reverseMap } = require('../proxy.js');

// ─── Hermes OAuth wire names (Sep 2026) ─────────────────────────────────────
// With a Claude Code token Hermes renames every tool to `mcp__<name>` before the
// proxy sees it. These tests use that exact wire shape.

const config = loadConfig();
const CC_NATIVE_2_1_283 = new Set(['Agent', 'AskUserQuestion', 'Bash', 'CronCreate', 'Edit', 'Glob', 'Grep',
  'Monitor', 'NotebookEdit', 'Read', 'SendMessage', 'Skill', 'WebFetch', 'WebSearch', 'Write', 'ToolSearch']);

function hermesOAuthBody(toolNames, historyToolName) {
  const messages = [{ role: 'user', content: [{ type: 'text', text: 'hi' }] }];
  if (historyToolName) {
    messages.push({ role: 'assistant', content: [{ type: 'tool_use', id: 'toolu_1', name: historyToolName, input: {} }] });
    messages.push({ role: 'user', content: [{ type: 'tool_result', tool_use_id: 'toolu_1', content: 'ok' }] });
  }
  return JSON.stringify({
    model: 'claude-opus-5-5', max_tokens: 100,
    system: [{ type: 'text', text: "You are Claude Code, Anthropic's official CLI for Claude." }],
    tools: toolNames.map((name) => ({ name, description: 'x', input_schema: { type: 'object', properties: {} } })),
    messages,
  });
}

test('Hermes wire names go out as current Claude Code natives or two-segment mcp__ names', () => {
  const wire = ['mcp__terminal', 'mcp__read_file', 'mcp__write_file', 'mcp__patch', 'mcp__search_files',
    'mcp__delegate_task', 'mcp__web_search', 'mcp__web_extract', 'mcp__clarify', 'mcp__skill_view',
    'mcp__kanban_create', 'mcp__context_notes', 'mcp__coingecko_execute', 'mcp__brand_new_tool', 'mcp__solo'];
  const out = JSON.parse(processBody(hermesOAuthBody(wire), config, '/v1/messages'));
  const names = out.tools.map((t) => t.name);
  for (const n of names) {
    assert.ok(CC_NATIVE_2_1_283.has(n) || /^mcp__[A-Za-z0-9]+__\w+$/.test(n), `not a genuine CC shape: ${n}`);
  }
  assert.strictEqual(new Set(names).size, names.length, `duplicate tool names: ${names}`);
  assert.ok(names.includes('Bash') && names.includes('Agent') && names.includes('Grep'));
});

test('history tool_use names are renamed exactly like the tools array', () => {
  const out = JSON.parse(processBody(hermesOAuthBody(['mcp__terminal'], 'mcp__terminal'), config, '/v1/messages'));
  const used = out.messages.flatMap((m) => (Array.isArray(m.content) ? m.content : []))
    .filter((b) => b.type === 'tool_use').map((b) => b.name);
  assert.deepStrictEqual(used, ['Bash']);
});

test('every disguised name reverses to a name Hermes can dispatch', () => {
  // Hermes dispatches a registered name as-is and un-prefixes only `mcp__…`
  // names (resolving its own aliases there), so both forms below are valid.
  const cases = {
    mcp__terminal: 'terminal', mcp__delegate_task: 'delegate_task', mcp__search_files: 'search_files',
    mcp__context_notes: 'memory', mcp__kanban_create: 'kanban_create',
    mcp__coingecko_execute: 'mcp_coingecko_execute', mcp__brand_new_tool: 'mcp__brand_new_tool',
  };
  for (const [sent, dispatchable] of Object.entries(cases)) {
    const out = JSON.parse(processBody(hermesOAuthBody([sent]), config, '/v1/messages'));
    const onWire = out.tools[out.tools.length - 1].name; // stubs are inserted first
    const back = reverseMap(`{"type":"tool_use","name":"${onWire}","input":{}}`, config);
    assert.ok(back.includes(`"name":"${dispatchable}"`), `${sent} -> ${onWire} -> ${back}`);
  }
});

test('the Grep stub is not injected when search_files already maps to Grep', () => {
  const out = JSON.parse(processBody(hermesOAuthBody(['mcp__search_files']), config, '/v1/messages'));
  assert.strictEqual(out.tools.filter((t) => t.name === 'Grep').length, 1);
});

// ─── adaptDisabledThinking ──────────────────────────────────────────────────
// Measured 2026-09-28: opus-5-5 and fable-5-1 400 on thinking:disabled; opus-5,
// sonnet-5, opus-4-8, sonnet-4-6 and haiku-4-5 accept it.

test('isAdaptiveOnlyModel matches the measured split', () => {
  for (const m of ['claude-opus-5-5', 'claude-fable-5-1', 'claude-opus-6', 'claude-sonnet-5-5']) {
    assert.ok(isAdaptiveOnlyModel(m), m);
  }
  for (const m of ['claude-opus-5', 'claude-sonnet-5', 'claude-opus-4-8', 'claude-sonnet-4-6', 'claude-haiku-4-5', 'claude-fable-5']) {
    assert.ok(!isAdaptiveOnlyModel(m), m);
  }
});

test('adaptive-only model: disabled thinking becomes effort low with a budget that fits an answer', () => {
  const body = JSON.stringify({
    model: 'claude-opus-5-5', max_tokens: 16, thinking: { type: 'disabled' },
    output_config: { format: { type: 'json_schema', schema: {} } }, messages: [],
  });
  const out = JSON.parse(adaptDisabledThinking(body));
  assert.strictEqual(out.thinking, undefined);
  assert.strictEqual(out.output_config.effort, 'low');
  assert.deepStrictEqual(out.output_config.format, { type: 'json_schema', schema: {} }, 'existing output_config kept');
  assert.ok(out.max_tokens >= 1024, 'a 16-token budget is spent entirely on thinking');
});

test('adaptive-only model: a budget already above the floor is left alone', () => {
  const body = JSON.stringify({ model: 'claude-fable-5-1', max_tokens: 4096, thinking: { type: 'disabled' } });
  assert.strictEqual(JSON.parse(adaptDisabledThinking(body)).max_tokens, 4096);
});

test('models that accept disabled thinking keep the body byte-identical', () => {
  for (const model of ['claude-opus-5', 'claude-sonnet-5', 'claude-haiku-4-5']) {
    const body = `{"model":"${model}","max_tokens":16,"thinking": {"type": "disabled"}}`;
    assert.strictEqual(adaptDisabledThinking(body), body, model);
  }
});

test('disabled thinking quoted inside message text is not mistaken for the field', () => {
  const body = JSON.stringify({ model: 'claude-opus-5-5', thinking: { type: 'adaptive' },
    messages: [{ role: 'user', content: 'send "thinking":{"type":"disabled"}' }] });
  assert.strictEqual(adaptDisabledThinking(body), body);
});

// ─── envOAuthToken ──────────────────────────────────────────────────────────

test('envOAuthToken: accepts CLAUDE_CODE_OAUTH_TOKEN, prefers OAUTH_TOKEN', () => {
  const saved = { a: process.env.OAUTH_TOKEN, b: process.env.CLAUDE_CODE_OAUTH_TOKEN };
  try {
    delete process.env.OAUTH_TOKEN;
    process.env.CLAUDE_CODE_OAUTH_TOKEN = ' sk-ant-oat01-x ';
    assert.strictEqual(envOAuthToken(), 'sk-ant-oat01-x');
    process.env.OAUTH_TOKEN = 'sk-ant-y';
    assert.strictEqual(envOAuthToken(), 'sk-ant-y');
  } finally {
    if (saved.a === undefined) delete process.env.OAUTH_TOKEN; else process.env.OAUTH_TOKEN = saved.a;
    if (saved.b === undefined) delete process.env.CLAUDE_CODE_OAUTH_TOKEN; else process.env.CLAUDE_CODE_OAUTH_TOKEN = saved.b;
  }
});
