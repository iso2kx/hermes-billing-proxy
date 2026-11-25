'use strict';
// The path / env-var / CLI-name swaps (HERMES_HOME -> CLAUDE_HOME, .hermes/ ->
// .claude-ws/, HERMES.md -> CLAUDE.md, `hermes gateway` -> `claude gateway`, ...)
// were removed on 2026-11-25. Two problems drove it:
//   1. The model read a different text from the disk, inconsistently: `.hermes/`
//      was swapped but bare `.hermes` and `hermes plugins` were not.
//   2. The reverses collided with real Claude Code names, so a tool call to
//      `cat repo/CLAUDE.md` or `claude setup-token` reached Hermes as
//      `cat repo/HERMES.md` / `hermes setup-token`.
// These tests run against the real defaults (loadConfig), not a test config.

const test = require('node:test');
const assert = require('node:assert');
const { processBody, reverseMapToolArgs, reverseMap, loadConfig } = require('../proxy.js');

const CFG = loadConfig();

function forwardText(text) {
  const body = JSON.stringify({
    model: 'claude-opus-5-5', max_tokens: 16,
    messages: [{ role: 'user', content: [{ type: 'text', text }] }],
  });
  const out = JSON.parse(processBody(body, CFG, '/v1/messages'));
  return JSON.stringify(out.messages);
}

test('forward: Hermes paths, env vars and CLI names reach the model unchanged', () => {
  const samples = [
    '~/.hermes/plugins/phone-bridge', 'ls ~/.hermes', '$HERMES_HOME/config.yaml',
    'hermes_home', 'HERMES.md', '.hermes.md', 'hermes_cli/main.py', 'HermesCLI',
    'hermes gateway status', 'hermes skills list', 'hermes cron list',
    'hermes setup', 'hermes model', 'hermes status', 'hermes plugins list',
    'HERMES_PLATFORM', 'HERMES_SESSION_PLATFORM',
  ];
  const out = forwardText(samples.join('\n'));
  for (const s of samples) {
    assert.ok(out.includes(JSON.stringify(s).slice(1, -1)), `forward rewrote ${s}: ${out.slice(0, 400)}`);
  }
  for (const bad of ['claude-ws', 'CLAUDE_HOME', 'claude_cli', 'claude gateway', 'ClaudeCLI']) {
    assert.ok(!out.includes(bad), `forward produced ${bad}`);
  }
});

test('tool args: real Claude Code names are no longer rewritten to Hermes ones', () => {
  const cases = [
    '{"command":"cat D:/repo/CLAUDE.md"}',
    '{"path":"C:/Users/u/project/.claude.md"}',
    '{"command":"claude setup-token"}',
    '{"command":"claude model list"}',
    '{"command":"claude status"}',
    '{"path":"C:/Users/u/.claude/settings.json"}',
  ];
  for (const c of cases) assert.equal(reverseMapToolArgs(c, CFG), c);
});

test('prose: real Claude Code names survive the response reverse map', () => {
  const s = 'Edit CLAUDE.md, then run claude setup-token and claude model.';
  assert.equal(reverseMap(s, CFG), s);
});

test('transition: proxy-invented tokens from older sessions still reverse', () => {
  assert.equal(
    reverseMapToolArgs('{"command":"ls ~/.claude-ws/plugins; ls ~/.claude-ws; echo $CLAUDE_HOME"}', CFG),
    '{"command":"ls ~/.hermes/plugins; ls ~/.hermes; echo $HERMES_HOME"}');
});
