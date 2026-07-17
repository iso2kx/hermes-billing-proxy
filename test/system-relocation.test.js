// Tests for system-prompt relocation — the subscription-billing fix that reduces
// `system` to [billing, CC identity] and moves everything else into the first
// user message as <system-reminder> blocks. This is what makes subagent (and all)
// Hermes traffic bill to the Claude subscription instead of extra usage.
//
// Run with:  node --test test/system-relocation.test.js

const test = require('node:test');
const assert = require('node:assert');
const { relocateSystemToUser } = require('../proxy.js');

const IDENTITY = "You are Claude Code, Anthropic's official CLI for Claude.";
const BILLING = 'x-anthropic-billing-header: cc_version=2.1.203.abc; cc_entrypoint=cli; cch=00000;';

function sysTexts(o) { return (o.system || []).map((b) => b.text || ''); }
function userText(o) {
  const um = o.messages.find((m) => m.role === 'user');
  return Array.isArray(um.content) ? um.content.map((c) => c.text || '').join('') : String(um.content);
}

test('subagent-style body: framework moves to user, system keeps billing+identity', () => {
  const body = JSON.stringify({
    model: 'claude-opus-4-8',
    system: [
      { type: 'text', text: BILLING },
      { type: 'text', text: IDENTITY },
      { type: 'text', text: 'You are Hermes Agent, an intelligent AI assistant created by Nous Research. [lots of framework]' },
    ],
    messages: [{ role: 'user', content: [{ type: 'text', text: 'do the task' }] }],
  });
  const out = relocateSystemToUser(body, {});
  const o = JSON.parse(out);
  assert.deepStrictEqual(sysTexts(o), [BILLING, IDENTITY], 'system must be exactly [billing, identity]');
  const ut = userText(o);
  assert.ok(ut.includes('<system-reminder>'), 'framework not wrapped in <system-reminder>');
  assert.ok(ut.includes('You are Hermes Agent'), 'framework text not relocated');
  assert.ok(ut.includes('do the task'), 'original user text lost');
  assert.ok(ut.indexOf('You are Hermes Agent') < ut.indexOf('do the task'), 'reminder must be prepended');
});

test('identity block with trailing content: identity kept, trailing relocated', () => {
  const body = JSON.stringify({
    system: [
      { type: 'text', text: BILLING },
      { type: 'text', text: IDENTITY + '\n\n# Persona\nYou are a helpful sidekick.' },
    ],
    messages: [{ role: 'user', content: 'hi' }],
  });
  const o = JSON.parse(relocateSystemToUser(body, {}));
  assert.deepStrictEqual(sysTexts(o), [BILLING, IDENTITY]);
  assert.ok(userText(o).includes('You are a helpful sidekick.'), 'trailing persona not relocated');
  assert.ok(!sysTexts(o).join('').includes('helpful sidekick'), 'persona leaked into system');
});

test('no identity present: identity is synthesized after billing', () => {
  const body = JSON.stringify({
    system: [{ type: 'text', text: BILLING }, { type: 'text', text: 'Custom framework prompt here.' }],
    messages: [{ role: 'user', content: 'hi' }],
  });
  const o = JSON.parse(relocateSystemToUser(body, {}));
  assert.deepStrictEqual(sysTexts(o), [BILLING, IDENTITY], 'identity should be inserted after billing');
  assert.ok(userText(o).includes('Custom framework prompt here.'));
});

test('nothing to relocate (only billing+identity): body unchanged', () => {
  const body = JSON.stringify({
    system: [{ type: 'text', text: BILLING }, { type: 'text', text: IDENTITY }],
    messages: [{ role: 'user', content: 'hi' }],
  });
  assert.strictEqual(relocateSystemToUser(body, {}), body);
});

test('string user content is handled', () => {
  const body = JSON.stringify({
    system: [{ type: 'text', text: IDENTITY }, { type: 'text', text: 'framework' }],
    messages: [{ role: 'user', content: 'original question' }],
  });
  const o = JSON.parse(relocateSystemToUser(body, {}));
  const ut = userText(o);
  assert.ok(ut.includes('<system-reminder>') && ut.includes('framework') && ut.includes('original question'));
});

test('disabled via config.relocateSystem=false: untouched', () => {
  const body = JSON.stringify({
    system: [{ type: 'text', text: IDENTITY }, { type: 'text', text: 'framework' }],
    messages: [{ role: 'user', content: 'hi' }],
  });
  assert.strictEqual(relocateSystemToUser(body, { relocateSystem: false }), body);
});

test('malformed / non-JSON body returns unchanged', () => {
  assert.strictEqual(relocateSystemToUser('not json', {}), 'not json');
});

test('first user turn is a tool_result response: reminder inserted AFTER tool_result, not before', () => {
  // A compacted/long history can begin mid tool-exchange (assistant tool_use ->
  // user tool_result). The tool_result must lead its turn or Anthropic 400s
  // ("tool_use ids ... without tool_result blocks immediately after").
  const body = JSON.stringify({
    system: [{ type: 'text', text: IDENTITY }, { type: 'text', text: 'framework instructions' }],
    messages: [
      { role: 'assistant', content: [{ type: 'text', text: 'ok' }, { type: 'tool_use', id: 'toolu_ABC', name: 'Bash', input: {} }] },
      { role: 'user', content: [{ type: 'tool_result', tool_use_id: 'toolu_ABC', content: 'done' }] },
    ],
  });
  const o = JSON.parse(relocateSystemToUser(body, {}));
  const uc = o.messages[1].content;
  assert.strictEqual(uc[0].type, 'tool_result', 'tool_result must still lead the user turn');
  assert.ok(uc.some((c) => c.type === 'text' && c.text.includes('framework instructions')), 'reminder must be present');
});

test('first user turn has both tool_result and text: merge into text, tool_result stays first', () => {
  const body = JSON.stringify({
    system: [{ type: 'text', text: IDENTITY }, { type: 'text', text: 'framework' }],
    messages: [
      { role: 'assistant', content: [{ type: 'tool_use', id: 'toolu_X', name: 'Bash', input: {} }] },
      { role: 'user', content: [{ type: 'tool_result', tool_use_id: 'toolu_X', content: 'r' }, { type: 'text', text: 'q' }] },
    ],
  });
  const o = JSON.parse(relocateSystemToUser(body, {}));
  const uc = o.messages[1].content;
  assert.strictEqual(uc[0].type, 'tool_result', 'tool_result must still lead the user turn');
  assert.ok(uc.some((c) => c.type === 'text' && c.text.includes('framework') && c.text.includes('q')));
});
