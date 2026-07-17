// Tests for the /chat/completions -> /v1/messages routing fix that keeps
// Hermes' delegation/subagent traffic on the subscription-billed Messages API
// instead of Anthropic's metered OpenAI-compat endpoint.
//
// Run with:  node --test test/path-routing.test.js

const test = require('node:test');
const assert = require('node:assert');
const { looksLikeAnthropicMessages } = require('../proxy.js');

test('detects Anthropic Messages body: top-level system + content blocks', () => {
  const body = JSON.stringify({
    model: 'claude-opus-4-8',
    max_tokens: 1024,
    system: 'be brief',
    messages: [{ role: 'user', content: [{ type: 'text', text: 'hi' }] }],
  });
  assert.strictEqual(looksLikeAnthropicMessages(body), true);
});

test('detects Anthropic body via tool_use content block', () => {
  const body = JSON.stringify({
    model: 'claude-opus-4-8',
    messages: [{ role: 'assistant', content: [{ type: 'tool_use', id: 'x', name: 'y', input: {} }] }],
  });
  assert.strictEqual(looksLikeAnthropicMessages(body), true);
});

test('rejects genuine OpenAI body (role:system message)', () => {
  const body = JSON.stringify({
    model: 'gpt-4',
    messages: [
      { role: 'system', content: 'You are helpful' },
      { role: 'user', content: 'hi' },
    ],
    max_completion_tokens: 100,
  });
  assert.strictEqual(looksLikeAnthropicMessages(body), false);
});

test('rejects minimal OpenAI body with string content and no Anthropic markers', () => {
  const body = JSON.stringify({ model: 'x', messages: [{ role: 'user', content: 'hi' }] });
  assert.strictEqual(looksLikeAnthropicMessages(body), false);
});

test('rejects non-chat bodies (no messages array)', () => {
  assert.strictEqual(looksLikeAnthropicMessages(JSON.stringify({ input: 'embed me' })), false);
});

test('max_completion_tokens forces OpenAI even if content blocks present', () => {
  // Defensive: a hypothetical hybrid must not be misrouted to /v1/messages.
  const body = JSON.stringify({
    messages: [{ role: 'user', content: [{ type: 'text', text: 'hi' }] }],
    max_completion_tokens: 50,
  });
  assert.strictEqual(looksLikeAnthropicMessages(body), false);
});
