'use strict';
// The forward identity pass (Hermes -> Toolkit) used to be a blind split/join
// over every system block, and it is forward-only — nothing maps 'toolkit' back.
// So it rewrote real paths and skill names into strings the model then repeated
// into tool calls that could not resolve: 85 such calls across 48 sessions.
//
// Every literal below was recovered from those sessions.

const test = require('node:test');
const assert = require('node:assert');
const {
  replaceBareWord, isStructuralContext, reverseMap, processBody, loadConfig,
} = require('../proxy.js');

const H = 'Hermes';
const h = 'hermes';

// ─── the observed failures ──────────────────────────────────────────────────

test('real paths and identifiers survive the disguise pass', () => {
  const cases = [
    '~/hermes-projects.json',
    'C:\\Users\\Vimal\\hermes-projects.json',
    'C:/Users/Vimal/AppData/Local/hermes/skills/devops/',
    '$HOME/AppData/Local/hermes',
    'hermes-scheduled-watchers',
    'hermes-gateway-ops',
    'hermes-instance-customization',
    'skill_view(name="hermes-desktop-plugins")',
    'hermes_tools.core',
  ];
  for (const c of cases) {
    const out = replaceBareWord(replaceBareWord(c, H, 'Toolkit'), h, 'toolkit');
    assert.strictEqual(out, c, `disguised a real identifier: ${c} -> ${out}`);
  }
});

test('the brand is still hidden in prose', () => {
  assert.strictEqual(replaceBareWord('Hermes is the agent.', H, 'Toolkit'),
    'Toolkit is the agent.');
  assert.strictEqual(replaceBareWord('running on hermes right now', h, 'toolkit'),
    'running on toolkit right now');
  // Sentence-final and possessive forms are prose, not identifiers.
  assert.strictEqual(replaceBareWord('It runs on Hermes.', H, 'Toolkit'),
    'It runs on Toolkit.');
  assert.strictEqual(replaceBareWord('(Hermes)', H, 'Toolkit'), '(Toolkit)');
});

test('a version-suffixed brand mention is still an identifier', () => {
  assert.strictEqual(replaceBareWord('hermes-agent v0.18.0', h, 'toolkit'),
    'hermes-agent v0.18.0');
});

// ─── the boundary rule itself ───────────────────────────────────────────────

test('isStructuralContext separates domains from sentence ends', () => {
  // "claude.ai" — dot then alphanumeric — is a domain.
  assert.strictEqual(isStructuralContext('see claude.ai/x', 4, 6), true);
  // "Claude." — dot then space/EOL — ends a sentence.
  assert.strictEqual(isStructuralContext('Ask Claude. Then', 4, 6), false);
  assert.strictEqual(isStructuralContext('Ask Claude.', 4, 6), false);
});

test('isStructuralContext catches every adjacency that forms an identifier', () => {
  for (const [s, start] of [
    ['a/hermes', 2], ['hermes/b', 0], ['a-hermes', 2], ['hermes-b', 0],
    ['a_hermes', 2], ['hermes_b', 0], ['a\\hermes', 2], ['hermes.json', 0],
    ['xhermes', 1], ['hermesx', 0],
  ]) {
    assert.strictEqual(isStructuralContext(s, start, 6), true, `missed: ${s}`);
  }
  for (const [s, start] of [['a hermes b', 2], ['hermes', 0], ['"hermes"', 1]]) {
    assert.strictEqual(isStructuralContext(s, start, 6), false, `false positive: ${s}`);
  }
});

// ─── the reverse direction, same rule ───────────────────────────────────────

const CFG = {
  replacements: [], toolRenames: [], propRenames: [],
  reverseMap: [
    ['Claude Code', 'Hermes Agent'],
    ['.claude-ws/', '.hermes/'],
    ['Claude', 'Hermes', 'word'],
    ['claude', 'hermes', 'word'],
  ],
};

test('reverse pass leaves third-party Claude references intact', () => {
  for (const s of [
    'Add more at claude.ai/settings/usage',
    'the claude-api skill',
    'git clone https://github.com/x/claude-utils',
    'cd /projects/claude-demo',
  ]) {
    assert.strictEqual(reverseMap(s, CFG), s, `corrupted: ${s}`);
  }
});

test('reverse pass still restores identity in prose and structural tokens', () => {
  assert.strictEqual(reverseMap('I am Claude Code', CFG), 'I am Hermes Agent');
  assert.strictEqual(reverseMap('ask Claude about it', CFG), 'ask Hermes about it');
  assert.strictEqual(reverseMap('under .claude-ws/skills', CFG), 'under .hermes/skills');
});

// ─── round trip ─────────────────────────────────────────────────────────────

test('a system prompt round-trips without inventing a dead path', () => {
  const sys = [
    'You are Hermes, an agent.',
    'Project state lives in ~/hermes-projects.json.',
    'Skills are under C:/Users/Vimal/AppData/Local/hermes/skills.',
    '  - hermes-gateway-ops: diagnose the gateway',
  ].join('\n');

  let out = replaceBareWord(sys, H, 'Toolkit');
  out = replaceBareWord(out, h, 'toolkit');

  assert.ok(out.includes('You are Toolkit, an agent.'), 'brand not hidden');
  assert.ok(out.includes('~/hermes-projects.json'), 'state file path disguised');
  assert.ok(out.includes('AppData/Local/hermes/skills'), 'skills dir disguised');
  assert.ok(out.includes('- hermes-gateway-ops:'), 'skill name disguised');
  assert.ok(!/toolkit[-_\/\\]/.test(out), `produced a dead identifier: ${out}`);
});

// ─── through the real pipeline ──────────────────────────────────────────────

function bodyWithSystem(sys) {
  return JSON.stringify({
    model: 'hermes-fable-5',
    system: [{ type: 'text', text: sys }],
    messages: [{ role: 'user', content: 'hi' }],
  });
}

// The sanitize writes into the parsed body, but `mutated` — which gates the
// re-stringify — used to be set only when STRIP_PATTERNS removed something.
// Hermes -> Toolkit is one char LONGER, so on a request with nothing to strip
// the sanitized copy was discarded and the brand leaked through untouched.
test('identity is disguised even when there is nothing to strip', () => {
  const filler = 'Follow the user instructions carefully and cite files. '.repeat(45);
  const out = processBody(bodyWithSystem('You are Hermes, an agent.\n' + filler), loadConfig());
  assert.ok(out.includes('You are Toolkit'), `brand leaked through: ${out.slice(0, 300)}`);
  assert.ok(!/\bHermes\b/.test(out), 'a bare brand mention survived');
});

// The skills trim used to run only inside `if (stripped > 0)`, so a request
// whose system prompt had an <available_skills> index but no STRIP_PATTERNS
// boilerplate kept every removable skill. Two transforms, no dependency.
//
// The coupling was masked in production by an incidental `.trim()` in the same
// loop: any system prompt with a trailing newline made `stripped` 1, which was
// enough to satisfy the gate. So this fixture must have NO leading/trailing
// whitespace and no 3+ newline run, or it silently stops discriminating.
test('unused skills are trimmed even when there is nothing to strip', () => {
  const filler = 'Follow the user instructions carefully and cite files. '.repeat(45);
  const sys = filler + '<available_skills>\n  gaming:\n' +
    '    - pokemon-player: play pokemon\n' +
    '  devops:\n    - hermes-gateway-ops: diagnose the gateway\n' +
    '</available_skills>';
  assert.strictEqual(sys, sys.trim(), 'fixture must not be trimmable');
  assert.ok(!/\n{3,}/.test(sys), 'fixture must not have collapsible newlines');

  const out = processBody(bodyWithSystem(sys), loadConfig());
  assert.ok(!out.includes('pokemon-player'), 'removable skill survived the trim');
  assert.ok(out.includes('hermes-gateway-ops'), 'kept skill was trimmed');
});

test('processBody disguises the brand without inventing dead identifiers', () => {
  const filler = 'Follow the user instructions carefully and cite files. '.repeat(45);
  const sys = 'You are Hermes, an agent.\n' + filler +
    '\nProject state lives in ~/hermes-projects.json.\n' +
    'Skills are under C:/Users/Vimal/AppData/Local/hermes/skills.\n' +
    '<available_skills>\n  devops:\n    - hermes-gateway-ops: diagnose the gateway\n</available_skills>\n';
  const out = processBody(bodyWithSystem(sys), loadConfig());

  assert.ok(out.includes('You are Toolkit'), 'brand not hidden');
  assert.ok(out.includes('hermes-projects.json'), 'state file path disguised');
  assert.ok(/Local[/\\]+hermes[/\\]+skills/.test(out), 'skills dir disguised');
  assert.ok(out.includes('hermes-gateway-ops'), 'skill name disguised');
  assert.ok(/"model":"claude-/.test(out), 'model not remapped');

  const dead = out.match(/toolkit[-_/\\][A-Za-z0-9][\w.-]*|AppData[/\\]+Local[/\\]+toolkit/g);
  assert.strictEqual(dead, null, `dead identifiers reached the model: ${dead}`);
});
