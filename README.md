# Hermes Billing Proxy

Route [Hermes Agent](https://github.com/NousResearch/hermes-agent) (Nous Research) API requests through your Claude Max/Pro subscription instead of Anthropic **Extra Usage** billing.

A zero-dependency Node proxy that sits between Hermes and `api.anthropic.com`, rewriting each request so Anthropic recognizes it as genuine Claude Code traffic and bills it to the subscription. Works on Windows, Linux, and macOS.

- **origin:** [`iso2kx/hermes-billing-proxy`](https://github.com/iso2kx/hermes-billing-proxy)
- **upstream:** [`avaclaw1/hermes-billing-proxy`](https://github.com/avaclaw1/hermes-billing-proxy) → originally forked from [`zacdcook/openclaw-billing-proxy`](https://github.com/zacdcook/openclaw-billing-proxy)

> **Status:** v2.2.x. As of June 2026 Anthropic gates subscription billing on a **native attestation hash (`cch`)** in addition to the older tool-set / template fingerprints. The proxy reproduces all of them — see [How detection works](#how-detection-works).

---

## How it works

The proxy performs bidirectional, byte-careful request/response surgery. Outbound (request → Anthropic):

1. **Model-id remap** — `hermes-*` → `claude-*` (raw-string, runs first and unconditionally so a thinking block in the body can't skip it).
2. **Orphaned tool-pair repair** — drops `tool_use`/`tool_result` blocks with no matching partner (prevents 400s on truncated/resumed sessions).
3. **Billing header** — injects `x-anthropic-billing-header: cc_version=<ver>.<fp>; cc_entrypoint=cli; cch=00000;` as a system block, where `<fp>` is a 3-char SHA256 fingerprint over the first user message (`utils/fingerprint.ts` parity).
4. **String sanitization** — paraphrases framework trigger phrases (`Hermes Agent`→`Claude Code`, `Nous Research`→`Anthropic`, Telegram/Discord platform hints, doc-domain leaks, etc.).
5. **Tool-set fingerprint bypass** — renames **every** Hermes tool to either a native Claude Code tool (`terminal`→`Bash`, `read_file`→`Read`, `write_file`→`Write`, `patch`→`Edit`, `delegate_task`→`Task`, `todo`→`TodoWrite`, `process`→`BashOutput`) or a genuine `mcp__<server>__<tool>` name. 1:1 reversible.
6. **Property renames** — `session_id`→`thread_id`, `agent_id`→`worker_id`, etc.
7. **CC tool stubs** — injects a few native CC tool schemas (Glob/Grep/Agent/…) so the tool set reads as "Claude Code + a few MCP servers".
8. **System-prompt template strip** — JSON-aware pass that paraphrases/strips Hermes boilerplate in system blocks >2000 chars (memory guidance, skills XML, CLI footer) and prunes unused skills/categories from `<available_skills>`.
9. **Trailing assistant prefill strip** — pops trailing `assistant` messages so the body ends on a `user` turn (Opus 4.6+ rejects prefill).
10. **Effort strip for Haiku** — removes the `effort` param Haiku 400s on (Opus/Sonnet keep it).
11. **Stainless SDK + identity headers** — full `claude-cli/<ver>`, `x-app: cli`, `x-stainless-*` header set.
12. **Model-aware beta flags** — auto-extracted from the installed CC binary; Haiku drops `interleaved-thinking`/`effort`/`fast-mode`; `context-1m` is never sent on OAuth.
13. **`cch` attestation** — after all transforms, computes `xxHash64(full body with the `cch=00000` placeholder) & 0xFFFFF` and writes the 5-hex result back in place. This is the signal Anthropic uses to confirm genuine Claude Code; without it, traffic falls to extra usage.

Inbound (Anthropic → Hermes):

14. **Full reverse mapping** — restores every tool name, property, and identity string in both **SSE streaming** and **JSON** responses. Thinking blocks pass through byte-identical; tool-call arguments use a "tool-arg-safe" reverse map so identity swaps don't corrupt model-generated paths/commands.
15. **Path normalization** — `/chat/completions` → `/v1/chat/completions` for Hermes's OpenAI-mode client (no-op for `/v1/messages`).

CC version is auto-detected from `claude --version` (falls back to a pinned default), so the emulated identity tracks whatever Claude Code you actually have installed.

---

## Requirements

- **Node.js 18+**
- A **Claude Max or Pro** subscription, with the **Claude Code CLI authenticated** — i.e. `~/.claude/.credentials.json` exists and contains a valid `claudeAiOauth` token.
- Hermes Agent installed, with the `anthropic` Python package available in its venv (required for `api_mode: anthropic_messages`).

## Quick start

```bash
git clone https://github.com/iso2kx/hermes-billing-proxy.git
cd hermes-billing-proxy
node proxy.js
```

The proxy binds `127.0.0.1:18802` by default. Verify:

```bash
curl http://127.0.0.1:18802/health
```

A healthy response shows `"status":"ok"` and `"subscriptionBilling":"ok"`. Run the tests with `node --test`.

---

## Hermes configuration

Point Hermes at the proxy in `config.yaml` (`%LOCALAPPDATA%\hermes\config.yaml` on Windows, `~/.hermes/config.yaml` elsewhere).

> ⚠️ **This is the part people get wrong.** Use the built-in `anthropic` provider with `api_mode: anthropic_messages`, and keep the top-level `providers:` map **empty**. Do **not** define a custom provider named `anthropic` and do **not** use `provider: custom` (see gotchas).

```yaml
model:
  provider: anthropic            # built-in provider; auto-selects anthropic_messages
  api_mode: anthropic_messages   # makes Hermes speak /v1/messages, not /chat/completions
  base_url: http://127.0.0.1:18802
  api_key: no-key-required       # allowlisted sentinel; the proxy supplies real OAuth
  default: claude-opus-4-8       # or claude-opus-4-7, claude-sonnet-4-6, claude-haiku-4-5

providers: {}                    # MUST be empty — see gotcha #1
fallback_providers: []           # fallbacks would bypass the proxy

prompt_caching:
  enabled: true                  # fewer reprocessed tokens = more stable fingerprint
streaming:
  enabled: true                  # the proxy handles SSE
```

Restart the gateway after any config change (`python hermes_cli/main.py gateway run --replace`). To test config parsing without a full gateway, a one-shot read is `python hermes_cli/main.py -z "hi"`.

### Gotchas

1. **`providers: { anthropic: {...} }` collides.** Defining a *custom* provider named `anthropic` makes Hermes rewrite the provider to `anthropic:anthropic` → **"Unknown provider"**. Keep `providers: {}` empty; the built-in `anthropic` provider already reads `model.base_url` and pulls real Claude Code OAuth from the credential pool.
2. **Avoid `provider: custom`.** After recent Hermes updates it no longer honors `model.api_mode` (resolves to `chat_completions` → `/chat/completions` → 400 `tools.0.type` against the proxy's Anthropic stubs) **and** fails the credential check ("No usable credentials for custom") unless `api_key` is exactly the `no-key-required` sentinel. Prefer `provider: anthropic`.
3. **`anthropic` package must be installed** in the Hermes venv, or `anthropic_messages` mode won't load.
4. **Control test:** the genuine `claude` CLI billing the same way is the baseline — if it bills to subscription and Hermes doesn't, the proxy disguise is the variable.

### Delegation / subagents

Subagents inherit the main provider config and route through the proxy automatically. Only add a `delegation:` provider block if you've overridden it — and if so, point it at the proxy too.

### Auxiliary models (compression, vision, title-gen, …)

Auxiliary slots set to `provider: auto` resolve to the main config and route through the proxy (so they also bill to the subscription). That's fine, but it spends subscription rate-limit on trivial work (e.g. title generation on Opus). If you have a cheaper provider, point those slots at it directly to bypass the proxy.

---

## Proxy configuration

Create a `config.json` next to `proxy.js` (all keys optional — see `config.example.json`):

```json
{
  "port": 18802,
  "refreshEnabled": true,
  "refreshThresholdMinutes": 2,
  "refreshRetrySeconds": 15
}
```

| Key | Default | Purpose |
|-----|---------|---------|
| `port` | `18802` | Listen port |
| `credentialsPath` | auto | Override path to `.credentials.json` |
| `refreshEnabled` | `true` | Auto-refresh the OAuth token before expiry |
| `refreshThresholdMinutes` | `2` | Refresh when the token has less than this remaining |
| `refreshRetrySeconds` | `15` | Base retry delay (exponential backoff, capped 10m, gives up after 20) |
| `mergeDefaults` | `true` | Merge config pattern arrays over built-in defaults (set `false` for full manual control) |
| `replacements` / `reverseMap` / `toolRenames` / `propRenames` | — | Extra rewrite pairs, merged with defaults |
| `computeRealCch` | `true` | Compute the real `cch` attestation hash (the subscription-billing signal) |
| `repairOrphanedTools` | `true` | Strip orphaned `tool_use`/`tool_result` pairs |
| `stripTrailingAssistantPrefill` | `true` | Pop trailing assistant prefill messages |
| `stripEffortForHaiku` | `true` | Remove `effort` for Haiku models |
| `injectCCStubs` | `true` | Inject native CC tool stubs |
| `maskToolUseInputs` | `false` | Mask tool-call args on the request side (leaks `.hermes/` markers — usually leave off) |

### Environment variables

| Var | Effect |
|-----|--------|
| `PROXY_PORT` / `PROXY_HOST` | Override port / bind address (default `127.0.0.1`) |
| `OAUTH_TOKEN` | Supply the token directly (Docker/headless) instead of reading the creds file |
| `CC_VERSION` | Pin the emulated Claude Code version instead of auto-detecting from `claude --version` |
| `CCH_SEED` | Override the xxHash64 seed for `cch` (accepts `0x`-hex or decimal) if a CC update ever changes it |
| `REQUIRED_BETAS` | Comma-separated override for the `anthropic-beta` set (otherwise auto-extracted from the CC binary, cached in `.betas_cache.json`) |
| `DEBUG_DUMPS=1` | Dump the processed system prompt and any extra-usage-rejected bodies to disk for debugging |

### Token refresh

When the OAuth token is within `refreshThresholdMinutes` of expiry, the proxy runs `claude -p "ping" --max-turns 1 --no-session-persistence` to make the CLI rewrite the credential store, re-reads the refreshed token, and retries with exponential backoff. No cron job needed.

---

## Endpoints

| Endpoint | Method | Purpose |
|----------|--------|---------|
| `/health` | GET | Proxy + billing health (see below) |
| `/v1/models`, `/models` | GET | Advertises `claude-*` model ids with context-window sizes |
| everything else | * | Proxied to `api.anthropic.com` with full transform |

`/health` reports the one otherwise-silent failure mode — when Anthropic rejects the disguise and bills to extra usage:

```json
{
  "status": "ok",
  "version": "2.2.3",
  "subscriptionBilling": "ok",        // flips to "extra-usage" if cch is rejected
  "extraUsageHits": 0,
  "lastExtraUsageAt": null,
  "ccVersion": "2.1.186",
  "tokenExpiresInHours": "7.4",
  "subscriptionType": "max",
  "requestsServed": 142,
  "uptime": "3600s",
  "layers": { "stringReplacements": 38, "toolNameRenames": 49, "propertyRenames": 8, "ccToolStubs": 5 }
}
```

---

## Running as a background service

### Windows (primary)

Run detached so it survives terminal close:

```powershell
Start-Process node -ArgumentList "proxy.js" -WorkingDirectory "D:\Personal Stuff\Code\hermes-billing-proxy" -WindowStyle Hidden
```

Or with [pm2](https://pm2.keymetrics.io/) for auto-restart/boot-start: `pm2 start proxy.js --name hermes-proxy && pm2 save`. Or register a Task Scheduler task with trigger "At log on" running `node proxy.js`.

**Restart the proxy after editing `proxy.js`** (kill the node process and relaunch).

### Linux (systemd user service)

```bash
mkdir -p ~/.config/systemd/user
cat > ~/.config/systemd/user/hermes-proxy.service << 'EOF'
[Unit]
Description=Hermes Billing Proxy
After=network.target
[Service]
ExecStart=/usr/bin/node /path/to/proxy.js
Restart=always
RestartSec=5
[Install]
WantedBy=default.target
EOF
systemctl --user daemon-reload && systemctl --user enable --now hermes-proxy.service
```

---

## How detection works

Anthropic grants subscription billing only to traffic that looks like genuine Claude Code. As of June 2026 the binding signals are:

1. **`cch` attestation** — a native (Bun/Zig) hash Claude Code writes over the serialized body. **This is the primary gate now.** The proxy reproduces it (`xxHash64`, seed `0x6E52736AC806831E`, masked to 5 hex), self-tested against canonical vectors so it degrades rather than sending a corrupt hash. Miss it → extra usage.
2. **Tool-set fingerprint** — the *combination* of tool names must match real Claude Code (native tools + `mcp__server__tool`). The proxy disguises every Hermes tool accordingly. This is structural — broad brand-string scrubbing does **not** defeat it (and breaks tool execution), so the proxy is surgical.
3. **Model id** — must be a real `claude-*` id; `hermes-*` 404s.
4. **Billing header + fingerprint**, **Stainless/identity headers**, and **system-prompt template** matching round out the composite score.

If billing falls to extra usage, `/health` flips `subscriptionBilling` to `extra-usage`, and the proxy logs a warning naming the likely cause (often a stale `cch` seed after a CC update — override with `CCH_SEED`). Run with `DEBUG_DUMPS=1` to capture the rejected body.

---

## Troubleshooting

**`subscriptionBilling: extra-usage` / 400 "extra usage"** — the disguise was rejected.
- Token expired → check `/health` `tokenExpiresInHours`; re-auth the Claude Code CLI.
- CC updated and changed the `cch` seed → set `CCH_SEED`. Compare against upstream for a known-good seed.
- Very short conversations (<20KB) have few signals; usually resolves after a few turns.

**Proxy won't start** — port 18802 in use (`netstat -ano | findstr 18802` on Windows / `lsof -i :18802` elsewhere), Node <18, or no `~/.claude/.credentials.json` (authenticate the Claude Code CLI, or set `OAUTH_TOKEN`).

**Hermes can't connect** — verify `model.base_url` matches the proxy, the proxy is up (`curl .../health`), and you're using `127.0.0.1` (not `localhost`).

**"Unknown provider" / 400 `tools.0.type` / "No usable credentials"** — Hermes config issue, not the proxy. Re-check the [gotchas](#gotchas): empty `providers: {}`, `provider: anthropic` (not `custom`), `api_mode: anthropic_messages`, `api_key: no-key-required`.

**404 on every reasoning request** — a `hermes-*` model id reached Anthropic. Should be fixed by the unconditional remap; confirm you're on a current proxy build.

---

## License

MIT
