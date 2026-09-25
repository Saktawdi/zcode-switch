# Z·SWITCH (zcode-switch)

[简体中文](README.md) ｜ **English**

A Tauri 2 desktop tool for one-click switching between multiple ZCode accounts, with live quota display and an embedded local API gateway. Only the login identity changes — projects, sessions, settings and plugins all stay untouched.

![screenshot](docs/screenshot.png)

## Features

- **Save / switch accounts**: one-click login switching; the current login is auto-preserved before any switch — accounts are never lost
- **Add accounts**: OAuth login for new accounts inside the tool (BigModel / z.ai entries), never touching the current login
- **Quota display**: inline plan quota and reset time per account row, multi-plan grouping
- **Claim promotions**: one-click claim for eligible promotions; "Auto claim" toggle (off by default) checks and claims periodically — manual actions take priority
- **Z·GATEWAY local API gateway** (fused from [zcode-api/ZCode Proxy](https://github.com/TriDefender/zcode-api), see below)
- **Encrypted import / export**: `.zsb` bundle, PBKDF2(100k) + AES-256-GCM password encryption
- **Bilingual UI (中文 / English)**: one-click switch in Settings — main window, tray, error messages and CLI output all covered; first run follows your OS language
- **Tray / autostart / CLI automation**

## Z·GATEWAY — Local API Gateway

Enable "API gateway" in Settings and Z·SWITCH serves an OpenAI / Anthropic compatible API on
`127.0.0.1:8317`, using **every account in your store** as an upstream credential pool —
Claude Code, Codex-style clients, Cherry Studio, Cline and friends only need a Base URL change.
The protocol layer is ported from ZCode Proxy.

### What the fusion adds over a single-account proxy

- **Multi-account pool scheduling**: all usable accounts rotate round-robin; 401 / 402 / 429 / 5xx / network errors automatically fail over to the next account with per-failure cooldowns (401 → 5 min, 429 → 30 s, …) so quota is never wasted
- **Per-account device fingerprint**: requests carry each account's own virtual `device_mid` (Z·SWITCH's isolation feature), not one shared identity
- **Zero-config credentials**: saved/logged-in accounts join the pool automatically (coding-plan API key first, start-plan JWT as fallback) — no second login needed

### Endpoints & quick start

| Endpoint | Description |
|----------|-------------|
| `POST /v1/chat/completions` | OpenAI Chat Completions compatible (streaming included, SSE auto-translated both ways) |
| `POST /v1/messages` | Native Anthropic Messages passthrough (Claude Code plugs right in) |
| `GET /v1/models` | GLM model catalog (OpenAI format) |
| `GET /health`, `GET /gw/status` | Health check / pool status |

```bash
# Claude Code
export ANTHROPIC_BASE_URL=http://127.0.0.1:8317
export ANTHROPIC_AUTH_TOKEN=sk-anything   # must match the access key if set; anything works otherwise
export ANTHROPIC_MODEL=glm-5.3

# OpenAI-compatible tools
Base URL: http://127.0.0.1:8317/v1
```

### Protocol compatibility layer (ported from ZCode Proxy)

- Client disguise: full ZCode desktop identity headers (`ZCode/{ver} ai-sdk/anthropic` UA, `X-Platform`, `X-ZCode-Agent`, …) plus trace headers
- **Dynamic endpoint routing**: fetches the official `agent/configs` mapping table and rewrites coding-plan requests to `zcode.z.ai/api/v1/ultra[-zai]` (fail-open)
- **Client Signing V4**: when the coding-plan signing gate is on, performs the Ed25519 handshake + PoW signing automatically (including the 401 VERIFY retry ladder and permanent bypass), always fail-open
- **start-plan system prompt injection**: assembles the official 3-block system shape + currentDate context prefix (the gateway rejects requests without it with 3012)
- **GLM-5.3 reasoning compat**: maps `reasoning_effort` onto `output_config.effort` + paired `thinking.budget_tokens`, dropping sampling params that conflict with thinking
- **Cache & metadata**: re-arranges `cache_control` breakpoints and injects `metadata.user_id` exactly like the real client
- Optional access key (`Authorization` / `x-api-key`, constant-time compare), permissive CORS

The main window shows a gateway status card: run state, endpoint URLs (one-click copy) and pool health (per-account success/failure counters and cooldowns).

> Not ported yet: Responses API (`/v1/responses`), off-peak channel `/async/*`, and the start-plan captcha auto-solver (a 403 challenge cools that account down and the pool moves on).

## Security Design

- **Local first**: all data stays on your machine; no telemetry, no remote storage; quota queries go directly to official endpoints
- **WebView CSP**: the `script-src` baseline is `'self'`; minimal third-party script/image sources are allowed for the official promotion web component. UI events do not rely on dynamic execution — they go through a whitelist-based dispatcher
- **No account loss**: the current login is auto-preserved before switching if not yet saved; file writes go through a temp file + atomic rename
- **Path traversal protection**: account id whitelist (`[A-Za-z0-9-]`); delete/read cannot escape the account store directory
- **Encrypted export**: PBKDF2-HMAC-SHA256 (100k iterations) + AES-256-GCM, random salt/nonce; wrong password simply fails, no plaintext traces
- **Credentials decrypted locally only**: decryption is used solely to display username/email; export files are password-encrypted

## CLI

```
zcode-switch.exe --cli state|list
zcode-switch.exe --cli quota [--id <account-id>]
zcode-switch.exe --cli claim-preview [--id <account-id>]
zcode-switch.exe --cli capture [--name <name>]
zcode-switch.exe --cli switch --id <id> [--force] [--restart|--no-restart] [--hot <bool>|--no-hot]
zcode-switch.exe --cli kill
zcode-switch.exe --cli export --id <id> --out <a.zsb>
zcode-switch.exe --cli export-all --out <all.zsb>
zcode-switch.exe --cli import --file <file.zsb>
zcode-switch.exe --cli rename|delete|update|behavior|setpath|launch
zcode-switch.exe --cli --lang en state              # English output (--lang takes a space-separated value, works anywhere in the command line; defaults to the GUI/system language)
```

CLI password (export / import): prefer the `ZSW_PASSWORD` environment variable (keeps it out of process lists and command history); `--password <password>` also works.

## FAQ

### macOS asks for Microphone / Accessibility / Screen Recording permission?

Deny all of them — nothing breaks.
The embedded pages (such as the login page) are rendered by the system WebView, which relays their requests as system permission prompts attributed to the app; neither the app itself nor its embedded pages use any of these three capabilities.

## Build

```bash
npm install
npm run tauri dev      # development (HMR)
npm run tauri build    # NSIS installer
```

Windows-first (path detection / process management / tray are all Win32 semantics).

## License

[MIT](./LICENSE)
