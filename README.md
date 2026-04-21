# pocket-agent

`pocket-agent` is a mobile-friendly web client for running a local coding agent from your phone.

Today it is built around a local machine running Devin for Terminal, with:
- a local HTTP agent
- a phone-friendly web UI
- LAN-only pairing and auth
- thread-per-workspace task management

## What it does

- Pair a phone browser with a machine on your LAN
- Create threads that map to specific workspace folders
- Send prompts to Devin from a mobile UI
- Stream stdout/stderr chunks when available
- Reuse prior context in a thread with `devin --continue -p ...`
- Optionally run tasks as a dedicated runner user

## Current model

- One active thread maps to one workspace folder
- Duplicate active threads for the same workspace are rejected
- Only one queued/running task is allowed per thread at a time
- Tasks are one-shot Devin invocations, not a mirrored terminal session
- Follow-up tasks in a thread reuse prior Devin session context when possible

## Requirements

- Node.js with ESM support
- Devin for Terminal installed and available as `devin`, or configured via `agent/config.json`
- A machine on the same LAN as your phone

## Project structure

- `agent/server.mjs` — local HTTP server, auth, threads, tasks, SSE, persistence
- `agent/config.example.json` — canonical config template
- `web/` — mobile-first UI
- `data/app.sqlite` — app persistence
- `test/security.test.mjs` — security and task-flow tests

## Quick start

1. Copy the config template:

   ```bash
   cp agent/config.example.json agent/config.json
   ```

2. Edit `agent/config.json` for your machine:
   - set `workspaceAllowlist`
   - set `allowedOrigins` if needed
   - set `devinBinary` if `devin` is not on your `PATH`

3. Start the server:

   ```bash
   npm start
   ```

4. On the host machine, open:

   ```text
   http://localhost:8787
   ```

   Use that page to generate a pairing code.

5. On your phone, open the LAN URL shown by the server, for example:

   ```text
   http://192.168.x.x:8787
   ```

6. Enter the pairing code on the phone and start creating threads.

## Development

- Start server:

  ```bash
  npm start
  ```

- Watch mode:

  ```bash
  npm run dev
  ```

- Run tests:

  ```bash
  npm test
  ```

## Configuration

Example:

```json
{
  "host": "0.0.0.0",
  "port": 8787,
  "pairingCodeTtlSeconds": 300,
  "tokenTtlDays": 30,
  "workspaceAllowlist": [
    "/absolute/path/to/allowed/workspace"
  ],
  "allowedOrigins": [
    "http://localhost:8787"
  ],
  "devinBinary": "devin",
  "devinPermissionMode": "normal",
  "sudoBinary": "/usr/bin/sudo",
  "runnerUsers": [],
  "defaultExecutionMode": "direct",
  "defaultRunnerUser": "",
  "rateLimits": {
    "pairStartPerMinute": 10,
    "pairCompletePerMinute": 20,
    "threadCreatePerMinute": 30,
    "taskCreatePerMinute": 60
  }
}
```

### Important fields

- `workspaceAllowlist` — folders the app is allowed to operate in
- `allowedOrigins` — browser origins allowed for state-changing requests
- `devinBinary` — path or command name for Devin for Terminal
- `devinPermissionMode` — passed through to Devin
- `runnerUsers` — allowed usernames for runner-user execution mode

## Pairing and auth

Pairing is intentionally LAN/local-first:

1. `POST /api/pair/start` generates a short-lived code
2. That endpoint is loopback-only
3. The phone submits the code to `POST /api/pair/complete`
4. The server issues a token and sets the `dfi_token` cookie

## Runner-user mode

Threads can run in:
- `direct`
- `runner_user`

Runner-user mode uses:

```text
sudo -n -u <runnerUser> -- <devinBinary> ...
```

This requires:
- the runner username to be listed in `agent/config.json`
- that user to exist on the system
- a narrow passwordless sudo rule for the app user

## Verification

- Syntax check:

  ```bash
  node --check agent/server.mjs && node --check web/app.js
  ```

- Health check:

  ```bash
  curl http://127.0.0.1:8787/health
  ```

- Security check:

  ```bash
  curl -i -X POST http://127.0.0.1:8787/api/threads \
    -H 'Origin: http://evil.example'
  ```

  Expected result: `403` with `origin_not_allowed`

## Current limitations

- This is not a native app
- It does not mirror an interactive terminal session
- Live progress is limited to what Devin emits in one-shot mode
- Pair-code generation must happen on the host machine itself
- The default product flow assumes LAN-only usage

## Status

This repo is currently an MVP with a working local web UI, pairing flow, auth, thread/task model, and basic security hardening.
