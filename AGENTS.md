# Project Notes

## Run
- Start server: `npm start`
- Dev mode: `npm run dev`

## Config
- Copy `agent/config.example.json` to `agent/config.json` to customize host, port, allowlist, origin allowlist, and Devin binary path.
- Pair-code generation endpoint is loopback-only; generate codes from the Mac itself at `http://localhost:8787`.
- iPhone should use the same server over LAN, e.g. `http://<mac-lan-ip>:8787`.

## Verification
- Syntax check: `node --check agent/server.mjs && node --check web/app.js`
- Health check: `curl http://127.0.0.1:8787/health`
- Security check: POST with a bad `Origin` should return `403 origin_not_allowed`.

## Current architecture
- `agent/server.mjs`: local HTTP server, pairing/auth, threads, tasks, SSE, SQLite persistence
- `web/`: mobile-first thread-based UI served by the agent
- `data/app.sqlite`: pairing, token, thread, task, and audit persistence

## Current UX model
- One thread maps to one workspace folder
- Each thread contains a series of Devin tasks/prompts
- Only one queued/running task is allowed per thread at a time
- Each thread can run in either `direct` mode or `runner_user` mode

## Runner-user mode
- Add allowed runner usernames in `agent/config.json` under `runnerUsers`
- Select `runner_user` in the thread creation UI and choose one configured username
- Execution uses `sudo -n -u <runnerUser> -- <devinBinary> ...`
- This requires passwordless sudo for the specific command path on the Mac
- If runner user is not configured or not present on the system, thread creation is rejected

## Suggested setup for a dedicated runner user
1. Create a dedicated non-admin macOS user manually from System Settings or command line
2. Grant that user access only to the intended project directories
3. Add the username to `runnerUsers` in `agent/config.json`
4. Configure a narrow sudoers rule so the app user can run only the Devin binary as that runner user without a password
5. Keep `devinPermissionMode` conservative unless you intentionally need more power
