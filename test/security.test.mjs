import test from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import net from 'node:net';
import { spawn } from 'node:child_process';

const repoRoot = '/Users/mohit/Claude/fun-project/devin-from-iphone';
const serverPath = path.join(repoRoot, 'agent', 'server.mjs');

test('security: rejects disallowed origin for preflight and protected POSTs', async t => {
  const app = await startTestApp(t);

  const preflight = await request(app, '/api/threads', {
    method: 'OPTIONS',
    headers: { Origin: 'http://evil.example', 'Access-Control-Request-Method': 'POST' }
  });
  assert.equal(preflight.status, 403);
  assert.deepEqual(await preflight.json(), { error: 'origin_not_allowed' });

  const paired = await pairDevice(app);
  const create = await request(app, '/api/threads', {
    method: 'POST',
    headers: {
      Authorization: `Bearer ${paired.token}`,
      Origin: 'http://evil.example',
      'Content-Type': 'application/json'
    },
    body: JSON.stringify({ title: 'Blocked', workspace: app.workspaceDir })
  });
  assert.equal(create.status, 403);
  assert.deepEqual(await create.json(), { error: 'origin_not_allowed' });
});

test('security: requires auth for protected endpoints', async t => {
  const app = await startTestApp(t);

  const response = await request(app, '/api/threads');
  assert.equal(response.status, 401);
  assert.deepEqual(await response.json(), { error: 'unauthorized' });
});

test('security: pair completion sets hardened cookie and pair codes are single-use', async t => {
  const app = await startTestApp(t);

  const start = await pairStart(app);
  const first = await pairComplete(app, start.code);
  assert.equal(first.status, 200);
  const firstBody = await first.json();
  assert.match(firstBody.token, /^dfi_[a-f0-9]{48}$/);

  const cookie = first.headers.get('set-cookie') || '';
  assert.match(cookie, /dfi_token=/);
  assert.match(cookie, /HttpOnly/);
  assert.match(cookie, /SameSite=Lax/);
  assert.match(cookie, /Path=\//);

  const second = await pairComplete(app, start.code);
  assert.equal(second.status, 400);
  assert.deepEqual(await second.json(), { error: 'invalid_pair_code' });
});

test('security: revoke-all invalidates existing bearer tokens', async t => {
  const app = await startTestApp(t);
  const paired = await pairDevice(app);

  const revoke = await request(app, '/api/tokens/revoke-all', {
    method: 'POST',
    headers: {
      Authorization: `Bearer ${paired.token}`,
      Origin: app.allowedOrigin
    }
  });
  assert.equal(revoke.status, 200);

  const me = await request(app, '/api/me', {
    headers: {
      Authorization: `Bearer ${paired.token}`,
      Origin: app.allowedOrigin
    }
  });
  assert.equal(me.status, 401);
  assert.deepEqual(await me.json(), { error: 'invalid_token' });
});

test('security: rejects thread workspaces outside the configured allowlist', async t => {
  const app = await startTestApp(t);
  const paired = await pairDevice(app);

  const outsideWorkspace = path.join(os.tmpdir(), `dfi-outside-${Date.now()}`);
  await fs.mkdir(outsideWorkspace, { recursive: true });

  const response = await request(app, '/api/threads', {
    method: 'POST',
    headers: {
      Authorization: `Bearer ${paired.token}`,
      Origin: app.allowedOrigin,
      'Content-Type': 'application/json'
    },
    body: JSON.stringify({ title: 'Outside', workspace: outsideWorkspace })
  });
  assert.equal(response.status, 400);
  assert.deepEqual(await response.json(), { error: 'workspace_required' });
});

test('security: rejects malformed Origin headers on protected endpoints', async t => {
  const app = await startTestApp(t);
  const paired = await pairDevice(app);

  const response = await rawRequest(app, '/api/threads', {
    headers: {
      Authorization: `Bearer ${paired.token}`,
      Origin: 'not-a-valid-origin'
    }
  });
  assert.equal(response.status, 403);
  assert.deepEqual(JSON.parse(response.body), { error: 'origin_not_allowed' });
});

test('security: health endpoint sends defensive browser headers', async t => {
  const app = await startTestApp(t);

  const response = await request(app, '/health');
  assert.equal(response.status, 200);
  assert.equal(response.headers.get('x-frame-options'), 'DENY');
  assert.equal(response.headers.get('x-content-type-options'), 'nosniff');
  assert.equal(response.headers.get('referrer-policy'), 'no-referrer');
  assert.equal(response.headers.get('cross-origin-opener-policy'), 'same-origin');
  assert.equal(response.headers.get('cross-origin-resource-policy'), 'same-origin');
  assert.match(response.headers.get('content-security-policy') || '', /default-src 'self'/);
});

test('security: rejects forged host headers even when Origin matches the forged host', async t => {
  const app = await startTestApp(t);
  const paired = await pairDevice(app);

  const response = await rawRequest(app, '/api/me', {
    headers: {
      Host: `evil.example:${app.port}`,
      Origin: `http://evil.example:${app.port}`,
      Authorization: `Bearer ${paired.token}`
    }
  });
  assert.equal(response.status, 421);
  assert.deepEqual(JSON.parse(response.body), { error: 'invalid_host' });
});

test('security: rejects static app requests with untrusted host headers', async t => {
  const app = await startTestApp(t);

  const response = await rawRequest(app, '/', {
    headers: {
      Host: `evil.example:${app.port}`
    }
  });
  assert.equal(response.status, 421);
  assert.deepEqual(JSON.parse(response.body), { error: 'invalid_host' });
});

test('security: persists paired devices across restart when sqlite is unavailable', async t => {
  const fixture = await createTestFixture();
  t.after(() => cleanupFixture(fixture));

  const firstApp = await launchTestApp(fixture);
  const paired = await pairDevice(firstApp);
  assert.match(paired.token, /^dfi_[a-f0-9]{48}$/);

  await stopTestApp(firstApp);

  const secondApp = await launchTestApp(fixture);
  const health = await request(secondApp, '/health');
  assert.equal(health.status, 200);
  const body = await health.json();
  assert.equal(body.pairedDevices, 1);
});

test('threads: rejects creating a second active thread for the same workspace', async t => {
  const app = await startTestApp(t);
  const paired = await pairDevice(app);

  const first = await createThread(app, paired.token, { title: 'Main', workspace: app.workspaceDir });
  assert.equal(first.status, 201);

  const second = await createThread(app, paired.token, { title: 'Duplicate', workspace: app.workspaceDir });
  assert.equal(second.status, 409);
  assert.deepEqual(await second.json(), { error: 'workspace_already_assigned' });
});

test('tasks: later prompts continue the previous Devin session in the same workspace', async t => {
  const fixture = await createTestFixture({ captureArgs: true });
  const app = await launchTestApp(fixture);
  t.after(() => cleanupFixture(fixture));

  const paired = await pairDevice(app);
  const created = await createThread(app, paired.token, { title: 'Main', workspace: app.workspaceDir });
  assert.equal(created.status, 201);
  const thread = (await created.json()).thread;

  const firstTask = await createTask(app, paired.token, { threadId: thread.id, prompt: 'first prompt' });
  assert.equal(firstTask.status, 202);
  await waitForTaskCount(app, paired.token, 1, 12_000);

  const secondTask = await createTask(app, paired.token, { threadId: thread.id, prompt: 'second prompt' });
  assert.equal(secondTask.status, 202);
  await waitForTaskCount(app, paired.token, 2);

  const invocations = JSON.parse(await fs.readFile(app.invocationsPath, 'utf8'));
  assert.equal(invocations.length, 2);
  assert.deepEqual(invocations[0].args.slice(0, 3), ['--permission-mode', 'dangerous', '-p']);
  assert.equal(invocations[0].args.includes('--continue'), false);
  assert.equal(invocations[1].args.includes('--continue'), true);
  assert.deepEqual(invocations[1].args.slice(0, 4), ['--permission-mode', 'dangerous', '--continue', '-p']);
});

test('tasks: task stream sends output events before done', async t => {
  const fixture = await createTestFixture({ streamOutput: true });
  const app = await launchTestApp(fixture);
  t.after(() => cleanupFixture(fixture));

  const paired = await pairDevice(app);
  const created = await createThread(app, paired.token, { title: 'Stream', workspace: app.workspaceDir });
  assert.equal(created.status, 201);
  const thread = (await created.json()).thread;

  const taskResponse = await createTask(app, paired.token, { threadId: thread.id, prompt: 'stream please' });
  assert.equal(taskResponse.status, 202);
  const taskBody = await taskResponse.json();

  const events = await collectTaskStreamUntilDone(app, paired.token, taskBody.taskId);
  const eventNames = events.map(event => event.event);
  assert.equal(eventNames.includes('output'), true);
  assert.equal(eventNames.at(-1), 'done');
  assert.equal(eventNames.indexOf('output') < eventNames.indexOf('done'), true);
  assert.match(events.filter(event => event.event === 'output').map(event => event.data.chunk).join(''), /chunk-one[\s\S]*chunk-two/);
});

async function startTestApp(t) {
  const fixture = await createTestFixture();
  const app = await launchTestApp(fixture);
  t.after(() => cleanupFixture(fixture));
  return app;
}

async function createTestFixture(options = {}) {
  const tempRoot = await fs.mkdtemp(path.join(os.tmpdir(), 'dfi-security-'));
  const dataDir = path.join(tempRoot, 'data');
  const workspaceDir = path.join(tempRoot, 'workspace');
  const fakeDevinPath = path.join(tempRoot, 'fake-devin.sh');
  const invocationsPath = path.join(tempRoot, 'invocations.json');
  const configPath = path.join(tempRoot, 'config.json');
  const port = await getFreePort();
  const allowedOrigin = `http://127.0.0.1:${port}`;

  await fs.mkdir(dataDir, { recursive: true });
  await fs.mkdir(workspaceDir, { recursive: true });
  if (options.captureArgs) await fs.writeFile(invocationsPath, '[]');

  const fakeScript = options.captureArgs
    ? [
        '#!/bin/sh',
        'set -eu',
        `log_file=${JSON.stringify(invocationsPath)}`,
        'python3 - "$log_file" "$@" <<\'PY\'',
        'import json, sys',
        'path = sys.argv[1]',
        'args = sys.argv[2:]',
        'with open(path, "r", encoding="utf-8") as f:',
        '    data = json.load(f)',
        'data.append({"args": args})',
        'with open(path, "w", encoding="utf-8") as f:',
        '    json.dump(data, f)',
        'PY',
        'printf "fake devin\\n"',
        'exit 0'
      ].join('\n') + '\n'
    : options.streamOutput
      ? [
          '#!/bin/sh',
          'printf "chunk-one\\n"',
          'sleep 1',
          'printf "chunk-two\\n"',
          'exit 0'
        ].join('\n') + '\n'
    : ['#!/bin/sh', 'printf "fake devin\\n"', 'exit 0'].join('\n') + '\n';

  await fs.writeFile(fakeDevinPath, fakeScript, { mode: 0o755 });
  await fs.writeFile(
    configPath,
    JSON.stringify(
      {
        host: '127.0.0.1',
        port,
        pairingCodeTtlSeconds: 300,
        tokenTtlDays: 30,
        workspaceAllowlist: [workspaceDir],
        allowedOrigins: [allowedOrigin],
        devinBinary: fakeDevinPath,
        devinPermissionMode: 'dangerous',
        rateLimits: {
          pairStartPerMinute: 10,
          pairCompletePerMinute: 20,
          threadCreatePerMinute: 30,
          taskCreatePerMinute: 60
        }
      },
      null,
      2
    )
  );

  return { tempRoot, dataDir, workspaceDir, fakeDevinPath, invocationsPath, configPath, port, allowedOrigin };
}

async function launchTestApp(fixture) {
  const child = spawn(process.execPath, [serverPath], {
    cwd: repoRoot,
    env: {
      ...process.env,
      DFI_CONFIG_PATH: fixture.configPath,
      DFI_DATA_DIR: fixture.dataDir
    },
    stdio: ['ignore', 'pipe', 'pipe']
  });

  const logs = [];
  child.stdout.on('data', chunk => logs.push(chunk.toString()));
  child.stderr.on('data', chunk => logs.push(chunk.toString()));

  await waitForServer(`http://127.0.0.1:${fixture.port}/health`, logs, child);
  return { ...fixture, child, logs };
}

async function stopTestApp(app) {
  if (!app.child.killed) app.child.kill('SIGTERM');
  await onceExit(app.child);
}

async function cleanupFixture(fixture) {
  if (fixture.child && fixture.child.exitCode === null && !fixture.child.killed) await stopTestApp(fixture);
  await fs.rm(fixture.tempRoot, { recursive: true, force: true });
}

async function pairDevice(app) {
  const started = await pairStart(app);
  const completed = await pairComplete(app, started.code);
  assert.equal(completed.status, 200);
  return completed.json();
}

async function pairStart(app) {
  const response = await request(app, '/api/pair/start', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ label: 'Security Test' })
  });
  assert.equal(response.status, 200);
  return response.json();
}

function pairComplete(app, code) {
  return request(app, '/api/pair/complete', {
    method: 'POST',
    headers: {
      Origin: app.allowedOrigin,
      'Content-Type': 'application/json'
    },
    body: JSON.stringify({ code, label: 'Security Test' })
  });
}

function request(app, pathname, init = {}) {
  return fetch(`http://127.0.0.1:${app.port}${pathname}`, init);
}

function createThread(app, token, body) {
  return request(app, '/api/threads', {
    method: 'POST',
    headers: {
      Authorization: `Bearer ${token}`,
      Origin: app.allowedOrigin,
      'Content-Type': 'application/json'
    },
    body: JSON.stringify(body)
  });
}

function createTask(app, token, body) {
  return request(app, '/api/tasks', {
    method: 'POST',
    headers: {
      Authorization: `Bearer ${token}`,
      Origin: app.allowedOrigin,
      'Content-Type': 'application/json'
    },
    body: JSON.stringify(body)
  });
}

async function waitForTaskCount(app, token, expected, timeoutMs = 5_000) {
  await waitFor(async () => {
    const response = await request(app, '/api/tasks', {
      headers: {
        Authorization: `Bearer ${token}` ,
        Origin: app.allowedOrigin
      }
    });
    if (response.status !== 200) return false;
    const body = await response.json();
    return body.tasks.filter(task => task.status === 'completed' || task.status === 'failed').length >= expected;
  }, timeoutMs, `tasks to reach count ${expected}`);
}

async function waitFor(check, timeoutMs, label) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    if (await check()) return;
    await new Promise(resolve => setTimeout(resolve, 50));
  }
  throw new Error(`Timed out waiting for ${label}`);
}

async function collectTaskStreamUntilDone(app, token, taskId) {
  const response = await fetch(`http://127.0.0.1:${app.port}/api/tasks/${taskId}/stream`, {
    headers: {
      Authorization: `Bearer ${token}`,
      Origin: app.allowedOrigin
    }
  });
  assert.equal(response.status, 200);
  const reader = response.body.getReader();
  const decoder = new TextDecoder();
  const events = [];
  let buffer = '';

  while (true) {
    const { done, value } = await reader.read();
    if (done) break;
    buffer += decoder.decode(value, { stream: true });
    while (buffer.includes('\n\n')) {
      const index = buffer.indexOf('\n\n');
      const rawEvent = buffer.slice(0, index);
      buffer = buffer.slice(index + 2);
      const event = parseSseEvent(rawEvent);
      if (!event) continue;
      events.push(event);
      if (event.event === 'done') {
        reader.cancel().catch(() => {});
        return events;
      }
    }
  }

  return events;
}

function parseSseEvent(raw) {
  const event = { event: 'message', data: null };
  for (const line of raw.split('\n')) {
    if (line.startsWith('event: ')) event.event = line.slice(7);
    if (line.startsWith('data: ')) event.data = JSON.parse(line.slice(6));
  }
  return event.data ? event : null;
}

function rawRequest(app, pathname, { method = 'GET', headers = {}, body } = {}) {
  return new Promise((resolve, reject) => {
    const req = http.request(
      {
        host: '127.0.0.1',
        port: app.port,
        path: pathname,
        method,
        headers
      },
      res => {
        let raw = '';
        res.setEncoding('utf8');
        res.on('data', chunk => {
          raw += chunk;
        });
        res.on('end', () => {
          resolve({ status: res.statusCode || 0, headers: res.headers, body: raw });
        });
      }
    );
    req.on('error', reject);
    if (body) req.write(body);
    req.end();
  });
}

async function waitForServer(url, logs, child) {
  const deadline = Date.now() + 10_000;
  while (Date.now() < deadline) {
    if (child.exitCode !== null) {
      throw new Error(`Server exited early:\n${logs.join('')}`);
    }
    try {
      const response = await fetch(url);
      if (response.ok) return;
    } catch {
      // Server is still starting.
    }
    await new Promise(resolve => setTimeout(resolve, 100));
  }
  throw new Error(`Timed out waiting for server:\n${logs.join('')}`);
}

function getFreePort() {
  return new Promise((resolve, reject) => {
    const server = net.createServer();
    server.listen(0, '127.0.0.1', () => {
      const address = server.address();
      const port = typeof address === 'object' && address ? address.port : 0;
      server.close(error => {
        if (error) return reject(error);
        resolve(port);
      });
    });
    server.on('error', reject);
  });
}

function onceExit(child) {
  if (child.exitCode !== null) return Promise.resolve();
  return new Promise(resolve => child.once('exit', resolve));
}
