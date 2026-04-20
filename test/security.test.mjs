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

async function startTestApp(t) {
  const tempRoot = await fs.mkdtemp(path.join(os.tmpdir(), 'dfi-security-'));
  const dataDir = path.join(tempRoot, 'data');
  const workspaceDir = path.join(tempRoot, 'workspace');
  const fakeDevinPath = path.join(tempRoot, 'fake-devin.sh');
  const configPath = path.join(tempRoot, 'config.json');
  const port = await getFreePort();
  const allowedOrigin = `http://127.0.0.1:${port}`;

  await fs.mkdir(dataDir, { recursive: true });
  await fs.mkdir(workspaceDir, { recursive: true });
  await fs.writeFile(
    fakeDevinPath,
    '#!/bin/sh\n' +
      'printf "fake devin\\n"\n' +
      'exit 0\n',
    { mode: 0o755 }
  );
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

  const child = spawn(process.execPath, [serverPath], {
    cwd: repoRoot,
    env: {
      ...process.env,
      DFI_CONFIG_PATH: configPath,
      DFI_DATA_DIR: dataDir
    },
    stdio: ['ignore', 'pipe', 'pipe']
  });

  const logs = [];
  child.stdout.on('data', chunk => logs.push(chunk.toString()));
  child.stderr.on('data', chunk => logs.push(chunk.toString()));

  t.after(async () => {
    if (!child.killed) child.kill('SIGTERM');
    await onceExit(child);
    await fs.rm(tempRoot, { recursive: true, force: true });
  });

  await waitForServer(`http://127.0.0.1:${port}/health`, logs, child);
  return { port, workspaceDir, allowedOrigin };
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
