import http from 'node:http';
import fs from 'node:fs';
import fsp from 'node:fs/promises';
import path from 'node:path';
import crypto from 'node:crypto';
import { spawn, spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import os from 'node:os';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const rootDir = path.resolve(__dirname, '..');
const webDir = path.join(rootDir, 'web');
const dataDir = process.env.DFI_DATA_DIR ? path.resolve(process.env.DFI_DATA_DIR) : path.join(rootDir, 'data');
const dbPath = path.join(dataDir, 'app.sqlite');
const configPath = process.env.DFI_CONFIG_PATH ? path.resolve(process.env.DFI_CONFIG_PATH) : path.join(rootDir, 'agent', 'config.json');
const exampleConfigPath = path.join(rootDir, 'agent', 'config.example.json');

await fsp.mkdir(dataDir, { recursive: true });
const config = await loadConfig();
const trustedOrigins = buildTrustedOrigins(config);
const trustedHosts = buildTrustedHosts(trustedOrigins);
let db;

const taskStreams = new Map();
const taskProcesses = new Map();
const rateLimits = new Map();

const server = http.createServer(async (req, res) => {
  try {
    setSecurityHeaders(res);
    await route(req, res);
  } catch (error) {
    console.error(error);
    sendJson(res, 500, { error: 'internal_error', message: error.message });
  }
});

server.listen(config.port, config.host, () => {
  const urls = getStartupUrls(config.host, config.port);
  console.log('pocket-agent is running:');
  for (const url of urls) console.log(`  ${url}`);
  console.log('Open localhost on your host machine to generate a pair code, then open a LAN URL on your phone.');
  if (config.runnerUsers.length) console.log(`Configured runner users: ${config.runnerUsers.join(', ')}`);
});

function getStartupUrls(host, port) {
  const urls = new Set();
  if (host === '0.0.0.0' || host === '::') {
    urls.add(`http://localhost:${port}`);
    urls.add(`http://127.0.0.1:${port}`);
    for (const address of getLanAddresses()) urls.add(`http://${address}:${port}`);
  } else {
    urls.add(`http://${host}:${port}`);
    if (host === '127.0.0.1' || host === 'localhost') urls.add(`http://localhost:${port}`);
  }
  return [...urls];
}

function getLanAddresses() {
  const interfaces = os.networkInterfaces();
  const addresses = [];
  for (const entries of Object.values(interfaces)) {
    for (const entry of entries || []) {
      if (!entry || entry.internal) continue;
      if (entry.family !== 'IPv4') continue;
      addresses.push(entry.address);
    }
  }
  return addresses.sort();
}

async function loadConfig() {
  const configSource = fs.existsSync(configPath) ? configPath : exampleConfigPath;
  const parsed = JSON.parse(await fsp.readFile(configSource, 'utf8'));
  return {
    host: parsed.host ?? '0.0.0.0',
    port: parsed.port ?? 8787,
    pairingCodeTtlSeconds: parsed.pairingCodeTtlSeconds ?? 300,
    tokenTtlDays: parsed.tokenTtlDays ?? 30,
    workspaceAllowlist: (parsed.workspaceAllowlist ?? [rootDir]).map(value => path.resolve(value)),
    allowedOrigins: parsed.allowedOrigins ?? [`http://localhost:${parsed.port ?? 8787}`],
    devinBinary: parsed.devinBinary ?? 'devin',
    devinPermissionMode: parsed.devinPermissionMode ?? 'normal',
    sudoBinary: parsed.sudoBinary ?? '/usr/bin/sudo',
    runnerUsers: (parsed.runnerUsers ?? []).filter(isValidUsername),
    defaultExecutionMode: parsed.defaultExecutionMode === 'runner_user' ? 'runner_user' : 'direct',
    defaultRunnerUser: isValidUsername(parsed.defaultRunnerUser ?? '') ? parsed.defaultRunnerUser : '',
    rateLimits: {
      pairStartPerMinute: parsed.rateLimits?.pairStartPerMinute ?? 10,
      pairCompletePerMinute: parsed.rateLimits?.pairCompletePerMinute ?? 20,
      threadCreatePerMinute: parsed.rateLimits?.threadCreatePerMinute ?? 30,
      taskCreatePerMinute: parsed.rateLimits?.taskCreatePerMinute ?? 60
    }
  };
}

async function createDatabase(filePath) {
  try {
    const sqlite = await import('node:sqlite');
    return new sqlite.DatabaseSync(filePath);
  } catch {
    return new JsonDatabase(filePath);
  }
}

class JsonDatabase {
  constructor(filePath) {
    this.filePath = filePath;
    this.state = this.load();
  }

  load() {
    if (fs.existsSync(this.filePath)) {
      try {
        return JSON.parse(fs.readFileSync(this.filePath, 'utf8'));
      } catch {
        // Fall back to a clean state if an older file is unreadable.
      }
    }
    return {
      _schema: {
        pair_codes: ['code', 'created_at', 'expires_at', 'consumed_at', 'label', 'created_ip'],
        tokens: ['id', 'token_hash', 'label', 'created_at', 'expires_at', 'revoked_at', 'scope', 'created_ip', 'last_seen_at', 'last_seen_ip'],
        threads: ['id', 'title', 'workspace', 'execution_mode', 'runner_user', 'created_at', 'updated_at', 'archived_at', 'last_task_status'],
        tasks: ['id', 'thread_id', 'prompt', 'workspace', 'status', 'created_at', 'started_at', 'completed_at', 'exit_code', 'output', 'error'],
        audit_logs: ['id', 'event_type', 'created_at', 'detail_json']
      },
      pair_codes: [],
      tokens: [],
      threads: [],
      tasks: [],
      audit_logs: []
    };
  }

  save() {
    fs.writeFileSync(this.filePath, JSON.stringify(this.state, null, 2));
  }

  exec(sql) {
    const normalized = normalizeSql(sql);
    const alterMatch = normalized.match(/^ALTER TABLE (\w+) ADD COLUMN (\w+) (.+)$/);
    if (alterMatch) {
      const [, table, column] = alterMatch;
      const columns = this.state._schema[table] || (this.state._schema[table] = []);
      if (!columns.includes(column)) columns.push(column);
      if (!this.state[table]) this.state[table] = [];
      for (const row of this.state[table]) {
        if (!(column in row)) row[column] = defaultValueForColumn(table, column);
      }
      this.save();
    }
  }

  prepare(sql) {
    return new JsonStatement(this, normalizeSql(sql));
  }
}

class JsonStatement {
  constructor(db, sql) {
    this.db = db;
    this.sql = sql;
  }

  all(...args) {
    const state = this.db.state;
    if (this.sql.startsWith('PRAGMA table_info(')) {
      const table = this.sql.slice('PRAGMA table_info('.length, -1);
      return (state._schema[table] || []).map((name, index) => ({ cid: index, name }));
    }
    if (this.sql === 'SELECT id, thread_id, prompt, workspace, status, created_at, started_at, completed_at, exit_code FROM tasks ORDER BY created_at DESC LIMIT 100') {
      return [...state.tasks]
        .sort((a, b) => compareDesc(a.created_at, b.created_at))
        .slice(0, 100)
        .map(task => pick(task, ['id', 'thread_id', 'prompt', 'workspace', 'status', 'created_at', 'started_at', 'completed_at', 'exit_code']));
    }
    if (this.sql === 'SELECT id, thread_id, prompt, workspace, status, created_at, started_at, completed_at, exit_code, output, error FROM tasks WHERE thread_id = ? ORDER BY created_at ASC') {
      return state.tasks
        .filter(task => task.thread_id === args[0])
        .sort((a, b) => compareAsc(a.created_at, b.created_at))
        .map(task => pick(task, ['id', 'thread_id', 'prompt', 'workspace', 'status', 'created_at', 'started_at', 'completed_at', 'exit_code', 'output', 'error']));
    }
    if (this.sql.startsWith('SELECT t.id, t.title, t.workspace, t.execution_mode')) {
      return state.threads
        .filter(thread => !thread.archived_at)
        .map(thread => {
          const tasks = state.tasks.filter(task => task.thread_id === thread.id).sort((a, b) => compareDesc(a.created_at, b.created_at));
          return {
            id: thread.id,
            title: thread.title,
            workspace: thread.workspace,
            execution_mode: thread.execution_mode,
            runner_user: thread.runner_user,
            created_at: thread.created_at,
            updated_at: thread.updated_at,
            last_task_status: thread.last_task_status,
            last_prompt: tasks[0]?.prompt ?? null,
            last_task_at: tasks[0]?.created_at ?? null,
            task_count: tasks.length
          };
        })
        .sort((a, b) => compareDesc(a.last_task_at || a.updated_at, b.last_task_at || b.updated_at));
    }
    throw new Error(`Unsupported query: ${this.sql}`);
  }

  get(...args) {
    const state = this.db.state;
    if (this.sql === 'SELECT COUNT(*) AS count FROM tokens WHERE revoked_at IS NULL AND expires_at > ?') {
      return { count: state.tokens.filter(token => !token.revoked_at && token.expires_at > args[0]).length };
    }
    if (this.sql === 'SELECT COUNT(*) AS count FROM threads WHERE archived_at IS NULL') {
      return { count: state.threads.filter(thread => !thread.archived_at).length };
    }
    if (this.sql === 'SELECT COUNT(*) AS count FROM tasks') return { count: state.tasks.length };
    if (this.sql === 'SELECT * FROM tasks WHERE id = ?') return clone(state.tasks.find(task => task.id === args[0]) || null);
    if (this.sql === 'SELECT id, label, created_at, expires_at, revoked_at, scope FROM tokens WHERE token_hash = ?') {
      const token = state.tokens.find(item => item.token_hash === args[0]);
      return token ? pick(token, ['id', 'label', 'created_at', 'expires_at', 'revoked_at', 'scope']) : null;
    }
    if (this.sql === 'SELECT * FROM pair_codes WHERE code = ?') return clone(state.pair_codes.find(code => code.code === args[0]) || null);
    if (this.sql === 'SELECT * FROM threads WHERE id = ? AND archived_at IS NULL') {
      return clone(state.threads.find(thread => thread.id === args[0] && !thread.archived_at) || null);
    }
    if (this.sql === "SELECT COUNT(*) AS count FROM tasks WHERE thread_id = ? AND status IN ('queued','running')") {
      return { count: state.tasks.filter(task => task.thread_id === args[0] && (task.status === 'queued' || task.status === 'running')).length };
    }
    throw new Error(`Unsupported query: ${this.sql}`);
  }

  run(...args) {
    const state = this.db.state;
    if (this.sql === 'UPDATE tokens SET revoked_at = ? WHERE revoked_at IS NULL') {
      for (const token of state.tokens) if (!token.revoked_at) token.revoked_at = args[0];
      return this.commit();
    }
    if (this.sql === 'UPDATE tokens SET last_seen_at = ?, last_seen_ip = ? WHERE id = ?') {
      const token = state.tokens.find(item => item.id === args[2]);
      if (token) [token.last_seen_at, token.last_seen_ip] = [args[0], args[1]];
      return this.commit();
    }
    if (this.sql === 'INSERT INTO pair_codes (code, created_at, expires_at, label, created_ip) VALUES (?, ?, ?, ?, ?)') {
      state.pair_codes.push({ code: args[0], created_at: args[1], expires_at: args[2], consumed_at: null, label: args[3], created_ip: args[4] });
      return this.commit();
    }
    if (this.sql === 'UPDATE pair_codes SET consumed_at = ? WHERE code = ?') {
      const row = state.pair_codes.find(item => item.code === args[1]);
      if (row) row.consumed_at = args[0];
      return this.commit();
    }
    if (this.sql === 'INSERT INTO tokens (id, token_hash, label, created_at, expires_at, scope, created_ip, last_seen_at, last_seen_ip) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)') {
      state.tokens.push({ id: args[0], token_hash: args[1], label: args[2], created_at: args[3], expires_at: args[4], revoked_at: null, scope: args[5], created_ip: args[6], last_seen_at: args[7], last_seen_ip: args[8] });
      return this.commit();
    }
    if (this.sql === 'INSERT INTO threads (id, title, workspace, execution_mode, runner_user, created_at, updated_at, last_task_status) VALUES (?, ?, ?, ?, ?, ?, ?, ?)') {
      state.threads.push({ id: args[0], title: args[1], workspace: args[2], execution_mode: args[3], runner_user: args[4], created_at: args[5], updated_at: args[6], archived_at: null, last_task_status: args[7] });
      return this.commit();
    }
    if (this.sql === 'UPDATE threads SET title = ?, workspace = ?, execution_mode = ?, runner_user = ?, updated_at = ? WHERE id = ?') {
      const thread = state.threads.find(item => item.id === args[5]);
      if (thread) [thread.title, thread.workspace, thread.execution_mode, thread.runner_user, thread.updated_at] = [args[0], args[1], args[2], args[3], args[4]];
      return this.commit();
    }
    if (this.sql === 'INSERT INTO tasks (id, thread_id, prompt, workspace, status, created_at) VALUES (?, ?, ?, ?, ?, ?)') {
      state.tasks.push({ id: args[0], thread_id: args[1], prompt: args[2], workspace: args[3], status: args[4], created_at: args[5], started_at: null, completed_at: null, exit_code: null, output: '', error: '' });
      return this.commit();
    }
    if (this.sql === 'UPDATE threads SET updated_at = ?, last_task_status = ? WHERE id = ?') {
      const thread = state.threads.find(item => item.id === args[2]);
      if (thread) [thread.updated_at, thread.last_task_status] = [args[0], args[1]];
      return this.commit();
    }
    if (this.sql === 'UPDATE tasks SET status = ?, started_at = ? WHERE id = ?') {
      const task = state.tasks.find(item => item.id === args[2]);
      if (task) [task.status, task.started_at] = [args[0], args[1]];
      return this.commit();
    }
    if (this.sql === 'UPDATE tasks SET status = ?, completed_at = ?, exit_code = ? WHERE id = ?') {
      const task = state.tasks.find(item => item.id === args[3]);
      if (task) [task.status, task.completed_at, task.exit_code] = [args[0], args[1], args[2]];
      return this.commit();
    }
    if (this.sql === 'INSERT INTO audit_logs (id, event_type, created_at, detail_json) VALUES (?, ?, ?, ?)') {
      state.audit_logs.push({ id: args[0], event_type: args[1], created_at: args[2], detail_json: args[3] });
      return this.commit();
    }
    const appendMatch = this.sql.match(/^UPDATE tasks SET (output|error) = \1 \|\| \? WHERE id = \?$/);
    if (appendMatch) {
      const task = state.tasks.find(item => item.id === args[1]);
      if (task) task[appendMatch[1]] = `${task[appendMatch[1]] || ''}${args[0]}`;
      return this.commit();
    }
    throw new Error(`Unsupported query: ${this.sql}`);
  }

  commit() {
    this.db.save();
    return { changes: 1 };
  }
}

function normalizeSql(sql) {
  return sql.replace(/\s+/g, ' ').trim();
}

function defaultValueForColumn(table, column) {
  if (table === 'tokens' && column === 'scope') return 'lan';
  if (table === 'threads' && column === 'execution_mode') return 'direct';
  if (table === 'tasks' && (column === 'output' || column === 'error')) return '';
  return null;
}

function pick(row, keys) {
  return Object.fromEntries(keys.map(key => [key, row[key] ?? null]));
}

function clone(value) {
  return value ? JSON.parse(JSON.stringify(value)) : value;
}

function compareAsc(left, right) {
  return String(left || '').localeCompare(String(right || ''));
}

function compareDesc(left, right) {
  return compareAsc(right, left);
}

db = await createDatabase(dbPath);
initDb(db);

function initDb(db) {
  db.exec(`
    CREATE TABLE IF NOT EXISTS pair_codes (
      code TEXT PRIMARY KEY,
      created_at TEXT NOT NULL,
      expires_at TEXT NOT NULL,
      consumed_at TEXT,
      label TEXT,
      created_ip TEXT NOT NULL DEFAULT ''
    );
    CREATE TABLE IF NOT EXISTS tokens (
      id TEXT PRIMARY KEY,
      token_hash TEXT NOT NULL UNIQUE,
      label TEXT,
      created_at TEXT NOT NULL,
      expires_at TEXT NOT NULL,
      revoked_at TEXT,
      scope TEXT NOT NULL DEFAULT 'lan',
      created_ip TEXT NOT NULL DEFAULT '',
      last_seen_at TEXT,
      last_seen_ip TEXT
    );
    CREATE TABLE IF NOT EXISTS threads (
      id TEXT PRIMARY KEY,
      title TEXT NOT NULL,
      workspace TEXT NOT NULL,
      execution_mode TEXT NOT NULL DEFAULT 'direct',
      runner_user TEXT,
      created_at TEXT NOT NULL,
      updated_at TEXT NOT NULL,
      archived_at TEXT,
      last_task_status TEXT
    );
    CREATE TABLE IF NOT EXISTS tasks (
      id TEXT PRIMARY KEY,
      thread_id TEXT,
      prompt TEXT NOT NULL,
      workspace TEXT NOT NULL,
      status TEXT NOT NULL,
      created_at TEXT NOT NULL,
      started_at TEXT,
      completed_at TEXT,
      exit_code INTEGER,
      output TEXT NOT NULL DEFAULT '',
      error TEXT NOT NULL DEFAULT ''
    );
    CREATE TABLE IF NOT EXISTS audit_logs (
      id TEXT PRIMARY KEY,
      event_type TEXT NOT NULL,
      created_at TEXT NOT NULL,
      detail_json TEXT NOT NULL
    );
  `);
  ensureColumn('pair_codes', 'created_ip', "TEXT NOT NULL DEFAULT ''");
  ensureColumn('tokens', 'scope', "TEXT NOT NULL DEFAULT 'lan'");
  ensureColumn('tokens', 'created_ip', "TEXT NOT NULL DEFAULT ''");
  ensureColumn('tokens', 'last_seen_at', 'TEXT');
  ensureColumn('tokens', 'last_seen_ip', 'TEXT');
  ensureColumn('tasks', 'thread_id', 'TEXT');
  ensureColumn('threads', 'execution_mode', "TEXT NOT NULL DEFAULT 'direct'");
  ensureColumn('threads', 'runner_user', 'TEXT');
}

function ensureColumn(table, column, definition) {
  const columns = db.prepare(`PRAGMA table_info(${table})`).all();
  if (!columns.some(item => item.name === column)) db.exec(`ALTER TABLE ${table} ADD COLUMN ${column} ${definition}`);
}

async function route(req, res) {
  const url = new URL(req.url, `http://${req.headers.host || 'localhost'}`);
  if (!assertTrustedHost(req, res)) return;
  applyCors(req, res, url);
  if (req.method === 'OPTIONS') {
    if (!isAllowedOrigin(req, url)) return sendJson(res, 403, { error: 'origin_not_allowed' });
    return end(res, 204);
  }

  if (req.method === 'GET' && url.pathname === '/health') {
    return sendJson(res, 200, {
      ok: true,
      pairedDevices: db.prepare('SELECT COUNT(*) AS count FROM tokens WHERE revoked_at IS NULL AND expires_at > ?').get(nowIso()).count,
      threads: db.prepare('SELECT COUNT(*) AS count FROM threads WHERE archived_at IS NULL').get().count,
      tasks: db.prepare('SELECT COUNT(*) AS count FROM tasks').get().count,
      workspaceAllowlist: config.workspaceAllowlist,
      runnerUsers: config.runnerUsers
    });
  }

  if (req.method === 'GET' && isStaticPath(url.pathname)) return serveStatic(url.pathname, res);

  if (req.method === 'POST' && url.pathname === '/api/pair/start') {
    if (!isLoopbackRequest(req)) return sendJson(res, 403, { error: 'pair_start_local_only' });
    if (!withinRateLimit(`pair-start:${clientIp(req)}`, config.rateLimits.pairStartPerMinute, 60_000)) return sendJson(res, 429, { error: 'rate_limited' });
    return handlePairStart(req, res);
  }
  if (req.method === 'POST' && url.pathname === '/api/pair/complete') {
    if (!assertAllowedOrigin(req, res, url)) return;
    if (!withinRateLimit(`pair-complete:${clientIp(req)}`, config.rateLimits.pairCompletePerMinute, 60_000)) return sendJson(res, 429, { error: 'rate_limited' });
    return handlePairComplete(req, res);
  }

  const auth = requireAuth(req, res, url);
  if (!auth) return;

  if (req.method === 'GET' && url.pathname === '/api/me') {
    return sendJson(res, 200, {
      ok: true,
      token: auth.tokenMeta,
      allowlist: config.workspaceAllowlist,
      runnerUsers: config.runnerUsers,
      currentUser: os.userInfo().username,
      defaultExecutionMode: config.defaultExecutionMode,
      defaultRunnerUser: config.defaultRunnerUser,
      threads: listThreads()
    });
  }

  if (req.method === 'POST' && url.pathname === '/api/tokens/revoke-all') {
    if (!assertAllowedOrigin(req, res, url)) return;
    db.prepare('UPDATE tokens SET revoked_at = ? WHERE revoked_at IS NULL').run(nowIso());
    setCookie(res, 'dfi_token', '', { maxAge: 0, httpOnly: true, sameSite: 'Lax', path: '/' });
    audit('tokens.revoked_all', { by: auth.tokenMeta.id });
    return sendJson(res, 200, { ok: true });
  }

  if (req.method === 'GET' && url.pathname === '/api/threads') return sendJson(res, 200, { threads: listThreads() });
  if (req.method === 'POST' && url.pathname === '/api/threads') {
    if (!assertAllowedOrigin(req, res, url)) return;
    if (!withinRateLimit(`thread-create:${auth.tokenMeta.id}`, config.rateLimits.threadCreatePerMinute, 60_000)) return sendJson(res, 429, { error: 'rate_limited' });
    return handleCreateThread(req, res, auth);
  }

  const threadMatch = url.pathname.match(/^\/api\/threads\/([^/]+)$/);
  if (threadMatch && req.method === 'GET') return handleGetThread(threadMatch[1], res);
  if (threadMatch && req.method === 'PATCH') {
    if (!assertAllowedOrigin(req, res, url)) return;
    return handleUpdateThread(req, res, threadMatch[1]);
  }

  if (req.method === 'POST' && url.pathname === '/api/tasks') {
    if (!assertAllowedOrigin(req, res, url)) return;
    if (!withinRateLimit(`task-create:${auth.tokenMeta.id}`, config.rateLimits.taskCreatePerMinute, 60_000)) return sendJson(res, 429, { error: 'rate_limited' });
    return handleCreateTask(req, res, auth);
  }
  if (req.method === 'GET' && url.pathname === '/api/tasks') {
    const rows = db.prepare('SELECT id, thread_id, prompt, workspace, status, created_at, started_at, completed_at, exit_code FROM tasks ORDER BY created_at DESC LIMIT 100').all();
    return sendJson(res, 200, { tasks: rows });
  }

  const taskMatch = url.pathname.match(/^\/api\/tasks\/([^/]+)$/);
  if (taskMatch && req.method === 'GET') {
    const task = db.prepare('SELECT * FROM tasks WHERE id = ?').get(taskMatch[1]);
    if (!task) return sendJson(res, 404, { error: 'not_found' });
    return sendJson(res, 200, { task });
  }

  const streamMatch = url.pathname.match(/^\/api\/tasks\/([^/]+)\/stream$/);
  if (streamMatch && req.method === 'GET') return handleTaskStream(streamMatch[1], res);

  const cancelMatch = url.pathname.match(/^\/api\/tasks\/([^/]+)\/cancel$/);
  if (cancelMatch && req.method === 'POST') {
    if (!assertAllowedOrigin(req, res, url)) return;
    return handleCancelTask(cancelMatch[1], res, auth);
  }

  return sendJson(res, 404, { error: 'not_found' });
}

function listThreads() {
  return db.prepare(`
    SELECT t.id, t.title, t.workspace, t.execution_mode, t.runner_user, t.created_at, t.updated_at, t.last_task_status,
           (SELECT prompt FROM tasks WHERE thread_id = t.id ORDER BY created_at DESC LIMIT 1) AS last_prompt,
           (SELECT created_at FROM tasks WHERE thread_id = t.id ORDER BY created_at DESC LIMIT 1) AS last_task_at,
           (SELECT COUNT(*) FROM tasks WHERE thread_id = t.id) AS task_count
    FROM threads t
    WHERE t.archived_at IS NULL
    ORDER BY COALESCE(last_task_at, t.updated_at) DESC
  `).all();
}

function isStaticPath(pathname) {
  return pathname === '/' || pathname.startsWith('/assets/') || pathname.startsWith('/app') || pathname.endsWith('.css') || pathname.endsWith('.js') || pathname.endsWith('.webmanifest');
}

function setSecurityHeaders(res) {
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('Referrer-Policy', 'no-referrer');
  res.setHeader('Permissions-Policy', 'camera=(), microphone=(), geolocation=()');
  res.setHeader('Cross-Origin-Opener-Policy', 'same-origin');
  res.setHeader('Cross-Origin-Resource-Policy', 'same-origin');
  res.setHeader('Content-Security-Policy', "default-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline'; script-src 'self'; connect-src 'self'; base-uri 'self'; form-action 'self'; frame-ancestors 'none'");
}

function isLoopbackRequest(req) {
  const ip = clientIp(req);
  return ip === '127.0.0.1' || ip === '::1' || ip === '::ffff:127.0.0.1';
}

function clientIp(req) {
  return req.socket.remoteAddress || '';
}

function applyCors(req, res, url) {
  const origin = req.headers.origin;
  if (!origin) return;
  if (!isAllowedOrigin(req, url)) return;
  res.setHeader('Access-Control-Allow-Origin', origin);
  res.setHeader('Vary', 'Origin');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, PATCH, OPTIONS');
  res.setHeader('Access-Control-Allow-Credentials', 'true');
}

function isAllowedOrigin(req, url) {
  const origin = req.headers.origin;
  if (!origin) return true;
  try {
    const parsedOrigin = new URL(origin);
    return trustedOrigins.has(parsedOrigin.origin);
  } catch {
    return false;
  }
}

function assertTrustedHost(req, res) {
  if (isTrustedHost(req)) return true;
  sendJson(res, 421, { error: 'invalid_host' });
  return false;
}

function isTrustedHost(req) {
  const hostHeader = req.headers.host;
  if (!hostHeader) return false;
  try {
    const parsedHost = new URL(`http://${hostHeader}`);
    return trustedHosts.has(parsedHost.host);
  } catch {
    return false;
  }
}

function buildTrustedOrigins(config) {
  const origins = new Set();
  for (const value of config.allowedOrigins) {
    try {
      origins.add(new URL(value).origin);
    } catch {
      // Skip malformed configured origins instead of crashing startup.
    }
  }
  for (const value of getStartupUrls(config.host, config.port)) {
    try {
      origins.add(new URL(value).origin);
    } catch {
      // Startup URLs are generated locally, but keep normalization defensive.
    }
  }
  return origins;
}

function buildTrustedHosts(origins) {
  const hosts = new Set();
  for (const origin of origins) hosts.add(new URL(origin).host);
  return hosts;
}

function assertAllowedOrigin(req, res, url) {
  if (isAllowedOrigin(req, url)) return true;
  sendJson(res, 403, { error: 'origin_not_allowed' });
  return false;
}

function withinRateLimit(key, limit, windowMs) {
  const now = Date.now();
  const record = rateLimits.get(key) || [];
  const recent = record.filter(time => now - time < windowMs);
  if (recent.length >= limit) return false;
  recent.push(now);
  rateLimits.set(key, recent);
  return true;
}

function requireAuth(req, res, url) {
  if (!assertAllowedOrigin(req, res, url)) return null;
  const header = req.headers.authorization || '';
  const bearer = header.startsWith('Bearer ') ? header.slice(7) : '';
  const cookieToken = parseCookies(req.headers.cookie || '').dfi_token || '';
  const token = bearer || cookieToken;
  if (!token) return sendJson(res, 401, { error: 'unauthorized' }), null;
  const tokenHash = sha256(token);
  const row = db.prepare('SELECT id, label, created_at, expires_at, revoked_at, scope FROM tokens WHERE token_hash = ?').get(tokenHash);
  if (!row || row.revoked_at || row.expires_at <= nowIso()) return sendJson(res, 401, { error: 'invalid_token' }), null;
  db.prepare('UPDATE tokens SET last_seen_at = ?, last_seen_ip = ? WHERE id = ?').run(nowIso(), clientIp(req), row.id);
  return { tokenMeta: row, rawToken: token };
}

async function handlePairStart(req, res) {
  const body = await readJson(req);
  const label = clampText(body.label, 100) || 'iPhone';
  const code = randomCode();
  const createdAt = nowIso();
  const expiresAt = new Date(Date.now() + config.pairingCodeTtlSeconds * 1000).toISOString();
  db.prepare('INSERT INTO pair_codes (code, created_at, expires_at, label, created_ip) VALUES (?, ?, ?, ?, ?)').run(code, createdAt, expiresAt, label, clientIp(req));
  audit('pair.start', { code, label, expiresAt });
  return sendJson(res, 200, { code, expiresAt });
}

async function handlePairComplete(req, res) {
  const body = await readJson(req);
  const code = clampText(body.code, 32).toUpperCase();
  const label = clampText(body.label, 100) || 'iPhone';
  const row = db.prepare('SELECT * FROM pair_codes WHERE code = ?').get(code);
  if (!row || row.consumed_at || row.expires_at <= nowIso()) return sendJson(res, 400, { error: 'invalid_pair_code' });
  db.prepare('UPDATE pair_codes SET consumed_at = ? WHERE code = ?').run(nowIso(), code);
  const token = `dfi_${crypto.randomBytes(24).toString('hex')}`;
  const tokenId = crypto.randomUUID();
  const expiresAt = new Date(Date.now() + config.tokenTtlDays * 86400 * 1000).toISOString();
  db.prepare('INSERT INTO tokens (id, token_hash, label, created_at, expires_at, scope, created_ip, last_seen_at, last_seen_ip) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)').run(tokenId, sha256(token), label, nowIso(), expiresAt, 'lan', clientIp(req), nowIso(), clientIp(req));
  audit('pair.complete', { code, label, tokenId });
  setCookie(res, 'dfi_token', token, { maxAge: config.tokenTtlDays * 86400, httpOnly: true, sameSite: 'Lax', path: '/' });
  return sendJson(res, 200, { token, expiresAt });
}

async function handleCreateThread(req, res, auth) {
  const body = await readJson(req);
  const title = clampText(body.title, 120);
  const workspace = safeWorkspace(body.workspace);
  const execution = resolveExecution(body.executionMode, body.runnerUser);
  if (!title) return sendJson(res, 400, { error: 'title_required' });
  if (!workspace) return sendJson(res, 400, { error: 'workspace_required' });
  if (findActiveThreadByWorkspace(workspace)) return sendJson(res, 409, { error: 'workspace_already_assigned' });
  if (!execution.ok) return sendJson(res, 400, { error: execution.error });
  const id = crypto.randomUUID();
  const now = nowIso();
  db.prepare('INSERT INTO threads (id, title, workspace, execution_mode, runner_user, created_at, updated_at, last_task_status) VALUES (?, ?, ?, ?, ?, ?, ?, ?)').run(id, title, workspace, execution.mode, execution.runnerUser, now, now, 'idle');
  audit('thread.created', { id, workspace, executionMode: execution.mode, runnerUser: execution.runnerUser, by: auth.tokenMeta.id });
  return sendJson(res, 201, { thread: getThreadWithTasks(id) });
}

function handleGetThread(threadId, res) {
  const thread = getThreadWithTasks(threadId);
  if (!thread) return sendJson(res, 404, { error: 'not_found' });
  return sendJson(res, 200, { thread });
}

async function handleUpdateThread(req, res, threadId) {
  const body = await readJson(req);
  const current = db.prepare('SELECT * FROM threads WHERE id = ? AND archived_at IS NULL').get(threadId);
  if (!current) return sendJson(res, 404, { error: 'not_found' });
  const title = body.title === undefined ? current.title : clampText(body.title, 120);
  const workspace = body.workspace === undefined ? current.workspace : safeWorkspace(body.workspace);
  const execution = resolveExecution(body.executionMode ?? current.execution_mode, body.runnerUser ?? current.runner_user);
  if (!title) return sendJson(res, 400, { error: 'title_required' });
  if (!workspace) return sendJson(res, 400, { error: 'workspace_required' });
  if (findActiveThreadByWorkspace(workspace, threadId)) return sendJson(res, 409, { error: 'workspace_already_assigned' });
  if (!execution.ok) return sendJson(res, 400, { error: execution.error });
  db.prepare('UPDATE threads SET title = ?, workspace = ?, execution_mode = ?, runner_user = ?, updated_at = ? WHERE id = ?').run(title, workspace, execution.mode, execution.runnerUser, nowIso(), threadId);
  return sendJson(res, 200, { thread: getThreadWithTasks(threadId) });
}

async function handleCreateTask(req, res, auth) {
  const body = await readJson(req);
  const prompt = clampText(body.prompt, 12000);
  const threadId = clampText(body.threadId, 64);
  if (!prompt) return sendJson(res, 400, { error: 'prompt_required' });
  if (!threadId) return sendJson(res, 400, { error: 'thread_required' });
  const thread = db.prepare('SELECT * FROM threads WHERE id = ? AND archived_at IS NULL').get(threadId);
  if (!thread) return sendJson(res, 404, { error: 'thread_not_found' });
  if (!isAllowedWorkspace(thread.workspace)) return sendJson(res, 403, { error: 'workspace_not_allowed' });
  const execution = resolveExecution(thread.execution_mode, thread.runner_user);
  if (!execution.ok) return sendJson(res, 400, { error: execution.error });
  const runningCount = db.prepare("SELECT COUNT(*) AS count FROM tasks WHERE thread_id = ? AND status IN ('queued','running')").get(threadId).count;
  if (runningCount > 0) return sendJson(res, 409, { error: 'thread_busy' });
  const continueSession = getThreadWithTasks(threadId)?.tasks?.length > 0;
  const taskId = crypto.randomUUID();
  const createdAt = nowIso();
  db.prepare('INSERT INTO tasks (id, thread_id, prompt, workspace, status, created_at) VALUES (?, ?, ?, ?, ?, ?)').run(taskId, threadId, prompt, thread.workspace, 'queued', createdAt);
  db.prepare('UPDATE threads SET updated_at = ?, last_task_status = ? WHERE id = ?').run(createdAt, 'queued', threadId);
  audit('task.created', { taskId, threadId, workspace: thread.workspace, executionMode: execution.mode, runnerUser: execution.runnerUser, continueSession, by: auth.tokenMeta.id });
  runTask(taskId, threadId, prompt, thread.workspace, execution, { continueSession });
  return sendJson(res, 202, { taskId, threadId });
}

function handleTaskStream(taskId, res) {
  const task = db.prepare('SELECT * FROM tasks WHERE id = ?').get(taskId);
  if (!task) return sendJson(res, 404, { error: 'not_found' });
  res.writeHead(200, {
    'Content-Type': 'text/event-stream',
    'Cache-Control': 'no-cache, no-transform',
    Connection: 'keep-alive'
  });
  res.write(`event: snapshot\ndata: ${JSON.stringify(task)}\n\n`);
  let set = taskStreams.get(taskId);
  if (!set) {
    set = new Set();
    taskStreams.set(taskId, set);
  }
  set.add(res);
  reqClose(res, () => {
    const current = taskStreams.get(taskId);
    if (!current) return;
    current.delete(res);
    if (!current.size) taskStreams.delete(taskId);
  });
}

function handleCancelTask(taskId, res, auth) {
  const child = taskProcesses.get(taskId);
  if (!child) return sendJson(res, 409, { error: 'task_not_running' });
  child.kill('SIGTERM');
  audit('task.cancelled', { taskId, by: auth.tokenMeta.id });
  sendJson(res, 200, { ok: true });
}

function runTask(taskId, threadId, prompt, workspace, execution, options = {}) {
  const startedAt = nowIso();
  db.prepare('UPDATE tasks SET status = ?, started_at = ? WHERE id = ?').run('running', startedAt, taskId);
  db.prepare('UPDATE threads SET updated_at = ?, last_task_status = ? WHERE id = ?').run(startedAt, 'running', threadId);
  broadcast(taskId, 'status', { status: 'running', startedAt, threadId });

  const { command, args } = buildTaskCommand(prompt, execution, options);
  const child = spawn(command, args, {
    cwd: workspace,
    stdio: ['ignore', 'pipe', 'pipe']
  });
  taskProcesses.set(taskId, child);

  child.stdout.on('data', chunk => appendTaskOutput(taskId, chunk.toString(), 'output'));
  child.stderr.on('data', chunk => appendTaskOutput(taskId, chunk.toString(), 'stderr'));
  child.on('error', error => appendTaskOutput(taskId, `\n[spawn error] ${error.message}\n`, 'stderr'));
  child.on('close', code => {
    taskProcesses.delete(taskId);
    const status = code === 0 ? 'completed' : 'failed';
    const completedAt = nowIso();
    db.prepare('UPDATE tasks SET status = ?, completed_at = ?, exit_code = ? WHERE id = ?').run(status, completedAt, code, taskId);
    db.prepare('UPDATE threads SET updated_at = ?, last_task_status = ? WHERE id = ?').run(completedAt, status, threadId);
    broadcast(taskId, 'status', { status, completedAt, exitCode: code, threadId });
    broadcast(taskId, 'done', { status, completedAt, exitCode: code, threadId });
    audit('task.finished', { taskId, threadId, status, exitCode: code });
  });
}

function buildTaskCommand(prompt, execution, options = {}) {
  const devinArgs = ['--permission-mode', config.devinPermissionMode];
  if (options.continueSession) devinArgs.push('--continue');
  devinArgs.push('-p', prompt);
  if (execution.mode === 'runner_user') {
    return {
      command: config.sudoBinary,
      args: ['-n', '-u', execution.runnerUser, '--', config.devinBinary, ...devinArgs]
    };
  }
  return { command: config.devinBinary, args: devinArgs };
}

function appendTaskOutput(taskId, chunk, field) {
  const column = field === 'stderr' ? 'error' : 'output';
  db.prepare(`UPDATE tasks SET ${column} = ${column} || ? WHERE id = ?`).run(chunk, taskId);
  broadcast(taskId, field, { chunk });
}

function broadcast(taskId, event, payload) {
  const set = taskStreams.get(taskId);
  if (!set) return;
  const message = `event: ${event}\ndata: ${JSON.stringify(payload)}\n\n`;
  for (const res of set) res.write(message);
}

function findActiveThreadByWorkspace(workspace, excludeThreadId = '') {
  return listThreads().find(thread => thread.workspace === workspace && thread.id !== excludeThreadId) || null;
}

function safeWorkspace(input) {
  if (typeof input !== 'string' || !input.trim()) return '';
  const resolved = path.resolve(input.trim());
  return isAllowedWorkspace(resolved) ? resolved : '';
}

function isAllowedWorkspace(workspace) {
  return config.workspaceAllowlist.some(base => workspace === base || workspace.startsWith(`${base}${path.sep}`));
}

function resolveExecution(modeInput, runnerUserInput) {
  const mode = modeInput === 'runner_user' ? 'runner_user' : 'direct';
  const runnerUser = clampText(runnerUserInput, 64);
  if (mode === 'direct') return { ok: true, mode, runnerUser: null };
  if (!runnerUser) return { ok: false, error: 'runner_user_required' };
  if (!isValidUsername(runnerUser)) return { ok: false, error: 'runner_user_invalid' };
  if (!config.runnerUsers.includes(runnerUser)) return { ok: false, error: 'runner_user_not_allowed' };
  if (!systemUserExists(runnerUser)) return { ok: false, error: 'runner_user_missing' };
  return { ok: true, mode, runnerUser };
}

function isValidUsername(value) {
  return /^[a-z_][a-z0-9_-]{0,31}$/i.test(value || '');
}

function systemUserExists(username) {
  const result = spawnSync('/usr/bin/id', ['-u', username], { stdio: 'ignore' });
  return result.status === 0;
}

function getThreadWithTasks(threadId) {
  const thread = db.prepare('SELECT * FROM threads WHERE id = ? AND archived_at IS NULL').get(threadId);
  if (!thread) return null;
  const tasks = db.prepare('SELECT id, thread_id, prompt, workspace, status, created_at, started_at, completed_at, exit_code, output, error FROM tasks WHERE thread_id = ? ORDER BY created_at ASC').all(threadId);
  return { ...thread, tasks };
}

function serveStatic(requestPath, res) {
  const relative = requestPath === '/' ? '/index.html' : requestPath;
  const filePath = path.normalize(path.join(webDir, relative));
  if (!filePath.startsWith(webDir)) return sendJson(res, 403, { error: 'forbidden' });
  if (!fs.existsSync(filePath) || fs.statSync(filePath).isDirectory()) return sendJson(res, 404, { error: 'not_found' });
  const ext = path.extname(filePath);
  const type = {
    '.html': 'text/html; charset=utf-8',
    '.css': 'text/css; charset=utf-8',
    '.js': 'text/javascript; charset=utf-8',
    '.webmanifest': 'application/manifest+json; charset=utf-8'
  }[ext] || 'application/octet-stream';
  res.writeHead(200, { 'Content-Type': type, 'Cache-Control': 'no-store' });
  fs.createReadStream(filePath).pipe(res);
}

function audit(eventType, detail) {
  db.prepare('INSERT INTO audit_logs (id, event_type, created_at, detail_json) VALUES (?, ?, ?, ?)').run(crypto.randomUUID(), eventType, nowIso(), JSON.stringify(detail));
}

function readJson(req) {
  return new Promise((resolve, reject) => {
    let raw = '';
    req.on('data', chunk => {
      raw += chunk.toString();
      if (raw.length > 1_000_000) {
        reject(new Error('payload_too_large'));
        req.destroy();
      }
    });
    req.on('end', () => {
      try {
        resolve(raw ? JSON.parse(raw) : {});
      } catch {
        reject(new Error('invalid_json'));
      }
    });
    req.on('error', reject);
  });
}

function parseCookies(cookieHeader) {
  return Object.fromEntries(
    cookieHeader.split(';').map(part => part.trim()).filter(Boolean).map(part => {
      const idx = part.indexOf('=');
      return idx === -1 ? [part, ''] : [part.slice(0, idx), decodeURIComponent(part.slice(idx + 1))];
    })
  );
}

function setCookie(res, name, value, options = {}) {
  const parts = [`${name}=${encodeURIComponent(value)}`];
  if (options.maxAge !== undefined) parts.push(`Max-Age=${options.maxAge}`);
  if (options.path) parts.push(`Path=${options.path}`);
  if (options.httpOnly) parts.push('HttpOnly');
  if (options.sameSite) parts.push(`SameSite=${options.sameSite}`);
  res.setHeader('Set-Cookie', parts.join('; '));
}

function sendJson(res, status, body) {
  res.writeHead(status, { 'Content-Type': 'application/json; charset=utf-8' });
  res.end(JSON.stringify(body));
}

function end(res, status) {
  res.writeHead(status);
  res.end();
}

function nowIso() {
  return new Date().toISOString();
}

function randomCode() {
  return crypto.randomBytes(3).toString('hex').toUpperCase();
}

function sha256(input) {
  return crypto.createHash('sha256').update(input).digest('hex');
}

function clampText(input, limit) {
  return typeof input === 'string' ? input.trim().slice(0, limit) : '';
}

function reqClose(res, onClose) {
  let done = false;
  const once = () => {
    if (done) return;
    done = true;
    onClose();
  };
  res.on('close', once);
  res.on('finish', once);
}
