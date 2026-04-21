const state = {
  allowlist: [],
  runnerUsers: [],
  defaultExecutionMode: 'direct',
  defaultRunnerUser: '',
  threads: [],
  selectedThreadId: localStorage.getItem('dfi_selected_thread') || '',
  activeTaskId: '',
  activeTaskStatus: 'idle',
  eventSource: null,
  currentThread: null,
  threadFilter: 'all',
  threadSearch: '',
  expandedTasks: new Set(),
  sidebarOpen: false,
  loadingThread: false,
  notificationsEnabled: localStorage.getItem('dfi_notifications_enabled') === 'true'
};

const els = {
  authShell: document.getElementById('authShell'),
  workspaceShell: document.getElementById('workspaceShell'),
  startPairBtn: document.getElementById('startPairBtn'),
  generatedCode: document.getElementById('generatedCode'),
  pairLabel: document.getElementById('pairLabel'),
  pairCode: document.getElementById('pairCode'),
  pairBtn: document.getElementById('pairBtn'),
  pairStatus: document.getElementById('pairStatus'),
  logoutBtn: document.getElementById('logoutBtn'),
  openSidebarBtn: document.getElementById('openSidebarBtn'),
  closeSidebarBtn: document.getElementById('closeSidebarBtn'),
  sidebar: document.getElementById('sidebar'),
  backdrop: document.getElementById('backdrop'),
  threadSearchInput: document.getElementById('threadSearchInput'),
  threadFilters: document.getElementById('threadFilters'),
  newThreadBtn: document.getElementById('newThreadBtn'),
  newThreadModal: document.getElementById('newThreadModal'),
  closeModalBtn: document.getElementById('closeModalBtn'),
  newThreadTitle: document.getElementById('newThreadTitle'),
  newThreadWorkspace: document.getElementById('newThreadWorkspace'),
  newThreadExecutionMode: document.getElementById('newThreadExecutionMode'),
  runnerUserLabel: document.getElementById('runnerUserLabel'),
  newThreadRunnerUser: document.getElementById('newThreadRunnerUser'),
  newThreadPrompt: document.getElementById('newThreadPrompt'),
  createThreadBtn: document.getElementById('createThreadBtn'),
  threadCreateStatus: document.getElementById('threadCreateStatus'),
  threadList: document.getElementById('threadList'),
  threadTitle: document.getElementById('threadTitle'),
  threadWorkspaceLabel: document.getElementById('threadWorkspaceLabel'),
  threadExecutionLabel: document.getElementById('threadExecutionLabel'),
  threadStatusPill: document.getElementById('threadStatusPill'),
  notifyBtn: document.getElementById('notifyBtn'),
  refreshBtn: document.getElementById('refreshBtn'),
  messages: document.getElementById('messages'),
  composerPanel: document.getElementById('composerPanel'),
  promptInput: document.getElementById('promptInput'),
  runBtn: document.getElementById('runBtn'),
  cancelBtn: document.getElementById('cancelBtn'),
  composerStatus: document.getElementById('composerStatus'),
  threadCountStat: document.getElementById('threadCountStat'),
  runningCountStat: document.getElementById('runningCountStat'),
  workspaceShortStat: document.getElementById('workspaceShortStat'),
  toast: document.getElementById('toast')
};

els.startPairBtn.addEventListener('click', startPairing);
els.pairBtn.addEventListener('click', pairDevice);
els.logoutBtn.addEventListener('click', unpair);
els.openSidebarBtn.addEventListener('click', () => setSidebar(true));
els.closeSidebarBtn.addEventListener('click', () => setSidebar(false));
els.backdrop.addEventListener('click', () => {
  setSidebar(false);
  setModal(false);
});
els.threadSearchInput.addEventListener('input', event => {
  state.threadSearch = event.target.value.trim().toLowerCase();
  renderThreadList();
});
els.threadFilters.addEventListener('click', event => {
  const button = event.target.closest('[data-filter]');
  if (!button) return;
  state.threadFilter = button.dataset.filter;
  renderThreadFilters();
  renderThreadList();
});
els.newThreadBtn.addEventListener('click', () => setModal(true));
els.closeModalBtn.addEventListener('click', () => setModal(false));
els.createThreadBtn.addEventListener('click', createThread);
els.newThreadExecutionMode.addEventListener('change', syncExecutionModeUI);
els.notifyBtn.addEventListener('click', toggleNotifications);
els.refreshBtn.addEventListener('click', refreshThreads);
els.runBtn.addEventListener('click', createTask);
els.cancelBtn.addEventListener('click', cancelTask);
els.messages.addEventListener('click', event => {
  const button = event.target.closest('[data-toggle-task]');
  if (!button) return;
  const taskId = button.dataset.toggleTask;
  if (state.expandedTasks.has(taskId)) state.expandedTasks.delete(taskId);
  else state.expandedTasks.add(taskId);
  renderSelectedThread();
});

boot();

async function boot() {
  const me = await api('/api/me').catch(() => null);
  if (!me?.ok) {
    return renderAuth();
  }
  state.allowlist = me.allowlist || [];
  state.runnerUsers = me.runnerUsers || [];
  state.defaultExecutionMode = me.defaultExecutionMode || 'direct';
  state.defaultRunnerUser = me.defaultRunnerUser || '';
  state.threads = me.threads || [];
  syncWorkspaceOptions();
  syncRunnerUserOptions();
  els.newThreadExecutionMode.value = state.defaultExecutionMode;
  if (state.defaultRunnerUser) els.newThreadRunnerUser.value = state.defaultRunnerUser;
  syncExecutionModeUI();
  if (!state.selectedThreadId || !state.threads.some(thread => thread.id === state.selectedThreadId)) {
    state.selectedThreadId = state.threads[0]?.id || '';
  }
  persistSelectedThread();
  renderNotificationButton();
  renderApp();
  await refreshSelectedThread();
}

function renderAuth() {
  closeStream();
  els.authShell.classList.remove('hidden');
  els.workspaceShell.classList.add('hidden');
  setSidebar(false);
  setModal(false);
}

function renderApp() {
  renderNotificationButton();
  els.authShell.classList.add('hidden');
  els.workspaceShell.classList.remove('hidden');
  renderThreadFilters();
  renderThreadList();
  renderStats();
  renderSelectedThread();
}

function syncWorkspaceOptions() {
  els.newThreadWorkspace.innerHTML = state.allowlist.map(item => `<option value="${escapeAttr(item)}">${escapeHtml(item)}</option>`).join('');
}

function syncRunnerUserOptions() {
  els.newThreadRunnerUser.innerHTML = state.runnerUsers.map(item => `<option value="${escapeAttr(item)}">${escapeHtml(item)}</option>`).join('');
  if (state.defaultRunnerUser && state.runnerUsers.includes(state.defaultRunnerUser)) els.newThreadRunnerUser.value = state.defaultRunnerUser;
}

function syncExecutionModeUI() {
  const runner = els.newThreadExecutionMode.value === 'runner_user';
  els.runnerUserLabel.classList.toggle('hidden', !runner);
}

async function startPairing() {
  els.generatedCode.textContent = 'Generating…';
  const result = await fetch('/api/pair/start', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ label: 'Mac pairing screen' })
  }).then(r => r.json()).catch(() => null);
  els.generatedCode.textContent = result?.code ? `Pair code: ${result.code} · expires ${new Date(result.expiresAt).toLocaleTimeString()}` : 'Failed to generate code.';
}

async function pairDevice() {
  els.pairStatus.textContent = 'Pairing…';
  const result = await fetch('/api/pair/complete', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    credentials: 'same-origin',
    body: JSON.stringify({ code: els.pairCode.value, label: els.pairLabel.value })
  }).then(r => r.json()).catch(() => null);
  if (!result?.token) {
    els.pairStatus.textContent = 'Invalid or expired pair code.';
    return;
  }
  toast('Paired successfully.');
  await boot();
}

async function createThread() {
  els.threadCreateStatus.textContent = 'Creating thread…';
  const title = els.newThreadTitle.value.trim();
  const workspace = els.newThreadWorkspace.value;
  const executionMode = els.newThreadExecutionMode.value;
  const runnerUser = els.newThreadRunnerUser.value;
  const starterPrompt = els.newThreadPrompt.value.trim();
  if (!title) {
    els.threadCreateStatus.textContent = 'Thread title is required.';
    return;
  }
  if (!workspace) {
    els.threadCreateStatus.textContent = 'Choose a workspace folder first.';
    return;
  }
  if (executionMode === 'runner_user' && !runnerUser) {
    els.threadCreateStatus.textContent = 'Choose a runner user.';
    return;
  }
  const result = await api('/api/threads', {
    method: 'POST',
    body: JSON.stringify({ title, workspace, executionMode, runnerUser })
  }).catch(error => ({ error: error.message || 'request_failed' }));
  if (!result?.thread?.id) {
    els.threadCreateStatus.textContent = humanizeError(result);
    return;
  }
  els.threadCreateStatus.textContent = 'Thread created.';
  state.selectedThreadId = result.thread.id;
  persistSelectedThread();
  els.newThreadTitle.value = '';
  els.newThreadPrompt.value = '';
  setModal(false);
  await refreshThreads();
  toast('Thread created.');
  if (starterPrompt) {
    els.promptInput.value = starterPrompt;
    await createTask();
  }
}

async function refreshThreads() {
  const result = await api('/api/threads').catch(() => null);
  state.threads = result?.threads || [];
  if (!state.selectedThreadId && state.threads[0]) state.selectedThreadId = state.threads[0].id;
  persistSelectedThread();
  renderThreadList();
  renderStats();
  await refreshSelectedThread();
}

async function refreshSelectedThread() {
  if (!state.selectedThreadId) {
    state.currentThread = null;
    return renderSelectedThread();
  }
  state.loadingThread = true;
  renderSelectedThread();
  const result = await api(`/api/threads/${state.selectedThreadId}`).catch(() => null);
  state.loadingThread = false;
  if (!result?.thread) {
    state.currentThread = null;
    return renderSelectedThread();
  }
  const index = state.threads.findIndex(item => item.id === result.thread.id);
  const summary = summarizeThread(result.thread);
  if (index === -1) state.threads.unshift(summary);
  else state.threads[index] = { ...state.threads[index], ...summary };
  state.currentThread = result.thread;
  renderNotificationButton();
  renderApp();
  const activeTask = [...(result.thread.tasks || [])].reverse().find(task => task.status === 'running' || task.status === 'queued');
  if (activeTask) attachStream(activeTask.id, false);
}

function renderThreadFilters() {
  for (const button of els.threadFilters.querySelectorAll('[data-filter]')) {
    button.classList.toggle('active', button.dataset.filter === state.threadFilter);
  }
}

function filteredThreads() {
  return state.threads.filter(thread => {
    const matchesSearch = !state.threadSearch || [thread.title, thread.workspace, thread.last_prompt || ''].join(' ').toLowerCase().includes(state.threadSearch);
    if (!matchesSearch) return false;
    if (state.threadFilter === 'all') return true;
    return (thread.last_task_status || 'idle') === state.threadFilter;
  });
}

function renderThreadList() {
  const threads = filteredThreads();
  if (!threads.length) {
    els.threadList.innerHTML = `<div class="thread-empty muted">No matching threads. Try another filter or create a new one.</div>`;
    return;
  }
  els.threadList.innerHTML = threads.map(thread => `
    <button class="thread-card ${thread.id === state.selectedThreadId ? 'active' : ''}" data-thread-id="${escapeAttr(thread.id)}">
      <div class="thread-card-top">
        <strong>${escapeHtml(thread.title)}</strong>
        <span class="mini-status ${statusClass(thread.last_task_status)}">${escapeHtml(thread.last_task_status || 'idle')}</span>
      </div>
      <div class="thread-workspace">${escapeHtml(shortPath(thread.workspace))}</div>
      <div class="thread-preview">${escapeHtml(thread.last_prompt || 'No task yet')}</div>
      <div class="thread-meta">${thread.last_task_at ? `Updated ${formatRelativeTime(thread.last_task_at)}` : 'Ready'}</div>
    </button>
  `).join('');
  for (const button of els.threadList.querySelectorAll('[data-thread-id]')) {
    button.addEventListener('click', async () => {
      state.selectedThreadId = button.dataset.threadId;
      persistSelectedThread();
      closeStream();
      setSidebar(false);
      await refreshSelectedThread();
    });
  }
}

function renderStats() {
  els.threadCountStat.textContent = String(state.threads.length);
  els.runningCountStat.textContent = String(state.threads.filter(thread => ['running', 'queued'].includes(thread.last_task_status)).length);
  const workspace = state.currentThread?.workspace || state.threads.find(t => t.id === state.selectedThreadId)?.workspace || '';
  els.workspaceShortStat.textContent = workspace ? shortPath(workspace) : '—';
}

function renderSelectedThread() {
  const thread = state.currentThread && state.currentThread.id === state.selectedThreadId ? state.currentThread : null;
  if (!thread) {
    els.threadTitle.textContent = state.loadingThread ? 'Loading thread…' : 'No thread selected';
    els.threadWorkspaceLabel.textContent = state.loadingThread ? 'Fetching thread details.' : 'Choose or create a thread to start.';
    els.threadStatusPill.textContent = 'idle';
    els.threadStatusPill.className = 'status-pill status-idle';
    els.messages.className = 'messages empty-state';
    els.messages.innerHTML = `<div class="empty-card"><h3>Start with a thread</h3><p class="muted">Create a thread, assign a folder, and keep separate workstreams isolated.</p></div>`;
    els.composerPanel.classList.add('hidden');
    renderStats();
    return;
  }
  els.threadTitle.textContent = thread.title;
  els.threadWorkspaceLabel.textContent = thread.workspace;
  els.threadExecutionLabel.textContent = formatExecution(thread);
  els.threadStatusPill.textContent = thread.last_task_status || 'idle';
  els.threadStatusPill.className = `status-pill ${statusClass(thread.last_task_status)}`;
  els.composerPanel.classList.remove('hidden');
  renderMessages(thread.tasks || []);
  renderStats();
}

function renderMessages(tasks) {
  els.messages.className = 'messages';
  if (!tasks.length) {
    els.messages.innerHTML = `<div class="empty-card"><h3>No tasks yet</h3><p class="muted">Send a prompt below and Devin will work inside this folder.</p></div>`;
    return;
  }
  els.messages.innerHTML = tasks.map(task => {
    const fullOutput = joinTaskOutput(task);
    const expanded = state.expandedTasks.has(task.id) || fullOutput.length < 500;
    const preview = expanded ? fullOutput : `${fullOutput.slice(0, 500)}\n\n…`;
    return `
      <article class="message-group">
        <div class="bubble user-bubble">
          <div class="bubble-label">You</div>
          <div>${escapeHtml(task.prompt)}</div>
        </div>
        <div class="bubble assistant-bubble ${statusClass(task.status)}">
          <div class="assistant-header-row">
            <div class="bubble-label">Devin · ${escapeHtml(task.status)}</div>
            <div class="assistant-actions">
              <span class="mini-status ${statusClass(task.status)}">${escapeHtml(task.status)}</span>
              ${fullOutput.length > 500 ? `<button class="ghost compact tiny" data-toggle-task="${escapeAttr(task.id)}">${expanded ? 'Collapse' : 'Expand'}</button>` : ''}
            </div>
          </div>
          <pre>${escapeHtml(preview)}</pre>
          <div class="bubble-meta">${formatTime(task.created_at)}${task.exit_code === null || task.exit_code === undefined ? '' : ` · exit ${task.exit_code}`}</div>
        </div>
      </article>
    `;
  }).join('');
  els.messages.scrollTop = els.messages.scrollHeight;
}

async function createTask() {
  if (!state.selectedThreadId) return;
  els.composerStatus.textContent = 'Starting task…';
  const prompt = els.promptInput.value.trim();
  if (!prompt) {
    els.composerStatus.textContent = 'Prompt is required.';
    return;
  }
  const result = await api('/api/tasks', {
    method: 'POST',
    body: JSON.stringify({ threadId: state.selectedThreadId, prompt })
  }).catch(error => ({ error: error.message || 'request_failed' }));
  if (!result?.taskId) {
    els.composerStatus.textContent = humanizeError(result);
    return;
  }
  els.promptInput.value = '';
  state.activeTaskId = result.taskId;
  state.activeTaskStatus = 'running';
  els.cancelBtn.classList.remove('hidden');
  els.composerStatus.textContent = 'Task running…';
  await refreshSelectedThread();
  attachStream(result.taskId, true);
}

function attachStream(taskId, refreshFirst) {
  closeStream();
  state.activeTaskId = taskId;
  const es = new EventSource(`/api/tasks/${taskId}/stream`);
  state.eventSource = es;
  if (refreshFirst) refreshSelectedThread();
  es.addEventListener('output', event => patchCurrentTask(taskId, { outputAppend: JSON.parse(event.data).chunk }));
  es.addEventListener('stderr', event => patchCurrentTask(taskId, { errorAppend: JSON.parse(event.data).chunk }));
  es.addEventListener('status', async event => {
    const payload = JSON.parse(event.data);
    state.activeTaskStatus = payload.status;
    if (payload.status === 'completed' || payload.status === 'failed') {
      els.cancelBtn.classList.add('hidden');
      els.composerStatus.textContent = `Task ${payload.status}.`;
    }
    await refreshSelectedThread();
  });
  es.addEventListener('done', async event => {
    const payload = JSON.parse(event.data);
    state.activeTaskStatus = payload.status;
    els.cancelBtn.classList.add('hidden');
    els.composerStatus.textContent = `Task ${payload.status}.`;
    toast(`Task ${payload.status}.`);
    notifyTaskFinished(payload.status);
    closeStream();
    await refreshSelectedThread();
  });
}

function patchCurrentTask(taskId, patch) {
  const thread = state.currentThread;
  if (!thread?.tasks) return;
  const task = thread.tasks.find(item => item.id === taskId);
  if (!task) return;
  if (patch.outputAppend) task.output = `${task.output || ''}${patch.outputAppend}`;
  if (patch.errorAppend) task.error = `${task.error || ''}${patch.errorAppend}`;
  renderMessages(thread.tasks);
}

async function cancelTask() {
  if (!state.activeTaskId) return;
  await api(`/api/tasks/${state.activeTaskId}/cancel`, { method: 'POST' }).catch(() => null);
  els.composerStatus.textContent = 'Cancel requested.';
  toast('Cancel requested.');
}

async function unpair() {
  await api('/api/tokens/revoke-all', { method: 'POST' }).catch(() => null);
  localStorage.removeItem('dfi_selected_thread');
  state.selectedThreadId = '';
  state.currentThread = null;
  toast('Device unpaired.');
  renderAuth();
}

async function api(url, options = {}) {
  const headers = {
    'Content-Type': 'application/json',
    ...(options.headers || {})
  };
  const response = await fetch(url, { ...options, headers, credentials: 'same-origin' });
  const data = await response.json().catch(() => ({}));
  if (!response.ok) throw new Error(data.error || `http_${response.status}`);
  return data;
}

function formatExecution(thread) {
  return thread.execution_mode === 'runner_user' ? `Runner user: ${thread.runner_user || 'unknown'}` : 'Direct mode';
}

function humanizeError(result) {
  const code = result?.error || 'request_failed';
  return ({
    title_required: 'Thread title is required.',
    workspace_required: 'Workspace is required.',
    workspace_not_allowed: 'That folder is outside the allowed workspace list.',
    origin_not_allowed: 'This browser origin is not allowed by the server.',
    invalid_token: 'Your session expired. Pair again.',
    unauthorized: 'Pair this device again.',
    rate_limited: 'Too many requests. Try again in a moment.',
    thread_busy: 'This thread already has a running task.',
    workspace_already_assigned: 'That workspace already belongs to another active thread.',
    runner_user_required: 'Runner user is required for runner mode.',
    runner_user_invalid: 'Runner user name is invalid.',
    runner_user_not_allowed: 'That runner user is not allowed by server config.',
    runner_user_missing: 'That runner user does not exist on this Mac.'
  })[code] || `Request failed: ${code}`;
}

function summarizeThread(thread) {
  const lastTask = [...(thread.tasks || [])].reverse()[0];
  return {
    id: thread.id,
    title: thread.title,
    workspace: thread.workspace,
    updated_at: thread.updated_at,
    last_task_status: thread.last_task_status || lastTask?.status || 'idle',
    last_prompt: lastTask?.prompt || '',
    last_task_at: lastTask?.created_at || thread.updated_at,
    task_count: (thread.tasks || []).length
  };
}

function joinTaskOutput(task) {
  const text = [task.output, task.error].filter(Boolean).join(task.output && task.error ? '\n' : '');
  return text || 'Waiting for output…';
}

function setSidebar(open) {
  state.sidebarOpen = open;
  els.sidebar.classList.toggle('sidebar-open', open);
  els.backdrop.classList.toggle('hidden', !open && els.newThreadModal.classList.contains('hidden'));
}

function setModal(open) {
  els.newThreadModal.classList.toggle('hidden', !open);
  els.newThreadModal.setAttribute('aria-hidden', String(!open));
  els.backdrop.classList.toggle('hidden', !open && !state.sidebarOpen);
  if (open) {
    els.threadCreateStatus.textContent = '';
    els.newThreadTitle.focus();
  }
}


async function toggleNotifications() {
  if (!supportsNotifications()) {
    toast('This browser does not support notifications.');
    return;
  }
  if (Notification.permission === 'granted') {
    state.notificationsEnabled = !state.notificationsEnabled;
    localStorage.setItem('dfi_notifications_enabled', String(state.notificationsEnabled));
    renderNotificationButton();
    toast(state.notificationsEnabled ? 'Notifications enabled.' : 'Notifications muted.');
    return;
  }
  const permission = await Notification.requestPermission();
  state.notificationsEnabled = permission === 'granted';
  localStorage.setItem('dfi_notifications_enabled', String(state.notificationsEnabled));
  renderNotificationButton();
  toast(state.notificationsEnabled ? 'Notifications enabled.' : 'Notification permission denied.');
}

function renderNotificationButton() {
  if (!els.notifyBtn) return;
  if (!supportsNotifications()) {
    els.notifyBtn.textContent = 'Notifications unavailable';
    els.notifyBtn.disabled = true;
    return;
  }
  if (Notification.permission === 'granted') {
    els.notifyBtn.disabled = false;
    els.notifyBtn.textContent = state.notificationsEnabled ? 'Notifications on' : 'Notifications muted';
    return;
  }
  els.notifyBtn.disabled = false;
  els.notifyBtn.textContent = Notification.permission === 'denied' ? 'Notifications blocked' : 'Enable notifications';
}

function notifyTaskFinished(status) {
  if (!supportsNotifications() || Notification.permission !== 'granted' || !state.notificationsEnabled) return;
  const thread = state.currentThread;
  const title = status === 'completed' ? 'Devin finished a task' : 'Devin task failed';
  const body = thread ? `${thread.title} · ${shortPath(thread.workspace)}` : 'Your task is done.';
  try {
    new Notification(title, { body, tag: 'dfi-task-finished' });
  } catch {}
}

function supportsNotifications() {
  return typeof Notification !== 'undefined';
}

function persistSelectedThread() {
  if (state.selectedThreadId) localStorage.setItem('dfi_selected_thread', state.selectedThreadId);
  else localStorage.removeItem('dfi_selected_thread');
}

function toast(message) {
  els.toast.textContent = message;
  els.toast.classList.remove('hidden');
  clearTimeout(toast.timer);
  toast.timer = setTimeout(() => els.toast.classList.add('hidden'), 2200);
}

function shortPath(input) {
  const value = String(input || '');
  const parts = value.split('/').filter(Boolean);
  return parts.length <= 3 ? value : `…/${parts.slice(-3).join('/')}`;
}

function formatTime(value) {
  return value ? new Date(value).toLocaleString() : '';
}

function formatRelativeTime(value) {
  const diffMs = Date.now() - new Date(value).getTime();
  const minutes = Math.floor(diffMs / 60000);
  if (minutes < 1) return 'just now';
  if (minutes < 60) return `${minutes}m ago`;
  const hours = Math.floor(minutes / 60);
  if (hours < 24) return `${hours}h ago`;
  const days = Math.floor(hours / 24);
  return `${days}d ago`;
}

function statusClass(status) {
  return ['running', 'queued', 'completed', 'failed'].includes(status) ? `status-${status}` : 'status-idle';
}

function closeStream() {
  if (!state.eventSource) return;
  state.eventSource.close();
  state.eventSource = null;
}

function escapeHtml(input) {
  return String(input || '').replace(/[&<>"']/g, ch => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[ch]));
}

function escapeAttr(input) {
  return escapeHtml(input);
}
