let token = '';

const byId = (id) => document.getElementById(id);

for (const item of document.querySelectorAll('.nav-item[data-target]')) {
  item.addEventListener('click', () => {
    const target = document.getElementById(item.dataset.target);
    if (!target) return;
    for (const peer of document.querySelectorAll('.nav-item')) peer.classList.remove('active');
    item.classList.add('active');
    target.scrollIntoView({ behavior: 'smooth', block: 'start' });
  });
}
const api = async (path, options = {}) => {
  const response = await fetch(path, {
    ...options,
    headers: { Authorization: `Bearer ${token}`, ...(options.headers || {}) }
  });
  const data = await response.json();
  if (!response.ok) {
    if (response.status === 401) {
      globalThis.HongAiDashboardSession?.clearToken();
      token = '';
      data.error = '控制台会话已失效，请重启 Edge Cage 控制台。';
    }
    throw Object.assign(new Error(data.error || data.failures?.join(' ') || 'Request failed'), { data });
  }
  return data;
};

const formatTime = (iso) => new Intl.DateTimeFormat('zh-CN', {
  hour: '2-digit', minute: '2-digit', second: '2-digit', hour12: false
}).format(new Date(iso));

function renderAudit(payload) {
  const list = byId('auditList');
  const state = byId('auditState');
  list.textContent = '';
  state.textContent = payload.ok ? '链路完整' : '链路异常';
  state.classList.toggle('fail', !payload.ok);
  if (!payload.events.length) {
    const empty = document.createElement('div');
    empty.className = 'empty';
    empty.textContent = '暂无审计事件';
    list.append(empty);
    return;
  }
  for (const event of payload.events) {
    const item = document.createElement('div');
    item.className = 'timeline-item';
    const time = document.createElement('time');
    time.textContent = formatTime(event.timestamp);
    const content = document.createElement('div');
    const title = document.createElement('strong');
    title.textContent = event.type;
    const detail = document.createElement('small');
    detail.textContent = `#${event.sequence} · ${event.actor} · ${event.hash.slice(0, 10)}`;
    content.append(title, detail);
    item.append(time, content);
    list.append(item);
  }
}

function renderStatus(status) {
  byId('expectedExitIp').textContent = status.expectedExit.ipv4;
  byId('exitRegion').textContent = `${status.expectedExit.countryCode} · ${status.expectedExit.timeZone}`;
  byId('observedExitIp').textContent = status.verification.observedExitIp || '—';
  byId('verificationState').textContent = status.verification.state.replaceAll('_', ' ');
  byId('controllerState').textContent = status.controller.state;
  byId('controlPlaneState').textContent = status.controller.state;
  byId('runtimeState').textContent = status.runtime.state.replaceAll('_', ' ');
  byId('watchdog').textContent = status.policy.watchdog;
  byId('scoreGate').textContent = `${status.scoreGate}+`;
  byId('workspacePath').textContent = status.workspace;
}

async function load() {
  try {
    const status = await api('/api/status');
    renderStatus(status);
    renderAudit(await api('/api/audit'));
  } catch (error) {
    byId('preflightResult').textContent = `控制台认证失败：${error.message}`;
    byId('preflightResult').className = 'result-box fail';
  }
}

byId('runPreflight').addEventListener('click', async () => {
  const button = byId('runPreflight');
  const result = byId('preflightResult');
  button.disabled = true;
  button.textContent = '核验中…';
  result.className = 'result-box';
  result.textContent = '正在通过受控代理连续核验最终出口…';
  try {
    const data = await api('/api/preflight', { method: 'POST' });
    result.className = 'result-box pass';
    result.textContent = `出口核验通过：连续 ${data.probes.length} 次均为 ${data.expectedExitIp}，时区 ${data.currentTimeZone}。此结果不代表 Claude 会话正在运行。`;
  } catch (error) {
    result.className = 'result-box fail';
    result.textContent = `未通过：${error.data?.failures?.join('；') || error.message}`;
  } finally {
    button.disabled = false;
    button.textContent = '执行出口核验';
    try {
      renderStatus(await api('/api/status'));
      renderAudit(await api('/api/audit'));
    } catch {}
  }
});

async function initialize() {
  try {
    token = await globalThis.HongAiDashboardSession?.resolveToken() || '';
    await load();
  } catch (error) {
    byId('preflightResult').textContent = `控制台认证失败：${error.message}`;
    byId('preflightResult').className = 'result-box fail';
  }
}

initialize();
