import assert from 'node:assert/strict';
import { EventEmitter } from 'node:events';
import { mkdir, mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { request as httpRequest } from 'node:http';
import { createServer as createTcpServer } from 'node:net';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import test from 'node:test';
import vm from 'node:vm';
import type { ChildProcess, spawn } from 'node:child_process';
import { customerConfigSchema, type CustomerConfig } from '../src/config.js';
import {
  createDashboardServer,
  openVisibleBrowser
} from '../src/dashboard.js';
import type { PreflightResult } from '../src/preflight.js';

const projectRoot = resolve(dirname(fileURLToPath(import.meta.url)), '..', '..');
const tempBase = resolve(projectRoot, '.tmp');

async function testRoot(): Promise<string> {
  await mkdir(tempBase, { recursive: true });
  return await mkdtemp(join(tempBase, 'dashboard-test-'));
}

function testConfig(root: string): CustomerConfig {
  return customerConfigSchema.parse({
    schemaVersion: 1,
    environment: { id: 'dashboard-test', displayName: 'Dashboard Test' },
    platform: { strategy: 'auto' },
    workspace: {
      path: resolve(root, 'workspace'),
      stateRoot: resolve(root, 'state'),
      stateMode: 'isolated-persistent'
    },
    network: {
      localProxyUrl: 'http://127.0.0.1:7897',
      expectedExit: {
        ipv4: '203.0.113.10',
        countryCode: 'US',
        timeZone: 'America/Los_Angeles'
      },
      preflightAttempts: 3,
      watchdogIntervalSeconds: 30,
      watchdogFailureLimit: 2,
      failClosed: true,
      strictAllowlist: true,
      allowedDomains: ['api.anthropic.com'],
      deniedDomains: []
    },
    chain: {
      clashProfileName: 'test',
      frontGroupName: 'front',
      preferredFrontNode: 'node',
      landing: {
        type: 'socks5',
        host: '203.0.113.10',
        port: 1080,
        usernameSecretRef: 'EDGE_USER',
        passwordSecretRef: 'EDGE_PASS'
      }
    },
    filesystem: {
      denyRead: [],
      allowRead: ['${WORKSPACE}', '${AGENT_STATE}', '${INSTALL_ROOT}'],
      allowWrite: ['${WORKSPACE}', '${AGENT_STATE}'],
      denyWrite: []
    },
    runtime: {
      isolationTier: 'process',
      claudeCommand: 'bundled-official',
      sandboxEngine: 'anthropic-srt',
      requireOfficialClaude: true,
      allowUnsandboxedCommands: false,
      failIfSandboxUnavailable: true
    },
    assessment: {
      minimumScore: 90,
      reportBrand: 'HONG AI',
      runBeforeDelivery: true
    }
  });
}

const successfulPreflight: PreflightResult = {
  ok: true,
  proxyListener: true,
  platformMatches: true,
  expectedExitIp: '203.0.113.10',
  observedExitIps: ['203.0.113.10', '203.0.113.10', '203.0.113.10'],
  stableExit: true,
  timeZoneMatches: true,
  currentTimeZone: 'America/Los_Angeles',
  probes: [1, 2, 3].map((attempt) => ({
    attempt,
    exitIp: '203.0.113.10',
    elapsedMs: 10,
    ok: true
  })),
  failures: []
};

function memoryStorage() {
  const values = new Map<string, string>();
  return {
    getItem: (key: string) => values.get(key) ?? null,
    setItem: (key: string, value: string) => { values.set(key, value); },
    removeItem: (key: string) => { values.delete(key); },
    clear: () => values.clear()
  };
}

async function loadTokenResolver(
  hash: string,
  storage: ReturnType<typeof memoryStorage>,
  exchangedToken = 'tab-session-token'
) {
  const source = await readFile(resolve(projectRoot, 'ui', 'session-token.js'), 'utf8');
  const location = { hash, pathname: '/', search: '' };
  let replacement = '';
  let exchanges = 0;
  const context = vm.createContext({
    URLSearchParams,
    fetch: async (_path: string, init: RequestInit) => {
      exchanges += 1;
      assert.equal(init.headers && (init.headers as Record<string, string>).Authorization, 'Bearer one-time-dashboard-token');
      return Response.json({ ok: true, sessionToken: exchangedToken });
    },
    location,
    sessionStorage: storage,
    history: {
      replaceState: (_state: unknown, _title: string, value: string) => {
        replacement = value;
        location.hash = '';
      }
    }
  });
  new vm.Script(source).runInContext(context);
  const session = (context as unknown as {
    HongAiDashboardSession: { resolveToken: () => Promise<string>; clearToken: () => void; storageKey: string };
  }).HongAiDashboardSession;
  return {
    token: await session.resolveToken(),
    clearToken: session.clearToken,
    replacement,
    storageKey: session.storageKey,
    exchanges
  };
}

async function freePort(): Promise<number> {
  const probe = createTcpServer();
  await new Promise<void>((resolveListen, reject) => {
    probe.once('error', reject);
    probe.listen(0, '127.0.0.1', resolveListen);
  });
  const address = probe.address();
  assert.ok(address && typeof address !== 'string');
  await new Promise<void>((resolveClose) => probe.close(() => resolveClose()));
  return address.port;
}

async function rawStatusWithHost(port: number, host: string, authorization: string): Promise<number> {
  return await new Promise<number>((resolveStatus, reject) => {
    const request = httpRequest({
      hostname: '127.0.0.1',
      port,
      path: '/api/status',
      method: 'GET',
      headers: { Host: host, Authorization: authorization }
    }, (response) => {
      response.resume();
      response.once('end', () => resolveStatus(response.statusCode ?? 0));
    });
    request.once('error', reject);
    request.end();
  });
}

test('dashboard exchanges a short-lived bootstrap and keeps only the tab session token', async () => {
  const sameTabStorage = memoryStorage();
  const firstLoad = await loadTokenResolver('#token=one-time-dashboard-token', sameTabStorage);
  assert.equal(firstLoad.token, 'tab-session-token');
  assert.equal(firstLoad.replacement, '/');
  assert.equal(firstLoad.exchanges, 1);

  const reload = await loadTokenResolver('', sameTabStorage);
  assert.equal(reload.token, 'tab-session-token');
  assert.equal(reload.exchanges, 0);

  const newTab = await loadTokenResolver('', memoryStorage());
  assert.equal(newTab.token, '');

  const staleStorage = memoryStorage();
  staleStorage.setItem(firstLoad.storageKey, 'stale-session-token');
  const restartedServer = await loadTokenResolver('#token=one-time-dashboard-token', staleStorage, 'replacement-session-token');
  assert.equal(restartedServer.token, 'replacement-session-token');
  assert.equal(restartedServer.exchanges, 1);
  assert.equal(staleStorage.getItem(firstLoad.storageKey), 'replacement-session-token');
  restartedServer.clearToken();
  assert.equal(staleStorage.getItem(firstLoad.storageKey), null);
});

test('dashboard markup labels configured, expected and observed states without claiming ACTIVE', async () => {
  const markup = await readFile(resolve(projectRoot, 'ui', 'index.html'), 'utf8');
  assert.doesNotMatch(markup, /Claude 已进入受控空间/);
  assert.doesNotMatch(markup, />\s*ACTIVE\s*</);
  assert.match(markup, /id="expectedExitIp"/);
  assert.match(markup, /id="observedExitIp"/);
  assert.match(markup, /id="runtimeState"/);
  assert.match(markup, /src="\/session-token\.js"/);
});

test('dashboard distinguishes configured policy, runtime telemetry and observed exit', async () => {
  const root = await testRoot();
  const config = testConfig(root);
  const bootstrapToken = 'dashboard-test-bootstrap-token-00000001';
  const dashboard = await createDashboardServer(config, {
    token: bootstrapToken,
    runPreflight: async () => successfulPreflight
  });
  const bootstrapCannotCallApi = await fetch(`http://127.0.0.1:${dashboard.port}/api/status`, {
    headers: { Authorization: `Bearer ${bootstrapToken}` }
  });
  assert.equal(bootstrapCannotCallApi.status, 401);
  const exchange = await fetch(`http://127.0.0.1:${dashboard.port}/api/session`, {
    method: 'POST',
    headers: { Authorization: `Bearer ${bootstrapToken}` }
  });
  assert.equal(exchange.status, 200);
  const { sessionToken } = await exchange.json() as { sessionToken: string };
  const request = async (path: string, init: RequestInit = {}) => fetch(
    `http://127.0.0.1:${dashboard.port}${path}`,
    {
      ...init,
      headers: { Authorization: `Bearer ${sessionToken}`, ...init.headers }
    }
  );
  try {
    const unauthorized = await fetch(`http://127.0.0.1:${dashboard.port}/api/status`);
    assert.equal(unauthorized.status, 401);
    const replay = await fetch(`http://127.0.0.1:${dashboard.port}/api/session`, {
      method: 'POST',
      headers: { Authorization: `Bearer ${bootstrapToken}` }
    });
    assert.equal(replay.status, 200);
    assert.equal((await replay.json() as { sessionToken: string }).sessionToken, sessionToken);

    const invalidHostStatus = await rawStatusWithHost(
      dashboard.port,
      'dashboard.attacker.invalid',
      `Bearer ${sessionToken}`
    );
    assert.equal(invalidHostStatus, 421);

    const initialResponse = await request('/api/status');
    assert.equal(initialResponse.status, 200);
    const initial = await initialResponse.json() as {
      controller: { state: string };
      runtime: { state: string; activeSession: unknown };
      verification: { state: string; observedExitIp: string | null };
      expectedExit: { ipv4: string };
    };
    assert.equal(initial.controller.state, 'CONFIGURED');
    assert.equal(initial.runtime.state, 'NOT_OBSERVED');
    assert.equal(initial.runtime.activeSession, null);
    assert.equal(initial.expectedExit.ipv4, '203.0.113.10');
    assert.equal(initial.verification.state, 'NOT_TESTED');
    assert.equal(initial.verification.observedExitIp, null);

    const preflight = await request('/api/preflight', { method: 'POST' });
    assert.equal(preflight.status, 200);
    const verifiedResponse = await request('/api/status');
    const verified = await verifiedResponse.json() as {
      runtime: { state: string };
      verification: { state: string; observedExitIp: string | null };
    };
    assert.equal(verified.runtime.state, 'NOT_OBSERVED');
    assert.equal(verified.verification.state, 'VERIFIED');
    assert.equal(verified.verification.observedExitIp, '203.0.113.10');
  } finally {
    await dashboard.close();
    await rm(root, { recursive: true, force: true });
  }
});

test('browser launcher reports asynchronous spawn errors without an unhandled error event', () => {
  const child = new EventEmitter() as ChildProcess;
  child.unref = () => child;
  const errors: Error[] = [];
  openVisibleBrowser(
    'http://127.0.0.1/#token=test',
    (() => child) as unknown as typeof spawn,
    (error) => errors.push(error)
  );
  assert.doesNotThrow(() => child.emit('error', new Error('launcher missing')));
  assert.equal(errors[0]?.message, 'launcher missing');
});

test('dashboard closes its listener when startup audit persistence fails', async () => {
  const root = await testRoot();
  const port = await freePort();
  const config = testConfig(root);
  try {
    await assert.rejects(
      createDashboardServer(config, {
        port,
        appendAuditEvent: async () => { throw new Error('audit disk unavailable'); }
      }),
      /audit disk unavailable/
    );

    const replacement = createTcpServer();
    await new Promise<void>((resolveListen, reject) => {
      replacement.once('error', reject);
      replacement.listen(port, '127.0.0.1', resolveListen);
    });
    await new Promise<void>((resolveClose) => replacement.close(() => resolveClose()));
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test('missing static assets return a controlled response instead of crashing the server', async () => {
  const root = await testRoot();
  const uiRoot = resolve(root, 'ui');
  await mkdir(uiRoot, { recursive: true });
  await writeFile(resolve(uiRoot, 'index.html'), '<!doctype html><title>test</title>', 'utf8');
  const dashboard = await createDashboardServer(testConfig(root), {
    token: 'asset-test-bootstrap-token-0000000001',
    uiRoot
  });
  try {
    const response = await fetch(`http://127.0.0.1:${dashboard.port}/styles.css`);
    assert.equal(response.status, 500);
    assert.deepEqual(await response.json(), {
      ok: false,
      error: 'Dashboard asset is unavailable.'
    });

    const exchange = await fetch(`http://127.0.0.1:${dashboard.port}/api/session`, {
      method: 'POST',
      headers: { Authorization: 'Bearer asset-test-bootstrap-token-0000000001' }
    });
    const { sessionToken } = await exchange.json() as { sessionToken: string };
    const status = await fetch(`http://127.0.0.1:${dashboard.port}/api/status`, {
      headers: { Authorization: `Bearer ${sessionToken}` }
    });
    assert.equal(status.status, 200);
  } finally {
    await dashboard.close();
    await rm(root, { recursive: true, force: true });
  }
});

test('dashboard expires the bootstrap retry window without revoking its session', async () => {
  const root = await testRoot();
  const bootstrapToken = 'expiry-test-bootstrap-token-000000001';
  const dashboard = await createDashboardServer(testConfig(root), {
    token: bootstrapToken,
    bootstrapRetryWindowMs: 5
  });
  try {
    const exchange = await fetch(`http://127.0.0.1:${dashboard.port}/api/session`, {
      method: 'POST',
      headers: { Authorization: `Bearer ${bootstrapToken}` }
    });
    const { sessionToken } = await exchange.json() as { sessionToken: string };
    await new Promise((resolveWait) => setTimeout(resolveWait, 20));
    const expiredBootstrap = await fetch(`http://127.0.0.1:${dashboard.port}/api/session`, {
      method: 'POST',
      headers: { Authorization: `Bearer ${bootstrapToken}` }
    });
    assert.equal(expiredBootstrap.status, 401);
    const existingSession = await fetch(`http://127.0.0.1:${dashboard.port}/api/status`, {
      headers: { Authorization: `Bearer ${sessionToken}` }
    });
    assert.equal(existingSession.status, 200);
  } finally {
    await dashboard.close();
    await rm(root, { recursive: true, force: true });
  }
});
