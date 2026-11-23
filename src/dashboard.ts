import { randomBytes } from 'node:crypto';
import { createReadStream } from 'node:fs';
import { access } from 'node:fs/promises';
import { createServer, type IncomingMessage, type Server, type ServerResponse } from 'node:http';
import { dirname, extname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { spawn } from 'node:child_process';
import type { CustomerConfig } from './config.js';
import {
  appendAuditEvent as appendAuditEventDefault,
  readAuditEvents as readAuditEventsDefault,
  verifyAuditChain
} from './audit.js';
import { runPreflight as runPreflightDefault, type PreflightResult } from './preflight.js';

const mimeTypes: Record<string, string> = {
  '.html': 'text/html; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.js': 'text/javascript; charset=utf-8',
  '.svg': 'image/svg+xml'
};

interface DashboardState {
  lastPreflight: PreflightResult | null;
  lastPreflightAt: string | null;
}

export interface DashboardServerOptions {
  port?: number;
  token?: string;
  uiRoot?: string;
  runPreflight?: typeof runPreflightDefault;
  appendAuditEvent?: typeof appendAuditEventDefault;
  readAuditEvents?: typeof readAuditEventsDefault;
}

export interface DashboardServerHandle {
  port: number;
  token: string;
  url: string;
  close: () => Promise<void>;
}

function defaultUiRoot(): string {
  return resolve(dirname(fileURLToPath(import.meta.url)), '..', '..', 'ui');
}

function setSecurityHeaders(response: ServerResponse): void {
  response.setHeader('Cache-Control', 'no-store');
  response.setHeader('X-Content-Type-Options', 'nosniff');
  response.setHeader('X-Frame-Options', 'DENY');
  response.setHeader('Referrer-Policy', 'no-referrer');
  response.setHeader(
    'Content-Security-Policy',
    "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'"
  );
}

function isLoopbackHost(request: IncomingMessage): boolean {
  const host = request.headers.host ?? '';
  return /^(127\.0\.0\.1|localhost|\[::1\])(?::\d+)?$/i.test(host);
}

function sendJson(response: ServerResponse, status: number, body: unknown): void {
  if (response.writableEnded) return;
  setSecurityHeaders(response);
  response.statusCode = status;
  response.setHeader('Content-Type', 'application/json; charset=utf-8');
  response.end(`${JSON.stringify(body)}\n`);
}

function closeServer(server: Server): Promise<void> {
  if (!server.listening) return Promise.resolve();
  return new Promise((resolveClose, reject) => {
    server.close((error) => {
      if (error) reject(error);
      else resolveClose();
    });
  });
}

export function openVisibleBrowser(
  url: string,
  spawnProcess: typeof spawn = spawn,
  onError: (error: Error) => void = (error) => {
    console.error(`Dashboard browser launch failed: ${error.message}`);
    console.error(`Open this private local URL manually: ${url}`);
  }
): void {
  const command = process.platform === 'win32'
    ? { file: 'rundll32.exe', args: ['url.dll,FileProtocolHandler', url] }
    : process.platform === 'darwin'
      ? { file: 'open', args: [url] }
      : { file: 'xdg-open', args: [url] };
  try {
    const child = spawnProcess(command.file, command.args, {
      detached: true,
      stdio: 'ignore',
      windowsHide: false
    });
    child.once('error', onError);
    child.unref();
  } catch (error) {
    onError(error instanceof Error ? error : new Error(String(error)));
  }
}

function serveStaticAsset(response: ServerResponse, assetPath: string): void {
  const stream = createReadStream(assetPath);
  let opened = false;
  stream.once('open', () => {
    opened = true;
    setSecurityHeaders(response);
    response.statusCode = 200;
    response.setHeader('Content-Type', mimeTypes[extname(assetPath)] ?? 'application/octet-stream');
    stream.pipe(response);
  });
  stream.once('error', (error) => {
    if (!opened && !response.headersSent) {
      sendJson(response, 500, { ok: false, error: 'Dashboard asset is unavailable.' });
    } else if (!response.writableEnded) {
      response.destroy(error);
    }
  });
}

export async function createDashboardServer(
  config: CustomerConfig,
  options: DashboardServerOptions = {}
): Promise<DashboardServerHandle> {
  const token = options.token ?? randomBytes(32).toString('base64url');
  const root = options.uiRoot ?? defaultUiRoot();
  const runPreflight = options.runPreflight ?? runPreflightDefault;
  const appendAuditEvent = options.appendAuditEvent ?? appendAuditEventDefault;
  const readAuditEvents = options.readAuditEvents ?? readAuditEventsDefault;
  const state: DashboardState = { lastPreflight: null, lastPreflightAt: null };
  await access(join(root, 'index.html'));

  const server = createServer(async (request, response) => {
    try {
      if (!isLoopbackHost(request)) {
        sendJson(response, 421, { ok: false, error: 'Loopback host required.' });
        return;
      }
      const url = new URL(request.url ?? '/', 'http://127.0.0.1');
      if (url.pathname.startsWith('/api/')) {
        if (request.headers.authorization !== `Bearer ${token}`) {
          sendJson(response, 401, { ok: false, error: 'Unauthorized.' });
          return;
        }
        if (request.method === 'GET' && url.pathname === '/api/status') {
          const events = await readAuditEvents(config);
          const observedExitIps = state.lastPreflight?.observedExitIps ?? [];
          sendJson(response, 200, {
            ok: true,
            product: 'HONG AI Edge Cage',
            version: '0.2.0-alpha.2',
            environment: config.environment,
            platform: config.platform.strategy,
            workspace: config.workspace.path,
            expectedExit: config.network.expectedExit,
            scoreGate: config.assessment.minimumScore,
            controller: {
              state: 'CONFIGURED',
              meaning: 'Policy loaded; this is not evidence that a Claude session is currently running.'
            },
            runtime: {
              state: 'NOT_OBSERVED',
              activeSession: null,
              meaning: 'The dashboard is not connected to launcher lifecycle telemetry.'
            },
            verification: {
              state: state.lastPreflight === null
                ? 'NOT_TESTED'
                : state.lastPreflight.ok ? 'VERIFIED' : 'FAILED',
              observedExitIp: observedExitIps.at(-1) ?? null,
              observedExitIps,
              checkedAt: state.lastPreflightAt
            },
            policy: {
              state: 'CONFIGURED',
              directInternet: 'DENY_WHEN_SANDBOX_RUNNING',
              localNetwork: 'DENY_WHEN_SANDBOX_RUNNING',
              hostClaudeState: 'ISOLATE_WHEN_SANDBOX_RUNNING',
              hostBrowserState: 'DENY_WHEN_SANDBOX_RUNNING',
              softwareFingerprint: 'PROCESS_ISOLATION_POLICY',
              hardwareFingerprint: 'HOST_VISIBLE_IN_PROCESS_MODE',
              watchdog: `${config.network.watchdogIntervalSeconds}s / ${config.network.watchdogFailureLimit} failures`
            },
            audit: { events: events.length, chainValid: verifyAuditChain(events) }
          });
          return;
        }
        if (request.method === 'POST' && url.pathname === '/api/preflight') {
          const result = await runPreflight(config);
          await appendAuditEvent(config, 'PREFLIGHT_COMPLETED', 'operator', {
            ok: result.ok,
            observedExitIps: result.observedExitIps,
            stableExit: result.stableExit,
            timeZoneMatches: result.timeZoneMatches,
            failures: result.failures
          });
          state.lastPreflight = result;
          state.lastPreflightAt = new Date().toISOString();
          sendJson(response, result.ok ? 200 : 409, result);
          return;
        }
        if (request.method === 'GET' && url.pathname === '/api/audit') {
          const events = await readAuditEvents(config);
          sendJson(response, 200, {
            ok: verifyAuditChain(events),
            events: events.slice(-50).reverse()
          });
          return;
        }
        sendJson(response, 404, { ok: false, error: 'Not found.' });
        return;
      }

      const asset = url.pathname === '/'
        ? 'index.html'
        : url.pathname.replace(/^\//, '');
      if (!['index.html', 'styles.css', 'app.js', 'session-token.js'].includes(asset)) {
        sendJson(response, 404, { ok: false, error: 'Not found.' });
        return;
      }
      serveStaticAsset(response, join(root, asset));
    } catch (error) {
      sendJson(response, 500, {
        ok: false,
        error: error instanceof Error ? error.message : String(error)
      });
    }
  });

  await new Promise<void>((resolveListen, reject) => {
    server.once('error', reject);
    server.listen(options.port ?? 0, '127.0.0.1', resolveListen);
  });
  const address = server.address();
  if (!address || typeof address === 'string') {
    await closeServer(server).catch(() => {});
    throw new Error('Dashboard did not receive a TCP port.');
  }

  try {
    await appendAuditEvent(config, 'DASHBOARD_STARTED', 'controller', { port: address.port });
  } catch (error) {
    await closeServer(server).catch(() => {});
    throw error;
  }

  return {
    port: address.port,
    token,
    url: `http://127.0.0.1:${address.port}/#token=${token}`,
    close: async () => closeServer(server)
  };
}

export async function startDashboard(config: CustomerConfig): Promise<void> {
  const dashboard = await createDashboardServer(config);
  console.log(`HONG AI Edge Cage dashboard: http://127.0.0.1:${dashboard.port}/`);
  if (process.env.EDGE_CAGE_NO_BROWSER !== '1') {
    openVisibleBrowser(dashboard.url);
  }

  let signalHandler: (() => void) | undefined;
  try {
    await new Promise<void>((resolveSignal) => {
      signalHandler = resolveSignal;
      process.once('SIGINT', signalHandler);
      process.once('SIGTERM', signalHandler);
    });
  } finally {
    if (signalHandler) {
      process.off('SIGINT', signalHandler);
      process.off('SIGTERM', signalHandler);
    }
    await dashboard.close();
  }
}
