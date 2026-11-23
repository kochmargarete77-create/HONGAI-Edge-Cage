import { randomBytes } from 'node:crypto';
import { createReadStream } from 'node:fs';
import { access } from 'node:fs/promises';
import { createServer, type IncomingMessage, type ServerResponse } from 'node:http';
import { dirname, extname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { spawn } from 'node:child_process';
import type { CustomerConfig } from './config.js';
import { appendAuditEvent, readAuditEvents, verifyAuditChain } from './audit.js';
import { runPreflight } from './preflight.js';

const mimeTypes: Record<string, string> = {
  '.html': 'text/html; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.js': 'text/javascript; charset=utf-8',
  '.svg': 'image/svg+xml'
};

function uiRoot(): string {
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
  setSecurityHeaders(response);
  response.statusCode = status;
  response.setHeader('Content-Type', 'application/json; charset=utf-8');
  response.end(`${JSON.stringify(body)}\n`);
}

function openVisibleBrowser(url: string): void {
  const command = process.platform === 'win32'
    ? { file: 'rundll32.exe', args: ['url.dll,FileProtocolHandler', url] }
    : process.platform === 'darwin'
      ? { file: 'open', args: [url] }
      : { file: 'xdg-open', args: [url] };
  const child = spawn(command.file, command.args, {
    detached: true,
    stdio: 'ignore',
    windowsHide: false
  });
  child.unref();
}

export async function startDashboard(config: CustomerConfig): Promise<void> {
  const token = randomBytes(32).toString('base64url');
  const root = uiRoot();
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
          sendJson(response, 200, {
            ok: true,
            product: 'HONG AI Edge Cage',
            version: '0.2.0-alpha.1',
            environment: config.environment,
            platform: config.platform.strategy,
            workspace: config.workspace.path,
            expectedExit: config.network.expectedExit,
            scoreGate: config.assessment.minimumScore,
            protection: {
              directInternet: 'DENIED',
              localNetwork: 'DENIED',
              hostClaudeState: 'ISOLATED',
              hostBrowserState: 'DENIED',
              softwareFingerprint: 'PROCESS_ISOLATED',
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
      if (!['index.html', 'styles.css', 'app.js'].includes(asset)) {
        sendJson(response, 404, { ok: false, error: 'Not found.' });
        return;
      }
      const assetPath = join(root, asset);
      setSecurityHeaders(response);
      response.statusCode = 200;
      response.setHeader('Content-Type', mimeTypes[extname(assetPath)] ?? 'application/octet-stream');
      createReadStream(assetPath).pipe(response);
    } catch (error) {
      sendJson(response, 500, {
        ok: false,
        error: error instanceof Error ? error.message : String(error)
      });
    }
  });

  await new Promise<void>((resolveListen, reject) => {
    server.once('error', reject);
    server.listen(0, '127.0.0.1', resolveListen);
  });
  const address = server.address();
  if (!address || typeof address === 'string') {
    throw new Error('Dashboard did not receive a TCP port.');
  }
  const url = `http://127.0.0.1:${address.port}/#token=${token}`;
  await appendAuditEvent(config, 'DASHBOARD_STARTED', 'controller', { port: address.port });
  console.log(`HONG AI Edge Cage dashboard: http://127.0.0.1:${address.port}/`);
  if (process.env.EDGE_CAGE_NO_BROWSER !== '1') {
    openVisibleBrowser(url);
  }

  await new Promise<void>((resolveClose) => {
    const close = () => server.close(() => resolveClose());
    process.once('SIGINT', close);
    process.once('SIGTERM', close);
  });
}
