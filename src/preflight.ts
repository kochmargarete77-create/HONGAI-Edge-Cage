import { connect } from 'node:net';
import { ProxyAgent, fetch } from 'undici';
import type { CustomerConfig } from './config.js';
import { configuredPlatformMatchesHost } from './config.js';

export interface ProbeResult {
  attempt: number;
  exitIp?: string;
  elapsedMs: number;
  ok: boolean;
  error?: string;
}

export interface PreflightResult {
  ok: boolean;
  proxyListener: boolean;
  platformMatches: boolean;
  expectedExitIp: string;
  observedExitIps: string[];
  stableExit: boolean;
  timeZoneMatches: boolean;
  currentTimeZone: string;
  probes: ProbeResult[];
  failures: string[];
}

function currentTimeZone(): string {
  return Intl.DateTimeFormat().resolvedOptions().timeZone;
}

async function testTcpListener(proxyUrl: string): Promise<boolean> {
  const url = new URL(proxyUrl);
  const port = Number(url.port || (url.protocol === 'https:' ? 443 : 80));

  return await new Promise<boolean>((resolve) => {
    const socket = connect({ host: url.hostname, port });
    const finish = (value: boolean) => {
      socket.removeAllListeners();
      socket.destroy();
      resolve(value);
    };
    socket.setTimeout(2500);
    socket.once('connect', () => finish(true));
    socket.once('timeout', () => finish(false));
    socket.once('error', () => finish(false));
  });
}

export async function probeExit(proxyUrl: string, attempt: number): Promise<ProbeResult> {
  const started = performance.now();
  const dispatcher = new ProxyAgent(proxyUrl);

  try {
    const response = await fetch('https://api.ipify.org', {
      dispatcher,
      signal: AbortSignal.timeout(10_000),
      headers: {
        'user-agent': 'HONG-AI-Edge-Cage/0.1'
      }
    });
    if (!response.ok) {
      throw new Error(`Exit probe returned HTTP ${response.status}.`);
    }
    const exitIp = (await response.text()).trim();
    return {
      attempt,
      exitIp,
      elapsedMs: Math.round(performance.now() - started),
      ok: true
    };
  } catch (error) {
    return {
      attempt,
      elapsedMs: Math.round(performance.now() - started),
      ok: false,
      error: error instanceof Error ? error.message : String(error)
    };
  } finally {
    await dispatcher.close();
  }
}

export async function runPreflight(config: CustomerConfig): Promise<PreflightResult> {
  const platformMatches = configuredPlatformMatchesHost(config);
  const proxyListener = await testTcpListener(config.network.localProxyUrl);
  const probes: ProbeResult[] = [];

  if (proxyListener && platformMatches) {
    for (let attempt = 1; attempt <= config.network.preflightAttempts; attempt += 1) {
      probes.push(await probeExit(config.network.localProxyUrl, attempt));
    }
  }

  const observedExitIps = probes
    .map((probe) => probe.exitIp)
    .filter((value): value is string => Boolean(value));
  const uniqueExitIps = [...new Set(observedExitIps)];
  const stableExit = (
    observedExitIps.length === config.network.preflightAttempts &&
    uniqueExitIps.length === 1 &&
    uniqueExitIps[0] === config.network.expectedExit.ipv4
  );
  const detectedTimeZone = currentTimeZone();
  const timeZoneMatches = detectedTimeZone === config.network.expectedExit.timeZone;
  const failures: string[] = [];

  if (!platformMatches) {
    failures.push('Configured platform does not match this host.');
  }
  if (!proxyListener) {
    failures.push('Local Clash proxy is not listening.');
  }
  if (!stableExit) {
    failures.push('Observed proxy exit is unavailable, unstable, or different from expectedExit.ipv4.');
  }
  if (!timeZoneMatches) {
    failures.push('System time zone does not match the configured exit time zone.');
  }

  return {
    ok: failures.length === 0,
    proxyListener,
    platformMatches,
    expectedExitIp: config.network.expectedExit.ipv4,
    observedExitIps,
    stableExit,
    timeZoneMatches,
    currentTimeZone: detectedTimeZone,
    probes,
    failures
  };
}
