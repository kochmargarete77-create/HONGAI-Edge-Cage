import { createRequire } from 'node:module';
import { dirname, join, resolve } from 'node:path';
import { isAbsolute, relative } from 'node:path';
import { mkdir, mkdtemp, rm, writeFile } from 'node:fs/promises';
import { spawn } from 'node:child_process';
import type { CustomerConfig } from './config.js';
import { renderSandboxPolicy } from './policy.js';
import { probeExit, runPreflight, type PreflightResult } from './preflight.js';

export interface LaunchResult {
  exitCode: number;
  preflight: PreflightResult;
  policyPath: string;
}

export interface PreparedEnvironment {
  policyPath: string;
  claudeConfigDir: string;
  homeDir: string;
  tempDir: string;
  agentStateRoot: string;
  cacheDir: string;
  configDir: string;
  dataDir: string;
  appDataDir: string;
  localAppDataDir: string;
  cleanup: () => Promise<void>;
}

export interface SandboxSmokeResult {
  ok: boolean;
  exitCode: number;
  output: string;
  errorOutput: string;
}

function monitorExit(
  config: CustomerConfig,
  onFailureLimit: (message: string) => void
): () => void {
  let failures = 0;
  let running = false;
  const timer = setInterval(async () => {
    if (running) {
      return;
    }
    running = true;
    try {
      const probe = await probeExit(config.network.localProxyUrl, 0);
      if (probe.ok && probe.exitIp === config.network.expectedExit.ipv4) {
        failures = 0;
      } else {
        failures += 1;
      }
      if (failures >= config.network.watchdogFailureLimit) {
        onFailureLimit(
          `Final exit failed ${failures} consecutive watchdog checks; expected ` +
          `${config.network.expectedExit.ipv4}, last observed ${probe.exitIp ?? 'unavailable'}.`
        );
      }
    } finally {
      running = false;
    }
  }, config.network.watchdogIntervalSeconds * 1000);
  timer.unref();
  return () => clearInterval(timer);
}

function sandboxRuntimeCliPath(): string {
  const require = createRequire(import.meta.url);
  const entry = require.resolve('@anthropic-ai/sandbox-runtime');
  return join(dirname(entry), 'cli.js');
}

function officialClaudeCliPath(): string {
  const require = createRequire(import.meta.url);
  const packageJsonPath = require.resolve('@anthropic-ai/claude-code/package.json');
  return join(dirname(packageJsonPath), 'bin', process.platform === 'win32' ? 'claude.exe' : 'claude');
}

export function buildSandboxEnvironment(
  config: CustomerConfig,
  prepared: PreparedEnvironment,
  hostEnvironment: NodeJS.ProcessEnv = process.env
): NodeJS.ProcessEnv {
  const environment: NodeJS.ProcessEnv = {};
  const inheritedKeys = process.platform === 'win32'
    ? ['SystemRoot', 'WINDIR', 'ComSpec', 'PATHEXT', 'TERM', 'COLORTERM']
    : ['SHELL', 'TERM', 'COLORTERM'];
  for (const key of inheritedKeys) {
    if (hostEnvironment[key]) environment[key] = hostEnvironment[key];
  }
  const pathValue = hostEnvironment.Path ?? hostEnvironment.PATH;
  if (pathValue) environment.PATH = pathValue;

  return {
    ...environment,
    CLAUDE_CONFIG_DIR: prepared.claudeConfigDir,
    HOME: prepared.homeDir,
    USERPROFILE: prepared.homeDir,
    APPDATA: prepared.appDataDir,
    LOCALAPPDATA: prepared.localAppDataDir,
    XDG_CACHE_HOME: prepared.cacheDir,
    XDG_CONFIG_HOME: prepared.configDir,
    XDG_DATA_HOME: prepared.dataDir,
    NPM_CONFIG_CACHE: resolve(prepared.cacheDir, 'npm'),
    NPM_CONFIG_USERCONFIG: resolve(prepared.configDir, 'npmrc'),
    GIT_CONFIG_GLOBAL: resolve(prepared.configDir, 'gitconfig'),
    GIT_CONFIG_NOSYSTEM: '1',
    GNUPGHOME: resolve(prepared.configDir, 'gnupg'),
    TMPDIR: prepared.tempDir,
    TEMP: prepared.tempDir,
    TMP: prepared.tempDir,
    TZ: config.network.expectedExit.timeZone,
    LANG: 'en_US.UTF-8',
    LC_ALL: 'en_US.UTF-8',
    CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC: '1',
    ENABLE_CLAUDEAI_MCP_SERVERS: 'false',
    CLAUDE_CODE_DISABLE_ARTIFACT: '1',
    // The customer payload is a version-pinned, integrity-checked offline
    // distribution. Prevent the upstream binary from replacing itself outside
    // the HONG AI release and rollback transaction.
    DISABLE_UPDATES: '1',
    DISABLE_INSTALLATION_CHECKS: '1',
    DISABLE_TELEMETRY: '1',
    DISABLE_ERROR_REPORTING: '1',
    DO_NOT_TRACK: '1',
    CLAUDE_CODE_PLUGIN_PREFER_HTTPS: '1'
  };
}

export async function prepareEnvironment(config: CustomerConfig): Promise<PreparedEnvironment> {
  await mkdir(config.workspace.stateRoot, { recursive: true });
  let sessionRoot = config.workspace.stateRoot;
  let cleanup = async (): Promise<void> => {};
  if (config.workspace.stateMode === 'ephemeral') {
    const sessionsRoot = resolve(config.workspace.stateRoot, 'sessions');
    await mkdir(sessionsRoot, { recursive: true });
    sessionRoot = await mkdtemp(join(sessionsRoot, 'session-'));
    cleanup = async () => {
      const childPath = relative(config.workspace.stateRoot, sessionRoot);
      if (!childPath || childPath.startsWith('..') || isAbsolute(childPath)) {
        throw new Error('Refusing to remove an ephemeral session outside the configured state root.');
      }
      await rm(sessionRoot, { recursive: true, force: true });
    };
  }

  const policyPath = resolve(sessionRoot, 'policy', 'srt-settings.json');
  const agentStateRoot = resolve(sessionRoot, 'agent');
  const claudeConfigDir = resolve(agentStateRoot, 'claude');
  const homeDir = resolve(agentStateRoot, 'home');
  const tempDir = resolve(agentStateRoot, 'tmp');
  const cacheDir = resolve(agentStateRoot, 'cache');
  const configDir = resolve(agentStateRoot, 'config');
  const dataDir = resolve(agentStateRoot, 'data');
  const appDataDir = resolve(agentStateRoot, 'appdata', 'roaming');
  const localAppDataDir = resolve(agentStateRoot, 'appdata', 'local');

  await Promise.all([
    mkdir(dirname(policyPath), { recursive: true }),
    mkdir(claudeConfigDir, { recursive: true }),
    mkdir(homeDir, { recursive: true }),
    mkdir(tempDir, { recursive: true }),
    mkdir(cacheDir, { recursive: true }),
    mkdir(configDir, { recursive: true }),
    mkdir(dataDir, { recursive: true }),
    mkdir(appDataDir, { recursive: true }),
    mkdir(localAppDataDir, { recursive: true }),
    mkdir(config.workspace.path, { recursive: true })
  ]);

  const policy = renderSandboxPolicy(config, agentStateRoot);
  await writeFile(policyPath, `${JSON.stringify(policy, null, 2)}\n`, {
    encoding: 'utf8',
    mode: 0o600
  });

  return {
    policyPath,
    claudeConfigDir,
    homeDir,
    tempDir,
    agentStateRoot,
    cacheDir,
    configDir,
    dataDir,
    appDataDir,
    localAppDataDir,
    cleanup
  };
}

export async function smokeTestSandbox(
  config: CustomerConfig,
  prepared: PreparedEnvironment
): Promise<SandboxSmokeResult> {
  const srtCli = sandboxRuntimeCliPath();
  const hostProfile = process.env.USERPROFILE ?? process.env.HOME ?? '';
  const probeScript = [
    "const fs=require('node:fs');const net=require('node:net');const path=require('node:path');",
    "let readBlocked=false,writeAllowed=false,networkBlocked=false;",
    "try{fs.readdirSync(process.env.EDGE_CAGE_FORBIDDEN_PROBE)}catch{readBlocked=true}",
    "try{const p=path.join(process.env.TEMP,'edge-cage-smoke.tmp');fs.writeFileSync(p,'ok');fs.unlinkSync(p);writeAllowed=true}catch{}",
    "const done=()=>{const ok=readBlocked&&writeAllowed&&networkBlocked;process.stdout.write(JSON.stringify({ok,readBlocked,writeAllowed,networkBlocked}));process.exit(ok?0:1)};",
    "const socket=net.connect({host:'1.1.1.1',port:443});",
    "socket.setTimeout(2000);socket.once('connect',()=>{socket.destroy();networkBlocked=false;done()});",
    "socket.once('error',()=>{networkBlocked=true;done()});socket.once('timeout',()=>{socket.destroy();networkBlocked=true;done()});"
  ].join('');
  const environment = {
    ...buildSandboxEnvironment(config, prepared),
    EDGE_CAGE_FORBIDDEN_PROBE: hostProfile
  };
  const args = [
    srtCli,
    '--settings',
    prepared.policyPath,
    '--',
    process.execPath,
    '-e',
    probeScript
  ];

  return await new Promise<SandboxSmokeResult>((resolveResult) => {
    const child = spawn(process.execPath, args, {
      cwd: config.workspace.path,
      env: environment,
      stdio: ['ignore', 'pipe', 'pipe'],
      windowsHide: true
    });
    let output = '';
    let errorOutput = '';
    child.stdout.setEncoding('utf8');
    child.stderr.setEncoding('utf8');
    child.stdout.on('data', (chunk: string) => { output += chunk; });
    child.stderr.on('data', (chunk: string) => { errorOutput += chunk; });
    child.once('error', (error) => {
      resolveResult({ ok: false, exitCode: 1, output, errorOutput: `${errorOutput}${error.message}` });
    });
    child.once('exit', (code) => {
      resolveResult({ ok: code === 0, exitCode: code ?? 1, output: output.trim(), errorOutput: errorOutput.trim() });
    });
  });
}

export async function launchSandboxedClaude(
  config: CustomerConfig,
  claudeArguments: string[]
): Promise<LaunchResult> {
  const preflight = await runPreflight(config);
  if (!preflight.ok) {
    throw new Error(`Fail-closed preflight refused launch: ${preflight.failures.join(' ')}`);
  }

  const prepared = await prepareEnvironment(config);
  const srtCli = sandboxRuntimeCliPath();
  const claudeCli = officialClaudeCliPath();
  const childEnvironment = buildSandboxEnvironment(config, prepared);
  const srtArguments = [
    srtCli,
    '--settings',
    prepared.policyPath,
    '--',
    claudeCli,
    ...claudeArguments
  ];

  let exitCode: number;
  try {
    exitCode = await new Promise<number>((resolveExit, reject) => {
      const child = spawn(process.execPath, srtArguments, {
        cwd: config.workspace.path,
        env: childEnvironment,
        stdio: 'inherit',
        windowsHide: false
      });
      let watchdogMessage: string | undefined;
      const stopMonitor = monitorExit(config, (message) => {
        if (watchdogMessage) {
          return;
        }
        watchdogMessage = message;
        child.kill('SIGTERM');
      });
      child.once('error', (error) => {
        stopMonitor();
        reject(error);
      });
      child.once('exit', (code, signal) => {
        stopMonitor();
        if (watchdogMessage) {
          reject(new Error(`Fail-closed watchdog stopped Claude: ${watchdogMessage}`));
          return;
        }
        if (signal) {
          reject(new Error(`Sandboxed Claude terminated by signal ${signal}.`));
          return;
        }
        resolveExit(code ?? 1);
      });
    });
  } finally {
    await prepared.cleanup();
  }

  return {
    exitCode,
    preflight,
    policyPath: prepared.policyPath
  };
}
