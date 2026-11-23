import { isIP } from 'node:net';
import { posix, resolve, win32 } from 'node:path';
import { lstat, readFile, realpath } from 'node:fs/promises';
import { dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import YAML from 'yaml';
import { z } from 'zod';

const absolutePath = z.string().min(1).transform((value, context) => {
  if (posix.isAbsolute(value)) {
    return posix.normalize(value);
  }
  if (win32.isAbsolute(value)) {
    return win32.normalize(value);
  }
  context.addIssue({ code: 'custom', message: 'Path must be absolute.' });
  return z.NEVER;
});

const ipv4Address = z.string().refine((value) => isIP(value) === 4, {
  message: 'Expected a valid IPv4 address.'
});

const loopbackProxyUrl = z.string().url().refine((value) => {
  const url = new URL(value);
  return (
    (url.protocol === 'http:' || url.protocol === 'https:') &&
    Boolean(url.port) &&
    !url.username &&
    !url.password &&
    (url.hostname === '127.0.0.1' || url.hostname === 'localhost' || url.hostname === '[::1]')
  );
}, {
  message: 'localProxyUrl must be an unauthenticated HTTP(S) loopback proxy with an explicit port.'
});

const ianaTimeZone = z.string().min(3).refine((value) => {
  try {
    new Intl.DateTimeFormat('en-US', { timeZone: value }).format();
    return true;
  } catch {
    return false;
  }
}, { message: 'Expected a valid IANA time zone.' });

const domainEntry = z.string().min(1).regex(/^(\*\.)?[a-zA-Z0-9.-]+(?::\d+)?$/, {
  message: 'Expected a hostname, wildcard hostname, or hostname:port entry.'
});

const safeReadPlaceholder = z.enum(['${WORKSPACE}', '${AGENT_STATE}', '${INSTALL_ROOT}']);
const safeWritePlaceholder = z.enum(['${WORKSPACE}', '${AGENT_STATE}']);
const requiredReadPlaceholders = new Set(['${WORKSPACE}', '${AGENT_STATE}', '${INSTALL_ROOT}']);
const requiredWritePlaceholders = new Set(['${WORKSPACE}', '${AGENT_STATE}']);

function exactPlaceholderSet(values: readonly string[], required: ReadonlySet<string>): boolean {
  return values.length === required.size
    && new Set(values).size === required.size
    && values.every((value) => required.has(value));
}

function pathContainsOrEquals(parent: string, child: string, windowsSyntax: boolean): boolean {
  const pathApi = windowsSyntax ? win32 : posix;
  const normalize = (value: string): string => {
    const normalized = pathApi.resolve(value);
    return windowsSyntax ? normalized.toLowerCase() : normalized;
  };
  const normalizedParent = normalize(parent);
  const normalizedChild = normalize(child);
  const relativePath = pathApi.relative(normalizedParent, normalizedChild);
  const separator = windowsSyntax ? '\\' : '/';
  return relativePath === '' || (
    relativePath !== '..'
    && !relativePath.startsWith(`..${separator}`)
    && !pathApi.isAbsolute(relativePath)
  );
}

export const customerConfigSchema = z.object({
  schemaVersion: z.literal(1),
  environment: z.object({
    id: z.string().min(2).max(64).regex(/^[a-z0-9][a-z0-9-]*$/),
    displayName: z.string().min(2).max(120)
  }).strict(),
  platform: z.object({
    strategy: z.enum(['auto', 'windows', 'macos', 'linux'])
  }).strict(),
  workspace: z.object({
    path: absolutePath,
    stateRoot: absolutePath,
    stateMode: z.enum(['ephemeral', 'isolated-persistent'])
  }).strict(),
  network: z.object({
    localProxyUrl: loopbackProxyUrl,
    expectedExit: z.object({
      ipv4: ipv4Address,
      countryCode: z.string().regex(/^[A-Za-z]{2}$/).transform((value) => value.toUpperCase()),
      timeZone: ianaTimeZone
    }).strict(),
    preflightAttempts: z.number().int().min(2).max(10).default(3),
    watchdogIntervalSeconds: z.number().int().min(15).max(300).default(30),
    watchdogFailureLimit: z.number().int().min(1).max(5).default(2),
    failClosed: z.literal(true),
    strictAllowlist: z.literal(true),
    allowedDomains: z.array(domainEntry).min(1),
    deniedDomains: z.array(domainEntry).default([])
  }).strict(),
  chain: z.object({
    clashProfileName: z.string().min(1),
    frontGroupName: z.string().min(1),
    preferredFrontNode: z.string().min(1),
    landing: z.object({
      type: z.enum(['socks5', 'http']),
      host: ipv4Address,
      port: z.number().int().min(1).max(65535),
      usernameSecretRef: z.string().min(1),
      passwordSecretRef: z.string().min(1)
    }).strict()
  }).strict(),
  filesystem: z.object({
    denyRead: z.array(z.string()).default([]),
    allowRead: z.array(safeReadPlaceholder).min(1),
    allowWrite: z.array(safeWritePlaceholder).min(1),
    denyWrite: z.array(z.string()).default([])
  }).strict(),
  runtime: z.object({
    isolationTier: z.literal('process'),
    claudeCommand: z.literal('bundled-official'),
    sandboxEngine: z.literal('anthropic-srt'),
    requireOfficialClaude: z.literal(true),
    allowUnsandboxedCommands: z.literal(false),
    failIfSandboxUnavailable: z.literal(true)
  }).strict(),
  assessment: z.object({
    minimumScore: z.number().min(90).max(100),
    reportBrand: z.literal('HONG AI'),
    runBeforeDelivery: z.literal(true)
  }).strict()
}).strict().superRefine((config, context) => {
  const windowsStrategy = config.platform.strategy === 'windows';
  const windowsPaths = /^[A-Za-z]:[\\/]/.test(config.workspace.path)
    || /^[A-Za-z]:[\\/]/.test(config.workspace.stateRoot);
  if (windowsStrategy || windowsPaths) {
    for (const [field, value] of [
      ['path', config.workspace.path],
      ['stateRoot', config.workspace.stateRoot]
    ] as const) {
      if (!/^[DE]:[\\/]/i.test(value)) {
        context.addIssue({
          code: 'custom',
          path: ['workspace', field],
          message: 'Windows customer workspace and state must use the D: or E: data drive; C: is system-only.'
        });
      }
    }
  }
  if (config.platform.strategy === 'macos' || config.platform.strategy === 'linux') {
    for (const [field, value] of [
      ['path', config.workspace.path],
      ['stateRoot', config.workspace.stateRoot]
    ] as const) {
      if (!posix.isAbsolute(value) || /^[A-Za-z]:[\\/]/.test(value)) {
        context.addIssue({
          code: 'custom',
          path: ['workspace', field],
          message: 'macOS and Linux customer paths must use native absolute POSIX syntax.'
        });
      }
    }
  }
  const windowsPathSemantics = windowsStrategy || windowsPaths;
  if (
    pathContainsOrEquals(config.workspace.path, config.workspace.stateRoot, windowsPathSemantics)
    || pathContainsOrEquals(config.workspace.stateRoot, config.workspace.path, windowsPathSemantics)
  ) {
    context.addIssue({
      code: 'custom',
      path: ['workspace', 'stateRoot'],
      message: 'workspace.path and workspace.stateRoot must be separate, non-overlapping trees.'
    });
  }
  if (!exactPlaceholderSet(config.filesystem.allowRead, requiredReadPlaceholders)) {
    context.addIssue({
      code: 'custom',
      path: ['filesystem', 'allowRead'],
      message: 'allowRead must contain exactly WORKSPACE, AGENT_STATE, and INSTALL_ROOT placeholders.'
    });
  }
  if (!exactPlaceholderSet(config.filesystem.allowWrite, requiredWritePlaceholders)) {
    context.addIssue({
      code: 'custom',
      path: ['filesystem', 'allowWrite'],
      message: 'allowWrite must contain exactly WORKSPACE and AGENT_STATE placeholders.'
    });
  }
  for (const [field, values] of [
    ['denyRead', config.filesystem.denyRead],
    ['denyWrite', config.filesystem.denyWrite]
  ] as const) {
    values.forEach((value, index) => {
      if (requiredReadPlaceholders.has(value)) {
        context.addIssue({
          code: 'custom',
          path: ['filesystem', field, index],
          message: 'A required safe allow placeholder cannot also be denied at the same root.'
        });
      }
    });
  }
});

export type CustomerConfig = z.infer<typeof customerConfigSchema>;

export async function loadCustomerConfig(configPath: string): Promise<CustomerConfig> {
  const raw = await readFile(configPath, 'utf8');
  const parsed = YAML.parse(raw) as unknown;
  return customerConfigSchema.parse(parsed);
}

export function expandPolicyPath(
  value: string,
  config: CustomerConfig,
  agentStateRoot = resolve(config.workspace.stateRoot, 'agent')
): string {
  const installRoot = resolve(dirname(fileURLToPath(import.meta.url)), '..', '..');
  return value
    .replaceAll('${WORKSPACE}', config.workspace.path)
    .replaceAll('${STATE_ROOT}', config.workspace.stateRoot)
    .replaceAll('${AGENT_STATE}', agentStateRoot)
    .replaceAll('${INSTALL_ROOT}', installRoot);
}

export function configuredPlatformMatchesHost(config: CustomerConfig): boolean {
  const hostPlatform = process.platform === 'win32'
    ? 'windows'
    : process.platform === 'darwin'
      ? 'macos'
      : process.platform === 'linux'
        ? 'linux'
        : 'unsupported';
  if (config.platform.strategy !== 'auto' && config.platform.strategy !== hostPlatform) {
    return false;
  }
  if (hostPlatform === 'windows') {
    return /^[DE]:[\\/]/i.test(config.workspace.path)
      && /^[DE]:[\\/]/i.test(config.workspace.stateRoot);
  }
  if (hostPlatform === 'macos' || hostPlatform === 'linux') {
    return posix.isAbsolute(config.workspace.path)
      && posix.isAbsolute(config.workspace.stateRoot)
      && !/^[A-Za-z]:[\\/]/.test(config.workspace.path)
      && !/^[A-Za-z]:[\\/]/.test(config.workspace.stateRoot);
  }
  return false;
}

export async function assertHostStoragePolicy(config: CustomerConfig): Promise<void> {
  if (!configuredPlatformMatchesHost(config)) {
    throw new Error('Configured platform or workspace/state path policy does not match this host.');
  }
  if (process.platform === 'win32') {
    // Keep the Windows data-drive and reparse-point behavior unchanged. The
    // Windows customer installer applies the same rule before machine changes.
    for (const [label, value] of [
      ['workspace.path', config.workspace.path],
      ['workspace.stateRoot', config.workspace.stateRoot]
    ] as const) {
      let candidate = win32.resolve(value);
      while (true) {
        try {
          const metadata = await lstat(candidate);
          if (metadata.isSymbolicLink()) {
            throw new Error(`${label} contains a junction, mount point, or symbolic-link ancestor: ${candidate}`);
          }
          const canonical = await realpath(candidate);
          if (!/^[DE]:[\\/]/i.test(canonical)) {
            throw new Error(`${label} resolves outside the D: or E: data drive.`);
          }
        } catch (error) {
          if ((error as NodeJS.ErrnoException).code !== 'ENOENT') throw error;
        }
        const parent = win32.dirname(candidate);
        if (parent === candidate) break;
        candidate = parent;
      }
    }
    return;
  }

  if (process.platform !== 'darwin') return;
  for (const [label, value] of [
    ['workspace.path', config.workspace.path],
    ['workspace.stateRoot', config.workspace.stateRoot]
  ] as const) {
    let candidate = posix.resolve(value);
    while (true) {
      try {
        const metadata = await lstat(candidate);
        if (metadata.isSymbolicLink()) {
          throw new Error(`${label} contains a symbolic-link ancestor: ${candidate}`);
        }
        // lstat above rejects a link at this exact component. Comparing its
        // canonical spelling also fails closed if the host resolves an
        // existing ancestor through another path before state is created.
        const canonical = await realpath(candidate);
        if (posix.normalize(canonical) !== posix.normalize(candidate)) {
          throw new Error(`${label} existing ancestor resolves outside its configured path: ${candidate}`);
        }
      } catch (error) {
        if ((error as NodeJS.ErrnoException).code !== 'ENOENT') throw error;
      }
      const parent = posix.dirname(candidate);
      if (parent === candidate) break;
      candidate = parent;
    }
  }
}
