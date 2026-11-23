import { isIP } from 'node:net';
import { posix, resolve, win32 } from 'node:path';
import { readFile } from 'node:fs/promises';
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
    allowRead: z.array(z.string()).min(1),
    allowWrite: z.array(z.string()).min(1),
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
}).strict();

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
  if (config.platform.strategy === 'auto') {
    return true;
  }
  const hostPlatform = process.platform === 'win32'
    ? 'windows'
    : process.platform === 'darwin'
      ? 'macos'
      : process.platform === 'linux'
        ? 'linux'
        : 'unsupported';
  return config.platform.strategy === hostPlatform;
}
