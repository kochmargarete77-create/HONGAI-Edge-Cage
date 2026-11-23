import { readFile } from 'node:fs/promises';
import { isIP } from 'node:net';
import YAML from 'yaml';
import { z } from 'zod';
import { customerConfigSchema, type CustomerConfig } from './config.js';

const ipv4Address = z.string().refine((value) => isIP(value) === 4, {
  message: 'Expected a valid IPv4 address.'
});

const intakeSchema = z.object({
  schemaVersion: z.literal(1),
  customer: z.object({
    id: z.string().min(2).max(64).regex(/^[a-z0-9][a-z0-9-]*$/),
    displayName: z.string().min(2).max(120)
  }).strict(),
  platform: z.enum(['windows', 'macos']),
  dataRoot: z.string().min(1).optional(),
  clash: z.object({
    localProxyPort: z.number().int().min(1).max(65535).default(7897),
    sourceGroup: z.string().min(1),
    frontNode: z.string().min(1)
  }).strict(),
  finalExit: z.object({
    type: z.enum(['socks5', 'http']).default('socks5'),
    endpointIpv4: ipv4Address,
    endpointPort: z.number().int().min(1).max(65535),
    expectedPublicIpv4: ipv4Address,
    countryCode: z.string().length(2),
    timeZone: z.string().min(3),
    usernameSecretRef: z.string().min(1).default('EDGE_CAGE_LANDING_USERNAME'),
    passwordSecretRef: z.string().min(1).default('EDGE_CAGE_LANDING_PASSWORD')
  }).strict()
}).strict();

export type CustomerIntake = z.infer<typeof intakeSchema>;

function defaultDataRoot(platform: CustomerIntake['platform']): string {
  return platform === 'windows' ? 'D:/HONGAI-Edge-Cage' : '/Users/Shared/HONGAI-Edge-Cage';
}

function joinPortable(root: string, ...parts: string[]): string {
  return [root.replace(/[\\/]$/, ''), ...parts].join('/');
}

export function compileCustomerIntake(raw: unknown): CustomerConfig {
  const intake = intakeSchema.parse(raw);
  const dataRoot = intake.dataRoot ?? defaultDataRoot(intake.platform);
  const denyRead = intake.platform === 'windows'
    ? ['C:/Users', 'D:/', 'E:/', 'F:/', 'G:/', 'H:/', '**/.env', '**/.env.*']
    : ['/Users', '/Volumes', '**/.env', '**/.env.*'];

  return customerConfigSchema.parse({
    schemaVersion: 1,
    environment: {
      id: intake.customer.id,
      displayName: intake.customer.displayName
    },
    platform: { strategy: intake.platform },
    workspace: {
      path: joinPortable(dataRoot, 'Workspaces', intake.customer.id),
      stateRoot: joinPortable(dataRoot, 'State', intake.customer.id),
      stateMode: 'isolated-persistent'
    },
    network: {
      localProxyUrl: `http://127.0.0.1:${intake.clash.localProxyPort}`,
      expectedExit: {
        ipv4: intake.finalExit.expectedPublicIpv4,
        countryCode: intake.finalExit.countryCode,
        timeZone: intake.finalExit.timeZone
      },
      preflightAttempts: 3,
      watchdogIntervalSeconds: 30,
      watchdogFailureLimit: 2,
      failClosed: true,
      strictAllowlist: true,
      allowedDomains: [
        'api.anthropic.com',
        'claude.ai',
        'claude.com',
        'platform.claude.com',
        'sso.claude.com',
        'code.claude.com'
      ],
      deniedDomains: []
    },
    chain: {
      clashProfileName: intake.clash.sourceGroup,
      frontGroupName: 'HONG AI Edge Cage | Front Hop',
      preferredFrontNode: intake.clash.frontNode,
      landing: {
        type: intake.finalExit.type,
        host: intake.finalExit.endpointIpv4,
        port: intake.finalExit.endpointPort,
        usernameSecretRef: intake.finalExit.usernameSecretRef,
        passwordSecretRef: intake.finalExit.passwordSecretRef
      }
    },
    filesystem: {
      denyRead,
      allowRead: ['${WORKSPACE}', '${AGENT_STATE}', '${INSTALL_ROOT}'],
      allowWrite: ['${WORKSPACE}', '${AGENT_STATE}'],
      denyWrite: ['**/.env', '**/.env.*', '**/clash-global-script.js']
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

export async function loadAndCompileCustomerIntake(path: string): Promise<CustomerConfig> {
  const contents = await readFile(path, 'utf8');
  return compileCustomerIntake(YAML.parse(contents) as unknown);
}

export function serializeCustomerConfig(config: CustomerConfig): string {
  return YAML.stringify(config, { lineWidth: 0 });
}
