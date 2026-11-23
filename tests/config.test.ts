import assert from 'node:assert/strict';
import test from 'node:test';
import { customerConfigSchema } from '../src/config.js';
import { renderSandboxPolicy } from '../src/policy.js';
import { renderClashScript } from '../src/clash.js';
import vm from 'node:vm';
import { compileCustomerIntake } from '../src/intake.js';
import { buildSandboxEnvironment, type PreparedEnvironment } from '../src/runtime.js';

const validConfig = {
  schemaVersion: 1,
  environment: { id: 'test-customer', displayName: 'Test Customer' },
  platform: { strategy: 'auto' },
  workspace: {
    path: 'E:/projects/test',
    stateRoot: 'E:/state/test',
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
    allowedDomains: ['api.anthropic.com', 'claude.ai', 'platform.claude.com'],
    deniedDomains: []
  },
  chain: {
    clashProfileName: 'example',
    frontGroupName: 'HONG AI | Front',
    preferredFrontNode: 'front-node',
    landing: {
      type: 'socks5',
      host: '203.0.113.10',
      port: 1080,
      usernameSecretRef: 'EDGE_USER',
      passwordSecretRef: 'EDGE_PASS'
    }
  },
  filesystem: {
    denyRead: ['~/.ssh'],
    allowRead: ['${WORKSPACE}', '${AGENT_STATE}', '${INSTALL_ROOT}'],
    allowWrite: ['${WORKSPACE}', '${AGENT_STATE}'],
    denyWrite: ['**/.env']
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
};

test('accepts a strict fail-closed customer configuration', () => {
  const parsed = customerConfigSchema.parse(validConfig);
  assert.equal(parsed.network.failClosed, true);
  assert.equal(parsed.network.strictAllowlist, true);
});

test('rejects disabling fail-closed mode', () => {
  const unsafe = structuredClone(validConfig);
  unsafe.network.failClosed = false;
  assert.throws(() => customerConfigSchema.parse(unsafe));
});

test('rejects lowering the commercial delivery threshold below 90', () => {
  const unsafe = structuredClone(validConfig);
  unsafe.assessment.minimumScore = 85;
  assert.throws(() => customerConfigSchema.parse(unsafe));
});

test('renders a parent-proxy and strict allowlist policy', () => {
  const parsed = customerConfigSchema.parse(validConfig);
  const policy = renderSandboxPolicy(parsed);
  assert.deepEqual(policy.network.parentProxy, {
    http: 'http://127.0.0.1:7897',
    https: 'http://127.0.0.1:7897'
  });
  assert.equal(policy.network.strictAllowlist, true);
  assert.equal(policy.network.allowLocalBinding, false);
  assert.ok(policy.filesystem.allowWrite.some((value) => {
    const path = typeof value === 'string' ? value : value.path;
    return path.includes('projects');
  }));
  const writablePaths = policy.filesystem.allowWrite.map((value) =>
    typeof value === 'string' ? value : value.path
  );
  assert.ok(writablePaths.some((value) => value.endsWith('state\\test\\agent')));
  assert.ok(!writablePaths.some((value) => value.endsWith('state\\test')));
});

test('renders an idempotent Clash fail-closed chain without a DIRECT fallback', () => {
  const parsed = customerConfigSchema.parse(validConfig);
  const source = renderClashScript(parsed, { username: 'demo-user', password: 'demo-pass' });
  const context = vm.createContext({});
  new vm.Script(`${source}\nthis.edgeCageMain = main;`).runInContext(context);
  const main = context.edgeCageMain as (config: Record<string, unknown>, profileName: string) => Record<string, unknown>;
  const clashConfig = {
    proxies: [],
    'proxy-groups': [
      { name: 'example', type: 'select', proxies: ['front-node', 'backup-node', 'DIRECT'] }
    ],
    rules: ['MATCH,DIRECT']
  };

  const first = main(clashConfig, 'test');
  const second = main(first, 'test');
  const groups = second['proxy-groups'] as Array<{ name: string; proxies: string[] }>;
  const failClosed = groups.find((group) => group.name === 'HONG AI Edge Cage | Claude ONLY');
  assert.deepEqual(Array.from(failClosed?.proxies ?? []), ['HONG AI Edge Cage | Final Exit']);
  assert.equal(groups.filter((group) => group.name === 'HONG AI Edge Cage | Claude ONLY').length, 1);
  const proxies = second.proxies as Array<{ name: string; 'dialer-proxy': string }>;
  assert.equal(proxies.filter((proxy) => proxy.name === 'HONG AI Edge Cage | Final Exit').length, 1);
  assert.equal(proxies[0]?.['dialer-proxy'], 'HONG AI | Front');
  const rules = second.rules as string[];
  assert.ok(rules.some((rule) => rule.includes('anthropic.com,HONG AI Edge Cage | Claude ONLY')));
});

test('compiles a minimal Windows intake into a strict customer configuration', () => {
  const config = compileCustomerIntake({
    schemaVersion: 1,
    customer: { id: 'customer-001', displayName: 'Customer 001' },
    platform: 'windows',
    clash: { localProxyPort: 7897, sourceGroup: 'fast-fish', frontNode: 'US-01' },
    finalExit: {
      type: 'socks5',
      endpointIpv4: '203.0.113.10',
      endpointPort: 1080,
      expectedPublicIpv4: '203.0.113.10',
      countryCode: 'US',
      timeZone: 'America/Los_Angeles'
    }
  });
  assert.equal(config.network.failClosed, true);
  assert.equal(config.network.strictAllowlist, true);
  assert.equal(config.assessment.minimumScore, 90);
  assert.equal(config.chain.preferredFrontNode, 'US-01');
  assert.ok(config.filesystem.allowRead.includes('${INSTALL_ROOT}'));
  assert.ok(config.filesystem.allowWrite.includes('${AGENT_STATE}'));
});

test('preserves macOS absolute paths when preparing a macOS customer on Windows', () => {
  const config = compileCustomerIntake({
    schemaVersion: 1,
    customer: { id: 'customer-mac', displayName: 'Customer Mac' },
    platform: 'macos',
    clash: { localProxyPort: 7897, sourceGroup: 'fast-fish', frontNode: 'US-01' },
    finalExit: {
      type: 'socks5',
      endpointIpv4: '203.0.113.10',
      endpointPort: 1080,
      expectedPublicIpv4: '203.0.113.10',
      countryCode: 'US',
      timeZone: 'America/Los_Angeles'
    }
  });
  assert.equal(config.workspace.path, '/Users/Shared/HONGAI-Edge-Cage/Workspaces/customer-mac');
  assert.equal(config.platform.strategy, 'macos');
});

test('does not inherit host identity and credential environment variables', () => {
  const config = customerConfigSchema.parse(validConfig);
  const prepared: PreparedEnvironment = {
    policyPath: 'E:/state/test/controller/policy.json',
    claudeConfigDir: 'E:/state/test/agent/claude',
    homeDir: 'E:/state/test/agent/home',
    tempDir: 'E:/state/test/agent/tmp',
    agentStateRoot: 'E:/state/test/agent',
    cacheDir: 'E:/state/test/agent/cache',
    configDir: 'E:/state/test/agent/config',
    dataDir: 'E:/state/test/agent/data',
    appDataDir: 'E:/state/test/agent/appdata/roaming',
    localAppDataDir: 'E:/state/test/agent/appdata/local',
    cleanup: async () => {}
  };
  const environment = buildSandboxEnvironment(config, prepared, {
    PATH: 'E:/safe-tools',
    COMPUTERNAME: 'HOST-NAME',
    USERNAME: 'host-user',
    PROCESSOR_IDENTIFIER: 'host-cpu',
    ANTHROPIC_API_KEY: 'secret',
    SSH_AUTH_SOCK: 'secret-socket'
  });
  assert.equal(environment.PATH, 'E:/safe-tools');
  assert.equal(environment.COMPUTERNAME, undefined);
  assert.equal(environment.USERNAME, undefined);
  assert.equal(environment.PROCESSOR_IDENTIFIER, undefined);
  assert.equal(environment.ANTHROPIC_API_KEY, undefined);
  assert.equal(environment.SSH_AUTH_SOCK, undefined);
  assert.equal(environment.TZ, 'America/Los_Angeles');
});
