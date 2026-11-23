import { createHash } from 'node:crypto';
import { mkdir, writeFile } from 'node:fs/promises';
import { dirname, resolve } from 'node:path';
import { readAuditEvents, verifyAuditChain } from './audit.js';
import type { CustomerConfig } from './config.js';
import { verifyInstalledPortablePayload } from './deployment.js';
import { runPreflight } from './preflight.js';
import { productName, productRoot, productVersion } from './product.js';
import { prepareEnvironment, smokeTestSandbox } from './runtime.js';

function fingerprint(value: string): string {
  return createHash('sha256').update(value, 'utf8').digest('hex');
}

export interface SupportBundleResult {
  outputPath: string;
  ok: boolean;
}

export async function createSupportBundle(
  config: CustomerConfig,
  outputPath: string
): Promise<SupportBundleResult> {
  const generatedAt = new Date().toISOString();
  const version = await productVersion();
  let payloadIntegrity: Record<string, unknown>;
  try {
    const result = await verifyInstalledPortablePayload(productRoot());
    payloadIntegrity = { ok: true, ...result };
  } catch {
    payloadIntegrity = { ok: false, reason: 'PAYLOAD_INTEGRITY_UNAVAILABLE_OR_FAILED' };
  }

  const preflight = await runPreflight(config);
  let sandboxSmoke: Record<string, unknown> = {
    ok: false,
    skipped: true,
    reason: 'PREFLIGHT_FAILED'
  };
  if (preflight.ok) {
    const prepared = await prepareEnvironment(config);
    try {
      const smoke = await smokeTestSandbox(config, prepared);
      sandboxSmoke = {
        ok: smoke.ok,
        skipped: false,
        exitCode: smoke.exitCode
      };
    } finally {
      await prepared.cleanup();
    }
  }

  const auditEvents = await readAuditEvents(config);
  const sanitizedPreflight = {
    ok: preflight.ok,
    proxyListener: preflight.proxyListener,
    platformMatches: preflight.platformMatches,
    stableExit: preflight.stableExit,
    timeZoneMatches: preflight.timeZoneMatches,
    currentTimeZone: preflight.currentTimeZone,
    expectedExitFingerprint: fingerprint(preflight.expectedExitIp),
    observedExitFingerprints: preflight.observedExitIps.map(fingerprint),
    probeElapsedMs: preflight.probes.map((probe) => probe.elapsedMs),
    failures: preflight.failures
  };
  const ok = preflight.ok && sandboxSmoke.ok === true && payloadIntegrity.ok === true;
  const report = {
    schemaVersion: 1,
    product: productName,
    version,
    generatedAt,
    ok,
    host: {
      platform: process.platform,
      architecture: process.arch,
      node: process.version,
      configuredPlatform: config.platform
    },
    customerEnvironment: {
      idFingerprint: fingerprint(config.environment.id),
      stateMode: config.workspace.stateMode,
      expectedTimeZone: config.network.expectedExit.timeZone
    },
    payloadIntegrity,
    preflight: sanitizedPreflight,
    sandboxSmoke,
    audit: {
      eventCount: auditEvents.length,
      chainValid: verifyAuditChain(auditEvents),
      lastEventAt: auditEvents.at(-1)?.timestamp ?? null
    },
    privacy: {
      credentialsIncluded: false,
      licenseOrOtpIncluded: false,
      fullIpAddressesIncluded: false,
      fullCustomerPathsIncluded: false,
      rawLogsIncluded: false
    }
  };
  const resolvedOutput = resolve(outputPath);
  await mkdir(dirname(resolvedOutput), { recursive: true });
  await writeFile(resolvedOutput, `${JSON.stringify(report, null, 2)}\n`, {
    encoding: 'utf8',
    mode: 0o600
  });
  return { outputPath: resolvedOutput, ok };
}
