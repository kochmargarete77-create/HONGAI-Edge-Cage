#!/usr/bin/env node

import { readFile } from 'node:fs/promises';
import { abandonActivation } from '../../src/delivery-client.js';
import { assertHostStoragePolicy, configuredPlatformMatchesHost, loadCustomerConfig } from '../../src/config.js';
import { acquireDeliveryTransactionLock, assertNoRecoverableDeliveryResidue } from '../../src/delivery-lock.js';
import {
  absoluteArgument,
  hiddenPrompt,
  optionalAbsoluteArgument,
  required,
  visiblePrompt
} from './terminal.js';

async function main(): Promise<void> {
  const serviceUrl = required('service-url');
  const artifactId = required('artifact-id');
  const signingPublicKeyPath = absoluteArgument('signing-public-key');
  const artifactOutputPath = absoluteArgument('archive-output');
  const activationRecoveryPath = absoluteArgument('activation-recovery');
  const installRoot = absoluteArgument('install-root');
  const configPath = absoluteArgument('config');
  const currentLink = optionalAbsoluteArgument('current-link');
  const transactionLock = await acquireDeliveryTransactionLock(artifactOutputPath);
  try {
  const customerConfig = await loadCustomerConfig(configPath);
  await assertHostStoragePolicy(customerConfig);
  if (!configuredPlatformMatchesHost(customerConfig)) {
    throw new Error('Customer configuration does not match this host platform.');
  }
  await assertNoRecoverableDeliveryResidue({ artifactOutputPath, installRoot, ...(currentLink ? { currentLink } : {}) });

  const confirmationPhrase = `确认放弃 ${artifactId}`;
  const confirmation = await visiblePrompt(
    `此操作会把该授权激活永久记为 FAILED，且不会自动删除恢复/隔离目录。\n` +
    `仅在确认安装目标已安全清理且不再重试时，完整输入：${confirmationPhrase}\n> `
  );
  if (confirmation !== confirmationPhrase) {
    throw new Error('Typed confirmation did not match; activation remains recoverable and no FAILED receipt was created.');
  }

  const signingPublicKeyPem = await readFile(signingPublicKeyPath, 'utf8');
  let licenseKey = await hiddenPrompt('长期授权密钥（输入不可见）：');
  try {
    // Recheck after both interactive waits while still holding the shared lock.
    // This is the final local terminal-state gate immediately before FAILED.
    await assertNoRecoverableDeliveryResidue({ artifactOutputPath, installRoot, ...(currentLink ? { currentLink } : {}) });
    const result = await abandonActivation({
      activationRecoveryPath,
      artifactOutputPath,
      licenseKey,
      expectedServiceUrl: serviceUrl,
      expectedArtifactId: artifactId,
      signingPublicKeyPem,
      proxyUrl: customerConfig.network.localProxyUrl
    });
    console.log(JSON.stringify({ ok: true, explicitlyAbandoned: true, artifactId, ...result }, null, 2));
    if (!result.receiptRecorded) {
      console.error(
        `WARNING: FAILED is durably queued but not yet acknowledged. Retry receipt at "${result.receiptPendingPath}" after connectivity is restored.`
      );
    }
  } finally {
    licenseKey = '';
  }
  } finally {
    await transactionLock.release();
  }
}

main().catch((error: unknown) => {
  console.error(JSON.stringify({
    ok: false,
    error: error instanceof Error ? error.message : String(error)
  }));
  process.exitCode = 1;
});
