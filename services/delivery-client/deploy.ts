#!/usr/bin/env node

import { randomUUID } from 'node:crypto';
import { lstat, readFile, rename, rm } from 'node:fs/promises';
import { reconcileCompletedActivation, retrieveArtifact } from '../../src/delivery-client.js';
import { assertHostStoragePolicy, configuredPlatformMatchesHost, loadCustomerConfig } from '../../src/config.js';
import { acquireDeliveryTransactionLock } from '../../src/delivery-lock.js';
import { runPreflight } from '../../src/preflight.js';
import {
  deployArtifactArchive,
  assertNativePilotArtifactId,
  preflightDeploymentTarget,
  recoverInterruptedWindowsDeployment,
  verifyCompletedDeployment,
  verifyInstalledPortablePayload,
  type DeploymentResult
} from '../../src/deployment.js';
import { absoluteArgument, argument, hiddenPrompt, optionalAbsoluteArgument, required } from './terminal.js';

async function main(): Promise<void> {
  const serviceUrl = required('service-url');
  const artifactId = required('artifact-id');
  assertNativePilotArtifactId(artifactId);
  const signingPublicKeyPem = await readFile(absoluteArgument('signing-public-key'), 'utf8');
  const outputPath = absoluteArgument('archive-output');
  const installRoot = absoluteArgument('install-root');
  const configPath = absoluteArgument('config');
  const currentLink = optionalAbsoluteArgument('current-link');
  const keepArchive = argument('keep-archive') === 'true';
  const activationRecoveryPath = `${outputPath}.activation.pending.json`;
  const transactionLock = await acquireDeliveryTransactionLock(outputPath);
  try {
  const customerConfig = await loadCustomerConfig(configPath);
  await assertHostStoragePolicy(customerConfig);
  if (!configuredPlatformMatchesHost(customerConfig)) {
    throw new Error(`Customer configuration platform strategy ${customerConfig.platform.strategy} does not match this computer.`);
  }
  let [installExists, recoveryExists] = await Promise.all([
    lstat(installRoot).then(() => true, (error: NodeJS.ErrnoException) => {
      if (error.code === 'ENOENT') return false;
      throw error;
    }),
    lstat(activationRecoveryPath).then(() => true, (error: NodeJS.ErrnoException) => {
      if (error.code === 'ENOENT') return false;
      throw error;
    })
  ]);
  if (installExists && recoveryExists) {
    let installed;
    try {
      installed = await verifyCompletedDeployment({
        installRoot,
        configPath,
        runDoctor: true,
        repairMacActivation: true,
        ...(currentLink ? { currentLink } : {})
      });
    } catch (error) {
      const markerPath = process.platform === 'win32'
        ? `${installRoot}\\.edge-cage\\windows-install-state.json`
        : `${installRoot}/.hongai-install.json`;
      const markerExists = await lstat(markerPath).then(() => true, (markerError: NodeJS.ErrnoException) => {
        if (markerError.code === 'ENOENT') return false;
        throw markerError;
      });
      if (!markerExists) {
        const interruptedPayload = await verifyInstalledPortablePayload(installRoot);
        if (interruptedPayload.artifactId !== artifactId) {
          throw new Error('Unmarked installRoot is not the exact expected portable payload; refusing to move unrelated data.');
        }
        const quarantine = `${installRoot}.interrupted-${randomUUID()}`;
        await rename(installRoot, quarantine);
        installExists = false;
        console.error(`WARNING: quarantined an interrupted pre-marker payload at "${quarantine}"; inspect it before later cleanup.`);
      } else if (process.platform === 'win32') {
        try {
          const recovered = await recoverInterruptedWindowsDeployment({
            installRoot,
            expectedArtifactId: artifactId
          });
          installExists = false;
          console.error(
            `WARNING: rolled back a verified interrupted Windows installation and quarantined its payload at "${recovered.quarantinePath}"; inspect it before later cleanup.`
          );
        } catch (recoveryError) {
          throw new Error(
            `An interrupted delivery exists but is neither a verified completed installation nor an automatically recoverable Windows INSTALLING transaction. ` +
            `No new token was consumed. Verification detail: ${error instanceof Error ? error.message : String(error)}; ` +
            `recovery detail: ${recoveryError instanceof Error ? recoveryError.message : String(recoveryError)}`
          );
        }
      } else {
        throw new Error(
          `An interrupted delivery exists but is not a verified completed installation. ` +
          `No new token was consumed. Use the platform recovery/uninstall procedure before retrying. ` +
          `Verification detail: ${error instanceof Error ? error.message : String(error)}`
        );
      }
    }
    if (installExists && installed && installed.artifactId !== artifactId) {
      throw new Error('Installed payload artifact ID does not match the activation recovery request.');
    }
    const recoveryNetworkPreflight = installExists ? await runPreflight(customerConfig) : undefined;
    if (recoveryNetworkPreflight && !recoveryNetworkPreflight.ok) {
      throw new Error(`Completed-install recovery network preflight failed: ${recoveryNetworkPreflight.failures.join(' ')}`);
    }
    if (installExists) {
    let recoveryLicenseKey = await hiddenPrompt('长期授权密钥（用于恢复安装回执，输入不可见）：');
    try {
      const receipt = await reconcileCompletedActivation({
        activationRecoveryPath,
        artifactOutputPath: outputPath,
        licenseKey: recoveryLicenseKey,
        expectedServiceUrl: serviceUrl,
        expectedArtifactId: artifactId,
        signingPublicKeyPem,
        proxyUrl: customerConfig.network.localProxyUrl
      });
      console.log(JSON.stringify({
        ok: true,
        recoveredCompletedInstallation: true,
        installRoot,
        ...receipt
      }, null, 2));
      if (!receipt.receiptRecorded) {
        console.error(`WARNING: recovered installation is safe, but its receipt remains pending at "${receipt.receiptPendingPath}".`);
      }
      return;
    } finally {
      recoveryLicenseKey = '';
    }
    }
  }
  if (!installExists && recoveryExists) {
    const outputMetadata = await lstat(outputPath).catch((error: NodeJS.ErrnoException) => {
      if (error.code === 'ENOENT') return undefined;
      throw error;
    });
    if (outputMetadata) {
      if (!outputMetadata.isFile() || outputMetadata.isSymbolicLink()) {
        throw new Error('Interrupted artifact output is not a regular file and cannot be recovered safely.');
      }
      const quarantine = `${outputPath}.interrupted-${randomUUID()}`;
      await rename(outputPath, quarantine);
      console.error(`WARNING: quarantined an interrupted plaintext archive at "${quarantine}"; inspect and securely remove it after successful recovery.`);
    }
  }
  await preflightDeploymentTarget({
    archivePath: outputPath,
    installRoot,
    configPath,
    ...(currentLink ? { currentLink } : {})
  });
  const networkPreflight = await runPreflight(customerConfig);
  if (!networkPreflight.ok) {
    throw new Error(`Customer network preflight failed before activation: ${networkPreflight.failures.join(' ')}`);
  }
  let archiveRetained = true;
  let deployment: DeploymentResult | undefined;
  let licenseKey = await hiddenPrompt('长期授权密钥（输入不可见）：');
  let oneTimeToken = await hiddenPrompt('一次性临时令牌（输入不可见）：');
  try {
    const result = await retrieveArtifact({
      serviceUrl,
      artifactId,
      licenseKey,
      oneTimeToken,
      signingPublicKeyPem,
      outputPath,
      activationRecoveryPath,
      proxyUrl: customerConfig.network.localProxyUrl,
      finalize: async (artifact) => {
        deployment = await deployArtifactArchive({
          archivePath: outputPath,
          installRoot,
          configPath,
          expectedArtifactId: artifactId,
          expectedPlaintextSha256: artifact.plaintextSha256,
          ...(currentLink ? { currentLink } : {})
        });
        if (!keepArchive) {
          archiveRetained = !await rm(outputPath, { force: true }).then(() => true, () => false);
        }
      }
    });
    console.log(JSON.stringify({ ok: true, ...result, archiveRetained, deployment }, null, 2));
    if (!result.receiptRecorded) {
      console.error(`WARNING: deliveryState=PENDING_RECEIPT. Retry with --pending "${result.receiptPendingPath}" after connectivity is restored.`);
    }
  } finally {
    licenseKey = '';
    oneTimeToken = '';
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
