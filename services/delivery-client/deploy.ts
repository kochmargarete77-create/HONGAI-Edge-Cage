#!/usr/bin/env node

import { readFile, rm } from 'node:fs/promises';
import { retrieveArtifact } from '../../src/delivery-client.js';
import {
  deploySourceArchive,
  preflightDeploymentTarget,
  type DeploymentResult
} from '../../src/deployment.js';
import { absoluteArgument, argument, hiddenPrompt, required } from './terminal.js';

async function main(): Promise<void> {
  const serviceUrl = required('service-url');
  const artifactId = required('artifact-id');
  const signingPublicKeyPem = await readFile(absoluteArgument('signing-public-key'), 'utf8');
  const outputPath = absoluteArgument('archive-output');
  const installRoot = absoluteArgument('install-root');
  const configPath = absoluteArgument('config');
  const keepArchive = argument('keep-archive') === 'true';
  await preflightDeploymentTarget({ installRoot, configPath });
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
      finalize: async () => {
        deployment = await deploySourceArchive({ archivePath: outputPath, installRoot, configPath });
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
}

main().catch((error: unknown) => {
  console.error(JSON.stringify({
    ok: false,
    error: error instanceof Error ? error.message : String(error)
  }));
  process.exitCode = 1;
});
