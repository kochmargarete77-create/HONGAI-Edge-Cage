#!/usr/bin/env node

import { retryPendingReceipt } from '../../src/delivery-client.js';
import { absoluteArgument, hiddenPrompt } from './terminal.js';

async function main(): Promise<void> {
  const pendingPath = absoluteArgument('pending');
  let licenseKey = await hiddenPrompt('长期授权密钥（输入不可见）：');
  try {
    await retryPendingReceipt(pendingPath, licenseKey);
    console.log(JSON.stringify({ ok: true, receiptRecorded: true, removed: pendingPath }, null, 2));
  } finally {
    licenseKey = '';
  }
}

main().catch((error: unknown) => {
  console.error(JSON.stringify({
    ok: false,
    error: error instanceof Error ? error.message : String(error)
  }));
  process.exitCode = 1;
});
