#!/usr/bin/env node

import { mkdir, writeFile } from 'node:fs/promises';
import { dirname, resolve } from 'node:path';
import { ZodError } from 'zod';
import { assertHostStoragePolicy, loadCustomerConfig } from './config.js';
import { renderSandboxPolicy } from './policy.js';
import { runPreflight } from './preflight.js';
import { launchSandboxedClaude, prepareEnvironment, smokeTestSandbox } from './runtime.js';
import { credentialsFromEnvironment, renderClashScript } from './clash.js';
import { loadAndCompileCustomerIntake, serializeCustomerConfig } from './intake.js';
import { startDashboard } from './dashboard.js';
import { productVersion } from './product.js';
import { createSupportBundle } from './support.js';

interface CliArguments {
  command: 'init' | 'validate' | 'render' | 'preflight' | 'doctor' | 'dashboard' | 'launch' | 'clash-script' | 'support-bundle';
  configPath: string;
  outputPath?: string;
  passthrough: string[];
}

function usage(): never {
  console.error('Usage: hongai-edge-cage <init|validate|render|preflight|doctor|dashboard|launch|clash-script|support-bundle> --config <file> [--output <file>] [-- <claude args>]');
  process.exit(2);
}

function parseArguments(argv: string[]): CliArguments {
  const [command, ...rest] = argv;
  if (!command || !['init', 'validate', 'render', 'preflight', 'doctor', 'dashboard', 'launch', 'clash-script', 'support-bundle'].includes(command)) {
    return usage();
  }

  let configPath: string | undefined;
  let outputPath: string | undefined;
  let passthrough: string[] = [];
  for (let index = 0; index < rest.length; index += 1) {
    const token = rest[index];
    if (token === '--') {
      passthrough = rest.slice(index + 1);
      break;
    }
    if (token === '--config') {
      configPath = rest[index + 1];
      index += 1;
    } else if (token === '--output') {
      outputPath = rest[index + 1];
      index += 1;
    } else {
      return usage();
    }
  }
  if (!configPath) {
    return usage();
  }

  return {
    command: command as CliArguments['command'],
    configPath: resolve(configPath),
    ...(outputPath ? { outputPath: resolve(outputPath) } : {}),
    passthrough
  };
}

async function main(): Promise<void> {
  const args = parseArguments(process.argv.slice(2));

  if (args.command === 'init') {
    const outputPath = args.outputPath ?? resolve('config', 'customer.local.yaml');
    const customerConfig = await loadAndCompileCustomerIntake(args.configPath);
    await mkdir(dirname(outputPath), { recursive: true });
    await writeFile(outputPath, serializeCustomerConfig(customerConfig), { encoding: 'utf8', mode: 0o600 });
    console.log(JSON.stringify({ ok: true, outputPath, environment: customerConfig.environment }, null, 2));
    return;
  }

  const config = await loadCustomerConfig(args.configPath);
  await assertHostStoragePolicy(config);

  if (args.command === 'support-bundle') {
    const outputPath = args.outputPath ?? resolve(
      config.workspace.stateRoot,
      'controller',
      'support',
      `support-${new Date().toISOString().replace(/[:.]/g, '-')}.json`
    );
    const result = await createSupportBundle(config, outputPath);
    console.log(JSON.stringify(result, null, 2));
    if (!result.ok) process.exitCode = 1;
    return;
  }

  if (args.command === 'validate') {
    console.log(JSON.stringify({ ok: true, environment: config.environment }, null, 2));
    return;
  }

  if (args.command === 'render') {
    const outputPath = args.outputPath ?? resolve('.edge-cage', config.environment.id, 'srt-settings.json');
    const policy = renderSandboxPolicy(config);
    await mkdir(dirname(outputPath), { recursive: true });
    await writeFile(outputPath, `${JSON.stringify(policy, null, 2)}\n`, { encoding: 'utf8', mode: 0o600 });
    console.log(JSON.stringify({ ok: true, outputPath }, null, 2));
    return;
  }

  if (args.command === 'clash-script') {
    const outputPath = args.outputPath ?? resolve(
      config.workspace.stateRoot,
      'controller',
      'clash',
      'clash-global-script.js'
    );
    const credentials = credentialsFromEnvironment(config);
    const script = renderClashScript(config, credentials);
    await mkdir(dirname(outputPath), { recursive: true });
    await writeFile(outputPath, script, { encoding: 'utf8', mode: 0o600 });
    console.log(JSON.stringify({
      ok: true,
      outputPath,
      warning: 'This file contains proxy credentials. Import it only on the authorized customer device.'
    }, null, 2));
    return;
  }

  if (args.command === 'launch') {
    const result = await launchSandboxedClaude(config, args.passthrough);
    process.exitCode = result.exitCode;
    return;
  }

  if (args.command === 'dashboard') {
    await startDashboard(config);
    return;
  }

  if (args.command === 'doctor') {
    const version = await productVersion();
    const result = await runPreflight(config);
    if (!result.ok) {
      console.log(JSON.stringify({
        ok: false,
        product: 'HONG AI Edge Cage',
        version,
        platform: process.platform,
        architecture: process.arch,
        node: process.version,
        stateMode: config.workspace.stateMode,
        preflight: result,
        sandboxSmoke: { ok: false, skipped: true, reason: 'Preflight failed before sandbox preparation.' }
      }, null, 2));
      process.exitCode = 1;
      return;
    }
    const prepared = await prepareEnvironment(config);
    try {
      const sandboxSmoke = await smokeTestSandbox(config, prepared);
      const doctorOk = result.ok && sandboxSmoke.ok;
      console.log(JSON.stringify({
        ok: doctorOk,
        product: 'HONG AI Edge Cage',
        version,
        platform: process.platform,
        architecture: process.arch,
        node: process.version,
        policyPath: prepared.policyPath,
        stateMode: config.workspace.stateMode,
        preflight: result,
        sandboxSmoke
      }, null, 2));
      if (!doctorOk) {
        process.exitCode = 1;
      }
    } finally {
      await prepared.cleanup();
    }
    return;
  }

  const result = await runPreflight(config);
  console.log(JSON.stringify(result, null, 2));
  if (!result.ok) {
    process.exitCode = 1;
  }
}

main().catch((error: unknown) => {
  if (error instanceof ZodError) {
    console.error(JSON.stringify({ ok: false, type: 'configuration', issues: error.issues }, null, 2));
  } else {
    console.error(JSON.stringify({
      ok: false,
      type: 'runtime',
      message: error instanceof Error ? error.message : String(error)
    }, null, 2));
  }
  process.exitCode = 1;
});
