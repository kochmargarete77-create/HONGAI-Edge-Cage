import assert from 'node:assert/strict';
import { execFile as execFileCallback } from 'node:child_process';
import { mkdir, mkdtemp, readFile, readdir, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import test from 'node:test';
import { pathToFileURL } from 'node:url';
import { promisify } from 'node:util';
import {
  buildBootstrap,
  collectCompiledDependencyClosure,
  deliveryTemplate,
  moduleSpecifiers,
  validateBootstrapOutputDirectory
} from '../src/bootstrap-builder.js';

const root = resolve(process.cwd());
const execFile = promisify(execFileCallback);

test('bootstrap output policy rejects C: and repository-style relative paths on Windows', () => {
  assert.equal(validateBootstrapOutputDirectory('D:\\HONGAI\\bootstrap', 'win32'), 'D:\\HONGAI\\bootstrap');
  assert.equal(validateBootstrapOutputDirectory('E:\\HONGAI\\bootstrap', 'win32'), 'E:\\HONGAI\\bootstrap');
  assert.throws(() => validateBootstrapOutputDirectory('C:\\Users\\customer\\bootstrap', 'win32'), /D: or E:/);
  assert.throws(() => validateBootstrapOutputDirectory('bootstrap', 'win32'), /absolute D: or E:/);
  assert.equal(validateBootstrapOutputDirectory('/Users/Shared/HONGAI/bootstrap', 'darwin'), '/Users/Shared/HONGAI/bootstrap');
  assert.throws(() => validateBootstrapOutputDirectory('bootstrap', 'darwin'), /must be absolute/);
});

test('compiled bootstrap dependency closure is limited to deploy, abandon, receipt, terminal and required src modules', async () => {
  const files = await collectCompiledDependencyClosure(resolve(root, 'dist'), [
    'services/delivery-client/deploy.js',
    'services/delivery-client/abandon.js',
    'services/delivery-client/receipt.js'
  ]);
  const relative = files.map((path) => path.slice(resolve(root, 'dist').length + 1).replaceAll('\\', '/'));
  for (const required of [
    'services/delivery-client/deploy.js',
    'services/delivery-client/abandon.js',
    'services/delivery-client/receipt.js',
    'services/delivery-client/terminal.js',
    'src/config.js',
    'src/delivery-client.js',
    'src/delivery-lock.js',
    'src/deployment.js',
    'src/license-protocol.js'
  ]) assert.ok(relative.includes(required), `missing ${required}`);
  assert.equal(relative.every((path) => path.startsWith('services/delivery-client/') || path.startsWith('src/')), true);
  assert.equal(relative.some((path) => /claude|sandbox|pilot-builder/i.test(path)), false);
});

test('module scanner recognizes static, side-effect and dynamic module specifiers', () => {
  assert.deepEqual(moduleSpecifiers([
    "import { x } from './a.js';",
    "export * from './b.js';",
    "import './c.js';",
    "await import('./d.js');"
  ].join('\n')).sort(), ['./a.js', './b.js', './c.js', './d.js']);
});

test('delivery templates contain only public routing and path fields, never authorization secrets', () => {
  for (const platform of ['windows', 'macos'] as const) {
    const template = deliveryTemplate(platform);
    const expectedKeys = [
      'archiveOutput',
      'artifactId',
      'customerConfig',
      'installRoot',
      'keepArchive',
      'schemaVersion',
      'serviceUrl',
      'signingPublicKey'
    ];
    if (platform === 'macos') expectedKeys.push('currentLink');
    assert.deepEqual(Object.keys(template).sort(), expectedKeys.sort());
    const serialized = JSON.stringify(template);
    assert.doesNotMatch(serialized, /licenseKey|oneTimeToken|password|secret/i);
  }
  assert.equal('currentLink' in deliveryTemplate('windows'), false);
  assert.equal(deliveryTemplate('macos').currentLink, '/Users/Shared/HONGAI-Edge-Cage/current');
});

test('macOS bootstrap entries replace a hostile inherited PATH before running commands', async () => {
  const directory = resolve(root, 'platform', 'bootstrap', 'macos');
  const names = (await readdir(directory))
    .filter((name) => name.endsWith('.sh') || name.endsWith('.command'))
    .sort();
  assert.ok(names.length > 0);
  const safePrefix = '#!/bin/sh\nPATH=/usr/bin:/bin:/usr/sbin:/sbin\nexport PATH\n';
  for (const name of names) {
    const contents = await readFile(resolve(directory, name), 'utf8');
    assert.ok(contents.startsWith(safePrefix), `${name} must fix and export PATH immediately after its shebang`);
  }
});

test('platform entries use the packaged Node and runner without shell interpolation', async () => {
  const [runner, windowsDeploy, windowsReceipt, windowsAbandon, windowsCommand, windowsReceiptCommand, windowsAbandonCommand, macDeploy, macReceipt, macAbandon, macCommand, macReceiptCommand, macAbandonCommand, builder] = await Promise.all([
    readFile(resolve(root, 'platform', 'bootstrap', 'bootstrap-runner.mjs'), 'utf8'),
    readFile(resolve(root, 'platform', 'bootstrap', 'windows', 'Start-HONGAI-Delivery.ps1'), 'utf8'),
    readFile(resolve(root, 'platform', 'bootstrap', 'windows', 'Retry-HONGAI-Receipt.ps1'), 'utf8'),
    readFile(resolve(root, 'platform', 'bootstrap', 'windows', 'Abandon-HONGAI-Delivery.ps1'), 'utf8'),
    readFile(resolve(root, 'platform', 'bootstrap', 'windows', '00-Start-HONGAI-Delivery.cmd'), 'utf8'),
    readFile(resolve(root, 'platform', 'bootstrap', 'windows', '01-Retry-HONGAI-Receipt.cmd'), 'utf8'),
    readFile(resolve(root, 'platform', 'bootstrap', 'windows', '99-Explicitly-Abandon-HONGAI-Delivery.cmd'), 'utf8'),
    readFile(resolve(root, 'platform', 'bootstrap', 'macos', 'start-delivery.sh'), 'utf8'),
    readFile(resolve(root, 'platform', 'bootstrap', 'macos', 'retry-receipt.sh'), 'utf8'),
    readFile(resolve(root, 'platform', 'bootstrap', 'macos', 'abandon-delivery.sh'), 'utf8'),
    readFile(resolve(root, 'platform', 'bootstrap', 'macos', '00-Start-HONGAI-Delivery.command'), 'utf8'),
    readFile(resolve(root, 'platform', 'bootstrap', 'macos', '01-Retry-HONGAI-Receipt.command'), 'utf8'),
    readFile(resolve(root, 'platform', 'bootstrap', 'macos', '99-Explicitly-Abandon-HONGAI-Delivery.command'), 'utf8'),
    readFile(resolve(root, 'src', 'bootstrap-builder.ts'), 'utf8')
  ]);
  assert.match(windowsDeploy, /runtime\\node\.exe/);
  assert.match(windowsReceipt, /runtime\\node\.exe/);
  assert.match(windowsAbandon, /runtime\\node\.exe/);
  assert.match(macDeploy, /runtime\/bin\/node/);
  assert.match(macReceipt, /runtime\/bin\/node/);
  assert.match(macAbandon, /runtime\/bin\/node/);
  assert.match(runner, /spawn\(process\.execPath/);
  assert.match(runner, /hidden|secrets are never stored here/);
  assert.match(runner, /sanitizedChildEnvironment/);
  assert.match(runner, /EDGE_CAGE_/);
  assert.match(runner, /if \(process\.platform === 'darwin'\) environment\.PATH = '\/usr\/bin:\/bin:\/usr\/sbin:\/sbin';/);
  assert.doesNotMatch(runner, /env:\s*process\.env/);
  for (const launcher of [macDeploy, macReceipt, macAbandon]) assert.match(launcher, /unset NODE_OPTIONS NODE_PATH/);
  for (const launcher of [windowsDeploy, windowsReceipt, windowsAbandon]) assert.match(launcher, /Remove-Item Env:NODE_OPTIONS/);
  assert.match(windowsCommand, /-Verb RunAs/);
  assert.match(windowsCommand, /%~dp0Start-HONGAI-Delivery\.ps1/);
  assert.match(windowsReceiptCommand, /%~dp0Retry-HONGAI-Receipt\.ps1/);
  assert.match(windowsAbandonCommand, /%~dp0Abandon-HONGAI-Delivery\.ps1/);
  for (const launcher of [windowsCommand, windowsReceiptCommand, windowsAbandonCommand, macCommand, macReceiptCommand, macAbandonCommand]) {
    assert.doesNotMatch(launcher, /licenseKey|oneTimeToken|--license|--token/i);
  }
  assert.match(macCommand, /start-delivery\.sh/);
  assert.match(macReceiptCommand, /retry-receipt\.sh/);
  assert.match(macAbandonCommand, /abandon-delivery\.sh/);
  assert.doesNotMatch(`${macCommand}\n${macReceiptCommand}\n${macAbandonCommand}`, /xattr|spctl|--master-disable/i);
  assert.doesNotMatch(runner, /shell:\s*true|execSync|eval\(/);
  assert.match(builder, /HONGAI-BOOTSTRAP-MANIFEST\.json|BOOTSTRAP-MANIFEST\.json/);
  assert.match(builder, /sha256/);
  assert.match(builder, /process\.execPath/);
  assert.doesNotMatch(builder, /@anthropic-ai[\\/]claude-code.*copy|npm\s+(?:ci|install)/i);
});

test('native bootstrap smoke build verifies with its packaged Node and excludes Claude payloads', async () => {
  const parent = process.platform === 'win32' ? 'E:\\codexdata' : tmpdir();
  await mkdir(parent, { recursive: true });
  const output = await mkdtemp(join(parent, '_hongai-bootstrap-test-'));
  try {
    const result = await buildBootstrap({
      projectRoot: root,
      outputDirectory: output,
      unsafeAllowDirtyForTests: true
    });
    const manifest = JSON.parse(await readFile(resolve(result.bootstrapRoot, 'BOOTSTRAP-MANIFEST.json'), 'utf8')) as {
      files: Array<{ path: string }>;
      runtime: { path: string };
      commitSha: string;
      treeSha: string;
    };
    assert.equal(manifest.files.some((file) => /@anthropic-ai|claude-code|sandbox-runtime/i.test(file.path)), false);
    const packagedPaths = new Set(manifest.files.map((file) => file.path));
    assert.ok(packagedPaths.has('README.md'));
    assert.ok(packagedPaths.has(process.platform === 'win32'
      ? '00-Start-HONGAI-Delivery.cmd'
      : '00-Start-HONGAI-Delivery.command'));
    assert.ok(packagedPaths.has(process.platform === 'win32'
      ? '01-Retry-HONGAI-Receipt.cmd'
      : '01-Retry-HONGAI-Receipt.command'));
    assert.equal(result.record.contents.claudeRuntimeIncluded, false);
    assert.equal(result.record.contents.secretsEmbedded, false);
    assert.deepEqual(result.record.contents.runtimeDependencyPackages, ['undici', 'yaml', 'zod']);
    assert.match(result.record.source.commitSha, /^[a-f0-9]{40,64}$/);
    assert.equal(result.record.source.commitSha, manifest.commitSha);
    assert.equal(result.record.source.treeSha, manifest.treeSha);
    assert.equal(result.record.source.workingTree, 'unsafe-dirty-test');
    assert.match(result.bootstrapRoot, new RegExp(`${result.record.source.commitSha.slice(0, 12)}$`));
    const packagedNode = resolve(result.bootstrapRoot, ...manifest.runtime.path.split('/'));
    await execFile(packagedNode, ['--check', resolve(result.bootstrapRoot, 'bootstrap-runner.mjs')]);
    const deploymentModule = pathToFileURL(resolve(result.bootstrapRoot, 'app', 'src', 'deployment.js')).href;
    const deliveryClientModule = pathToFileURL(resolve(result.bootstrapRoot, 'app', 'src', 'delivery-client.js')).href;
    const configModule = pathToFileURL(resolve(result.bootstrapRoot, 'app', 'src', 'config.js')).href;
    await execFile(packagedNode, [
      '--input-type=module',
      '-e',
      'await import(process.argv[1]); await import(process.argv[2]); await import(process.argv[3]);',
      deploymentModule,
      deliveryClientModule,
      configModule
    ]);
    await assert.rejects(
      execFile(packagedNode, [resolve(result.bootstrapRoot, 'bootstrap-runner.mjs'), 'deploy']),
      (error: unknown) => /delivery\.json.*missing/i.test(String((error as { stderr?: unknown }).stderr ?? error))
    );
    const delivery = JSON.parse(await readFile(resolve(result.bootstrapRoot, 'delivery.example.json'), 'utf8')) as Record<string, unknown>;
    delivery.serviceUrl = 'http://127.0.0.1:9/';
    delivery.artifactId = `hongai-edge-cage-0.2.0-alpha.4-${process.platform === 'win32' ? 'windows' : 'macos'}-${process.arch}-${'a'.repeat(12)}`;
    delivery.archiveOutput = resolve(result.bootstrapRoot, 'artifact.tgz');
    delivery.installRoot = resolve(output, 'install-root');
    if (process.platform === 'darwin') delivery.currentLink = resolve(output, 'current');
    await writeFile(resolve(result.bootstrapRoot, 'delivery.json'), `${JSON.stringify(delivery, null, 2)}\n`, 'utf8');
    await assert.rejects(
      execFile(packagedNode, [resolve(result.bootstrapRoot, 'bootstrap-runner.mjs'), 'deploy']),
      (error: unknown) => /archiveOutput.*outside the bootstrap/i.test(String((error as { stderr?: unknown }).stderr ?? error))
    );
    delivery.archiveOutput = resolve(output, 'artifact.tgz');
    delivery.installRoot = resolve(output, 'install-root');
    if (process.platform === 'darwin') delivery.currentLink = resolve(output, 'current');
    await writeFile(resolve(result.bootstrapRoot, 'delivery.json'), `${JSON.stringify(delivery, null, 2)}\n`, 'utf8');
    await writeFile(resolve(result.bootstrapRoot, 'customer.yaml'), 'schemaVersion: 1\n', 'utf8');
    await writeFile(resolve(result.bootstrapRoot, 'delivery-signing-public.pem'), 'not-a-key-yet\n', 'utf8');
    await assert.rejects(
      execFile(packagedNode, [resolve(result.bootstrapRoot, 'bootstrap-runner.mjs'), 'deploy']),
      (error: unknown) => {
        const stderr = String((error as { stderr?: unknown }).stderr ?? error);
        return !/undeclared file/i.test(stderr) && /expected object|configuration|yaml|schema|public key|ed25519/i.test(stderr);
      }
    );
    await writeFile(resolve(result.bootstrapRoot, 'undeclared-loader.js'), 'throw new Error("not allowed");\n', 'utf8');
    await assert.rejects(
      execFile(packagedNode, [resolve(result.bootstrapRoot, 'bootstrap-runner.mjs'), 'deploy']),
      (error: unknown) => /undeclared file/i.test(String((error as { stderr?: unknown }).stderr ?? error))
    );
  } finally {
    await rm(output, { recursive: true, force: true });
  }
});
