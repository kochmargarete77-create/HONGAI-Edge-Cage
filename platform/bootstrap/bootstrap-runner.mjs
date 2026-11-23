#!/usr/bin/env node

import { createHash } from 'node:crypto';
import { spawn } from 'node:child_process';
import { createReadStream } from 'node:fs';
import { lstat, readFile, readdir, realpath } from 'node:fs/promises';
import { basename, dirname, isAbsolute, relative, resolve, sep } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = dirname(fileURLToPath(import.meta.url));
const manifestPath = resolve(root, 'BOOTSTRAP-MANIFEST.json');
const deliveryPath = resolve(root, 'delivery.json');
const allowedDeliveryKeys = new Set([
  'schemaVersion',
  'serviceUrl',
  'artifactId',
  'signingPublicKey',
  'archiveOutput',
  'installRoot',
  'customerConfig',
  'currentLink',
  'keepArchive'
]);

function fail(message) {
  throw new Error(`HONG AI bootstrap: ${message}`);
}

function platformName() {
  if (process.platform === 'win32') return 'windows';
  if (process.platform === 'darwin') return 'macos';
  fail(`unsupported platform ${process.platform}`);
}

function safeRelativePath(value) {
  if (
    typeof value !== 'string'
    || !value
    || value.includes('\\')
    || value.startsWith('/')
    || /^[a-zA-Z]:/.test(value)
    || value.split('/').some((part) => !part || part === '.' || part === '..')
  ) {
    fail(`unsafe manifest path ${String(value)}`);
  }
  return value;
}

function inside(rootPath, candidate) {
  const prefix = rootPath.endsWith(sep) ? rootPath : `${rootPath}${sep}`;
  return candidate === rootPath || candidate.startsWith(prefix);
}

async function regularFile(path, label) {
  const metadata = await lstat(path).catch((error) => {
    if (error?.code === 'ENOENT') fail(`${label} is missing: ${path}`);
    throw error;
  });
  if (!metadata.isFile() || metadata.isSymbolicLink()) fail(`${label} must be a regular file: ${path}`);
  return metadata;
}

async function sha256File(path) {
  const hash = createHash('sha256');
  for await (const chunk of createReadStream(path)) hash.update(chunk);
  return hash.digest('hex');
}

async function actualBootstrapFiles(directory) {
  const files = [];
  async function visit(current) {
    const entries = await readdir(current, { withFileTypes: true });
    for (const entry of entries) {
      const path = resolve(current, entry.name);
      const metadata = await lstat(path);
      if (metadata.isSymbolicLink()) fail(`bootstrap contains a symbolic link: ${path}`);
      if (metadata.isDirectory()) await visit(path);
      else if (metadata.isFile()) files.push(path);
      else fail(`bootstrap contains an unsupported filesystem entry: ${path}`);
    }
  }
  await visit(directory);
  return files;
}

async function readSmallJson(path, label, maximumBytes = 128 * 1024) {
  const metadata = await regularFile(path, label);
  if (metadata.size <= 0 || metadata.size > maximumBytes) fail(`${label} is empty or oversized`);
  try {
    return JSON.parse(await readFile(path, 'utf8'));
  } catch {
    fail(`${label} is not valid JSON`);
  }
}

async function verifyBootstrap(mutableInputs) {
  const manifest = await readSmallJson(manifestPath, 'bootstrap manifest', 8 * 1024 * 1024);
  if (
    manifest?.schemaVersion !== 1
    || manifest?.product !== 'HONG AI Edge Cage Bootstrap'
    || manifest?.platform !== platformName()
    || manifest?.architecture !== process.arch
    || manifest?.runtime?.node !== process.version
    || !Array.isArray(manifest?.files)
  ) {
    fail('manifest identity, platform, architecture, or runtime does not match this computer');
  }
  const expectedRuntime = resolve(root, safeRelativePath(manifest.runtime.path));
  const [actualNode, packagedNode] = await Promise.all([realpath(process.execPath), realpath(expectedRuntime)]);
  const sameRuntime = process.platform === 'win32'
    ? actualNode.toLowerCase() === packagedNode.toLowerCase()
    : actualNode === packagedNode;
  if (!sameRuntime) fail('launcher is not using the bundled Node runtime');

  const seen = new Set();
  for (const entry of manifest.files) {
    const relativePath = safeRelativePath(entry?.path);
    const canonical = process.platform === 'win32' ? relativePath.toLowerCase() : relativePath;
    if (seen.has(canonical)) fail(`duplicate manifest path ${relativePath}`);
    seen.add(canonical);
    if (!Number.isSafeInteger(entry?.bytes) || entry.bytes < 0 || !/^[a-f0-9]{64}$/.test(entry?.sha256 ?? '')) {
      fail(`invalid manifest metadata for ${relativePath}`);
    }
    const path = resolve(root, ...relativePath.split('/'));
    if (!inside(root, path)) fail(`manifest path escapes bootstrap root: ${relativePath}`);
    const metadata = await regularFile(path, `bootstrap payload ${relativePath}`);
    if (metadata.size !== entry.bytes || await sha256File(path) !== entry.sha256) {
      fail(`bootstrap payload integrity check failed: ${relativePath}`);
    }
  }
  const canonicalPath = (value) => process.platform === 'win32' ? value.toLowerCase() : value;
  const mutableOrSelf = new Map([
    [canonicalPath('BOOTSTRAP-MANIFEST.json'), 8 * 1024 * 1024],
    [canonicalPath('delivery.json'), 128 * 1024],
    ...mutableInputs
  ]);
  for (const path of await actualBootstrapFiles(root)) {
    const relativePath = path.slice(root.length + 1).split(sep).join('/');
    const canonical = process.platform === 'win32' ? relativePath.toLowerCase() : relativePath;
    const maximumMutableBytes = mutableOrSelf.get(canonical);
    if (!seen.has(canonical) && maximumMutableBytes === undefined) {
      fail(`bootstrap contains an undeclared file: ${relativePath}`);
    }
    if (!seen.has(canonical)) {
      const metadata = await regularFile(path, `mutable bootstrap input ${relativePath}`);
      if (metadata.size <= 0 || metadata.size > maximumMutableBytes) {
        fail(`mutable bootstrap input is empty or oversized: ${relativePath}`);
      }
    }
  }
  return manifest;
}

function mutableBootstrapInputs(delivery) {
  const inputs = new Map();
  for (const [path, maximumBytes] of [
    [delivery.signingPublicKey, 64 * 1024],
    [delivery.customerConfig, 1024 * 1024]
  ]) {
    if (!inside(root, path)) continue;
    const relativePath = relative(root, path).split(sep).join('/');
    if (!relativePath || relativePath.startsWith('../')) {
      fail('mutable bootstrap input could not be resolved safely');
    }
    const canonical = process.platform === 'win32' ? relativePath.toLowerCase() : relativePath;
    const existing = inputs.get(canonical);
    inputs.set(canonical, existing === undefined ? maximumBytes : Math.min(existing, maximumBytes));
  }
  return inputs;
}

function configuredPath(value, field) {
  if (typeof value !== 'string' || !value.trim() || value.length > 4096) fail(`${field} must be a non-empty path`);
  if (/REPLACE_|\.invalid(?:[\\/]|$)/i.test(value)) fail(`${field} still contains a template placeholder`);
  return isAbsolute(value) ? resolve(value) : resolve(root, value);
}

function configuredOutputPath(value, field) {
  const path = configuredPath(value, field);
  if (inside(root, path)) {
    fail(`${field} must be outside the bootstrap directory so runtime state cannot invalidate its manifest`);
  }
  return path;
}

async function readDelivery() {
  const value = await readSmallJson(deliveryPath, 'adjacent delivery.json');
  if (!value || typeof value !== 'object' || Array.isArray(value)) fail('delivery.json must contain one object');
  for (const key of Object.keys(value)) {
    if (!allowedDeliveryKeys.has(key)) fail(`delivery.json contains unsupported field ${key}; secrets are never stored here`);
  }
  if (value.schemaVersion !== 1) fail('delivery.json schemaVersion must be 1');
  if (typeof value.serviceUrl !== 'string' || value.serviceUrl.length > 2048 || /\.invalid(?:[/:]|$)/i.test(value.serviceUrl)) {
    fail('serviceUrl is missing or still contains a template placeholder');
  }
  let serviceUrl;
  try {
    serviceUrl = new URL(value.serviceUrl);
  } catch {
    fail('serviceUrl is not a valid URL');
  }
  const loopback = ['127.0.0.1', 'localhost', '::1', '[::1]'].includes(serviceUrl.hostname);
  if (serviceUrl.protocol !== 'https:' && !(serviceUrl.protocol === 'http:' && loopback)) {
    fail('serviceUrl must use HTTPS; HTTP is allowed only for loopback development');
  }
  if (serviceUrl.username || serviceUrl.password) fail('serviceUrl must not contain credentials');
  if (typeof value.artifactId !== 'string' || !/^[A-Za-z0-9._-]{1,160}$/.test(value.artifactId) || /REPLACE_/i.test(value.artifactId)) {
    fail('artifactId is missing, unsafe, or still a template placeholder');
  }
  if (value.keepArchive !== undefined && typeof value.keepArchive !== 'boolean') fail('keepArchive must be boolean');
  const result = {
    serviceUrl: serviceUrl.href,
    artifactId: value.artifactId,
    signingPublicKey: configuredPath(value.signingPublicKey, 'signingPublicKey'),
    archiveOutput: configuredOutputPath(value.archiveOutput, 'archiveOutput'),
    installRoot: configuredOutputPath(value.installRoot, 'installRoot'),
    customerConfig: configuredPath(value.customerConfig, 'customerConfig'),
    currentLink: value.currentLink === undefined ? undefined : configuredOutputPath(value.currentLink, 'currentLink'),
    keepArchive: value.keepArchive === true
  };
  const platform = platformName();
  if (platform === 'windows' && result.currentLink !== undefined) {
    fail('currentLink is a macOS-only activation setting and must be omitted on Windows');
  }
  if (platform === 'macos' && result.currentLink === undefined) {
    fail('currentLink is required on macOS so activate/rollback uses the verified version');
  }
  return result;
}

function sanitizedChildEnvironment() {
  const common = new Set(['PATH', 'TEMP', 'TMP', 'TERM', 'LANG', 'LC_ALL']);
  const platformSpecific = process.platform === 'win32'
    ? ['SYSTEMROOT', 'WINDIR', 'COMSPEC', 'PATHEXT', 'USERPROFILE', 'APPDATA', 'LOCALAPPDATA']
    : ['HOME', 'USER', 'LOGNAME', 'SHELL', 'TMPDIR'];
  for (const key of platformSpecific) common.add(key);
  const environment = {};
  for (const [key, value] of Object.entries(process.env)) {
    if (value === undefined) continue;
    const normalized = process.platform === 'win32' ? key.toUpperCase() : key;
    if (common.has(normalized) || normalized.startsWith('EDGE_CAGE_')) environment[key] = value;
  }
  if (process.platform === 'darwin') environment.PATH = '/usr/bin:/bin:/usr/sbin:/sbin';
  return environment;
}

function runNode(entry, args) {
  return new Promise((resolveRun, reject) => {
    const child = spawn(process.execPath, [entry, ...args], {
      cwd: root,
      env: sanitizedChildEnvironment(),
      stdio: 'inherit',
      windowsHide: false,
      shell: false
    });
    child.once('error', reject);
    child.once('exit', (code, signal) => {
      if (signal) reject(new Error(`child process terminated by signal ${signal}`));
      else resolveRun(code ?? 1);
    });
  });
}

async function pendingReceipt(delivery, explicitPath) {
  if (explicitPath) return configuredPath(explicitPath, 'pending receipt');
  const directory = dirname(delivery.archiveOutput);
  const prefix = `${basename(delivery.archiveOutput)}.receipt-`;
  const candidates = (await readdir(directory, { withFileTypes: true }).catch((error) => {
    if (error?.code === 'ENOENT') return [];
    throw error;
  }))
    .filter((entry) => entry.isFile() && entry.name.startsWith(prefix) && entry.name.endsWith('.pending.json'))
    .map((entry) => resolve(directory, entry.name));
  if (candidates.length !== 1) {
    fail(`expected exactly one pending receipt beside archiveOutput, found ${candidates.length}; pass its absolute path explicitly`);
  }
  return candidates[0];
}

async function main() {
  const command = process.argv[2];
  if (!['deploy', 'receipt', 'abandon'].includes(command)) {
    fail('usage: bootstrap-runner.mjs <deploy|receipt|abandon> [absolute-pending-receipt]');
  }
  const delivery = await readDelivery();
  await verifyBootstrap(mutableBootstrapInputs(delivery));
  if (command === 'deploy') {
    await regularFile(delivery.signingPublicKey, 'delivery signing public key');
    await regularFile(delivery.customerConfig, 'customer configuration');
    const args = [
      '--service-url', delivery.serviceUrl,
      '--artifact-id', delivery.artifactId,
      '--signing-public-key', delivery.signingPublicKey,
      '--archive-output', delivery.archiveOutput,
      '--install-root', delivery.installRoot,
      '--config', delivery.customerConfig,
      '--keep-archive', String(delivery.keepArchive)
    ];
    if (delivery.currentLink) args.push('--current-link', delivery.currentLink);
    process.exitCode = await runNode(resolve(root, 'app', 'services', 'delivery-client', 'deploy.js'), args);
    return;
  }
  if (command === 'abandon') {
    await regularFile(delivery.signingPublicKey, 'delivery signing public key');
    await regularFile(delivery.customerConfig, 'customer configuration');
    const args = [
      '--service-url', delivery.serviceUrl,
      '--artifact-id', delivery.artifactId,
      '--signing-public-key', delivery.signingPublicKey,
      '--archive-output', delivery.archiveOutput,
      '--activation-recovery', `${delivery.archiveOutput}.activation.pending.json`,
      '--install-root', delivery.installRoot,
      '--config', delivery.customerConfig
    ];
    if (delivery.currentLink) args.push('--current-link', delivery.currentLink);
    process.exitCode = await runNode(resolve(root, 'app', 'services', 'delivery-client', 'abandon.js'), args);
    return;
  }
  const pending = await pendingReceipt(delivery, process.argv[3]);
  await regularFile(pending, 'pending receipt');
  process.exitCode = await runNode(
    resolve(root, 'app', 'services', 'delivery-client', 'receipt.js'),
    ['--pending', pending]
  );
}

main().catch((error) => {
  console.error(JSON.stringify({
    ok: false,
    error: error instanceof Error ? error.message : String(error)
  }));
  process.exitCode = 1;
});
