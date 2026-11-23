import { spawn } from 'node:child_process';
import { createHash, randomUUID } from 'node:crypto';
import { createReadStream, createWriteStream } from 'node:fs';
import { access, lstat, mkdir, mkdtemp, open, readFile, readdir, realpath, rename, rm, stat, statfs, writeFile } from 'node:fs/promises';
import { dirname, isAbsolute, join, relative, resolve, sep } from 'node:path';
import { Transform } from 'node:stream';
import { pipeline } from 'node:stream/promises';
import { z } from 'zod';

const sourceDeliveryManifestSchema = z.object({
  schemaVersion: z.literal(1),
  product: z.literal('HONG AI Edge Cage'),
  version: z.string().min(1).max(80),
  bundleType: z.literal('source'),
  platforms: z.array(z.enum(['windows', 'macos'])).min(1)
}).strict();

const portableDeliveryManifestSchema = z.object({
  schemaVersion: z.literal(2),
  product: z.literal('HONG AI Edge Cage'),
  version: z.string().min(1).max(80),
  bundleType: z.literal('portable'),
  platform: z.enum(['windows', 'macos']),
  architecture: z.enum(['x64', 'arm64']),
  commitSha: z.string().regex(/^[a-f0-9]{40,64}$/),
  treeSha: z.string().regex(/^[a-f0-9]{40,64}$/),
  runtime: z.object({
    node: z.string().min(1).max(80),
    claudeCode: z.string().min(1).max(80),
    sandboxRuntime: z.string().min(1).max(80)
  }).strict(),
  payloadManifest: z.literal('HONGAI-PAYLOAD.json')
}).strict();

const deliveryManifestSchema = z.discriminatedUnion('schemaVersion', [
  sourceDeliveryManifestSchema,
  portableDeliveryManifestSchema
]);

const payloadFileSchema = z.object({
  path: z.string().min(1).max(512),
  bytes: z.number().int().nonnegative().max(2 * 1024 * 1024 * 1024),
  sha256: z.string().regex(/^[a-f0-9]{64}$/)
}).strict();

const portablePayloadManifestSchema = z.object({
  schemaVersion: z.literal(1),
  product: z.literal('HONG AI Edge Cage'),
  artifactId: z.string().min(1).max(240).regex(/^[a-zA-Z0-9._-]+$/),
  commitSha: z.string().regex(/^[a-f0-9]{40,64}$/),
  treeSha: z.string().regex(/^[a-f0-9]{40,64}$/),
  files: z.array(payloadFileSchema).min(1).max(25_000)
}).strict();

type DeliveryManifest = z.infer<typeof deliveryManifestSchema>;

interface TrustedPlatformHelpers {
  tar: string;
  powershell?: string;
  icacls?: string;
}

export interface DeploymentResult {
  installRoot: string;
  version: string;
  platform: 'windows' | 'macos';
  currentLink?: string;
  transactionWarning?: string;
}

export interface PortablePayloadVerificationResult {
  artifactId: string;
  fileCount: number;
  totalBytes: number;
}

function hostPlatform(): 'windows' | 'macos' {
  if (process.platform === 'win32') return 'windows';
  if (process.platform === 'darwin') return 'macos';
  throw new Error('Automatic customer deployment currently supports Windows and macOS only.');
}

async function trustedSystemExecutable(path: string, label: string): Promise<string> {
  if (!isAbsolute(path)) throw new Error(`${label} path is not absolute.`);
  const metadata = await lstat(path);
  if (!metadata.isFile() || metadata.isSymbolicLink()) {
    throw new Error(`${label} must be a regular non-link system executable.`);
  }
  return path;
}

async function trustedPlatformHelpers(platform: 'windows' | 'macos'): Promise<TrustedPlatformHelpers> {
  if (platform === 'macos') {
    return { tar: await trustedSystemExecutable('/usr/bin/tar', 'macOS tar') };
  }
  const systemRootValue = process.env.SystemRoot ?? process.env.WINDIR ?? 'C:\\Windows';
  if (!/^[A-Za-z]:[\\/]Windows$/i.test(systemRootValue)) {
    throw new Error('Windows SystemRoot is unavailable or has an unexpected value.');
  }
  const systemRoot = resolve(systemRootValue);
  const [powershell, tar, icacls] = await Promise.all([
    trustedSystemExecutable(
      resolve(systemRoot, 'System32', 'WindowsPowerShell', 'v1.0', 'powershell.exe'),
      'Windows PowerShell'
    ),
    trustedSystemExecutable(resolve(systemRoot, 'System32', 'tar.exe'), 'Windows system tar'),
    trustedSystemExecutable(resolve(systemRoot, 'System32', 'icacls.exe'), 'Windows ACL utility')
  ]);
  return { powershell, tar, icacls };
}

async function protectWindowsTree(
  path: string,
  helpers: TrustedPlatformHelpers,
  userReadExecute = false
): Promise<void> {
  if (process.platform !== 'win32') return;
  const grants = [
    '*S-1-5-32-544:(OI)(CI)(F)',
    '*S-1-5-18:(OI)(CI)(F)'
  ];
  if (userReadExecute) {
    const userSid = (await capture(helpers.powershell!, [
      '-NoLogo', '-NoProfile', '-NonInteractive', '-Command',
      '[Security.Principal.WindowsIdentity]::GetCurrent().User.Value'
    ], 64 * 1024)).trim();
    if (!/^S-1-[0-9-]+$/.test(userSid)) throw new Error('Unable to determine the Windows customer user SID safely.');
    grants.push(`*${userSid}:(OI)(CI)(RX)`);
  }
  await capture(helpers.icacls!, [path, '/inheritance:r', '/grant:r', ...grants, '/t', '/c'], 8 * 1024 * 1024, 120_000);
}

async function copyFileVerified(source: string, destination: string, expectedSha256?: string): Promise<string> {
  const sourceMetadata = await lstat(source);
  if (!sourceMetadata.isFile() || sourceMetadata.isSymbolicLink()) {
    throw new Error(`Verified copy source must be a regular non-link file: ${source}`);
  }
  const hash = createHash('sha256');
  const hasher = new Transform({
    transform(chunk: Buffer, _encoding, callback) {
      hash.update(chunk);
      callback(null, chunk);
    }
  });
  await pipeline(
    createReadStream(source),
    hasher,
    createWriteStream(destination, { flags: 'wx', mode: 0o600 })
  );
  const digest = hash.digest('hex');
  if (expectedSha256 && digest !== expectedSha256) {
    await rm(destination, { force: true });
    throw new Error('Artifact changed after signed download verification.');
  }
  return digest;
}

export function assertNativePilotArtifactId(artifactId: string): void {
  const match = artifactId.match(/-(windows|macos)-(x64|arm64)-[a-f0-9]{12}$/);
  if (!match) {
    throw new Error('Customer deployment accepts only an architecture-native pilot artifact ID, not a source bundle.');
  }
  const platform = hostPlatform();
  if (match[1] !== platform || match[2] !== process.arch) {
    throw new Error(`Artifact ${artifactId} does not match this ${platform}/${process.arch} host.`);
  }
}

function capture(
  command: string,
  arguments_: string[],
  maximumOutputBytes = 8 * 1024 * 1024,
  timeoutMs = 30_000
): Promise<string> {
  return new Promise((resolveOutput, reject) => {
    const child = spawn(command, arguments_, {
      stdio: ['ignore', 'pipe', 'pipe'],
      windowsHide: true
    });
    const output: Buffer[] = [];
    const errors: Buffer[] = [];
    let size = 0;
    let settled = false;
    const finish = (callback: () => void): void => {
      if (settled) return;
      settled = true;
      clearTimeout(timeout);
      callback();
    };
    const timeout = setTimeout(() => {
      child.kill();
      finish(() => reject(new Error(`${command} timed out after ${timeoutMs}ms.`)));
    }, timeoutMs);
    const collect = (target: Buffer[]) => (chunk: Buffer) => {
      size += chunk.length;
      if (size > maximumOutputBytes) {
        child.kill();
        finish(() => reject(new Error('Archive listing exceeded the safety limit.')));
        return;
      }
      target.push(Buffer.from(chunk));
    };
    child.stdout.on('data', collect(output));
    child.stderr.on('data', collect(errors));
    child.once('error', (error) => finish(() => reject(error)));
    child.once('exit', (code) => {
      if (code !== 0) {
        finish(() => reject(new Error(`${command} failed: ${Buffer.concat(errors).toString('utf8').trim()}`)));
        return;
      }
      finish(() => resolveOutput(Buffer.concat(output).toString('utf8')));
    });
  });
}

function inherit(command: string, arguments_: string[], cwd: string): Promise<void> {
  return new Promise((resolveExit, reject) => {
    const child = spawn(command, arguments_, {
      cwd,
      stdio: 'inherit',
      windowsHide: false
    });
    child.once('error', reject);
    child.once('exit', (code, signal) => {
      if (signal) {
        reject(new Error(`${command} terminated by signal ${signal}.`));
      } else if (code !== 0) {
        reject(new Error(`${command} exited with code ${code ?? 1}.`));
      } else {
        resolveExit();
      }
    });
  });
}

export function validateDeliveryArchiveEntries(listing: string): string[] {
  const entries = listing.split(/\r?\n/).filter(Boolean);
  if (entries.length < 2 || entries.length > 25_000) {
    throw new Error('Delivery bundle contains an invalid number of entries.');
  }
  const canonicalEntries = new Set<string>();
  for (const rawEntry of entries) {
    if (
      rawEntry.length > 512 ||
      rawEntry.includes('\\') ||
      /[\u0000-\u001f\u007f]/.test(rawEntry) ||
      /[<>:"|?*]/.test(rawEntry)
    ) {
      throw new Error(`Unsafe archive entry: ${rawEntry}`);
    }
    const entry = rawEntry.replace(/\/+$/, '');
    if (entry !== entry.normalize('NFC')) {
      throw new Error(`Archive entry is not Unicode NFC normalized: ${rawEntry}`);
    }
    const segments = entry.split('/');
    if (
      entry.startsWith('/') ||
      /^[a-zA-Z]:/.test(entry) ||
      segments[0] !== 'package' ||
      segments.some((segment) =>
        !segment ||
        segment === '..' ||
        segment === '.' ||
        segment.trim() !== segment ||
        /[. ]$/.test(segment) ||
        /^(con|prn|aux|nul|com[1-9]|lpt[1-9])(?:\..*)?$/i.test(segment)
      )
    ) {
      throw new Error(`Unsafe archive entry: ${rawEntry}`);
    }
    const canonicalEntry = segments.map((segment) => segment.toLowerCase()).join('/');
    if (canonicalEntries.has(canonicalEntry)) {
      throw new Error(`Archive contains a duplicate or case-colliding entry: ${rawEntry}`);
    }
    canonicalEntries.add(canonicalEntry);
  }
  if (!entries.some((entry) => entry.replace(/\/+$/, '') === 'package/HONGAI-DELIVERY.json')) {
    throw new Error('Delivery bundle is missing HONGAI-DELIVERY.json.');
  }
  if (!entries.some((entry) => entry.replace(/\/+$/, '') === 'package/package.json')) {
    throw new Error('Delivery bundle is missing package.json.');
  }
  return entries;
}

/** @deprecated Retained for source-bundle API compatibility. */
export const validateSourceArchiveEntries = validateDeliveryArchiveEntries;

export function validateTarEntryTypes(verboseListing: string): void {
  const lines = verboseListing.split(/\r?\n/).filter(Boolean);
  if (lines.some((line) => !['-', 'd'].includes(line[0] ?? ''))) {
    throw new Error('Source bundle contains a link, device, socket or other unsupported entry type.');
  }
}

export function validateTarExpandedSize(
  verboseListing: string,
  maximumExpandedBytes = 2 * 1024 * 1024 * 1024
): number {
  let total = 0;
  for (const line of verboseListing.split(/\r?\n/).filter(Boolean)) {
    if ((line[0] ?? '') === 'd') continue;
    const fields = line.trim().split(/\s+/);
    const sizeField = /^\d+$/.test(fields[1] ?? '') && /^\d+$/.test(fields[2] ?? '') && /^\d+$/.test(fields[3] ?? '')
      ? fields[3]
      : (fields[1]?.includes('/') && /^\d+$/.test(fields[2] ?? '') ? fields[2] : undefined);
    if (sizeField === undefined) {
      throw new Error('Unable to determine an archive entry size safely.');
    }
    const size = Number(sizeField);
    if (!Number.isSafeInteger(size) || size < 0) {
      throw new Error('Archive entry has an invalid expanded size.');
    }
    total += size;
    if (!Number.isSafeInteger(total) || total > maximumExpandedBytes) {
      throw new Error('Source bundle exceeds the expanded-size safety limit.');
    }
  }
  return total;
}

async function rejectLinks(root: string): Promise<void> {
  for (const entry of await readdir(root, { withFileTypes: true })) {
    const path = join(root, entry.name);
    const stat = await lstat(path);
    if (stat.isSymbolicLink()) throw new Error(`Source bundle contains a symbolic link: ${entry.name}`);
    if (stat.isDirectory()) await rejectLinks(path);
  }
}

function validatePayloadPath(value: string): string {
  if (
    value.length > 512
    || value.includes('\\')
    || value.startsWith('/')
    || /^[a-zA-Z]:/.test(value)
    || /[\u0000-\u001f\u007f]/.test(value)
    || /[<>:"|?*]/.test(value)
    || value !== value.normalize('NFC')
  ) {
    throw new Error(`Portable payload manifest contains an unsafe path: ${value}`);
  }
  const segments = value.split('/');
  if (segments.some((segment) =>
    !segment
    || segment === '.'
    || segment === '..'
    || segment.trim() !== segment
    || /[. ]$/.test(segment)
    || /^(con|prn|aux|nul|com[1-9]|lpt[1-9])(?:\..*)?$/i.test(segment)
  )) {
    throw new Error(`Portable payload manifest contains an unsafe path: ${value}`);
  }
  return segments.join('/');
}

async function sha256File(path: string): Promise<string> {
  const hash = createHash('sha256');
  for await (const chunk of createReadStream(path)) hash.update(chunk as Buffer);
  return hash.digest('hex');
}

async function regularPayloadFiles(root: string): Promise<Map<string, string>> {
  const files = new Map<string, string>();
  async function visit(directory: string): Promise<void> {
    const entries = await readdir(directory, { withFileTypes: true });
    for (const entry of entries) {
      const path = join(directory, entry.name);
      const metadata = await lstat(path);
      if (metadata.isSymbolicLink()) {
        throw new Error(`Portable payload contains a symbolic link: ${path}`);
      }
      if (metadata.isDirectory()) {
        await visit(path);
      } else if (metadata.isFile()) {
        const portablePath = relative(root, path).split(sep).join('/');
        files.set(portablePath, path);
      } else {
        throw new Error(`Portable payload contains an unsupported filesystem entry: ${path}`);
      }
    }
  }
  await visit(root);
  return files;
}

export async function verifyPortablePayload(
  packageRoot: string,
  deliveryManifest: Extract<DeliveryManifest, { bundleType: 'portable' }>,
  options: { allowedAdditionalPaths?: string[] } = {}
): Promise<PortablePayloadVerificationResult> {
  const manifestPath = resolve(packageRoot, deliveryManifest.payloadManifest);
  const payloadManifest = portablePayloadManifestSchema.parse(JSON.parse(
    await readFile(manifestPath, 'utf8')
  ) as unknown);
  if (
    payloadManifest.commitSha !== deliveryManifest.commitSha
    || payloadManifest.treeSha !== deliveryManifest.treeSha
  ) {
    throw new Error('Portable payload provenance does not match HONGAI-DELIVERY.json.');
  }

  const expected = new Map<string, z.infer<typeof payloadFileSchema>>();
  const canonicalPaths = new Set<string>();
  let totalBytes = 0;
  for (const file of payloadManifest.files) {
    const path = validatePayloadPath(file.path);
    if (path === deliveryManifest.payloadManifest) {
      throw new Error('Portable payload manifest must not include itself.');
    }
    const canonicalPath = path.toLowerCase();
    if (canonicalPaths.has(canonicalPath)) {
      throw new Error(`Portable payload manifest has a duplicate or case-colliding path: ${path}`);
    }
    canonicalPaths.add(canonicalPath);
    expected.set(path, file);
    totalBytes += file.bytes;
    if (!Number.isSafeInteger(totalBytes) || totalBytes > 2 * 1024 * 1024 * 1024) {
      throw new Error('Portable payload manifest exceeds the expanded-size safety limit.');
    }
  }

  const actual = await regularPayloadFiles(packageRoot);
  const actualPayloadManifest = actual.get(deliveryManifest.payloadManifest);
  if (!actualPayloadManifest) throw new Error('Portable payload manifest file is missing.');
  actual.delete(deliveryManifest.payloadManifest);
  const allowedAdditionalPaths = (options.allowedAdditionalPaths ?? []).map((value) => {
    const directoryPrefix = value.endsWith('/');
    const path = validatePayloadPath(directoryPrefix ? value.slice(0, -1) : value);
    return directoryPrefix ? `${path}/` : path;
  });
  for (const path of [...actual.keys()]) {
    if (!expected.has(path) && allowedAdditionalPaths.some((allowed) => (
      allowed.endsWith('/') ? path.startsWith(allowed) : path === allowed
    ))) {
      actual.delete(path);
    }
  }
  if (actual.size !== expected.size) {
    throw new Error(`Portable payload file set mismatch: expected ${expected.size}, found ${actual.size}.`);
  }
  for (const [path, metadata] of expected) {
    const actualPath = actual.get(path);
    if (!actualPath) throw new Error(`Portable payload file is missing or has different casing: ${path}`);
    const actualMetadata = await stat(actualPath);
    if (actualMetadata.size !== metadata.bytes) {
      throw new Error(`Portable payload size mismatch: ${path}`);
    }
    if (await sha256File(actualPath) !== metadata.sha256) {
      throw new Error(`Portable payload digest mismatch: ${path}`);
    }
  }
  return { artifactId: payloadManifest.artifactId, fileCount: expected.size, totalBytes };
}

export async function verifyInstalledPortablePayload(
  packageRoot: string
): Promise<PortablePayloadVerificationResult> {
  const root = resolve(packageRoot);
  const manifest = deliveryManifestSchema.parse(JSON.parse(
    await readFile(resolve(root, 'HONGAI-DELIVERY.json'), 'utf8')
  ) as unknown);
  if (manifest.bundleType !== 'portable') {
    throw new Error('Installed payload is not a portable offline-runtime bundle.');
  }
  const platform = hostPlatform();
  if (manifest.platform !== platform || manifest.architecture !== process.arch) {
    throw new Error('Installed portable payload does not match this host.');
  }
  return await verifyPortablePayload(root, manifest, {
    allowedAdditionalPaths: platform === 'windows'
      ? ['.edge-cage/windows-install-state.json']
      : ['.hongai-install.json']
  });
}

export async function verifyCompletedDeployment(args: {
  installRoot: string;
  configPath: string;
  currentLink?: string;
  runDoctor?: boolean;
  repairMacActivation?: boolean;
}): Promise<PortablePayloadVerificationResult> {
  if (!isAbsolute(args.installRoot) || !isAbsolute(args.configPath)) {
    throw new Error('Installed recovery paths must be absolute.');
  }
  const installRoot = resolve(args.installRoot);
  const configPath = resolve(args.configPath);
  const verification = await verifyInstalledPortablePayload(installRoot);
  const configSha256 = await sha256File(configPath);
  const platform = hostPlatform();
  if (platform === 'windows') {
    const marker = z.object({
      schemaVersion: z.literal(1),
      product: z.literal('HONG AI Edge Cage'),
      status: z.literal('INSTALLED'),
      configSha256: z.string().regex(/^[a-f0-9]{64}$/)
    }).passthrough().parse(JSON.parse(
      await readFile(resolve(installRoot, '.edge-cage', 'windows-install-state.json'), 'utf8')
    ) as unknown);
    if (marker.configSha256 !== configSha256) {
      throw new Error('Installed Windows marker is bound to a different customer configuration.');
    }
    if (args.runDoctor) {
      const helpers = await trustedPlatformHelpers(platform);
      await inherit(
        helpers.powershell!,
        [
          '-NoLogo',
          '-NoProfile',
          '-NonInteractive',
          '-ExecutionPolicy',
          'Bypass',
          '-File',
          resolve(installRoot, 'platform', 'windows', 'Test-HONGAI-Edge-Cage.ps1'),
          '-ConfigPath',
          configPath
        ],
        installRoot
      );
    }
  } else {
    const marker = z.object({
      schemaVersion: z.literal(1),
      product: z.literal('HONG AI Edge Cage'),
      platform: z.literal('macos'),
      configSha256: z.string().regex(/^[a-f0-9]{64}$/)
    }).passthrough().parse(JSON.parse(
      await readFile(resolve(installRoot, '.hongai-install.json'), 'utf8')
    ) as unknown);
    if (marker.configSha256 !== configSha256) {
      throw new Error('Installed macOS marker is bound to a different customer configuration.');
    }
    if (!args.currentLink || !isAbsolute(args.currentLink)) {
      throw new Error('macOS installed recovery requires the absolute currentLink.');
    }
    if (args.repairMacActivation) {
      const activationPath = resolve(installRoot, 'platform', 'macos', 'activate.sh');
      await access(activationPath);
      await inherit('/bin/sh', [activationPath, installRoot, resolve(args.currentLink)], installRoot);
    }
    const [activeTarget, installedTarget] = await Promise.all([
      realpath(resolve(args.currentLink)),
      realpath(installRoot)
    ]);
    if (activeTarget !== installedTarget) {
      throw new Error('macOS currentLink does not point to the completed installation.');
    }
    if (args.runDoctor) {
      await inherit(
        '/bin/sh',
        [resolve(installRoot, 'platform', 'macos', 'doctor.sh'), configPath],
        installRoot
      );
    }
  }
  return verification;
}

async function pathDoesNotExist(path: string): Promise<boolean> {
  try {
    await lstat(path);
    return false;
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === 'ENOENT') return true;
    throw error;
  }
}

function pathWithin(parent: string, child: string): boolean {
  const path = relative(resolve(parent), resolve(child));
  return path === '' || (!path.startsWith(`..${sep}`) && path !== '..' && !isAbsolute(path));
}

export async function recoverInterruptedWindowsDeployment(args: {
  installRoot: string;
  expectedArtifactId: string;
}): Promise<{ quarantinePath: string }> {
  if (process.platform !== 'win32') {
    throw new Error('Interrupted Windows deployment recovery is available on Windows only.');
  }
  if (!isAbsolute(args.installRoot)) {
    throw new Error('Interrupted Windows install root must be absolute.');
  }
  const installRoot = resolve(args.installRoot);
  const verified = await verifyInstalledPortablePayload(installRoot);
  if (verified.artifactId !== args.expectedArtifactId) {
    throw new Error('Interrupted Windows payload does not match the requested signed artifact.');
  }
  const statePath = resolve(installRoot, '.edge-cage', 'windows-install-state.json');
  const state = z.object({
    schemaVersion: z.literal(1),
    product: z.literal('HONG AI Edge Cage'),
    status: z.literal('INSTALLING'),
    sandboxPreexisting: z.boolean()
  }).passthrough().parse(JSON.parse(await readFile(statePath, 'utf8')) as unknown);
  if (typeof state.sandboxPreexisting !== 'boolean') {
    throw new Error('Interrupted Windows ownership journal is incomplete.');
  }

  const helpers = await trustedPlatformHelpers('windows');
  const uninstallerPath = resolve(installRoot, 'platform', 'windows', 'Uninstall-HONGAI-Edge-Cage.ps1');
  await access(uninstallerPath);
  await inherit(
    helpers.powershell!,
    [
      '-NoLogo',
      '-NoProfile',
      '-NonInteractive',
      '-ExecutionPolicy',
      'Bypass',
      '-File',
      uninstallerPath,
      '-SuppressInterruptedCompletionRecord'
    ],
    installRoot
  );
  if (!(await pathDoesNotExist(statePath))) {
    throw new Error('Interrupted Windows recovery did not retire the INSTALLING ownership journal.');
  }
  const afterRecovery = await verifyInstalledPortablePayload(installRoot);
  if (afterRecovery.artifactId !== args.expectedArtifactId) {
    throw new Error('Recovered Windows payload identity changed unexpectedly.');
  }
  const quarantinePath = `${installRoot}.interrupted-${randomUUID()}`;
  await rename(installRoot, quarantinePath);
  return { quarantinePath };
}

function assertWindowsDeliveryDrive(path: string, label: string): void {
  if (process.platform === 'win32' && !/^[DE]:[\\\\/]/i.test(path)) {
    throw new Error(`${label} must be on D: or E: for a Windows customer pilot.`);
  }
}

async function assertWindowsDataPathNoLinks(path: string, label: string): Promise<void> {
  assertWindowsDeliveryDrive(path, label);
  let candidate = resolve(path);
  while (true) {
    try {
      const metadata = await lstat(candidate);
      if (metadata.isSymbolicLink()) {
        throw new Error(`${label} contains a junction, mount point, or symbolic-link ancestor: ${candidate}`);
      }
      const canonical = await realpath(candidate);
      if (!/^[DE]:[\\/]/i.test(canonical)) {
        throw new Error(`${label} resolves outside the D: or E: data drive.`);
      }
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code !== 'ENOENT') throw error;
    }
    const parent = dirname(candidate);
    if (parent === candidate) break;
    candidate = parent;
  }
}

export async function preflightDeploymentTarget(args: {
  installRoot: string;
  configPath: string;
  archivePath?: string;
  currentLink?: string;
  minimumFreeBytes?: number;
}): Promise<{ platform: 'windows' | 'macos'; availableBytes: number }> {
  const paths = [args.installRoot, args.configPath, args.archivePath, args.currentLink]
    .filter((value): value is string => value !== undefined);
  if (!paths.every(isAbsolute)) {
    throw new Error('Install root, customer config, archive and current-link paths must be absolute when provided.');
  }
  const installRoot = resolve(args.installRoot);
  const configPath = resolve(args.configPath);
  const archivePath = args.archivePath ? resolve(args.archivePath) : undefined;
  const currentLink = args.currentLink ? resolve(args.currentLink) : undefined;
  const platform = hostPlatform();
  const helpers = await trustedPlatformHelpers(platform);
  if (platform === 'windows') {
    await assertWindowsDataPathNoLinks(installRoot, 'Install root');
    await assertWindowsDataPathNoLinks(configPath, 'Customer config');
    if (archivePath) await assertWindowsDataPathNoLinks(archivePath, 'Encrypted artifact output');
    if (currentLink) throw new Error('currentLink is a macOS-only deployment option.');
    const isAdministrator = (await capture(helpers.powershell!, [
      '-NoLogo', '-NoProfile', '-NonInteractive', '-Command',
      "[Security.Principal.WindowsPrincipal]::new([Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)"
    ])).trim().toLowerCase() === 'true';
    if (!isAdministrator) throw new Error('Windows customer deployment must be run from an Administrator PowerShell.');
  } else if (typeof process.getuid === 'function' && process.getuid() === 0) {
    throw new Error('macOS customer deployment must run as the signed-in user, not root; the installer will request sudo when needed.');
  }
  await access(configPath);
  if (archivePath) {
    if (pathWithin(installRoot, archivePath)) {
      throw new Error('Artifact archive cannot be stored inside the install root.');
    }
    const archiveParent = dirname(archivePath);
    await mkdir(archiveParent, { recursive: true });
    const archiveProbePath = join(archiveParent, `.hongai-archive-probe-${randomUUID()}`);
    const archiveProbe = await open(archiveProbePath, 'wx', 0o600);
    await archiveProbe.close();
    await rm(archiveProbePath, { force: true });
  }
  if (currentLink && (pathWithin(installRoot, currentLink) || pathWithin(currentLink, installRoot))) {
    throw new Error('macOS currentLink must be a sibling of versioned install roots, not an ancestor or child of installRoot.');
  }
  if (!(await pathDoesNotExist(installRoot))) {
    throw new Error('Install root already exists; refusing to consume a token or overwrite an existing deployment.');
  }
  const parent = dirname(installRoot);
  await mkdir(parent, { recursive: true });
  const probePath = join(parent, `.hongai-write-probe-${randomUUID()}`);
  const probe = await open(probePath, 'wx', 0o600);
  await probe.close();
  await rm(probePath, { force: true });
  await capture(helpers.tar, ['--version']);
  const filesystem = await statfs(parent);
  const availableBytes = Number(filesystem.bavail) * Number(filesystem.bsize);
  const minimumFreeBytes = args.minimumFreeBytes ?? 3 * 1024 * 1024 * 1024;
  if (!Number.isFinite(availableBytes) || availableBytes < minimumFreeBytes) {
    throw new Error(`Install volume requires at least ${minimumFreeBytes} free bytes before activation.`);
  }
  return { platform, availableBytes };
}

export async function deployArtifactArchive(args: {
  archivePath: string;
  installRoot: string;
  configPath: string;
  expectedArtifactId: string;
  expectedPlaintextSha256: string;
  currentLink?: string;
}): Promise<DeploymentResult> {
  if (![args.archivePath, args.installRoot, args.configPath].every(isAbsolute)) {
    throw new Error('Archive, install root and customer config paths must be absolute.');
  }
  const archivePath = resolve(args.archivePath);
  const installRoot = resolve(args.installRoot);
  const configPath = resolve(args.configPath);
  const currentLink = args.currentLink ? resolve(args.currentLink) : undefined;
  if (args.currentLink && !isAbsolute(args.currentLink)) {
    throw new Error('Current link must be absolute when provided.');
  }
  if (!/^[a-f0-9]{64}$/.test(args.expectedPlaintextSha256)) {
    throw new Error('Expected signed plaintext SHA-256 is invalid.');
  }
  await access(archivePath);
  await preflightDeploymentTarget({ archivePath, installRoot, configPath, ...(currentLink ? { currentLink } : {}) });

  const archiveTimeoutMs = 10 * 60 * 1000;
  const platform = hostPlatform();
  const helpers = await trustedPlatformHelpers(platform);
  const parent = dirname(installRoot);
  await mkdir(parent, { recursive: true });
  const transactionId = randomUUID();
  const stagingRoot = await mkdtemp(join(parent, '.hongai-edge-cage-install-'));
  if (platform === 'windows') await protectWindowsTree(stagingRoot, helpers, false);
  const protectedArchivePath = resolve(stagingRoot, 'verified-artifact.tgz');
  const protectedConfigPath = resolve(stagingRoot, 'customer-config.yaml');
  const transactionPath = join(parent, `.hongai-edge-cage-transaction-${transactionId}.json`);
  let payloadPlaced = false;
  let recoveryPath: string | undefined;
  const recordTransaction = async (
    phase: 'EXTRACTING' | 'VERIFIED' | 'PAYLOAD_PLACED' | 'INSTALLING' | 'COMPLETED' | 'FAILED',
    detail?: string
  ): Promise<void> => {
    const temporaryTransactionPath = `${transactionPath}.tmp-${randomUUID()}`;
    await writeFile(temporaryTransactionPath, `${JSON.stringify({
      schemaVersion: 1,
      product: 'HONG AI Edge Cage',
      transactionId,
      phase,
      installRoot,
      recoveryPath: recoveryPath ?? null,
      detail: detail ?? null,
      updatedAt: new Date().toISOString()
    }, null, 2)}\n`, { encoding: 'utf8', mode: 0o600 });
    await rename(temporaryTransactionPath, transactionPath);
  };
  try {
    await recordTransaction('EXTRACTING');
    await copyFileVerified(archivePath, protectedArchivePath, args.expectedPlaintextSha256);
    await copyFileVerified(configPath, protectedConfigPath);
    validateDeliveryArchiveEntries(await capture(helpers.tar, ['-tzf', protectedArchivePath], 8 * 1024 * 1024, archiveTimeoutMs));
    const protectedVerboseListing = await capture(helpers.tar, ['-tvzf', protectedArchivePath], 8 * 1024 * 1024, archiveTimeoutMs);
    validateTarEntryTypes(protectedVerboseListing);
    validateTarExpandedSize(protectedVerboseListing);
    await capture(helpers.tar, ['-xzf', protectedArchivePath, '-C', stagingRoot], 8 * 1024 * 1024, archiveTimeoutMs);
    const packageRoot = resolve(stagingRoot, 'package');
    await rejectLinks(packageRoot);
    const manifest = deliveryManifestSchema.parse(JSON.parse(
      await readFile(resolve(packageRoot, 'HONGAI-DELIVERY.json'), 'utf8')
    ) as unknown);
    const packageMetadata = z.object({
      name: z.literal('@hongai/edge-cage'),
      version: z.string().min(1)
    }).passthrough().parse(JSON.parse(
      await readFile(resolve(packageRoot, 'package.json'), 'utf8')
    ) as unknown);
    if (packageMetadata.version !== manifest.version) {
      throw new Error('Delivery manifest version does not match package.json.');
    }
    if (manifest.bundleType === 'source') {
      throw new Error('Source bundles are internal review artifacts and cannot be installed on customer computers.');
    } else {
      if (manifest.platform !== platform) {
        throw new Error(`Portable bundle targets ${manifest.platform}, not ${platform}.`);
      }
      if (manifest.architecture !== process.arch) {
        throw new Error(`Portable bundle targets ${manifest.architecture}, not ${process.arch}.`);
      }
      const verification = await verifyPortablePayload(packageRoot, manifest);
      if (verification.artifactId !== args.expectedArtifactId) {
        throw new Error(`Portable payload artifact ID ${verification.artifactId} does not match requested artifact ${args.expectedArtifactId}.`);
      }
    }
    const relativeInstallerPath = platform === 'windows'
      ? join('platform', 'windows', 'Install-HONGAI-Edge-Cage.ps1')
      : join('platform', 'macos', 'install.sh');
    await access(resolve(packageRoot, relativeInstallerPath));

    await recordTransaction('VERIFIED');
    if (!(await pathDoesNotExist(installRoot))) {
      throw new Error('Install root appeared during deployment; refusing to overwrite it.');
    }
    await rename(packageRoot, installRoot);
    payloadPlaced = true;
    await recordTransaction('PAYLOAD_PLACED');
    const installerPath = resolve(installRoot, relativeInstallerPath);
    await recordTransaction('INSTALLING');
    if (platform === 'windows') {
      await inherit(
        helpers.powershell!,
        [
          '-NoLogo',
          '-NoProfile',
          '-NonInteractive',
          '-ExecutionPolicy',
          'Bypass',
          '-File',
          installerPath,
          '-ConfigPath',
          protectedConfigPath,
          '-TransactionScratchPath',
          stagingRoot
        ],
        installRoot
      );
    } else {
      await inherit(
        '/bin/sh',
        [installerPath, protectedConfigPath],
        installRoot
      );
      if (currentLink) {
        const activationPath = resolve(installRoot, 'platform', 'macos', 'activate.sh');
        await access(activationPath);
        await inherit('/bin/sh', [activationPath, installRoot, currentLink], installRoot);
      }
    }
    if (platform === 'windows') await protectWindowsTree(installRoot, helpers, true);
    let transactionWarning: string | undefined;
    try {
      await recordTransaction('COMPLETED');
    } catch (error) {
      // Installation and platform activation already succeeded. Never move or
      // disable the live payload merely because the operator journal could not
      // record its final line; surface the warning for support reconciliation.
      transactionWarning = `Installed successfully, but completion journal update failed: ${error instanceof Error ? error.message : String(error)}`;
    }
    return {
      installRoot,
      version: manifest.version,
      platform,
      ...(currentLink ? { currentLink } : {}),
      ...(transactionWarning ? { transactionWarning } : {})
    };
  } catch (error) {
    const detail = error instanceof Error ? error.message : String(error);
    if (payloadPlaced && !(await pathDoesNotExist(installRoot))) {
      recoveryPath = `${installRoot}.failed-${transactionId}`;
      try {
        await rename(installRoot, recoveryPath);
      } catch (recoveryError) {
        await recordTransaction('FAILED', `${detail}; recovery move failed: ${recoveryError instanceof Error ? recoveryError.message : String(recoveryError)}`);
        throw new Error(`${detail} Installation payload remains at ${installRoot}; transaction: ${transactionPath}.`);
      }
    }
    try {
      await recordTransaction('FAILED', detail);
    } catch (journalError) {
      throw new Error(`${detail} Recovery payload: ${recoveryPath ?? 'not created'}; transaction journal also failed: ${journalError instanceof Error ? journalError.message : String(journalError)}.`);
    }
    throw new Error(`${detail} Recovery payload: ${recoveryPath ?? 'not created'}; transaction: ${transactionPath}.`);
  } finally {
    await rm(stagingRoot, { recursive: true, force: true });
  }
}

/** @deprecated Use deployArtifactArchive for source and portable deliveries. */
export const deploySourceArchive = deployArtifactArchive;
