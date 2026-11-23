import { spawn } from 'node:child_process';
import { randomUUID } from 'node:crypto';
import { access, lstat, mkdir, mkdtemp, open, readFile, readdir, rename, rm, statfs } from 'node:fs/promises';
import { dirname, isAbsolute, join, resolve } from 'node:path';
import { z } from 'zod';

const deliveryManifestSchema = z.object({
  schemaVersion: z.literal(1),
  product: z.literal('HONG AI Edge Cage'),
  version: z.string().min(1).max(80),
  bundleType: z.literal('source'),
  platforms: z.array(z.enum(['windows', 'macos'])).min(1)
}).strict();

export interface DeploymentResult {
  installRoot: string;
  version: string;
  platform: 'windows' | 'macos';
}

function hostPlatform(): 'windows' | 'macos' {
  if (process.platform === 'win32') return 'windows';
  if (process.platform === 'darwin') return 'macos';
  throw new Error('Automatic customer deployment currently supports Windows and macOS only.');
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

export function validateSourceArchiveEntries(listing: string): string[] {
  const entries = listing.split(/\r?\n/).filter(Boolean);
  if (entries.length < 2 || entries.length > 10_000) {
    throw new Error('Source bundle contains an invalid number of entries.');
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
    throw new Error('Source bundle is missing HONGAI-DELIVERY.json.');
  }
  if (!entries.some((entry) => entry.replace(/\/+$/, '') === 'package/package.json')) {
    throw new Error('Source bundle is missing package.json.');
  }
  return entries;
}

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

async function pathDoesNotExist(path: string): Promise<boolean> {
  try {
    await lstat(path);
    return false;
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === 'ENOENT') return true;
    throw error;
  }
}

export async function preflightDeploymentTarget(args: {
  installRoot: string;
  configPath: string;
  minimumFreeBytes?: number;
}): Promise<{ platform: 'windows' | 'macos'; availableBytes: number }> {
  if (![args.installRoot, args.configPath].every(isAbsolute)) {
    throw new Error('Install root and customer config paths must be absolute.');
  }
  const installRoot = resolve(args.installRoot);
  const configPath = resolve(args.configPath);
  const platform = hostPlatform();
  await access(configPath);
  if (!(await pathDoesNotExist(installRoot))) {
    throw new Error('Install root already exists; refusing to consume a token or overwrite an existing deployment.');
  }
  const parent = dirname(installRoot);
  await mkdir(parent, { recursive: true });
  const probePath = join(parent, `.hongai-write-probe-${randomUUID()}`);
  const probe = await open(probePath, 'wx', 0o600);
  await probe.close();
  await rm(probePath, { force: true });
  const filesystem = await statfs(parent);
  const availableBytes = Number(filesystem.bavail) * Number(filesystem.bsize);
  const minimumFreeBytes = args.minimumFreeBytes ?? 3 * 1024 * 1024 * 1024;
  if (!Number.isFinite(availableBytes) || availableBytes < minimumFreeBytes) {
    throw new Error(`Install volume requires at least ${minimumFreeBytes} free bytes before activation.`);
  }
  return { platform, availableBytes };
}

export async function deploySourceArchive(args: {
  archivePath: string;
  installRoot: string;
  configPath: string;
}): Promise<DeploymentResult> {
  if (![args.archivePath, args.installRoot, args.configPath].every(isAbsolute)) {
    throw new Error('Archive, install root and customer config paths must be absolute.');
  }
  const archivePath = resolve(args.archivePath);
  const installRoot = resolve(args.installRoot);
  const configPath = resolve(args.configPath);
  await access(archivePath);
  await preflightDeploymentTarget({ installRoot, configPath });

  validateSourceArchiveEntries(await capture('tar', ['-tzf', archivePath]));
  const verboseListing = await capture('tar', ['-tvzf', archivePath]);
  validateTarEntryTypes(verboseListing);
  validateTarExpandedSize(verboseListing);
  const parent = dirname(installRoot);
  await mkdir(parent, { recursive: true });
  const stagingRoot = await mkdtemp(join(parent, '.hongai-edge-cage-install-'));
  try {
    await capture('tar', ['-xzf', archivePath, '-C', stagingRoot]);
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
    const platform = hostPlatform();
    if (!manifest.platforms.includes(platform)) {
      throw new Error(`Bundle does not support ${platform}.`);
    }
    const installerPath = platform === 'windows'
      ? resolve(packageRoot, 'platform', 'windows', 'Install-HONGAI-Edge-Cage.ps1')
      : resolve(packageRoot, 'platform', 'macos', 'install.sh');
    await access(installerPath);

    if (platform === 'windows') {
      await inherit(
        'powershell.exe',
        [
          '-NoLogo',
          '-NoProfile',
          '-NonInteractive',
          '-ExecutionPolicy',
          'Bypass',
          '-File',
          installerPath,
          '-ConfigPath',
          configPath
        ],
        packageRoot
      );
    } else {
      await inherit(
        '/bin/sh',
        [installerPath, configPath],
        packageRoot
      );
    }
    if (!(await pathDoesNotExist(installRoot))) {
      throw new Error('Install root appeared during deployment; refusing to overwrite it.');
    }
    await rename(packageRoot, installRoot);
    return { installRoot, version: manifest.version, platform };
  } finally {
    await rm(stagingRoot, { recursive: true, force: true });
  }
}
