import { spawn } from 'node:child_process';
import { access, lstat, mkdir, mkdtemp, readFile, readdir, rename, rm } from 'node:fs/promises';
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

function capture(command: string, arguments_: string[], maximumOutputBytes = 8 * 1024 * 1024): Promise<string> {
  return new Promise((resolveOutput, reject) => {
    const child = spawn(command, arguments_, {
      stdio: ['ignore', 'pipe', 'pipe'],
      windowsHide: true
    });
    const output: Buffer[] = [];
    const errors: Buffer[] = [];
    let size = 0;
    const collect = (target: Buffer[]) => (chunk: Buffer) => {
      size += chunk.length;
      if (size > maximumOutputBytes) {
        child.kill();
        reject(new Error('Archive listing exceeded the safety limit.'));
        return;
      }
      target.push(Buffer.from(chunk));
    };
    child.stdout.on('data', collect(output));
    child.stderr.on('data', collect(errors));
    child.once('error', reject);
    child.once('exit', (code) => {
      if (code !== 0) {
        reject(new Error(`${command} failed: ${Buffer.concat(errors).toString('utf8').trim()}`));
        return;
      }
      resolveOutput(Buffer.concat(output).toString('utf8'));
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
  for (const rawEntry of entries) {
    if (rawEntry.length > 512 || rawEntry.includes('\\') || rawEntry.includes('\0')) {
      throw new Error(`Unsafe archive entry: ${rawEntry}`);
    }
    const entry = rawEntry.replace(/\/+$/, '');
    const segments = entry.split('/');
    if (
      entry.startsWith('/') ||
      /^[a-zA-Z]:/.test(entry) ||
      segments[0] !== 'package' ||
      segments.some((segment) => segment === '..' || segment === '.')
    ) {
      throw new Error(`Unsafe archive entry: ${rawEntry}`);
    }
  }
  if (!entries.some((entry) => entry.replace(/\/+$/, '') === 'package/HONGAI-DELIVERY.json')) {
    throw new Error('Source bundle is missing HONGAI-DELIVERY.json.');
  }
  if (!entries.some((entry) => entry.replace(/\/+$/, '') === 'package/package.json')) {
    throw new Error('Source bundle is missing package.json.');
  }
  return entries;
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
  await Promise.all([access(archivePath), access(configPath)]);
  if (!(await pathDoesNotExist(installRoot))) {
    throw new Error('Install root already exists; refusing to overwrite an existing deployment.');
  }

  validateSourceArchiveEntries(await capture('tar', ['-tzf', archivePath]));
  const verboseListing = await capture('tar', ['-tvzf', archivePath]);
  if (verboseListing.split(/\r?\n/).some((line) =>
    /^[lh]/.test(line) || line.includes(' -> ') || line.includes(' link to ')
  )) {
    throw new Error('Source bundle contains a link entry.');
  }
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
    await rename(packageRoot, installRoot);

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
          resolve(installRoot, 'platform', 'windows', 'Install-HONGAI-Edge-Cage.ps1'),
          '-ConfigPath',
          configPath
        ],
        installRoot
      );
    } else {
      await inherit(
        '/bin/sh',
        [resolve(installRoot, 'platform', 'macos', 'install.sh'), configPath],
        installRoot
      );
    }
    return { installRoot, version: manifest.version, platform };
  } finally {
    await rm(stagingRoot, { recursive: true, force: true });
  }
}
