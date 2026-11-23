#!/usr/bin/env node

import { createHash, randomBytes } from 'node:crypto';
import { spawn } from 'node:child_process';
import { link, mkdir, open, realpath, rm } from 'node:fs/promises';
import { gzipSync } from 'node:zlib';
import {
  dirname,
  isAbsolute,
  relative,
  resolve,
  sep,
  win32
} from 'node:path';
import { fileURLToPath } from 'node:url';

interface CommandResult {
  stdout: Buffer;
  stderr: Buffer;
}

export interface ReleaseBuildRecord {
  schemaVersion: 1;
  product: 'HONG AI Edge Cage';
  version: string;
  commitSha: string;
  treeSha: string;
  commitTimestamp: string;
  releaseMetadata: {
    packageJson: {
      gitBlobSha: string;
      sha256: string;
      name: '@hongai/edge-cage';
      version: string;
    };
    deliveryManifest: {
      gitBlobSha: string;
      sha256: string;
      schemaVersion: 1;
      product: 'HONG AI Edge Cage';
      version: string;
      bundleType: 'source';
      platforms: ['windows', 'macos'];
    };
  };
  sourceArchive: {
    filename: string;
    sha256: string;
    bytes: number;
    format: 'tar+gzip';
    rootPrefix: 'package/';
  };
  toolchain: {
    node: string;
    npm: string;
    git: string;
    zlib: string;
  };
  reproducibility: {
    committedTreeOnly: true;
    cleanWorktreeRequired: true;
    gzipHeaderTimestamp: 0;
    gzipHeaderOperatingSystem: 255;
  };
}

export interface ReleaseBuildResult {
  archivePath: string;
  recordPath: string;
  record: ReleaseBuildRecord;
}

export interface ReleaseBuilderOptions {
  projectRoot: string;
  outputDirectory: string;
}

function command(
  file: string,
  args: string[],
  cwd: string,
  maximumOutputBytes = 512 * 1024 * 1024,
  timeoutMs = 60_000
): Promise<CommandResult> {
  return new Promise((resolveCommand, reject) => {
    const child = spawn(file, args, {
      cwd,
      stdio: ['ignore', 'pipe', 'pipe'],
      windowsHide: true
    });
    const stdout: Buffer[] = [];
    const stderr: Buffer[] = [];
    let outputBytes = 0;
    let settled = false;
    let timeout: NodeJS.Timeout | undefined;
    const settle = (callback: () => void): void => {
      if (settled) return;
      settled = true;
      if (timeout) clearTimeout(timeout);
      callback();
    };
    timeout = setTimeout(() => {
      child.kill();
      settle(() => reject(new Error(`${file} timed out after ${timeoutMs}ms.`)));
    }, timeoutMs);
    const collect = (target: Buffer[]) => (chunk: Buffer) => {
      outputBytes += chunk.length;
      if (outputBytes > maximumOutputBytes) {
        child.kill();
        settle(() => reject(new Error(`${file} output exceeded the release-builder safety limit.`)));
        return;
      }
      target.push(Buffer.from(chunk));
    };
    child.stdout.on('data', collect(stdout));
    child.stderr.on('data', collect(stderr));
    child.once('error', (error) => settle(() => reject(error)));
    child.once('exit', (code, signal) => settle(() => {
      if (signal) {
        reject(new Error(`${file} terminated by signal ${signal}.`));
      } else if (code !== 0) {
        reject(new Error(`${file} exited with code ${code ?? 1}: ${Buffer.concat(stderr).toString('utf8').trim()}`));
      } else {
        resolveCommand({ stdout: Buffer.concat(stdout), stderr: Buffer.concat(stderr) });
      }
    }));
  });
}

function text(result: CommandResult): string {
  return result.stdout.toString('utf8').trim();
}

function isWithin(parent: string, candidate: string): boolean {
  const path = relative(parent, candidate);
  return path === '' || (!path.startsWith(`..${sep}`) && path !== '..' && !isAbsolute(path));
}

async function nearestExistingAncestor(value: string): Promise<string> {
  let candidate = value;
  while (true) {
    try {
      return await realpath(candidate);
    } catch (error: unknown) {
      if (!(error && typeof error === 'object' && 'code' in error && error.code === 'ENOENT')) throw error;
      const parent = dirname(candidate);
      if (parent === candidate) throw error;
      candidate = parent;
    }
  }
}

export function validateReleaseOutputDirectory(
  value: string,
  platform: NodeJS.Platform = process.platform
): string {
  if (/^c:[\\/]/i.test(value)) {
    throw new Error('Release output must not be written to the C: system drive.');
  }
  if (platform === 'win32') {
    if (!win32.isAbsolute(value)) throw new Error('Release output directory must be an absolute D: or E: path.');
    const drive = win32.parse(value).root.slice(0, 2).toUpperCase();
    if (!['D:', 'E:'].includes(drive)) {
      throw new Error('Release output directory must be on D: or E:.');
    }
    return win32.resolve(value);
  }
  if (!isAbsolute(value)) throw new Error('Release output directory must be absolute.');
  return resolve(value);
}

function sha256(value: Buffer): string {
  return createHash('sha256').update(value).digest('hex');
}

async function writeExclusiveAtomic(path: string, value: Buffer | string): Promise<void> {
  const temporaryPath = `${path}.${process.pid}.${randomBytes(6).toString('hex')}.tmp`;
  const handle = await open(temporaryPath, 'wx', 0o600);
  let closed = false;
  try {
    await handle.writeFile(value);
    await handle.sync();
    await handle.close();
    closed = true;
    await link(temporaryPath, path);
  } finally {
    if (!closed) await handle.close().catch(() => {});
    await rm(temporaryPath, { force: true });
  }
}

function safeVersion(value: unknown): string {
  if (typeof value !== 'string' || !/^[0-9A-Za-z][0-9A-Za-z.+-]{0,79}$/.test(value)) {
    throw new Error('package.json contains an invalid release version.');
  }
  return value;
}

interface ReleaseMetadata {
  version: string;
  packageJson: {
    gitBlobSha: string;
    sha256: string;
  };
  deliveryManifest: {
    gitBlobSha: string;
    sha256: string;
    platforms: ['windows', 'macos'];
  };
}

async function readReleaseMetadata(
  projectRoot: string,
  commitSha: string
): Promise<ReleaseMetadata> {
  const packageBytes = (await command(
    'git',
    ['show', `${commitSha}:package.json`],
    projectRoot
  )).stdout;
  const packageMetadata = JSON.parse(packageBytes.toString('utf8')) as {
    name?: unknown;
    version?: unknown;
  };
  if (packageMetadata.name !== '@hongai/edge-cage') {
    throw new Error('package.json does not identify @hongai/edge-cage.');
  }
  const version = safeVersion(packageMetadata.version);
  const deliveryBytes = (await command(
    'git',
    ['show', `${commitSha}:HONGAI-DELIVERY.json`],
    projectRoot
  )).stdout;
  const delivery = JSON.parse(deliveryBytes.toString('utf8')) as {
    schemaVersion?: unknown;
    product?: unknown;
    version?: unknown;
    bundleType?: unknown;
    platforms?: unknown;
  };
  if (delivery.schemaVersion !== 1 || delivery.product !== 'HONG AI Edge Cage' || delivery.bundleType !== 'source') {
    throw new Error('HONGAI-DELIVERY.json is not a HONG AI source delivery manifest.');
  }
  const platforms = Array.isArray(delivery.platforms) ? delivery.platforms : [];
  if (
    platforms.length !== 2
    || new Set(platforms).size !== 2
    || !platforms.includes('windows')
    || !platforms.includes('macos')
  ) {
    throw new Error('HONGAI-DELIVERY.json must declare exactly the Windows and macOS delivery platforms.');
  }
  if (delivery.version !== version) {
    throw new Error('package.json and HONGAI-DELIVERY.json versions do not match.');
  }
  const packageBlobSha = text(await command(
    'git',
    ['rev-parse', `${commitSha}:package.json`],
    projectRoot
  ));
  const deliveryBlobSha = text(await command(
    'git',
    ['rev-parse', `${commitSha}:HONGAI-DELIVERY.json`],
    projectRoot
  ));
  if (!/^[a-f0-9]{40,64}$/.test(packageBlobSha) || !/^[a-f0-9]{40,64}$/.test(deliveryBlobSha)) {
    throw new Error('Git returned an invalid release metadata blob identifier.');
  }
  return {
    version,
    packageJson: {
      gitBlobSha: packageBlobSha,
      sha256: sha256(packageBytes)
    },
    deliveryManifest: {
      gitBlobSha: deliveryBlobSha,
      sha256: sha256(deliveryBytes),
      platforms: ['windows', 'macos']
    }
  };
}

export async function buildReleaseBundle(options: ReleaseBuilderOptions): Promise<ReleaseBuildResult> {
  const projectRoot = await realpath(resolve(options.projectRoot));
  const requestedOutputDirectory = validateReleaseOutputDirectory(options.outputDirectory);
  const outputAncestor = await nearestExistingAncestor(requestedOutputDirectory);
  validateReleaseOutputDirectory(outputAncestor);
  if (
    isWithin(projectRoot, requestedOutputDirectory)
    || isWithin(projectRoot, outputAncestor)
  ) {
    throw new Error('Release output directory must be outside the Git worktree.');
  }

  const repositoryRoot = await realpath(resolve(
    text(await command('git', ['rev-parse', '--show-toplevel'], projectRoot))
  ));
  const sameRepository = process.platform === 'win32'
    ? repositoryRoot.toLowerCase() === projectRoot.toLowerCase()
    : repositoryRoot === projectRoot;
  if (!sameRepository) throw new Error('Project root must be the Git repository root.');

  const status = text(await command('git', ['status', '--porcelain=v1', '--untracked-files=all'], projectRoot));
  if (status) throw new Error('Git worktree must be clean before building a release.');

  const commitSha = text(await command('git', ['rev-parse', 'HEAD'], projectRoot));
  const treeSha = text(await command('git', ['rev-parse', 'HEAD^{tree}'], projectRoot));
  const commitEpoch = Number(text(await command('git', ['show', '-s', '--format=%ct', 'HEAD'], projectRoot)));
  if (!/^[a-f0-9]{40,64}$/.test(commitSha) || !/^[a-f0-9]{40,64}$/.test(treeSha)) {
    throw new Error('Git returned an invalid commit or tree identifier.');
  }
  if (!Number.isSafeInteger(commitEpoch) || commitEpoch < 0) {
    throw new Error('Git returned an invalid commit timestamp.');
  }
  const releaseMetadata = await readReleaseMetadata(projectRoot, commitSha);
  const version = releaseMetadata.version;

  const tar = (await command(
    'git',
    ['archive', '--format=tar', '--prefix=package/', commitSha],
    projectRoot
  )).stdout;
  const archive = gzipSync(tar, { level: 9 });
  if (archive.length < 10) throw new Error('gzip returned an invalid source archive.');
  archive.fill(0, 4, 8);
  archive[9] = 255;

  const finalStatus = text(await command(
    'git',
    ['status', '--porcelain=v1', '--untracked-files=all'],
    projectRoot
  ));
  const finalCommitSha = text(await command('git', ['rev-parse', 'HEAD'], projectRoot));
  const finalTreeSha = text(await command('git', ['rev-parse', 'HEAD^{tree}'], projectRoot));
  if (finalStatus || finalCommitSha !== commitSha || finalTreeSha !== treeSha) {
    tar.fill(0);
    archive.fill(0);
    throw new Error('Git repository changed while the release bundle was being built.');
  }

  const archiveHash = sha256(archive);
  const shortCommit = commitSha.slice(0, 12);
  const archiveFilename = `hongai-edge-cage-${version}-${shortCommit}-source.tgz`;
  const recordFilename = `${archiveFilename}.build-record.json`;
  const npmVersion = process.platform === 'win32'
    ? text(await command(
      process.env.ComSpec ?? 'C:\\Windows\\System32\\cmd.exe',
      ['/d', '/s', '/c', 'npm --version'],
      projectRoot,
      1024 * 1024
    ))
    : text(await command('npm', ['--version'], projectRoot, 1024 * 1024));
  const record: ReleaseBuildRecord = {
    schemaVersion: 1,
    product: 'HONG AI Edge Cage',
    version,
    commitSha,
    treeSha,
    commitTimestamp: new Date(commitEpoch * 1000).toISOString(),
    releaseMetadata: {
      packageJson: {
        gitBlobSha: releaseMetadata.packageJson.gitBlobSha,
        sha256: releaseMetadata.packageJson.sha256,
        name: '@hongai/edge-cage',
        version
      },
      deliveryManifest: {
        gitBlobSha: releaseMetadata.deliveryManifest.gitBlobSha,
        sha256: releaseMetadata.deliveryManifest.sha256,
        schemaVersion: 1,
        product: 'HONG AI Edge Cage',
        version,
        bundleType: 'source',
        platforms: releaseMetadata.deliveryManifest.platforms
      }
    },
    sourceArchive: {
      filename: archiveFilename,
      sha256: archiveHash,
      bytes: archive.length,
      format: 'tar+gzip',
      rootPrefix: 'package/'
    },
    toolchain: {
      node: process.version,
      npm: npmVersion,
      git: text(await command('git', ['--version'], projectRoot, 1024 * 1024)),
      zlib: process.versions.zlib
    },
    reproducibility: {
      committedTreeOnly: true,
      cleanWorktreeRequired: true,
      gzipHeaderTimestamp: 0,
      gzipHeaderOperatingSystem: 255
    }
  };

  await mkdir(requestedOutputDirectory, { recursive: true });
  const outputDirectory = await realpath(requestedOutputDirectory);
  validateReleaseOutputDirectory(outputDirectory);
  if (isWithin(projectRoot, outputDirectory)) {
    throw new Error('Release output directory resolves inside the Git worktree.');
  }
  const archivePath = resolve(outputDirectory, archiveFilename);
  const recordPath = resolve(outputDirectory, recordFilename);
  let archiveCreated = false;
  try {
    await writeExclusiveAtomic(archivePath, archive);
    archiveCreated = true;
    await writeExclusiveAtomic(recordPath, `${JSON.stringify(record, null, 2)}\n`);
  } catch (error) {
    if (archiveCreated) await rm(archivePath, { force: true }).catch(() => {});
    throw error;
  } finally {
    tar.fill(0);
    archive.fill(0);
  }

  return { archivePath, recordPath, record };
}

function argument(name: string): string | undefined {
  const index = process.argv.indexOf(`--${name}`);
  return index >= 0 ? process.argv[index + 1] : undefined;
}

async function main(): Promise<void> {
  const projectRoot = argument('project-root');
  const outputDirectory = argument('output-dir');
  if (!projectRoot || !outputDirectory) {
    throw new Error('Usage: release-builder --project-root <absolute-repo-root> --output-dir <absolute-data-drive-path>');
  }
  if (!isAbsolute(projectRoot)) throw new Error('--project-root must be absolute.');
  const result = await buildReleaseBundle({ projectRoot, outputDirectory });
  console.log(JSON.stringify({
    ok: true,
    archivePath: result.archivePath,
    recordPath: result.recordPath,
    sha256: result.record.sourceArchive.sha256,
    bytes: result.record.sourceArchive.bytes,
    commitSha: result.record.commitSha,
    treeSha: result.record.treeSha,
    version: result.record.version,
    next: 'Encrypt the source archive locally before any upload. Never upload this plaintext .tgz.'
  }, null, 2));
}

const invokedPath = process.argv[1] ? resolve(process.argv[1]) : '';
if (invokedPath === resolve(fileURLToPath(import.meta.url))) {
  main().catch((error: unknown) => {
    console.error(JSON.stringify({
      ok: false,
      error: error instanceof Error ? error.message : String(error)
    }));
    process.exitCode = 1;
  });
}
