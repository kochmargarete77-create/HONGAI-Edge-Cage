#!/usr/bin/env node

import { createHash } from 'node:crypto';
import { spawn } from 'node:child_process';
import { createReadStream, createWriteStream } from 'node:fs';
import { appendFile, chmod, lstat, mkdir, readFile, rm } from 'node:fs/promises';
import { dirname, isAbsolute, join, resolve } from 'node:path';
import { Readable, Transform } from 'node:stream';
import { pipeline } from 'node:stream/promises';
import { fileURLToPath } from 'node:url';

process.umask(0o077);

function argument(name) {
  const index = process.argv.indexOf(`--${name}`);
  return index >= 0 ? process.argv[index + 1] : undefined;
}

async function sha256File(path) {
  const hash = createHash('sha256');
  for await (const chunk of createReadStream(path)) hash.update(chunk);
  return hash.digest('hex');
}

function command(file, args) {
  return new Promise((resolveCommand, reject) => {
    const child = spawn(file, args, { stdio: ['ignore', 'pipe', 'pipe'] });
    const stdout = [];
    const stderr = [];
    child.stdout.on('data', (chunk) => stdout.push(Buffer.from(chunk)));
    child.stderr.on('data', (chunk) => stderr.push(Buffer.from(chunk)));
    child.once('error', reject);
    child.once('exit', (code, signal) => {
      if (signal) return reject(new Error(`${file} terminated by signal ${signal}.`));
      if (code !== 0) {
        return reject(new Error(
          `${file} exited with code ${code ?? 1}: ${Buffer.concat(stderr).toString('utf8').trim()}`
        ));
      }
      resolveCommand(Buffer.concat(stdout).toString('utf8'));
    });
  });
}

function safeArchiveEntries(listing, requiredPath) {
  const entries = listing.split(/\r?\n/).filter(Boolean);
  if (entries.length === 0 || entries.filter((entry) => entry === requiredPath).length !== 1) {
    throw new Error('Pinned ripgrep archive does not contain its declared binary.');
  }
  for (const entry of entries) {
    const normalized = entry.endsWith('/') ? entry.slice(0, -1) : entry;
    if (
      !normalized
      || normalized.startsWith('/')
      || normalized.includes('\\')
      || normalized.split('/').some((part) => !part || part === '.' || part === '..')
    ) throw new Error(`Pinned ripgrep archive contains an unsafe path: ${entry}`);
  }
}

async function main() {
  if (process.platform !== 'darwin') throw new Error('This provisioning tool is supported only on macOS.');
  const targetName = argument('target');
  const outputInput = argument('output-dir');
  const githubEnvironment = argument('github-env');
  if (!targetName || !outputInput || !githubEnvironment) {
    throw new Error(
      'Usage: provision-macos-ripgrep.mjs --target macos-arm64|macos-x64 ' +
      '--output-dir /absolute/path --github-env /absolute/path'
    );
  }
  if (!isAbsolute(outputInput) || !isAbsolute(githubEnvironment)) {
    throw new Error('Provisioning output and GitHub environment paths must be absolute.');
  }
  const repositoryRoot = resolve(dirname(fileURLToPath(import.meta.url)), '..');
  const manifest = JSON.parse(await readFile(
    resolve(repositoryRoot, 'third_party', 'ripgrep-14.1.1-release.json'),
    'utf8'
  ));
  const target = manifest.targets?.[targetName];
  const expectedArchitecture = targetName === 'macos-arm64'
    ? 'arm64'
    : targetName === 'macos-x64' ? 'x64' : undefined;
  if (
    manifest.schemaVersion !== 1
    || manifest.name !== 'ripgrep'
    || manifest.version !== '14.1.1'
    || manifest.versionOutput !== 'ripgrep 14.1.1 (rev 4649aa9700)'
    || manifest.sourceRepository !== 'https://github.com/BurntSushi/ripgrep'
    || !target
    || !expectedArchitecture
    || target.architecture !== expectedArchitecture
    || !/^ripgrep-14\.1\.1-(?:aarch64|x86_64)-apple-darwin\.tar\.gz$/.test(target.archiveName)
    || !/^[a-f0-9]{64}$/.test(target.archiveSha256)
    || !/^[a-f0-9]{64}$/.test(target.binarySha256)
    || target.downloadUrl !== `${manifest.sourceRepository}/releases/download/${manifest.version}/${target.archiveName}`
    || target.binaryPath !== `${target.archiveName.slice(0, -'.tar.gz'.length)}/rg`
  ) throw new Error('Pinned ripgrep release manifest is invalid.');

  const outputDirectory = resolve(outputInput);
  await mkdir(outputDirectory, { recursive: true });
  const targetRoot = join(outputDirectory, targetName);
  await mkdir(targetRoot, { recursive: false, mode: 0o700 });
  const archivePath = join(targetRoot, target.archiveName);
  try {
    const response = await fetch(target.downloadUrl, {
      redirect: 'follow',
      signal: AbortSignal.timeout(120_000)
    });
    if (!response.ok || !response.body || !response.url.startsWith('https://')) {
      throw new Error(`Unable to download pinned ripgrep release: HTTP ${response.status}.`);
    }
    const declaredLength = response.headers.get('content-length');
    if (
      declaredLength !== null
      && (!/^\d+$/.test(declaredLength) || Number(declaredLength) > 16 * 1024 * 1024)
    ) throw new Error('Pinned ripgrep response declared an invalid or oversized body.');
    let downloadedBytes = 0;
    const sizeGate = new Transform({
      transform(chunk, _encoding, callback) {
        downloadedBytes += chunk.length;
        if (downloadedBytes > 16 * 1024 * 1024) {
          callback(new Error('Pinned ripgrep download exceeded the 16 MiB safety limit.'));
        } else {
          callback(null, chunk);
        }
      }
    });
    await pipeline(
      Readable.fromWeb(response.body),
      sizeGate,
      createWriteStream(archivePath, { flags: 'wx', mode: 0o600 })
    );
    if (await sha256File(archivePath) !== target.archiveSha256) {
      throw new Error('Pinned ripgrep archive SHA-256 does not match the release manifest.');
    }
    const listing = await command('/usr/bin/tar', ['-tzf', archivePath]);
    safeArchiveEntries(listing, target.binaryPath);
    await command('/usr/bin/tar', ['-xzf', archivePath, '-C', targetRoot, '--', target.binaryPath]);
    const binaryPath = join(targetRoot, ...target.binaryPath.split('/'));
    const metadata = await lstat(binaryPath);
    if (!metadata.isFile() || metadata.isSymbolicLink()) {
      throw new Error('Pinned ripgrep binary is not a regular non-link file.');
    }
    if (await sha256File(binaryPath) !== target.binarySha256) {
      throw new Error('Pinned ripgrep binary SHA-256 does not match the release manifest.');
    }
    await chmod(binaryPath, 0o755);
    if (/\r|\n/.test(binaryPath)) throw new Error('Pinned ripgrep path contains a line break.');
    const githubEnvironmentMetadata = await lstat(githubEnvironment);
    if (!githubEnvironmentMetadata.isFile() || githubEnvironmentMetadata.isSymbolicLink()) {
      throw new Error('GitHub environment target must be a regular non-link file.');
    }
    await appendFile(githubEnvironment, `HONGAI_RIPGREP_SOURCE=${binaryPath}\n`, 'utf8');
    process.stdout.write(`${JSON.stringify({ ok: true, target: targetName, path: binaryPath })}\n`);
  } finally {
    await rm(archivePath, { force: true });
  }
}

main().catch((error) => {
  process.stderr.write(`${JSON.stringify({ ok: false, error: error instanceof Error ? error.message : String(error) })}\n`);
  process.exitCode = 1;
});
