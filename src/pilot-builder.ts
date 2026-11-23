#!/usr/bin/env node

import { createHash, randomUUID } from 'node:crypto';
import { spawn } from 'node:child_process';
import { createReadStream } from 'node:fs';
import {
  access,
  chmod,
  cp,
  lstat,
  mkdir,
  readFile,
  readdir,
  realpath,
  rename,
  rm,
  stat,
  writeFile
} from 'node:fs/promises';
import { dirname, isAbsolute, join, relative, resolve, sep } from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  validateDeliveryArchiveEntries,
  validateTarEntryTypes,
  verifyPortablePayload
} from './deployment.js';
import { validateReleaseOutputDirectory } from './release-builder.js';

type PilotPlatform = 'windows' | 'macos';
type PilotArchitecture = 'x64' | 'arm64';

interface CommandResult {
  stdout: string;
  stderr: string;
}

export interface PilotBuildRecord {
  schemaVersion: 1;
  product: 'HONG AI Edge Cage';
  version: string;
  commitSha: string;
  treeSha: string;
  platform: PilotPlatform;
  architecture: PilotArchitecture;
  artifactId: string;
  archive: { filename: string; sha256: string; bytes: number; format: 'tar+gzip' };
  payloadManifestSha256: string;
  runtime: {
    node: string;
    claudeCode: string;
    sandboxRuntime: string;
    ripgrep: string | null;
    ripgrepSha256: string | null;
    ripgrepArchitectures: PilotArchitecture[] | null;
  };
  claudeCodeVendorSignature: ClaudeCodeVendorSignature;
  limitations: {
    codeSigned: false;
    notarized: false;
    runtimeDownloadRequiredDuringInstall: false;
    customerNetworkRequiredDuringInstall: true;
  };
}

export type ClaudeCodeVendorSignature = {
  scheme: 'authenticode';
  verified: true;
  signerSubject: string;
  productVersion: string;
  companyName: string;
  fileDescription: string;
} | {
  scheme: 'apple-codesign';
  verified: true;
  identifier: 'com.anthropic.claude-code';
  teamIdentifier: 'Q6L2SF6YDW';
  signingAuthority: string;
};

const anthropicAppleTeamIdentifier = 'Q6L2SF6YDW' as const;
const anthropicAppleBundleIdentifier = 'com.anthropic.claude-code' as const;

export interface PinnedMacRipgrepPolicy {
  version: '14.1.1';
  architecture: PilotArchitecture;
  archiveName: string;
  downloadUrl: string;
  archiveSha256: string;
  binaryPath: string;
  binarySha256: string;
}

export interface PilotBuildResult {
  archivePath: string;
  recordPath: string;
  record: PilotBuildRecord;
}

export interface PilotBuilderOptions {
  projectRoot: string;
  outputDirectory: string;
}

function command(
  file: string,
  args: string[],
  cwd: string,
  timeoutMs = 10 * 60 * 1000,
  maximumOutputBytes = 64 * 1024 * 1024,
  environment?: NodeJS.ProcessEnv
): Promise<CommandResult> {
  return new Promise((resolveCommand, reject) => {
    const child = spawn(file, args, {
      cwd,
      stdio: ['ignore', 'pipe', 'pipe'],
      windowsHide: true,
      ...(environment ? { env: environment } : {})
    });
    const stdout: Buffer[] = [];
    const stderr: Buffer[] = [];
    let bytes = 0;
    let settled = false;
    const settle = (callback: () => void): void => {
      if (settled) return;
      settled = true;
      clearTimeout(timeout);
      callback();
    };
    const timeout = setTimeout(() => {
      child.kill();
      settle(() => reject(new Error(`${file} timed out after ${timeoutMs}ms.`)));
    }, timeoutMs);
    const collect = (target: Buffer[]) => (chunk: Buffer) => {
      bytes += chunk.length;
      if (bytes > maximumOutputBytes) {
        child.kill();
        settle(() => reject(new Error(`${file} output exceeded the pilot-builder safety limit.`)));
        return;
      }
      target.push(Buffer.from(chunk));
    };
    child.stdout.on('data', collect(stdout));
    child.stderr.on('data', collect(stderr));
    child.once('error', (error) => settle(() => reject(error)));
    child.once('exit', (code, signal) => settle(() => {
      const errorText = Buffer.concat(stderr).toString('utf8').trim();
      if (signal) reject(new Error(`${file} terminated by signal ${signal}.`));
      else if (code !== 0) reject(new Error(`${file} exited with code ${code ?? 1}: ${errorText}`));
      else resolveCommand({
        stdout: Buffer.concat(stdout).toString('utf8'),
        stderr: errorText
      });
    }));
  });
}

export function windowsProductVersionMatchesPackage(
  productVersion: string,
  packageVersion: string
): boolean {
  const packageMatch = packageVersion.match(/^(\d+)\.(\d+)\.(\d+)(?:-[0-9A-Za-z.-]+)?$/);
  const productMatch = productVersion.trim().match(/^(\d+)\.(\d+)\.(\d+)((?:\.\d+)*)$/);
  if (!packageMatch || !productMatch) return false;
  if (
    packageMatch[1] !== productMatch[1]
    || packageMatch[2] !== productMatch[2]
    || packageMatch[3] !== productMatch[3]
  ) return false;
  const extraComponents = (productMatch[4] ?? '').split('.').filter(Boolean);
  return extraComponents.every((value) => /^0+$/.test(value));
}

export function isAnthropicCertificateSubject(subject: string): boolean {
  return [
    /(?:^|,\s*)(?:CN|O)\s*=\s*Anthropic\s+PBC(?:,|$)/i,
    /(?:^|,\s*)(?:CN|O)\s*=\s*"Anthropic,\s*PBC"(?:,|$)/i,
    /(?:^|,\s*)(?:CN|O)\s*=\s*Anthropic\\,\s*PBC(?:,|$)/i
  ].some((pattern) => pattern.test(subject));
}

export function parseAppleClaudeCodeSignature(details: string): Extract<
  ClaudeCodeVendorSignature,
  { scheme: 'apple-codesign' }
> {
  const lines = details.split(/\r?\n/).map((line) => line.trim()).filter(Boolean);
  const teamIdentifier = lines
    .find((line) => line.startsWith('TeamIdentifier='))
    ?.slice('TeamIdentifier='.length);
  if (teamIdentifier !== anthropicAppleTeamIdentifier) {
    throw new Error('Claude Code signature does not use the pinned Anthropic Apple TeamIdentifier.');
  }
  const identifier = lines
    .find((line) => line.startsWith('Identifier='))
    ?.slice('Identifier='.length);
  if (identifier !== anthropicAppleBundleIdentifier) {
    throw new Error('Claude Code signature does not use the pinned Anthropic bundle identifier.');
  }
  const authorities = lines
    .filter((line) => line.startsWith('Authority='))
    .map((line) => line.slice('Authority='.length));
  const authority = authorities.find((value) => {
    const match = value.match(
      /^Developer ID Application:\s*Anthropic(?:\s+PBC|,\s*PBC)\s*\(([A-Z0-9]{10})\)$/i
    );
    return match?.[1] === teamIdentifier;
  });
  if (
    !authority
    || !authorities.includes('Developer ID Certification Authority')
    || !authorities.includes('Apple Root CA')
  ) {
    throw new Error('Claude Code is not signed by the pinned Anthropic Developer ID chain.');
  }
  return {
    scheme: 'apple-codesign',
    verified: true,
    identifier,
    teamIdentifier,
    signingAuthority: authority
  };
}

export function parseLipoArchitectures(output: string): PilotArchitecture[] {
  const tokens = output.trim().split(/\s+/).filter(Boolean);
  if (tokens.length === 0) {
    throw new Error('macOS lipo returned no architecture slices.');
  }
  const mapped = tokens.map((token): PilotArchitecture => {
    if (token === 'arm64') return 'arm64';
    if (token === 'x86_64') return 'x64';
    throw new Error(`macOS runtime contains an unsupported architecture slice: ${token}.`);
  });
  if (new Set(mapped).size !== mapped.length) {
    throw new Error('macOS runtime contains duplicate architecture slices.');
  }
  return mapped.sort((left, right) => left.localeCompare(right, 'en'));
}

async function macBinaryArchitectures(
  executablePath: string,
  projectRoot: string
): Promise<PilotArchitecture[]> {
  const lipoPath = '/usr/bin/lipo';
  const lipoMetadata = await lstat(lipoPath);
  if (!lipoMetadata.isFile() || lipoMetadata.isSymbolicLink()) {
    throw new Error('Trusted macOS lipo utility is unavailable.');
  }
  return parseLipoArchitectures(text(await command(
    lipoPath,
    ['-archs', executablePath],
    projectRoot,
    60_000,
    1024 * 1024
  )));
}

export async function verifyOfficialClaudeExecutable(
  executablePath: string,
  packageVersion: string,
  projectRoot: string,
  platform: PilotPlatform
): Promise<ClaudeCodeVendorSignature> {
  if (platform === 'windows') {
    const windowsRoot = process.env.SystemRoot ?? process.env.WINDIR ?? 'C:\\Windows';
    if (!/^[A-Za-z]:[\\/]Windows$/i.test(windowsRoot)) {
      throw new Error('Windows SystemRoot is unavailable or has an unexpected value.');
    }
    const powershell = resolve(
      windowsRoot,
      'System32',
      'WindowsPowerShell',
      'v1.0',
      'powershell.exe'
    );
    const script = [
      "$ErrorActionPreference='Stop'",
      "$securityModule=Join-Path $PSHOME 'Modules\\Microsoft.PowerShell.Security\\Microsoft.PowerShell.Security.psd1'",
      'Import-Module $securityModule -Force',
      '$path=$env:HONGAI_CLAUDE_CODE_BINARY',
      "if([string]::IsNullOrWhiteSpace($path)){throw 'Missing binary path'}",
      '$signature=Get-AuthenticodeSignature -LiteralPath $path',
      '$version=[Diagnostics.FileVersionInfo]::GetVersionInfo($path)',
      '[ordered]@{status=[string]$signature.Status;signerSubject=[string]$signature.SignerCertificate.Subject;productVersion=[string]$version.ProductVersion;companyName=[string]$version.CompanyName;fileDescription=[string]$version.FileDescription}|ConvertTo-Json -Compress'
    ].join(';');
    const result = await command(
      powershell,
      ['-NoLogo', '-NoProfile', '-NonInteractive', '-Command', script],
      projectRoot,
      60_000,
      1024 * 1024,
      {
        SystemRoot: windowsRoot,
        WINDIR: windowsRoot,
        ...(process.env.TEMP ? { TEMP: process.env.TEMP } : {}),
        ...(process.env.TMP ? { TMP: process.env.TMP } : {}),
        HONGAI_CLAUDE_CODE_BINARY: executablePath
      }
    );
    let evidence: {
      status?: unknown;
      signerSubject?: unknown;
      productVersion?: unknown;
      companyName?: unknown;
      fileDescription?: unknown;
    };
    try {
      evidence = JSON.parse(result.stdout) as typeof evidence;
    } catch {
      throw new Error('Authenticode returned malformed Claude Code signature evidence.');
    }
    const { status, signerSubject, productVersion, companyName, fileDescription } = evidence;
    if (
      status !== 'Valid'
      || typeof signerSubject !== 'string'
      || !isAnthropicCertificateSubject(signerSubject)
    ) {
      throw new Error('Claude Code Authenticode signature is invalid or is not issued to Anthropic PBC.');
    }
    if (
      typeof productVersion !== 'string'
      || !windowsProductVersionMatchesPackage(productVersion, packageVersion)
    ) {
      throw new Error(`Claude Code file version does not match pinned package version ${packageVersion}.`);
    }
    if (
      typeof companyName !== 'string'
      || !/^Anthropic(?:\s+PBC|,\s*PBC)$/i.test(companyName.trim())
      || fileDescription !== 'Claude Code'
    ) {
      throw new Error('Claude Code Windows version metadata does not identify the official Anthropic product.');
    }
    return {
      scheme: 'authenticode',
      verified: true,
      signerSubject,
      productVersion,
      companyName,
      fileDescription
    };
  }

  const pinnedAppleRequirement =
    `=anchor apple generic and certificate leaf[subject.OU] = "${anthropicAppleTeamIdentifier}" ` +
    `and identifier "${anthropicAppleBundleIdentifier}"`;
  await command(
    '/usr/bin/codesign',
    [
      '--verify',
      '--deep',
      '--strict',
      '--verbose=2',
      '--test-requirement',
      pinnedAppleRequirement,
      executablePath
    ],
    projectRoot,
    60_000,
    1024 * 1024
  );
  const details = await command(
    '/usr/bin/codesign',
    ['--display', '--verbose=4', executablePath],
    projectRoot,
    60_000,
    1024 * 1024
  );
  return parseAppleClaudeCodeSignature(`${details.stdout}\n${details.stderr}`);
}

function text(result: CommandResult): string {
  return result.stdout.trim();
}

async function npmCommand(projectRoot: string, arguments_: string[]): Promise<CommandResult> {
  const npmCache = resolve(projectRoot, '.npm-cache');
  const taskTemp = resolve(projectRoot, '.tmp');
  await Promise.all([
    mkdir(npmCache, { recursive: true }),
    mkdir(taskTemp, { recursive: true })
  ]);
  const environment: NodeJS.ProcessEnv = {
    ...process.env,
    npm_config_cache: npmCache,
    TEMP: taskTemp,
    TMP: taskTemp,
    TMPDIR: taskTemp
  };
  if (process.platform === 'win32') {
    const windowsRoot = process.env.SystemRoot ?? process.env.WINDIR ?? 'C:\\Windows';
    if (!/^[A-Za-z]:[\\/]Windows$/i.test(windowsRoot)) {
      throw new Error('Windows SystemRoot is unavailable or has an unexpected value.');
    }
    return await command(
      resolve(windowsRoot, 'System32', 'cmd.exe'),
      ['/d', '/s', '/c', `npm ${arguments_.join(' ')}`],
      projectRoot,
      10 * 60 * 1000,
      64 * 1024 * 1024,
      environment
    );
  }
  return await command('npm', arguments_, projectRoot, 10 * 60 * 1000, 64 * 1024 * 1024, environment);
}

function isWithin(parent: string, candidate: string): boolean {
  const value = relative(parent, candidate);
  return value === '' || (!value.startsWith(`..${sep}`) && value !== '..' && !isAbsolute(value));
}

async function nearestExistingAncestor(value: string): Promise<string> {
  let candidate = value;
  let nearest: string | undefined;
  while (true) {
    try {
      const metadata = await lstat(candidate);
      if (process.platform === 'win32' && metadata.isSymbolicLink()) {
        throw new Error(`Pilot output path must not traverse a Windows reparse point: ${candidate}`);
      }
      nearest ??= await realpath(candidate);
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code !== 'ENOENT') throw error;
    }
    const parent = dirname(candidate);
    if (parent === candidate) {
      if (!nearest) throw new Error(`Pilot output path has no existing ancestor: ${value}`);
      return nearest;
    }
    candidate = parent;
  }
}

function hostTarget(): { platform: PilotPlatform; architecture: PilotArchitecture } {
  const platform = process.platform === 'win32'
    ? 'windows'
    : process.platform === 'darwin'
      ? 'macos'
      : undefined;
  if (!platform) throw new Error('Pilot payloads are built only on Windows or macOS hosts.');
  if (!['x64', 'arm64'].includes(process.arch)) {
    throw new Error(`Unsupported pilot architecture: ${process.arch}.`);
  }
  if (platform === 'windows' && process.arch !== 'x64') {
    throw new Error('The current Windows pilot target is x64 only.');
  }
  return { platform, architecture: process.arch as PilotArchitecture };
}

async function sha256File(path: string): Promise<string> {
  const hash = createHash('sha256');
  for await (const chunk of createReadStream(path)) hash.update(chunk as Buffer);
  return hash.digest('hex');
}

async function listRegularFiles(root: string): Promise<string[]> {
  const files: string[] = [];
  async function visit(directory: string): Promise<void> {
    const entries = await readdir(directory, { withFileTypes: true });
    entries.sort((left, right) => left.name.localeCompare(right.name, 'en'));
    for (const entry of entries) {
      const path = join(directory, entry.name);
      const metadata = await lstat(path);
      if (metadata.isSymbolicLink()) throw new Error(`Pilot payload contains a symbolic link: ${path}`);
      if (metadata.isDirectory()) await visit(path);
      else if (metadata.isFile()) files.push(path);
      else throw new Error(`Pilot payload contains an unsupported filesystem entry: ${path}`);
    }
  }
  await visit(root);
  return files;
}

function portablePath(root: string, path: string): string {
  return relative(root, path).split(sep).join('/');
}

export async function loadPinnedMacRipgrepPolicy(
  projectRoot: string,
  architecture: PilotArchitecture
): Promise<PinnedMacRipgrepPolicy> {
  const manifest = JSON.parse(await readFile(
    resolve(projectRoot, 'third_party', 'ripgrep-14.1.1-release.json'),
    'utf8'
  )) as {
    schemaVersion?: unknown;
    name?: unknown;
    version?: unknown;
    sourceRepository?: unknown;
    targets?: Record<string, Partial<PinnedMacRipgrepPolicy>>;
  };
  const targetName = `macos-${architecture}`;
  const target = manifest.targets?.[targetName];
  const expectedArchiveStem = typeof target?.archiveName === 'string'
    ? target.archiveName.slice(0, -'.tar.gz'.length)
    : '';
  if (
    manifest.schemaVersion !== 1
    || manifest.name !== 'ripgrep'
    || manifest.version !== '14.1.1'
    || manifest.sourceRepository !== 'https://github.com/BurntSushi/ripgrep'
    || target?.architecture !== architecture
    || typeof target.archiveName !== 'string'
    || !target.archiveName.endsWith('.tar.gz')
    || target.downloadUrl !== `${manifest.sourceRepository}/releases/download/14.1.1/${target.archiveName}`
    || typeof target.archiveSha256 !== 'string'
    || !/^[a-f0-9]{64}$/.test(target.archiveSha256)
    || target.binaryPath !== `${expectedArchiveStem}/rg`
    || typeof target.binarySha256 !== 'string'
    || !/^[a-f0-9]{64}$/.test(target.binarySha256)
  ) throw new Error(`Pinned macOS ripgrep policy is invalid for ${targetName}.`);
  return {
    version: '14.1.1',
    architecture,
    archiveName: target.archiveName,
    downloadUrl: target.downloadUrl,
    archiveSha256: target.archiveSha256,
    binaryPath: target.binaryPath,
    binarySha256: target.binarySha256
  };
}

export async function selectProductionDependencyPaths(
  projectRoot: string,
  dependencies: string[]
): Promise<string[]> {
  const canonicalRoot = await realpath(projectRoot);
  const canonicalNodeModulesRoot = await realpath(resolve(canonicalRoot, 'node_modules'));
  const selected = new Set<string>();
  for (const value of dependencies) {
    const dependency = await realpath(value);
    if (dependency === canonicalRoot) continue;
    const relativePath = relative(canonicalNodeModulesRoot, dependency);
    if (
      relativePath === ''
      || relativePath === '..'
      || relativePath.startsWith(`..${sep}`)
      || isAbsolute(relativePath)
    ) {
      throw new Error(`npm reported a production dependency outside the project: ${dependency}`);
    }
    if (/(?:^|[\\/])@anthropic-ai[\\/]claude-code-(?:darwin|linux|win32)-/i.test(relativePath)) {
      continue;
    }
    selected.add(dependency);
  }
  return [...selected].sort();
}

async function productionDependencyPaths(projectRoot: string): Promise<string[]> {
  const args = ['ls', '--omit=dev', '--parseable', '--all'];
  const result = await npmCommand(projectRoot, args);
  const dependencies = result.stdout.split(/\r?\n/).map((value) => value.trim()).filter(Boolean);
  return await selectProductionDependencyPaths(projectRoot, dependencies);
}

async function copyPayloadFiles(
  projectRoot: string,
  packageRoot: string,
  platform: PilotPlatform
): Promise<void> {
  // dist/ was deleted and regenerated immediately before this function runs.
  // Static assets are copied only from Git's tracked-file set so ignored
  // customer-local configuration and stale files cannot enter a release.
  for (const entry of ['dist/src', 'dist/services']) {
    const source = resolve(projectRoot, entry);
    await access(source);
    await cp(source, resolve(packageRoot, entry), {
      recursive: true,
      force: false,
      dereference: true
    });
  }

  const trackedSelectors = [
    'ui',
    'config',
    'third_party',
    `platform/${platform}`,
    'package.json',
    'package-lock.json',
    'LICENSE',
    'NOTICE.md',
    'README.md',
    'README_zh.md'
  ];
  const trackedOutput = (await command(
    'git',
    ['ls-files', '-z', '--', ...trackedSelectors],
    projectRoot
  )).stdout;
  const trackedFiles = trackedOutput.split('\0').filter(Boolean);
  if (trackedFiles.length === 0) throw new Error('Git returned no tracked static payload files.');
  for (const entry of trackedFiles) {
    const portable = entry.replaceAll('\\', '/');
    if (portable.startsWith('/') || portable.split('/').some((part) => !part || part === '.' || part === '..')) {
      throw new Error(`Git returned an unsafe tracked payload path: ${entry}`);
    }
    const source = resolve(projectRoot, ...portable.split('/'));
    const destination = resolve(packageRoot, ...portable.split('/'));
    if (!isWithin(projectRoot, source) || !isWithin(packageRoot, destination)) {
      throw new Error(`Tracked payload path escapes its root: ${entry}`);
    }
    const metadata = await lstat(source);
    if (!metadata.isFile() || metadata.isSymbolicLink()) {
      throw new Error(`Tracked static payload entry must be a regular non-link file: ${entry}`);
    }
    await mkdir(dirname(destination), { recursive: true });
    await cp(source, destination, { force: false });
  }

  for (const dependency of await productionDependencyPaths(projectRoot)) {
    const relativePath = relative(projectRoot, dependency);
    await cp(dependency, resolve(packageRoot, relativePath), {
      recursive: true,
      force: false,
      dereference: true
    });
  }
}

async function packageVersion(projectRoot: string): Promise<{
  version: string;
  claudeCode: string;
  sandboxRuntime: string;
}> {
  const metadata = JSON.parse(await readFile(resolve(projectRoot, 'package.json'), 'utf8')) as {
    version?: unknown;
    dependencies?: Record<string, unknown>;
  };
  const version = metadata.version;
  const claudeCode = metadata.dependencies?.['@anthropic-ai/claude-code'];
  const sandboxRuntime = metadata.dependencies?.['@anthropic-ai/sandbox-runtime'];
  if (
    typeof version !== 'string'
    || typeof claudeCode !== 'string'
    || typeof sandboxRuntime !== 'string'
  ) {
    throw new Error('package.json is missing pinned pilot runtime versions.');
  }
  return { version, claudeCode, sandboxRuntime };
}

export async function buildPilotPayload(options: PilotBuilderOptions): Promise<PilotBuildResult> {
  const projectRoot = await realpath(resolve(options.projectRoot));
  const repositoryRoot = await realpath(text(await command('git', ['rev-parse', '--show-toplevel'], projectRoot)));
  if (repositoryRoot.toLowerCase() !== projectRoot.toLowerCase()) {
    throw new Error('Project root must be the Git repository root.');
  }
  if (text(await command('git', ['status', '--porcelain=v1', '--untracked-files=all'], projectRoot))) {
    throw new Error('Git worktree must be clean before building a pilot payload.');
  }
  const [commitSha, treeSha] = await Promise.all([
    command('git', ['rev-parse', 'HEAD'], projectRoot).then(text),
    command('git', ['rev-parse', 'HEAD^{tree}'], projectRoot).then(text)
  ]);
  if (!/^[a-f0-9]{40,64}$/.test(commitSha) || !/^[a-f0-9]{40,64}$/.test(treeSha)) {
    throw new Error('Git returned an invalid commit or tree identifier.');
  }
  // Recreate dependencies from the lockfile and compiled output from an empty
  // directory. This excludes locally injected node_modules files and stale
  // ignored compiler output from the customer artifact.
  await npmCommand(projectRoot, ['ci', '--fund=false', '--audit=false']);
  await rm(resolve(projectRoot, 'dist'), { recursive: true, force: true });
  await npmCommand(projectRoot, ['run', 'build']);
  const [postBuildStatus, postBuildCommit, postBuildTree] = await Promise.all([
    command('git', ['status', '--porcelain=v1', '--untracked-files=all'], projectRoot).then(text),
    command('git', ['rev-parse', 'HEAD'], projectRoot).then(text),
    command('git', ['rev-parse', 'HEAD^{tree}'], projectRoot).then(text)
  ]);
  if (postBuildStatus || postBuildCommit !== commitSha || postBuildTree !== treeSha) {
    throw new Error('Build changed the Git worktree; refusing to package uncommitted output.');
  }

  const requestedOutput = validateReleaseOutputDirectory(options.outputDirectory);
  const outputAncestor = await nearestExistingAncestor(requestedOutput);
  validateReleaseOutputDirectory(outputAncestor);
  await mkdir(requestedOutput, { recursive: true });
  const outputDirectory = await realpath(requestedOutput);
  // A D:/E: lexical path can traverse a junction into C:. Re-validate the
  // canonical destination before writing any native runtime payload.
  validateReleaseOutputDirectory(outputDirectory);
  if (isWithin(projectRoot, outputDirectory)) {
    throw new Error('Pilot output directory must be outside the Git worktree.');
  }

  const target = hostTarget();
  const versions = await packageVersion(projectRoot);
  await access(resolve(projectRoot, 'third_party', `node-${process.version}-LICENSE.txt`));
  const artifactId = `hongai-edge-cage-${versions.version}-${target.platform}-${target.architecture}-${commitSha.slice(0, 12)}`;
  const archiveFilename = `${artifactId}.tgz`;
  const archivePath = resolve(outputDirectory, archiveFilename);
  const recordPath = `${archivePath}.build-record.json`;
  await Promise.all([
    stat(archivePath).then(() => { throw new Error(`Pilot archive already exists: ${archivePath}`); }, (error: NodeJS.ErrnoException) => {
      if (error.code !== 'ENOENT') throw error;
    }),
    stat(recordPath).then(() => { throw new Error(`Pilot build record already exists: ${recordPath}`); }, (error: NodeJS.ErrnoException) => {
      if (error.code !== 'ENOENT') throw error;
    })
  ]);

  const stagingRoot = resolve(outputDirectory, `.pilot-stage-${randomUUID()}`);
  const packageRoot = resolve(stagingRoot, 'package');
  const temporaryArchive = `${archivePath}.${randomUUID()}.tmp`;
  await mkdir(packageRoot, { recursive: true });
  try {
    await copyPayloadFiles(projectRoot, packageRoot, target.platform);
    const runtimePath = target.platform === 'windows'
      ? resolve(packageRoot, 'runtime', 'node.exe')
      : resolve(packageRoot, 'runtime', 'bin', 'node');
    await mkdir(dirname(runtimePath), { recursive: true });
    await cp(process.execPath, runtimePath, { force: false, dereference: true });
    if (target.platform === 'macos') await chmod(runtimePath, 0o755);
    let ripgrepVersion: string | null = null;
    let ripgrepSha256: string | null = null;
    let ripgrepArchitectures: PilotArchitecture[] | null = null;
    if (target.platform === 'macos') {
      const policy = await loadPinnedMacRipgrepPolicy(projectRoot, target.architecture);
      const ripgrepInput = process.env.HONGAI_RIPGREP_SOURCE;
      if (!ripgrepInput || !isAbsolute(ripgrepInput)) {
        throw new Error(
          'macOS pilot build requires an absolute HONGAI_RIPGREP_SOURCE provisioned ' +
          'from the pinned official ripgrep release.'
        );
      }
      const ripgrepMetadata = await lstat(ripgrepInput);
      if (!ripgrepMetadata.isFile() || ripgrepMetadata.isSymbolicLink()) {
        throw new Error('Provisioned macOS ripgrep must be a regular non-link file.');
      }
      const ripgrepSource = await realpath(ripgrepInput);
      if (await sha256File(ripgrepSource) !== policy.binarySha256) {
        throw new Error('Provisioned macOS ripgrep SHA-256 does not match the pinned release policy.');
      }
      const sourceArchitectures = await macBinaryArchitectures(ripgrepSource, projectRoot);
      if (
        sourceArchitectures.length !== 1
        || sourceArchitectures[0] !== target.architecture
      ) {
        throw new Error(
          `macOS ripgrep is not the pinned thin ${target.architecture} release binary.`
        );
      }
      const ripgrepPath = resolve(packageRoot, 'runtime', 'bin', 'rg');
      await cp(ripgrepSource, ripgrepPath, { force: false, dereference: true });
      // Do not execute or even mark the copied file executable until the
      // destination itself is bound to the pinned digest. This closes the
      // source-hash-to-copy replacement window.
      await chmod(ripgrepPath, 0o600);
      ripgrepSha256 = await sha256File(ripgrepPath);
      if (ripgrepSha256 !== policy.binarySha256) {
        throw new Error('Packaged ripgrep SHA-256 changed during the verified copy.');
      }
      ripgrepArchitectures = await macBinaryArchitectures(ripgrepPath, projectRoot);
      if (
        !ripgrepArchitectures.includes(target.architecture)
        || ripgrepArchitectures.join('\0') !== sourceArchitectures.join('\0')
      ) {
        throw new Error('Packaged ripgrep architecture slices do not match the verified source binary.');
      }
      await chmod(ripgrepPath, 0o755);
      ripgrepVersion = text(await command(ripgrepPath, ['--version'], projectRoot)).split(/\r?\n/, 1)[0] ?? null;
      if (ripgrepVersion !== `ripgrep ${policy.version}`) {
        throw new Error(`Packaged ripgrep does not report pinned version ${policy.version}.`);
      }
      if (await sha256File(ripgrepPath) !== policy.binarySha256) {
        throw new Error('Packaged ripgrep SHA-256 changed while verifying its version.');
      }
    }

    // Anthropic's wrapper deliberately uses bin/claude.exe on every platform.
    // On Unix the suffix is harmless, and the postinstall replaces that file
    // with the matching signed native binary from the optional platform package.
    const claudeExecutable = resolve(
      packageRoot,
      'node_modules',
      '@anthropic-ai',
      'claude-code',
      'bin',
      'claude.exe'
    );
    await access(claudeExecutable);
    const claudeCodeVendorSignature = await verifyOfficialClaudeExecutable(
      claudeExecutable,
      versions.claudeCode,
      projectRoot,
      target.platform
    );
    await access(resolve(packageRoot, 'node_modules', '@anthropic-ai', 'sandbox-runtime', 'dist', 'cli.js'));

    const deliveryManifest = {
      schemaVersion: 2,
      product: 'HONG AI Edge Cage',
      version: versions.version,
      bundleType: 'portable',
      platform: target.platform,
      architecture: target.architecture,
      commitSha,
      treeSha,
      runtime: {
        node: process.version,
        claudeCode: versions.claudeCode,
        sandboxRuntime: versions.sandboxRuntime
      },
      payloadManifest: 'HONGAI-PAYLOAD.json'
    } as const;
    await writeFile(
      resolve(packageRoot, 'HONGAI-DELIVERY.json'),
      `${JSON.stringify(deliveryManifest, null, 2)}\n`,
      { encoding: 'utf8', mode: 0o600, flag: 'wx' }
    );

    const files = [];
    for (const path of await listRegularFiles(packageRoot)) {
      const relativePath = portablePath(packageRoot, path);
      if (relativePath === 'HONGAI-PAYLOAD.json') continue;
      const metadata = await stat(path);
      files.push({ path: relativePath, bytes: metadata.size, sha256: await sha256File(path) });
    }
    const payloadManifest = {
      schemaVersion: 1,
      product: 'HONG AI Edge Cage',
      artifactId,
      commitSha,
      treeSha,
      files
    };
    const payloadManifestPath = resolve(packageRoot, 'HONGAI-PAYLOAD.json');
    await writeFile(payloadManifestPath, `${JSON.stringify(payloadManifest, null, 2)}\n`, {
      encoding: 'utf8',
      mode: 0o600,
      flag: 'wx'
    });
    const payloadManifestSha256 = await sha256File(payloadManifestPath);
    await verifyPortablePayload(packageRoot, deliveryManifest);

    const tar = target.platform === 'windows'
      ? resolve(process.env.SystemRoot ?? process.env.WINDIR ?? 'C:\\Windows', 'System32', 'tar.exe')
      : '/usr/bin/tar';
    await command(tar, ['-czf', temporaryArchive, '-C', stagingRoot, 'package'], projectRoot);
    // Verify the bytes that will actually be delivered, not only the staging
    // tree from which tar was invoked. This catches archive-tool failures and
    // any unexpected entry/type drift before publication.
    validateDeliveryArchiveEntries(text(await command(tar, ['-tzf', temporaryArchive], projectRoot)));
    validateTarEntryTypes(text(await command(tar, ['-tvzf', temporaryArchive], projectRoot)));
    const archiveVerificationRoot = resolve(stagingRoot, 'archive-verification');
    await mkdir(archiveVerificationRoot, { recursive: false });
    await command(tar, ['-xzf', temporaryArchive, '-C', archiveVerificationRoot], projectRoot);
    await verifyPortablePayload(resolve(archiveVerificationRoot, 'package'), deliveryManifest);
    const [finalStatus, finalCommitSha, finalTreeSha] = await Promise.all([
      command('git', ['status', '--porcelain=v1', '--untracked-files=all'], projectRoot).then(text),
      command('git', ['rev-parse', 'HEAD'], projectRoot).then(text),
      command('git', ['rev-parse', 'HEAD^{tree}'], projectRoot).then(text)
    ]);
    if (finalStatus || finalCommitSha !== commitSha || finalTreeSha !== treeSha) {
      throw new Error('Git source changed while the native pilot payload was being materialized.');
    }
    await rename(temporaryArchive, archivePath);
    const archiveMetadata = await stat(archivePath);
    const record: PilotBuildRecord = {
      schemaVersion: 1,
      product: 'HONG AI Edge Cage',
      version: versions.version,
      commitSha,
      treeSha,
      platform: target.platform,
      architecture: target.architecture,
      artifactId,
      archive: {
        filename: archiveFilename,
        sha256: await sha256File(archivePath),
        bytes: archiveMetadata.size,
        format: 'tar+gzip'
      },
      payloadManifestSha256,
      runtime: {
        node: process.version,
        claudeCode: versions.claudeCode,
        sandboxRuntime: versions.sandboxRuntime,
        ripgrep: ripgrepVersion,
        ripgrepSha256,
        ripgrepArchitectures
      },
      claudeCodeVendorSignature,
      limitations: {
        codeSigned: false,
        notarized: false,
        runtimeDownloadRequiredDuringInstall: false,
        customerNetworkRequiredDuringInstall: true
      }
    };
    await writeFile(recordPath, `${JSON.stringify(record, null, 2)}\n`, {
      encoding: 'utf8',
      mode: 0o600,
      flag: 'wx'
    });
    return { archivePath, recordPath, record };
  } catch (error) {
    await rm(temporaryArchive, { force: true }).catch(() => {});
    await rm(archivePath, { force: true }).catch(() => {});
    await rm(recordPath, { force: true }).catch(() => {});
    throw error;
  } finally {
    await rm(stagingRoot, { recursive: true, force: true });
  }
}

function argument(name: string): string | undefined {
  const index = process.argv.indexOf(`--${name}`);
  return index >= 0 ? process.argv[index + 1] : undefined;
}

async function main(): Promise<void> {
  const projectRoot = argument('project-root');
  const outputDirectory = argument('output-dir');
  if (!projectRoot || !outputDirectory || !isAbsolute(projectRoot) || !isAbsolute(outputDirectory)) {
    throw new Error('Usage: pilot-builder --project-root <absolute-repo-root> --output-dir <absolute-data-drive-path>');
  }
  const result = await buildPilotPayload({ projectRoot, outputDirectory });
  console.log(JSON.stringify({ ok: true, ...result.record, archivePath: result.archivePath, recordPath: result.recordPath }, null, 2));
}

const invokedPath = process.argv[1] ? resolve(process.argv[1]) : '';
if (invokedPath === resolve(fileURLToPath(import.meta.url))) {
  main().catch((error: unknown) => {
    console.error(JSON.stringify({ ok: false, error: error instanceof Error ? error.message : String(error) }));
    process.exitCode = 1;
  });
}
