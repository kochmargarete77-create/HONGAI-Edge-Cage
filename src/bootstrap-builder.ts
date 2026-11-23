#!/usr/bin/env node

import { createHash, randomUUID } from 'node:crypto';
import { spawn } from 'node:child_process';
import { createReadStream } from 'node:fs';
import {
  access,
  chmod,
  cp,
  copyFile,
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
import {
  dirname,
  isAbsolute,
  posix,
  relative,
  resolve,
  sep,
  win32
} from 'node:path';
import { fileURLToPath } from 'node:url';

export type BootstrapPlatform = 'windows' | 'macos';
export type BootstrapArchitecture = 'x64' | 'arm64';

export interface BootstrapBuilderOptions {
  projectRoot: string;
  outputDirectory: string;
  /** Test-only escape hatch. The CLI never exposes this option. */
  unsafeAllowDirtyForTests?: boolean;
}

export interface BootstrapBuildRecord {
  schemaVersion: 1;
  product: 'HONG AI Edge Cage Bootstrap';
  version: string;
  platform: BootstrapPlatform;
  architecture: BootstrapArchitecture;
  createdAt: string;
  source: {
    commitSha: string;
    treeSha: string;
    workingTree: 'clean' | 'unsafe-dirty-test';
  };
  runtime: { node: string; path: string };
  bootstrap: {
    directory: string;
    manifest: string;
    manifestSha256: string;
    files: number;
    bytes: number;
  };
  contents: {
    compiledDeliveryClientOnly: true;
    runtimeDependencyPackages: ['undici', 'yaml', 'zod'];
    claudeRuntimeIncluded: false;
    secretsEmbedded: false;
  };
}

export interface BootstrapBuildResult {
  bootstrapRoot: string;
  recordPath: string;
  record: BootstrapBuildRecord;
}

interface ManifestFile {
  path: string;
  bytes: number;
  sha256: string;
}

function hostTarget(): { platform: BootstrapPlatform; architecture: BootstrapArchitecture } {
  const platform = process.platform === 'win32'
    ? 'windows'
    : process.platform === 'darwin'
      ? 'macos'
      : undefined;
  if (!platform) throw new Error('Bootstrap builds require a native Windows or macOS host.');
  if (process.arch !== 'x64' && process.arch !== 'arm64') {
    throw new Error(`Unsupported bootstrap architecture: ${process.arch}.`);
  }
  if (platform === 'windows' && process.arch !== 'x64') {
    throw new Error('The current Windows customer delivery target is x64 only.');
  }
  return { platform, architecture: process.arch };
}

function run(
  command: string,
  arguments_: string[],
  cwd: string,
  inheritOutput = false,
  environment: NodeJS.ProcessEnv = process.env
): Promise<string> {
  return new Promise((resolveRun, reject) => {
    const child = spawn(command, arguments_, {
      cwd,
      env: environment,
      stdio: inheritOutput ? 'inherit' : ['ignore', 'pipe', 'pipe'],
      windowsHide: true,
      shell: false
    });
    const stdout: Buffer[] = [];
    const stderr: Buffer[] = [];
    if (!inheritOutput) {
      child.stdout?.on('data', (chunk: Buffer) => stdout.push(chunk));
      child.stderr?.on('data', (chunk: Buffer) => stderr.push(chunk));
    }
    child.once('error', reject);
    child.once('exit', (code, signal) => {
      if (code === 0 && !signal) {
        resolveRun(Buffer.concat(stdout).toString('utf8').trim());
        return;
      }
      reject(new Error(`${command} ${arguments_.join(' ')} failed${signal ? ` (${signal})` : ''}: ${Buffer.concat(stderr).toString('utf8').trim()}`));
    });
  });
}

async function runNpm(arguments_: string[], cwd: string, inheritOutput = false): Promise<string> {
  const npmCache = resolve(cwd, '.npm-cache');
  const taskTemp = resolve(cwd, '.tmp');
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
  if (process.platform !== 'win32') return await run('npm', arguments_, cwd, inheritOutput, environment);
  // Windows CreateProcess cannot reliably execute npm.cmd directly when
  // shell=false. Invoke the system command processor explicitly, using only
  // fixed builder-owned npm arguments.
  const windowsRoot = process.env.SystemRoot ?? process.env.WINDIR ?? 'C:\\Windows';
  if (!/^[A-Za-z]:[\\/]Windows$/i.test(windowsRoot)) {
    throw new Error('Windows SystemRoot is unavailable or has an unexpected value.');
  }
  const commandProcessor = resolve(windowsRoot, 'System32', 'cmd.exe');
  return await run(
    commandProcessor,
    ['/d', '/s', '/c', `npm ${arguments_.join(' ')}`],
    cwd,
    inheritOutput,
    environment
  );
}

async function gitSourceState(projectRoot: string): Promise<{ commitSha: string; treeSha: string; dirty: boolean }> {
  const [commitSha, treeSha, status] = await Promise.all([
    run('git', ['rev-parse', 'HEAD'], projectRoot),
    run('git', ['rev-parse', 'HEAD^{tree}'], projectRoot),
    run('git', ['status', '--porcelain=v1', '--untracked-files=all'], projectRoot)
  ]);
  if (!/^[a-f0-9]{40,64}$/.test(commitSha) || !/^[a-f0-9]{40,64}$/.test(treeSha)) {
    throw new Error('Bootstrap source Git provenance is invalid.');
  }
  return { commitSha, treeSha, dirty: status.length > 0 };
}

export function validateBootstrapOutputDirectory(
  value: string,
  platform: NodeJS.Platform = process.platform
): string {
  if (platform === 'win32') {
    if (!win32.isAbsolute(value)) throw new Error('Windows bootstrap output must be an absolute D: or E: path.');
    const drive = win32.parse(value).root.slice(0, 2).toUpperCase();
    if (!['D:', 'E:'].includes(drive)) {
      throw new Error('Windows bootstrap output must be on D: or E:; C: is system-only storage.');
    }
    return win32.resolve(value);
  }
  if (!posix.isAbsolute(value)) throw new Error('Bootstrap output directory must be absolute.');
  return posix.resolve(value);
}

function pathWithin(parent: string, candidate: string): boolean {
  const normalize = process.platform === 'win32' ? (value: string) => value.toLowerCase() : (value: string) => value;
  const value = relative(normalize(parent), normalize(candidate));
  return value === '' || (!value.startsWith(`..${sep}`) && value !== '..' && !isAbsolute(value));
}

async function nearestExistingAncestor(value: string): Promise<string> {
  let candidate = value;
  let nearest: string | undefined;
  while (true) {
    try {
      const metadata = await lstat(candidate);
      if (process.platform === 'win32' && metadata.isSymbolicLink()) {
        throw new Error(`Bootstrap output path must not traverse a Windows reparse point: ${candidate}`);
      }
      nearest ??= await realpath(candidate);
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code !== 'ENOENT') throw error;
    }
    const parent = dirname(candidate);
    if (parent === candidate) {
      if (!nearest) throw new Error(`Bootstrap output path has no existing ancestor: ${value}`);
      return nearest;
    }
    candidate = parent;
  }
}

async function pathExists(path: string): Promise<boolean> {
  try {
    await lstat(path);
    return true;
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === 'ENOENT') return false;
    throw error;
  }
}

async function sha256File(path: string): Promise<string> {
  const hash = createHash('sha256');
  for await (const chunk of createReadStream(path)) hash.update(chunk as Buffer);
  return hash.digest('hex');
}

function portablePath(root: string, path: string): string {
  return relative(root, path).split(sep).join('/');
}

async function regularFiles(root: string): Promise<string[]> {
  const files: string[] = [];
  async function visit(directory: string): Promise<void> {
    const entries = await readdir(directory, { withFileTypes: true });
    entries.sort((left, right) => left.name.localeCompare(right.name, 'en'));
    for (const entry of entries) {
      const path = resolve(directory, entry.name);
      const metadata = await lstat(path);
      if (metadata.isSymbolicLink()) throw new Error(`Bootstrap payload contains a symbolic link: ${path}`);
      if (metadata.isDirectory()) await visit(path);
      else if (metadata.isFile()) files.push(path);
      else throw new Error(`Bootstrap payload contains an unsupported filesystem entry: ${path}`);
    }
  }
  await visit(root);
  return files;
}

export function moduleSpecifiers(source: string): string[] {
  const values = new Set<string>();
  const patterns = [
    /\bfrom\s*["']([^"']+)["']/g,
    /\bimport\s*["']([^"']+)["']/g,
    /\bimport\s*\(\s*["']([^"']+)["']\s*\)/g
  ];
  for (const pattern of patterns) {
    for (const match of source.matchAll(pattern)) {
      if (match[1]) values.add(match[1]);
    }
  }
  return [...values];
}

export async function collectCompiledDependencyClosure(
  distRoot: string,
  entryRelativePaths: string[]
): Promise<string[]> {
  const canonicalDist = await realpath(distRoot);
  const queue = entryRelativePaths.map((entry) => resolve(canonicalDist, entry));
  const collected = new Set<string>();
  while (queue.length > 0) {
    const path = queue.shift();
    if (!path) continue;
    const canonical = await realpath(path);
    if (!pathWithin(canonicalDist, canonical)) throw new Error(`Compiled module escapes dist/: ${path}`);
    if (collected.has(canonical)) continue;
    if (!canonical.endsWith('.js')) throw new Error(`Bootstrap compiled dependency is not JavaScript: ${canonical}`);
    const metadata = await stat(canonical);
    if (!metadata.isFile()) throw new Error(`Bootstrap compiled dependency is not a file: ${canonical}`);
    collected.add(canonical);
    const source = await readFile(canonical, 'utf8');
    for (const specifier of moduleSpecifiers(source)) {
      if (specifier.startsWith('node:')) continue;
      if (specifier === 'zod' || specifier === 'yaml' || specifier === 'undici') continue;
      if (!specifier.startsWith('.')) {
        throw new Error(`Bootstrap requires an unexpected production dependency: ${specifier}`);
      }
      const dependency = resolve(dirname(canonical), specifier);
      if (!pathWithin(canonicalDist, dependency)) {
        throw new Error(`Compiled import escapes dist/: ${canonical} -> ${specifier}`);
      }
      queue.push(dependency);
    }
  }
  return [...collected].sort((left, right) => portablePath(canonicalDist, left).localeCompare(portablePath(canonicalDist, right), 'en'));
}

async function collectZodEsmClosure(zodRoot: string): Promise<string[]> {
  const canonicalRoot = await realpath(zodRoot);
  const queue = [resolve(canonicalRoot, 'index.js')];
  const collected = new Set<string>();
  while (queue.length > 0) {
    const path = queue.shift();
    if (!path) continue;
    const canonical = await realpath(path);
    if (!pathWithin(canonicalRoot, canonical)) throw new Error(`Zod module escapes package root: ${path}`);
    if (collected.has(canonical)) continue;
    if (!canonical.endsWith('.js')) throw new Error(`Unexpected non-JavaScript Zod dependency: ${canonical}`);
    collected.add(canonical);
    const source = await readFile(canonical, 'utf8');
    for (const specifier of moduleSpecifiers(source)) {
      // Zod has no production dependencies. Its published comments contain
      // illustrative bare imports (`zod` and `zod/compile`), so only relative
      // ESM edges belong to the runtime closure.
      if (!specifier.startsWith('.')) continue;
      const dependency = resolve(dirname(canonical), specifier);
      if (!pathWithin(canonicalRoot, dependency)) throw new Error(`Zod import escapes package root: ${specifier}`);
      queue.push(dependency);
    }
  }
  return [...collected].sort((left, right) => portablePath(canonicalRoot, left).localeCompare(portablePath(canonicalRoot, right), 'en'));
}

async function copyFileCreatingParent(source: string, target: string): Promise<void> {
  await mkdir(dirname(target), { recursive: true });
  await copyFile(source, target);
}

export function deliveryTemplate(platform: BootstrapPlatform): Record<string, unknown> {
  return platform === 'windows'
    ? {
      schemaVersion: 1,
      serviceUrl: 'https://REPLACE_WITH_LICENSE_SERVICE.invalid/',
      artifactId: 'REPLACE_WITH_ARTIFACT_ID',
      signingPublicKey: '.\\delivery-signing-public.pem',
      archiveOutput: 'D:\\HONGAI-Delivery\\artifact.tgz',
      installRoot: 'D:\\HONGAI-Edge-Cage\\versions\\REPLACE_WITH_VERSION',
      customerConfig: '.\\customer.yaml',
      keepArchive: false
    }
    : {
      schemaVersion: 1,
      serviceUrl: 'https://REPLACE_WITH_LICENSE_SERVICE.invalid/',
      artifactId: 'REPLACE_WITH_ARTIFACT_ID',
      signingPublicKey: './delivery-signing-public.pem',
      archiveOutput: '/Users/Shared/HONGAI-Delivery/artifact.tgz',
      installRoot: '/Users/Shared/HONGAI-Edge-Cage/versions/REPLACE_WITH_VERSION',
      customerConfig: './customer.yaml',
      currentLink: '/Users/Shared/HONGAI-Edge-Cage/current',
      keepArchive: false
    };
}

async function packageVersion(projectRoot: string): Promise<string> {
  const metadata = JSON.parse(await readFile(resolve(projectRoot, 'package.json'), 'utf8')) as {
    name?: unknown;
    version?: unknown;
  };
  if (metadata.name !== '@hongai/edge-cage') throw new Error('Project package identity is invalid.');
  if (typeof metadata.version !== 'string' || !/^[0-9A-Za-z][0-9A-Za-z.+-]{0,79}$/.test(metadata.version)) {
    throw new Error('Project package version is invalid.');
  }
  return metadata.version;
}

export async function buildBootstrap(options: BootstrapBuilderOptions): Promise<BootstrapBuildResult> {
  const projectRoot = await realpath(resolve(options.projectRoot));
  const target = hostTarget();
  const initialSource = await gitSourceState(projectRoot);
  if (initialSource.dirty && !options.unsafeAllowDirtyForTests) {
    throw new Error('Bootstrap release builds require a clean Git working tree.');
  }
  if (!options.unsafeAllowDirtyForTests) {
    // Recreate the dependency tree from the lockfile and compile from an empty
    // output directory. Git cleanliness alone cannot detect injected files in
    // ignored node_modules/ or stale files in ignored dist/.
    await runNpm(
      ['ci', '--ignore-scripts', '--fund=false', '--audit=false'],
      projectRoot,
      true
    );
    await rm(resolve(projectRoot, 'dist'), { recursive: true, force: true });
    await runNpm(['run', 'build'], projectRoot, true);
    const postBuildSource = await gitSourceState(projectRoot);
    if (
      postBuildSource.dirty
      || postBuildSource.commitSha !== initialSource.commitSha
      || postBuildSource.treeSha !== initialSource.treeSha
    ) {
      throw new Error('Bootstrap build changed or drifted from the clean Git source snapshot.');
    }
  }
  const version = await packageVersion(projectRoot);
  const requestedOutput = validateBootstrapOutputDirectory(options.outputDirectory);
  const outputAncestor = await nearestExistingAncestor(requestedOutput);
  validateBootstrapOutputDirectory(outputAncestor);
  if (pathWithin(projectRoot, requestedOutput) || pathWithin(projectRoot, outputAncestor)) {
    throw new Error('Bootstrap output must be outside the repository.');
  }
  await mkdir(requestedOutput, { recursive: true });
  const outputDirectory = await realpath(requestedOutput);
  validateBootstrapOutputDirectory(outputDirectory);
  if (pathWithin(projectRoot, outputDirectory)) throw new Error('Bootstrap output resolves inside the repository.');

  const artifactName = `hongai-edge-cage-bootstrap-${version}-${target.platform}-${target.architecture}-${initialSource.commitSha.slice(0, 12)}`;
  const bootstrapRoot = resolve(outputDirectory, artifactName);
  const recordPath = `${bootstrapRoot}.build-record.json`;
  const recordTemporaryPath = `${recordPath}.${randomUUID()}.tmp`;
  if (await pathExists(bootstrapRoot) || await pathExists(recordPath)) {
    throw new Error(`Bootstrap output already exists: ${bootstrapRoot}`);
  }

  const stagingRoot = resolve(outputDirectory, `.bootstrap-stage-${randomUUID()}`);
  const appRoot = resolve(stagingRoot, 'app');
  let placed = false;
  let recordCreated = false;
  try {
    await mkdir(appRoot, { recursive: true });
    const distRoot = resolve(projectRoot, 'dist');
    const compiledFiles = await collectCompiledDependencyClosure(distRoot, [
      'services/delivery-client/deploy.js',
      'services/delivery-client/abandon.js',
      'services/delivery-client/receipt.js'
    ]);
    for (const source of compiledFiles) {
      await copyFileCreatingParent(source, resolve(appRoot, portablePath(distRoot, source)));
    }

    const zodRoot = resolve(projectRoot, 'node_modules', 'zod');
    const zodMetadata = JSON.parse(await readFile(resolve(zodRoot, 'package.json'), 'utf8')) as {
      name?: unknown;
      version?: unknown;
      license?: unknown;
      dependencies?: unknown;
    };
    if (
      zodMetadata.name !== 'zod'
      || typeof zodMetadata.version !== 'string'
      || (zodMetadata.dependencies !== undefined
        && (typeof zodMetadata.dependencies !== 'object'
          || zodMetadata.dependencies === null
          || Object.keys(zodMetadata.dependencies).length > 0))
    ) {
      throw new Error('Installed Zod package metadata is invalid.');
    }
    const packagedZodRoot = resolve(appRoot, 'node_modules', 'zod');
    for (const source of await collectZodEsmClosure(zodRoot)) {
      await copyFileCreatingParent(source, resolve(packagedZodRoot, portablePath(zodRoot, source)));
    }
    await writeFile(resolve(packagedZodRoot, 'package.json'), `${JSON.stringify({
      name: 'zod',
      version: zodMetadata.version,
      type: 'module',
      license: zodMetadata.license,
      exports: { '.': './index.js' }
    }, null, 2)}\n`, { encoding: 'utf8', mode: 0o600, flag: 'wx' });
    const zodLicense = resolve(zodRoot, 'LICENSE');
    await access(zodLicense);
    await copyFile(zodLicense, resolve(packagedZodRoot, 'LICENSE'));

    const yamlRoot = resolve(projectRoot, 'node_modules', 'yaml');
    const yamlMetadata = JSON.parse(await readFile(resolve(yamlRoot, 'package.json'), 'utf8')) as {
      name?: unknown;
      version?: unknown;
      dependencies?: unknown;
    };
    if (
      yamlMetadata.name !== 'yaml'
      || typeof yamlMetadata.version !== 'string'
      || (yamlMetadata.dependencies !== undefined
        && (typeof yamlMetadata.dependencies !== 'object'
          || yamlMetadata.dependencies === null
          || Object.keys(yamlMetadata.dependencies).length > 0))
    ) {
      throw new Error('Installed YAML package metadata is invalid.');
    }
    await cp(yamlRoot, resolve(appRoot, 'node_modules', 'yaml'), {
      recursive: true,
      force: false,
      errorOnExist: true
    });
    const undiciRoot = resolve(projectRoot, 'node_modules', 'undici');
    const undiciMetadata = JSON.parse(await readFile(resolve(undiciRoot, 'package.json'), 'utf8')) as {
      name?: unknown;
      version?: unknown;
      dependencies?: unknown;
    };
    if (
      undiciMetadata.name !== 'undici'
      || typeof undiciMetadata.version !== 'string'
      || (undiciMetadata.dependencies !== undefined
        && (typeof undiciMetadata.dependencies !== 'object'
          || undiciMetadata.dependencies === null
          || Object.keys(undiciMetadata.dependencies).length > 0))
    ) {
      throw new Error('Installed Undici package metadata is invalid.');
    }
    await cp(undiciRoot, resolve(appRoot, 'node_modules', 'undici'), {
      recursive: true,
      force: false,
      errorOnExist: true
    });
    await writeFile(resolve(appRoot, 'package.json'), `${JSON.stringify({
      name: '@hongai/edge-cage-bootstrap-runtime',
      version,
      private: true,
      type: 'module',
      dependencies: { undici: undiciMetadata.version, yaml: yamlMetadata.version, zod: zodMetadata.version }
    }, null, 2)}\n`, { encoding: 'utf8', mode: 0o600, flag: 'wx' });

    const runtimeRelativePath = target.platform === 'windows' ? 'runtime/node.exe' : 'runtime/bin/node';
    const runtimePath = resolve(stagingRoot, ...runtimeRelativePath.split('/'));
    await copyFileCreatingParent(process.execPath, runtimePath);
    if (target.platform === 'macos') await chmod(runtimePath, 0o755);

    const bootstrapSource = resolve(projectRoot, 'platform', 'bootstrap');
    await copyFile(resolve(bootstrapSource, 'bootstrap-runner.mjs'), resolve(stagingRoot, 'bootstrap-runner.mjs'));
    await copyFile(resolve(bootstrapSource, 'README.md'), resolve(stagingRoot, 'README.md'));
    await copyFile(resolve(projectRoot, 'LICENSE'), resolve(stagingRoot, 'LICENSE'));
    await copyFile(resolve(projectRoot, 'NOTICE.md'), resolve(stagingRoot, 'NOTICE.md'));
    await copyFile(
      resolve(projectRoot, 'third_party', `node-${process.version}-LICENSE.txt`),
      resolve(stagingRoot, `node-${process.version}-LICENSE.txt`)
    );
    await copyFile(
      resolve(projectRoot, 'third_party', 'RUNTIME-LICENSES.txt'),
      resolve(stagingRoot, 'RUNTIME-LICENSES.txt')
    );
    if (target.platform === 'windows') {
      await copyFile(resolve(bootstrapSource, 'windows', 'Start-HONGAI-Delivery.ps1'), resolve(stagingRoot, 'Start-HONGAI-Delivery.ps1'));
      await copyFile(resolve(bootstrapSource, 'windows', 'Retry-HONGAI-Receipt.ps1'), resolve(stagingRoot, 'Retry-HONGAI-Receipt.ps1'));
      await copyFile(resolve(bootstrapSource, 'windows', 'Abandon-HONGAI-Delivery.ps1'), resolve(stagingRoot, 'Abandon-HONGAI-Delivery.ps1'));
      await copyFile(resolve(bootstrapSource, 'windows', '00-Start-HONGAI-Delivery.cmd'), resolve(stagingRoot, '00-Start-HONGAI-Delivery.cmd'));
      await copyFile(resolve(bootstrapSource, 'windows', '01-Retry-HONGAI-Receipt.cmd'), resolve(stagingRoot, '01-Retry-HONGAI-Receipt.cmd'));
      await copyFile(resolve(bootstrapSource, 'windows', '99-Explicitly-Abandon-HONGAI-Delivery.cmd'), resolve(stagingRoot, '99-Explicitly-Abandon-HONGAI-Delivery.cmd'));
    } else {
      const start = resolve(stagingRoot, 'start-delivery.sh');
      const retry = resolve(stagingRoot, 'retry-receipt.sh');
      const abandon = resolve(stagingRoot, 'abandon-delivery.sh');
      const startCommand = resolve(stagingRoot, '00-Start-HONGAI-Delivery.command');
      const retryCommand = resolve(stagingRoot, '01-Retry-HONGAI-Receipt.command');
      const abandonCommand = resolve(stagingRoot, '99-Explicitly-Abandon-HONGAI-Delivery.command');
      await copyFile(resolve(bootstrapSource, 'macos', 'start-delivery.sh'), start);
      await copyFile(resolve(bootstrapSource, 'macos', 'retry-receipt.sh'), retry);
      await copyFile(resolve(bootstrapSource, 'macos', 'abandon-delivery.sh'), abandon);
      await copyFile(resolve(bootstrapSource, 'macos', '00-Start-HONGAI-Delivery.command'), startCommand);
      await copyFile(resolve(bootstrapSource, 'macos', '01-Retry-HONGAI-Receipt.command'), retryCommand);
      await copyFile(resolve(bootstrapSource, 'macos', '99-Explicitly-Abandon-HONGAI-Delivery.command'), abandonCommand);
      await Promise.all([
        chmod(start, 0o755),
        chmod(retry, 0o755),
        chmod(abandon, 0o755),
        chmod(startCommand, 0o755),
        chmod(retryCommand, 0o755),
        chmod(abandonCommand, 0o755),
        chmod(resolve(stagingRoot, 'bootstrap-runner.mjs'), 0o755)
      ]);
    }
    await writeFile(
      resolve(stagingRoot, 'delivery.example.json'),
      `${JSON.stringify(deliveryTemplate(target.platform), null, 2)}\n`,
      { encoding: 'utf8', mode: 0o600, flag: 'wx' }
    );

    const files: ManifestFile[] = [];
    let totalBytes = 0;
    for (const path of await regularFiles(stagingRoot)) {
      const metadata = await stat(path);
      totalBytes += metadata.size;
      if (!Number.isSafeInteger(totalBytes)) throw new Error('Bootstrap payload size overflow.');
      files.push({ path: portablePath(stagingRoot, path), bytes: metadata.size, sha256: await sha256File(path) });
    }
    if (files.some((file) => /(?:^|\/)@anthropic-ai(?:\/|$)|claude-code/i.test(file.path))) {
      throw new Error('Bootstrap unexpectedly contains a Claude runtime payload.');
    }
    const manifest = {
      schemaVersion: 1,
      product: 'HONG AI Edge Cage Bootstrap',
      version,
      platform: target.platform,
      architecture: target.architecture,
      commitSha: initialSource.commitSha,
      treeSha: initialSource.treeSha,
      runtime: { node: process.version, path: runtimeRelativePath },
      mutableFilesExcluded: [
        'delivery.json',
        'the exact signingPublicKey path referenced by delivery.json',
        'the exact customerConfig path referenced by delivery.json'
      ],
      files
    };
    const manifestPath = resolve(stagingRoot, 'BOOTSTRAP-MANIFEST.json');
    await writeFile(manifestPath, `${JSON.stringify(manifest, null, 2)}\n`, {
      encoding: 'utf8', mode: 0o600, flag: 'wx'
    });
    const manifestSha256 = await sha256File(manifestPath);
    const record: BootstrapBuildRecord = {
      schemaVersion: 1,
      product: 'HONG AI Edge Cage Bootstrap',
      version,
      platform: target.platform,
      architecture: target.architecture,
      createdAt: new Date().toISOString(),
      source: {
        commitSha: initialSource.commitSha,
        treeSha: initialSource.treeSha,
        workingTree: options.unsafeAllowDirtyForTests ? 'unsafe-dirty-test' : 'clean'
      },
      runtime: { node: process.version, path: runtimeRelativePath },
      bootstrap: {
        directory: artifactName,
        manifest: 'BOOTSTRAP-MANIFEST.json',
        manifestSha256,
        files: files.length,
        bytes: totalBytes
      },
      contents: {
        compiledDeliveryClientOnly: true,
      runtimeDependencyPackages: ['undici', 'yaml', 'zod'],
        claudeRuntimeIncluded: false,
        secretsEmbedded: false
      }
    };
    await writeFile(recordTemporaryPath, `${JSON.stringify(record, null, 2)}\n`, {
      encoding: 'utf8', mode: 0o600, flag: 'wx'
    });
    if (!options.unsafeAllowDirtyForTests) {
      const finalSource = await gitSourceState(projectRoot);
      if (
        finalSource.dirty
        || finalSource.commitSha !== initialSource.commitSha
        || finalSource.treeSha !== initialSource.treeSha
      ) {
        throw new Error('Git source changed while the bootstrap payload was being materialized.');
      }
    }
    await rename(stagingRoot, bootstrapRoot);
    placed = true;
    await rename(recordTemporaryPath, recordPath);
    recordCreated = true;
    return { bootstrapRoot, recordPath, record };
  } catch (error) {
    if (placed) await rm(bootstrapRoot, { recursive: true, force: true }).catch(() => {});
    if (recordCreated) await rm(recordPath, { force: true }).catch(() => {});
    await rm(recordTemporaryPath, { force: true }).catch(() => {});
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
    throw new Error('Usage: bootstrap-builder --project-root <absolute-repository> --output-dir <absolute-external-directory>');
  }
  const result = await buildBootstrap({ projectRoot, outputDirectory });
  console.log(JSON.stringify({ ok: true, ...result.record.bootstrap, bootstrapRoot: result.bootstrapRoot, recordPath: result.recordPath }, null, 2));
}

const invokedPath = process.argv[1] ? resolve(process.argv[1]) : '';
if (invokedPath === resolve(fileURLToPath(import.meta.url))) {
  main().catch((error: unknown) => {
    console.error(JSON.stringify({ ok: false, error: error instanceof Error ? error.message : String(error) }));
    process.exitCode = 1;
  });
}
