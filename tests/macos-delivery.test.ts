import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { createHash } from 'node:crypto';
import { createReadStream } from 'node:fs';
import {
  chmod,
  cp,
  mkdir,
  mkdtemp,
  readFile,
  readdir,
  readlink,
  rename,
  rm,
  stat,
  writeFile
} from 'node:fs/promises';
import { resolve } from 'node:path';
import test from 'node:test';

const root = resolve(process.cwd());

async function sha256File(path: string): Promise<string> {
  const hash = createHash('sha256');
  for await (const chunk of createReadStream(path)) hash.update(chunk as Buffer);
  return hash.digest('hex');
}

async function fixtureManifestFiles(fixture: string): Promise<Array<{ path: string; bytes: number; sha256: string }>> {
  const files: Array<{ path: string; bytes: number; sha256: string }> = [];
  async function visit(directory: string): Promise<void> {
    for (const entry of await readdir(directory, { withFileTypes: true })) {
      const absolute = resolve(directory, entry.name);
      if (entry.isDirectory()) await visit(absolute);
      else if (entry.isFile()) {
        const relativePath = absolute.slice(fixture.length + 1).replaceAll('\\', '/');
        if (relativePath === 'HONGAI-PAYLOAD.json') continue;
        const metadata = await stat(absolute);
        files.push({ path: relativePath, bytes: metadata.size, sha256: await sha256File(absolute) });
      } else {
        throw new Error(`Unexpected fixture entry: ${absolute}`);
      }
    }
  }
  await visit(fixture);
  return files.sort((left, right) => left.path.localeCompare(right.path, 'en'));
}

async function script(name: string): Promise<string> {
  return await readFile(resolve(root, 'platform', 'macos', name), 'utf8');
}

function run(file: string, args: string[], environment: NodeJS.ProcessEnv = process.env): Promise<string> {
  return new Promise((resolveRun, reject) => {
    const child = spawn(file, args, {
      env: environment,
      stdio: ['ignore', 'pipe', 'pipe']
    });
    let output = '';
    let errorOutput = '';
    child.stdout.setEncoding('utf8');
    child.stderr.setEncoding('utf8');
    child.stdout.on('data', (chunk: string) => { output += chunk; });
    child.stderr.on('data', (chunk: string) => { errorOutput += chunk; });
    child.once('error', reject);
    child.once('exit', (code, signal) => {
      if (signal || code !== 0) reject(new Error(`${file} failed (${signal ?? code}): ${errorOutput}`));
      else resolveRun(output);
    });
  });
}

async function macFixture(base: string): Promise<{ root: string; config: string; log: string }> {
  const fixture = resolve(base, 'payload');
  const log = resolve(base, 'commands.log');
  await mkdir(resolve(fixture, 'platform', 'macos'), { recursive: true });
  await cp(resolve(root, 'platform', 'macos'), resolve(fixture, 'platform', 'macos'), { recursive: true });
  await mkdir(resolve(fixture, 'runtime', 'bin'), { recursive: true });
  await cp(process.execPath, resolve(fixture, 'runtime', 'bin', 'node'));
  await chmod(resolve(fixture, 'runtime', 'bin', 'node'), 0o755);
  const rg = resolve(fixture, 'runtime', 'bin', 'rg');
  await writeFile(rg, '#!/bin/sh\necho "ripgrep 99.0.0"\n');
  await chmod(rg, 0o755);
  await mkdir(resolve(fixture, 'dist', 'src'), { recursive: true });
  await writeFile(resolve(fixture, 'dist', 'src', 'cli.js'), [
    "import { appendFileSync } from 'node:fs';",
    "appendFileSync(process.env.HONGAI_TEST_LOG, `${process.argv.slice(2).join(' ')}\\n`);"
  ].join('\n'));
  await mkdir(resolve(fixture, 'node_modules', '@anthropic-ai', 'claude-code', 'bin'), { recursive: true });
  await writeFile(resolve(fixture, 'node_modules', '@anthropic-ai', 'claude-code', 'package.json'), '{"name":"@anthropic-ai/claude-code","version":"9.9.1"}\n');
  const claude = resolve(fixture, 'node_modules', '@anthropic-ai', 'claude-code', 'bin', 'claude');
  await writeFile(claude, '#!/bin/sh\nexit 0\n');
  await chmod(claude, 0o755);
  await mkdir(resolve(fixture, 'node_modules', '@anthropic-ai', 'sandbox-runtime', 'dist'), { recursive: true });
  await writeFile(resolve(fixture, 'node_modules', '@anthropic-ai', 'sandbox-runtime', 'package.json'), '{"name":"@anthropic-ai/sandbox-runtime","version":"9.9.2"}\n');
  await writeFile(resolve(fixture, 'node_modules', '@anthropic-ai', 'sandbox-runtime', 'dist', 'cli.js'), '');
  await writeFile(resolve(fixture, 'node_modules', '.package-lock.json'), JSON.stringify({
    name: '@hongai/edge-cage',
    version: '9.9.9-macos-test'
  }));
  await writeFile(resolve(fixture, 'package.json'), JSON.stringify({
    name: '@hongai/edge-cage',
    version: '9.9.9-macos-test',
    type: 'module',
    dependencies: {
      '@anthropic-ai/claude-code': '9.9.1',
      '@anthropic-ai/sandbox-runtime': '9.9.2'
    }
  }));
  await writeFile(resolve(fixture, 'HONGAI-DELIVERY.json'), JSON.stringify({
    schemaVersion: 2,
    product: 'HONG AI Edge Cage',
    version: '9.9.9-macos-test',
    bundleType: 'portable',
    platform: 'macos',
    architecture: process.arch,
    commitSha: 'a'.repeat(40),
    treeSha: 'b'.repeat(40),
    runtime: {
      node: process.version,
      claudeCode: '9.9.1',
      sandboxRuntime: '9.9.2'
    },
    payloadManifest: 'HONGAI-PAYLOAD.json'
  }));
  const files = await fixtureManifestFiles(fixture);
  await writeFile(resolve(fixture, 'HONGAI-PAYLOAD.json'), JSON.stringify({
    schemaVersion: 1,
    product: 'HONG AI Edge Cage',
    artifactId: 'macos-test',
    commitSha: 'a'.repeat(40),
    treeSha: 'b'.repeat(40),
    files
  }));
  const config = resolve(base, 'customer.yaml');
  await writeFile(config, 'schemaVersion: 1\n');
  return { root: fixture, config, log };
}

test('macOS shell entries replace a hostile inherited PATH before running commands', async () => {
  const directory = resolve(root, 'platform', 'macos');
  const names = (await readdir(directory)).filter((name) => name.endsWith('.sh')).sort();
  assert.ok(names.length > 0);
  const safePrefix = '#!/bin/sh\nPATH=/usr/bin:/bin:/usr/sbin:/sbin\nexport PATH\n';
  for (const name of names) {
    const contents = await readFile(resolve(directory, name), 'utf8');
    assert.ok(contents.startsWith(safePrefix), `${name} must fix and export PATH immediately after its shebang`);
  }

  const common = await script('common.sh');
  assert.match(common, /PATH="\$HONGAI_RUNTIME_ROOT\/runtime\/bin:\/usr\/bin:\/bin:\/usr\/sbin:\/sbin"/);
  assert.doesNotMatch(common, /runtime\/bin\$\{PATH/);
});

test('macOS customer installer requires an offline architecture-matched payload', async () => {
  const installer = await script('install.sh');
  const common = await script('common.sh');
  assert.doesNotMatch(installer, /\bnpm\s+(?:ci|install)\b/);
  assert.doesNotMatch(installer, /\bcurl\b|\bwget\b|\bbrew\b/);
  assert.match(installer, /hongai_require_offline_payload/);
  assert.match(installer, /mktemp -d "\$PROJECT_PARENT\/\.hongai-install-tmp\.XXXXXX"/);
  assert.doesNotMatch(installer, /PROJECT_ROOT\/\.install-tmp/);
  assert.match(common, /runtime\/bin\/node/);
  assert.match(common, /runtime\/bin\/rg/);
  assert.match(common, /process\.platform/);
  assert.match(common, /process\.arch/);
  assert.match(common, /delivery\.schemaVersion === 2/);
  assert.match(common, /delivery\.bundleType === 'portable'/);
  assert.match(common, /HONGAI-PAYLOAD\.json/);
  assert.match(common, /unset NODE_OPTIONS NODE_PATH NPM_CONFIG_USERCONFIG npm_config_userconfig/);
  assert.match(common, /marker\.configSha256/);
  assert.match(common, /customer configuration differs from the configuration verified during installation/);
  assert.match(common, /node_modules\/@anthropic-ai\/claude-code/);
  assert.match(common, /node_modules\/@anthropic-ai\/sandbox-runtime/);
});

test('macOS activation and rollback validate installation markers and use atomic link replacement', async () => {
  const activate = await script('activate.sh');
  const rollback = await script('rollback.sh');
  const uninstall = await script('uninstall.sh');
  assert.match(activate, /hongai_verify_install_marker/);
  assert.match(activate, /mv -f -h -- "\$CURRENT_TMP" "\$CURRENT_LINK"/);
  assert.match(rollback, /hongai_verify_install_marker/);
  assert.match(rollback, /PREVIOUS_LINK/);
  assert.match(rollback, /rollback-transaction\.json/);
  assert.match(rollback, /CURRENT_SWITCHED/);
  assert.match(rollback, /HONGAI_TEST_ROLLBACK_FAIL_AFTER_CURRENT/);
  assert.match(uninstall, /hongai_verify_install_marker/);
  assert.match(uninstall, /state is intentionally preserved/);
  assert.match(uninstall, /refusing to remove unsafe installation root/);
});

test('macOS start and doctor always use the bundled runtime', async () => {
  const start = await script('start.sh');
  const doctor = await script('doctor.sh');
  for (const value of [start, doctor]) {
    assert.match(value, /hongai_require_offline_payload/);
    assert.match(value, /hongai_verify_install_marker/);
    assert.match(value, /hongai_verify_installed_config/);
    assert.match(value, /hongai_prepend_runtime_path/);
    assert.doesNotMatch(value, /exec node|\bnode dist\//);
  }
});

test('macOS offline payload installs, survives relocation, activates and rolls back', {
  skip: process.platform !== 'darwin'
}, async () => {
  await mkdir(resolve(root, '.test-tmp'), { recursive: true });
  const base = await mkdtemp(resolve(root, '.test-tmp', 'macos-offline-'));
  try {
    const fixture = await macFixture(base);
    const environment = { ...process.env, HONGAI_TEST_LOG: fixture.log };
    await run('/bin/sh', [resolve(fixture.root, 'platform', 'macos', 'install.sh'), fixture.config], environment);
    const marker = JSON.parse(await readFile(resolve(fixture.root, '.hongai-install.json'), 'utf8')) as {
      architecture: string;
      version: string;
      configSha256: string;
    };
    assert.equal(marker.architecture, process.arch);
    assert.equal(marker.version, '9.9.9-macos-test');
    assert.match(marker.configSha256, /^[a-f0-9]{64}$/);

    const first = resolve(base, 'versions', 'one');
    await mkdir(resolve(base, 'versions'), { recursive: true });
    await rename(fixture.root, first);
    await run('/bin/sh', [resolve(first, 'platform', 'macos', 'doctor.sh'), fixture.config], environment);
    await writeFile(fixture.config, 'schemaVersion: 1\n# changed after installation\n');
    await assert.rejects(
      run('/bin/sh', [resolve(first, 'platform', 'macos', 'doctor.sh'), fixture.config], environment),
      /customer configuration differs from the configuration verified during installation/
    );
    await writeFile(fixture.config, 'schemaVersion: 1\n');
    const second = resolve(base, 'versions', 'two');
    await cp(first, second, { recursive: true, verbatimSymlinks: true });
    const current = resolve(base, 'current');
    await run('/bin/sh', [resolve(first, 'platform', 'macos', 'activate.sh'), first, current], environment);
    await run('/bin/sh', [resolve(second, 'platform', 'macos', 'activate.sh'), second, current], environment);
    assert.equal(await readlink(current), second);
    await assert.rejects(
      run('/bin/sh', [resolve(second, 'platform', 'macos', 'rollback.sh'), current], {
        ...environment,
        HONGAI_TEST_ROLLBACK_FAIL_AFTER_CURRENT: '1'
      }),
      /injected rollback interruption/
    );
    assert.equal(await readlink(current), first);
    assert.equal(await readlink(`${current}.previous`), first);
    await run('/bin/sh', [resolve(second, 'platform', 'macos', 'rollback.sh'), current], environment);
    assert.equal(await readlink(current), first);
    assert.equal(await readlink(`${current}.previous`), second);

    const commands = await readFile(fixture.log, 'utf8');
    assert.match(commands, /validate --config/);
    assert.match(commands, /doctor --config/);
  } finally {
    await rm(base, { recursive: true, force: true });
  }
});
