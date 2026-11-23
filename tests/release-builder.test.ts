import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { spawnSync } from 'node:child_process';
import { mkdir, mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import test from 'node:test';
import {
  buildReleaseBundle,
  validateReleaseOutputDirectory
} from '../src/release-builder.js';

const projectRoot = resolve(dirname(fileURLToPath(import.meta.url)), '..', '..');
const tempBase = resolve(projectRoot, '.test-tmp');

function git(cwd: string, args: string[]): string {
  const result = spawnSync('git', args, {
    cwd,
    encoding: 'utf8',
    windowsHide: true
  });
  assert.equal(result.status, 0, result.stderr);
  return result.stdout.trim();
}

function sha256(value: Buffer): string {
  return createHash('sha256').update(value).digest('hex');
}

async function fixtureRepository(): Promise<{ root: string; repository: string }> {
  await mkdir(tempBase, { recursive: true });
  const root = await mkdtemp(resolve(tempBase, 'release-builder-'));
  const repository = resolve(root, 'repository');
  await mkdir(repository);
  await writeFile(resolve(repository, 'package.json'), JSON.stringify({
    name: '@hongai/edge-cage',
    version: '9.8.7-test.1'
  }, null, 2));
  await writeFile(resolve(repository, 'HONGAI-DELIVERY.json'), JSON.stringify({
    schemaVersion: 1,
    product: 'HONG AI Edge Cage',
    version: '9.8.7-test.1',
    bundleType: 'source',
    platforms: ['windows', 'macos']
  }, null, 2));
  await writeFile(resolve(repository, 'source.txt'), 'deterministic source payload\n');
  git(repository, ['init']);
  git(repository, ['add', '.']);
  git(repository, [
    '-c', 'user.name=HONG AI Test',
    '-c', 'user.email=test@example.invalid',
    'commit', '-m', 'release fixture'
  ]);
  return { root, repository };
}

test('release builder emits the same source archive for the same clean commit', async () => {
  const fixture = await fixtureRepository();
  try {
    const first = await buildReleaseBundle({
      projectRoot: fixture.repository,
      outputDirectory: resolve(fixture.root, 'output-one')
    });
    const second = await buildReleaseBundle({
      projectRoot: fixture.repository,
      outputDirectory: resolve(fixture.root, 'output-two')
    });
    assert.equal(first.record.version, '9.8.7-test.1');
    assert.equal(first.record.commitSha, git(fixture.repository, ['rev-parse', 'HEAD']));
    assert.equal(first.record.treeSha, git(fixture.repository, ['rev-parse', 'HEAD^{tree}']));
    assert.equal(
      first.record.releaseMetadata.packageJson.gitBlobSha,
      git(fixture.repository, ['rev-parse', 'HEAD:package.json'])
    );
    assert.equal(
      first.record.releaseMetadata.deliveryManifest.gitBlobSha,
      git(fixture.repository, ['rev-parse', 'HEAD:HONGAI-DELIVERY.json'])
    );
    assert.equal(
      first.record.releaseMetadata.packageJson.sha256,
      sha256(await readFile(resolve(fixture.repository, 'package.json')))
    );
    assert.equal(
      first.record.releaseMetadata.deliveryManifest.sha256,
      sha256(await readFile(resolve(fixture.repository, 'HONGAI-DELIVERY.json')))
    );
    assert.deepEqual(first.record.releaseMetadata.deliveryManifest.platforms, ['windows', 'macos']);
    assert.equal(first.record.sourceArchive.sha256, second.record.sourceArchive.sha256);
    assert.equal(first.record.toolchain.zlib, process.versions.zlib);
    assert.equal(first.record.toolchain.zlib, process.versions.zlib);
    assert.deepEqual(await readFile(first.archivePath), await readFile(second.archivePath));
    const gzip = await readFile(first.archivePath);
    assert.deepEqual([...gzip.subarray(4, 8)], [0, 0, 0, 0]);
    assert.equal(gzip[9], 255);
  } finally {
    await rm(fixture.root, { recursive: true, force: true });
  }
});

test('release builder refuses dirty worktrees before creating output', async () => {
  const fixture = await fixtureRepository();
  try {
    await writeFile(resolve(fixture.repository, 'untracked.txt'), 'not committed\n');
    await assert.rejects(buildReleaseBundle({
      projectRoot: fixture.repository,
      outputDirectory: resolve(fixture.root, 'output')
    }), /worktree must be clean/);
  } finally {
    await rm(fixture.root, { recursive: true, force: true });
  }
});

test('release builder never overwrites an existing release candidate', async () => {
  const fixture = await fixtureRepository();
  try {
    const outputDirectory = resolve(fixture.root, 'output');
    const first = await buildReleaseBundle({ projectRoot: fixture.repository, outputDirectory });
    const originalArchive = await readFile(first.archivePath);
    const originalRecord = await readFile(first.recordPath);
    await assert.rejects(
      buildReleaseBundle({ projectRoot: fixture.repository, outputDirectory }),
      (error: NodeJS.ErrnoException) => error.code === 'EEXIST'
    );
    assert.deepEqual(await readFile(first.archivePath), originalArchive);
    assert.deepEqual(await readFile(first.recordPath), originalRecord);
  } finally {
    await rm(fixture.root, { recursive: true, force: true });
  }
});

test('release builder refuses a committed version mismatch', async () => {
  const fixture = await fixtureRepository();
  try {
    await writeFile(resolve(fixture.repository, 'HONGAI-DELIVERY.json'), JSON.stringify({
      schemaVersion: 1,
      product: 'HONG AI Edge Cage',
      version: '9.8.8-test.1',
      bundleType: 'source',
      platforms: ['windows', 'macos']
    }, null, 2));
    git(fixture.repository, ['add', 'HONGAI-DELIVERY.json']);
    git(fixture.repository, [
      '-c', 'user.name=HONG AI Test',
      '-c', 'user.email=test@example.invalid',
      'commit', '-m', 'mismatched release manifest'
    ]);
    await assert.rejects(buildReleaseBundle({
      projectRoot: fixture.repository,
      outputDirectory: resolve(fixture.root, 'output')
    }), /versions do not match/);
  } finally {
    await rm(fixture.root, { recursive: true, force: true });
  }
});

test('release builder refuses an unsupported delivery platform manifest', async () => {
  const fixture = await fixtureRepository();
  try {
    await writeFile(resolve(fixture.repository, 'HONGAI-DELIVERY.json'), JSON.stringify({
      schemaVersion: 1,
      product: 'HONG AI Edge Cage',
      version: '9.8.7-test.1',
      bundleType: 'source',
      platforms: ['linux']
    }, null, 2));
    git(fixture.repository, ['add', 'HONGAI-DELIVERY.json']);
    git(fixture.repository, [
      '-c', 'user.name=HONG AI Test',
      '-c', 'user.email=test@example.invalid',
      'commit', '-m', 'unsupported delivery platforms'
    ]);
    await assert.rejects(buildReleaseBundle({
      projectRoot: fixture.repository,
      outputDirectory: resolve(fixture.root, 'output')
    }), /exactly the Windows and macOS/);
  } finally {
    await rm(fixture.root, { recursive: true, force: true });
  }
});

test('release builder refuses output inside the source worktree', async () => {
  const fixture = await fixtureRepository();
  try {
    await assert.rejects(buildReleaseBundle({
      projectRoot: fixture.repository,
      outputDirectory: resolve(fixture.repository, 'release-output')
    }), /outside the Git worktree/);
  } finally {
    await rm(fixture.root, { recursive: true, force: true });
  }
});

test('Windows release output policy rejects C and non-data drives', () => {
  assert.throws(() => validateReleaseOutputDirectory('C:\\release', 'win32'), /must not be written to the C:/);
  assert.throws(() => validateReleaseOutputDirectory('F:\\release', 'win32'), /must be on D: or E:/);
  assert.equal(validateReleaseOutputDirectory('E:\\release', 'win32'), 'E:\\release');
});
