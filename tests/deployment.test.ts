import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { mkdir, mkdtemp, rm, writeFile } from 'node:fs/promises';
import { join, resolve } from 'node:path';
import test from 'node:test';
import {
  assertNativePilotArtifactId,
  verifyPortablePayload,
  validateSourceArchiveEntries,
  validateTarEntryTypes,
  validateTarExpandedSize
} from '../src/deployment.js';

const validListing = [
  'package/',
  'package/HONGAI-DELIVERY.json',
  'package/package.json',
  'package/platform/windows/Install-HONGAI-Edge-Cage.ps1'
].join('\n');

test('accepts a rooted HONG AI source delivery archive', () => {
  assert.equal(validateSourceArchiveEntries(validListing).length, 4);
});

test('customer deployment accepts only a host-matched architecture-native artifact id', () => {
  if (!['win32', 'darwin'].includes(process.platform) || !['x64', 'arm64'].includes(process.arch)) return;
  const platform = process.platform === 'win32' ? 'windows' : 'macos';
  assert.doesNotThrow(() => assertNativePilotArtifactId(
    `hongai-edge-cage-0.2.0-alpha.4-${platform}-${process.arch}-aaaaaaaaaaaa`
  ));
  assert.throws(() => assertNativePilotArtifactId('hongai-edge-cage-0.2.0-alpha.4-aaaaaaaaaaaa-source'));
  const otherPlatform = platform === 'windows' ? 'macos' : 'windows';
  assert.throws(() => assertNativePilotArtifactId(
    `hongai-edge-cage-0.2.0-alpha.4-${otherPlatform}-${process.arch}-aaaaaaaaaaaa`
  ));
});

test('rejects archive path traversal and alternate path syntax', () => {
  assert.throws(() => validateSourceArchiveEntries(`${validListing}\npackage/../escape.txt`));
  assert.throws(() => validateSourceArchiveEntries(`${validListing}\nC:/escape.txt`));
  assert.throws(() => validateSourceArchiveEntries(`${validListing}\npackage\\escape.txt`));
  assert.throws(() => validateSourceArchiveEntries(`${validListing}\npackage/file:stream`));
  assert.throws(() => validateSourceArchiveEntries(`${validListing}\npackage/CON.txt`));
  assert.throws(() => validateSourceArchiveEntries(`${validListing}\npackage/trailing.`));
  assert.throws(() => validateSourceArchiveEntries(`${validListing}\npackage/PACKAGE.JSON`));
  assert.throws(() => validateSourceArchiveEntries(`${validListing}\npackage/cafe\u0301.txt`));
  assert.throws(() => validateSourceArchiveEntries('package/package.json'));
});

test('allows only regular files and directories in tar metadata', () => {
  assert.doesNotThrow(() => validateTarEntryTypes(
    '-rw-r--r-- 0/0 10 2026-11-22 package/package.json\n' +
    'drwxr-xr-x 0/0 0 2026-11-22 package/docs/'
  ));
  assert.throws(() => validateTarEntryTypes(
    'lrwxrwxrwx 0/0 0 2026-11-22 package/link -> ../../escape'
  ));
  assert.throws(() => validateTarEntryTypes(
    'prw-r--r-- 0/0 0 2026-11-22 package/pipe'
  ));
});

test('limits the total expanded archive size for GNU and BSD tar listings', () => {
  assert.equal(validateTarExpandedSize(
    '-rw-r--r-- 0/0 10 2026-11-22 package/package.json\n' +
    'drwxr-xr-x 0/0 0 2026-11-22 package/docs/'
  ), 10);
  assert.equal(validateTarExpandedSize(
    '-rw-r--r--  0 0 25 Nov 22 06:17 package/package.json\n' +
    'drwxr-xr-x  0 0 0 Nov 22 06:17 package/docs/'
  ), 25);
  assert.throws(() => validateTarExpandedSize(
    '-rw-r--r-- 0/0 101 2026-11-22 package/package.json',
    100
  ));
});

const portableDeliveryManifest = {
  schemaVersion: 2,
  product: 'HONG AI Edge Cage',
  version: '0.2.0-test',
  bundleType: 'portable',
  platform: 'windows',
  architecture: 'x64',
  commitSha: 'a'.repeat(40),
  treeSha: 'b'.repeat(40),
  runtime: {
    node: 'v24.0.0',
    claudeCode: '2.1.330',
    sandboxRuntime: '0.0.83'
  },
  payloadManifest: 'HONGAI-PAYLOAD.json'
} as const;

async function portableFixture(): Promise<string> {
  const root = await mkdtemp(resolve('.tmp-deployment-test-'));
  await mkdir(join(root, 'dist', 'src'), { recursive: true });
  const content = 'verified portable payload\n';
  await writeFile(join(root, 'dist', 'src', 'cli.js'), content, 'utf8');
  await writeFile(join(root, 'HONGAI-PAYLOAD.json'), `${JSON.stringify({
    schemaVersion: 1,
    product: 'HONG AI Edge Cage',
    artifactId: 'hongai-test-windows-x64',
    commitSha: portableDeliveryManifest.commitSha,
    treeSha: portableDeliveryManifest.treeSha,
    files: [{
      path: 'dist/src/cli.js',
      bytes: Buffer.byteLength(content),
      sha256: createHash('sha256').update(content).digest('hex')
    }]
  })}\n`, 'utf8');
  return root;
}

test('verifies every file in a portable payload', async () => {
  const root = await portableFixture();
  try {
    const result = await verifyPortablePayload(root, portableDeliveryManifest);
    assert.equal(result.fileCount, 1);
    assert.equal(result.artifactId, 'hongai-test-windows-x64');
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test('rejects modified and undeclared portable payload files', async () => {
  const modified = await portableFixture();
  try {
    await writeFile(join(modified, 'dist', 'src', 'cli.js'), 'modified\n', 'utf8');
    await assert.rejects(() => verifyPortablePayload(modified, portableDeliveryManifest), /size mismatch|digest mismatch/);
  } finally {
    await rm(modified, { recursive: true, force: true });
  }

  const extra = await portableFixture();
  try {
    await writeFile(join(extra, 'unexpected.txt'), 'not declared\n', 'utf8');
    await assert.rejects(() => verifyPortablePayload(extra, portableDeliveryManifest), /file set mismatch/);
  } finally {
    await rm(extra, { recursive: true, force: true });
  }
});

test('installed verification can allow only explicitly named runtime state', async () => {
  const root = await portableFixture();
  try {
    await mkdir(join(root, '.edge-cage'), { recursive: true });
    await writeFile(join(root, '.edge-cage', 'windows-install-state.json'), '{}\n', 'utf8');
    await assert.doesNotReject(() => verifyPortablePayload(root, portableDeliveryManifest, {
      allowedAdditionalPaths: ['.edge-cage/windows-install-state.json']
    }));
    await writeFile(join(root, '.edge-cage', 'unexpected-runtime-state.json'), '{}\n', 'utf8');
    await assert.rejects(() => verifyPortablePayload(root, portableDeliveryManifest, {
      allowedAdditionalPaths: ['.edge-cage/windows-install-state.json']
    }), /file set mismatch/);
    await rm(join(root, '.edge-cage', 'unexpected-runtime-state.json'));
    await writeFile(join(root, 'undeclared.txt'), 'no\n', 'utf8');
    await assert.rejects(() => verifyPortablePayload(root, portableDeliveryManifest, {
      allowedAdditionalPaths: ['.edge-cage/windows-install-state.json']
    }), /file set mismatch/);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});
