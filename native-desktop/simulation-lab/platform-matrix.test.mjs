import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { SURFACES, profileDigest, validateModel } from './model.mjs';
import { runLocalReadback } from './readback.mjs';

const matrix = [
  { fixture: 'windows-x64.json', platform: 'windows', architecture: 'x64', host: 'win32' },
  { fixture: 'macos-arm64.json', platform: 'macOS', architecture: 'arm64', host: 'darwin' },
  { fixture: 'macos-x64.json', platform: 'macOS', architecture: 'x64', host: 'darwin' },
];

test('CI runner records its actual Node platform and architecture', (t) => {
  const expectedPlatform = process.env.HONGAI_LAB_EXPECT_PLATFORM;
  const expectedArchitecture = process.env.HONGAI_LAB_EXPECT_ARCH;
  if (expectedPlatform !== undefined) {
    assert.ok(['win32', 'darwin'].includes(expectedPlatform), 'explicit supported runner platform required');
    assert.equal(process.platform, expectedPlatform, 'CI runner is not the declared platform');
  }
  if (expectedArchitecture !== undefined) {
    assert.ok(['x64', 'arm64'].includes(expectedArchitecture), 'explicit supported runner architecture required');
    assert.equal(process.arch, expectedArchitecture, 'CI Node architecture is not the declared architecture');
  }
  t.diagnostic(JSON.stringify({
    schema: 'hongai.local-simulation-runner.v1',
    hostPlatform: process.platform,
    hostArchitecture: process.arch,
    nodeVersion: process.version,
    declaredCIPlatform: expectedPlatform ?? null,
    declaredCIArchitecture: expectedArchitecture ?? null,
    evidenceLevel: 'LOCAL_SIMULATOR_READBACK',
    nativeHardwareReadPathsValidated: false,
    officialClientConnected: false,
    targetServiceContacted: false,
  }));
});

test('three platform models remain independent across concurrent and interleaved child processes', async (t) => {
  const profiles = await Promise.all(matrix.map(async (entry) => {
    const profile = JSON.parse(await readFile(new URL('./fixtures/' + entry.fixture, import.meta.url), 'utf8'));
    return validateModel(profile);
  }));
  // Start separate probes together, then revisit each model in reverse order.
  // This catches a shared provider/cache accidentally retaining another model.
  const first = await Promise.all(profiles.map((profile) => runLocalReadback(profile, { providerKind: 'local_mock' })));
  const second = new Array(matrix.length);
  for (let index = matrix.length - 1; index >= 0; index--) {
    second[index] = await runLocalReadback(profiles[index], { providerKind: 'local_mock' });
  }
  assert.equal(new Set(first.map((report) => report.modelDigest)).size, matrix.length, 'fixtures need independent model identities');
  assert.equal(new Set([...first, ...second].map((report) => report.runId)).size, matrix.length * 2, 'each readback needs a new process run');
  assert.equal(new Set([...first, ...second].map((report) => report.challenge)).size, matrix.length * 2, 'each readback needs an independent challenge');

  for (const [index, entry] of matrix.entries()) {
    await t.test(entry.fixture, () => {
      const profile = profiles[index], a = first[index], b = second[index];
      assert.deepEqual(profile.platform, { os: entry.platform, architecture: entry.architecture, osVersion: profile.platform.osVersion });
      assert.equal(a.modelDigest, profileDigest(profile));
      assert.equal(b.modelDigest, a.modelDigest);
      for (const report of [a, b]) {
        assert.equal(report.executionHost, process.platform);
        assert.deepEqual(report.targetModel, profile.platform);
        assert.deepEqual(report.observed, Object.fromEntries(SURFACES.map((surface) => [surface, profile[surface]])));
        assert.notEqual(report.probe.pid, process.pid);
        assert.ok(Number.isInteger(report.probe.pid) && report.probe.pid > 0);
        assert.equal(report.probe.exitCode, 0);
        assert.equal(report.providerKind, 'local_mock');
        assert.equal(report.evidenceLevel, 'LOCAL_SIMULATOR_READBACK');
        assert.equal(report.nativeHardwareReadPathsValidated, false);
        assert.equal(report.officialClientConnected, false);
        assert.equal(report.targetServiceContacted, false);
        assert.equal(report.hostIdentifiersModified, false);
        assert.equal(report.hostNetworkModified, false);
        assert.equal(report.customerReady, false);
      }
      const samePlatformAndArchitecture = process.platform === entry.host && process.arch === entry.architecture;
      t.diagnostic(JSON.stringify({
        schema: 'hongai.local-simulation-platform-matrix.v1',
        fixture: entry.fixture,
        hostPlatform: process.platform,
        hostArchitecture: process.arch,
        targetModel: profile.platform,
        modelDigest: a.modelDigest,
        childProcessIds: [a.probe.pid, b.probe.pid],
        runIds: [a.runId, b.runId],
        hostMatchesModelPlatformAndArchitecture: samePlatformAndArchitecture,
        executionCoverage: samePlatformAndArchitecture ? 'LOCAL_SIMULATOR_ON_MATCHING_NODE_HOST' : 'CROSS_MODEL_ON_DIFFERENT_NODE_HOST',
        evidenceLevel: 'LOCAL_SIMULATOR_READBACK',
        nativeHardwareReadPathsValidated: false,
        officialClientConnected: false,
        targetServiceContacted: false,
        customerReady: false,
      }));
    });
  }
});
