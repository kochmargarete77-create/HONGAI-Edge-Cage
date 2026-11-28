import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { evaluateCoherence } from './coherence.mjs';
import { runLocalReadback } from './readback.mjs';

const load = async (name) => JSON.parse(await readFile(new URL('./fixtures/' + name, import.meta.url), 'utf8'));
const windows = await load('windows-x64.json');
const mac = await load('macos-arm64.json');
const readback = (model) => runLocalReadback(model, { providerKind: 'local_mock' });
const pair = await Promise.all([readback(windows), readback(windows)]);

test('actual independent child readbacks pass only the local coherence layer', () => {
  for (const report of pair) assert.notEqual(report.probe.pid, process.pid);
  const result = evaluateCoherence(windows, pair);
  assert.equal(result.status, 'PASS');
  assert.equal(result.localReadbackComplete, true);
  assert.equal(result.acceptedIndependentRuns, 2);
  assert.equal(result.evidenceLevel, 'LOCAL_SIMULATOR_READBACK');
  assert.ok(Object.values(result.surfaces).every((entry) => entry.status === 'PASS' && entry.matchedRuns === 2));
  for (const flag of ['targetClientVerified', 'customerReady', 'fullEnvironmentAccepted', 'nativeHardwareReadPathsValidated']) assert.equal(result[flag], false);
  assert.equal(result.executionHostEvidence, 'INPUT_REPORT_CLAIMS_NOT_PLATFORM_ATTESTATION');
});

test('absent or incomplete observations remain untested rather than failures or acceptance', () => {
  for (const reports of [[], [pair[0]]]) {
    const result = evaluateCoherence(windows, reports);
    assert.equal(result.status, 'NOT_TESTED');
    assert.equal(result.localReadbackComplete, false);
  }
  const missing = structuredClone(pair);
  delete missing[1].observed.hardware;
  const result = evaluateCoherence(windows, missing);
  assert.equal(result.status, 'NOT_TESTED');
  assert.equal(result.surfaces.hardware.status, 'NOT_TESTED');
  assert.equal(result.surfaces.network.status, 'PASS');
  assert.equal(result.acceptedIndependentRuns, 1);
});

test('mixed revisions and interleaved models cannot certify one requested snapshot', async () => {
  const changed = structuredClone(windows);
  changed.revision++;
  const nextRevision = await readback(changed);
  const otherModel = await readback(mac);
  for (const foreign of [nextRevision, otherModel]) {
    const result = evaluateCoherence(windows, [pair[0], foreign]);
    assert.equal(result.status, 'FAIL');
    assert.equal(result.localReadbackComplete, false);
    assert.ok(result.runs[1].codes.includes('REQUESTED_MODEL_REVISION_DIGEST_MISMATCH'));
  }
  const stitched = structuredClone(pair);
  stitched[1].observed.hardware = otherModel.observed.hardware;
  const result = evaluateCoherence(windows, stitched);
  assert.equal(result.surfaces.hardware.status, 'FAIL');
  assert.equal(result.status, 'FAIL');
});

test('repeated or missing run identities fail, while a PID alone is not a stable identity', () => {
  for (const change of [
    (reports) => { reports[1].runId = reports[0].runId; },
    (reports) => { reports[1].challenge = reports[0].challenge; },
    (reports) => { delete reports[1].runId; },
    (reports) => { reports[1].runId = {}; },
    (reports) => { reports[1].probe.pid = 0; },
  ]) {
    const reports = structuredClone(pair); change(reports);
    assert.equal(evaluateCoherence(windows, reports).status, 'FAIL');
  }
  const reports = structuredClone(pair);
  reports[1].probe.pid = reports[0].probe.pid;
  reports[1].probe.startedUtc = '2099-01-01T00:00:00.000Z';
  reports[1].probe.finishedUtc = '2099-01-01T00:00:01.000Z';
  assert.equal(evaluateCoherence(windows, reports).status, 'PASS', 'sequential OS PID reuse must not fabricate a replay');
});

test('unknown report, probe and observation fields fail without evaluating getters', () => {
  for (const change of [
    (reports) => { reports[1].unknown = true; },
    (reports) => { reports[1].probe.extra = true; },
    (reports) => { reports[1].observed.network.extra = 'synthetic-unexpected'; },
    (reports) => { reports[1].observed.unknownSurface = {}; },
    (reports) => { reports[1].targetClientVerified = true; },
  ]) {
    const reports = structuredClone(pair); change(reports);
    assert.equal(evaluateCoherence(windows, reports).status, 'FAIL');
  }
  const reports = structuredClone(pair);
  let called = false;
  Object.defineProperty(reports[1], 'observed', { enumerable: true, get() { called = true; throw Error('MUST_NOT_RUN'); } });
  assert.equal(evaluateCoherence(windows, reports).status, 'FAIL');
  assert.equal(called, false);
});

test('expected values cannot authorize altered observations or hide failed execution', () => {
  for (const change of [
    (report) => { report.expected.hardware.memoryMiB = report.observed.hardware.memoryMiB = 32768; },
    (report) => { report.observed.network.reachable = false; },
    (report) => { report.matched = false; },
    (report) => { report.probe.exitCode = 1; },
    (report) => { report.probe.finishedUtc = '2000-01-01T00:00:00.000Z'; },
    (report) => { report.customerReady = true; },
  ]) {
    const reports = structuredClone(pair); change(reports[1]);
    const result = evaluateCoherence(windows, reports);
    assert.equal(result.status, 'FAIL');
    assert.equal(result.localReadbackComplete, false);
    assert.equal(result.targetClientVerified, false);
  }
});

test('host OS is separated from target model and regional values imply no human identity', async () => {
  const crossModel = await Promise.all([readback(mac), readback(mac)]);
  const assessment = evaluateCoherence(mac, crossModel);
  assert.equal(assessment.status, 'PASS');
  for (const run of assessment.runs) {
    assert.equal(run.executionHost.reportedHostPlatform, process.platform);
    assert.equal(run.executionHost.nativePlatformCoverage, 'NOT_ESTABLISHED');
    assert.equal(run.executionHost.hostArchitecture, 'NOT_RECORDED_BY_READBACK_SCHEMA');
    assert.equal(run.executionHost.relationship, process.platform === 'darwin' ? 'REPORTED_HOST_OS_MATCHES_MODEL' : 'CROSS_MODEL_REPORTED_HOST_OS');
  }
  const regional = structuredClone(windows);
  regional.regional.languageTag = regional.regional.locale = 'zh-CN';
  regional.regional.timeZone = 'Asia/Shanghai';
  const reports = await Promise.all([readback(regional), readback(regional)]);
  const result = evaluateCoherence(regional, reports);
  assert.equal(result.status, 'PASS');
  assert.equal(result.nationalityOrPersonalIdentityInferred, false);
});
