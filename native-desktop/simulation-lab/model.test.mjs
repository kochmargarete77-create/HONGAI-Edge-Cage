import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { SURFACES, validateModel, profileDigest, createLocalProvider } from './model.mjs';

// Tests load synthetic fixtures only; the provider itself imports no host IO.
const windows = JSON.parse(await readFile(new URL('./fixtures/windows-x64.json', import.meta.url), 'utf8'));
const mac = JSON.parse(await readFile(new URL('./fixtures/macos-arm64.json', import.meta.url), 'utf8'));

test('both platform metadata models normalize into independent objects without host input', () => {
  assert.deepEqual(SURFACES, ['network', 'regional', 'platform', 'hardware', 'rendering', 'state', 'tools']);
  for (const fixture of [windows, mac]) {
    const before = structuredClone(fixture);
    const result = validateModel(fixture);
    assert.deepEqual(fixture, before);
    assert.notEqual(result, fixture);
    assert.notEqual(result.hardware.cpu, fixture.hardware.cpu);
    assert.equal(result.mode, 'LOCAL_AUTHORIZED_TEST_ONLY');
    assert.equal(result.hardware.identityKind, 'SYNTHETIC_PLACEHOLDER_NOT_REAL_HARDWARE_ID');
    assert.equal(result.rendering.mode, 'METADATA_ONLY');
    assert.deepEqual(validateModel(result), result);
  }
});

test('canonical digest ignores input key order and accepted normalization variations', () => {
  const variant = Object.fromEntries(Object.entries(structuredClone(windows)).reverse());
  variant.environmentId = ' LAB-WINDOWS-X64-DEMO ';
  variant.platform.os = ' WINDOWS ';
  variant.platform.architecture = ' X64 ';
  variant.regional.languageTag = 'EN-us';
  variant.regional.locale = 'en-us';
  variant.regional.timeZone = 'america/los_angeles';
  variant.network.countryCode = 'us';
  variant.regional.countryCode = 'us';
  variant.tools.capabilities.reverse();
  assert.equal(profileDigest(variant), profileDigest(windows));
  assert.match(profileDigest(windows), /^[a-f0-9]{64}$/);
  const revised = structuredClone(windows);
  revised.revision++;
  assert.notEqual(profileDigest(revised), profileDigest(windows));
  const otherDevice = structuredClone(windows);
  otherDevice.hardware.deviceId = 'synthetic-device-other';
  assert.notEqual(profileDigest(otherDevice), profileDigest(windows));
});

test('impossible or unsupported platform, core, memory, graphics and regional combinations fail', () => {
  const cases = [
    [windows, (p) => { p.platform.os = 'Linux'; }, /SUPPORTED_DESKTOP_PLATFORM/],
    [windows, (p) => { p.platform.architecture = 'arm64'; }, /PLATFORM_ARCHITECTURE_NOT_IMPLEMENTED/],
    [windows, (p) => { p.hardware.cpu.logicalCores = 3; }, /CPU_THREAD_TOPOLOGY/],
    [windows, (p) => { p.hardware.cpu.physicalCores = 0; }, /PHYSICAL_CORE_COUNT/],
    [mac, (p) => { p.hardware.cpu.logicalCores = 16; }, /ARM64_MAC_CPU_TOPOLOGY/],
    [windows, (p) => { p.hardware.memoryMiB = 3000; }, /MEMORY_CAPACITY_ALIGNMENT/],
    [windows, (p) => { p.rendering.graphicsApi = 'metal'; }, /GRAPHICS_API_PLATFORM_MISMATCH/],
    [mac, (p) => { p.rendering.graphicsApi = 'd3d12'; }, /GRAPHICS_API_PLATFORM_MISMATCH/],
    [windows, (p) => { p.network.countryCode = 'CA'; }, /DECLARED_COUNTRY_LABELS_DISAGREE/],
    [windows, (p) => { p.regional.timeZone = 'Imaginary/Nowhere'; }, /IANA_TIME_ZONE/],
    [windows, (p) => { p.regional.languageTag = 'en_US'; }, /BCP47/],
    [windows, (p) => { p.hardware.deviceId = 'REAL-HARDWARE-ID'; }, /SYNTHETIC_PLACEHOLDER/],
    [windows, (p) => { p.network.exitIPv4 = '8.8.8.8'; }, /DOCUMENTATION_RANGE_IPV4/],
    [windows, (p) => { p.network.exitIPv4 = '203.0.113.010'; }, /DOCUMENTATION_RANGE_IPV4/],
    [windows, (p) => { p.rendering.fingerprint = 'measured-real-gpu'; }, /REAL_RENDERING_NOT_IMPLEMENTED/],
    [windows, (p) => { p.tools.resultContext = 'HOST'; }, /SYNTHETIC_TOOL_CONTEXT/],
    [windows, (p) => { p.state.authentication = 'REAL_SESSION'; }, /REAL_AUTHENTICATION_NOT_SUPPORTED/],
    [windows, (p) => { p.mode = 'PRODUCTION'; }, /LOCAL_AUTHORIZED_TEST_MODE/],
  ];
  for (const [base, change, expected] of cases) {
    const input = structuredClone(base); change(input);
    assert.throws(() => validateModel(input), expected);
  }
});

test('provider requires explicit local_mock and never falls back from vendor or unknown adapters', () => {
  for (const options of [undefined, null, {}, { kind: 'vendor_adapter' }, { kind: 'unknown' }, { kind: 'local_mock', fallback: true }]) {
    assert.throws(() => createLocalProvider(windows, options));
  }
  assert.equal(createLocalProvider(windows, { kind: 'local_mock' }).kind, 'local_mock');
});

test('repeat providers return stable snapshots and reject every unknown surface', () => {
  const source = structuredClone(mac);
  const a = createLocalProvider(source, { kind: 'local_mock' });
  const b = createLocalProvider(mac, { kind: 'local_mock' });
  source.hardware.deviceId = 'synthetic-changed-after-creation';
  for (const surface of SURFACES) assert.deepEqual(a.observe(surface), b.observe(surface));
  const observed = a.observe('hardware');
  observed.deviceId = 'synthetic-observer-modification';
  observed.cpu.logicalCores = 100;
  assert.deepEqual(a.observe('hardware'), b.observe('hardware'));
  for (const surface of [undefined, null, '', 'Hardware', 'cpuid', '__proto__', 'host', 'network.real', 1]) {
    assert.throws(() => a.observe(surface), /MODEL_SURFACE_UNKNOWN/);
  }
});

test('schema whitelist rejects hidden fields and accessors without executing supplied getters', () => {
  const unexpected = structuredClone(windows);
  unexpected.realHostId = 'MUST_NOT_BE_READ';
  assert.throws(() => validateModel(unexpected), /MODEL_FIELDS_INVALID/);
  const withGetter = structuredClone(windows);
  let getterCalled = false;
  Object.defineProperty(withGetter.hardware, 'deviceId', { enumerable: true, get() { getterCalled = true; return 'synthetic-should-not-read'; } });
  assert.throws(() => validateModel(withGetter), /MODEL_ACCESSOR_FIELDS_NOT_ALLOWED/);
  assert.equal(getterCalled, false);
  const changedType = structuredClone(windows);
  changedType.hardware.memoryMiB = '16384';
  assert.throws(() => validateModel(changedType), /MEMORY_CAPACITY_INVALID/);
});
