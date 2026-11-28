import { types } from 'node:util';
import { SURFACES, validateModel, profileDigest } from './model.mjs';

export const MINIMUM_INDEPENDENT_RUNS = 2;
const MAXIMUM_REPORTS = 64;
const REPORT_FIELDS = ['schema', 'evidenceLevel', 'providerKind', 'runId', 'challenge', 'modelDigest', 'executionHost', 'targetModel', 'probe', 'expected', 'observed', 'matched', 'officialClientConnected', 'vendorAdapterStatus', 'targetServiceContacted', 'nativeHardwareReadPathsValidated', 'hostIdentifiersModified', 'hostNetworkModified', 'customerReady'];
const PROBE_FIELDS = ['pid', 'codeDigest', 'exitCode', 'signal', 'startedUtc', 'finishedUtc', 'protocolDigest', 'stderrDigest'];
const HEX64 = /^[a-f0-9]{64}$/;
const UUID = /^[a-f0-9]{8}-[a-f0-9]{4}-4[a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/;
const fail = (code) => { throw new Error(code); };
const isRecord = (value) => value !== null && typeof value === 'object' && !Array.isArray(value);

// Only bounded JSON data is inspected. Do not execute getters, toJSON, proxies
// or caller callbacks while deciding whether supplied evidence is admissible.
function snapshot(value, depth = 0, budget = { nodes: 0 }) {
  if (++budget.nodes > 10000 || depth > 16) fail('COHERENCE_INPUT_COMPLEXITY_LIMIT');
  if (value === null || typeof value === 'boolean') return value;
  if (typeof value === 'string') {
    if (value.length > 4096) fail('COHERENCE_INPUT_TEXT_LIMIT');
    return value;
  }
  if (typeof value === 'number' && Number.isFinite(value)) return value;
  if (typeof value !== 'object' || types.isProxy(value)) fail('COHERENCE_JSON_DATA_REQUIRED');
  const array = Array.isArray(value), prototype = Object.getPrototypeOf(value);
  if (!array && prototype !== Object.prototype && prototype !== null) fail('COHERENCE_PLAIN_RECORD_REQUIRED');
  const keys = Reflect.ownKeys(value);
  if (keys.length > 128 || (array && value.length > 128)) fail('COHERENCE_INPUT_COLLECTION_LIMIT');
  const result = array ? [] : Object.create(null);
  for (const key of keys) {
    if (array && key === 'length') continue;
    if (typeof key !== 'string' || (array && (!/^(?:0|[1-9][0-9]*)$/.test(key) || Number(key) >= value.length))) fail('COHERENCE_JSON_FIELDS_REQUIRED');
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    if (!descriptor || !Object.hasOwn(descriptor, 'value') || !descriptor.enumerable) fail('COHERENCE_ACCESSOR_OR_HIDDEN_FIELDS_REJECTED');
    result[key] = snapshot(descriptor.value, depth + 1, budget);
  }
  if (array && Object.keys(result).length !== value.length) fail('COHERENCE_SPARSE_ARRAY_REJECTED');
  return result;
}

function canonical(value) {
  if (Array.isArray(value)) return '[' + value.map(canonical).join(',') + ']';
  if (isRecord(value)) return '{' + Object.keys(value).sort().map((key) => JSON.stringify(key) + ':' + canonical(value[key])).join(',') + '}';
  return JSON.stringify(value);
}

const equal = (a, b) => canonical(a) === canonical(b);
const unknownFields = (record, allowed) => Object.keys(record).some((key) => !allowed.includes(key));
const missingFields = (record, required) => required.some((key) => !Object.hasOwn(record, key));

function shape(value, expected) {
  if (!isRecord(expected) || !isRecord(value)) return { unknown: false, missing: false };
  let unknown = unknownFields(value, Object.keys(expected));
  let missing = missingFields(value, Object.keys(expected));
  for (const key of Object.keys(expected)) if (Object.hasOwn(value, key)) {
    const child = shape(value[key], expected[key]);
    unknown ||= child.unknown; missing ||= child.missing;
  }
  return { unknown, missing };
}

function validInstant(value) {
  if (typeof value !== 'string' || !/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/.test(value)) return false;
  const instant = Date.parse(value);
  return Number.isFinite(instant) && new Date(instant).toISOString() === value;
}

function inspect(raw, index, model, digest, seen) {
  const result = { index, status: 'NOT_TESTED', codes: [], surfaces: Object.fromEntries(SURFACES.map((surface) => [surface, { status: 'NOT_TESTED', codes: [] }])) };
  const error = (code) => { if (!result.codes.includes(code)) result.codes.push(code); };
  let report;
  try { report = snapshot(raw); } catch (exception) { error(exception.message); result.status = 'FAIL'; return result; }
  if (!isRecord(report)) { error('READBACK_REPORT_RECORD_REQUIRED'); result.status = 'FAIL'; return result; }
  if (unknownFields(report, REPORT_FIELDS)) error('READBACK_REPORT_FIELDS_UNKNOWN');
  if (missingFields(report, REPORT_FIELDS.filter((key) => !['expected', 'observed'].includes(key)))) error('READBACK_REPORT_FIELDS_MISSING');
  if (report.schema !== 'hongai.local-simulation-readback.v1' || report.evidenceLevel !== 'LOCAL_SIMULATOR_READBACK' || report.providerKind !== 'local_mock') error('LOCAL_READBACK_SCOPE_REQUIRED');
  if (typeof report.runId !== 'string' || !UUID.test(report.runId)) error('INDEPENDENT_RUN_ID_REQUIRED');
  else if (seen.runIds.has(report.runId)) error('RUN_ID_REUSED');
  else seen.runIds.add(report.runId);
  if (typeof report.challenge !== 'string' || !/^[a-f0-9]{48}$/.test(report.challenge)) error('INDEPENDENT_CHALLENGE_REQUIRED');
  else if (seen.challenges.has(report.challenge)) error('CHALLENGE_REUSED');
  else seen.challenges.add(report.challenge);
  if (report.modelDigest !== digest) error('REQUESTED_MODEL_REVISION_DIGEST_MISMATCH');
  if (!equal(report.targetModel, model.platform)) error('TARGET_MODEL_PLATFORM_MISMATCH');
  if (!['win32', 'darwin'].includes(report.executionHost)) error('SUPPORTED_EXECUTION_HOST_REQUIRED');
  else result.executionHost = {
    reportedHostPlatform: report.executionHost,
    targetModelOS: model.platform.os,
    relationship: report.executionHost === (model.platform.os === 'windows' ? 'win32' : 'darwin') ? 'REPORTED_HOST_OS_MATCHES_MODEL' : 'CROSS_MODEL_REPORTED_HOST_OS',
    hostArchitecture: 'NOT_RECORDED_BY_READBACK_SCHEMA',
    nativePlatformCoverage: 'NOT_ESTABLISHED',
  };
  if (report.matched !== true) error('READBACK_DID_NOT_MATCH');
  for (const key of ['officialClientConnected', 'targetServiceContacted', 'nativeHardwareReadPathsValidated', 'hostIdentifiersModified', 'hostNetworkModified', 'customerReady']) {
    if (report[key] !== false) error('UNSUPPORTED_COVERAGE_OR_SIDE_EFFECT_CLAIM');
  }
  if (report.vendorAdapterStatus !== 'NOT_CONNECTED') error('VENDOR_ADAPTER_SCOPE_NOT_LOCAL');
  const probe = report.probe;
  if (!isRecord(probe) || unknownFields(probe, PROBE_FIELDS) || missingFields(probe, PROBE_FIELDS)) error('PROBE_FIELDS_INVALID');
  else {
    if (!Number.isSafeInteger(probe.pid) || probe.pid < 1) error('INDEPENDENT_PROBE_PID_REQUIRED');
    if (![probe.codeDigest, probe.protocolDigest, probe.stderrDigest].every((value) => typeof value === 'string' && HEX64.test(value))) error('PROBE_DIGESTS_INVALID');
    if (probe.exitCode !== 0 || probe.signal !== null) error('PROBE_DID_NOT_EXIT_SUCCESSFULLY');
    if (!validInstant(probe.startedUtc) || !validInstant(probe.finishedUtc) || Date.parse(probe.startedUtc) > Date.parse(probe.finishedUtc)) error('PROBE_TIME_WINDOW_INVALID');
    // PID reuse after a process exits is legitimate. The unique run/challenge
    // are the replay checks; a PID by itself is not a stable run identity.
  }
  if (result.codes.length) {
    result.status = 'FAIL';
    return result;
  }
  for (const key of ['expected', 'observed']) {
    if (Object.hasOwn(report, key) && (!isRecord(report[key]) || unknownFields(report[key], SURFACES))) error('SURFACE_SNAPSHOT_FIELDS_INVALID');
  }
  if (result.codes.length) { result.status = 'FAIL'; return result; }
  let incomplete = false;
  for (const surface of SURFACES) {
    const check = result.surfaces[surface];
    if (!Object.hasOwn(report.expected ?? {}, surface) || !Object.hasOwn(report.observed ?? {}, surface)) {
      check.codes.push('SURFACE_NOT_OBSERVED'); incomplete = true; continue;
    }
    const expectedShape = shape(report.expected[surface], model[surface]);
    const observedShape = shape(report.observed[surface], model[surface]);
    if (expectedShape.unknown || observedShape.unknown) { check.status = 'FAIL'; check.codes.push('SURFACE_FIELDS_UNKNOWN'); }
    else if (expectedShape.missing || observedShape.missing) { check.codes.push('SURFACE_FIELDS_NOT_OBSERVED'); incomplete = true; }
    else if (!equal(report.expected[surface], model[surface])) { check.status = 'FAIL'; check.codes.push('DECLARED_EXPECTATION_DIFFERS_FROM_MODEL'); }
    else if (!equal(report.observed[surface], model[surface])) { check.status = 'FAIL'; check.codes.push('OBSERVATION_DIFFERS_FROM_MODEL'); }
    else check.status = 'PASS';
  }
  const failed = Object.values(result.surfaces).some((entry) => entry.status === 'FAIL');
  result.status = failed ? 'FAIL' : incomplete ? 'NOT_TESTED' : 'PASS';
  return result;
}

/**
 * Pure evaluation of synthetic model/readback JSON. No IO, host mutation or
 * target-client integration. Reports are not authenticated attestations: their
 * protocol digests and PIDs cannot prove a live process to a later evaluator.
 */
export function evaluateCoherence(profile, reports) {
  const model = validateModel(snapshot(profile));
  if (!Array.isArray(reports) || types.isProxy(reports)) fail('COHERENCE_REPORT_ARRAY_REQUIRED');
  if (reports.length > MAXIMUM_REPORTS) fail('COHERENCE_REPORT_LIMIT');
  const seen = { runIds: new Set(), challenges: new Set() }, digest = profileDigest(model);
  const runs = [];
  for (let index = 0; index < reports.length; index++) {
    const descriptor = Object.getOwnPropertyDescriptor(reports, String(index));
    if (!descriptor || !Object.hasOwn(descriptor, 'value')) {
      runs.push({ index, status: 'FAIL', codes: ['READBACK_SAMPLE_MISSING_OR_ACCESSOR'], surfaces: Object.fromEntries(SURFACES.map((surface) => [surface, { status: 'NOT_TESTED', codes: [] }])) });
    } else runs.push(inspect(descriptor.value, index, model, digest, seen));
  }
  const surfaces = Object.fromEntries(SURFACES.map((surface) => {
    const observations = runs.map((run) => run.surfaces[surface]);
    const matchedRuns = observations.filter((entry) => entry.status === 'PASS').length;
    const failedRuns = observations.filter((entry) => entry.status === 'FAIL').length;
    const status = failedRuns ? 'FAIL' : matchedRuns >= MINIMUM_INDEPENDENT_RUNS ? 'PASS' : 'NOT_TESTED';
    return [surface, { status, matchedRuns, failedRuns, missingRuns: reports.length - matchedRuns - failedRuns,
      codes: [...new Set(observations.flatMap((entry) => entry.codes))] }];
  }));
  const acceptedIndependentRuns = runs.filter((run) => run.status === 'PASS').length;
  const failed = runs.some((run) => run.status === 'FAIL') || Object.values(surfaces).some((surface) => surface.status === 'FAIL');
  const complete = !failed && acceptedIndependentRuns >= MINIMUM_INDEPENDENT_RUNS && Object.values(surfaces).every((surface) => surface.status === 'PASS');
  return {
    schema: 'hongai.local-simulation-coherence.v1', evidenceLevel: 'LOCAL_SIMULATOR_READBACK',
    status: failed ? 'FAIL' : complete ? 'PASS' : 'NOT_TESTED',
    model: { environmentId: model.environmentId, revision: model.revision, modelDigest: digest, targetPlatform: model.platform },
    minimumIndependentRuns: MINIMUM_INDEPENDENT_RUNS, sampleCount: reports.length, acceptedIndependentRuns,
    localReadbackComplete: complete, codes: complete ? [] : acceptedIndependentRuns < MINIMUM_INDEPENDENT_RUNS ? ['INSUFFICIENT_ACCEPTED_INDEPENDENT_RUNS'] : [],
    surfaces, runs,
    executionHostEvidence: 'INPUT_REPORT_CLAIMS_NOT_PLATFORM_ATTESTATION',
    nationalityOrPersonalIdentityInferred: false,
    targetClientVerified: false, officialClientConnected: false, targetServiceContacted: false,
    nativeHardwareReadPathsValidated: false, customerReady: false, fullEnvironmentAccepted: false,
  };
}
