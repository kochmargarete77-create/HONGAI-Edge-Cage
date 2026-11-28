import { createHash } from 'node:crypto';

export const SURFACES = Object.freeze([
  'network', 'regional', 'platform', 'hardware', 'rendering', 'state', 'tools',
]);

const SCHEMA = 'hongai.environment-model.v1';
const MODE = 'LOCAL_AUTHORIZED_TEST_ONLY';
const TOP_KEYS = ['schema', 'mode', 'environmentId', 'revision', ...SURFACES];
const fail = (code) => { throw new Error(code); };

function record(value, keys, code) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) fail(code);
  const prototype = Object.getPrototypeOf(value);
  if (prototype !== Object.prototype && prototype !== null) fail(code);
  const ownKeys = Reflect.ownKeys(value);
  if (ownKeys.length !== keys.length || ownKeys.some((key) => typeof key !== 'string' || !keys.includes(key))) fail(code);
  for (const key of keys) {
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    if (!descriptor || !Object.hasOwn(descriptor, 'value')) fail('MODEL_ACCESSOR_FIELDS_NOT_ALLOWED');
  }
  return value;
}

function text(value, pattern, code, { lower = false, upper = false } = {}) {
  if (typeof value !== 'string') fail(code);
  if (value.length > 256) fail('MODEL_TEXT_LIMIT_EXCEEDED');
  let normalized = value.trim();
  if (lower) normalized = normalized.toLowerCase();
  if (upper) normalized = normalized.toUpperCase();
  if (!pattern.test(normalized)) fail(code);
  return normalized;
}

function exact(value, expected, code) {
  if (value !== expected) fail(code);
  return expected;
}

function integer(value, minimum, maximum, code) {
  if (!Number.isSafeInteger(value) || value < minimum || value > maximum) fail(code);
  return value;
}

function syntheticLabel(value) {
  return text(value, /^synthetic-[a-z0-9]+(?:-[a-z0-9]+)*$/, 'SYNTHETIC_PLACEHOLDER_LABEL_REQUIRED', { lower: true });
}

function documentationIPv4(value) {
  const address = text(value, /^\d{1,3}(?:\.\d{1,3}){3}$/, 'DOCUMENTATION_RANGE_IPV4_REQUIRED');
  const parts = address.split('.');
  if (parts.some((part) => String(Number(part)) !== part || Number(part) > 255)) fail('DOCUMENTATION_RANGE_IPV4_REQUIRED');
  const prefix = parts.slice(0, 3).join('.');
  if (!['192.0.2', '198.51.100', '203.0.113'].includes(prefix)) fail('DOCUMENTATION_RANGE_IPV4_REQUIRED');
  const host = Number(parts[3]);
  if (host < 1 || host > 254) fail('DOCUMENTATION_RANGE_HOST_ADDRESS_REQUIRED');
  return address;
}

function normalizedList(value, normalize, minimum, maximum, code) {
  if (!Array.isArray(value) || value.length < minimum || value.length > maximum) fail(code);
  const normalized = value.map(normalize);
  return [...new Set(normalized)].sort();
}

function languageTag(value) {
  if (typeof value !== 'string' || value.length > 128 || value.includes('_')) fail('BCP47_LANGUAGE_TAG_REQUIRED');
  try {
    const normalized = Intl.getCanonicalLocales(value.trim());
    if (normalized.length !== 1) fail('BCP47_LANGUAGE_TAG_REQUIRED');
    return normalized[0];
  } catch { fail('BCP47_LANGUAGE_TAG_REQUIRED'); }
}

function timeZone(value) {
  if (typeof value !== 'string' || value.length > 128) fail('IANA_TIME_ZONE_REQUIRED');
  const supplied = value.trim();
  if (!/^(?:UTC|[A-Za-z_+-]+(?:\/[A-Za-z0-9_+-]+)+)$/i.test(supplied)) fail('IANA_TIME_ZONE_REQUIRED');
  try {
    return new Intl.DateTimeFormat('en-US', { timeZone: supplied }).resolvedOptions().timeZone;
  } catch { fail('IANA_TIME_ZONE_REQUIRED'); }
}

/** Normalize a supplied synthetic metadata model; never inspect the host. */
export function validateModel(profile) {
  record(profile, TOP_KEYS, 'MODEL_FIELDS_INVALID');
  exact(profile.schema, SCHEMA, 'MODEL_SCHEMA_UNSUPPORTED');
  exact(profile.mode, MODE, 'LOCAL_AUTHORIZED_TEST_MODE_REQUIRED');

  const network = record(profile.network,
    ['transport', 'exitIPv4', 'countryCode', 'dnsResolvers', 'reachable'], 'NETWORK_FIELDS_INVALID');
  exact(network.transport, 'LOCAL_MOCK_ONLY', 'LOCAL_MOCK_TRANSPORT_REQUIRED');
  if (typeof network.reachable !== 'boolean') fail('SYNTHETIC_REACHABILITY_BOOLEAN_REQUIRED');
  const normalizedNetwork = {
    transport: 'LOCAL_MOCK_ONLY',
    exitIPv4: documentationIPv4(network.exitIPv4),
    countryCode: text(network.countryCode, /^[A-Z]{2}$/, 'DECLARED_COUNTRY_CODE_REQUIRED', { upper: true }),
    dnsResolvers: normalizedList(network.dnsResolvers, documentationIPv4, 1, 4, 'SYNTHETIC_DNS_LIST_REQUIRED'),
    reachable: network.reachable,
  };

  const regional = record(profile.regional,
    ['countryCode', 'timeZone', 'languageTag', 'locale'], 'REGIONAL_FIELDS_INVALID');
  const normalizedRegional = {
    countryCode: text(regional.countryCode, /^[A-Z]{2}$/, 'DECLARED_COUNTRY_CODE_REQUIRED', { upper: true }),
    timeZone: timeZone(regional.timeZone),
    languageTag: languageTag(regional.languageTag),
    locale: languageTag(regional.locale),
  };
  // These are two explicit synthetic labels, never IP geolocation inferences.
  if (normalizedNetwork.countryCode !== normalizedRegional.countryCode) fail('DECLARED_COUNTRY_LABELS_DISAGREE');

  const platform = record(profile.platform, ['os', 'architecture', 'osVersion'], 'PLATFORM_FIELDS_INVALID');
  const osInput = text(platform.os, /^(?:windows|macos)$/, 'SUPPORTED_DESKTOP_PLATFORM_REQUIRED', { lower: true });
  const normalizedPlatform = {
    os: osInput === 'macos' ? 'macOS' : 'windows',
    architecture: text(platform.architecture, /^(?:x64|arm64)$/, 'SUPPORTED_ARCHITECTURE_REQUIRED', { lower: true }),
    osVersion: text(platform.osVersion, /^\d{1,5}(?:\.\d{1,5}){0,3}$/, 'EXPLICIT_OS_VERSION_REQUIRED'),
  };
  // Only these combinations are implemented by this metadata lab.
  if (normalizedPlatform.os === 'windows' && normalizedPlatform.architecture !== 'x64') fail('PLATFORM_ARCHITECTURE_NOT_IMPLEMENTED');

  const hardware = record(profile.hardware,
    ['identityKind', 'deviceId', 'cpu', 'memoryMiB'], 'HARDWARE_FIELDS_INVALID');
  const cpu = record(hardware.cpu, ['label', 'physicalCores', 'logicalCores'], 'CPU_FIELDS_INVALID');
  const physicalCores = integer(cpu.physicalCores, 1, 64, 'PHYSICAL_CORE_COUNT_INVALID');
  const logicalCores = integer(cpu.logicalCores, 1, 128, 'LOGICAL_CORE_COUNT_INVALID');
  if (logicalCores !== physicalCores && logicalCores !== 2 * physicalCores) fail('CPU_THREAD_TOPOLOGY_INVALID');
  if (normalizedPlatform.os === 'macOS' && normalizedPlatform.architecture === 'arm64' && logicalCores !== physicalCores) fail('ARM64_MAC_CPU_TOPOLOGY_INVALID');
  const memoryMiB = integer(hardware.memoryMiB, 2048, 131072, 'MEMORY_CAPACITY_INVALID');
  if (memoryMiB % 1024 !== 0) fail('MEMORY_CAPACITY_ALIGNMENT_INVALID');
  const normalizedHardware = {
    identityKind: exact(hardware.identityKind, 'SYNTHETIC_PLACEHOLDER_NOT_REAL_HARDWARE_ID', 'SYNTHETIC_IDENTITY_KIND_REQUIRED'),
    deviceId: syntheticLabel(hardware.deviceId),
    cpu: { label: syntheticLabel(cpu.label), physicalCores, logicalCores },
    memoryMiB,
  };

  const rendering = record(profile.rendering,
    ['mode', 'graphicsApi', 'vendorLabel', 'deviceLabel', 'fingerprint'], 'RENDERING_FIELDS_INVALID');
  const graphicsApi = text(rendering.graphicsApi, /^(?:d3d11|d3d12|opengl|metal)$/, 'GRAPHICS_API_INVALID', { lower: true });
  const allowedGraphics = normalizedPlatform.os === 'windows' ? ['d3d11', 'd3d12', 'opengl'] : ['metal', 'opengl'];
  if (!allowedGraphics.includes(graphicsApi)) fail('GRAPHICS_API_PLATFORM_MISMATCH');
  const normalizedRendering = {
    mode: exact(rendering.mode, 'METADATA_ONLY', 'RENDERING_METADATA_ONLY_REQUIRED'),
    graphicsApi,
    vendorLabel: syntheticLabel(rendering.vendorLabel),
    deviceLabel: syntheticLabel(rendering.deviceLabel),
    fingerprint: exact(rendering.fingerprint, 'NOT_RENDERED_NOT_A_REAL_GPU_FINGERPRINT', 'REAL_RENDERING_NOT_IMPLEMENTED'),
  };

  const state = record(profile.state, ['profileId', 'persistence', 'authentication'], 'STATE_FIELDS_INVALID');
  const normalizedState = {
    profileId: syntheticLabel(state.profileId),
    persistence: exact(state.persistence, 'FIXED_METADATA', 'SYNTHETIC_STATE_MODE_REQUIRED'),
    authentication: exact(state.authentication, 'SYNTHETIC_UNAUTHENTICATED', 'REAL_AUTHENTICATION_NOT_SUPPORTED'),
  };

  const tools = record(profile.tools, ['transport', 'capabilities', 'resultContext'], 'TOOLS_FIELDS_INVALID');
  const capabilities = normalizedList(tools.capabilities,
    (name) => text(name, /^(?:file\.read|file\.write|project\.inspect|network\.describe)$/, 'SYNTHETIC_TOOL_CAPABILITY_UNKNOWN', { lower: true }),
    0, 4, 'SYNTHETIC_TOOL_CAPABILITIES_INVALID');
  const normalizedTools = {
    transport: exact(tools.transport, 'LOCAL_MOCK_ONLY', 'LOCAL_MOCK_TOOL_TRANSPORT_REQUIRED'),
    capabilities,
    resultContext: exact(tools.resultContext, 'SYNTHETIC_WORKSPACE_ONLY_NO_HOST_ACCESS', 'SYNTHETIC_TOOL_CONTEXT_REQUIRED'),
  };

  const environmentId = text(profile.environmentId, /^lab-[a-z0-9]+(?:-[a-z0-9]+)*$/, 'STABLE_LAB_ENVIRONMENT_ID_REQUIRED', { lower: true });
  if (environmentId.length > 96) fail('MODEL_ENVIRONMENT_ID_TOO_LONG');
  return {
    schema: SCHEMA,
    mode: MODE,
    environmentId,
    revision: integer(profile.revision, 1, Number.MAX_SAFE_INTEGER, 'MODEL_REVISION_INVALID'),
    network: normalizedNetwork,
    regional: normalizedRegional,
    platform: normalizedPlatform,
    hardware: normalizedHardware,
    rendering: normalizedRendering,
    state: normalizedState,
    tools: normalizedTools,
  };
}

function canonical(value) {
  if (Array.isArray(value)) return '[' + value.map(canonical).join(',') + ']';
  if (value !== null && typeof value === 'object') {
    return '{' + Object.keys(value).sort().map((key) => JSON.stringify(key) + ':' + canonical(value[key])).join(',') + '}';
  }
  return JSON.stringify(value);
}

export function profileDigest(profile) {
  return createHash('sha256').update(canonical(validateModel(profile)), 'utf8').digest('hex');
}

/** This provider observes supplied metadata only. It has no vendor or host IO. */
export function createLocalProvider(profile, options) {
  record(options, ['kind'], 'EXPLICIT_LOCAL_MOCK_PROVIDER_REQUIRED');
  exact(options.kind, 'local_mock', 'PROVIDER_KIND_NOT_IMPLEMENTED_NO_FALLBACK');
  const snapshot = validateModel(profile);
  return Object.freeze({
    kind: 'local_mock',
    observe(surface) {
      if (typeof surface !== 'string' || !SURFACES.includes(surface)) fail('MODEL_SURFACE_UNKNOWN');
      // Each caller receives its own data; consumers cannot mutate the saved model.
      return structuredClone(snapshot[surface]);
    },
  });
}
