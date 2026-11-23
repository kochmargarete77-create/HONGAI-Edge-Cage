import {
  SandboxRuntimeConfigSchema,
  type SandboxRuntimeConfig
} from '@anthropic-ai/sandbox-runtime';
import type { CustomerConfig } from './config.js';
import { expandPolicyPath } from './config.js';

export function renderSandboxPolicy(
  config: CustomerConfig,
  agentStateRoot?: string
): SandboxRuntimeConfig {
  const policy = {
    network: {
      allowedDomains: [...config.network.allowedDomains],
      deniedDomains: [...config.network.deniedDomains],
      strictAllowlist: true,
      allowLocalBinding: false,
      deniedResolvedAddresses: [
        '0.0.0.0/8',
        '10.0.0.0/8',
        '100.64.0.0/10',
        '127.0.0.0/8',
        '169.254.0.0/16',
        '172.16.0.0/12',
        '192.168.0.0/16',
        '224.0.0.0/4',
        '240.0.0.0/4',
        '::1/128',
        'fc00::/7',
        'fe80::/10'
      ],
      parentProxy: {
        http: config.network.localProxyUrl,
        https: config.network.localProxyUrl
      }
    },
    filesystem: {
      denyRead: config.filesystem.denyRead.map((value) => expandPolicyPath(value, config, agentStateRoot)),
      allowRead: config.filesystem.allowRead.map((value) => expandPolicyPath(value, config, agentStateRoot)),
      allowWrite: config.filesystem.allowWrite.map((value) => expandPolicyPath(value, config, agentStateRoot)),
      denyWrite: config.filesystem.denyWrite.map((value) => expandPolicyPath(value, config, agentStateRoot))
    }
  };

  return SandboxRuntimeConfigSchema.parse(policy);
}
