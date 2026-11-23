import assert from 'node:assert/strict';
import { mkdir, mkdtemp, readFile, rm, symlink } from 'node:fs/promises';
import { join, resolve } from 'node:path';
import test from 'node:test';
import {
  isAnthropicCertificateSubject,
  parseAppleClaudeCodeSignature,
  parseLipoArchitectures,
  selectProductionDependencyPaths,
  verifyOfficialClaudeExecutable,
  windowsProductVersionMatchesPackage
} from '../src/pilot-builder.js';

test('pilot dependency selection skips npm root and rejects paths outside canonical node_modules', async () => {
  const testBase = resolve(process.cwd(), '.test-tmp');
  await mkdir(testBase, { recursive: true });
  const directory = await mkdtemp(join(testBase, 'pilot-dependencies-'));
  const projectRoot = join(directory, 'project');
  const packageRoot = join(projectRoot, 'node_modules', 'allowed-package');
  const excludedPlatformPackage = join(
    projectRoot,
    'node_modules',
    '@anthropic-ai',
    'claude-code-win32-x64'
  );
  const excludedNestedPlatformPackage = join(
    projectRoot,
    'node_modules',
    'nested-parent',
    'node_modules',
    '@anthropic-ai',
    'claude-code-darwin-arm64'
  );
  const externalRoot = join(directory, 'external-package');
  const linkedPackage = join(projectRoot, 'node_modules', 'linked-package');
  try {
    await Promise.all([
      mkdir(packageRoot, { recursive: true }),
      mkdir(excludedPlatformPackage, { recursive: true }),
      mkdir(excludedNestedPlatformPackage, { recursive: true }),
      mkdir(externalRoot, { recursive: true })
    ]);
    assert.deepEqual(
      await selectProductionDependencyPaths(projectRoot, [
        projectRoot,
        packageRoot,
        excludedPlatformPackage,
        excludedNestedPlatformPackage
      ]),
      [resolve(packageRoot)]
    );
    await assert.rejects(
      selectProductionDependencyPaths(projectRoot, [externalRoot]),
      /outside the project/
    );

    await symlink(externalRoot, linkedPackage, process.platform === 'win32' ? 'junction' : 'dir');
    await assert.rejects(
      selectProductionDependencyPaths(projectRoot, [linkedPackage]),
      /outside the project/
    );
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

test('macOS lipo architecture evidence maps only supported native slices', () => {
  assert.deepEqual(parseLipoArchitectures('arm64\n'), ['arm64']);
  assert.deepEqual(parseLipoArchitectures('x86_64 arm64\n'), ['arm64', 'x64']);
  assert.throws(() => parseLipoArchitectures(''), /no architecture slices/);
  assert.throws(() => parseLipoArchitectures('i386'), /unsupported architecture slice/);
  assert.throws(() => parseLipoArchitectures('arm64 arm64'), /duplicate architecture slices/);
});

test('Windows Claude Code product version is bound to the pinned package version', () => {
  assert.equal(windowsProductVersionMatchesPackage('2.1.330.0', '2.1.330'), true);
  assert.equal(windowsProductVersionMatchesPackage('2.1.330', '2.1.330'), true);
  assert.equal(windowsProductVersionMatchesPackage('2.1.330.1', '2.1.330'), false);
  assert.equal(windowsProductVersionMatchesPackage('2.1.331.0', '2.1.330'), false);
  assert.equal(windowsProductVersionMatchesPackage('2.1.330-evil', '2.1.330'), false);
});

test('Authenticode signer subject accepts only an Anthropic PBC identity component', () => {
  assert.equal(isAnthropicCertificateSubject('CN=Anthropic PBC'), true);
  assert.equal(isAnthropicCertificateSubject('CN=Claude Code, O="Anthropic, PBC", C=US'), true);
  assert.equal(isAnthropicCertificateSubject('CN=Claude Code, O=Anthropic\\, PBC, C=US'), true);
  assert.equal(isAnthropicCertificateSubject('CN=Not Anthropic PBC'), false);
  assert.equal(isAnthropicCertificateSubject('CN=Anthropic PBC Malware'), false);
});

test('Apple signature evidence requires Anthropic authority and matching team identifier', () => {
  const result = parseAppleClaudeCodeSignature([
    'Executable=/tmp/claude',
    'Identifier=com.anthropic.claude-code',
    'Authority=Developer ID Application: Anthropic, PBC (Q6L2SF6YDW)',
    'Authority=Developer ID Certification Authority',
    'Authority=Apple Root CA',
    'TeamIdentifier=Q6L2SF6YDW'
  ].join('\n'));
  assert.equal(result.verified, true);
  assert.equal(result.identifier, 'com.anthropic.claude-code');
  assert.equal(result.teamIdentifier, 'Q6L2SF6YDW');
  assert.match(result.signingAuthority, /^Developer ID Application: Anthropic/);
});

test('Apple signature evidence rejects ad-hoc, lookalike and mismatched identities', () => {
  assert.throws(() => parseAppleClaudeCodeSignature([
    'Signature=adhoc',
    'TeamIdentifier=not set'
  ].join('\n')), /TeamIdentifier/);
  assert.throws(() => parseAppleClaudeCodeSignature([
    'Identifier=com.anthropic.claude-code',
    'Authority=Developer ID Application: Not Anthropic PBC (Q6L2SF6YDW)',
    'Authority=Developer ID Certification Authority',
    'Authority=Apple Root CA',
    'TeamIdentifier=Q6L2SF6YDW'
  ].join('\n')), /pinned Anthropic Developer ID chain/);
  assert.throws(() => parseAppleClaudeCodeSignature([
    'Identifier=com.anthropic.claude-code',
    'Authority=Developer ID Application: Anthropic PBC (AAAAAAAAAA)',
    'Authority=Developer ID Certification Authority',
    'Authority=Apple Root CA',
    'TeamIdentifier=BBBBBBBBBB'
  ].join('\n')), /pinned Anthropic Apple TeamIdentifier/);
  assert.throws(() => parseAppleClaudeCodeSignature([
    'Identifier=com.example.lookalike',
    'Authority=Developer ID Application: Anthropic PBC (Q6L2SF6YDW)',
    'Authority=Developer ID Certification Authority',
    'Authority=Apple Root CA',
    'TeamIdentifier=Q6L2SF6YDW'
  ].join('\n')), /pinned Anthropic bundle identifier/);
  assert.throws(() => parseAppleClaudeCodeSignature([
    'Identifier=com.anthropic.claude-code',
    'Authority=Developer ID Application: Anthropic PBC (Q6L2SF6YDW)',
    'TeamIdentifier=Q6L2SF6YDW'
  ].join('\n')), /pinned Anthropic Developer ID chain/);
});

test('the installed pinned Claude Code binary has a valid Anthropic vendor signature', {
  skip: !['win32', 'darwin'].includes(process.platform)
}, async () => {
  const projectRoot = resolve(process.cwd());
  const metadata = JSON.parse(await readFile(
    resolve(projectRoot, 'node_modules', '@anthropic-ai', 'claude-code', 'package.json'),
    'utf8'
  )) as { version: string; bin?: { claude?: string } };
  assert.equal(metadata.bin?.claude, 'bin/claude.exe');
  const platform = process.platform === 'win32' ? 'windows' : 'macos';
  const executable = resolve(
    projectRoot,
    'node_modules',
    '@anthropic-ai',
    'claude-code',
    'bin',
    'claude.exe'
  );
  const result = await verifyOfficialClaudeExecutable(
    executable,
    metadata.version,
    projectRoot,
    platform
  );
  assert.equal(result.verified, true);
});
