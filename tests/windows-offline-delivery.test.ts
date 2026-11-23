import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { spawnSync } from 'node:child_process';
import { mkdir, mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { dirname, resolve } from 'node:path';
import test from 'node:test';

const projectRoot = resolve(process.cwd());
const windowsRoot = resolve(projectRoot, 'platform', 'windows');

async function script(name: string): Promise<string> {
  return await readFile(resolve(windowsRoot, name), 'utf8');
}

test('Windows customer flow is offline and always uses the pinned payload runtime', async () => {
  const [common, installer, start, doctor, uninstaller] = await Promise.all([
    script('HONGAI-Windows.Common.ps1'),
    script('Install-HONGAI-Edge-Cage.ps1'),
    script('Start-HONGAI-Edge-Cage.ps1'),
    script('Test-HONGAI-Edge-Cage.ps1'),
    script('Uninstall-HONGAI-Edge-Cage.ps1')
  ]);
  for (const value of [common, installer, start, doctor, uninstaller]) {
    assert.doesNotMatch(value, /\bnpm\s+(?:ci|install|run)\b/i);
    assert.doesNotMatch(value, /\b(?:curl|wget|Invoke-WebRequest|Start-BitsTransfer)\b/i);
  }
  assert.match(common, /runtime\\node\.exe/);
  assert.match(common, /never downloads or substitutes Node\.js/);
  assert.match(common, /HONGAI-PAYLOAD\.json/);
  assert.match(installer, /-VerifyPortableManifest/);
  for (const value of [start, doctor, uninstaller]) {
    assert.match(value, /-VerifyPortableManifest\s+-AllowInstalledState/);
  }
  assert.match(common, /\.edge-cage\/windows-install-state\.json/);
  assert.match(start, /Assert-HongAiInstalledConfig/);
  assert.match(doctor, /Assert-HongAiInstalledConfig/);
});

test('Windows install owns only fresh sandbox state and rolls it back on failure', async () => {
  const [installer, uninstaller] = await Promise.all([
    script('Install-HONGAI-Edge-Cage.ps1'),
    script('Uninstall-HONGAI-Edge-Cage.ps1')
  ]);
  assert.match(installer, /Assert-HongAiAdministrator/);
  assert.match(installer, /Assert-HongAiFreeSpace/);
  assert.match(installer, /Enter-HongAiMachineMutationLock/);
  assert.match(installer, /Exit-HongAiMachineMutationLock/);
  assert.match(installer, /SandboxPreexisting/);
  assert.match(installer, /status\s*=\s*'INSTALLING'/);
  assert.match(installer, /TransactionScratchPath/);
  assert.match(installer, /-ScratchDirectory \$ResolvedTransactionScratch/);
  assert.match(installer, /StatusAfterRollback/);
  assert.match(installer, /sandboxProvisionedByThisInstall/);
  assert.match(installer, /windows-uninstall/);
  assert.match(installer, /Rolling back/);
  assert.match(uninstaller, /RemoveSharedSandbox/);
  assert.match(uninstaller, /Enter-HongAiMachineMutationLock/);
  assert.match(uninstaller, /Refusing to remove a potentially shared sandbox/);
  assert.match(uninstaller, /APPLICATION_DETACHED/);
  assert.match(uninstaller, /completed\./);
  assert.match(uninstaller, /'INSTALLED',\s*'INSTALLING'/);
  assert.match(uninstaller, /InterruptedInstall/);
  assert.match(uninstaller, /-not \[bool\]\$State\.sandboxPreexisting/);
  assert.match(uninstaller, /SuppressInterruptedCompletionRecord/);
  assert.match(uninstaller, /reserved for delivery-controller recovery of a verified INSTALLING journal/);
  assert.match(uninstaller, /if \(-not \$SuppressCompletionRecord\)/);

  const installingJournal = installer.indexOf('Write-HongAiJsonAtomic -Path $StatePath -Value $InstallingState');
  const machineProvision = installer.indexOf("-Arguments @('windows-install', '--skip-profile-grant')");
  assert.ok(installingJournal >= 0 && machineProvision >= 0 && installingJournal < machineProvision,
    'INSTALLING ownership state must be durable before machine-wide provisioning starts');
});

test('Windows state replacement is atomic and unsafe Node loaders are cleared before bundled Node runs', async () => {
  const common = await script('HONGAI-Windows.Common.ps1');
  assert.match(common, /Remove-Item -LiteralPath "Env:\$HongAiUnsafeEnvironmentName"/);
  assert.match(common, /'NODE_OPTIONS'/);
  assert.match(common, /'NODE_PATH'/);
  assert.match(common, /\[IO\.File\]::Replace\(\$temporaryPath, \$Path/);
  assert.match(common, /Flush\(\$true\)/);
  assert.match(common, /Atomic state scratch path must be on the same volume/);
});

test('Windows atomic state writer replaces INSTALLING with INSTALLED', {
  skip: process.platform !== 'win32'
}, async () => {
  const tempRoot = resolve(projectRoot, '.test-tmp');
  await mkdir(tempRoot, { recursive: true });
  const fixture = await mkdtemp(resolve(tempRoot, 'windows-state-'));
  try {
    const common = resolve(windowsRoot, 'HONGAI-Windows.Common.ps1').replaceAll("'", "''");
    const statePath = resolve(fixture, 'state.json').replaceAll("'", "''");
    const command = [
      `. '${common}';`,
      `$path='${statePath}';`,
      "Write-HongAiJsonAtomic -Path $path -Value ([ordered]@{schemaVersion=1;status='INSTALLING'});",
      "Write-HongAiJsonAtomic -Path $path -Value ([ordered]@{schemaVersion=1;status='INSTALLED'});",
      '(Get-Content -LiteralPath $path -Raw | ConvertFrom-Json).status'
    ].join('');
    const result = spawnSync('powershell.exe', ['-NoLogo', '-NoProfile', '-NonInteractive', '-Command', command], {
      encoding: 'utf8',
      windowsHide: true
    });
    assert.equal(result.status, 0, result.stderr);
    assert.equal(result.stdout.trim(), 'INSTALLED');
  } finally {
    await rm(fixture, { recursive: true, force: true });
  }
});

test('all Windows delivery scripts parse with Windows PowerShell', {
  skip: process.platform !== 'win32'
}, async () => {
  for (const name of [
    'HONGAI-Windows.Common.ps1',
    'Install-HONGAI-Edge-Cage.ps1',
    'Start-HONGAI-Edge-Cage.ps1',
    'Test-HONGAI-Edge-Cage.ps1',
    'Uninstall-HONGAI-Edge-Cage.ps1'
  ]) {
    const path = resolve(windowsRoot, name).replaceAll("'", "''");
    const command = [
      '$tokens=$null;$errors=$null;',
      `[System.Management.Automation.Language.Parser]::ParseFile('${path}',[ref]$tokens,[ref]$errors)|Out-Null;`,
      'if($errors.Count){$errors|ForEach-Object{Write-Error $_.Message};exit 1}'
    ].join('');
    const result = spawnSync('powershell.exe', ['-NoLogo', '-NoProfile', '-NonInteractive', '-Command', command], {
      encoding: 'utf8',
      windowsHide: true
    });
    assert.equal(result.status, 0, `${name}: ${result.stderr}`);
  }
});

test('Windows payload verification detects post-build tampering', {
  skip: process.platform !== 'win32'
}, async () => {
  const tempRoot = resolve(projectRoot, '.test-tmp');
  await mkdir(tempRoot, { recursive: true });
  const fixture = await mkdtemp(resolve(tempRoot, 'windows-payload-'));
  try {
    const delivery = {
      schemaVersion: 2,
      product: 'HONG AI Edge Cage',
      version: '9.9.9-test',
      bundleType: 'portable',
      platform: 'windows',
      architecture: 'x64',
      payloadManifest: 'HONGAI-PAYLOAD.json'
    };
    const contents = new Map<string, Buffer>([
      ['HONGAI-DELIVERY.json', Buffer.from(`${JSON.stringify(delivery)}\n`)],
      ['package.json', Buffer.from('{"name":"@hongai/edge-cage","version":"9.9.9-test"}\n')],
      ['dist/src/cli.js', Buffer.from('export {};\n')],
      ['runtime/node.exe', Buffer.from('test node runtime')],
      ['node_modules/@anthropic-ai/sandbox-runtime/dist/cli.js', Buffer.from('export {};\n')],
      ['node_modules/@anthropic-ai/sandbox-runtime/vendor/srt-win/x64/srt-win.exe', Buffer.from('test srt runtime')],
      ['node_modules/@anthropic-ai/claude-code/bin/claude.exe', Buffer.from('test claude runtime')]
    ]);
    for (const [relativePath, value] of contents) {
      const path = resolve(fixture, relativePath);
      await mkdir(dirname(path), { recursive: true });
      await writeFile(path, value);
    }
    await writeFile(resolve(fixture, 'HONGAI-PAYLOAD.json'), `${JSON.stringify({
      schemaVersion: 1,
      product: 'HONG AI Edge Cage',
      files: [...contents].map(([path, value]) => ({
        path: path.replaceAll('\\', '/'),
        bytes: value.byteLength,
        sha256: createHash('sha256').update(value).digest('hex')
      }))
    })}\n`);

    const common = resolve(windowsRoot, 'HONGAI-Windows.Common.ps1').replaceAll("'", "''");
    const payload = fixture.replaceAll("'", "''");
    const verify = `. '${common}'; Assert-HongAiPortablePayload -ProjectRoot '${payload}' -Architecture x64`;
    const valid = spawnSync('powershell.exe', ['-NoLogo', '-NoProfile', '-NonInteractive', '-Command', verify], {
      encoding: 'utf8',
      windowsHide: true
    });
    assert.equal(valid.status, 0, valid.stderr);

    await mkdir(resolve(fixture, '.edge-cage'), { recursive: true });
    await writeFile(resolve(fixture, '.edge-cage', 'windows-install-state.json'), '{"status":"INSTALLED"}\n');
    const installedVerify = `${verify} -AllowInstalledState`;
    const installed = spawnSync('powershell.exe', ['-NoLogo', '-NoProfile', '-NonInteractive', '-Command', installedVerify], {
      encoding: 'utf8',
      windowsHide: true
    });
    assert.equal(installed.status, 0, installed.stderr);

    await writeFile(resolve(fixture, '.edge-cage', 'unexpected.json'), '{}\n');
    const undeclared = spawnSync('powershell.exe', ['-NoLogo', '-NoProfile', '-NonInteractive', '-Command', installedVerify], {
      encoding: 'utf8',
      windowsHide: true
    });
    assert.notEqual(undeclared.status, 0);
    assert.match(`${undeclared.stdout}\n${undeclared.stderr}`, /undeclared file/i);
    await rm(resolve(fixture, '.edge-cage', 'unexpected.json'));

    await writeFile(resolve(fixture, 'dist', 'src', 'cli.js'), 'tampered\n');
    const tampered = spawnSync('powershell.exe', ['-NoLogo', '-NoProfile', '-NonInteractive', '-Command', verify], {
      encoding: 'utf8',
      windowsHide: true
    });
    assert.notEqual(tampered.status, 0);
    assert.match(`${tampered.stdout}\n${tampered.stderr}`, /(?:byte count|SHA-256) mismatch/i);
  } finally {
    await rm(fixture, { recursive: true, force: true });
  }
});
