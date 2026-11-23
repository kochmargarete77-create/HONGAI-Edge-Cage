import assert from 'node:assert/strict';
import { execFile as execFileCallback } from 'node:child_process';
import { createHash, generateKeyPairSync, randomBytes } from 'node:crypto';
import { mkdir, mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { join, resolve } from 'node:path';
import test from 'node:test';
import { promisify } from 'node:util';

const execFile = promisify(execFileCallback);
const projectRoot = resolve(process.cwd());
const tool = resolve(projectRoot, 'tools', 'ci-artifact-transport.mjs');

async function run(arguments_: string[]): Promise<void> {
  await execFile(process.execPath, [tool, ...arguments_], {
    cwd: projectRoot,
    windowsHide: true,
    maxBuffer: 1024 * 1024
  });
}

async function expectFailure(arguments_: string[], pattern: RegExp): Promise<void> {
  try {
    await run(arguments_);
    assert.fail('transport command unexpectedly succeeded');
  } catch (error) {
    const stderr = (error as { stderr?: string }).stderr ?? String(error);
    assert.match(stderr, pattern);
  }
}

test('CI artifact transport round-trips and rejects tampering without overwriting output', async () => {
  const testBase = resolve(projectRoot, '.test-tmp');
  await mkdir(testBase, { recursive: true });
  const directory = await mkdtemp(join(testBase, 'ci-artifact-transport-'));
  try {
    const { publicKey, privateKey } = generateKeyPairSync('rsa', {
      modulusLength: 3072,
      publicKeyEncoding: { type: 'spki', format: 'pem' },
      privateKeyEncoding: { type: 'pkcs8', format: 'pem' }
    });
    const publicKeyPath = join(directory, 'transport-public.pem');
    const privateKeyPath = join(directory, 'transport-private.pem');
    const archivePath = join(directory, 'hongai-native-pilot.tgz');
    const recordPath = `${archivePath}.build-record.json`;
    const encryptedPath = `${archivePath}.enc`;
    const envelopePath = `${encryptedPath}.envelope.json`;
    const decryptedPath = join(directory, 'decrypted.tgz');
    const plaintext = randomBytes(16 * 1024 + 37);
    const sha256 = createHash('sha256').update(plaintext).digest('hex');
    const record = {
      schemaVersion: 1,
      product: 'HONG AI Edge Cage',
      artifactId: 'test-native-pilot',
      commitSha: '1'.repeat(40),
      archive: {
        filename: 'hongai-native-pilot.tgz',
        sha256,
        bytes: plaintext.length,
        format: 'tar+gzip'
      }
    };
    await Promise.all([
      writeFile(publicKeyPath, publicKey, { mode: 0o644 }),
      writeFile(privateKeyPath, privateKey, { mode: 0o600 }),
      writeFile(archivePath, plaintext, { mode: 0o600 }),
      writeFile(recordPath, `${JSON.stringify(record, null, 2)}\n`, { mode: 0o600 })
    ]);

    await run([
      'encrypt',
      '--input', archivePath,
      '--output', encryptedPath,
      '--envelope', envelopePath,
      '--public-key', publicKeyPath,
      '--build-record', recordPath
    ]);
    await run([
      'decrypt',
      '--input', encryptedPath,
      '--output', decryptedPath,
      '--envelope', envelopePath,
      '--private-key', privateKeyPath,
      '--build-record', recordPath
    ]);
    assert.deepEqual(await readFile(decryptedPath), plaintext);

    const tamperedCiphertext = Buffer.from(await readFile(encryptedPath));
    tamperedCiphertext[Math.floor(tamperedCiphertext.length / 2)]! ^= 0x01;
    const tamperedPath = join(directory, 'tampered.enc');
    await writeFile(tamperedPath, tamperedCiphertext);
    await expectFailure([
      'decrypt',
      '--input', tamperedPath,
      '--output', join(directory, 'tampered-output.tgz'),
      '--envelope', envelopePath,
      '--private-key', privateKeyPath,
      '--build-record', recordPath
    ], /authenticate data|digest does not match|Unsupported state/i);

    const forgedRecordPath = join(directory, 'forged.build-record.json');
    await writeFile(forgedRecordPath, `${JSON.stringify({ ...record, commitSha: '2'.repeat(40) }, null, 2)}\n`);
    await expectFailure([
      'decrypt',
      '--input', encryptedPath,
      '--output', join(directory, 'forged-output.tgz'),
      '--envelope', envelopePath,
      '--private-key', privateKeyPath,
      '--build-record', forgedRecordPath
    ], /build record does not match/i);

    const sentinelPath = join(directory, 'sentinel.tgz');
    await writeFile(sentinelPath, 'do-not-overwrite');
    await expectFailure([
      'decrypt',
      '--input', encryptedPath,
      '--output', sentinelPath,
      '--envelope', envelopePath,
      '--private-key', privateKeyPath,
      '--build-record', recordPath
    ], /decrypted output already exists/i);
    assert.equal(await readFile(sentinelPath, 'utf8'), 'do-not-overwrite');
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});
