import { isAbsolute, resolve } from 'node:path';

export function argument(name: string): string | undefined {
  const index = process.argv.indexOf(`--${name}`);
  return index >= 0 ? process.argv[index + 1] : undefined;
}

export function required(name: string): string {
  const value = argument(name);
  if (!value) throw new Error(`Missing --${name}.`);
  return value;
}

export function absoluteArgument(name: string): string {
  const value = required(name);
  if (!isAbsolute(value)) throw new Error(`--${name} must be an absolute path.`);
  return resolve(value);
}

export async function hiddenPrompt(label: string): Promise<string> {
  if (!process.stdin.isTTY || !process.stdout.isTTY || !process.stdin.setRawMode) {
    throw new Error('License secrets require an interactive terminal and are never accepted as command-line arguments.');
  }
  process.stdout.write(label);
  process.stdin.setRawMode(true);
  process.stdin.resume();
  process.stdin.setEncoding('utf8');
  return await new Promise<string>((resolveValue, reject) => {
    let value = '';
    const cleanup = () => {
      process.stdin.off('data', onData);
      process.stdin.setRawMode(false);
      process.stdin.pause();
      process.stdout.write('\n');
    };
    const onData = (chunk: string) => {
      for (const character of chunk) {
        if (character === '\u0003') {
          cleanup();
          reject(new Error('Cancelled.'));
          return;
        }
        if (character === '\r' || character === '\n') {
          cleanup();
          resolveValue(value);
          return;
        }
        if (character === '\u007f' || character === '\b') {
          value = value.slice(0, -1);
        } else if (character >= ' ') {
          value += character;
        }
      }
    };
    process.stdin.on('data', onData);
  });
}
