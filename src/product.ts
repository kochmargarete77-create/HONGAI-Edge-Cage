import { readFile } from 'node:fs/promises';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { z } from 'zod';

const packageSchema = z.object({
  name: z.literal('@hongai/edge-cage'),
  version: z.string().min(1).max(80)
}).passthrough();

export const productName = 'HONG AI Edge Cage' as const;

export function productRoot(): string {
  return resolve(dirname(fileURLToPath(import.meta.url)), '..', '..');
}

export async function productVersion(): Promise<string> {
  const metadata = packageSchema.parse(JSON.parse(
    await readFile(resolve(productRoot(), 'package.json'), 'utf8')
  ) as unknown);
  return metadata.version;
}
