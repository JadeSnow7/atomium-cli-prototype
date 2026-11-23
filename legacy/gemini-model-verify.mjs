import { lstat, mkdir, mkdtemp, realpath, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { verifyGeminiFixtureContract } from './gemini-model-adapter.mjs';

export async function runGeminiContractAudit() {
  const receipt = await verifyGeminiFixtureContract();
  const root = fileURLToPath(new URL('./runs', import.meta.url));
  await mkdir(root, { recursive: true, mode: 0o700 });
  if (!(await lstat(root)).isDirectory() || await realpath(root) !== root) throw new Error('unsafe-run-root');
  const dir = await mkdtemp(join(root, 'gemini-contract-'));
  const evidence = join(dir, 'evidence.json');
  await writeFile(evidence, JSON.stringify(receipt, null, 2) + '\n', { mode: 0o600, flag: 'wx' });
  for (const result of receipt.checks) console.log((result.pass ? 'PASS ' : 'FAIL ') + result.id);
  console.log('Evidence: ' + evidence);
  return receipt.checks.every(c => c.pass);
}
if (process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1]) {
  if (process.argv.length !== 2) {
    console.error('Usage: node gemini-model-verify.mjs');
    process.exitCode = 2;
  } else process.exitCode = await runGeminiContractAudit() ? 0 : 1;
}
