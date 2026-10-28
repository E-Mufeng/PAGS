// Reuse only the pinned upstream pure redactor, never its store/context/QMD APIs.
import { redactSecrets } from '../vendor/myagentmemory/core.js';
import { readFileSync } from 'node:fs';
const raw = readFileSync(0);
if (raw.length > 32 * 1024 * 1024) throw new Error('privacy input budget');
const texts = JSON.parse(raw.toString('utf8'));
if (!Array.isArray(texts) || texts.length > 2000 || texts.some(x => typeof x !== 'string')) {
  throw new Error('privacy input shape');
}
process.stdout.write(JSON.stringify(texts.map(x => redactSecrets(x).redacted)));
