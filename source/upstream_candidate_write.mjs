// PAGS glue: reuse pinned upstream writing/redaction, never its context or QMD.
import fs from 'node:fs';
import crypto from 'node:crypto';
import path from 'node:path';
import {fileURLToPath, pathToFileURL} from 'node:url';
const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const input = JSON.parse(fs.readFileSync(0, 'utf8'));
const destination = path.resolve(input.directory);
if (!destination.startsWith(root + path.sep)) throw new Error('PAGS staging only');
const upstream = path.join(root, 'vendor/myagentmemory/core.js');
if (crypto.createHash('sha256').update(fs.readFileSync(upstream)).digest('hex') !== '636d664064ddf08764b72d47d94dba84bad6abf50f982932d0c1d2c7b9a9c348') throw new Error('upstream changed');
process.env.AGENT_MEMORY_DIR = destination;
process.env.AGENT_MEMORY_QMD_UPDATE = 'off';
process.env.AGENT_MEMORY_QMD_EMBED = 'off';
const core = await import(pathToFileURL(upstream).href);
const meta = input.metadata;
let redacted = false;
for (const key of ['summary', 'conditions']) {
  const result = core.redactSecrets(meta.proposal[key]);
  meta.proposal[key] = result.content; redacted ||= result.redacted;
}
meta.proposal.evidence = meta.proposal.evidence.map(text => {
  const result = core.redactSecrets(text); redacted ||= result.redacted; return result.content;
});
if (input.redact_only === true) {
  process.stdout.write(JSON.stringify({metadata:meta, redacted, qmd:'off'}));
} else {
const result = await core.memoryWrite({target:'long_term', mode:'overwrite',
  content:'Trust: untrusted\nStatus: candidate\n\n' + JSON.stringify(meta, null, 2),
  sessionId:meta.source_session_id, sourceUri:`codex://${meta.source_session_id}/${meta.source_turn_id}`});
if (result.isError || result.details.qmdUpdateMode !== 'off' || core._getUpdateTimer() || core._getEmbedTimer()) throw new Error('unexpected writer mode');
process.stdout.write(JSON.stringify({metadata:meta, redacted, qmd:'off'}));
}
