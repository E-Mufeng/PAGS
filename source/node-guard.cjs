// Lexical runtime probe: block Node networking; record native loads/model access.
// This is process instrumentation, not a claim of OS-level network isolation.
const fs = require('node:fs');
const originalAppend = fs.appendFileSync.bind(fs);
function record(kind, detail) {
  if (process.env.PAGS_GUARD_LOG) originalAppend(process.env.PAGS_GUARD_LOG,
    JSON.stringify({pid: process.pid, kind, detail: String(detail)}) + '\n');
}
function denied(kind) {
  return function(...args) {
    record('network-blocked', kind);
    throw new Error('PAGS lexical probe blocked network: ' + kind);
  };
}
require('node:net').Socket.prototype.connect = denied('net.connect');
require('node:tls').connect = denied('tls.connect');
for (const protocol of ['node:http', 'node:https']) {
  const mod = require(protocol);
  mod.request = denied(protocol + '.request');
  mod.get = denied(protocol + '.get');
}
global.fetch = denied('fetch');
const originalDlopen = process.dlopen;
process.dlopen = function(module, filename, ...rest) {
  record('native-load', filename);
  return originalDlopen.call(this, module, filename, ...rest);
};
for (const name of ['openSync', 'readFileSync', 'open', 'readFile', 'createReadStream']) {
  const original = fs[name];
  fs[name] = function(path, ...args) {
    if (/\.(gguf|safetensors|onnx)$/i.test(String(path))) {
      record('model-access-blocked', path);
      throw new Error('PAGS probe blocked model file access');
    }
    return original.call(this, path, ...args);
  };
}
record('guard-start', process.argv.join(' '));
