#!/usr/bin/env node
'use strict';
// Cryptmp CLI (Node).
//   cryptmp gen-key
//   cryptmp hash   [--cost N] [--key HEX | env CRYPTMP_KEY] [password]
//   cryptmp verify [--key HEX | env CRYPTMP_KEY] <encoded> [password]
const th = require('../cryptmp');

function loadKey(hexFlag) {
  const val = hexFlag || process.env.CRYPTMP_KEY || '';
  if (!val) {
    console.error('error: no key (pass --key or set CRYPTMP_KEY)');
    process.exit(1);
  }
  return th.Key.fromHex(1, val);
}

function readPassword(arg) {
  if (arg !== undefined) return arg;
  try {
    const data = require('fs').readFileSync(0, 'utf8');
    return data.replace(/[\r\n]+$/, '');
  } catch {
    return '';
  }
}

function popFlag(args, name) {
  const i = args.indexOf(name);
  if (i === -1) return undefined;
  const val = args[i + 1];
  args.splice(i, 2);
  return val;
}

function main() {
  const [, , cmd, ...rest] = process.argv;
  if (cmd === 'gen-key') {
    console.log(th.Key.generate(1).hex);
    return;
  }
  if (cmd === 'hash') {
    const cost = Number(popFlag(rest, '--cost') ?? th.DEFAULT_COST);
    const key = loadKey(popFlag(rest, '--key'));
    const hasher = new th.Cryptmp(new th.Keyring(key), { cost });
    console.log(hasher.hash(readPassword(rest[0])));
    return;
  }
  if (cmd === 'verify') {
    const key = loadKey(popFlag(rest, '--key'));
    const encoded = rest[0];
    if (!encoded) {
      console.error('usage: cryptmp verify [--key HEX] <encoded> [password]');
      process.exit(1);
    }
    const hasher = new th.Cryptmp(new th.Keyring(key));
    const ok = hasher.verify(readPassword(rest[1]), encoded);
    console.log(ok ? 'OK: password matches' : 'FAIL: password does not match');
    process.exit(ok ? 0 : 1);
  }
  console.error('usage: cryptmp <gen-key|hash|verify> ...');
  process.exit(2);
}

main();
