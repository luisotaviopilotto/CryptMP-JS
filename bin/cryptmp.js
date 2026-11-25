#!/usr/bin/env node
'use strict';
// Cryptmp CLI (Node).
//   cryptmp gen-key
//   cryptmp hash   [--cost N] [--key-id N]   < password
//   cryptmp verify <encoded>                 < password
// Key comes from env CRYPTMP_KEY and password from stdin or a hidden prompt:
// command-line arguments leak into shell history and the process list.
const fs = require('fs');
const readline = require('readline');
const { Writable } = require('stream');
const th = require('../cryptmp');

const USAGE = 'usage: cryptmp <gen-key | hash [--cost N] [--key-id N] | verify <encoded>>\n' +
  '  key: env CRYPTMP_KEY    password: stdin, or typed at the prompt';

function die(msg, code = 2) {
  console.error(msg);
  process.exit(code);
}

function loadKey(id) {
  const val = process.env.CRYPTMP_KEY;
  if (!val) die('error: no key (set CRYPTMP_KEY)');
  return th.Key.fromHex(id, val);
}

function promptHidden() {
  const muted = new Writable({ write: (chunk, enc, done) => done() });
  const rl = readline.createInterface({ input: process.stdin, output: muted, terminal: true });
  process.stderr.write('Password: ');
  return new Promise((resolve, reject) => {
    rl.once('line', (line) => {
      resolve(line);
      rl.close();
    });
    rl.once('SIGINT', () => rl.close());
    rl.once('close', () => {
      process.stderr.write('\n');
      reject(new Error('no password entered'));
    });
  });
}

// Strict decoding: invalid bytes would all become U+FFFD and collide.
function readPiped() {
  try {
    return new TextDecoder('utf-8', { fatal: true })
      .decode(fs.readFileSync(0))
      .replace(/[\r\n]+$/, '');
  } catch (err) {
    if (err.code === 'ERR_ENCODING_INVALID_ENCODED_DATA') die('error: password is not valid UTF-8');
    throw err;
  }
}

async function readPassword() {
  const password = process.stdin.isTTY ? await promptHidden() : readPiped();
  if (!password) die('error: empty password');
  return password;
}

function numberFlag(args, name, fallback) {
  const i = args.indexOf(name);
  if (i === -1) return fallback;
  const [, val] = args.splice(i, 2);
  if (!/^[0-9]+$/.test(val ?? '')) die(`error: ${name} needs a number`);
  return Number(val);
}

async function main() {
  const [, , cmd, ...rest] = process.argv;
  if (cmd === 'gen-key') {
    console.log(th.Key.generate(1).hex);
    return;
  }
  if (cmd === 'hash') {
    const cost = numberFlag(rest, '--cost', th.DEFAULT_COST);
    const key = loadKey(numberFlag(rest, '--key-id', 1));
    if (rest.length) die(USAGE);
    const hasher = new th.Cryptmp(new th.Keyring(key), { cost });
    console.log(hasher.hash(await readPassword()));
    return;
  }
  if (cmd === 'verify') {
    const [encoded, ...extra] = rest;
    if (!encoded || extra.length) die(USAGE);
    // CRYPTMP_KEY is the only key, so take its id from the hash itself.
    const key = loadKey(th.parse(encoded).keyId);
    // The operator chose this hash, so any supported cost is fine here.
    const hasher = new th.Cryptmp(new th.Keyring(key), { maxCost: th.MAX_COST });
    const ok = hasher.verify(await readPassword(), encoded);
    console.log(ok ? 'OK: password matches' : 'FAIL: password does not match');
    process.exit(ok ? 0 : 1);
  }
  die(USAGE);
}

// Exit 1 is reserved for "password does not match"; errors are 2.
main().catch((err) => die(`error: ${err.message}`));
