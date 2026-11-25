'use strict';
// Known-Answer Tests + roundtrip for the Node.js Cryptmp library.
// Run: node test.js   (exit 0 = all pass)
const fs = require('fs');
const path = require('path');
const util = require('util');
const { spawnSync } = require('child_process');
const th = require('./cryptmp');

const vf = JSON.parse(fs.readFileSync(path.join(__dirname, 'vectors.json'), 'utf8'));
let fails = 0;

function check(name, got, want) {
  if (got === want) {
    console.log(`  PASS ${name}`);
  } else {
    fails++;
    console.log(`  FAIL ${name}\n       got  ${got}\n       want ${want}`);
  }
}

console.log('Primitive vectors:');
const zeroKey = Buffer.alloc(32);
const zeroSalt = Buffer.alloc(16);
const b = th.normalizePassword('password');
check("normalize_password('password')", b.toString('hex'), vf.primitives["normalize_password('password')"]);
const pep0 = th.derivePepper(zeroKey, 0n, zeroSalt, 4);
check('derive_pepper(0,0,0,4)', pep0.toString('hex'), vf.primitives['derive_pepper(0,0,0,4)']);
const pep1 = th.derivePepper(zeroKey, 1n, zeroSalt, 4);
check('derive_pepper(0,1,0,4)', pep1.toString('hex'), vf.primitives['derive_pepper(0,1,0,4)']);
const bl0 = th.blindPassword(b, pep0, zeroSalt);
check('blind_password(b,pep0,0)', bl0.toString('hex'), vf.primitives['blind_password(b,pep0,0)']);

console.log('Known-Answer vectors:');
for (const v of vf.vectors) {
  const key = Buffer.from(v.key_hex, 'hex');
  const salt = Buffer.from(v.salt_hex, 'hex');
  const { encoded, digest } = th.computeHash(key, v.key_id, salt, v.cost, BigInt(v.t), v.password, 1);
  check(`${v.name} hash`, digest.toString('hex'), v.hash_hex);
  check(`${v.name} encoded`, encoded, v.encoded);
}

console.log('Version 2 vectors (scrypt):');
for (const v of vf.vectors_v2) {
  const key = Buffer.from(v.key_hex, 'hex');
  const salt = Buffer.from(v.salt_hex, 'hex');
  const { encoded } = th.computeHash(key, v.key_id, salt, v.cost, BigInt(v.t), v.password, 2);
  check(`${v.name} encoded`, encoded, v.encoded);
}

console.log('Roundtrip (hash/verify):');
const key = th.Key.generate(1);
const kr = new th.Keyring(key);
const hasher = new th.Cryptmp(kr, { cost: th.MIN_COST });
const enc = hasher.hash('correct horse battery staple 🔒');
check('new hashes are v2', enc.split('$')[2], '2');
check('verify correct', hasher.verify('correct horse battery staple 🔒', enc), true);
check('verify wrong', hasher.verify('nope', enc), false);

console.log('Legacy v1 hashes still verify:');
const legacy = new th.Cryptmp(new th.Keyring(new th.Key(0, Buffer.alloc(32))));
check('v1 verify', legacy.verify('password', vf.vectors[0].encoded), true);
check('v1 needsRehash', legacy.needsRehash(vf.vectors[0].encoded), true);

function outcome(f) {
  try {
    return String(f());
  } catch {
    return 'throws';
  }
}
const tamper = (i, v) => {
  const p = enc.split('$');
  p[i] = v;
  return p.join('$');
};

console.log('Tampered hashes:');
const pw = 'correct horse battery staple 🔒';
check('t+1 rejected', outcome(() => hasher.verify(pw, tamper(7, String(BigInt(enc.split('$')[7]) + 1n)))), 'false');
check('unknown version', outcome(() => hasher.verify(pw, tamper(2, '3'))), 'throws');
check('v2 cost above max', outcome(() => hasher.verify(pw, tamper(3, '31'))), 'throws');

console.log('Invalid parameters (must throw):');
for (const [name, opts] of [
  ['cost 14.5', { cost: 14.5 }],
  ['cost NaN', { cost: NaN }],
  ['cost string', { cost: '14' }],
  ['cost below min', { cost: 13 }],
  ['cost above max', { cost: 21 }],
  ['salt size 16.5', { saltSize: 16.5 }],
  ['time window 0', { timeWindow: 0 }],
]) {
  check(name, outcome(() => new th.Cryptmp(kr, opts) && 'accepted'), 'throws');
}
for (const id of [undefined, -1, 1.5, '1', 2 ** 32]) {
  check(`key id ${JSON.stringify(id)}`, outcome(() => th.Key.generate(id) && 'accepted'), 'throws');
}
check('fromHex trailing junk', outcome(() => th.Key.fromHex(1, 'ab'.repeat(32) + 'zz') && 'accepted'), 'throws');
check('lone surrogate (hash)', outcome(() => hasher.hash('a\uD800')), 'throws');
check('lone surrogate (verify)', outcome(() => hasher.verify('a\uD800', enc)), 'throws');
check('keyring.add duplicate id', outcome(() => kr.add(th.Key.generate(1))), 'throws');

async function asyncTests() {
  console.log('Async API:');
  const e = await hasher.hashAsync('pw');
  check('hashAsync + verify', hasher.verify('pw', e), true);
  check('verifyAsync correct', await hasher.verifyAsync('pw', e), true);
  check('verifyAsync wrong', await hasher.verifyAsync('nope', e), false);
  check('verifyAsync v1', await legacy.verifyAsync('password', vf.vectors[0].encoded), true);
}

console.log('Malformed hashes (must throw on verify):');
const salt = '00'.repeat(16);
const dig = '00'.repeat(32);
const bad = [
  ['empty', ''],
  ['no prefix', 'plainpassword'],
  ['truncated', '$th$1$4$1$'],
  ['cost out of range', '$th$1$99$1$0000$00$0'],
  ['signed version', `$th$+1$4$1$${salt}$${dig}$0`],
  ['signed cost', `$th$1$+4$1$${salt}$${dig}$0`],
  ['hex cost', `$th$1$0x04$1$${salt}$${dig}$0`],
  ['float key id', `$th$1$4$1.5$${salt}$${dig}$0`],
  ['non-numeric key id', `$th$1$4$abc$${salt}$${dig}$0`],
  ['key id > uint32', `$th$1$4$4294967296$${salt}$${dig}$0`],
  ['salt hex with space', `$th$1$4$1$${salt.slice(0, 16)} ${salt.slice(0, 16)}$${dig}$0`],
  ['negative t', `$th$1$4$1$${salt}$${dig}$-1`],
  ['hex t', `$th$1$4$1$${salt}$${dig}$0x10`],
  ['t > uint64', `$th$1$4$1$${salt}$${dig}$18446744073709551616`],
];
for (const [name, s] of bad) {
  let threw = 'no error';
  try {
    hasher.verify('pw', s);
  } catch {
    threw = 'throws';
  }
  check(name, threw, 'throws');
  check(`${name} needsRehash`, hasher.needsRehash(s), true);
}

console.log('Password limits:');
const maxLen = th.MAX_PASSWORD_LENGTH;
check('max length accepted', outcome(() => hasher.verify('a'.repeat(maxLen), enc)), 'false');
check('over max length', outcome(() => hasher.verify('a'.repeat(maxLen + 1), enc)), 'throws');
check('over max length (v1)', outcome(() => legacy.verify('a'.repeat(maxLen + 1), vf.vectors[0].encoded)), 'throws');
check('empty password hash', outcome(() => hasher.hash('')), 'throws');

console.log('Key does not leak:');
const secret = new th.Key(9, Buffer.alloc(32, 0xab));
const holder = new th.Cryptmp(new th.Keyring(secret));
check('inspect', util.inspect(holder, { depth: 9, showHidden: true }).includes('ab ab'), false);
check('JSON.stringify', JSON.stringify(secret), '{"id":9}');
const source = Buffer.alloc(32, 1);
const copied = new th.Key(1, source);
source.fill(0);
check('key bytes are copied', copied.hex, '01'.repeat(32));

console.log('Hash policy:');
const parts = () => enc.split('$');
const high = th.computeHash(key.bytes, 1, Buffer.alloc(16), 18, 0n, 'pw', 2).encoded;
check('cost above maxCost', outcome(() => hasher.verify('pw', high)), 'throws');
check('maxCost raised', outcome(() => new th.Cryptmp(kr, { cost: 14, maxCost: 18 }).verify('pw', high)), 'true');
check('maxCost below cost', outcome(() => new th.Cryptmp(kr, { cost: 18, maxCost: 17 }) && 'accepted'), 'throws');
const strict = new th.Cryptmp(new th.Keyring(new th.Key(0, Buffer.alloc(32))), { minVersion: 2 });
check('v1 disabled', outcome(() => strict.verify('password', vf.vectors[0].encoded)), 'throws');

console.log('Non-canonical encodings (must throw):');
for (const [name, i, f] of [
  ['leading zero version', 2, (v) => `0${v}`],
  ['leading zero cost', 3, (v) => `0${v}`],
  ['leading zero key id', 4, (v) => `0${v}`],
  ['uppercase salt', 5, () => 'AB'.repeat(16)],
  ['uppercase digest', 6, () => 'AB'.repeat(32)],
  ['leading zero t', 7, (v) => `0${v}`],
]) {
  check(name, outcome(() => th.parse(tamper(i, f(parts()[i])))), 'throws');
}

console.log('Low-level and options:');
const low = (...args) => th.computeHash(key.bytes, 1, Buffer.alloc(16), ...args).encoded;
check('computeHash defaults to v2', outcome(() => low(14, 0n, 'pw').slice(0, 6)), '$th$2$');
check('computeHash v2 cost 4', outcome(() => low(4, 0n, 'pw')), 'throws');
check('computeHash unknown version', outcome(() => low(14, 0n, 'pw', 3)), 'throws');
for (const opts of [{ minversion: 2 }, { tolerance: 1 }]) {
  const name = `unknown option ${Object.keys(opts)[0]}`;
  check(name, outcome(() => new th.Cryptmp(kr, opts) && 'accepted'), 'throws');
}

console.log('needsRehash:');
check('current hash', hasher.needsRehash(enc), false);
check('lower cost', new th.Cryptmp(kr, { cost: 15 }).needsRehash(enc), true);
// Same cost as the hash, so only the key id can trigger the rehash.
const rotated = new th.Cryptmp(new th.Keyring(th.Key.generate(2), key), { cost: th.MIN_COST });
check('old key', rotated.needsRehash(enc), true);

console.log('Bounds:');
for (const minVersion of [0, 1.5, 3]) {
  check(`minVersion ${minVersion}`, outcome(() => new th.Cryptmp(kr, { minVersion }) && 'accepted'), 'throws');
}
for (const size of [31, 33]) {
  check(`${size}-byte key`, outcome(() => new th.Key(1, Buffer.alloc(size)) && 'accepted'), 'throws');
}
for (const [size, want] of [[15, 'throws'], [16, 'parses'], [32, 'parses'], [33, 'throws']]) {
  check(`${size}-byte salt`, outcome(() => th.parse(tamper(5, '00'.repeat(size))) && 'parses'), want);
}
check('t = 2^64 - 1', outcome(() => th.parse(tamper(7, '18446744073709551615')) && 'parses'), 'parses');
check('t = 2^64', outcome(() => th.parse(tamper(7, '18446744073709551616')) && 'parses'), 'throws');
let reason = 'no error';
try {
  th.computeHash(key.bytes, 1, Buffer.alloc(16), 14, 0n, 'pw', 3);
} catch (err) {
  reason = err.message;
}
check('computeHash version error', reason, 'cryptmp: unknown hash version');

console.log('CLI:');
const cliKey = '11'.repeat(32);
function cli(args, input, { tty = false } = {}) {
  const bin = path.join(__dirname, 'bin', 'cryptmp.js');
  // tty: pretend stdin is a terminal to exercise the hidden prompt.
  const argv = tty
    ? ['-e', `process.stdin.isTTY=true;process.argv.splice(1,0,'cli');require(${JSON.stringify(bin)})`, '--', ...args]
    : [bin, ...args];
  const r = spawnSync(process.execPath, argv, {
    input, encoding: 'utf8', env: { ...process.env, CRYPTMP_KEY: cliKey },
  });
  return { code: r.status, out: r.stdout.trim(), err: r.stderr };
}
const made = cli(['hash', '--cost', '14'], 'senha');
check('hash exit', made.code, 0);
check('verify ok', cli(['verify', made.out], 'senha\r\n').code, 0);
check('verify wrong', cli(['verify', made.out], 'outra').code, 1);
check('BOM ignored', cli(['verify', made.out], '﻿senha').code, 0);
check('invalid UTF-8', cli(['hash', '--cost', '14'], Buffer.from('senh\xe9', 'latin1')).code, 2);
check('empty password', cli(['hash', '--cost', '14'], '').code, 2);
check('--cost without value', cli(['hash', '--cost'], 'x').code, 2);
check('--key-id empty', cli(['hash', '--key-id', '', '--cost', '14'], 'x').code, 2);
check('verify cost 18', cli(['verify', th.computeHash(Buffer.from(cliKey, 'hex'), 1, Buffer.alloc(16), 18, 0n, 'pw', 2).encoded], 'pw').code, 0);
check('empty password on verify', cli(['verify', made.out], '').code, 2);
const secretPw = 'zzsecret';
const secretHash = cli(['hash', '--cost', '14'], secretPw).out;
const typed = cli(['verify', secretHash], `${secretPw}\n`, { tty: true });
check('prompt verify', typed.code, 0);
// Search for the password itself: an echo may not carry the newline.
check('prompt does not echo', (typed.out + typed.err).includes(secretPw), false);

async function concurrencyTest() {
  const x = new th.Cryptmp(kr, { cost: 14 });
  const pending = x.hashAsync('pw');
  x.cost = 15;
  const e = await pending;
  check('cost change during hashAsync', x.verify('pw', e), true);
}

asyncTests().then(concurrencyTest).then(() => {
  console.log();
  if (fails) {
    console.log(`${fails} FAILURES`);
    process.exit(1);
  }
  console.log('ALL PASS');
}).catch((err) => {
  console.error(err);
  process.exit(1);
});
