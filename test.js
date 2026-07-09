'use strict';
// Known-Answer Tests + roundtrip for the Node.js Cryptmp library.
// Run: node test.js   (exit 0 = all pass)
const fs = require('fs');
const path = require('path');
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
  const { encoded, digest } = th.computeHash(key, v.key_id, salt, v.cost, BigInt(v.t), v.password);
  check(`${v.name} hash`, digest.toString('hex'), v.hash_hex);
  check(`${v.name} encoded`, encoded, v.encoded);
}

console.log('Roundtrip (hash/verify):');
const key = th.Key.generate(1);
const hasher = new th.Cryptmp(new th.Keyring(key), { cost: 4 });
const enc = hasher.hash('correct horse battery staple 🔒');
check('verify correct', hasher.verify('correct horse battery staple 🔒', enc), true);
check('verify wrong', hasher.verify('nope', enc), false);

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

console.log();
if (fails) {
  console.log(`${fails} FAILURES`);
  process.exit(1);
}
console.log('ALL PASS');
