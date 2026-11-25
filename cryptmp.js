'use strict';
/**
 * Cryptmp — password hashing with a temporal pepper (Node.js, zero deps).
 *
 * Version 1 hashes are interoperable with the Go and Python implementations,
 * given the same global key. All primitives are the SHA-3 family and scrypt via
 * node:crypto (requires OpenSSL 1.1.1+, Node 16+):
 *
 *   - SHA3-256        fixed 256-bit digests
 *   - HMAC-SHA3-256   temporal pepper + blinding
 *   - scrypt          memory-hard KDF (version 2 hashes)
 *   - SHAKE256 (XOF)  legacy KDF, only to verify version 1 hashes
 *
 * Version 1 is NOT memory-hard (its output can be computed with a fraction of
 * the memory and work). It is kept only so existing hashes can be verified and
 * rehashed. Go/Python do not read version 2 yet.
 *
 * WARNING: educational/research construction, not independently audited. Prefer
 * argon2/scrypt for production unless reviewed by a cryptographer.
 */
const crypto = require('crypto');

// ---- Parameters ----------------------------------------------------------
const VERSION = 2;
const TIME_WINDOW = 30;
const MEMORY_COL = 1024;
// Version 2 cost is log2(scrypt N): memory = 1 KiB * 2^cost (r=8, p=1).
const MIN_COST = 14; // 16 MiB
const MAX_COST = 20; // 1 GiB
const DEFAULT_COST = 17; // 128 MiB
const SCRYPT_R = 8;
// Accepted cost range per stored hash version.
const COST_RANGE = { 1: [4, 31], 2: [MIN_COST, MAX_COST] };
const DEFAULT_SALT_SIZE = 16;
const HASH_OUTPUT = 32;
const KEY_SIZE = 32;
const MAX_PASSWORD_LENGTH = 4096; // UTF-16 code units

// ---- Primitives ----------------------------------------------------------
const sha3_256 = (buf) => crypto.createHash('sha3-256').update(buf).digest();
const hmacSha3_256 = (key, msg) =>
  crypto.createHmac('sha3-256', key).update(msg).digest();
const shake256 = (data, n) =>
  crypto.createHash('shake256', { outputLength: n }).update(data).digest();

function u16(x) {
  const b = Buffer.alloc(2);
  b.writeUInt16BE(x);
  return b;
}
function u32(x) {
  const b = Buffer.alloc(4);
  b.writeUInt32BE(x >>> 0);
  return b;
}
function u64(x) {
  const b = Buffer.alloc(8);
  b.writeBigUInt64BE(BigInt(x));
  return b;
}
function xorBuf(a, b) {
  const out = Buffer.allocUnsafe(a.length);
  for (let i = 0; i < a.length; i++) out[i] = a[i] ^ b[i];
  return out;
}

// ---- Core functions ------------------------------------------------------
function normalizePassword(password) {
  // NFC is quadratic on long runs of combining marks: bound the input first.
  if (password.length > MAX_PASSWORD_LENGTH)
    throw new Error('cryptmp: password too long');
  return sha3_256(Buffer.from(password.normalize('NFC'), 'utf8'));
}

function derivePepper(key, t, salt, cost) {
  return hmacSha3_256(key, Buffer.concat([u64(t), salt, u16(cost)]));
}

function blindPassword(b, pepper, salt) {
  return hmacSha3_256(pepper, Buffer.concat([b, salt]));
}

function memoryHardKDF(blinded, salt, cost) {
  const rows = cost * 1024;
  const seed = shake256(Buffer.concat([blinded, salt]), 32);

  const m = new Array(rows);
  m[0] = shake256(Buffer.concat([seed, u32(0)]), MEMORY_COL);
  for (let i = 1; i < rows; i++) {
    m[i] = shake256(Buffer.concat([m[i - 1], u32(i)]), MEMORY_COL);
  }

  for (let rnd = 0; rnd < 3; rnd++) {
    const rb = u32(rnd);
    for (let i = 0; i < rows; i++) {
      const j = m[i].readUInt32BE(0) % rows;
      const mixed = xorBuf(m[i], m[j]);
      m[i] = shake256(Buffer.concat([mixed, rb, u32(i)]), MEMORY_COL);
    }
  }

  const final = Buffer.concat([
    m[rows - 4], m[rows - 3], m[rows - 2], m[rows - 1], salt, u16(cost),
  ]);
  return sha3_256(final);
}

// Lone surrogates all encode to U+FFFD, so distinct passwords would collide.
// Not applied to version 1, where such hashes may already exist.
function checkPassword(password, version) {
  if (version !== 1 && /\p{Surrogate}/u.test(password))
    throw new Error('cryptmp: password is not well-formed Unicode');
}

function prepare(key, salt, cost, t, password, version) {
  checkPassword(password, version);
  const b = normalizePassword(password);
  const pepper = derivePepper(key, t, salt, cost);
  return blindPassword(b, pepper, salt);
}

function scryptOpts(cost) {
  const N = 2 ** cost;
  return { N, r: SCRYPT_R, p: 1, maxmem: 256 * SCRYPT_R * N };
}

function kdf(blinded, salt, cost, version) {
  return version === 1
    ? memoryHardKDF(blinded, salt, cost)
    : crypto.scryptSync(blinded, salt, HASH_OUTPUT, scryptOpts(cost));
}

// Version 2 runs off the event loop. Legacy version 1 is still synchronous.
function kdfAsync(blinded, salt, cost, version) {
  if (version === 1) return Promise.resolve(memoryHardKDF(blinded, salt, cost));
  return new Promise((resolve, reject) => {
    crypto.scrypt(blinded, salt, HASH_OUTPUT, scryptOpts(cost), (err, out) =>
      err ? reject(err) : resolve(out));
  });
}

// Version 1 (weak, legacy) must be asked for explicitly.
function computeHash(key, keyId, salt, cost, t, password, version = VERSION) {
  if (version !== 1 && version !== VERSION)
    throw new Error('cryptmp: unknown hash version');
  checkInt(cost, ...COST_RANGE[version], 'cost');
  const blinded = prepare(key, salt, cost, t, password, version);
  const digest = kdf(blinded, salt, cost, version);
  return { encoded: encode(version, cost, keyId, salt, digest, t), digest };
}

// ---- Encoding ------------------------------------------------------------
function encode(version, cost, keyId, salt, digest, t) {
  return `$th$${version}$${cost}$${keyId}$${salt.toString('hex')}$${digest.toString('hex')}$${t.toString()}`;
}

const DIGITS_RE = /^(0|[1-9][0-9]*)$/;
const MAX_T = 2n ** 64n - 1n;

// Canonical ASCII decimal only, so each hash has a single spelling.
// Number()/BigInt() would also accept "0x10", "1e2" and whitespace.
function parseUint(s, lo, hi) {
  if (!DIGITS_RE.test(s)) throw new Error('cryptmp: malformed hash string');
  const n = Number(s);
  if (!Number.isSafeInteger(n) || n < lo || n > hi)
    throw new Error('cryptmp: malformed hash string');
  return n;
}

function parse(encoded) {
  const parts = encoded.split('$');
  // Leading "$" -> parts[0] === ""
  if (parts.length !== 8 || parts[0] !== '' || parts[1] !== 'th') {
    throw new Error('cryptmp: malformed hash string');
  }
  const version = parseUint(parts[2], 1, VERSION);
  const cost = parseUint(parts[3], ...COST_RANGE[version]);
  const keyId = parseUint(parts[4], 0, 0xffffffff);
  const salt = Buffer.from(parts[5], 'hex');
  const digest = Buffer.from(parts[6], 'hex');
  // 20 digits is the longest uint64; check before the BigInt() conversion.
  if (parts[7].length > 20 || !DIGITS_RE.test(parts[7]))
    throw new Error('cryptmp: malformed hash string');
  const t = BigInt(parts[7]);
  if (t > MAX_T) throw new Error('cryptmp: malformed hash string');
  // salt hex must round-trip (lowercase) and be 16..32 bytes
  if (salt.length < 16 || salt.length > 32 || salt.toString('hex') !== parts[5])
    throw new Error('cryptmp: malformed hash string');
  if (digest.length !== HASH_OUTPUT || digest.toString('hex') !== parts[6])
    throw new Error('cryptmp: malformed hash string');
  return { version, cost, keyId, salt, digest, t };
}

// ---- Keys ----------------------------------------------------------------
function checkInt(value, lo, hi, what) {
  if (!Number.isInteger(value) || value < lo || value > hi)
    throw new Error(`cryptmp: ${what} must be an integer in [${lo},${hi}]`);
}

class Key {
  // Private so console.log() and JSON.stringify() never print the secret.
  #bytes;

  constructor(id, bytes) {
    checkInt(id, 0, 0xffffffff, 'key id');
    if (!Buffer.isBuffer(bytes) || bytes.length !== KEY_SIZE)
      throw new Error('cryptmp: global key must be exactly 32 bytes');
    this.id = id;
    this.#bytes = Buffer.from(bytes);
  }
  get bytes() {
    return this.#bytes;
  }
  static generate(id) {
    return new Key(id, crypto.randomBytes(32));
  }
  static fromHex(id, hex) {
    // Buffer.from() silently stops at the first non-hex character.
    if (!/^[0-9a-fA-F]{64}$/.test(hex))
      throw new Error('cryptmp: global key must be exactly 64 hex chars');
    return new Key(id, Buffer.from(hex, 'hex'));
  }
  get hex() {
    return this.bytes.toString('hex');
  }
}

class Keyring {
  constructor(active, ...legacy) {
    this._keys = new Map([[active.id, active]]);
    this._active = active.id;
    for (const k of legacy) this.add(k);
  }
  active() {
    return this._keys.get(this._active);
  }
  byId(id) {
    return this._keys.get(id);
  }
  add(k) {
    if (this._keys.has(k.id)) throw new Error(`cryptmp: duplicate key id ${k.id}`);
    this._keys.set(k.id, k);
  }
  setActive(id) {
    if (!this._keys.has(id)) throw new Error('cryptmp: unknown key id');
    this._active = id;
  }
}

// ---- Hasher --------------------------------------------------------------
const OPTIONS = ['cost', 'saltSize', 'timeWindow', 'now', 'maxCost', 'minVersion'];

class Cryptmp {
  /**
   * @param {Keyring} keyring
   * @param {{cost?:number, saltSize?:number, timeWindow?:number,
   *          now?:() => number, maxCost?:number, minVersion?:number}} [opts]
   * maxCost caps the memory a stored v2 hash may demand from verify();
   * minVersion: 2 rejects legacy v1 hashes once they are all migrated.
   */
  constructor(keyring, opts = {}) {
    // A misspelled option would otherwise leave its protection silently off.
    for (const name of Object.keys(opts)) {
      if (!OPTIONS.includes(name)) throw new Error(`cryptmp: unknown option ${name}`);
    }
    this.keyring = keyring;
    this.cost = opts.cost ?? DEFAULT_COST;
    this.saltSize = opts.saltSize ?? DEFAULT_SALT_SIZE;
    this.timeWindow = opts.timeWindow ?? TIME_WINDOW;
    this.now = opts.now ?? (() => Date.now() / 1000);
    checkInt(this.cost, MIN_COST, MAX_COST, 'cost');
    checkInt(this.saltSize, 16, 32, 'salt size');
    checkInt(this.timeWindow, 1, Number.MAX_SAFE_INTEGER, 'time window');
    this.maxCost = opts.maxCost ?? Math.max(this.cost, DEFAULT_COST);
    this.minVersion = opts.minVersion ?? 1;
    checkInt(this.maxCost, this.cost, MAX_COST, 'max cost');
    checkInt(this.minVersion, 1, VERSION, 'min version');
  }

  // Async variants are separate methods on purpose: making verify() return a
  // Promise would turn `if (verify(...))` in existing callers into a bypass.
  hash(password) {
    const { key, keyId, cost, salt, t } = this._fresh(password);
    return computeHash(key, keyId, salt, cost, t, password, VERSION).encoded;
  }

  async hashAsync(password) {
    // Everything is captured before the await: settings may change meanwhile.
    const { key, keyId, cost, salt, t } = this._fresh(password);
    const blinded = prepare(key, salt, cost, t, password, VERSION);
    const digest = await kdfAsync(blinded, salt, cost, VERSION);
    return encode(VERSION, cost, keyId, salt, digest, t);
  }

  verify(password, encoded) {
    const { p, blinded } = this._open(password, encoded);
    return crypto.timingSafeEqual(kdf(blinded, p.salt, p.cost, p.version), p.digest);
  }

  async verifyAsync(password, encoded) {
    const { p, blinded } = this._open(password, encoded);
    return crypto.timingSafeEqual(await kdfAsync(blinded, p.salt, p.cost, p.version), p.digest);
  }

  _fresh(password) {
    if (password === '') throw new Error('cryptmp: empty password');
    const active = this.keyring.active();
    return {
      key: active.bytes,
      keyId: active.id,
      cost: this.cost,
      salt: crypto.randomBytes(this.saltSize),
      t: BigInt(Math.floor(Math.floor(this.now()) / this.timeWindow)),
    };
  }

  _open(password, encoded) {
    const p = parse(encoded);
    if (p.version < this.minVersion) throw new Error('cryptmp: hash version disabled');
    if (p.version === VERSION && p.cost > this.maxCost)
      throw new Error('cryptmp: hash cost above maxCost');
    const key = this.keyring.byId(p.keyId);
    if (!key) throw new Error('cryptmp: unknown key id in hash');
    return { p, blinded: prepare(key.bytes, p.salt, p.cost, p.t, password, p.version) };
  }

  needsRehash(encoded) {
    let p;
    try {
      p = parse(encoded);
    } catch {
      return true;
    }
    if (p.version !== VERSION) return true;
    if (p.keyId !== this.keyring.active().id) return true;
    if (p.cost < this.cost) return true;
    return false;
  }
}

module.exports = {
  VERSION, MIN_COST, MAX_COST, DEFAULT_COST, TIME_WINDOW, MAX_PASSWORD_LENGTH,
  Key, Keyring, Cryptmp,
  // low-level (for tests / advanced use)
  normalizePassword, derivePepper, blindPassword, memoryHardKDF,
  computeHash, encode, parse,
};
