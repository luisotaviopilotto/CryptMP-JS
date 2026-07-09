'use strict';
/**
 * Cryptmp — password hashing with a temporal pepper (Node.js, zero deps).
 *
 * Interoperable with the Go and Python implementations: a hash produced by any
 * one verifies in the others given the same global key. All primitives are the
 * standard SHA-3 family via node:crypto (requires OpenSSL 1.1.1+, Node 16+):
 *
 *   - SHA3-256        fixed 256-bit digests
 *   - HMAC-SHA3-256   temporal pepper + blinding
 *   - SHAKE256 (XOF)  memory-hard KDF row/seed expansion
 *
 * WARNING: educational/research construction, not independently audited. Prefer
 * argon2/scrypt for production unless reviewed by a cryptographer.
 */
const crypto = require('crypto');

// ---- Parameters ----------------------------------------------------------
const VERSION = 1;
const TIME_WINDOW = 30;
const MEMORY_COL = 1024;
const MIN_COST = 4;
const MAX_COST = 31;
const DEFAULT_COST = 12;
const DEFAULT_SALT_SIZE = 16;
const HASH_OUTPUT = 32;
const KEY_SIZE = 32;

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

function computeHash(key, keyId, salt, cost, t, password) {
  const b = normalizePassword(password);
  const pepper = derivePepper(key, t, salt, cost);
  const blinded = blindPassword(b, pepper, salt);
  const digest = memoryHardKDF(blinded, salt, cost);
  return { encoded: encode(VERSION, cost, keyId, salt, digest, t), digest };
}

// ---- Encoding ------------------------------------------------------------
function encode(version, cost, keyId, salt, digest, t) {
  return `$th$${version}$${cost}$${keyId}$${salt.toString('hex')}$${digest.toString('hex')}$${t.toString()}`;
}

const DIGITS_RE = /^[0-9]+$/;
const MAX_T = 2n ** 64n - 1n;

// Strict ASCII decimal only: Number()/BigInt() would also accept "0x10",
// "1e2" and surrounding whitespace, which Go/Python reject.
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
  const version = parseUint(parts[2], 1, 255);
  const cost = parseUint(parts[3], MIN_COST, MAX_COST);
  const keyId = parseUint(parts[4], 0, 0xffffffff);
  const salt = Buffer.from(parts[5], 'hex');
  const digest = Buffer.from(parts[6], 'hex');
  if (!DIGITS_RE.test(parts[7])) throw new Error('cryptmp: malformed hash string');
  const t = BigInt(parts[7]);
  if (t > MAX_T) throw new Error('cryptmp: malformed hash string');
  // salt hex must round-trip and be 16..32 bytes
  if (salt.length < 16 || salt.length > 32 || salt.toString('hex') !== parts[5].toLowerCase())
    throw new Error('cryptmp: malformed hash string');
  if (digest.length !== HASH_OUTPUT || digest.toString('hex') !== parts[6].toLowerCase())
    throw new Error('cryptmp: malformed hash string');
  return { version, cost, keyId, salt, digest, t };
}

// ---- Keys ----------------------------------------------------------------
class Key {
  constructor(id, bytes) {
    if (!Buffer.isBuffer(bytes) || bytes.length !== KEY_SIZE)
      throw new Error('cryptmp: global key must be exactly 32 bytes');
    this.id = id;
    this.bytes = bytes;
  }
  static generate(id) {
    return new Key(id, crypto.randomBytes(32));
  }
  static fromHex(id, hex) {
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
    for (const k of legacy) {
      if (this._keys.has(k.id)) throw new Error(`duplicate key id ${k.id}`);
      this._keys.set(k.id, k);
    }
  }
  active() {
    return this._keys.get(this._active);
  }
  byId(id) {
    return this._keys.get(id);
  }
  add(k) {
    this._keys.set(k.id, k);
  }
  setActive(id) {
    if (!this._keys.has(id)) throw new Error('cryptmp: unknown key id');
    this._active = id;
  }
}

// ---- Hasher --------------------------------------------------------------
class Cryptmp {
  /**
   * @param {Keyring} keyring
   * @param {{cost?:number, saltSize?:number, timeWindow?:number,
   *          tolerance?:number, now?:() => number}} [opts]
   */
  constructor(keyring, opts = {}) {
    this.keyring = keyring;
    this.cost = opts.cost ?? DEFAULT_COST;
    this.saltSize = opts.saltSize ?? DEFAULT_SALT_SIZE;
    this.timeWindow = opts.timeWindow ?? TIME_WINDOW;
    this.tolerance = opts.tolerance ?? 1;
    this.now = opts.now ?? (() => Date.now() / 1000);
    if (this.cost < MIN_COST || this.cost > MAX_COST)
      throw new Error('cryptmp: cost out of range [4,31]');
    if (this.saltSize < 16 || this.saltSize > 32)
      throw new Error('cryptmp: salt size must be 16..32');
  }

  hash(password) {
    const salt = crypto.randomBytes(this.saltSize);
    const t = BigInt(Math.floor(Math.floor(this.now()) / this.timeWindow));
    const key = this.keyring.active();
    return computeHash(key.bytes, key.id, salt, this.cost, t, password).encoded;
  }

  verify(password, encoded) {
    const p = parse(encoded);
    const key = this.keyring.byId(p.keyId);
    if (!key) throw new Error('cryptmp: unknown key id in hash');
    const b = normalizePassword(password);
    let match = 0;
    const tol = BigInt(this.tolerance);
    for (let d = -tol; d <= tol; d++) {
      const tw = p.t + d;
      if (tw < 0n || tw > MAX_T) continue;
      const pepper = derivePepper(key.bytes, tw, p.salt, p.cost);
      const blinded = blindPassword(b, pepper, p.salt);
      const cand = memoryHardKDF(blinded, p.salt, p.cost);
      // constant-time; accumulate without early return
      if (cand.length === p.digest.length && crypto.timingSafeEqual(cand, p.digest)) {
        match |= 1;
      }
    }
    return match === 1;
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
  VERSION, MIN_COST, MAX_COST, DEFAULT_COST, TIME_WINDOW,
  Key, Keyring, Cryptmp,
  // low-level (for tests / advanced use)
  normalizePassword, derivePepper, blindPassword, memoryHardKDF,
  computeHash, encode, parse,
};
