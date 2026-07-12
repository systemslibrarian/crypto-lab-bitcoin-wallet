// engine.ts — real Bitcoin wallet mechanics, built on audited @noble libraries.
// Covers: secp256k1 key -> public key -> address (P2PKH Base58Check & P2WPKH
// Bech32), BIP-39 mnemonic -> seed, and BIP-32 HD key derivation.
// Verified against the official BIP-39 / BIP-32 test vectors.
//
// This is mainnet-style derivation for EDUCATION. Do not use generated keys to
// hold real funds — entropy and storage here are for learning only.

import * as secp from '@noble/secp256k1';
import { sha256 } from '@noble/hashes/sha2';
import { ripemd160 } from '@noble/hashes/legacy';
import { hmac } from '@noble/hashes/hmac';
import { pbkdf2 } from '@noble/hashes/pbkdf2';

// ---- helpers ----
export function bytesToHex(b: Uint8Array): string {
    return Array.from(b).map((x) => x.toString(16).padStart(2, '0')).join('');
}
export function hexToBytes(h: string): Uint8Array {
    const out = new Uint8Array(h.length / 2);
    for (let i = 0; i < out.length; i++) out[i] = parseInt(h.slice(i * 2, i * 2 + 2), 16);
    return out;
}
function concat(...a: Uint8Array[]): Uint8Array {
    const n = a.reduce((s, x) => s + x.length, 0);
    const out = new Uint8Array(n);
    let o = 0;
    for (const x of a) {
        out.set(x, o);
        o += x.length;
    }
    return out;
}
export function hash160(b: Uint8Array): Uint8Array {
    return ripemd160(sha256(b));
}
function dsha256(b: Uint8Array): Uint8Array {
    return sha256(sha256(b));
}

// ---- Base58Check ----
const B58 = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';
function base58encode(bytes: Uint8Array): string {
    let zeros = 0;
    while (zeros < bytes.length && bytes[zeros] === 0) zeros++;
    const digits: number[] = [];
    for (let i = zeros; i < bytes.length; i++) {
        let carry = bytes[i];
        for (let j = 0; j < digits.length; j++) {
            carry += digits[j] << 8;
            digits[j] = carry % 58;
            carry = (carry / 58) | 0;
        }
        while (carry > 0) {
            digits.push(carry % 58);
            carry = (carry / 58) | 0;
        }
    }
    let str = '1'.repeat(zeros);
    for (let i = digits.length - 1; i >= 0; i--) str += B58[digits[i]];
    return str;
}
export function base58check(payload: Uint8Array): string {
    const checksum = dsha256(payload).slice(0, 4);
    return base58encode(concat(payload, checksum));
}

// ---- Bech32 (BIP-173) for native segwit P2WPKH ----
const BECH = 'qpzry9x8gf2tvdw0s3jn54khce6mua7l';
function bech32Polymod(values: number[]): number {
    const GEN = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3];
    let chk = 1;
    for (const v of values) {
        const b = chk >> 25;
        chk = ((chk & 0x1ffffff) << 5) ^ v;
        for (let i = 0; i < 5; i++) if ((b >> i) & 1) chk ^= GEN[i];
    }
    return chk;
}
function bech32HrpExpand(hrp: string): number[] {
    const out: number[] = [];
    for (let i = 0; i < hrp.length; i++) out.push(hrp.charCodeAt(i) >> 5);
    out.push(0);
    for (let i = 0; i < hrp.length; i++) out.push(hrp.charCodeAt(i) & 31);
    return out;
}
function bech32Checksum(hrp: string, data: number[]): number[] {
    const values = bech32HrpExpand(hrp).concat(data).concat([0, 0, 0, 0, 0, 0]);
    const mod = bech32Polymod(values) ^ 1;
    const out: number[] = [];
    for (let i = 0; i < 6; i++) out.push((mod >> (5 * (5 - i))) & 31);
    return out;
}
function convertBits(data: Uint8Array, from: number, to: number, pad: boolean): number[] {
    let acc = 0,
        bits = 0;
    const ret: number[] = [];
    const maxv = (1 << to) - 1;
    for (const value of data) {
        acc = (acc << from) | value;
        bits += from;
        while (bits >= to) {
            bits -= to;
            ret.push((acc >> bits) & maxv);
        }
    }
    if (pad && bits > 0) ret.push((acc << (to - bits)) & maxv);
    return ret;
}
export function bech32Address(witnessProgram: Uint8Array, hrp = 'bc', version = 0): string {
    const data = [version].concat(convertBits(witnessProgram, 8, 5, true));
    const checksum = bech32Checksum(hrp, data);
    const combined = data.concat(checksum);
    let out = hrp + '1';
    for (const d of combined) out += BECH[d];
    return out;
}

// ---- key -> address pipeline ----
export interface AddressBundle {
    privKeyHex: string;
    wif: string; // wallet import format (compressed)
    pubKeyHex: string; // compressed public key
    hash160Hex: string;
    p2pkh: string; // 1... Base58Check
    p2wpkh: string; // bc1... Bech32
}

export function privToWif(priv: Uint8Array, compressed = true): string {
    // mainnet WIF: 0x80 || key || (0x01 if compressed)
    const payload = compressed ? concat(new Uint8Array([0x80]), priv, new Uint8Array([0x01])) : concat(new Uint8Array([0x80]), priv);
    return base58check(payload);
}

export function deriveAddress(priv: Uint8Array): AddressBundle {
    const pub = secp.getPublicKey(priv, true); // compressed
    const h160 = hash160(pub);
    // P2PKH: version 0x00 || hash160
    const p2pkh = base58check(concat(new Uint8Array([0x00]), h160));
    // P2WPKH: bech32 of the hash160 witness program, version 0
    const p2wpkh = bech32Address(h160, 'bc', 0);
    return {
        privKeyHex: bytesToHex(priv),
        wif: privToWif(priv, true),
        pubKeyHex: bytesToHex(pub),
        hash160Hex: bytesToHex(h160),
        p2pkh,
        p2wpkh,
    };
}

export function randomPrivateKey(): Uint8Array {
    return secp.utils.randomPrivateKey();
}

// ---- BIP-39 mnemonic -> seed ----
// Full wordlist is large; for the demo the UI can ship the official 2048-word
// list. The engine validates a mnemonic's checksum and derives the seed.
export function mnemonicToSeed(mnemonic: string, passphrase = ''): Uint8Array {
    const mnemonicBytes = new TextEncoder().encode(mnemonic.normalize('NFKD'));
    const salt = new TextEncoder().encode(('mnemonic' + passphrase).normalize('NFKD'));
    // BIP-39: PBKDF2-HMAC-SHA512, 2048 iterations, 64-byte output
    return pbkdf2(sha512Hash, mnemonicBytes, salt, { c: 2048, dkLen: 64 });
}

// import sha512 lazily to keep the import list tidy
import { sha512 } from '@noble/hashes/sha2';
const sha512Hash = sha512;

// entropy -> mnemonic (BIP-39). entropy length must be 16/20/24/28/32 bytes.
export function entropyToMnemonic(entropy: Uint8Array, wordlist: string[]): string {
    const ENT = entropy.length * 8;
    const CS = ENT / 32;
    const checksum = sha256(entropy);
    // build a bit string of entropy + checksum bits
    let bits = '';
    for (const b of entropy) bits += b.toString(2).padStart(8, '0');
    let csBits = '';
    for (const b of checksum) csBits += b.toString(2).padStart(8, '0');
    bits += csBits.slice(0, CS);
    const words: string[] = [];
    for (let i = 0; i < bits.length; i += 11) {
        const idx = parseInt(bits.slice(i, i + 11), 2);
        words.push(wordlist[idx]);
    }
    return words.join(' ');
}

export function validateMnemonic(mnemonic: string, wordlist: string[]): boolean {
    const words = mnemonic.trim().split(/\s+/);
    if (![12, 15, 18, 21, 24].includes(words.length)) return false;
    let bits = '';
    for (const w of words) {
        const idx = wordlist.indexOf(w);
        if (idx < 0) return false;
        bits += idx.toString(2).padStart(11, '0');
    }
    const ENT = (bits.length * 32) / 33;
    const CS = bits.length - ENT;
    const entropyBits = bits.slice(0, ENT);
    const checksumBits = bits.slice(ENT);
    const entropy = new Uint8Array(ENT / 8);
    for (let i = 0; i < entropy.length; i++) entropy[i] = parseInt(entropyBits.slice(i * 8, i * 8 + 8), 2);
    const checksum = sha256(entropy);
    let csBits = '';
    for (const b of checksum) csBits += b.toString(2).padStart(8, '0');
    return csBits.slice(0, CS) === checksumBits;
}

// ---- BIP-32 HD derivation ----
const N = secp.CURVE.n;

export interface HDKey {
    privateKey: Uint8Array;
    chainCode: Uint8Array;
    publicKey: Uint8Array;
    depth: number;
    index: number;
    /** HASH160(parent pubkey)[0:4]; 0 for the master key. */
    parentFingerprint?: number;
}

export function masterKeyFromSeed(seed: Uint8Array): HDKey {
    const I = hmac(sha512Hash, new TextEncoder().encode('Bitcoin seed'), seed);
    const IL = I.slice(0, 32);
    const IR = I.slice(32);
    return { privateKey: IL, chainCode: IR, publicKey: secp.getPublicKey(IL, true), depth: 0, index: 0, parentFingerprint: 0 };
}

// ---- BIP-32 extended key serialization (xprv / xpub, mainnet) ----
// These let the derivation be checked byte-for-byte against the official
// BIP-32 test vectors, which are stated as Base58Check-encoded extended keys.
const XPRV_VERSION = 0x0488ade4;
const XPUB_VERSION = 0x0488b21e;

function ser32u(i: number): Uint8Array {
    return ser32(i >>> 0);
}

/** HASH160(pubkey)[0:4] — the parent fingerprint used in extended keys. */
export function keyFingerprint(publicKey: Uint8Array): number {
    const h = hash160(publicKey);
    return ((h[0] << 24) | (h[1] << 16) | (h[2] << 8) | h[3]) >>> 0;
}

export function serializeXprv(key: HDKey): string {
    const payload = concat(
        ser32u(XPRV_VERSION),
        new Uint8Array([key.depth & 0xff]),
        ser32u(key.parentFingerprint ?? 0),
        ser32u(key.index),
        key.chainCode,
        concat(new Uint8Array([0]), key.privateKey),
    );
    return base58check(payload);
}

export function serializeXpub(key: HDKey): string {
    const payload = concat(
        ser32u(XPUB_VERSION),
        new Uint8Array([key.depth & 0xff]),
        ser32u(key.parentFingerprint ?? 0),
        ser32u(key.index),
        key.chainCode,
        key.publicKey,
    );
    return base58check(payload);
}

const HARDENED = 0x80000000;

function ser32(i: number): Uint8Array {
    const b = new Uint8Array(4);
    b[0] = (i >>> 24) & 0xff;
    b[1] = (i >>> 16) & 0xff;
    b[2] = (i >>> 8) & 0xff;
    b[3] = i & 0xff;
    return b;
}

function beToBig(a: Uint8Array): bigint {
    return BigInt('0x' + bytesToHex(a));
}
function bigToBe32(x: bigint): Uint8Array {
    return hexToBytes(x.toString(16).padStart(64, '0'));
}

export function deriveChild(parent: HDKey, index: number): HDKey {
    const hardened = index >= HARDENED;
    // BIP-32 CKDpriv: on a rare invalid case (parse256(IL) >= n, or the resulting
    // child private key == 0) the spec says the index is invalid and derivation
    // must proceed with the *next* index. We loop rather than recurse so the
    // final `index` we report is the one actually used.
    for (let i = index; ; i++) {
        let data: Uint8Array;
        if (hardened) {
            data = concat(new Uint8Array([0]), parent.privateKey, ser32(i));
        } else {
            data = concat(parent.publicKey, ser32(i));
        }
        const I = hmac(sha512Hash, parent.chainCode, data);
        const IL = I.slice(0, 32);
        const IR = I.slice(32);
        const ilNum = beToBig(IL);
        // Invalid if parse256(IL) >= n → try the next index.
        if (ilNum >= N) continue;
        const childNum = (ilNum + beToBig(parent.privateKey)) % N;
        // Invalid if the child private key is 0 → try the next index.
        if (childNum === 0n) continue;
        const childPriv = bigToBe32(childNum);
        return {
            privateKey: childPriv,
            chainCode: IR,
            publicKey: secp.getPublicKey(childPriv, true),
            depth: parent.depth + 1,
            index: i,
            parentFingerprint: keyFingerprint(parent.publicKey),
        };
    }
}

// derive along a path like "m/44'/0'/0'/0/0"
export function derivePath(seed: Uint8Array, path: string): HDKey {
    let key = masterKeyFromSeed(seed);
    const parts = path.split('/').slice(1); // drop "m"
    for (const p of parts) {
        const hardened = p.endsWith("'") || p.endsWith('h');
        const idx = parseInt(p.replace(/['h]/g, ''), 10) + (hardened ? HARDENED : 0);
        key = deriveChild(key, idx);
    }
    return key;
}

export { secp };
