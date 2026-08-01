import { describe, it, expect } from 'vitest';
import { sha256 } from '@noble/hashes/sha2';
import { encodeQR } from '../src/qr';

// The QR encoder in src/qr.ts is hand-written, and the two ways it can go wrong
// (data-module zigzag stepping, format-info placement) both produce a symbol
// that LOOKS like a QR code and is silently undecodable. Rendering it and
// eyeballing it proves nothing. So this suite pins the encoder two ways:
//
//   1. Known-answer: the module bitmap for fixed inputs is hashed and compared
//      to a digest captured from an independent, widely used implementation
//      (the `qrcode` npm package, byte mode, ECC level L, its own mask choice).
//      A single wrong module anywhere changes the digest.
//   2. Round-trip: a decoder written to the ISO/IEC 18004 reading rules — read
//      the format info, undo the mask, walk the zigzag, parse mode + length —
//      recovers the original string from the matrix.

function matrixDigest(text: string): { size: number; sha256: string } {
  const m = encodeQR(text);
  let bits = '';
  for (let r = 0; r < m.size; r++) {
    for (let c = 0; c < m.size; c++) bits += m.dark[r][c] ? '1' : '0';
  }
  const digest = sha256(new TextEncoder().encode(bits));
  return {
    size: m.size,
    sha256: Array.from(digest)
      .map((b) => b.toString(16).padStart(2, '0'))
      .join(''),
  };
}

describe('QR encoder matches an independent implementation (known answers)', () => {
  it('encodes the textbook P2PKH address identically to the reference encoder', () => {
    expect(matrixDigest('1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH')).toEqual({
      size: 29,
      sha256: 'b248e667880fbf5e3cb88ea0ad98cb5c694f7dec8443c0567c2476080123f354',
    });
  });

  it('encodes the BIP-173 P2WPKH address identically to the reference encoder', () => {
    expect(matrixDigest('bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4')).toEqual({
      size: 29,
      sha256: '3e4a2bafac096a4933ae4dd44757ea08bc3b7bf7e2cb87905d5ec240f3fd96a6',
    });
  });

  it('encodes a short version-1 payload identically to the reference encoder', () => {
    expect(matrixDigest('HELLO')).toEqual({
      size: 21,
      sha256: '7a381bcb34d02f3af6f20bb290409ced08ec7fb6849d56a1d721cf0f6127b363',
    });
  });
});

// ---------------------------------------------------------------------------
// A minimal spec-side decoder: enough of ISO/IEC 18004 to read back a
// single-block, byte-mode, level-L symbol. It does no error correction — it
// reads the data codewords straight out of the matrix, which is exactly the
// property we want to assert (the bits landed where a scanner looks for them).
// ---------------------------------------------------------------------------

const ALIGN: Record<number, number[]> = { 1: [], 2: [6, 18], 3: [6, 22], 4: [6, 26], 5: [6, 30] };

/** Rebuild the function-pattern mask (which modules a decoder must skip). */
function functionModules(size: number): boolean[][] {
  const fn: boolean[][] = Array.from({ length: size }, () => new Array(size).fill(false));
  const block = (r0: number, c0: number, h: number, w: number): void => {
    for (let r = r0; r < r0 + h; r++) {
      for (let c = c0; c < c0 + w; c++) {
        if (r >= 0 && c >= 0 && r < size && c < size) fn[r][c] = true;
      }
    }
  };
  // finders + separators
  block(0, 0, 8, 8);
  block(0, size - 8, 8, 8);
  block(size - 8, 0, 8, 8);
  // timing
  for (let i = 0; i < size; i++) {
    fn[6][i] = true;
    fn[i][6] = true;
  }
  // alignment
  const version = (size - 17) / 4;
  const centres = ALIGN[version] ?? [];
  for (const r of centres) {
    for (const c of centres) {
      if ((r === 6 && c === 6) || (r === 6 && c === size - 7) || (r === size - 7 && c === 6)) continue;
      block(r - 2, c - 2, 5, 5);
    }
  }
  // format info strips
  for (let i = 0; i <= 8; i++) {
    fn[i][8] = true;
    fn[8][i] = true;
  }
  for (let i = size - 8; i < size; i++) {
    fn[8][i] = true;
    fn[i][8] = true;
  }
  return fn;
}

function maskFn(n: number, r: number, c: number): boolean {
  switch (n) {
    case 0: return (r + c) % 2 === 0;
    case 1: return r % 2 === 0;
    case 2: return c % 3 === 0;
    case 3: return (r + c) % 3 === 0;
    case 4: return (Math.floor(r / 2) + Math.floor(c / 3)) % 2 === 0;
    case 5: return ((r * c) % 2) + ((r * c) % 3) === 0;
    case 6: return (((r * c) % 2) + ((r * c) % 3)) % 2 === 0;
    default: return (((r + c) % 2) + ((r * c) % 3)) % 2 === 0;
  }
}

/** Read the SECOND copy of the format info — the half this repo once placed
 *  backwards — and return { eccLevel, mask }. */
function readFormatInfo(dark: boolean[][], size: number): { ecc: number; mask: number } {
  let raw = 0;
  for (let i = 0; i < 8; i++) if (dark[8][size - 1 - i]) raw |= 1 << i;
  for (let i = 8; i < 15; i++) if (dark[size - 15 + i][8]) raw |= 1 << i;
  const bits = raw ^ 0x5412;
  // The 5 data bits are the top 5 of the 15-bit BCH codeword.
  const data = (bits >> 10) & 0x1f;
  return { ecc: (data >> 3) & 0x3, mask: data & 0x7 };
}

function decodeQR(matrix: { size: number; dark: boolean[][] }): string {
  const { size, dark } = matrix;
  const { ecc, mask } = readFormatInfo(dark, size);
  if (ecc !== 0b01) throw new Error(`expected ECC level L (01), read ${ecc.toString(2)}`);
  const fn = functionModules(size);
  // Undo the mask, then walk the zigzag exactly as a scanner does.
  const bits: number[] = [];
  let upward = true;
  for (let right = size - 1; right >= 1; right -= 2) {
    if (right === 6) right = 5;
    for (let vert = 0; vert < size; vert++) {
      const r = upward ? size - 1 - vert : vert;
      for (let dc = 0; dc < 2; dc++) {
        const c = right - dc;
        if (fn[r][c]) continue;
        const bit = dark[r][c] !== maskFn(mask, r, c);
        bits.push(bit ? 1 : 0);
      }
    }
    upward = !upward;
  }
  let p = 0;
  const take = (n: number): number => {
    let v = 0;
    for (let i = 0; i < n; i++) v = (v << 1) | bits[p++];
    return v;
  };
  const mode = take(4);
  if (mode !== 0b0100) throw new Error(`expected byte mode, read ${mode.toString(2)}`);
  const len = take(8); // versions 1-9 use an 8-bit character count
  const out = new Uint8Array(len);
  for (let i = 0; i < len; i++) out[i] = take(8);
  return new TextDecoder().decode(out);
}

describe('QR round-trip: a spec-side reader recovers the payload', () => {
  const cases = [
    '1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH',
    'bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4',
    'KwDiBf89QgGbjEhKnhXJuH7LrciVrZi3qYjgd9M7rFU73sVHnoWn',
    '1111111111111111111114oLvT2',
    'HELLO',
    'a',
  ];
  for (const text of cases) {
    it(`decodes ${text.slice(0, 16)}…`, () => {
      expect(decodeQR(encodeQR(text))).toBe(text);
    });
  }
});
