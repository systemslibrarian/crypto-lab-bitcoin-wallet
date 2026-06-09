// qr.ts — minimal pure-TS QR Code encoder (ISO/IEC 18004).
// Byte mode, error-correction level L, single-block versions 1–5.
// Capacity ≥ 106 bytes — more than enough for any Bitcoin address.
// No runtime dependencies.

// ---- per-version L data ----
// [totalCodewords, dataCodewords, eccCodewords] for ECC level L
const V_L: Record<number, [number, number, number]> = {
  1: [26, 19, 7],
  2: [44, 34, 10],
  3: [70, 55, 15],
  4: [100, 80, 20],
  5: [134, 108, 26],
};
const ALIGN: Record<number, number[]> = {
  1: [],
  2: [6, 18],
  3: [6, 22],
  4: [6, 26],
  5: [6, 30],
};

// ---- GF(256) tables with prim poly 0x11D ----
const GF_EXP = new Uint8Array(512);
const GF_LOG = new Uint8Array(256);
{
  let x = 1;
  for (let i = 0; i < 255; i++) {
    GF_EXP[i] = x;
    GF_LOG[x] = i;
    x <<= 1;
    if (x & 0x100) x ^= 0x11d;
  }
  for (let i = 255; i < 512; i++) GF_EXP[i] = GF_EXP[i - 255];
}
function gfMul(a: number, b: number): number {
  if (a === 0 || b === 0) return 0;
  return GF_EXP[GF_LOG[a] + GF_LOG[b]];
}

// Reed-Solomon generator polynomial of given degree.
function rsGenerator(degree: number): number[] {
  let poly: number[] = [1];
  for (let i = 0; i < degree; i++) {
    const next = new Array(poly.length + 1).fill(0);
    for (let j = 0; j < poly.length; j++) {
      next[j] ^= poly[j];
      next[j + 1] ^= gfMul(poly[j], GF_EXP[i]);
    }
    poly = next;
  }
  return poly;
}

function rsRemainder(data: number[], eccLen: number): number[] {
  const gen = rsGenerator(eccLen);
  const out = new Array(eccLen).fill(0);
  for (const b of data) {
    const factor = b ^ out.shift();
    out.push(0);
    if (factor !== 0) {
      for (let i = 0; i < eccLen; i++) {
        out[i] ^= gfMul(gen[i + 1], factor);
      }
    }
  }
  return out;
}

// ---- bit-stream builder ----
function buildDataBytes(version: number, data: Uint8Array): number[] {
  const [, dataLen] = V_L[version];
  const bits: number[] = [];
  const push = (v: number, n: number): void => {
    for (let i = n - 1; i >= 0; i--) bits.push((v >> i) & 1);
  };
  push(0b0100, 4); // byte mode
  push(data.length, version < 10 ? 8 : 16);
  for (const b of data) push(b, 8);
  const cap = dataLen * 8;
  const termN = Math.min(4, cap - bits.length);
  for (let i = 0; i < termN; i++) bits.push(0);
  while (bits.length % 8 !== 0) bits.push(0);
  const pads = [0xec, 0x11];
  let p = 0;
  while (bits.length < cap) {
    push(pads[p++ % 2], 8);
  }
  const bytes: number[] = [];
  for (let i = 0; i < bits.length; i += 8) {
    let v = 0;
    for (let j = 0; j < 8; j++) v = (v << 1) | bits[i + j];
    bytes.push(v);
  }
  return bytes;
}

function chooseVersion(byteLen: number): number {
  for (let v = 1; v <= 5; v++) {
    const [, dataLen] = V_L[v];
    const overhead = v < 10 ? 2 : 3; // mode (4b) + CCI (8 or 16b) ≈ 2-3 bytes
    if (byteLen <= dataLen - overhead) return v;
  }
  throw new Error('QR: data too long for V1-V5 (max ~106 bytes)');
}

// ---- matrix placement ----
interface QR {
  size: number;
  dark: boolean[][];
  fn: boolean[][]; // is function pattern (don't mask)
}

function newQR(version: number): QR {
  const size = 17 + 4 * version;
  const dark: boolean[][] = Array.from({ length: size }, () => new Array(size).fill(false));
  const fn: boolean[][] = Array.from({ length: size }, () => new Array(size).fill(false));
  return { size, dark, fn };
}

function set(q: QR, r: number, c: number, on: boolean): void {
  q.dark[r][c] = on;
  q.fn[r][c] = true;
}

function placeFinder(q: QR, top: number, left: number): void {
  for (let dr = -1; dr <= 7; dr++) {
    for (let dc = -1; dc <= 7; dc++) {
      const r = top + dr,
        c = left + dc;
      if (r < 0 || c < 0 || r >= q.size || c >= q.size) continue;
      if (dr < 0 || dr > 6 || dc < 0 || dc > 6) {
        set(q, r, c, false); // separator
      } else {
        const outerRing = dr === 0 || dr === 6 || dc === 0 || dc === 6;
        const innerBlock = dr >= 2 && dr <= 4 && dc >= 2 && dc <= 4;
        set(q, r, c, outerRing || innerBlock);
      }
    }
  }
}

function placeAlignment(q: QR, cr: number, cc: number): void {
  for (let dr = -2; dr <= 2; dr++) {
    for (let dc = -2; dc <= 2; dc++) {
      const edge = Math.abs(dr) === 2 || Math.abs(dc) === 2;
      const ctr = dr === 0 && dc === 0;
      set(q, cr + dr, cc + dc, edge || ctr);
    }
  }
}

function placeTiming(q: QR): void {
  for (let i = 0; i < q.size; i++) {
    if (!q.fn[6][i]) set(q, 6, i, i % 2 === 0);
    if (!q.fn[i][6]) set(q, i, 6, i % 2 === 0);
  }
}

function reserveFormatInfo(q: QR): void {
  const s = q.size;
  // top-left strip
  for (let i = 0; i <= 8; i++) {
    if (!q.fn[i][8]) set(q, i, 8, false);
    if (!q.fn[8][i]) set(q, 8, i, false);
  }
  // top-right strip
  for (let i = s - 8; i < s; i++) set(q, 8, i, false);
  // bottom-left strip
  for (let i = s - 7; i < s; i++) set(q, i, 8, false);
  // dark module — always 1 — at (4V+9, 8)
  set(q, s - 8, 8, true);
}

function placeFunctionPatterns(version: number): QR {
  const q = newQR(version);
  placeFinder(q, 0, 0);
  placeFinder(q, 0, q.size - 7);
  placeFinder(q, q.size - 7, 0);
  const aligns = ALIGN[version];
  for (const r of aligns) {
    for (const c of aligns) {
      // skip the three finder corners
      if ((r === 6 && c === 6) || (r === 6 && c === q.size - 7) || (r === q.size - 7 && c === 6))
        continue;
      placeAlignment(q, r, c);
    }
  }
  placeTiming(q);
  reserveFormatInfo(q);
  return q;
}

// ---- data placement (zigzag from bottom-right) ----
function placeData(q: QR, dataBytes: number[]): void {
  const s = q.size;
  // expand bytes to bits
  const bits: number[] = [];
  for (const b of dataBytes) for (let i = 7; i >= 0; i--) bits.push((b >> i) & 1);
  let bitIdx = 0;
  let upward = true;
  for (let col = s - 1; col >= 1; col -= 2) {
    const c0 = col === 6 ? col - 1 : col; // skip timing column 6
    for (let i = 0; i < s; i++) {
      const r = upward ? s - 1 - i : i;
      for (let dc = 0; dc < 2; dc++) {
        const cc = c0 - dc;
        if (q.fn[r][cc]) continue;
        const bit = bitIdx < bits.length ? bits[bitIdx++] : 0;
        q.dark[r][cc] = bit === 1;
      }
    }
    upward = !upward;
    if (col === 7) col--; // jump past column 6 next time
  }
}

// ---- masking ----
function maskFn(n: number, r: number, c: number): boolean {
  switch (n) {
    case 0:
      return (r + c) % 2 === 0;
    case 1:
      return r % 2 === 0;
    case 2:
      return c % 3 === 0;
    case 3:
      return (r + c) % 3 === 0;
    case 4:
      return (Math.floor(r / 2) + Math.floor(c / 3)) % 2 === 0;
    case 5:
      return ((r * c) % 2) + ((r * c) % 3) === 0;
    case 6:
      return (((r * c) % 2) + ((r * c) % 3)) % 2 === 0;
    case 7:
      return (((r + c) % 2) + ((r * c) % 3)) % 2 === 0;
  }
  return false;
}

function applyMask(q: QR, n: number): void {
  for (let r = 0; r < q.size; r++) {
    for (let c = 0; c < q.size; c++) {
      if (q.fn[r][c]) continue;
      if (maskFn(n, r, c)) q.dark[r][c] = !q.dark[r][c];
    }
  }
}

function maskPenalty(q: QR): number {
  let p = 0;
  const s = q.size;
  // N1: runs of 5+ same-colour modules
  for (let r = 0; r < s; r++) {
    let run = 1;
    for (let c = 1; c < s; c++) {
      if (q.dark[r][c] === q.dark[r][c - 1]) {
        run++;
        if (run === 5) p += 3;
        else if (run > 5) p++;
      } else run = 1;
    }
  }
  for (let c = 0; c < s; c++) {
    let run = 1;
    for (let r = 1; r < s; r++) {
      if (q.dark[r][c] === q.dark[r - 1][c]) {
        run++;
        if (run === 5) p += 3;
        else if (run > 5) p++;
      } else run = 1;
    }
  }
  // N2: 2x2 blocks of same colour
  for (let r = 0; r < s - 1; r++) {
    for (let c = 0; c < s - 1; c++) {
      if (
        q.dark[r][c] === q.dark[r][c + 1] &&
        q.dark[r][c] === q.dark[r + 1][c] &&
        q.dark[r][c] === q.dark[r + 1][c + 1]
      )
        p += 3;
    }
  }
  // N3: finder-like patterns (1011101 with 4 light modules adjacent) — abbreviated check
  const patA = [true, false, true, true, true, false, true, false, false, false, false];
  const patB = [false, false, false, false, true, false, true, true, true, false, true];
  for (let r = 0; r < s; r++) {
    for (let c = 0; c <= s - 11; c++) {
      let ok1 = true,
        ok2 = true;
      for (let k = 0; k < 11; k++) {
        if (q.dark[r][c + k] !== patA[k]) ok1 = false;
        if (q.dark[r][c + k] !== patB[k]) ok2 = false;
      }
      if (ok1) p += 40;
      if (ok2) p += 40;
    }
  }
  for (let c = 0; c < s; c++) {
    for (let r = 0; r <= s - 11; r++) {
      let ok1 = true,
        ok2 = true;
      for (let k = 0; k < 11; k++) {
        if (q.dark[r + k][c] !== patA[k]) ok1 = false;
        if (q.dark[r + k][c] !== patB[k]) ok2 = false;
      }
      if (ok1) p += 40;
      if (ok2) p += 40;
    }
  }
  // N4: dark/light proportion
  let dark = 0;
  for (let r = 0; r < s; r++) for (let c = 0; c < s; c++) if (q.dark[r][c]) dark++;
  const ratio = (dark * 100) / (s * s);
  const steps = Math.floor(Math.abs(ratio - 50) / 5);
  p += steps * 10;
  return p;
}

// ---- format info ----
// 15-bit BCH(15,5) encoding for: 2-bit ECC level (01 for L) + 3-bit mask number.
// Generator poly 0x537, XOR mask 0x5412.
function formatInfoBits(maskN: number): number {
  const eccLevel = 0b01; // L
  let data = (eccLevel << 3) | maskN; // 5 bits
  let rem = data;
  for (let i = 0; i < 10; i++) {
    rem = (rem << 1) ^ ((rem >> 9) * 0x537);
  }
  const full = ((data << 10) | rem) ^ 0x5412;
  return full & 0x7fff;
}

function placeFormatInfo(q: QR, bits: number): void {
  const s = q.size;
  // top-left strip — bits 0..5 at column 8, rows 0..5; bit 6 at (7,8); bit 7 at (8,8); bit 8 at (8,7); bits 9..14 at row 8, columns 5..0
  const setBit = (r: number, c: number, bit: number): void => {
    q.dark[r][c] = bit === 1;
  };
  for (let i = 0; i <= 5; i++) setBit(i, 8, (bits >> i) & 1);
  setBit(7, 8, (bits >> 6) & 1);
  setBit(8, 8, (bits >> 7) & 1);
  setBit(8, 7, (bits >> 8) & 1);
  for (let i = 9; i <= 14; i++) setBit(8, 14 - i, (bits >> i) & 1);
  // bottom-left strip + top-right strip
  for (let i = 0; i < 7; i++) setBit(s - 1 - i, 8, (bits >> i) & 1);
  for (let i = 0; i < 8; i++) setBit(8, s - 1 - i, (bits >> (i + 7)) & 1);
  // dark module
  q.dark[s - 8][8] = true;
}

// ---- main encode + render ----
export interface QRMatrix {
  size: number;
  dark: boolean[][];
}

export function encodeQR(text: string): QRMatrix {
  const bytes = new TextEncoder().encode(text);
  const version = chooseVersion(bytes.length);
  const dataBytes = buildDataBytes(version, bytes);
  const ecc = rsRemainder(dataBytes, V_L[version][2]);
  const fullBytes = dataBytes.concat(ecc);

  // pick best mask: try all 8, lowest penalty wins
  let best: QR | null = null;
  let bestPenalty = Infinity;
  let bestMask = 0;
  for (let m = 0; m < 8; m++) {
    const q = placeFunctionPatterns(version);
    placeData(q, fullBytes);
    applyMask(q, m);
    placeFormatInfo(q, formatInfoBits(m));
    const p = maskPenalty(q);
    if (p < bestPenalty) {
      bestPenalty = p;
      best = q;
      bestMask = m;
    }
  }
  if (!best) throw new Error('QR: no mask succeeded');
  // silence unused-var lint while keeping the choice observable for debugging
  void bestMask;
  return { size: best.size, dark: best.dark };
}

// ---- SVG render ----
export interface QRRenderOpts {
  size?: number; // pixel size of the SVG
  quietZone?: number; // modules of quiet zone (default 2)
  darkColor?: string; // CSS color (default currentColor)
  lightColor?: string; // CSS color (default transparent)
  ariaLabel?: string;
}

export function renderQRSVG(matrix: QRMatrix, opts: QRRenderOpts = {}): string {
  const quiet = opts.quietZone ?? 2;
  const dim = matrix.size + 2 * quiet;
  const px = opts.size ?? 200;
  const dark = opts.darkColor ?? 'currentColor';
  const light = opts.lightColor ?? 'transparent';
  const label = opts.ariaLabel ?? 'QR code';
  // Build one path of all dark modules (much smaller than per-rect SVG)
  let path = '';
  for (let r = 0; r < matrix.size; r++) {
    for (let c = 0; c < matrix.size; c++) {
      if (matrix.dark[r][c]) {
        path += `M${c + quiet},${r + quiet}h1v1h-1z`;
      }
    }
  }
  const bg =
    light === 'transparent'
      ? ''
      : `<rect width="${dim}" height="${dim}" fill="${light}"/>`;
  return (
    `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ${dim} ${dim}" ` +
    `width="${px}" height="${px}" role="img" aria-label="${label}" shape-rendering="crispEdges">` +
    bg +
    `<path d="${path}" fill="${dark}"/>` +
    `</svg>`
  );
}
