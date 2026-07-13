// flow.ts — animated teaching visuals that make the derivation *mechanism*
// visible, not just its output. Two exhibits:
//   1. byteFlowDiagram — carries the real pubkey bytes through SHA-256 →
//      RIPEMD-160 → HASH160, then splits into the Base58Check and Bech32
//      encoders, so a learner SEES both address types commit to one fingerprint.
//   2. bip39Strip — renders 132 bit-cells (128 entropy + 4 checksum) grouped
//      into twelve 11-bit bands, each indexing a word; flip a bit to watch the
//      affected word AND the checksum change.
// All crypto is delegated to engine.ts. No hardcoded outputs.

import { sha256Once, hash160, bytesToHex } from './engine';
import { sha256 } from '@noble/hashes/sha2';

// Minimal DOM helper (kept local so flow.ts has no dependency on ui.ts).
type Attrs = Record<string, string | number | boolean | undefined> & { text?: string };
function e<K extends keyof HTMLElementTagNameMap>(
  tag: K,
  attrs: Attrs = {},
  kids: (Node | string)[] = [],
): HTMLElementTagNameMap[K] {
  const n = document.createElement(tag);
  const { text, ...rest } = attrs;
  for (const [k, v] of Object.entries(rest)) {
    if (v === undefined || v === false) continue;
    if (k === 'class') n.className = String(v);
    else n.setAttribute(k, String(v));
  }
  if (text !== undefined) n.textContent = text;
  for (const c of kids) n.append(c);
  return n;
}

function prefersReducedMotion(): boolean {
  return (
    typeof window !== 'undefined' &&
    typeof window.matchMedia === 'function' &&
    window.matchMedia('(prefers-reduced-motion: reduce)').matches
  );
}

/** A short hex preview: first `n` bytes + ellipsis when longer. */
function hexPreview(b: Uint8Array, n = 6): string {
  const h = bytesToHex(b);
  return b.length > n ? h.slice(0, n * 2) + '…' : h;
}

// =====================================================================
// 1) Byte-flow diagram: pubkey → SHA-256 → RIPEMD-160 → HASH160 → (base58 | bech32)
// =====================================================================
export interface ByteFlow {
  root: HTMLElement;
  /** Re-run the animation for a freshly generated key. */
  run(pubKey: Uint8Array, p2pkh: string, p2wpkh: string): void;
}

export function byteFlowDiagram(): ByteFlow {
  const root = e('div', {
    class: 'byteflow',
    role: 'img',
    'aria-label':
      'Byte-flow diagram: the public key is hashed by SHA-256, then RIPEMD-160, producing the 20-byte HASH160 fingerprint, which is then encoded two ways — Base58Check for a 1-address and Bech32 for a bc1-address.',
  });

  // Build the stage boxes. Each has a title, a role caption, and a live byte
  // readout that fills in as the animation reaches it.
  function stage(id: string, kicker: string, title: string, sub: string): HTMLElement {
    const box = e('div', { class: 'bf-stage', 'data-stage': id, 'aria-hidden': 'true' });
    box.append(
      e('span', { class: 'bf-kicker', text: kicker }),
      e('span', { class: 'bf-title', text: title }),
      e('span', { class: 'bf-sub', text: sub }),
      e('span', { class: 'bf-bytes mono', text: '—', 'data-bytes': id }),
    );
    return box;
  }

  const sIn = stage('in', 'INPUT', 'Public key', '33 bytes (02/03 ‖ x)');
  const sSha = stage('sha', 'HASH', 'SHA-256', '→ 32-byte digest');
  const sRipe = stage('ripe', 'HASH', 'RIPEMD-160', '→ 20-byte digest');
  const sH160 = stage('h160', 'FINGERPRINT', 'HASH160', '20 bytes — both addresses commit to THIS');
  const sB58 = stage('b58', 'ENCODE', 'Base58Check', 'version 0x00 ‖ +4-byte checksum → 1…');
  const sBech = stage('bech', 'ENCODE', 'Bech32', 'witness v0 ‖ polymod checksum → bc1…');

  // Arrows are decorative; the aria-label on root narrates the whole chain.
  const arrow = (cls = '') => e('span', { class: 'bf-arrow ' + cls, 'aria-hidden': 'true', text: '→' });
  const splitArrow = (cls: string) =>
    e('span', { class: 'bf-arrow bf-arrow--split ' + cls, 'aria-hidden': 'true', text: '↳' });

  // Layout: a linear spine (in → sha → ripe → h160) then a split into two encoders.
  const spine = e('div', { class: 'bf-spine' }, [
    sIn,
    arrow('a-in-sha'),
    sSha,
    arrow('a-sha-ripe'),
    sRipe,
    arrow('a-ripe-h160'),
    sH160,
  ]);
  const split = e('div', { class: 'bf-split' }, [
    e('div', { class: 'bf-branch' }, [splitArrow('a-h160-b58'), sB58]),
    e('div', { class: 'bf-branch' }, [splitArrow('a-h160-bech'), sBech]),
  ]);
  const splitLabel = e('div', {
    class: 'bf-splitnote',
    text: 'One 20-byte fingerprint, two encodings — that is why a 1… and a bc1… address are the SAME key.',
  });
  root.append(spine, split, splitLabel);

  function setBytes(id: string, txt: string): void {
    const el = root.querySelector<HTMLElement>(`[data-bytes="${id}"]`);
    if (el) el.textContent = txt;
  }
  function lit(id: string, on: boolean): void {
    const el = root.querySelector<HTMLElement>(`[data-stage="${id}"]`);
    if (el) el.classList.toggle('bf-stage--lit', on);
  }
  function flowArrow(cls: string, on: boolean): void {
    const el = root.querySelector<HTMLElement>('.' + cls);
    if (el) el.classList.toggle('bf-arrow--flow', on);
  }

  let timers: number[] = [];
  function clearTimers(): void {
    timers.forEach((t) => clearTimeout(t));
    timers = [];
  }

  function run(pubKey: Uint8Array, p2pkh: string, p2wpkh: string): void {
    clearTimers();
    const shaDigest = sha256Once(pubKey);
    const h160 = hash160(pubKey); // == RIPEMD-160(shaDigest)

    // Reset
    ['in', 'sha', 'ripe', 'h160', 'b58', 'bech'].forEach((id) => {
      lit(id, false);
      setBytes(id, '—');
    });
    ['a-in-sha', 'a-sha-ripe', 'a-ripe-h160', 'a-h160-b58', 'a-h160-bech'].forEach((a) =>
      flowArrow(a, false),
    );

    const steps: { at: number; fn: () => void }[] = [
      { at: 0, fn: () => { lit('in', true); setBytes('in', hexPreview(pubKey)); } },
      { at: 1, fn: () => flowArrow('a-in-sha', true) },
      { at: 2, fn: () => { lit('sha', true); setBytes('sha', hexPreview(shaDigest)); } },
      { at: 3, fn: () => flowArrow('a-sha-ripe', true) },
      { at: 4, fn: () => { lit('ripe', true); setBytes('ripe', hexPreview(h160)); } },
      { at: 5, fn: () => flowArrow('a-ripe-h160', true) },
      { at: 6, fn: () => { lit('h160', true); setBytes('h160', bytesToHex(h160)); } },
      { at: 7, fn: () => { flowArrow('a-h160-b58', true); flowArrow('a-h160-bech', true); } },
      {
        at: 8,
        fn: () => {
          lit('b58', true);
          setBytes('b58', p2pkh);
          lit('bech', true);
          setBytes('bech', p2wpkh);
        },
      },
    ];

    if (prefersReducedMotion()) {
      // No motion: reveal every stage at once.
      steps.forEach((s) => s.fn());
      return;
    }
    const GAP = 380; // ms between beats
    steps.forEach((s) => {
      timers.push(window.setTimeout(s.fn, s.at * GAP));
    });
  }

  return { root, run };
}

// =====================================================================
// 2) BIP-39 bit-strip: 132 cells → twelve 11-bit bands → words + checksum
// =====================================================================
export interface Bip39Strip {
  root: HTMLElement;
  /** Render for a fresh 16-byte entropy. */
  render(entropy: Uint8Array): void;
  /** Current mnemonic (may be checksum-broken after a bit flip). */
  getWords(): string[];
  /** True if the currently displayed strip has a valid checksum. */
  isValid(): boolean;
  /** One-click "mangle": flip an entropy bit in the last band so the last word
   *  changes and the checksum breaks. Returns the new last word. */
  mangleLast(): string;
}

// Band palette — 12 hues cycled so adjacent bands are visually distinct.
// These are for the ENTROPY bands; the checksum band gets its own class.
const BAND_CLASSES = [
  'bf-band-0', 'bf-band-1', 'bf-band-2', 'bf-band-3', 'bf-band-4', 'bf-band-5',
];

export function bip39Strip(wordlist: string[]): Bip39Strip {
  const root = e('div', { class: 'bip39strip' });

  const help = e('p', {
    class: 'bip39strip-help',
    text:
      "128 entropy bits + a 4-bit checksum = 132 bits, sliced into twelve 11-bit groups. Each group's value (0–2047) indexes the wordlist. Click any entropy bit to flip it and watch its word — and the checksum band — change.",
  });

  // The bit grid: 132 cells, grouped into 12 bands of 11.
  const grid = e('div', { class: 'bip39-bits', role: 'group', 'aria-label': 'Entropy and checksum bits' });
  // The word row: 12 word chips, each tied to its band.
  const wordsRow = e('div', { class: 'bip39-words' });
  // Checksum status line.
  const status = e('p', { class: 'bip39-checkline', 'aria-live': 'polite' });

  root.append(help, grid, wordsRow, status);

  // Mutable state: the 132-bit string (entropy 0..127, checksum 128..131).
  let bits: number[] = []; // length 132, each 0/1
  let entropyLen = 128;

  function computeChecksumBits(entropyBits: number[]): number[] {
    const bytes = new Uint8Array(entropyBits.length / 8);
    for (let i = 0; i < bytes.length; i++) {
      let v = 0;
      for (let j = 0; j < 8; j++) v = (v << 1) | entropyBits[i * 8 + j];
      bytes[i] = v;
    }
    const cs = sha256(bytes);
    const csLen = entropyBits.length / 32;
    const out: number[] = [];
    for (let i = 0; i < csLen; i++) {
      out.push((cs[Math.floor(i / 8)] >> (7 - (i % 8))) & 1);
    }
    return out;
  }

  function bandValue(bandIdx: number): number {
    let v = 0;
    for (let i = 0; i < 11; i++) v = (v << 1) | bits[bandIdx * 11 + i];
    return v;
  }

  function currentChecksumValid(): boolean {
    const expected = computeChecksumBits(bits.slice(0, entropyLen));
    for (let i = 0; i < expected.length; i++) {
      if (bits[entropyLen + i] !== expected[i]) return false;
    }
    return true;
  }

  function paintWords(): void {
    wordsRow.replaceChildren();
    const nBands = bits.length / 11;
    for (let b = 0; b < nBands; b++) {
      const isChecksumBand = (b + 1) * 11 > entropyLen; // last band straddles checksum
      const val = bandValue(b);
      const chip = e('div', {
        class: 'bip39-word ' + (isChecksumBand ? 'bip39-word--cs' : BAND_CLASSES[b % BAND_CLASSES.length]),
        'data-band': String(b),
      });
      chip.append(
        e('span', { class: 'bip39-word-num mono', text: String(b + 1).padStart(2, '0') }),
        e('span', { class: 'bip39-word-idx mono', text: String(val) }),
        e('span', { class: 'bip39-word-text', text: wordlist[val] ?? '?' }),
      );
      wordsRow.append(chip);
    }
  }

  function paintChecksumBadge(): void {
    const valid = currentChecksumValid();
    status.className = 'bip39-checkline';
    const badge = e('span', {
      class: 'scenario-status ' + (valid ? 'scenario-status--valid' : 'scenario-status--invalid'),
      text: valid ? '✓ checksum valid' : '✗ checksum broken',
    });
    status.replaceChildren();
    const csVal = bandValue(bits.length / 11 - 1);
    status.append(
      badge,
      e('span', {
        class: 'bip39-checknote',
        text: valid
          ? ' — the last word encodes the SHA-256 checksum of the entropy, so this phrase would be accepted.'
          : ' — a flipped bit changed the entropy without fixing the checksum band, so a wallet rejects this phrase (last band value ' + csVal + ').',
      }),
    );
  }

  function highlightBand(bandIdx: number, on: boolean): void {
    grid.querySelectorAll<HTMLElement>(`[data-band="${bandIdx}"]`).forEach((cell) =>
      cell.classList.toggle('bip39-bit--pulse', on),
    );
    const chip = wordsRow.querySelector<HTMLElement>(`.bip39-word[data-band="${bandIdx}"]`);
    if (chip) chip.classList.toggle('bip39-word--pulse', on);
  }

  function flipBit(idx: number): void {
    if (idx >= entropyLen) return; // only entropy bits are user-flippable
    bits[idx] = bits[idx] ? 0 : 1;
    const cell = grid.querySelector<HTMLElement>(`[data-bit="${idx}"]`);
    if (cell) {
      cell.textContent = String(bits[idx]);
      cell.setAttribute('aria-pressed', bits[idx] ? 'true' : 'false');
      cell.classList.toggle('bip39-bit--one', bits[idx] === 1);
    }
    const band = Math.floor(idx / 11);
    // Repaint affected word + checksum band, and pulse them.
    paintWords();
    paintChecksumBadge();
    highlightBand(band, true);
    const lastBand = bits.length / 11 - 1;
    highlightBand(lastBand, true);
    window.setTimeout(() => {
      highlightBand(band, false);
      highlightBand(lastBand, false);
    }, 700);
  }

  function paintGrid(): void {
    grid.replaceChildren();
    const nBands = bits.length / 11;
    for (let b = 0; b < nBands; b++) {
      const bandWrap = e('div', {
        class: 'bip39-band ' + BAND_CLASSES[b % BAND_CLASSES.length],
        'data-band-wrap': String(b),
      });
      for (let i = 0; i < 11; i++) {
        const idx = b * 11 + i;
        const isCs = idx >= entropyLen;
        const cell = e(
          isCs ? 'span' : 'button',
          {
            class:
              'bip39-bit' +
              (bits[idx] === 1 ? ' bip39-bit--one' : '') +
              (isCs ? ' bip39-bit--cs' : ''),
            'data-bit': String(idx),
            'data-band': String(b),
            text: String(bits[idx]),
            ...(isCs
              ? { 'aria-hidden': 'true', title: 'checksum bit (derived, not editable)' }
              : {
                  type: 'button',
                  'aria-pressed': bits[idx] ? 'true' : 'false',
                  'aria-label': `Entropy bit ${idx + 1} of 128, value ${bits[idx]}. Activate to flip.`,
                  title: `entropy bit ${idx + 1} — click to flip`,
                }),
          },
        );
        if (!isCs) cell.addEventListener('click', () => flipBit(idx));
        bandWrap.append(cell);
      }
      grid.append(bandWrap);
    }
  }

  function render(entropy: Uint8Array): void {
    entropyLen = entropy.length * 8;
    const eBits: number[] = [];
    for (const byte of entropy) for (let j = 7; j >= 0; j--) eBits.push((byte >> j) & 1);
    const csBits = computeChecksumBits(eBits);
    bits = eBits.concat(csBits);
    paintGrid();
    paintWords();
    paintChecksumBadge();
  }

  function getWords(): string[] {
    const nBands = bits.length / 11;
    const out: string[] = [];
    for (let b = 0; b < nBands; b++) out.push(wordlist[bandValue(b)] ?? '?');
    return out;
  }

  function mangleLast(): string {
    const nBands = bits.length / 11;
    const lastBand = nBands - 1;
    // Flip the first entropy bit inside the last band (bands straddle the
    // checksum, so its low bits are entropy). This is guaranteed to change the
    // last word's value and, because it perturbs the entropy without fixing
    // the checksum bits, break the checksum.
    let target = lastBand * 11;
    while (target < lastBand * 11 + 11 && target >= entropyLen) target++;
    if (target >= entropyLen) target = entropyLen - 1; // fallback: last entropy bit
    flipBit(target);
    return wordlist[bandValue(lastBand)] ?? '?';
  }

  return { root, render, getWords, isValid: currentChecksumValid, mangleLast };
}
