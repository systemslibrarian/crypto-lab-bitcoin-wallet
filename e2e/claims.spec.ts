import { createHash } from 'node:crypto';
import { expect, test as base, type Page } from '@playwright/test';

/**
 * Functional claims gate.
 *
 * The a11y spec proves the page is reachable; this proves it is *right*. Every
 * assertion here is tied to something the README tells a learner they can see
 * with their own eyes:
 *
 *   - the official-vector panel showing a green match on every BIP constant,
 *     compared against the values the page itself printed rather than a
 *     hardcoded literal;
 *   - the key → address pipeline, checked with an INDEPENDENT Base58Check and
 *     Bech32 decoder implemented here, so both addresses are proved to commit
 *     to the HASH160 the page displayed;
 *   - the BIP-39 bit strip, whose 132 cells, twelve 11-bit bands and twelve
 *     word indices are checked to sum and index each other, and whose checksum
 *     badge is checked against a SHA-256 recomputed in Node from the bits the
 *     DOM is actually showing;
 *   - every failure path — mangled checksum, malformed derivation path,
 *     non-integer index, wrong word in the drill — asserted to reach the
 *     failure state AND to name its cause;
 *   - the memorize drill's counters, asserted to sum to the whole.
 *
 * Uncaught page exceptions and console errors fail every test (the boot
 * self-test logs console.error on a vector mismatch, so this also gates that).
 */

// ---------------------------------------------------------------------------
// Fixture: any uncaught exception or console error fails the test.
// ---------------------------------------------------------------------------
const test = base.extend<{ pageErrors: string[] }>({
  pageErrors: [
    async ({ page }, use) => {
      const errors: string[] = [];
      page.on('pageerror', (e) => errors.push(`pageerror: ${e.message}`));
      page.on('console', (m) => {
        if (m.type() === 'error') errors.push(`console.error: ${m.text()}`);
      });
      await use(errors);
      expect(errors, 'page reported uncaught errors').toEqual([]);
    },
    { auto: true },
  ],
});

const CANONICAL =
  'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about';

const sha256 = (b: Uint8Array): Uint8Array => new Uint8Array(createHash('sha256').update(b).digest());
const hex = (b: Uint8Array): string => Array.from(b, (x) => x.toString(16).padStart(2, '0')).join('');

// ---------------------------------------------------------------------------
// Independent Base58Check / Bech32 decoders. Deliberately NOT imported from
// src/ — an oracle that shares code with the thing it checks proves nothing.
// ---------------------------------------------------------------------------
const B58 = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';

function base58decode(s: string): Uint8Array {
  let num = 0n;
  for (const ch of s) {
    const v = B58.indexOf(ch);
    if (v < 0) throw new Error(`not base58: ${ch}`);
    num = num * 58n + BigInt(v);
  }
  let h = num.toString(16);
  if (h.length % 2) h = '0' + h;
  const body = num === 0n ? [] : (h.match(/../g) ?? []).map((p) => parseInt(p, 16));
  let zeros = 0;
  while (zeros < s.length && s[zeros] === '1') zeros++;
  return Uint8Array.from([...Array<number>(zeros).fill(0), ...body]);
}

const BECH_CHARSET = 'qpzry9x8gf2tvdw0s3jn54khce6mua7l';

function bechPolymod(values: number[]): number {
  const GEN = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3];
  let chk = 1;
  for (const v of values) {
    const top = chk >> 25;
    chk = ((chk & 0x1ffffff) << 5) ^ v;
    for (let i = 0; i < 5; i++) if ((top >> i) & 1) chk ^= GEN[i];
  }
  return chk;
}

function hrpExpand(hrp: string): number[] {
  const out: number[] = [];
  for (const c of hrp) out.push(c.charCodeAt(0) >> 5);
  out.push(0);
  for (const c of hrp) out.push(c.charCodeAt(0) & 31);
  return out;
}

function convert5to8(data: number[]): number[] {
  let acc = 0;
  let bits = 0;
  const out: number[] = [];
  for (const v of data) {
    acc = (acc << 5) | v;
    bits += 5;
    while (bits >= 8) {
      bits -= 8;
      out.push((acc >> bits) & 0xff);
    }
  }
  return out;
}

interface Bech32 {
  hrp: string;
  checksumOk: boolean;
  witnessVersion: number;
  program: string;
}

function bech32decode(addr: string): Bech32 {
  const pos = addr.lastIndexOf('1');
  const hrp = addr.slice(0, pos);
  const data = [...addr.slice(pos + 1)].map((c) => BECH_CHARSET.indexOf(c));
  if (data.some((v) => v < 0)) throw new Error(`not bech32: ${addr}`);
  return {
    hrp,
    checksumOk: bechPolymod(hrpExpand(hrp).concat(data)) === 1,
    witnessVersion: data[0],
    program: hex(Uint8Array.from(convert5to8(data.slice(1, -6)))),
  };
}

// ---------------------------------------------------------------------------
// Page readers
// ---------------------------------------------------------------------------
interface Pipeline {
  privHex: string;
  wif: string;
  pubHex: string;
  hash160: string;
  p2pkh: string;
  p2wpkh: string;
}

/** The five Key → Address stage blocks, parsed out of their rendered text. */
async function readPipeline(page: Page): Promise<Pipeline> {
  const blocks = await page.locator('.pipeline-step-value-wrap .pipeline-step-value').allTextContents();
  expect(blocks, 'the pipeline renders exactly five stages').toHaveLength(5);
  const priv = /priv hex\s+([0-9a-f]+)\s*\nWIF\s+(\S+)/.exec(blocks[0]);
  expect(priv, `stage 1 did not render a private key: ${blocks[0]}`).not.toBeNull();
  return {
    privHex: priv![1],
    wif: priv![2],
    pubHex: blocks[1].split('\n')[1].trim(),
    hash160: blocks[2].split('\n')[1].trim(),
    p2pkh: blocks[3].split('\n')[1].trim(),
    p2wpkh: blocks[4].split('\n')[1].trim(),
  };
}

interface StripState {
  bands: number[][];
  words: { idx: number; text: string; num: string }[];
  entropyCells: number;
  checksumCells: number;
  totalCells: number;
  checkline: string;
}

/** Everything the BIP-39 strip is actually painting, straight off the DOM. */
async function readStrip(page: Page): Promise<StripState> {
  return page.evaluate(() => {
    const bands = Array.from(document.querySelectorAll('[data-band-wrap]')).map((w) =>
      Array.from(w.querySelectorAll('.bip39-bit')).map((c) => Number(c.textContent)),
    );
    const words = Array.from(document.querySelectorAll('.bip39-word')).map((chip) => ({
      num: chip.querySelector('.bip39-word-num')?.textContent ?? '',
      idx: Number(chip.querySelector('.bip39-word-idx')?.textContent),
      text: chip.querySelector('.bip39-word-text')?.textContent ?? '',
    }));
    return {
      bands,
      words,
      entropyCells: document.querySelectorAll('button.bip39-bit').length,
      checksumCells: document.querySelectorAll('.bip39-bit--cs').length,
      totalCells: document.querySelectorAll('.bip39-bit').length,
      checkline: document.querySelector('.bip39-checkline')?.textContent ?? '',
    };
  });
}

/** Independent oracle: is the checksum the strip is showing actually correct? */
function checksumHolds(s: StripState): boolean {
  const bits = s.bands.flat();
  const entropyLen = s.entropyCells;
  const bytes = new Uint8Array(entropyLen / 8);
  for (let i = 0; i < bytes.length; i++) {
    let v = 0;
    for (let j = 0; j < 8; j++) v = (v << 1) | bits[i * 8 + j];
    bytes[i] = v;
  }
  const digest = sha256(bytes);
  const csLen = entropyLen / 32;
  for (let i = 0; i < csLen; i++) {
    if (bits[entropyLen + i] !== ((digest[Math.floor(i / 8)] >> (7 - (i % 8))) & 1)) return false;
  }
  return true;
}

async function generateMnemonic(page: Page): Promise<string[]> {
  await page.getByRole('button', { name: /Generate mnemonic/ }).click();
  await expect(page.locator('.mnemonic-word')).toHaveCount(12);
  const phrase = (await page.locator('.mnemonic-phrase').textContent()) ?? '';
  return phrase.trim().split(/\s+/);
}

/** The Walk-a-derivation-path readout (scoped: `.derived-bundle` is reused by
 *  the reference bundle in the Understand-it section). */
function derivedRows(page: Page) {
  return page.locator('.derive-card .derived-bundle .copy-row');
}

async function setPath(page: Page, path: string): Promise<void> {
  await page.fill('#path-input', path);
  await page.dispatchEvent('#path-input', 'change');
}

async function setIndex(page: Page, index: string): Promise<void> {
  await page.fill('#index-input', index);
  await page.dispatchEvent('#index-input', 'change');
}

// ===========================================================================
// 1. The headline verdict: the official-vector panel
// ===========================================================================
test('every published BIP vector recomputes to a match, and each badge agrees with the values it printed', async ({
  page,
}) => {
  await page.goto('.');

  const items = page.locator('.kat-item');
  await expect(items).toHaveCount(3);

  // The verdict is checked against what the page rendered — `got` vs `spec` —
  // not against a literal copied into this file. A badge claiming "match" over
  // two different values is exactly the failure worth catching.
  for (let i = 0; i < 3; i++) {
    const item = items.nth(i);
    const label = await item.locator('.kat-label').innerText();
    await expect(item.locator('.scenario-status'), `vector "${label}"`).toHaveText('✓ match');
    await expect(item.locator('.scenario-status')).toHaveClass(/scenario-status--valid/);
    const values = (await item.locator('.kat-values').innerText()).trim();
    const m = /^got\s+(\S+)\s+·\s+spec\s+(\S+)$/.exec(values);
    expect(m, `unparseable vector readout for "${label}": ${values}`).not.toBeNull();
    expect(m![1], `vector "${label}" badge says match over differing values`).toBe(m![2]);
  }

  // No vector anywhere on the page is allowed to be red.
  await expect(page.locator('.scenario-status--invalid')).toHaveCount(0);

  // The privkey = 1 address is computed twice on this page — once in the vector
  // panel, once in "Checksum in action". Both renderings must agree.
  const katAddress = (await items.nth(0).locator('.kat-values').innerText()).match(/got\s+(\S+)/)![1];
  const reference = page
    .locator('.checksum-card .copy-row')
    .filter({ hasText: 'Reference P2PKH' })
    .locator('.copy-row-value');
  await expect(reference).toHaveText(katAddress);
});

// ===========================================================================
// 2. Key → Address, proved against independent decoders
// ===========================================================================
test('both addresses provably commit to the HASH160 the page displayed, and a second Generate replaces every value', async ({
  page,
}) => {
  await page.goto('.');

  async function assertConsistent(p: Pipeline): Promise<void> {
    expect(p.privHex, 'private key is 32 bytes of hex').toMatch(/^[0-9a-f]{64}$/);
    expect(p.pubHex, 'compressed public key is 33 bytes with an 02/03 prefix').toMatch(
      /^0[23][0-9a-f]{64}$/,
    );
    expect(p.hash160, 'HASH160 is 20 bytes of hex').toMatch(/^[0-9a-f]{40}$/);

    // Stage 2 of the byte-flow shows SHA-256(pubkey); recompute it here.
    // (The stage fills on an animation beat, so this waits for it.)
    const pubBytes = Uint8Array.from((p.pubHex.match(/../g) ?? []).map((h) => parseInt(h, 16)));
    await expect(
      page.locator('[data-bytes="sha"]'),
      'byte-flow SHA-256 stage does not match SHA-256(pubkey)',
    ).toHaveText(hex(sha256(pubBytes)).slice(0, 12) + '…');

    // Base58Check: version 0x00 ‖ HASH160 ‖ first 4 bytes of double-SHA-256.
    const decoded = base58decode(p.p2pkh);
    expect(decoded.length, 'P2PKH decodes to 25 bytes').toBe(25);
    expect(decoded[0], 'P2PKH version byte is 0x00 (mainnet)').toBe(0);
    expect(hex(decoded.slice(1, 21)), 'P2PKH payload is NOT the displayed HASH160').toBe(p.hash160);
    expect(hex(sha256(sha256(decoded.slice(0, 21))).slice(0, 4)), 'P2PKH checksum is wrong').toBe(
      hex(decoded.slice(21)),
    );

    // Bech32: hrp "bc", witness version 0, witness program == the same HASH160.
    const b = bech32decode(p.p2wpkh);
    expect(b.hrp).toBe('bc');
    expect(b.checksumOk, 'P2WPKH bech32 polymod checksum is wrong').toBe(true);
    expect(b.witnessVersion, 'P2WPKH witness version is 0').toBe(0);
    expect(b.program, 'P2WPKH witness program is NOT the displayed HASH160').toBe(p.hash160);
  }

  const first = await readPipeline(page);
  await assertConsistent(first);

  // The byte-flow animation must land on the same values the pipeline printed —
  // one run, one set of numbers, two surfaces.
  await expect(page.locator('[data-bytes="h160"]')).toHaveText(first.hash160);
  await expect(page.locator('[data-bytes="b58"]')).toHaveText(first.p2pkh);
  await expect(page.locator('[data-bytes="bech"]')).toHaveText(first.p2wpkh);

  // Both QR codes are rendered and carry the addresses they are labelled with.
  const qrCards = page.locator('.qr-row').first().locator('.qr-card');
  await expect(qrCards).toHaveCount(2);
  await expect(qrCards.nth(0).locator('.qr-card-value')).toHaveText(first.p2pkh);
  await expect(qrCards.nth(1).locator('.qr-card-value')).toHaveText(first.p2wpkh);
  await expect(qrCards.locator('.qr-svg svg')).toHaveCount(2);

  // A second Generate must replace the WHOLE chain, not just the top of it: a
  // stale downstream value would be an address that no longer belongs to the
  // key shown above it.
  await page.getByRole('button', { name: 'Generate a new private key and derive its address' }).click();
  await expect(page.locator('.pipeline-step-value').first()).not.toHaveText(
    new RegExp(first.privHex),
  );
  const second = await readPipeline(page);
  for (const k of ['privHex', 'wif', 'pubHex', 'hash160', 'p2pkh', 'p2wpkh'] as const) {
    expect(second[k], `${k} survived a regenerate`).not.toBe(first[k]);
  }
  await assertConsistent(second);
  await expect(page.locator('[data-bytes="h160"]')).toHaveText(second.hash160);
  await expect(qrCards.nth(0).locator('.qr-card-value')).toHaveText(second.p2pkh);
});

// ===========================================================================
// 3. The BIP-39 strip: the parts sum to the whole and index each other
// ===========================================================================
test('the bit strip accounts for all 132 bits, each band indexes its own word, and the checksum badge matches an independent SHA-256', async ({
  page,
}) => {
  await page.goto('.');
  const phrase = await generateMnemonic(page);
  expect(phrase).toHaveLength(12);

  const s = await readStrip(page);

  // 128 entropy + 4 checksum = 132, and 12 bands × 11 bits = 132.
  expect(s.entropyCells, 'entropy bit cells').toBe(128);
  expect(s.checksumCells, 'checksum bit cells').toBe(4);
  expect(s.entropyCells + s.checksumCells, 'entropy + checksum must account for every cell').toBe(
    s.totalCells,
  );
  expect(s.totalCells).toBe(132);
  expect(s.bands).toHaveLength(12);
  for (const band of s.bands) expect(band).toHaveLength(11);
  expect(s.bands.flat().every((b) => b === 0 || b === 1), 'every cell renders a single bit').toBe(true);

  // Each word chip's printed index must be the integer its own 11 bits spell.
  expect(s.words).toHaveLength(12);
  s.bands.forEach((band, i) => {
    const value = band.reduce((acc, bit) => (acc << 1) | bit, 0);
    expect(s.words[i].idx, `band ${i + 1} bits spell ${value} but the chip prints ${s.words[i].idx}`).toBe(
      value,
    );
    expect(s.words[i].idx).toBeGreaterThanOrEqual(0);
    expect(s.words[i].idx).toBeLessThan(2048);
    expect(s.words[i].num).toBe(String(i + 1).padStart(2, '0'));
  });

  // The strip, the word grid and the copyable phrase line are three renderings
  // of one mnemonic; all three must say the same twelve words.
  expect(s.words.map((w) => w.text)).toEqual(phrase);
  const grid = await page.locator('.mnemonic-word-text').allTextContents();
  expect(grid).toEqual(phrase);

  // The badge is checked against a SHA-256 recomputed here from the DOM's bits.
  expect(checksumHolds(s), 'a freshly generated phrase must carry a valid checksum').toBe(true);
  expect(s.checkline).toContain('✓ checksum valid');
  expect(s.checkline).toContain('SHA-256 checksum of the entropy');

  // The seed line names the KDF the README promises, and prints 64 bytes.
  const seedLine = (await page.locator('.mnemonic-seed').innerText()).trim();
  expect(seedLine).toContain('PBKDF2-HMAC-SHA512');
  expect(seedLine).toContain('2048 iter');
  expect(/([0-9a-f]{128})\s*$/.test(seedLine.replace(/\s+/g, ' ')), `seed line: ${seedLine}`).toBe(true);
});

// ===========================================================================
// 4. Tamper path: mangle the last word
// ===========================================================================
test('mangling the last word reaches the broken-checksum state, names the cause, and is confirmed broken by an independent SHA-256', async ({
  page,
}) => {
  await page.goto('.');
  const phrase = await generateMnemonic(page);

  await page.locator('.bip39-mangle-btn').click();
  await expect(page.locator('.bip39-checkline .scenario-status')).toHaveText('✗ checksum broken');

  const s = await readStrip(page);

  // The failure is real, not just painted.
  expect(checksumHolds(s), 'badge says broken but the checksum still verifies').toBe(false);

  // It names its cause: which band went wrong, and what that band now holds.
  const lastValue = s.bands[11].reduce((acc, bit) => (acc << 1) | bit, 0);
  expect(s.checkline).toContain('flipped bit changed the entropy without fixing the checksum band');
  expect(s.checkline, 'the failure text must name the offending band value').toContain(
    `last band value ${lastValue}`,
  );

  // Exactly one word changed, and it is the twelfth.
  const mangled = s.words.map((w) => w.text);
  const differing = mangled.map((w, i) => (w === phrase[i] ? -1 : i)).filter((i) => i >= 0);
  expect(differing, `mangle changed words ${JSON.stringify(differing)}`).toEqual([11]);

  // The mangled phrase is mirrored into the validator, which independently
  // reaches the same verdict — two surfaces, one run.
  await expect(page.locator('#validate-input')).toHaveValue(mangled.join(' '));
  const badge = page.locator('.validate-row .scenario-status');
  await expect(badge).toHaveText('invalid (bad word or checksum)');
  await expect(badge).toHaveClass(/scenario-status--invalid/);

  // The real mnemonic is untouched — the tamper demo must not rewrite the
  // phrase the learner was told to back up.
  const phraseLine = ((await page.locator('.mnemonic-phrase').textContent()) ?? '').trim();
  expect(phraseLine.split(/\s+/)).toEqual(phrase);

  // Screen-reader users are told the same thing the badge shows.
  await expect(page.locator('#app > [role="status"]')).toContainText('checksum now fails');
});

// ===========================================================================
// 5. Tamper path: flip a single entropy bit
// ===========================================================================
test('flipping one entropy bit re-indexes its band and the badge tracks the recomputed checksum either way', async ({
  page,
}) => {
  await page.goto('.');
  await generateMnemonic(page);
  const before = await readStrip(page);

  const cell = page.locator('button.bip39-bit[data-bit="3"]');
  const wasPressed = await cell.getAttribute('aria-pressed');
  await cell.click();
  await expect(cell).toHaveAttribute('aria-pressed', wasPressed === 'true' ? 'false' : 'true');
  await expect(cell).toHaveText(wasPressed === 'true' ? '0' : '1');

  const after = await readStrip(page);
  expect(after.bands[0][3], 'the clicked cell must flip').toBe(1 - before.bands[0][3]);
  expect(after.bands.flat().filter((b, i) => b !== before.bands.flat()[i]).length).toBeGreaterThan(0);

  // Band 1's word must follow its own bits.
  const value = after.bands[0].reduce((acc, bit) => (acc << 1) | bit, 0);
  expect(after.words[0].idx).toBe(value);
  expect(after.words[0].text).not.toBe(before.words[0].text);

  // The badge is not allowed to guess: whichever way the recomputation lands,
  // the rendered verdict has to match it. (A single flip leaves a 12-word
  // checksum intact about one time in sixteen, so both outcomes are legal —
  // what is illegal is the badge and the arithmetic disagreeing.)
  const holds = checksumHolds(after);
  expect(after.checkline).toContain(holds ? '✓ checksum valid' : '✗ checksum broken');

  // Checksum cells are derived, never editable.
  await expect(page.locator('.bip39-bit--cs')).toHaveCount(4);
  await expect(page.locator('button.bip39-bit--cs')).toHaveCount(0);
});

// ===========================================================================
// 5b. The other half of the checksum lesson
//
// "Mangle the last word" searches for a corruption the checksum CATCHES, which
// made the page's demonstration agree with a claim that is false: a 12-word
// phrase carries 4 checksum bits, so a wrong word passes about 1 time in 16.
// Measured with this repo's engine, 61,141 of 982,560 single-word substitutions
// across 40 random phrases (6.22%) still validate, flat across all 12 positions.
// The page now has to be able to show one, and the validator has to agree.
// ===========================================================================

test('the page can produce a one-word change the checksum misses, and both the badge and the validator call it valid', async ({
  page,
}) => {
  await page.goto('.');
  const before = await generateMnemonic(page);

  await page.locator('.bip39-miss-btn').click();

  const after = await readStrip(page);
  const changedWords = after.words.map((w) => w.text);

  // Exactly one word moved — a single entropy bit lives in exactly one band.
  const differing = changedWords
    .map((w, i) => (w === before[i] ? -1 : i))
    .filter((i) => i >= 0);
  expect(differing, `expected exactly one changed word, got ${JSON.stringify(differing)}`)
    .toHaveLength(1);

  // …and the phrase is STILL valid, confirmed by an independent SHA-256 rather
  // than by trusting the badge.
  expect(
    checksumHolds(after),
    'the control is supposed to find a corruption the checksum misses; this one did not survive',
  ).toBe(true);
  expect(after.checkline).toContain('✓ checksum valid');

  // The engine's own validator agrees — the mirrored phrase passes.
  await expect(page.locator('#validate-input')).toHaveValue(changedWords.join(' '));
  await expect(page.locator('.validate-row .scenario-status')).toHaveText('checksum valid');

  // The note has to state the count it found, and the count must be real: zero
  // survivors would mean the control had nothing to demonstrate.
  const note = ((await page.locator('.bip39-miss-note').textContent()) ?? '').replace(/\s+/g, ' ');
  const m = note.match(/(\d+) of the 128 single-bit changes/);
  expect(m, `miss note should quote a survivor count: ${note}`).not.toBeNull();
  expect(Number(m![1]), 'survivor count must be non-zero').toBeGreaterThan(0);
  expect(Number(m![1])).toBeLessThanOrEqual(128);
  expect(note).toContain(`Word ${differing[0] + 1} changed`);
  expect(note).toContain('not proof that it is your phrase');

  // The live region says the same thing, so a screen-reader user gets the
  // finding and not just the mangle-button version of the lesson.
  await expect(page.locator('#app > [role="status"]')).toContainText('still validates');
});

test('the page never claims a wrong word always fails validation', async ({ page }) => {
  await page.goto('.');
  const body = ((await page.locator('#app').textContent()) ?? '').replace(/\s+/g, ' ');
  // The exact sentence the seed-step card used to carry.
  expect(body).not.toContain('typing one wrong word makes the whole phrase fail to validate');
  // …replaced by the measured statement, including the split of the final word.
  expect(body).toContain('7 entropy bits plus those 4');
  expect(body).toMatch(/about 1 in 16/);
});

// ===========================================================================
// 5c. The five-address table is derived from the BIP-44 subtree, and says so
// ===========================================================================

test('the address table names the purpose subtree it derives from, and the ones it does not', async ({
  page,
}) => {
  await page.goto('.');
  await generateMnemonic(page);
  await expect(page.locator('.address-list-table tbody tr')).toHaveCount(5);

  const help = ((await page.locator('.address-list-card').textContent()) ?? '').replace(/\s+/g, ' ');
  // The claim that used to sit over a bc1 column derived from m/44'.
  expect(help).not.toContain('.getNextAddress() exactly this way');
  expect(help).toContain('BIP-44');
  expect(help).toContain('would very likely never look for');

  // All four purpose rows are present, with their real paths, and the row this
  // lab actually implements is the 44' one.
  const rows = await page.$$eval('.purpose-table tbody tr', (trs) =>
    trs.map((tr) => Array.from(tr.querySelectorAll('td')).map((td) => td.textContent?.trim() ?? '')),
  );
  expect(rows.map((r) => r[0])).toEqual(["44'", "49'", "84'", "86'"]);
  expect(rows.find((r) => r[0] === "84'")![2]).toBe("m/84'/0'/0'/0/i");
  expect(rows.find((r) => r[0] === "86'")![2]).toBe("m/86'/0'/0'/0/i");
  expect(rows.find((r) => r[0] === "84'")![3]).toContain('P2WPKH');

  // The path box really is on the 44' subtree, which is what makes the note true.
  await expect(page.locator('#path-input')).toHaveValue(/^m\/44'/);
});

// ===========================================================================
// 5d. "Only the seed can spend" was contradicted three panels down
// ===========================================================================

test('the xpub card does not claim only the seed can spend, while the page prints a child private key', async ({
  page,
}) => {
  await page.goto('.');
  await generateMnemonic(page);

  // The derivation panel prints a spendable child secret — priv hex and WIF.
  const rows = await derivedRows(page).allTextContents();
  const flat = rows.join(' ').replace(/\s+/g, ' ');
  expect(flat, 'the derivation panel must print a spendable child secret').toMatch(/priv hex\s*[0-9a-f]{64}/);
  expect(flat).toMatch(/WIF\s*[KL5][1-9A-HJ-NP-Za-km-z]{50,}/);

  const concepts = ((await page.locator('.concept-card').allTextContents()) ?? [])
    .join(' ')
    .replace(/\s+/g, ' ');
  expect(concepts).not.toContain('Only the seed (or a hardware wallet holding it) can produce signatures');
  expect(concepts).toContain('any private key below it spends its own outputs');
  expect(concepts).toContain('reveals the whole derivable address graph');
});

// ===========================================================================
// 6. The validator: pass, fail-with-cause, and no verdict outliving its input
// ===========================================================================
test('the validator passes the official phrase, names its failures, and retires the verdict when the phrase is edited', async ({
  page,
}) => {
  await page.goto('.');
  const badge = page.locator('.validate-row .scenario-status');
  const validate = page.getByRole('button', { name: 'Validate', exact: true });
  await expect(badge).toHaveText('awaiting input');
  await expect(badge).toHaveClass(/scenario-status--pending/);

  await page.fill('#validate-input', CANONICAL);
  await validate.click();
  await expect(badge).toHaveText('checksum valid');
  await expect(badge).toHaveClass(/scenario-status--valid/);

  // REGRESSION (verdict outliving its input): the green badge described the
  // phrase that was in the box when Validate ran. Editing the box makes it a
  // verdict about nothing, so it has to retire rather than sit there endorsing
  // text nobody checked.
  await page.locator('#validate-input').press('End');
  await page.locator('#validate-input').pressSequentially(' zoo');
  await expect(badge, 'a stale "checksum valid" survived an edit to the phrase').toHaveText(
    'awaiting input',
  );
  await expect(badge).toHaveClass(/scenario-status--pending/);
  await expect(page.locator('#app > [role="status"]')).toContainText('no longer applies');

  // Checksum failure: last word swapped for another valid wordlist entry.
  await page.fill('#validate-input', CANONICAL.replace(/about$/, 'abandon'));
  await validate.click();
  await expect(badge).toHaveText('invalid (bad word or checksum)');
  await expect(badge).toHaveClass(/scenario-status--invalid/);

  // Not-a-word failure reaches the same failure state.
  await page.fill('#validate-input', CANONICAL.replace(/about$/, 'notaword'));
  await validate.click();
  await expect(badge).toHaveText('invalid (bad word or checksum)');

  // Wrong length (11 words) is rejected too.
  await page.fill('#validate-input', CANONICAL.split(' ').slice(0, 11).join(' '));
  await validate.click();
  await expect(badge).toHaveText('invalid (bad word or checksum)');

  // Empty input returns to pending rather than keeping the last red badge.
  await page.fill('#validate-input', '');
  await validate.click();
  await expect(badge).toHaveText('awaiting input');
  await expect(badge).toHaveClass(/scenario-status--pending/);
});

// ===========================================================================
// 7. Derivation-path failures reach the failure state AND name the cause
// ===========================================================================
test('malformed derivation paths and indices are refused by name instead of silently deriving a wrong address', async ({
  page,
}) => {
  await page.goto('.');
  await generateMnemonic(page);

  const summary = page.locator('.derived-summary');
  await expect(summary).toHaveText("Derived along m/44'/0'/0'/0/0");
  await expect(derivedRows(page)).toHaveCount(6);
  await expect(page.locator('.derive-unify')).toBeVisible();
  const good = await derivedRows(page).nth(4).locator('.copy-row-value').innerText();

  // Missing "m" prefix.
  await setPath(page, "44'/0'/0'/0/0");
  await expect(summary).toHaveText("Path must start with 'm', e.g. m/44'/0'/0'/0/0");
  await expect(derivedRows(page), 'a refused path must not leave an address on screen').toHaveCount(0);
  await expect(page.locator('.derive-card .qr-card')).toHaveCount(0);
  await expect(page.locator('.derive-unify')).toBeHidden();

  // REGRESSION: a non-numeric segment used to reach parseInt → NaN → ser32(NaN)
  // → four zero bytes, so "m/abc/0" silently derived the index-0 child and the
  // page reported "Derived along m/abc/0" over an address that was not the
  // requested one at all.
  await setPath(page, 'm/abc/0');
  await expect(summary).toContainText('Path error');
  await expect(summary, 'the error must name the offending segment').toContainText('"abc"');
  await expect(derivedRows(page)).toHaveCount(0);

  // Out-of-range segment (>= 2^31 before hardening) is refused by name.
  await setPath(page, 'm/2147483648/0');
  await expect(summary).toContainText('Path error');
  await expect(summary).toContainText('out of range');
  await expect(derivedRows(page)).toHaveCount(0);

  // A fractional segment is not an index either.
  await setPath(page, 'm/1.5/0');
  await expect(summary).toContainText('Path error');
  await expect(summary).toContainText('"1.5"');

  // REGRESSION: Number('') is 0 and Number('1.5') is finite, so a blank or
  // fractional receive index used to derive a real address under a path the
  // summary printed as "…/1.5".
  await setPath(page, "m/44'/0'/0'/0/0");
  await expect(summary).toHaveText("Derived along m/44'/0'/0'/0/0");
  await setIndex(page, '1.5');
  await expect(summary).toHaveText('Index must be a non-negative integer.');
  await expect(derivedRows(page)).toHaveCount(0);
  await setIndex(page, '');
  await expect(summary).toHaveText('Index must be a non-negative integer.');

  // The controls are not left dead by a refusal — a good path derives again.
  await setIndex(page, '0');
  await expect(summary).toHaveText("Derived along m/44'/0'/0'/0/0");
  await expect(derivedRows(page)).toHaveCount(6);
  await expect(derivedRows(page).nth(4).locator('.copy-row-value')).toHaveText(good);
});

// ===========================================================================
// 8. One seed, five addresses: the two surfaces must agree index by index
// ===========================================================================
test('the receive index walks the same addresses the five-address table lists, and all five are distinct', async ({
  page,
}) => {
  await page.goto('.');
  await generateMnemonic(page);

  const rows = page.locator('.address-list-table tbody tr');
  await expect(rows).toHaveCount(5);

  const table: { p2pkh: string; p2wpkh: string }[] = [];
  for (let i = 0; i < 5; i++) {
    const cells = await rows.nth(i).locator('td.mono').allInnerTexts();
    expect(cells[0], 'the table lists indices 0-4 in order').toBe(String(i));
    table.push({ p2pkh: cells[1], p2wpkh: cells[2] });
  }
  expect(new Set(table.map((r) => r.p2pkh)).size, 'five distinct P2PKH addresses').toBe(5);
  expect(new Set(table.map((r) => r.p2wpkh)).size, 'five distinct P2WPKH addresses').toBe(5);

  for (let i = 0; i < 5; i++) {
    await setIndex(page, String(i));
    await expect(page.locator('.derived-summary')).toHaveText(`Derived along m/44'/0'/0'/0/${i}`);
    const values = await derivedRows(page).locator('.copy-row-value').allInnerTexts();
    expect(values[4], `derive card and table disagree about index ${i}`).toBe(table[i].p2pkh);
    expect(values[5], `derive card and table disagree about index ${i}`).toBe(table[i].p2wpkh);
    // The derived leaf is a real key for that address, checked independently.
    expect(hex(base58decode(values[4]).slice(1, 21))).toBe(values[3]);
    expect(bech32decode(values[5]).program).toBe(values[3]);
  }

  // A fresh mnemonic must replace the whole table, not leave the old seed's
  // addresses sitting under a new phrase.
  await generateMnemonic(page);
  const refreshed = await rows.nth(0).locator('td.mono').allInnerTexts();
  expect(refreshed[1]).not.toBe(table[0].p2pkh);
});

// ===========================================================================
// 9. The memorize drill: counters sum to the whole
// ===========================================================================
test('the drill counts placed words consistently, names a wrong word, and can be restarted after completion', async ({
  page,
}) => {
  await page.goto('.');
  const phrase = await generateMnemonic(page);

  const status = page.locator('.memorize-status');
  await page.getByRole('button', { name: 'Start the drill' }).click();
  await expect(page.locator('.memorize-slot')).toHaveCount(12);
  await expect(page.locator('.memorize-chip')).toHaveCount(12);
  await expect(status).toHaveText('Drill started — click the words in order.');

  // A wrong word must be refused with the slot named.
  const wrong = phrase.find((w) => w !== phrase[0])!;
  await page.locator(`.memorize-chip[data-word="${wrong}"]`).first().click();
  await expect(status).toHaveText('That word is out of order for slot 1. Try again.');
  await expect(page.locator('#app > [role="status"]')).toContainText(`Expected ${phrase[0]}`);
  await expect(page.locator('.memorize-chip:disabled'), 'a wrong guess must not consume a chip').toHaveCount(
    0,
  );
  await expect(page.locator('.memorize-slot-word').first()).toHaveText('—');

  // REGRESSION: a wrong guess schedules a 1.2s revert of the slot it landed in.
  // Answering correctly inside that window used to leave the revert pending, so
  // it fired afterwards and blanked a slot that was by then correctly filled —
  // a green slot showing an em dash. Recover fast enough to race it.
  await page.locator(`.memorize-chip[data-word="${wrong}"]`).first().click();
  await page.locator(`.memorize-chip[data-word="${phrase[0]}"]:not([disabled])`).first().click();
  await expect(status).toHaveText('Placed 1 of 12.');
  await page.waitForTimeout(1500); // outlive the revert the wrong guess scheduled
  await expect(
    page.locator('.memorize-slot-word').first(),
    'a stale revert wiped a slot that had already been answered correctly',
  ).toHaveText(phrase[0]);
  await expect(page.locator('.memorize-slot').first()).toHaveClass(/memorize-slot--ok/);
  await expect(page.locator('.memorize-slot--err')).toHaveCount(0);

  // Placed + remaining = 12 at every step.
  for (let i = 1; i < 12; i++) {
    await page.locator(`.memorize-chip[data-word="${phrase[i]}"]:not([disabled])`).first().click();
    const placed = i + 1;
    await expect(page.locator('.memorize-chip:disabled')).toHaveCount(placed);
    await expect(page.locator('.memorize-slot--ok')).toHaveCount(placed);
    if (placed < 12) {
      await expect(status).toHaveText(`Placed ${placed} of 12.`);
      await expect(page.locator('.memorize-chip:not([disabled])')).toHaveCount(12 - placed);
    } else {
      await expect(status).toHaveText('✓ Perfect — every word in order.');
      await expect(page.locator('#app > [role="status"]')).toContainText('Drill complete');
    }
  }

  // Every slot shows the word that belongs in it.
  expect(await page.locator('.memorize-slot-word').allInnerTexts()).toEqual(phrase);

  // The controls survive completion.
  await page.getByRole('button', { name: 'Reset' }).click();
  await expect(page.locator('.memorize-slot')).toHaveCount(0);
  await expect(page.locator('.memorize-chip')).toHaveCount(0);
  await page.getByRole('button', { name: 'Start the drill' }).click();
  await expect(page.locator('.memorize-slot')).toHaveCount(12);
  await expect(status).toHaveText('Drill started — click the words in order.');
});


// ===========================================================================
// 11. The `[hidden]` override trap
//     (probe from crypto-lab/tools/probes/hidden-attribute.spec.ts)
// ===========================================================================
test('no element carrying the hidden attribute is actually rendered', async ({ page }) => {
  await page.goto('.');
  await page.waitForTimeout(300);

  const leaks = await page.evaluate(() => {
    const out: { tag: string; cls: string; display: string }[] = [];
    for (const node of Array.from(document.querySelectorAll('[hidden]'))) {
      const el = node as HTMLElement;
      if (getComputedStyle(el).display !== 'none') {
        out.push({
          tag: el.tagName.toLowerCase(),
          cls: el.className?.toString().slice(0, 60) ?? '',
          display: getComputedStyle(el).display,
        });
      }
    }
    return out;
  });

  expect(leaks, `elements marked hidden that still render: ${JSON.stringify(leaks)}`).toEqual([]);
});
