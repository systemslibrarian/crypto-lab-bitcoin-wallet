import { describe, it, expect } from 'vitest';
import {
  bytesToHex,
  hexToBytes,
  hash160,
  base58check,
  bech32Address,
  deriveAddress,
  privToWif,
  mnemonicToSeed,
  entropyToMnemonic,
  validateMnemonic,
  masterKeyFromSeed,
  deriveChild,
  derivePath,
  serializeXprv,
  serializeXpub,
  keyFingerprint,
  secp,
} from '../src/engine';
import { WORDLIST } from '../src/wordlist';

const HARDENED = 0x80000000;

function privOf(n: bigint): Uint8Array {
  return hexToBytes(n.toString(16).padStart(64, '0'));
}
const ONE = privOf(1n);

describe('hex helpers round-trip', () => {
  it('bytesToHex ∘ hexToBytes is identity', () => {
    const h = '00ff10abcdef0102030405060708090a0b0c0d0e0f101112131415161718191a';
    expect(bytesToHex(hexToBytes(h))).toBe(h);
  });
});

describe('Base58Check / address pipeline (known answers)', () => {
  it('derives the canonical compressed pubkey + HASH160 for privkey = 1', () => {
    const pub = secp.getPublicKey(ONE, true);
    expect(bytesToHex(pub)).toBe(
      '0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798',
    );
    expect(bytesToHex(hash160(pub))).toBe('751e76e8199196d454941c45d1b3a323f1433bd6');
  });

  it('privkey = 1 → the textbook P2PKH address', () => {
    const b = deriveAddress(ONE);
    expect(b.p2pkh).toBe('1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH');
  });

  it('privkey = 1 → the textbook P2WPKH (bech32) address', () => {
    const b = deriveAddress(ONE);
    // bech32 of HASH160(pubkey(1)) with hrp "bc", witness version 0.
    expect(b.p2wpkh).toBe('bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4');
  });

  it('Base58Check appends a valid 4-byte double-SHA256 checksum', () => {
    // Version-0 payload with an all-zero hash160 has a well-known encoding.
    const addr = base58check(new Uint8Array(21));
    expect(addr).toBe('1111111111111111111114oLvT2');
  });

  it('WIF (compressed) for privkey = 1 matches the reference vector', () => {
    expect(privToWif(ONE, true)).toBe('KwDiBf89QgGbjEhKnhXJuH7LrciVrZi3qYjgd9M7rFU73sVHnoWn');
  });

  it('bech32 encodes the BIP-173 reference example', () => {
    // BIP-173: bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4 is the P2WPKH for
    // witness program 751e76e8199196d454941c45d1b3a323f1433bd6.
    const wp = hexToBytes('751e76e8199196d454941c45d1b3a323f1433bd6');
    expect(bech32Address(wp, 'bc', 0)).toBe('bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4');
  });
});

describe('BIP-39 mnemonic ↔ seed (official Trezor test vectors)', () => {
  it('12× "abandon" + "about" is a valid mnemonic', () => {
    const m =
      'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about';
    expect(validateMnemonic(m, WORDLIST)).toBe(true);
  });

  it('all-zero entropy encodes to the canonical abandon×11/about phrase', () => {
    const m = entropyToMnemonic(new Uint8Array(16), WORDLIST);
    expect(m).toBe(
      'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about',
    );
  });

  it('PBKDF2-HMAC-SHA512 seed matches the official vector (passphrase TREZOR)', () => {
    const m =
      'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about';
    expect(bytesToHex(mnemonicToSeed(m, 'TREZOR'))).toBe(
      'c55257c360c07c72029aebc1b53c05ed0362ada38ead3e3e9efa3708e53495531f09a6987599d18264c1e1c92f2cf141630c7a3c4ab7c81b2f001698e7463b04',
    );
  });

  it('second official vector: all-ff entropy → correct phrase + seed', () => {
    const entropy = new Uint8Array(16).fill(0xff);
    const m = entropyToMnemonic(entropy, WORDLIST);
    expect(m).toBe('zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo wrong');
    expect(validateMnemonic(m, WORDLIST)).toBe(true);
    expect(bytesToHex(mnemonicToSeed(m, 'TREZOR'))).toBe(
      'ac27495480225222079d7be181583751e86f571027b0497b5b5d11218e0a8a13332572917f0f8e5a589620c6f15b11c61dee327651a14c34e18231052e48c069',
    );
  });

  it('a passphrase changes the derived seed', () => {
    const m =
      'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about';
    expect(bytesToHex(mnemonicToSeed(m, 'TREZOR'))).not.toBe(bytesToHex(mnemonicToSeed(m, '')));
  });
});

describe('BIP-39 checksum rejects tampering (typo protection)', () => {
  const good =
    'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about';

  it('rejects a single wrong final word (bad checksum)', () => {
    const bad = good.replace(/about$/, 'zoo');
    expect(validateMnemonic(bad, WORDLIST)).toBe(false);
  });

  it('rejects an out-of-wordlist word', () => {
    const bad = good.replace(/about$/, 'notaword');
    expect(validateMnemonic(bad, WORDLIST)).toBe(false);
  });

  it('rejects a phrase of invalid length', () => {
    expect(validateMnemonic('abandon about', WORDLIST)).toBe(false);
  });

  it('entropyToMnemonic ∘ validateMnemonic round-trips random entropy', () => {
    for (let t = 0; t < 25; t++) {
      const e = new Uint8Array(16);
      for (let i = 0; i < e.length; i++) e[i] = (Math.random() * 256) | 0;
      const m = entropyToMnemonic(e, WORDLIST);
      expect(m.split(' ')).toHaveLength(12);
      expect(validateMnemonic(m, WORDLIST)).toBe(true);
    }
  });
});

describe('BIP-32 HD derivation — official Test Vector 1', () => {
  const seed = hexToBytes('000102030405060708090a0b0c0d0e0f');

  it('master key serializes to the official xprv / xpub', () => {
    const m = masterKeyFromSeed(seed);
    expect(serializeXprv(m)).toBe(
      'xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi',
    );
    expect(serializeXpub(m)).toBe(
      'xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8',
    );
  });

  it("m/0' matches the official vector", () => {
    const k = derivePath(seed, "m/0'");
    expect(serializeXprv(k)).toBe(
      'xprv9uHRZZhk6KAJC1avXpDAp4MDc3sQKNxDiPvvkX8Br5ngLNv1TxvUxt4cV1rGL5hj6KCesnDYUhd7oWgT11eZG7XnxHrnYeSvkzY7d2bhkJ7',
    );
    expect(serializeXpub(k)).toBe(
      'xpub68Gmy5EdvgibQVfPdqkBBCHxA5htiqg55crXYuXoQRKfDBFA1WEjWgP6LHhwBZeNK1VTsfTFUHCdrfp1bgwQ9xv5ski8PX9rL2dZXvgGDnw',
    );
  });

  it("m/0'/1/2'/2/1000000000 (mixed hardened/normal) matches the official vector", () => {
    const k = derivePath(seed, "m/0'/1/2'/2/1000000000");
    expect(serializeXprv(k)).toBe(
      'xprvA41z7zogVVwxVSgdKUHDy1SKmdb533PjDz7J6N6mV6uS3ze1ai8FHa8kmHScGpWmj4WggLyQjgPie1rFSruoUihUZREPSL39UNdE3BBDu76',
    );
    expect(serializeXpub(k)).toBe(
      'xpub6H1LXWLaKsWFhvm6RVpEL9P4KfRZSW7abD2ttkWP3SSQvnyA8FSVqNTEcYFgJS2UaFcxupHiYkro49S8yGasTvXEYBVPamhGW6cFJodrTHy',
    );
  });

  it('derivePath equals step-by-step deriveChild', () => {
    const m = masterKeyFromSeed(seed);
    let k = deriveChild(m, 0 + HARDENED);
    k = deriveChild(k, 1);
    const viaPath = derivePath(seed, "m/0'/1");
    expect(bytesToHex(k.privateKey)).toBe(bytesToHex(viaPath.privateKey));
    expect(bytesToHex(k.chainCode)).toBe(bytesToHex(viaPath.chainCode));
    expect(serializeXpub(k)).toBe(serializeXpub(viaPath));
  });

  it('depth, index and parent fingerprint are tracked correctly', () => {
    const m = masterKeyFromSeed(seed);
    const child = deriveChild(m, 0 + HARDENED);
    expect(child.depth).toBe(1);
    expect(child.index).toBe(0 + HARDENED);
    expect(child.parentFingerprint).toBe(keyFingerprint(m.publicKey));
    // Fingerprint of the master key in Test Vector 1 is 0x3442193e.
    expect(keyFingerprint(m.publicKey)).toBe(0x3442193e);
  });

  it('changing the receive index yields a different address', () => {
    const a0 = derivePath(seed, "m/44'/0'/0'/0/0");
    const a1 = derivePath(seed, "m/44'/0'/0'/0/1");
    expect(bytesToHex(a0.privateKey)).not.toBe(bytesToHex(a1.privateKey));
    expect(deriveAddress(a0.privateKey).p2pkh).not.toBe(deriveAddress(a1.privateKey).p2pkh);
  });

  // Regression: a malformed segment used to reach parseInt, yield NaN, and
  // serialize through ser32 as four zero bytes — so "m/abc/0" quietly derived
  // the index-0 child and every caller believed it had the path it asked for.
  // A path that cannot be parsed must throw, and the message must name the
  // segment so the UI can show a learner what it choked on.
  it.each([
    ['m/abc/0', 'abc'],
    ['m/1.5/0', '1.5'],
    ['m/-1/0', '-1'],
    ["m/44'/0'/0'/0/", ''],
    ['m/0x10/0', '0x10'],
  ])('derivePath rejects the malformed path %s by naming the segment', (path, segment) => {
    expect(() => derivePath(seed, path)).toThrow(new RegExp(`"${segment.replace('.', '\\.')}"`));
  });

  it('derivePath rejects an index at or above 2^31 as out of range', () => {
    expect(() => derivePath(seed, 'm/2147483648')).toThrow(/out of range/);
    // 2^31 - 1 is the largest non-hardened index and must still work.
    expect(() => derivePath(seed, 'm/2147483647')).not.toThrow();
  });

  it('derivePath requires the path to start with m', () => {
    expect(() => derivePath(seed, "44'/0'/0'/0/0")).toThrow(/must start with "m"/);
    expect(() => derivePath(seed, 'm')).not.toThrow();
  });

  it('deriveChild rejects a non-integer or out-of-range index instead of silently using 0', () => {
    const m = masterKeyFromSeed(seed);
    expect(() => deriveChild(m, Number.NaN)).toThrow(/invalid child index/);
    expect(() => deriveChild(m, 1.5)).toThrow(/invalid child index/);
    expect(() => deriveChild(m, -1)).toThrow(/invalid child index/);
    expect(() => deriveChild(m, 2 ** 32)).toThrow(/invalid child index/);
  });
});

describe('BIP-32 CKDpriv edge-case handling (IL >= n or child == 0 → skip index)', () => {
  // BIP-32: "In case parse256(IL) >= n or ki = 0, the resulting key is invalid,
  // and one should proceed with the next value for i." Both branches are
  // unreachable with the real HMAC (probability ~2^-127), so deriveChild takes
  // an injectable HMAC purely so the contract can be asserted rather than
  // assumed. The production call sites pass nothing and get the real HMAC.
  const seed = hexToBytes('000102030405060708090a0b0c0d0e0f');
  const N = secp.CURVE.n;

  /** Build a 64-byte I = IL ‖ IR with the requested IL scalar. */
  function fakeI(il: bigint): Uint8Array {
    const out = new Uint8Array(64);
    out.set(hexToBytes(il.toString(16).padStart(64, '0')), 0);
    out.fill(0x42, 32); // any chain code
    return out;
  }

  it('skips to the next index when parse256(IL) >= n', () => {
    const m = masterKeyFromSeed(seed);
    let calls = 0;
    const child = deriveChild(m, 5, () => {
      calls++;
      // First index yields IL == n (invalid); the next yields a usable scalar.
      return calls === 1 ? fakeI(N) : fakeI(12345n);
    });
    expect(calls).toBe(2);
    expect(child.index).toBe(6);
    expect(bytesToHex(child.privateKey)).toBe(
      bytesToHex(hexToBytes(((12345n + BigInt('0x' + bytesToHex(m.privateKey))) % N).toString(16).padStart(64, '0'))),
    );
  });

  it('skips to the next index when the child private key would be zero', () => {
    const m = masterKeyFromSeed(seed);
    const parentScalar = BigInt('0x' + bytesToHex(m.privateKey));
    let calls = 0;
    const child = deriveChild(m, 9, () => {
      calls++;
      // IL = n - parent makes (IL + parent) mod n == 0, which BIP-32 rejects.
      return calls === 1 ? fakeI(N - parentScalar) : fakeI(777n);
    });
    expect(calls).toBe(2);
    expect(child.index).toBe(10);
    expect(bytesToHex(child.privateKey)).not.toBe('0'.repeat(64));
  });

  it('does not advance the index when the first candidate is valid', () => {
    const m = masterKeyFromSeed(seed);
    let calls = 0;
    const child = deriveChild(m, 3, () => {
      calls++;
      return fakeI(999n);
    });
    expect(calls).toBe(1);
    expect(child.index).toBe(3);
  });

  it('never returns an all-zero private key across many derivations', () => {
    const m = masterKeyFromSeed(seed);
    for (let i = 0; i < 50; i++) {
      const c = deriveChild(m, i);
      expect(bytesToHex(c.privateKey)).not.toBe('0'.repeat(64));
      // And the key must be a valid secp256k1 scalar (getPublicKey would throw
      // otherwise; assert it produced a 33-byte compressed pubkey).
      expect(c.publicKey).toHaveLength(33);
    }
  });

  it('reported index is the one actually used for a valid child', () => {
    const m = masterKeyFromSeed(seed);
    // For a valid index (the overwhelmingly common case) the returned index is
    // unchanged — this guards against the loop mistakenly advancing.
    const c = deriveChild(m, 7);
    expect(c.index).toBe(7);
  });
});

// ===========================================================================
// The 4-bit checksum is typo detection, not identity
//
// The page used to say "typing one wrong word makes the whole phrase fail to
// validate", and this file backed it with ONE substitution — `about` -> `zoo` —
// which happens to fail. That is a case where the claim holds, chosen from a
// population where it often does not. The measurement below is the population.
// ===========================================================================
describe('a valid BIP-39 checksum is not proof the phrase is the intended one', () => {
  it('about 1 in 16 single-word substitutions still validate, at every position', () => {
    // Full enumeration over a handful of phrases: 12 positions x 2,047
    // alternatives each. Deterministic entropy so the count is reproducible.
    const TRIALS = 4;
    let totalSubs = 0;
    let stillValid = 0;
    const perPosition = new Array(12).fill(0);

    for (let t = 0; t < TRIALS; t++) {
      const entropy = new Uint8Array(16);
      for (let i = 0; i < 16; i++) entropy[i] = (i * 37 + t * 101) & 0xff;
      const words = entropyToMnemonic(entropy, WORDLIST).split(' ');
      expect(validateMnemonic(words.join(' '), WORDLIST), 'base phrase must be valid').toBe(true);

      for (let p = 0; p < 12; p++) {
        for (const w of WORDLIST) {
          if (w === words[p]) continue;
          const alt = words.slice();
          alt[p] = w;
          totalSubs++;
          if (validateMnemonic(alt.join(' '), WORDLIST)) {
            stillValid++;
            perPosition[p]++;
          }
        }
      }
    }

    expect(totalSubs).toBe(TRIALS * 12 * 2047);
    // The checksum is 4 bits, so the survival rate is ~1/16. Anything far from
    // that means the validator changed shape; anything at 0 would mean the
    // "one wrong word always fails" claim had somehow become true, and the copy
    // would need to change back.
    const rate = stillValid / totalSubs;
    expect(stillValid, `${stillValid} of ${totalSubs} substitutions survived`).toBeGreaterThan(0);
    expect(rate).toBeGreaterThan(0.04);
    expect(rate).toBeLessThan(0.09);

    // Flat across positions: the last word is NOT special. It carries 7 entropy
    // bits and 4 checksum bits, so corrupting it is no more detectable than
    // corrupting the first.
    for (let p = 0; p < 12; p++) {
      expect(perPosition[p], `position ${p + 1} survivors`).toBeGreaterThan(0);
      expect(perPosition[p] / (TRIALS * 2047)).toBeGreaterThan(0.03);
      expect(perPosition[p] / (TRIALS * 2047)).toBeLessThan(0.10);
    }
  });

  it('a single entropy-bit flip that the checksum misses always exists to find', () => {
    // This is exactly what the page's "Find a change the checksum misses" button
    // does. The strip keeps the DISPLAYED checksum bits when an entropy bit is
    // flipped — it does not recompute them — so the phrase stays valid whenever
    // the recomputed first 4 checksum bits happen to match the old ones, about
    // 1 time in 16. Each entropy bit belongs to exactly one 11-bit band, so a
    // single flip changes exactly one word.
    //
    // The button is dead if no flip ever survives, so this requires a strictly
    // positive count on every trial rather than merely tolerating zero.
    const bitsOf = (bytes: Uint8Array): number[] => {
      const out: number[] = [];
      for (const b of bytes) for (let j = 7; j >= 0; j--) out.push((b >> j) & 1);
      return out;
    };
    const wordsOf = (bits: number[]): string[] => {
      const out: string[] = [];
      for (let b = 0; b * 11 < bits.length; b++) {
        let v = 0;
        for (let i = 0; i < 11; i++) v = (v << 1) | bits[b * 11 + i];
        out.push(WORDLIST[v]);
      }
      return out;
    };

    let trialsWithSurvivors = 0;
    for (let t = 0; t < 8; t++) {
      const entropy = new Uint8Array(16);
      for (let i = 0; i < 16; i++) entropy[i] = (i * 53 + t * 17) & 0xff;
      const phrase = entropyToMnemonic(entropy, WORDLIST);
      const original = phrase.split(' ');
      expect(validateMnemonic(phrase, WORDLIST)).toBe(true);
      // The 132 displayed bits: 128 entropy + the 4 checksum bits as generated.
      const shown = bitsOf(entropy).concat(
        // Recover the checksum bits from the phrase itself, which is what the
        // strip renders.
        (() => {
          const all: number[] = [];
          for (const w of original) {
            const idx = WORDLIST.indexOf(w);
            for (let i = 10; i >= 0; i--) all.push((idx >> i) & 1);
          }
          return all.slice(128);
        })(),
      );
      expect(shown).toHaveLength(132);

      let survivors = 0;
      for (let bit = 0; bit < 128; bit++) {
        const mutated = shown.slice();
        mutated[bit] ^= 1;
        const changed = wordsOf(mutated);
        const differing = changed.filter((w, i) => w !== original[i]).length;
        expect(differing, 'one bit flip must change exactly one word').toBe(1);
        if (validateMnemonic(changed.join(' '), WORDLIST)) survivors++;
      }
      expect(
        survivors,
        `trial ${t}: no single-bit corruption slipped past the checksum, so the ` +
          '"find a change the checksum misses" control would have nothing to find',
      ).toBeGreaterThan(0);
      trialsWithSurvivors++;
    }
    expect(trialsWithSurvivors, 'the loop must actually have run').toBe(8);
  });
});

// ===========================================================================
// BIP-32 boundary conditions the spec names but the real HMAC never reaches
// ===========================================================================
describe('BIP-32 invalid-key branches fail closed instead of wrapping', () => {
  const seed = hexToBytes('000102030405060708090a0b0c0d0e0f');
  const N = secp.CURVE.n;

  /** An HMAC stub whose left half is a chosen scalar and right half is fixed. */
  function stubHmac(ilValue: bigint) {
    return () => {
      const out = new Uint8Array(64);
      out.set(hexToBytes(ilValue.toString(16).padStart(64, '0')), 0);
      out.fill(0x11, 32);
      return out;
    };
  }

  it('rejects a master key with parse256(IL) = 0, naming BIP-32', () => {
    expect(() => masterKeyFromSeed(seed, stubHmac(0n))).toThrow(/invalid BIP-32 master key/);
  });

  it('rejects a master key with parse256(IL) >= n, naming BIP-32', () => {
    expect(() => masterKeyFromSeed(seed, stubHmac(N))).toThrow(/invalid BIP-32 master key/);
    expect(() => masterKeyFromSeed(seed, stubHmac(N + 5n))).toThrow(/invalid BIP-32 master key/);
  });

  it('accepts the boundary value n - 1, so the guard is not off by one', () => {
    const key = masterKeyFromSeed(seed, stubHmac(N - 1n));
    expect(key.privateKey).toHaveLength(32);
    expect(key.publicKey).toHaveLength(33);
  });

  it('an always-invalid normal derivation stops at 0x7fffffff instead of crossing into hardened', () => {
    const m = masterKeyFromSeed(seed);
    // Every candidate invalid: IL >= n on every call.
    const alwaysInvalid = stubHmac(N);
    expect(() => deriveChild(m, 0x7ffffffe, alwaysInvalid)).toThrow(
      /no valid child index remains .* 2147483647 \(the top of the normal range\)/,
    );
  });

  it('an always-invalid hardened derivation stops at 0xffffffff instead of wrapping to 0', () => {
    const m = masterKeyFromSeed(seed);
    const alwaysInvalid = stubHmac(N);
    expect(() => deriveChild(m, 0xfffffffe, alwaysInvalid)).toThrow(
      /no valid child index remains .* 4294967295 \(the top of the hardened range\)/,
    );
  });

  it('a valid retry still advances by one and reports the index it used', () => {
    const m = masterKeyFromSeed(seed);
    let call = 0;
    const invalidOnce = () => {
      call++;
      const out = new Uint8Array(64);
      // First call: IL >= n (invalid). Second: a small valid scalar.
      out.set(hexToBytes((call === 1 ? N : 42n).toString(16).padStart(64, '0')), 0);
      out.fill(0x22, 32);
      return out;
    };
    const child = deriveChild(m, 5, invalidOnce);
    expect(child.index).toBe(6);
    expect(call).toBe(2);
  });
});

describe('extended-key serialization refuses to truncate', () => {
  const seed = hexToBytes('000102030405060708090a0b0c0d0e0f');

  it('rejects depth 256 rather than serializing it as a master key', () => {
    const key = masterKeyFromSeed(seed);
    const deep = { ...key, depth: 256 };
    // The old code wrote `depth & 0xff` = 0, producing a well-formed extended
    // key claiming depth 0 — indistinguishable from the master.
    expect(() => serializeXprv(deep)).toThrow(/depth field is one byte/);
    expect(() => serializeXpub(deep)).toThrow(/depth field is one byte/);
    // 255 is the last legal value and must still work.
    expect(serializeXprv({ ...key, depth: 255 })).toMatch(/^xprv/);
  });

  it('rejects an out-of-range child index and a short chain code', () => {
    const key = masterKeyFromSeed(seed);
    expect(() => serializeXpub({ ...key, index: 0x100000000 })).toThrow(/index field is a uint32/);
    expect(() => serializeXprv({ ...key, chainCode: new Uint8Array(31) })).toThrow(/31-byte chain code/);
  });
});
