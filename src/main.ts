import './style.css';
import './extra.css';
import { mountApp } from './ui';
import {
  deriveAddress,
  mnemonicToSeed,
  bytesToHex,
  hexToBytes,
  derivePath,
  serializeXprv,
  serializeXpub,
} from './engine';

const THEME_KEY = 'crypto-lab-theme';

function applyTheme(theme: 'dark' | 'light'): void {
  document.documentElement.setAttribute('data-theme', theme);
  try {
    localStorage.setItem(THEME_KEY, theme);
  } catch {
    /* storage may be disabled — ignore */
  }
  const toggle = document.getElementById('theme-toggle');
  if (toggle) {
    toggle.textContent = theme === 'dark' ? '🌙' : '☀️';
    toggle.setAttribute(
      'aria-label',
      theme === 'dark' ? 'Switch to light theme' : 'Switch to dark theme',
    );
  }
}

function currentTheme(): 'dark' | 'light' {
  const attr = document.documentElement.getAttribute('data-theme');
  return attr === 'light' ? 'light' : 'dark';
}

function wireThemeToggle(): void {
  applyTheme(currentTheme());
  const toggle = document.getElementById('theme-toggle');
  if (!toggle) return;
  toggle.addEventListener('click', () => {
    applyTheme(currentTheme() === 'dark' ? 'light' : 'dark');
  });
}

function selfTest(): void {
  // eslint-disable-next-line no-console
  console.group('crypto-lab-bitcoin-wallet · self-test');
  try {
    // BIP-32 / address sanity: privkey = 1 → P2PKH 1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH.
    const one = new Uint8Array(32);
    one[31] = 1;
    const bundle = deriveAddress(one);
    const expected = '1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH';
    console.log('privkey=1 P2PKH ===', bundle.p2pkh, '— expect', expected);
    if (bundle.p2pkh !== expected) {
      console.error('SELF-TEST FAIL: P2PKH mismatch for privkey=1');
    }

    // BIP-39 test vector: 12x "abandon" + "about" + passphrase "TREZOR"
    // -> seed begins with c55257c360c07c72.
    const m =
      'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about';
    const seedHex = bytesToHex(mnemonicToSeed(m, 'TREZOR'));
    console.log('BIP-39 seed prefix ===', seedHex.slice(0, 16), '— expect c55257c360c07c72');
    if (!seedHex.startsWith('c55257c360c07c72')) {
      console.error('SELF-TEST FAIL: BIP-39 PBKDF2 seed mismatch');
    }

    // BIP-32 Test Vector 1: seed 000102...0f, derive the mixed hardened/normal
    // path m/0'/1/2'/2/1000000000 and compare the serialized xprv/xpub to the
    // official extended keys. This exercises the full HD derivation chain, not
    // just the master key.
    const tvSeed = hexToBytes('000102030405060708090a0b0c0d0e0f');
    const tvKey = derivePath(tvSeed, "m/0'/1/2'/2/1000000000");
    const expXprv =
      'xprvA41z7zogVVwxVSgdKUHDy1SKmdb533PjDz7J6N6mV6uS3ze1ai8FHa8kmHScGpWmj4WggLyQjgPie1rFSruoUihUZREPSL39UNdE3BBDu76';
    const expXpub =
      'xpub6H1LXWLaKsWFhvm6RVpEL9P4KfRZSW7abD2ttkWP3SSQvnyA8FSVqNTEcYFgJS2UaFcxupHiYkro49S8yGasTvXEYBVPamhGW6cFJodrTHy';
    const gotXprv = serializeXprv(tvKey);
    const gotXpub = serializeXpub(tvKey);
    console.log("BIP-32 Vector 1  m/0'/1/2'/2/1000000000 xprv ===", gotXprv === expXprv ? 'match' : gotXprv);
    if (gotXprv !== expXprv || gotXpub !== expXpub) {
      console.error('SELF-TEST FAIL: BIP-32 Test Vector 1 derivation mismatch');
    }
  } catch (err) {
    console.error('Self-test threw:', err);
  } finally {
    console.groupEnd();
  }
}

function boot(): void {
  const root = document.getElementById('app');
  if (!(root instanceof HTMLDivElement)) {
    throw new Error('#app root not found');
  }
  mountApp(root);
  wireThemeToggle();
  selfTest();
}

if (document.readyState === 'loading') {
  document.addEventListener('DOMContentLoaded', boot, { once: true });
} else {
  boot();
}
