// ui.ts — renders the Bitcoin wallet-mechanics demo. All crypto is delegated to engine.ts.
import {
  deriveAddress,
  randomPrivateKey,
  hexToBytes,
  bytesToHex,
  entropyToMnemonic,
  validateMnemonic,
  mnemonicToSeed,
  masterKeyFromSeed,
  derivePath,
  type AddressBundle,
  type HDKey,
} from './engine';
import { WORDLIST } from './wordlist';
import {
  PIPELINE_STEPS,
  SEED_STEPS,
  CONCEPTS,
  SAFETY,
  PATH_STEPS,
  DEFAULT_DERIVATION_PATH,
  SCRIPTURE_TEXT,
  SCRIPTURE_CITATION,
} from './data';
import { encodeQR, renderQRSVG } from './qr';

// =====================================================================
// Tiny DOM helper
// =====================================================================
type Attrs = Record<string, string | boolean | number | undefined> & {
  text?: string;
  html?: string;
  on?: Record<string, EventListener>;
};
function el<K extends keyof HTMLElementTagNameMap>(
  tag: K,
  attrs: Attrs = {},
  children: (Node | string)[] = [],
): HTMLElementTagNameMap[K] {
  const node = document.createElement(tag);
  const { text, html, on, ...rest } = attrs;
  for (const [k, v] of Object.entries(rest)) {
    if (v === undefined || v === false) continue;
    if (k === 'class') node.className = String(v);
    else if (
      k.startsWith('data-') ||
      k.startsWith('aria-') ||
      k === 'role' ||
      k === 'tabindex'
    ) {
      node.setAttribute(k, String(v));
    } else if (k === 'id') node.id = String(v);
    else if (k === 'for') node.setAttribute('for', String(v));
    else node.setAttribute(k, String(v));
  }
  if (text !== undefined) node.textContent = text;
  if (html !== undefined) node.innerHTML = html;
  if (on) for (const [ev, fn] of Object.entries(on)) node.addEventListener(ev, fn);
  for (const c of children) node.append(c);
  return node;
}

// =====================================================================
// Live-announce region (single shared aria-live="polite" sink so SR users
// hear ad-hoc status messages without us sprinkling regions everywhere).
// =====================================================================
let announceTarget: HTMLElement | null = null;
function announce(msg: string): void {
  if (!announceTarget) return;
  // Clear-then-set so identical consecutive messages still trigger AT.
  announceTarget.textContent = '';
  setTimeout(() => {
    if (announceTarget) announceTarget.textContent = msg;
  }, 30);
}

// =====================================================================
// Copy-to-clipboard helper — inline icon button paired with any value.
// =====================================================================
function copyButton(getValue: () => string, label: string): HTMLButtonElement {
  const btn = el('button', {
    type: 'button',
    class: 'copy-btn secondary',
    'aria-label': `Copy ${label} to clipboard`,
    title: `Copy ${label}`,
  });
  // SVG icon — outline copy glyph, currentColor.
  btn.innerHTML =
    '<svg aria-hidden="true" focusable="false" viewBox="0 0 16 16" width="14" height="14">' +
    '<path fill="none" stroke="currentColor" stroke-width="1.4" stroke-linejoin="round" ' +
    'd="M5 2h7v9H5zM3 5h2v9h7"/></svg><span class="copy-btn-text">Copy</span>';
  btn.addEventListener('click', async () => {
    const value = getValue();
    try {
      await navigator.clipboard.writeText(value);
      btn.classList.add('copy-btn--ok');
      const span = btn.querySelector<HTMLSpanElement>('.copy-btn-text');
      const prev = span ? span.textContent : null;
      if (span) span.textContent = 'Copied';
      announce(`${label} copied to clipboard`);
      setTimeout(() => {
        btn.classList.remove('copy-btn--ok');
        if (span) span.textContent = prev ?? 'Copy';
      }, 1400);
    } catch {
      announce(`Copy failed — your browser blocked clipboard access`);
    }
  });
  return btn;
}

// Convenience: a row with a label, monospace value, and copy button.
// Structured as <div><dt><dd> where the button lives INSIDE the <dd>, so
// the parent <dl> never has non-list-item direct descendants (axe-friendly).
function copyRow(label: string, value: string): HTMLElement {
  const row = el('div', { class: 'copy-row' });
  const dd = el('dd', {});
  dd.append(
    el('span', { class: 'mono copy-row-value', text: value }),
    copyButton(() => value, label),
  );
  row.append(el('dt', { text: label }), dd);
  return row;
}

// =====================================================================
// QR-code panel — renders inline SVG from src/qr.ts.
// =====================================================================
function qrPanel(label: string, value: string): HTMLElement {
  const card = el('div', { class: 'qr-card' });
  card.append(el('h4', { class: 'qr-card-title', text: label }));
  const svg = renderQRSVG(encodeQR(value), {
    size: 168,
    quietZone: 3,
    ariaLabel: `${label} QR code`,
  });
  const holder = el('div', { class: 'qr-svg', html: svg });
  card.append(holder, el('div', { class: 'mono qr-card-value', text: value }));
  card.append(copyButton(() => value, label));
  return card;
}

// =====================================================================
// State
// =====================================================================
interface SeedState {
  mnemonic: string | null;
  seed: Uint8Array | null;
  master: HDKey | null;
}

// =====================================================================
// Hero
// =====================================================================
function renderHero(): HTMLElement {
  // Fleet-standard hero: title block on the left, "why it matters" on the right.
  // Rendered as a <section> (not <header>) so it does not become a second
  // implicit banner landmark alongside the shared .cl-topbar header.
  const hero = el('section', { class: 'hero-panel' });

  // The theme-toggle stays in the DOM (hidden by the shared header CSS) so the
  // page's own theme JS keeps working; the shared bar's toggle drives it.
  hero.append(
    el('button', {
      id: 'theme-toggle',
      class: 'theme-toggle',
      type: 'button',
      'aria-label': 'Switch to light theme',
      text: '🌙',
    }),
  );

  const heroStd = el('header', { class: 'cl-hero' });
  const main = el('div', { class: 'cl-hero-main' });
  main.append(
    el('h1', { class: 'cl-hero-title', text: 'Bitcoin Wallet' }),
    el('p', {
      class: 'cl-hero-sub',
      text: 'secp256k1 · HASH160 · Base58Check · Bech32 · BIP-39 · BIP-32',
    }),
    el('p', {
      class: 'cl-hero-desc',
      text:
        'Runs the real derivation chain in your browser — 32 random bytes → secp256k1 public key → HASH160 → P2PKH & P2WPKH addresses, plus a BIP-39 mnemonic decoded to a BIP-32 master key and walked down a derivation path.',
    }),
  );
  const why = el('aside', { class: 'cl-hero-why', 'aria-label': 'Why it matters' });
  why.append(
    el('span', { class: 'cl-hero-why-label', text: 'WHY IT MATTERS' }),
    el('p', {
      class: 'cl-hero-why-text',
      text:
        'Those 12 words and 32 bytes ARE the money — anyone who sees them can spend your Bitcoin, and there is no reset. Knowing how the chain is built is how you tell a safe wallet from a trap, and why hardware keys exist.',
    }),
  );
  heroStd.append(main, why);
  hero.append(heroStd);

  hero.append(
    el('div', { class: 'hero-metric-row' }, [
      el('span', {
        class: 'hero-metric',
        text: 'Real secp256k1 · BIP-39 · BIP-32 · validated against the official test vectors',
      }),
    ]),
  );

  const details = el('details');
  details.append(
    el('summary', { text: 'Is this safe to use?' }),
    el('p', {
      text:
        "Honest answer: for learning, yes — for real funds, no. The cryptography is real, but a browser tab is not a secure place to generate or hold value. Never paste a seed phrase that controls real Bitcoin into any web page — including this one. Use a hardware wallet or audited wallet software for anything you can't afford to lose.",
    }),
  );
  hero.append(details);
  return hero;
}

// =====================================================================
// Key → Address
// =====================================================================
function renderKeyToAddress(): HTMLElement {
  const section = el('section', { class: 'lab-section', 'aria-labelledby': 'key-h2' });
  section.append(
    el('div', { class: 'section-heading-row' }, [
      el('h2', { id: 'key-h2', text: 'Key → Address' }),
      el('span', { class: 'section-kicker', text: 'secp256k1 · HASH160 · Base58Check · Bech32' }),
    ]),
    el('p', {
      text:
        'A private key is the secret. Everything else — public key, address, even the WIF backup — is derived from it. Click Generate to make a fresh key in your browser and watch each transform happen.',
    }),
  );

  const controls = el('div', { class: 'panel-card key-controls' });
  const generateBtn = el('button', {
    type: 'button',
    text: 'Generate key',
    'aria-label': 'Generate a new private key and derive its address',
  });
  const warning = el('p', {
    class: 'key-warning',
    text: 'For learning only — keys generated here have only the entropy your browser provides. Do not fund them.',
  });
  controls.append(generateBtn, warning);
  section.append(controls);

  // aria-live wrapper around all stage values
  const pipelineLive = el('div', {
    class: 'pipeline-live',
    'aria-live': 'polite',
    'aria-atomic': 'false',
  });
  const pipelineList = el('ol', { class: 'pipeline-list' });
  for (const step of PIPELINE_STEPS) {
    const li = el('li', { class: 'pipeline-step' });
    li.append(
      el('div', { class: 'pipeline-step-head' }, [
        el('span', { class: 'pipeline-step-num', text: String(step.ordinal) }),
        el('span', { class: 'pipeline-step-label', text: step.label }),
      ]),
      el('p', { class: 'pipeline-step-detail', text: step.detail }),
    );
    const valueWrap = el('div', { class: 'pipeline-step-value-wrap' });
    const value = el('pre', {
      class: 'pipeline-step-value mono',
      text: '—',
      'data-step': String(step.ordinal),
    });
    valueWrap.append(value);
    li.append(valueWrap);
    pipelineList.append(li);
  }
  pipelineLive.append(pipelineList);
  section.append(pipelineLive);

  // QR row for the two real addresses — shown after first generation.
  const qrRow = el('div', { class: 'qr-row', 'aria-live': 'polite' });
  section.append(qrRow);

  function fillPipeline(bundle: AddressBundle): void {
    const blocks: { value: string; copy: string }[] = [
      {
        value: `priv hex   ${bundle.privKeyHex}\nWIF        ${bundle.wif}`,
        copy: bundle.privKeyHex,
      },
      { value: `pubkey (compressed, 33 bytes)\n${bundle.pubKeyHex}`, copy: bundle.pubKeyHex },
      { value: `HASH160 (20 bytes)\n${bundle.hash160Hex}`, copy: bundle.hash160Hex },
      { value: `P2PKH (mainnet)\n${bundle.p2pkh}`, copy: bundle.p2pkh },
      { value: `P2WPKH (mainnet, BIP-173)\n${bundle.p2wpkh}`, copy: bundle.p2wpkh },
    ];
    const labels = ['private key', 'public key', 'HASH160', 'P2PKH address', 'P2WPKH address'];
    pipelineList.querySelectorAll<HTMLElement>('.pipeline-step-value-wrap').forEach((wrap, idx) => {
      wrap.replaceChildren();
      const pre = el('pre', {
        class: 'pipeline-step-value mono',
        text: blocks[idx]?.value ?? '—',
        'data-step': String(idx + 1),
      });
      const btn = copyButton(() => blocks[idx]?.copy ?? '', labels[idx]);
      wrap.append(pre, btn);
    });

    qrRow.replaceChildren(qrPanel('P2PKH', bundle.p2pkh), qrPanel('P2WPKH', bundle.p2wpkh));
    announce(
      `Fresh key derived. P2PKH ${bundle.p2pkh.slice(0, 6)} ellipsis. P2WPKH ${bundle.p2wpkh.slice(0, 8)} ellipsis.`,
    );
  }

  generateBtn.addEventListener('click', () => {
    try {
      const priv = randomPrivateKey();
      fillPipeline(deriveAddress(priv));
    } catch (err) {
      console.error('Generate key failed:', err);
    }
  });

  try {
    fillPipeline(deriveAddress(randomPrivateKey()));
  } catch (err) {
    console.warn('Initial derive failed:', err);
  }

  return section;
}

// =====================================================================
// Derivation-tree visual (Item 8)
// =====================================================================
function renderDerivationTree(): HTMLElement {
  const tree = el('div', { class: 'derivation-tree', 'aria-label': 'BIP-44 derivation path' });
  PATH_STEPS.forEach((step, i) => {
    const node = el('div', {
      class: 'tree-node' + (step.hardened ? ' tree-node--hardened' : ''),
    });
    node.append(
      el('span', { class: 'tree-node-segment mono', text: step.segment }),
      el('span', { class: 'tree-node-name', text: step.name }),
      el('span', { class: 'tree-node-detail', text: step.detail }),
    );
    tree.append(node);
    if (i < PATH_STEPS.length - 1) {
      tree.append(el('span', { class: 'tree-arrow', 'aria-hidden': 'true', text: '→' }));
    }
  });
  return tree;
}

// =====================================================================
// Memorize-and-test (Item 7)
// =====================================================================
function renderMemorizeMode(getWords: () => string[]): HTMLElement {
  const card = el('div', { class: 'panel-card memorize-card' });
  card.append(
    el('h3', { class: 'card-title', text: 'Test yourself' }),
    el('p', {
      class: 'memorize-help',
      text:
        'A backup you cannot recall is no backup. Generate a mnemonic above, then click Start — the words hide and reappear shuffled below. Click them in the right order. Real wallets walk users through this exact drill on first setup.',
    }),
  );

  const liveStatus = el('p', { class: 'memorize-status', 'aria-live': 'polite' });
  const slots = el('ol', { class: 'memorize-slots' });
  const bank = el('div', {
    class: 'memorize-bank',
    role: 'group',
    'aria-label': 'Shuffled words to choose from',
  });
  const startBtn = el('button', { type: 'button', text: 'Start the drill', class: 'secondary' });
  const resetBtn = el('button', { type: 'button', text: 'Reset', class: 'secondary' });
  const resetRow = el('div', { class: 'memorize-controls' }, [startBtn, resetBtn]);

  let target: string[] = [];
  let placed: number = 0;

  function reset(): void {
    target = [];
    placed = 0;
    slots.replaceChildren();
    bank.replaceChildren();
    liveStatus.textContent = '';
  }

  function build(): void {
    reset();
    target = getWords();
    if (target.length === 0) {
      liveStatus.textContent = 'Generate a mnemonic above first.';
      announce('Generate a mnemonic above before starting the drill.');
      return;
    }
    target.forEach((_, i) => {
      const slot = el('li', { class: 'memorize-slot', 'data-idx': String(i) });
      slot.append(el('span', { class: 'memorize-slot-num', text: String(i + 1).padStart(2, '0') }));
      slot.append(el('span', { class: 'memorize-slot-word', text: '—' }));
      slots.append(slot);
    });
    const shuffled = target.slice();
    for (let i = shuffled.length - 1; i > 0; i--) {
      const j = Math.floor(Math.random() * (i + 1));
      [shuffled[i], shuffled[j]] = [shuffled[j], shuffled[i]];
    }
    for (const word of shuffled) {
      const chip = el('button', {
        type: 'button',
        class: 'memorize-chip',
        text: word,
        'data-word': word,
      });
      chip.addEventListener('click', () => choose(chip, word));
      bank.append(chip);
    }
    liveStatus.textContent = 'Drill started — click the words in order.';
    announce('Drill started. Click the words in their original order.');
  }

  function choose(chip: HTMLButtonElement, word: string): void {
    if (placed >= target.length) return;
    const expected = target[placed];
    const slot = slots.querySelector<HTMLElement>(`[data-idx="${placed}"]`);
    if (!slot) return;
    const slotWord = slot.querySelector<HTMLElement>('.memorize-slot-word');
    if (slotWord) slotWord.textContent = word;
    if (word === expected) {
      slot.classList.add('memorize-slot--ok');
      chip.disabled = true;
      chip.classList.add('memorize-chip--used');
      placed++;
      if (placed === target.length) {
        liveStatus.textContent = '✓ Perfect — every word in order.';
        announce('Drill complete. Every word was placed correctly.');
      } else {
        liveStatus.textContent = `Placed ${placed} of ${target.length}.`;
      }
    } else {
      slot.classList.add('memorize-slot--err');
      announce(`Wrong word for slot ${placed + 1}. Expected ${expected}.`);
      liveStatus.textContent = `That word is out of order for slot ${placed + 1}. Try again.`;
      setTimeout(() => {
        slot.classList.remove('memorize-slot--err');
        if (slotWord) slotWord.textContent = '—';
      }, 1200);
    }
  }

  startBtn.addEventListener('click', build);
  resetBtn.addEventListener('click', reset);

  card.append(resetRow, liveStatus, slots, bank);
  return card;
}

// =====================================================================
// 5-address HD view (Item 6)
// =====================================================================
function renderAddressList(getSeed: () => Uint8Array | null, basePath: string): HTMLElement {
  const card = el('div', { class: 'panel-card address-list-card' });
  card.append(
    el('h3', { class: 'card-title', text: 'Your first five receive addresses' }),
    el('p', {
      class: 'address-list-help',
      text: `Same seed, indices 0–4 of ${basePath.replace(/\/\d+$/, '/n')}. Wallets call .getNextAddress() exactly this way — a fresh address every time, all from one backup.`,
    }),
  );

  const table = el('table', { class: 'math-table address-list-table' });
  table.append(
    el('thead', {}, [
      el('tr', {}, [
        el('th', { text: 'Index' }),
        el('th', { text: 'P2PKH (1…)' }),
        el('th', { text: 'P2WPKH (bc1…)' }),
        el('th', { text: '' }),
      ]),
    ]),
  );
  const tbody = el('tbody', { 'aria-live': 'polite' });
  table.append(tbody);
  card.append(el('div', { class: 'table-wrap', tabindex: '0' }, [table]));

  function refresh(): void {
    const seed = getSeed();
    tbody.replaceChildren();
    if (!seed) {
      const row = el('tr', {}, [
        el('td', { colspan: '4', class: 'address-list-empty', text: 'Generate a mnemonic above to see the first five addresses derived from one seed.' }),
      ]);
      tbody.append(row);
      return;
    }
    const parts = basePath.split('/');
    for (let i = 0; i < 5; i++) {
      parts[parts.length - 1] = String(i);
      const path = parts.join('/');
      const hd = derivePath(seed, path);
      const bundle = deriveAddress(hd.privateKey);
      const row = el('tr', {});
      row.append(
        el('td', { class: 'mono', text: String(i) }),
        el('td', { class: 'mono', text: bundle.p2pkh }),
        el('td', { class: 'mono', text: bundle.p2wpkh }),
      );
      const actions = el('td', { class: 'address-list-actions' });
      actions.append(
        copyButton(() => bundle.p2pkh, `P2PKH at index ${i}`),
        copyButton(() => bundle.p2wpkh, `P2WPKH at index ${i}`),
      );
      row.append(actions);
      tbody.append(row);
    }
  }

  refresh();
  return Object.assign(card, { refresh });
}

// =====================================================================
// Seed phrase → wallet
// =====================================================================
function renderSeedSection(): HTMLElement {
  const section = el('section', { class: 'lab-section', 'aria-labelledby': 'seed-h2' });
  section.append(
    el('div', { class: 'section-heading-row' }, [
      el('h2', { id: 'seed-h2', text: 'Seed phrase → HD wallet' }),
      el('span', { class: 'section-kicker', text: 'BIP-39 · BIP-32 · derivation paths' }),
    ]),
    el('p', {
      text:
        'Modern wallets are hierarchical-deterministic: one seed phrase deterministically derives every address you will ever use. Generate a phrase, watch it stretch into a seed, then walk a derivation path to a real address.',
    }),
  );

  // Pipeline (BIP-39/BIP-32 chain)
  const chain = el('ol', { class: 'pipeline-list' });
  for (const step of SEED_STEPS) {
    const li = el('li', { class: 'pipeline-step' });
    li.append(
      el('div', { class: 'pipeline-step-head' }, [
        el('span', { class: 'pipeline-step-num', text: String(step.ordinal) }),
        el('span', { class: 'pipeline-step-label', text: step.label }),
      ]),
      el('p', { class: 'pipeline-step-detail', text: step.detail }),
    );
    chain.append(li);
  }
  section.append(chain);

  // Derivation-tree visual (Item 8)
  section.append(
    el('div', { class: 'panel-card tree-card' }, [
      el('h3', { class: 'card-title', text: 'BIP-44 path breakdown' }),
      el('p', {
        class: 'tree-help',
        text: 'The default path is more than a string — each segment encodes a wallet decision.',
      }),
      renderDerivationTree(),
    ]),
  );

  const state: SeedState = { mnemonic: null, seed: null, master: null };

  // Generate-mnemonic control
  const generateRow = el('div', { class: 'panel-card seed-controls' });
  const genBtn = el('button', { type: 'button', text: 'Generate mnemonic (12 words)' });
  generateRow.append(genBtn);
  section.append(generateRow);

  // Mnemonic card
  const mnemonicCard = el('div', { class: 'panel-card mnemonic-card', 'aria-live': 'polite' });
  mnemonicCard.append(el('h3', { class: 'card-title', text: 'Your fresh mnemonic' }));
  const wordGrid = el('div', { class: 'mnemonic-grid', role: 'list' });
  const phraseRow = el('div', { class: 'mnemonic-phrase-row' });
  const phraseLine = el('div', { class: 'mono mnemonic-phrase', text: '— click Generate —' });
  phraseRow.append(phraseLine);
  const phraseCopy = copyButton(() => state.mnemonic ?? '', 'mnemonic phrase');
  phraseRow.append(phraseCopy);
  const seedRow = el('div', { class: 'mnemonic-line-row' });
  const seedLine = el('div', { class: 'mono mnemonic-seed', text: 'seed: —' });
  seedRow.append(seedLine, copyButton(() => (state.seed ? bytesToHex(state.seed) : ''), 'BIP-39 seed (hex)'));
  const masterRow = el('div', { class: 'mnemonic-line-row' });
  const masterLine = el('div', { class: 'mono mnemonic-master', text: 'BIP-32 master priv: —' });
  masterRow.append(
    masterLine,
    copyButton(() => (state.master ? bytesToHex(state.master.privateKey) : ''), 'BIP-32 master private key'),
  );
  mnemonicCard.append(wordGrid, phraseRow, seedRow, masterRow);
  section.append(mnemonicCard);

  // Memorize-and-test (Item 7)
  const memorize = renderMemorizeMode(() =>
    state.mnemonic ? state.mnemonic.split(/\s+/) : [],
  );
  section.append(memorize);

  // Validate-mnemonic
  const validateCard = el('div', { class: 'panel-card validate-card' });
  validateCard.append(
    el('h3', { class: 'card-title', text: 'Validate a mnemonic' }),
    el('p', {
      class: 'validate-help',
      text:
        'Paste a 12/15/18/21/24-word phrase to see the BIP-39 checksum check pass or fail. (Do not paste a real wallet phrase — never expose a phrase that controls real funds.)',
    }),
  );
  validateCard.append(
    el('label', { class: 'visually-hidden', for: 'validate-input', text: 'Mnemonic to validate' }),
  );
  const validateInput = el('textarea', {
    id: 'validate-input',
    class: 'mnemonic-input mono',
    rows: 2,
    placeholder: 'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about',
  });
  const validateBtn = el('button', { type: 'button', text: 'Validate', class: 'secondary' });
  const validateStatus = el('span', {
    class: 'scenario-status scenario-status--pending',
    text: 'awaiting input',
    'aria-live': 'polite',
  });
  validateCard.append(validateInput, el('div', { class: 'validate-row' }, [validateBtn, validateStatus]));
  section.append(validateCard);

  // Derive-along-path
  const deriveCard = el('div', { class: 'panel-card derive-card' });
  deriveCard.append(
    el('h3', { class: 'card-title', text: 'Walk a derivation path' }),
    el('p', {
      class: 'derive-help',
      text:
        "After generating a mnemonic above, the path field is unlocked. The default path m/44'/0'/0'/0/0 is the first receive address of the first account of the legacy BIP-44 layout.",
    }),
  );

  const pathLabel = el('label', { class: 'derive-label', for: 'path-input', text: 'Path' });
  const pathInput = el('input', {
    type: 'text',
    id: 'path-input',
    class: 'mono path-input',
    value: DEFAULT_DERIVATION_PATH,
  });
  const indexLabel = el('label', { class: 'derive-label', for: 'index-input', text: 'Receive index' });
  const indexInput = el('input', {
    type: 'number',
    id: 'index-input',
    class: 'mono index-input',
    value: '0',
    min: 0,
    max: 2147483647,
  });
  const deriveBtn = el('button', { type: 'button', text: 'Derive address', class: 'secondary' });
  deriveCard.append(
    el('div', { class: 'derive-row' }, [pathLabel, pathInput, indexLabel, indexInput, deriveBtn]),
    el('p', {
      class: 'derive-keyboard-hint',
      text: 'Tip: focus the receive index and press ↑/↓ to step through the next addresses from the same seed.',
    }),
  );

  const derivedOut = el('div', { class: 'derived-out', 'aria-live': 'polite' });
  const derivedSummary = el('div', {
    class: 'mono derived-summary',
    text: 'Generate a mnemonic above to begin.',
  });
  const derivedBundle = el('dl', { class: 'derived-bundle' });
  derivedOut.append(derivedSummary, derivedBundle);
  deriveCard.append(derivedOut);
  // QR pair for the derived path
  const derivedQrRow = el('div', { class: 'qr-row', 'aria-live': 'polite' });
  deriveCard.append(derivedQrRow);
  section.append(deriveCard);

  // 5-address HD view (Item 6)
  const addressList = renderAddressList(() => state.seed, DEFAULT_DERIVATION_PATH);
  section.append(addressList);

  // ---- behaviour ----
  function renderMnemonic(mnemonic: string): void {
    state.mnemonic = mnemonic;
    state.seed = mnemonicToSeed(mnemonic);
    state.master = masterKeyFromSeed(state.seed);

    wordGrid.replaceChildren();
    const words = mnemonic.split(' ');
    words.forEach((w, i) => {
      const cell = el('div', { class: 'mnemonic-word', role: 'listitem' });
      cell.append(
        el('span', { class: 'mnemonic-word-num', text: String(i + 1).padStart(2, '0') }),
        el('span', { class: 'mnemonic-word-text', text: w }),
      );
      wordGrid.append(cell);
    });
    phraseLine.textContent = mnemonic;
    seedLine.textContent =
      'seed (PBKDF2-HMAC-SHA512, 2048 iter, salt="mnemonic"):\n' + bytesToHex(state.seed);
    masterLine.textContent =
      'BIP-32 master priv:\n' +
      bytesToHex(state.master.privateKey) +
      '\nchain code:\n' +
      bytesToHex(state.master.chainCode);

    announce('Fresh 12-word mnemonic generated. Seed and master key derived.');
    derive();
    (addressList as unknown as { refresh: () => void }).refresh();
  }

  function derive(): void {
    derivedBundle.replaceChildren();
    derivedQrRow.replaceChildren();
    if (!state.seed) {
      derivedSummary.textContent = 'Generate a mnemonic above to begin.';
      return;
    }
    let basePath = pathInput.value.trim();
    if (!basePath.startsWith('m')) {
      derivedSummary.textContent = "Path must start with 'm', e.g. m/44'/0'/0'/0/0";
      announce("Invalid path. It must start with m.");
      return;
    }
    const indexValue = Number(indexInput.value);
    if (!Number.isFinite(indexValue) || indexValue < 0) {
      derivedSummary.textContent = 'Index must be a non-negative integer.';
      announce('Index must be a non-negative integer.');
      return;
    }
    const parts = basePath.split('/');
    if (parts.length > 1) {
      parts[parts.length - 1] = String(indexValue);
      basePath = parts.join('/');
    }
    let hdKey: HDKey;
    try {
      hdKey = derivePath(state.seed, basePath);
    } catch (err) {
      derivedSummary.textContent = 'Path error: ' + (err instanceof Error ? err.message : String(err));
      announce('Path error: ' + (err instanceof Error ? err.message : 'unknown'));
      return;
    }
    const bundle = deriveAddress(hdKey.privateKey);
    derivedSummary.textContent = 'Derived along ' + basePath;
    derivedBundle.append(
      copyRow('priv hex', bundle.privKeyHex),
      copyRow('WIF', bundle.wif),
      copyRow('pubkey (compressed)', bundle.pubKeyHex),
      copyRow('HASH160', bundle.hash160Hex),
      copyRow('P2PKH (1…)', bundle.p2pkh),
      copyRow('P2WPKH (bc1…)', bundle.p2wpkh),
    );
    derivedQrRow.replaceChildren(qrPanel('P2PKH', bundle.p2pkh), qrPanel('P2WPKH', bundle.p2wpkh));
    announce(`Derived address at ${basePath}. P2PKH ${bundle.p2pkh.slice(0, 6)} ellipsis.`);
  }

  genBtn.addEventListener('click', () => {
    try {
      const entropy = new Uint8Array(16);
      crypto.getRandomValues(entropy);
      renderMnemonic(entropyToMnemonic(entropy, WORDLIST));
    } catch (err) {
      console.error('Generate mnemonic failed:', err);
    }
  });

  validateBtn.addEventListener('click', () => {
    const input = validateInput.value.trim();
    if (!input) {
      validateStatus.className = 'scenario-status scenario-status--pending';
      validateStatus.textContent = 'awaiting input';
      announce('Awaiting mnemonic input.');
      return;
    }
    const ok = validateMnemonic(input, WORDLIST);
    validateStatus.className =
      'scenario-status ' + (ok ? 'scenario-status--valid' : 'scenario-status--invalid');
    validateStatus.textContent = ok ? 'checksum valid' : 'invalid (bad word or checksum)';
    announce(ok ? 'Mnemonic checksum is valid.' : 'Mnemonic is invalid — bad word or checksum.');
  });

  deriveBtn.addEventListener('click', derive);
  pathInput.addEventListener('change', derive);
  indexInput.addEventListener('change', derive);
  indexInput.addEventListener('input', derive);

  return section;
}

// =====================================================================
// Understand it
// =====================================================================
function renderConcepts(): HTMLElement {
  const section = el('section', { class: 'lab-section', 'aria-labelledby': 'concepts-h2' });
  section.append(
    el('div', { class: 'section-heading-row' }, [
      el('h2', { id: 'concepts-h2', text: 'Understand it' }),
      el('span', { class: 'section-kicker', text: 'WIF · hardened paths · xpub · checksum' }),
    ]),
    el('p', {
      text:
        'A handful of vocabulary will make every wallet UI in the ecosystem readable. These are the ideas you will see again in any serious wallet, hardware or software.',
    }),
  );

  const grid = el('div', { class: 'reuse-grid' });
  for (const c of CONCEPTS) {
    const card = el('div', { class: 'panel-card concept-card' });
    card.append(el('h3', { class: 'card-title', text: c.title }), el('p', { text: c.body }));
    grid.append(card);
  }
  section.append(grid);

  const checkCard = el('div', { class: 'panel-card checksum-card' });
  checkCard.append(
    el('h3', { class: 'card-title', text: 'Checksum in action' }),
    el('p', {
      text:
        "Below is the address derived from private key = 1 (a textbook constant — do not fund it). The Base58Check tail on the P2PKH and the Bech32 polymod on the P2WPKH are exactly what a wallet's 'invalid address' error checks before letting you send.",
    }),
  );
  const referenceBundle = deriveAddress(
    (() => {
      const k = new Uint8Array(32);
      k[31] = 1;
      return k;
    })(),
  );
  const refDl = el('dl', { class: 'derived-bundle' });
  refDl.append(
    copyRow('Reference P2PKH (privkey = 1)', referenceBundle.p2pkh),
    copyRow('Reference P2WPKH (privkey = 1)', referenceBundle.p2wpkh),
    copyRow('Pubkey HASH160', referenceBundle.hash160Hex),
  );
  checkCard.append(refDl);
  section.append(checkCard);
  return section;
}

// =====================================================================
// Stay safe
// =====================================================================
function renderSafety(): HTMLElement {
  const section = el('section', { class: 'lab-section', 'aria-labelledby': 'safety-h2' });
  section.append(
    el('div', { class: 'section-heading-row' }, [
      el('h2', { id: 'safety-h2', text: 'Stay safe' }),
      el('span', { class: 'section-kicker', text: 'self-custody · cold storage · phishing' }),
    ]),
    el('p', {
      text:
        'Bitcoin gives you direct ownership; it also gives you direct responsibility. These are the rules every long-term holder learns, often by losing something the first time.',
    }),
  );
  const grid = el('div', { class: 'reuse-grid' });
  for (const c of SAFETY) {
    const card = el('div', { class: 'panel-card safety-card' });
    card.append(el('h3', { class: 'card-title', text: c.title }), el('p', { text: c.body }));
    grid.append(card);
  }
  section.append(grid);
  return section;
}

// =====================================================================
// Footer
// =====================================================================
function renderFooter(): HTMLElement {
  const footer = el('footer', {
    class: 'scripture-footer',
    role: 'contentinfo',
    'aria-label': 'Scripture',
  });
  footer.append(
    el('p', {
      class: 'footer-links',
      html:
        'Related demos: ' +
        '<a href="https://systemslibrarian.github.io/crypto-lab-ecdsa-forge/" target="_blank" rel="noopener noreferrer">secp256k1 ECDSA signing and nonce-reuse failures, the curve that spends Bitcoin</a> · ' +
        '<a href="https://systemslibrarian.github.io/crypto-lab-merkle-vault/" target="_blank" rel="noopener noreferrer">SHA-256 Merkle trees and inclusion proofs</a> · ' +
        '<a href="https://systemslibrarian.github.io/crypto-lab-hash-zoo/" target="_blank" rel="noopener noreferrer">the hash families behind addresses and checksums</a> · ' +
        '<a href="https://systemslibrarian.github.io/crypto-lab-babel-hash/" target="_blank" rel="noopener noreferrer">SHA-256, SHA3-256, and BLAKE3 with HMAC</a> · ' +
        '<a href="https://systemslibrarian.github.io/crypto-lab-curve-lens/" target="_blank" rel="noopener noreferrer">elliptic-curve fundamentals (Curve25519, P-256, ECDH)</a>',
    }),
    el('p', { text: SCRIPTURE_TEXT }),
    el('cite', { text: `— ${SCRIPTURE_CITATION}` }),
  );
  return footer;
}

// =====================================================================
// mountApp
// =====================================================================
export function mountApp(root: HTMLDivElement): void {
  root.replaceChildren();
  root.append(renderHero());
  const main = el('main', { id: 'main-content', role: 'main', tabindex: '-1' });
  main.append(renderKeyToAddress(), renderSeedSection(), renderConcepts(), renderSafety());
  root.append(main);

  // Shared announcer for all aria-live messages issued via announce().
  announceTarget = el('div', {
    class: 'visually-hidden',
    role: 'status',
    'aria-live': 'polite',
    'aria-atomic': 'true',
  });
  root.append(announceTarget);

  root.append(renderFooter());
}

export { hexToBytes };
