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
  DEFAULT_DERIVATION_PATH,
  SCRIPTURE_TEXT,
  SCRIPTURE_CITATION,
} from './data';

// Tiny DOM helper in the sibling-demo style.
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
    else node.setAttribute(k, String(v));
  }
  if (text !== undefined) node.textContent = text;
  if (html !== undefined) node.innerHTML = html;
  if (on) for (const [ev, fn] of Object.entries(on)) node.addEventListener(ev, fn);
  for (const c of children) node.append(c);
  return node;
}

// ---- demo state ----
interface SeedState {
  mnemonic: string | null;
  seed: Uint8Array | null;
  master: HDKey | null;
}

// =====================================================================
// Hero
// =====================================================================
function renderHero(): HTMLElement {
  const hero = el('section', { class: 'hero-panel', role: 'banner' });

  hero.append(
    el('button', {
      id: 'theme-toggle',
      class: 'theme-toggle',
      type: 'button',
      'aria-label': 'Switch theme',
      text: '🌙',
    }),
    el('p', { class: 'hero-eyebrow', text: 'Bitcoin · Wallet Mechanics' }),
    el('h1', { text: 'What a Bitcoin address (and a seed phrase) actually is' }),
    el('p', {
      class: 'hero-lede',
      text:
        'Most developers use a wallet without ever seeing the chain that turns 32 random bytes into a spendable address, or what the 12 words really encode. This page does that chain for real in your browser — secp256k1, HASH160, Base58Check, Bech32, BIP-39 and BIP-32 — built on the audited @noble libraries and validated against the official BIP test vectors. Every key here is generated locally; nothing is ever sent anywhere.',
    }),
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
// Section 2 — Key → Address
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

  const pipelineList = el('ol', { class: 'pipeline-list' });
  for (const step of PIPELINE_STEPS) {
    const li = el('li', { class: 'pipeline-step' });
    li.append(
      el('div', { class: 'pipeline-step-head' }, [
        el('span', { class: 'pipeline-step-num', text: String(step.ordinal) }),
        el('span', { class: 'pipeline-step-label', text: step.label }),
      ]),
      el('p', { class: 'pipeline-step-detail', text: step.detail }),
      el('pre', { class: 'pipeline-step-value mono', text: '—', 'data-step': String(step.ordinal) }),
    );
    pipelineList.append(li);
  }
  section.append(pipelineList);

  function fillPipeline(bundle: AddressBundle): void {
    const values = [
      `priv hex   ${bundle.privKeyHex}\nWIF        ${bundle.wif}`,
      `pubkey (compressed, 33 bytes)\n${bundle.pubKeyHex}`,
      `HASH160 (20 bytes)\n${bundle.hash160Hex}`,
      `P2PKH (mainnet)\n${bundle.p2pkh}`,
      `P2WPKH (mainnet, BIP-173)\n${bundle.p2wpkh}`,
    ];
    const slots = pipelineList.querySelectorAll<HTMLElement>('.pipeline-step-value');
    slots.forEach((slot, idx) => {
      slot.textContent = values[idx] ?? '—';
    });
  }

  generateBtn.addEventListener('click', () => {
    try {
      const priv = randomPrivateKey();
      const bundle = deriveAddress(priv);
      fillPipeline(bundle);
    } catch (err) {
      console.error('Generate key failed:', err);
    }
  });

  // Derive once on load so the panel isn't empty.
  try {
    fillPipeline(deriveAddress(randomPrivateKey()));
  } catch (err) {
    console.warn('Initial derive failed:', err);
  }

  return section;
}

// =====================================================================
// Section 3 — Seed phrase → wallet
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

  // ---- Pipeline cards (BIP-39/BIP-32 chain) ----
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

  // ---- Generate mnemonic + show stretching ----
  const state: SeedState = { mnemonic: null, seed: null, master: null };

  const generateRow = el('div', { class: 'panel-card seed-controls' });
  const genBtn = el('button', { type: 'button', text: 'Generate mnemonic (12 words)' });
  generateRow.append(genBtn);
  section.append(generateRow);

  const mnemonicCard = el('div', { class: 'panel-card mnemonic-card' });
  const mnemonicTitle = el('h3', { class: 'card-title', text: 'Your fresh mnemonic' });
  const wordGrid = el('div', { class: 'mnemonic-grid', role: 'list' });
  const phraseLine = el('div', { class: 'mono mnemonic-phrase', text: '— click Generate —' });
  const seedLine = el('div', { class: 'mono mnemonic-seed', text: 'seed: —' });
  const masterLine = el('div', { class: 'mono mnemonic-master', text: 'BIP-32 master priv: —' });
  mnemonicCard.append(mnemonicTitle, wordGrid, phraseLine, seedLine, masterLine);
  section.append(mnemonicCard);

  // ---- Validate-mnemonic input ----
  const validateCard = el('div', { class: 'panel-card validate-card' });
  validateCard.append(
    el('h3', { class: 'card-title', text: 'Validate a mnemonic' }),
    el('p', {
      class: 'validate-help',
      text:
        'Paste a 12/15/18/21/24-word phrase to see the BIP-39 checksum check pass or fail. (Do not paste a real wallet phrase — never expose a phrase that controls real funds.)',
    }),
  );
  const validateInput = el('textarea', {
    class: 'mnemonic-input mono',
    rows: 2,
    placeholder: 'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about',
    'aria-label': 'Mnemonic to validate',
  });
  const validateBtn = el('button', { type: 'button', text: 'Validate', class: 'secondary' });
  const validateStatus = el('span', {
    class: 'scenario-status scenario-status--pending',
    text: 'awaiting input',
  });
  const validateRow = el('div', { class: 'validate-row' }, [validateBtn, validateStatus]);
  validateCard.append(validateInput, validateRow);
  section.append(validateCard);

  // ---- Derivation path ----
  const deriveCard = el('div', { class: 'panel-card derive-card' });
  deriveCard.append(
    el('h3', { class: 'card-title', text: 'Walk a derivation path' }),
    el('p', {
      class: 'derive-help',
      text:
        "After generating a mnemonic above, the path field is unlocked. The default path m/44'/0'/0'/0/0 is the first receive address of the first account of the legacy BIP-44 layout. Bump the last index to see the next address from the same seed.",
    }),
  );
  const pathInput = el('input', {
    type: 'text',
    class: 'mono path-input',
    value: DEFAULT_DERIVATION_PATH,
    'aria-label': 'BIP-32 derivation path',
  });
  const indexInput = el('input', {
    type: 'number',
    class: 'mono index-input',
    value: '0',
    min: 0,
    max: 2147483647,
    'aria-label': 'Receive index to overwrite the last path component',
  });
  const deriveBtn = el('button', { type: 'button', text: 'Derive address', class: 'secondary' });
  const deriveRow = el('div', { class: 'derive-row' }, [
    el('label', { class: 'derive-label', text: 'Path' }),
    pathInput,
    el('label', { class: 'derive-label', text: 'Receive index' }),
    indexInput,
    deriveBtn,
  ]);
  deriveCard.append(deriveRow);

  const derivedOut = el('div', { class: 'derived-out' });
  const derivedSummary = el('div', { class: 'mono derived-summary', text: 'Generate a mnemonic above to begin.' });
  const derivedBundle = el('dl', { class: 'derived-bundle' });
  derivedOut.append(derivedSummary, derivedBundle);
  deriveCard.append(derivedOut);
  section.append(deriveCard);

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

    // Auto-derive default address once.
    derive();
  }

  function derive(): void {
    derivedBundle.replaceChildren();
    if (!state.seed) {
      derivedSummary.textContent = 'Generate a mnemonic above to begin.';
      return;
    }
    let basePath = pathInput.value.trim();
    if (!basePath.startsWith('m')) {
      derivedSummary.textContent = "Path must start with 'm', e.g. m/44'/0'/0'/0/0";
      return;
    }
    // Replace the final path component with the user's index.
    const indexValue = Number(indexInput.value);
    if (!Number.isFinite(indexValue) || indexValue < 0) {
      derivedSummary.textContent = 'Index must be a non-negative integer.';
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
      return;
    }
    const bundle = deriveAddress(hdKey.privateKey);
    derivedSummary.textContent = 'Derived along ' + basePath;
    const addRow = (label: string, value: string): void => {
      derivedBundle.append(
        el('dt', { text: label }),
        el('dd', { class: 'mono', text: value }),
      );
    };
    addRow('priv hex', bundle.privKeyHex);
    addRow('WIF', bundle.wif);
    addRow('pubkey (compressed)', bundle.pubKeyHex);
    addRow('HASH160', bundle.hash160Hex);
    addRow('P2PKH (1…)', bundle.p2pkh);
    addRow('P2WPKH (bc1…)', bundle.p2wpkh);
  }

  genBtn.addEventListener('click', () => {
    try {
      const entropy = new Uint8Array(16);
      crypto.getRandomValues(entropy);
      const mnemonic = entropyToMnemonic(entropy, WORDLIST);
      renderMnemonic(mnemonic);
    } catch (err) {
      console.error('Generate mnemonic failed:', err);
    }
  });

  validateBtn.addEventListener('click', () => {
    const input = validateInput.value.trim();
    if (!input) {
      validateStatus.className = 'scenario-status scenario-status--pending';
      validateStatus.textContent = 'awaiting input';
      return;
    }
    const ok = validateMnemonic(input, WORDLIST);
    validateStatus.className =
      'scenario-status ' + (ok ? 'scenario-status--valid' : 'scenario-status--invalid');
    validateStatus.textContent = ok ? 'checksum valid' : 'invalid (bad word or checksum)';
  });

  deriveBtn.addEventListener('click', derive);
  pathInput.addEventListener('change', derive);
  indexInput.addEventListener('change', derive);

  return section;
}

// =====================================================================
// Section 4 — Understand it
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
    card.append(
      el('h3', { class: 'card-title', text: c.title }),
      el('p', { text: c.body }),
    );
    grid.append(card);
  }
  section.append(grid);

  // Optional: small checksum-in-action demo using a real address.
  const checkCard = el('div', { class: 'panel-card checksum-card' });
  checkCard.append(
    el('h3', { class: 'card-title', text: 'Checksum in action' }),
    el('p', {
      text:
        "Below is the address derived from private key = 1 (a textbook constant — do not fund it). Change the highlighted character and the next valid-address rederive will not match: that is what a wallet's 'invalid address' error is detecting.",
    }),
  );
  const referenceBundle = deriveAddress((() => {
    const k = new Uint8Array(32);
    k[31] = 1;
    return k;
  })());
  checkCard.append(
    el('dl', { class: 'derived-bundle' }, [
      el('dt', { text: 'Reference P2PKH (privkey = 1)' }),
      el('dd', { class: 'mono', text: referenceBundle.p2pkh }),
      el('dt', { text: 'Reference P2WPKH (privkey = 1)' }),
      el('dd', { class: 'mono', text: referenceBundle.p2wpkh }),
      el('dt', { text: 'Pubkey HASH160' }),
      el('dd', { class: 'mono', text: referenceBundle.hash160Hex }),
    ]),
  );
  section.append(checkCard);

  return section;
}

// =====================================================================
// Section 5 — Stay safe
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
    card.append(
      el('h3', { class: 'card-title', text: c.title }),
      el('p', { text: c.body }),
    );
    grid.append(card);
  }
  section.append(grid);
  return section;
}

// =====================================================================
// Footer — scripture (Part D)
// =====================================================================
function renderFooter(): HTMLElement {
  const footer = el('footer', { class: 'scripture-footer', role: 'contentinfo' });
  footer.append(
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
  main.append(
    renderKeyToAddress(),
    renderSeedSection(),
    renderConcepts(),
    renderSafety(),
  );
  root.append(main);
  root.append(renderFooter());
}

// Tiny re-exports so it's clear what the UI module relies on.
export { hexToBytes };
