// data.ts — copy/content for the Bitcoin wallet-mechanics demo.
// Only plain content arrays here — no crypto, no DOM.

export interface PipelineStep {
  ordinal: number;
  label: string;
  detail: string;
}

export const PIPELINE_STEPS: PipelineStep[] = [
  {
    ordinal: 1,
    label: 'Private key (32 random bytes)',
    detail:
      'A wallet draws 256-bit candidates until one lands in the range secp256k1 accepts: an integer from 1 up to the group order n minus one. Not every 256-bit string qualifies — values of 0 or n and above are rejected and redrawn (which, at n ≈ 2^256 − 2^129, essentially never happens). Whoever knows the accepted integer can sign, so it is the entire secret behind a Bitcoin address.',
  },
  {
    ordinal: 2,
    label: 'Compressed public key (33 bytes)',
    detail:
      'Multiply the curve generator by the private key on secp256k1 to get an elliptic-curve point (x, y). Bitcoin serialises that point as 33 bytes: a parity prefix (02 or 03) followed by the x-coordinate.',
  },
  {
    ordinal: 3,
    label: 'HASH160 = RIPEMD-160(SHA-256(pubkey))',
    detail:
      'Hash the public key with SHA-256, then hash that with RIPEMD-160. The result is a 20-byte fingerprint of the public key. Real addresses commit to this, not to the public key directly.',
  },
  {
    ordinal: 4,
    label: 'P2PKH — version byte 0x00, then Base58Check',
    detail:
      'Prepend 0x00 (mainnet pay-to-pubkey-hash version), append a 4-byte double-SHA-256 checksum, encode in Base58. You get a classic address that starts with 1.',
  },
  {
    ordinal: 5,
    label: 'P2WPKH — Bech32 of the same HASH160',
    detail:
      'Native SegWit (BIP-173) encodes the same 20-byte HASH160 as a Bech32 string with the human-readable part bc and witness version 0. You get a modern address that starts with bc1.',
  },
];

export interface SeedStep {
  ordinal: number;
  label: string;
  detail: string;
}

export const SEED_STEPS: SeedStep[] = [
  {
    ordinal: 1,
    label: 'Entropy (16 bytes for 12 words)',
    detail:
      'BIP-39 starts with raw randomness. 16 bytes → 128 bits → 12 words. 32 bytes → 256 bits → 24 words. Every word maps to 11 bits, plus a checksum.',
  },
  {
    ordinal: 2,
    label: 'Append a SHA-256 checksum',
    detail:
      'Take the first ENT/32 bits of SHA-256(entropy) and append them. For a 12-word phrase that is 4 checksum bits, so the final word carries 7 entropy bits plus those 4 — it is not a pure checksum word. Four bits catch most typos but not all: measured over 982,560 single-word substitutions on 40 random phrases, 61,141 of them (6.22%, about 1 in 16) still validate. A valid checksum means the phrase was probably typed cleanly, not that it is the phrase you wrote down.',
  },
  {
    ordinal: 3,
    label: 'Look up each 11-bit group in the 2048-word list',
    detail:
      'Split the bit string into 11-bit chunks. Each chunk indexes the official BIP-39 English wordlist (2048 words). That is your mnemonic.',
  },
  {
    ordinal: 4,
    label: 'Mnemonic → seed via PBKDF2-HMAC-SHA512',
    detail:
      "Stretch the mnemonic with PBKDF2-HMAC-SHA512, 2048 iterations, salt = 'mnemonic' + optional passphrase. The output is 64 bytes — the BIP-32 root seed.",
  },
  {
    ordinal: 5,
    label: 'Seed → BIP-32 master key',
    detail:
      "HMAC-SHA512 the seed with the key 'Bitcoin seed'. Left 32 bytes are the master private key; right 32 bytes are the chain code, the extra HMAC material mixed into every child derivation. It is not an authorisation token — it carries no permission, it just makes each branch's key schedule distinct.",
  },
  {
    ordinal: 6,
    label: "Derive along a path like m/44'/0'/0'/0/0",
    detail:
      'Each path step combines the parent key, chain code, and the child index through HMAC-SHA512 to produce a child key. Hardened steps (with an apostrophe) require the private key; normal steps can be derived from the public key alone.',
  },
];

export interface ConceptCard {
  title: string;
  body: string;
}

export const CONCEPTS: ConceptCard[] = [
  {
    title: 'WIF — wallet import format',
    body: 'A private key encoded as Base58Check with version 0x80 and a trailing 0x01 byte (to flag compressed public keys). It is exactly the same secret as the raw hex — just easier for a human to copy without a typo.',
  },
  {
    title: 'Compressed vs uncompressed public keys',
    body: 'An elliptic-curve point has two coordinates (x, y), but y is determined by x up to a sign. Compressed pubkeys store x plus a one-byte parity prefix (02/03). Uncompressed (04 ‖ x ‖ y) is 65 bytes and almost never seen in modern wallets.',
  },
  {
    title: 'Address checksums catch typos, not attacks',
    body: 'Base58Check and Bech32 both append a checksum so a wallet refuses to send to a mistyped address. The checksum is mathematics; it does not prove who controls the address, only that the string was not corrupted in transit.',
  },
  {
    title: 'Hardened vs normal derivation',
    body: "Normal children can be derived from the parent public key, which is why an xpub can hand out fresh addresses without exposing any private key. Hardened children (m/44'/…') require the parent private key, breaking that chain — used at account boundaries so leaking one account does not leak siblings.",
  },
  {
    title: 'An xpub cannot sign — but plenty of other things can',
    body: 'Sharing an extended public key lets a service derive every non-hardened descendant address and watch deposits, without being able to sign. That is how watch-only wallets work. It does not mean only the seed can spend: any private key below it spends its own outputs, and an xprv spends everything under it — this page prints exactly such a child private key and WIF in the derivation panel below. An xpub is also privacy-sensitive in its own right, because it reveals the whole derivable address graph.',
  },
  {
    title: 'P2PKH vs P2WPKH',
    body: 'Both addresses commit to the same HASH160 of the same public key. P2PKH (1…) is the original encoding; P2WPKH (bc1…) is the SegWit version that puts the script witness in a separate field — lower fees, same security model.',
  },
];

export interface SafetyCard {
  title: string;
  body: string;
}

export const SAFETY: SafetyCard[] = [
  {
    title: 'Do not fund keys generated here',
    body: 'A browser tab is not a secure environment for serious entropy or long-term storage. Use this page to understand how Bitcoin keys and addresses are built — then use a hardware wallet (Ledger, Trezor, Coldcard) or audited wallet software for real money.',
  },
  {
    title: 'Never enter a real seed phrase into a website',
    body: 'Any page that asks for your 12 or 24 words is, with overwhelming likelihood, trying to steal your wallet. Real wallets do recovery offline, on the device that holds the seed. This page can take a mnemonic so you can see the checksum check — never paste a phrase that controls real funds.',
  },
  {
    title: 'Every layer below the words can spend too',
    body: 'The chain is entropy → words (+ optional passphrase) → 64-byte seed → BIP-32 master key → child keys → signatures, and each layer is enough to move whatever hangs below it. Anyone with the words takes everything; anyone with one leaked child key takes that address\u2019s coins without ever seeing the words. There is no support line that can reverse a theft. Back the phrase up on paper or steel, not in a screenshot, cloud note, or password manager that syncs to a hacked phone.',
  },
  {
    title: 'The checksum is typo protection, not security',
    body: 'A correct checksum only means the address or phrase was typed cleanly. It does NOT mean the address belongs to who you think, or that a phrase is safe to fund. Always verify a destination address out of band before sending non-trivial amounts.',
  },
];

export const DEFAULT_DERIVATION_PATH = "m/44'/0'/0'/0/0";

/**
 * BIP-43 purpose subtrees.
 *
 * This lab derives every key from the BIP-44 tree above and then shows the leaf
 * encoded BOTH as P2PKH and as P2WPKH, because the point of the Key -> Address
 * panel is that one HASH160 has two encodings. That is true of the encoding and
 * false of wallet practice: a real wallet keeps output types in separate purpose
 * subtrees so recovery software knows which type to scan for. A `bc1q...` address
 * derived under `44'` is a valid address that a restored wallet would very likely
 * never look for. This table is the correction, shown beside the derived one.
 */
export interface PurposePath {
  purpose: string;
  name: string;
  path: string;
  address: string;
}
export const PURPOSE_PATHS: PurposePath[] = [
  { purpose: "44'", name: 'Legacy', path: "m/44'/0'/0'/0/i", address: '1\u2026 P2PKH' },
  { purpose: "49'", name: 'Nested SegWit', path: "m/49'/0'/0'/0/i", address: '3\u2026 P2SH-P2WPKH' },
  { purpose: "84'", name: 'Native SegWit', path: "m/84'/0'/0'/0/i", address: 'bc1q\u2026 P2WPKH' },
  { purpose: "86'", name: 'Taproot', path: "m/86'/0'/0'/0/i", address: 'bc1p\u2026 P2TR' },
];

// Per-step gloss of the BIP-44 layout for the derivation-tree visual.
export interface PathStep {
  segment: string;
  name: string;
  detail: string;
  hardened: boolean;
}
export const PATH_STEPS: PathStep[] = [
  {
    segment: 'm',
    name: 'Master',
    detail: 'The BIP-32 root key derived from the seed. Everything hangs off this node.',
    hardened: false,
  },
  {
    segment: "44'",
    name: 'Purpose',
    detail: "BIP-44 layout (' = hardened). Tells wallets this is a P2PKH-style account tree.",
    hardened: true,
  },
  {
    segment: "0'",
    name: 'Coin',
    detail: "Bitcoin mainnet is 0 (hardened). Litecoin would be 2', Testnet 1', etc.",
    hardened: true,
  },
  {
    segment: "0'",
    name: 'Account',
    detail: "Your first account (hardened so accounts are independent — leaking one doesn't leak siblings).",
    hardened: true,
  },
  {
    segment: '0',
    name: 'Change',
    detail: '0 = receive addresses you give to senders, 1 = internal change addresses. Non-hardened so an xpub can watch.',
    hardened: false,
  },
  {
    segment: '0',
    name: 'Index',
    detail: 'The address index. Bump it to get a fresh receive address from the same seed.',
    hardened: false,
  },
];

export const SCRIPTURE_TEXT =
  '"So whether you eat or drink or whatever you do, do it all for the glory of God."';
export const SCRIPTURE_CITATION = '1 Corinthians 10:31';
