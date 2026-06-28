# crypto-lab-bitcoin-wallet

## What It Is

A working model of **Bitcoin wallet mechanics** — the chain that turns 32 random bytes into a spendable address, and 12 words into a hierarchical-deterministic wallet — using **real cryptography in the browser**. The page composes the audited [`@noble/secp256k1`](https://github.com/paulmillr/noble-secp256k1) and [`@noble/hashes`](https://github.com/paulmillr/noble-hashes) libraries to walk the full pipeline: secp256k1 private key → compressed public key → HASH160 (SHA-256 → RIPEMD-160) → P2PKH `1...` (Base58Check, BIP-13) and P2WPKH `bc1...` (Bech32, BIP-173); BIP-39 entropy → 12-word mnemonic with checksum → PBKDF2-HMAC-SHA512 seed; BIP-32 master key → hardened/normal child derivation along a path like `m/44'/0'/0'/0/0`. The derivation logic is validated at boot against the official **BIP-32 Test Vector 1** and **BIP-39** test phrase (`abandon × 11, about` with passphrase `TREZOR` → seed prefix `c55257c360c07c72`), plus the textbook privkey = 1 P2PKH address `1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH`. This is mainnet-style derivation **for education only** — do not hold real funds on any key generated here.

## When to Use It

- **Understanding what a Bitcoin address actually is** — show the secp256k1 → HASH160 → Base58Check / Bech32 chain step by step, instead of treating an address as opaque.
- **Teaching seed phrases honestly** — make BIP-39 visible: 16 random bytes become 12 words *because* the last word carries a SHA-256 checksum, and PBKDF2 stretches the phrase into the seed every wallet derives from.
- **Demonstrating HD wallets and derivation paths** — change the index of `m/44'/0'/0'/0/0` and watch one seed produce successive receive addresses; that is exactly how every modern wallet generates its address book.
- **Showing the address checksum doing its job** — paste a phrase, mangle a word, and watch the BIP-39 checksum reject it; the typo-protection check is the same idea as the four-byte Base58Check tail on `1...` addresses.
- **Do NOT use this for real funds.** A browser tab is not a secure place to generate or hold money. Use a hardware wallet (Ledger, Trezor, Coldcard) or audited wallet software for anything you cannot afford to lose. Never paste a phrase that controls real Bitcoin into any web page — including this one.

## Live Demo

**[systemslibrarian.github.io/crypto-lab-bitcoin-wallet](https://systemslibrarian.github.io/crypto-lab-bitcoin-wallet/)**

The page has two interactive flows. **Generate key** makes a fresh secp256k1 private key, then walks the five-stage pipeline — private key (hex + WIF), compressed public key, HASH160, P2PKH `1...`, and P2WPKH `bc1...` — every transform shown with its real bytes. **Generate mnemonic** produces 16 bytes of entropy via `crypto.getRandomValues`, encodes them as a 12-word BIP-39 phrase, stretches the phrase with PBKDF2-HMAC-SHA512 into a 64-byte seed, and derives the BIP-32 master key. A **validate-mnemonic** input runs the checksum check on any pasted phrase (pass / fail badge — do not paste a real wallet phrase). A **path** field (default `m/44'/0'/0'/0/0`) plus a **receive index** spinner walk the BIP-32 derivation to a real address; bumping the index produces the next address from the same seed, which is what a wallet does every time you click "new address". The page is dark by default with a top-right `🌙/☀️` toggle that persists across visits.

## What Can Go Wrong

- **A browser is not a vault:** keys generated in a web tab can be exposed by malicious extensions, cross-site scripting, swap files, or clipboard sniffers — never put real funds behind a browser-generated key.
- **Weak entropy:** a seed is only as strong as its randomness; a broken or backdoored RNG produces guessable keys and predictable addresses.
- **Seed-phrase phishing:** anyone who learns your mnemonic controls the funds, and fake "validate your phrase" prompts are a common theft vector.
- **No passphrase = single factor:** a BIP-39 seed with no extra passphrase rests entirely on the secrecy of the words themselves.
- **Address reuse leaks privacy:** reusing one address links transactions on a public ledger; HD wallets exist precisely so each receive can use a fresh address.

## Real-World Usage

- BIP-32/39/44 hierarchical-deterministic wallets are the standard behind hardware wallets like Ledger and Trezor and software wallets like Electrum and MetaMask.
- Bech32 (BIP-173) encodes the native SegWit `bc1...` addresses used across the Bitcoin network.
- secp256k1 is the signing curve for both Bitcoin and Ethereum transactions.
- BIP-39 mnemonics are the common backup format users write down to recover a wallet across devices.

## How to Run Locally

```bash
git clone https://github.com/systemslibrarian/crypto-lab-bitcoin-wallet
cd crypto-lab-bitcoin-wallet
npm install
npm run dev
```

No environment variables, no API keys, no servers — everything runs client-side. The build bundles `@noble/secp256k1`, `@noble/hashes`, and the in-repo BIP-39 wordlist + QR-code encoder into a single static JS file deployed straight to GitHub Pages, with no remote services and no telemetry. Additional scripts: `npm run build` (tsc + production build to `dist/`), `npm run preview` (serve the built `dist/` locally), and `npm run test:e2e` (headless Chromium e2e + axe-core WCAG 2.2 a11y gate).

## Related Demos

- [crypto-lab-ecdsa-forge](https://systemslibrarian.github.io/crypto-lab-ecdsa-forge/) — secp256k1 ECDSA signing and nonce-reuse failures, the curve that spends Bitcoin.
- [crypto-lab-merkle-vault](https://systemslibrarian.github.io/crypto-lab-merkle-vault/) — SHA-256 Merkle trees and inclusion proofs.
- [crypto-lab-hash-zoo](https://systemslibrarian.github.io/crypto-lab-hash-zoo/) — the hash families behind addresses and checksums.
- [crypto-lab-babel-hash](https://systemslibrarian.github.io/crypto-lab-babel-hash/) — SHA-256, SHA3-256, and BLAKE3 with HMAC.
- [crypto-lab-curve-lens](https://systemslibrarian.github.io/crypto-lab-curve-lens/) — elliptic-curve fundamentals (Curve25519, P-256, ECDH).

---

*One of 120+ browser demos in the [Crypto Lab](https://crypto-lab.systemslibrarian.dev/) suite.*

*"So whether you eat or drink or whatever you do, do it all for the glory of God." — 1 Corinthians 10:31*
