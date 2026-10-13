# nst-mpc-key-export

English | [日本語](README.ja.md)

Two offline desktop applications for exporting and restoring the MPC wallet
private keys held in [N Suite](https://nsuite.io/). Neither application performs
any network communication.

Restoring a wallet private key requires **both** a key pair file and an encrypted
wallet private key file. The tools are designed around a 2-of-2 separation model:
**two different people hold the two files in two different places.**

## Two apps, two roles

| App | Intended user | Role |
|---|---|---|
| KeyPairGenerator | Export Preparer (A) | Generates the extraction key pair, saves it to a file, and hands the public key over |
| KeyRestore | Export Operator (B) | Restores and extracts the wallet private key from the encrypted wallet private key file and the key pair file |

- **Export Preparer (A)** generates and stores the extraction key pair.
- **Export Operator (B)** creates the encrypted wallet private key file in the
  N Suite mobile app, downloads it from N Board, and stores it.

## Download

Get the archive for your OS from the
[Releases](https://github.com/nsuiteio/nst-mpc-key-export/releases) page.

| File | OS |
|---|---|
| `KeyExport-macOS.tar.gz` | macOS (universal: Apple Silicon and Intel) |
| `KeyExport-Windows.tar.gz` | Windows (x64) |

**Both archives contain both apps.** After extracting, use only the app that
matches your role:

- Export Preparer (A) uses `KeyPairGenerator`
- Export Operator (B) uses `KeyRestore`

## First launch

From v1.0.2, the macOS apps are signed with a Developer ID and notarized by
Apple. The Windows binaries are not code-signed, so Windows will warn you the
first time you open them. **Verify what you downloaded before you open it**,
and on Windows before you bypass the warning: the same warning appears whether
the cause is the missing signature or a download that was genuinely corrupted or
tampered with, and these apps handle key material.

### Verify the download

1. Download only from the official releases page:
   <https://github.com/nsuiteio/nst-mpc-key-export/releases>
2. Compare the checksum of your archive against the digest GitHub publishes for
   that asset. The two values must match, ignoring the `sha256:` prefix.

```sh
# your download
shasum -a 256 KeyExport-macOS.tar.gz          # macOS
certutil -hashfile KeyExport-Windows.tar.gz SHA256   # Windows

# the published digest
gh api repos/nsuiteio/nst-mpc-key-export/releases/latest \
  --jq '.assets[] | "\(.name) \(.digest)"'
```

Without the `gh` CLI, read the same `digest` values from
`https://api.github.com/repos/nsuiteio/nst-mpc-key-export/releases/latest`.

**If the checksums do not match, stop. Do not open the app**, and report it as
described in [SECURITY.md](SECURITY.md).

### macOS

The first time you open an app, macOS asks whether you want to open an app
downloaded from the Internet. Choose **Open**.

You can also confirm the signature yourself. Both apps must report
`source=Notarized Developer ID` and the double jump.tokyo team ID `FS25FA38F2`:

```sh
spctl --assess --verbose=2 --type execute KeyPairGenerator.app
# KeyPairGenerator.app: accepted
# source=Notarized Developer ID
# origin=Developer ID Application: double jump.tokyo Inc. (FS25FA38F2)
```

**If macOS says the app is damaged, cannot be checked for malicious software,
or comes from an unidentified developer, stop.** A signed and notarized build
never shows these. Do not clear the quarantine flag or use right-click **Open**
to get past them; report it as described in [SECURITY.md](SECURITY.md).

### Windows

If SmartScreen shows "Windows protected your PC", choose **More info**, then
**Run anyway** — again, only after the checksum matches.

### Where to run them

These tools never talk to the network, but they handle key material. Running
them on a machine disconnected from any network is **recommended**.

## End-to-end flow

1. **Export preparation** (KeyPairGenerator): generate the extraction key pair
   and hand the extraction public key to the Export Operator.
2. **Create the encrypted wallet private key file** (N Suite mobile app): enter
   the extraction public key so the signing keys (KeyShares) are encrypted to it.
3. **Download** (N Board): download the encrypted wallet private key file (zip)
   and store it.
4. **Restore and extract** (KeyRestore): restore the wallet private key from the
   key pair file plus the encrypted wallet private key file.

## Terminology

- **Extraction key pair** — the RSA-2048 key pair used to extract a wallet
  private key. Once its public key is given to the N Suite mobile app, the
  signing keys (KeyShares) are encrypted to that public key. The Export Preparer
  stores it as a key pair file (`*.nstkey`).
- **Encrypted wallet private key file (zip)** — the encrypted signing keys
  (three parties: FRONT, RECTO, VERSO) downloaded from N Board. The Export
  Operator stores it. **Once downloaded, this file is the only artifact from
  which the wallet private key can be restored**; it cannot be downloaded again.
- **Wallet private key** — the key that directly controls assets (the root key
  and the child keys derived along an HD path). It can be restored only when both
  the encrypted wallet private key file and the key pair file are available.

The app interfaces are in Japanese. The corresponding labels are 取出用キーペア
(extraction key pair), 暗号化ウォレット秘密鍵ファイル (encrypted wallet private
key file), and ウォレット秘密鍵 (wallet private key).

## Using KeyPairGenerator

For the Export Preparer (A), to generate an extraction key pair.

- Generates an RSA-2048 extraction key pair and writes it only to the file you
  choose. The app itself persists nothing.
- Shows the public key as hex, as a QR code, and as a fingerprint
  (`hex(sha256(pubkeyBytes))`). Compare the fingerprint against the one shown in
  the Export Operator's mobile app, by eye, to detect a substituted public key.
- **The fingerprint defaults to the first 8 digits (for example `F570 C28F`), which
  are easy to read aloud; "全桁を表示" (show all digits) expands all 64.** The
  short form carries only 32 bits, so always use the full value for a rigorous
  comparison. The mobile app shows it the same way.
- The save dialog defaults to
  `nsuite-mpc-extraction-keypair-<short-fingerprint>.nstkey`. It shares its
  prefix and fingerprint segment with the encrypted wallet private key file
  (`nsuite-mpc-export-<short-fingerprint>.zip`), which helps you spot which two
  files belong together. Treat this as a hint, not proof: the short value is
  32 bits and files can be renamed by hand. Loading does not depend on the file
  name, so files saved under older names still open.
- You can select a previously saved key pair file to display its public key
  information again, for a second or later export.

### Why the key pair file is not encrypted

The key pair file is stored in the clear, in a small custom format with a header
(`*.nstkey`).

- A key pair alone does nothing. A wallet private key can only be restored once
  the encrypted wallet private key file is also present. The primary control is
  **separate custody by separate people.**
- For disaster-recovery material that gets used once, years later, the largest
  risk of loss is not an attacker but a forgotten password. Password encryption
  would trade away the availability that recovery depends on.

## Using KeyRestore

For the Export Operator (B), to restore and extract a wallet private key.

- Select the key pair file and the encrypted wallet private key file. The root key
  is reconstructed from the three signing keys **in memory only**. Nothing about
  the result is persisted; it is gone when the app exits.
- Choose the curve (ECDSA for EVM, EdDSA for Solana) and the HD path index,
  confirm the derived address, then extract the matching child private key for
  import into a wallet such as MetaMask. Private keys are masked by default, and
  a copied value is cleared from the clipboard after a short delay.
- **Restore rehearsal**: stop at the address check. If the derived address matches
  the wallet address in N Suite, you have proven the encrypted wallet private key
  file can still be restored, without ever displaying a private key.

## Storage and operational rules

- **Never keep the key pair file and the encrypted wallet private key file in the
  same storage or the same backup lineage.** Putting both on one shared drive,
  NAS, or cloud backup is the classic failure. Each holder should keep their file
  on offline media such as a USB drive.
- Anyone holding both files can restore the wallet private key, because the key
  pair is stored in the clear.
- **If one of the two files has leaked** and the wallet is still active in
  N Suite, export again with a new key pair, then destroy the previous
  generation's files. Re-exporting does not disable the old files on its own: it
  re-encrypts the same wallet key material to a new extraction key pair, so an
  old key pair file and an old encrypted file still work as a pair. What protects
  you is that the leaked file's counterpart no longer exists anywhere.
- **If both files have leaked**, treat the wallet private key as compromised.
  Re-exporting does not undo this, because the wallet keeps the same address and
  therefore the same underlying key. Move the assets to a new wallet.
- A lost key pair file is recoverable by exporting again while N Suite is still
  active. **Always complete a restore rehearsal, confirming the
  address matches, before you terminate your N Suite contract.** After
  termination, losing either file leaves no path to recovery.

## Critical security note

**Treat an extracted child private key as being exactly as sensitive as the root
key.**

For compatibility with existing addresses, N Suite derives HD paths using
non-hardened BIP32 CKD. The chaincode is computed deterministically from the root
public key, so if a single child private key leaks to a party that can learn the
root public key, the root private key follows from
`rootScalar = childScalar - Σ IL` — and with it every address in the group. This
property is inherent to how N Suite forms addresses (delta injection during MPC
signing), and these tools cannot switch to hardened derivation. The extraction
screen therefore requires you to acknowledge this warning before it will proceed.

## Offline by design

These tools ship with no HTTP client, no telemetry, and no auto-update; they run
fully offline. Key material — extraction private keys, plaintext signing keys,
restored results, and derived private keys — is never written to logs.

## License

[MIT License](LICENSE). For third-party library licenses, see
[THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md).

To report a security problem, see [SECURITY.md](SECURITY.md). To build from source
or contribute, see [CONTRIBUTING.md](CONTRIBUTING.md).
