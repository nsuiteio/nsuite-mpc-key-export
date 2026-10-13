# Security Policy

## Reporting a vulnerability

**Please do not open a public issue for a security vulnerability.**

Use GitHub's private vulnerability reporting on this repository: open the
**Security** tab and choose **Report a vulnerability**. If that is unavailable to
you, email <devel@nsuite.io> instead.

Please include:

- which application is affected (KeyPairGenerator or KeyRestore) and its version
- the operating system you observed it on
- steps to reproduce, and the impact you believe it has

**Never include real key material in a report.** That means no key pair files
(`*.nstkey`), no encrypted wallet private key files, no private keys, and no
extraction private keys. If a reproduction needs key material, generate a
throwaway key pair for the purpose.

We aim to acknowledge a report within five business days.

## Scope

In scope:

- the two applications in this repository, KeyPairGenerator and KeyRestore
- the key derivation, reconstruction, and file format logic under `service/` and
  `utility/`
- the release workflows in `.github/workflows/`

Out of scope, because they are documented design decisions rather than defects:

- **Non-hardened HD derivation.** A single leaked child private key allows the
  root private key to be recovered by a party that knows the root public key. This
  is inherent to how N Suite forms addresses and cannot be changed in these tools.
  See "Critical security note" in [README.md](README.md).
- **Unencrypted key pair files.** `*.nstkey` files are stored in the clear on
  purpose; separate custody by separate people is the control, and password
  encryption would trade away recovery availability. See "Why the key pair file is
  not encrypted" in [README.md](README.md).
- **Unsigned Windows binaries.** The Windows archive is not code-signed, so users
  must get past SmartScreen on first launch. (A macOS build that Gatekeeper
  blocks *is* in scope: from v1.0.2 the macOS apps are signed and notarized.)
- The N Suite platform itself, N Board, and the N Suite mobile app. Report issues
  in those to <devel@nsuite.io>.

## Supported versions

Only the latest published release receives fixes. See
[Releases](https://github.com/nsuiteio/nst-mpc-key-export/releases).
