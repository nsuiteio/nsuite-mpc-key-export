# Contributing

Developer documentation for `nst-mpc-key-export`. If you only want to *use* the
released applications, see [README.md](README.md) instead.

## Repository layout

| Path | Contents |
|---|---|
| `apps/keypair` | KeyPairGenerator: the Wails app used for export preparation |
| `apps/restore` | KeyRestore: the Wails app used to restore and extract keys |
| `service/` | Domain logic: `derive`, `exportpubkey`, `keypairfile`, `reconstruct` |
| `utility/` | Shared helpers: crypto, zip, QR, logging, secret handling, config |
| `internal/testfixture` | Test fixtures shared across packages |

Each app is a separate Wails binary with its own `wails.json` and its own Svelte
frontend under `apps/<app>/frontend`.

## Prerequisites

| Tool | Version | Source of truth |
|---|---|---|
| Go | 1.25.x | `go.mod` (`go` and `toolchain` directives) |
| Node.js | 22.x | not pinned; `wails build` invokes `npm` for the frontend |
| Task | 3.x | `arduino/setup-task` in the CI workflows |
| Wails CLI | v2.10 | installed by the `init-wails` task in `Taskfile.yml` |

Every command below runs through [Task](https://taskfile.dev/), so install it
first:

```sh
brew install go-task
# or, without Homebrew:
go install github.com/go-task/task/v3/cmd/task@latest
```

The Wails CLI does not need a separate step; the `init-wails` task installs it on
first use.

On Linux, Wails also needs GTK and WebKit development headers:

```sh
sudo apt-get install libgtk-3-dev libwebkit2gtk-4.0-dev
```

## Build, run, test

```sh
# Install the Wails CLI (first time only; also run automatically by the tasks)
go install github.com/wailsapp/wails/v2/cmd/wails@v2.10

# Build both apps
task build

# Build one app
task build-keypair
task build-restore

# Run one app in Wails dev mode (hot reload)
task run-keypair
task run-restore

# Build, then run the whole Go test suite
task test
```

Binaries land in `apps/keypair/build/bin/` and `apps/restore/build/bin/`.

Two notes that will bite you otherwise:

- **`apps/*/frontend/dist` is a build artifact and is not tracked in Git.** It is
  the target of a `go:embed` directive, so `go build` and `go test` fail until it
  exists. Run `task build`, or `npm install && npm run build` in each `frontend`
  directory, first.
- **The two apps cannot be built in parallel.** Wails writes its bindings
  generator to a fixed path (`$TMPDIR/wailsbindings`) and deletes it afterwards,
  so concurrent builds delete each other's temporary files. The `build` task uses
  sequential `cmds` rather than parallel `deps` for this reason; keep it that way.

## Formatting and linting

CI checks formatting with pinned tool versions. Match them locally:

```sh
go install golang.org/x/tools/cmd/goimports@v0.49.0
go install github.com/segmentio/golines@v0.13.0

golines --base-formatter=goimports --max-len=80 -w .
```

`--base-formatter=goimports` is not optional. `golines` picks its base formatter
by looking for `goimports` on `PATH` and silently falls back to `gofmt`, so
leaving it implicit makes the import-grouping check depend on the machine.
CI also runs `golangci-lint` v2.5.

## Key derivation test vectors

HD path derivation follows non-hardened BIP32 CKD and is verified against
published external vectors:

- ECDSA: BIP32 official test vector 1
- EdDSA: the public Fireblocks recovery vector

```sh
go test ./service/derive/...
```

`service/derive` exposes `DeriveECDSAPrivateKey` / `DeriveEdDSAPrivateKey` (and
the public-key counterparts) on `Key`, with `ECDSAChild` / `EdDSAChild` in
`highlevel.go` as the entry points that also compute the chaincode from the root
public key. Read the tests before changing anything here — the output of this
package is a private key that controls real assets.

## Continuous integration

`.github/workflows/ci.yml` runs on every pull request:

| Job | What it does |
|---|---|
| `format` | `golines --base-formatter=goimports --max-len=80 --dry-run .` must produce no output |
| `lint` | builds both apps, then `golangci-lint` v2.5 |
| `test` | builds both apps, then `go test -p 1 ./...` |

CI runs the tests with `-p 1` (one package at a time). Keep it unless you have
verified that the suite is safe to run concurrently.

`.github/workflows/package_app.yml` is a manual (`workflow_dispatch`) job that
builds macOS and Windows binaries and uploads them as workflow artifacts. Use it
to test a build without cutting a release.

## Branching and releases

- `develop` is the default branch. Open pull requests against it.
- Never push directly to `main` or `develop`.
- `main` only ever receives release branches.

To cut a release:

1. Run the **Release prepare** workflow (`workflow_dispatch`) with a version such
   as `v1.2.0`. It creates `release/v1.2.0` and opens a pull request into `main`.
2. Merge that pull request. **Release merged** (`release_merges.yml`) then builds
   macOS and Windows binaries, tags the version, merges `main` back into
   `develop`, and creates a **draft** GitHub release with
   `KeyExport-macOS.tar.gz` and `KeyExport-Windows.tar.gz` attached.
3. Review the draft release notes and publish the release manually.

The release binaries are **not code-signed or notarized**. Users have to bypass
Gatekeeper and SmartScreen on first launch; [README.md](README.md) documents how.

Two known gaps in the release pipeline, both verified against the v1.0.1 assets:

- **The macOS artifact is arm64 only, not universal.** The build matrix carries a
  `platform: 'darwin/universal'` value, but the build step runs `task build`,
  which never passes `-platform` to `wails build`. The matrix value is therefore
  unused, and the binary is whatever the `macos-latest` runner produces.
- **The macOS app bundle has no valid signature.** `wails build` applies the Go
  linker's ad-hoc signature to the executable only and does not seal the bundle,
  so `codesign --verify --strict` fails with `code has no resources but signature
  indicates they must be present`. With the quarantine flag set, Gatekeeper
  reports this as "damaged" rather than "unsigned", which is why the README tells
  users to clear quarantine instead of using right-click Open.

## Reporting security issues

Do not open a public issue for a vulnerability. See [SECURITY.md](SECURITY.md).
