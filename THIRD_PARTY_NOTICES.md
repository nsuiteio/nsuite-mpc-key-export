# Third-Party Notices

本ソフトウェアは以下のオープンソースライブラリを利用しています。各ライブラリの
ライセンス全文は各配布元を参照してください。

注意: バイナリを配布する場合は、本ファイルと各ライブラリのライセンス全文を
配布物へ同梱する必要があります（パッケージングへの組み込みは Issue #15 で対応
予定。現時点の Package App ワークフローは未同梱）。

## Go の主要な直接依存

| ライブラリ | ライセンス | 用途 |
|---|---|---|
| github.com/bnb-chain/tss-lib/v2 | MIT | MPC/VSS 復元・楕円曲線点演算 |
| github.com/decred/dcrd/dcrec/secp256k1/v4 | ISC | secp256k1（ECDSA）鍵操作 |
| github.com/decred/dcrd/dcrec/edwards/v2 | ISC | ed25519（EdDSA）鍵操作 |
| github.com/wailsapp/wails/v2 | MIT | デスクトップアプリフレームワーク |
| github.com/yeqown/go-qrcode/v2 | MIT | QR コード生成 |
| golang.org/x/crypto | BSD-3-Clause | argon2（パスワード鍵導出）・Keccak256 |

`replace` により `github.com/agl/ed25519` は
`github.com/binance-chain/edwards25519`（MIT）に置換されています。

依存の完全な一覧とバージョンは `go.mod` / `go.sum` を参照してください。
`go install github.com/google/go-licenses@latest` などで全推移依存の
ライセンスを機械的に確認できます。

## フロントエンドの主要な依存

| ライブラリ | ライセンス |
|---|---|
| svelte | MIT |
| sv-router | MIT |
| tailwindcss | MIT |
| vite | MIT |

完全な一覧は `frontend/package.json` / `frontend/package-lock.json` を参照。
