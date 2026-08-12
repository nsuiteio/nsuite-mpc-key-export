# nst-mpc-key-export

N Suite の MPC 秘密鍵をエクスポートするためのオフライン専用ツールです。
[Wails](https://wails.io/) で動作します。

鍵管理者（Key Custodian）が、N Suite からダウンロードした暗号化 KeyShare zip を
オフライン環境で復号し、必要な秘密鍵を取り出すための最終工程を担います。

## 機能

- **Generate Key Pair**: エクスポート用の鍵ペア（RSA-2048）を生成し、公開鍵を QR
  コードで表示する。承認者のモバイルアプリがこの QR を読み取る。
- **Reconstruct**: N Suite からの暗号化 zip（FRONT/RECTO/VERSO の 3 パーティ分）を
  復号用秘密鍵で復号し、ECDSA / EdDSA の root 鍵を復元してローカルに保存する。
- **Derive**: 復元済み root 鍵から、curve 種別（ECDSA=EVM / EdDSA=Solana）と HDPath
  index を指定して個別アドレスの秘密鍵を取り出す（MetaMask 等へのインポート用）。
  取り出し前にアドレスだけを先に導出して宛先を確認でき、秘密鍵は既定でマスク表示、
  クリップボードへコピーした場合は一定時間後に自動クリアする。

## セキュリティ上の重要な注意

**取り出した子秘密鍵は root 鍵と同等の機密として扱ってください。**

N Suite の HDPath 導出は、既存アドレスとの互換性のため非 hardened の BIP32 CKD を
使用しています。chaincode は root 公開鍵から決定的に計算されるため、root 公開鍵を
知り得る主体に子秘密鍵が 1 つでも漏洩すると、`rootScalar = childScalar - Σ IL` に
より root 秘密鍵（＝同グループの全アドレスの秘密鍵）が復元可能です。これは
N Suite のアドレス体系（MPC 署名時の delta 注入方式）に固有の性質であり、本ツール
側で hardened 導出へ変更することはできません。Derive 画面では取り出し前にこの
警告への同意を必須にしています。

## オフライン動作

本ツールは HTTP クライアント・テレメトリ・自動更新を一切持たず、完全にオフラインで
動作します。鍵素材（エクスポート用秘密鍵・KeyShare 平文・復号結果・導出した秘密鍵）
はログに出力しません。

## 鍵導出の検証

HDPath 導出は BIP32 CKD（非 hardened）に基づき、外部の公開テストベクタで検証して
います。

- ECDSA: BIP32 公式テストベクタ 1
- EdDSA: Fireblocks recovery の公開ベクタ

```sh
go test ./service/derive/...
```

## ビルド手順（再現性）

想定バージョン（`go.mod` に固定）:

- Go: 1.25 系（`go.mod` の `go` / `toolchain` を正とする）
- Node.js: 22 系
- Wails CLI: v2.10（`Taskfile.yml` の `init-wails` が `@v2.10` を導入）

```sh
# Wails CLI の導入（初回のみ）
go install github.com/wailsapp/wails/v2/cmd/wails@v2.10

# フロントエンドの依存導入とビルド、アプリのビルド
task build          # 内部で wails build を実行（frontend/dist を生成）

# テスト
task test           # ビルド後に go test ./... を実行
```

`frontend/dist` はビルド生成物のため Git 管理対象外です（`go:embed` の対象なので
`go build` / `go test` の前に `wails build` もしくは
`cd frontend && npm install && npm run build` が必要）。

## ライセンス

[MIT License](LICENSE)。第三者ライブラリのライセンスは
[THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md) を参照してください。
