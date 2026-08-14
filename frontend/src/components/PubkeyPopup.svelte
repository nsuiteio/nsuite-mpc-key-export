<script>
    import {ClipboardSetText} from '../../wailsjs/runtime/runtime.js'

    // GenerateKeyPair の単一レスポンス（qrImage / fingerprint / publicKeyHex）。
    // すべて同一の公開鍵に由来する値を受け取る。
    export let qrImage
    export let fingerprint
    export let pubkeyHex
    export let onClose

    let copiedValue = ''
    let copyError = ''

    async function copyPublicKeyHex() {
        copyError = ''
        try {
            // WebView の navigator.clipboard は環境により使えないため、
            // Wails ランタイムのクリップボード API を使う。
            const ok = await ClipboardSetText(pubkeyHex)
            if (ok === false) {
                throw new Error('clipboard write failed')
            }
            copiedValue = pubkeyHex
        } catch (e) {
            copyError = 'コピーに失敗しました。もう一度お試しください。'
        }
    }

    // 「Copied!」は現在表示中の公開鍵をコピーした場合のみ表示する
    // （鍵を再生成した後に古いコピー状態を引き継がない）。
    $: copied = copiedValue !== '' && copiedValue === pubkeyHex
</script>

<div class="overlay">
    <div class="popup">
        <button class="btn" on:click={onClose}>
            <img alt="QR code" id="qr" src="{qrImage}" width="200" height="200">
        </button>
        <div class="fingerprint">
            <p>Fingerprint（モバイルアプリの表示と一致することを確認してください）</p>
            <code>{fingerprint}</code>
        </div>
        <button class="btn" on:click={copyPublicKeyHex}>
            {copied ? 'Copied!' : 'Copy public key hex'}
        </button>
        {#if copyError}
            <p class="error">{copyError}</p>
        {/if}
    </div>
</div>

<style>
    .overlay {
        position: fixed;
        top: 0;
        left: 0;
        width: 100%;
        height: 100%;
        background-color: rgba(0, 0, 0, 0.5);
        display: flex;
        justify-content: center;
        align-items: center;
        z-index: 999;
    }

    .popup {
        display: flex;
        flex-direction: column;
        align-items: center;
        gap: 0.75rem;
    }

    .btn {
        line-height: 30px;
        border-radius: 3px;
        border: none;
        padding: 0 12px;
        cursor: pointer;
    }

    .btn:hover {
        background-image: linear-gradient(to top, #cfd9df 0%, #e2ebf0 100%);
        color: #333333;
    }

    .fingerprint {
        max-width: 420px;
        text-align: center;
        background-color: rgba(0, 0, 0, 0.7);
        border-radius: 4px;
        padding: 0.75rem;
    }

    .fingerprint p {
        margin: 0 0 0.5rem;
        font-size: 0.85rem;
    }

    .fingerprint code {
        font-family: monospace;
        word-break: keep-all;
    }

    .error {
        color: #ff6b6b;
        margin: 0;
    }
</style>
