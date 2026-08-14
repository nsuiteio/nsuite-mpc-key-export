<script>
    import * as app from '../../wailsjs/go/main/App.js'
    import {onMount} from "svelte";

    let password
    let qrImage
    let fingerprint = ''
    let pubkeyHex = ''
    let pubkeyCopied = false
    let error = ''
    let showPopup = false
    let isGenerated = false

    onMount(async () => {
        try {
            isGenerated = await app.CheckKeyPair()
        } catch (e) {
            console.log(e)
        }
    })

    async function genKeyPair() {
        error = ''
        try {
            qrImage = await app.GenerateKeyPair(password, true)
            // 承認者のモバイルアプリに表示される値と目視照合するための
            // フィンガープリント（4文字区切り・大文字）。
            fingerprint = await app.GetKeyPairFingerprint(password)
            // カメラが使えない環境向けに、モバイル側のテキスト入力欄へ
            // 貼り付けるための公開鍵 hex（QR ペイロードと同一）。
            pubkeyHex = await app.GetPublicKeyHex(password)
            showPopup = true
            isGenerated = true
        } catch (e) {
            // エラーを画面に表示する（パスワード未入力・鍵ペア重複など）。
            error = String(e)
        }
    }

    async function copyPublicKeyHex() {
        if (!pubkeyHex) return
        try {
            await navigator.clipboard.writeText(pubkeyHex)
            pubkeyCopied = true
        } catch (e) {
            console.log(e)
        }
    }

    function closePopup() {
        showPopup = false
    }
</script>

{#if isGenerated}
    <div>
        <h1>Key Pair Generated</h1>
    </div>
{:else}
    <div class="input-box" id="input">
        <div>
            <label for="password">Password</label>
            <input autocomplete="off" bind:value={password} class="input" id="password" type="password"/>
        </div>
        <button class="btn" on:click={genKeyPair}>Generate Key Pair</button>
    </div>
{/if}

{#if error}
    <p class="error">{error}</p>
{/if}

{#if showPopup}
    <div class="overlay">
        <div class="popup">
            <button class="btn" on:click={closePopup}>
                <img alt="QR code" id="qr" src="{qrImage}" width="200" height="200">
            </button>
            <div class="fingerprint">
                <p>Fingerprint（モバイルアプリの表示と一致することを確認してください）</p>
                <code>{fingerprint}</code>
            </div>
            <button class="btn" on:click={copyPublicKeyHex}>
                {pubkeyCopied ? 'Copied!' : 'Copy public key hex'}
            </button>
        </div>
    </div>
{/if}


<style>
    .error {
        color: #ff6b6b;
        max-width: 640px;
        margin: 1rem auto;
        word-break: break-all;
    }

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
</style>
