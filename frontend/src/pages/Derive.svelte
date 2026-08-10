<script>
    import * as app from '../../wailsjs/go/main/App.js'

    let password = ''
    let keyType = 'ECDSA'
    let index = 0

    let address = ''
    let privateKey = ''
    let revealed = false
    let error = ''
    let copied = false

    let clearTimer = null

    // アドレスだけ先に導出して、取り出す前に宛先を確認できるようにする。
    async function deriveAddress() {
        reset()
        try {
            address = await app.DeriveAddress(password, keyType, Number(index))
        } catch (e) {
            error = String(e)
        }
    }

    // 秘密鍵を取り出す。既定はマスク表示で、明示操作で表示する。
    async function revealPrivateKey() {
        error = ''
        try {
            privateKey = await app.GetPrivateKey(password, keyType, Number(index))
            revealed = false
        } catch (e) {
            error = String(e)
        }
    }

    async function copyPrivateKey() {
        if (!privateKey) return
        try {
            await navigator.clipboard.writeText(privateKey)
            copied = true
            // クリップボードに残り続けないよう一定時間後にクリアする。
            if (clearTimer) clearTimeout(clearTimer)
            clearTimer = setTimeout(async () => {
                try {
                    await navigator.clipboard.writeText('')
                } catch (e) {
                    console.log(e)
                }
                copied = false
            }, 20000)
        } catch (e) {
            error = String(e)
        }
    }

    function reset() {
        address = ''
        privateKey = ''
        revealed = false
        error = ''
        copied = false
    }

    $: masked = privateKey
        ? privateKey.slice(0, 6) + '…'.repeat(4) + privateKey.slice(-4)
        : ''
</script>

<div class="derive">
    <div class="row">
        <label for="password">Password</label>
        <input autocomplete="off" bind:value={password} id="password" type="password"/>
    </div>

    <div class="row">
        <label for="keyType">Curve</label>
        <select bind:value={keyType} id="keyType" on:change={reset}>
            <option value="ECDSA">ECDSA (EVM)</option>
            <option value="EdDSA">EdDSA (Solana)</option>
        </select>
    </div>

    <div class="row">
        <label for="index">HDPath index</label>
        <input bind:value={index} id="index" type="number" min="0" step="1"/>
    </div>

    <button class="btn" on:click={deriveAddress}>Derive address</button>

    {#if address}
        <div class="result">
            <div class="label">Address</div>
            <code class="address">{address}</code>
        </div>

        <button class="btn" on:click={revealPrivateKey}>Extract private key</button>
    {/if}

    {#if privateKey}
        <div class="result">
            <div class="label">Private key</div>
            <code class="secret">{revealed ? privateKey : masked}</code>
            <div class="actions">
                <button class="btn small" on:click={() => (revealed = !revealed)}>
                    {revealed ? 'Hide' : 'Show'}
                </button>
                <button class="btn small" on:click={copyPrivateKey}>
                    {copied ? 'Copied (auto-clears)' : 'Copy'}
                </button>
            </div>
        </div>
    {/if}

    {#if error}
        <p class="error">{error}</p>
    {/if}
</div>

<style>
    .derive {
        display: flex;
        flex-direction: column;
        gap: 1rem;
        max-width: 640px;
        margin: 1.5rem auto;
        text-align: left;
    }

    .row {
        display: flex;
        align-items: center;
        gap: 0.75rem;
    }

    .row label {
        width: 120px;
    }

    .row input,
    .row select {
        flex: 1;
        min-width: 0;
        padding: 4px 8px;
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

    .btn.small {
        line-height: 24px;
    }

    .result {
        background-color: rgba(255, 255, 255, 0.08);
        border-radius: 4px;
        padding: 0.75rem;
    }

    .result .label {
        font-size: 0.8rem;
        opacity: 0.7;
        margin-bottom: 0.25rem;
    }

    .address,
    .secret {
        word-break: break-all;
        font-family: monospace;
    }

    .actions {
        display: flex;
        gap: 0.5rem;
        margin-top: 0.5rem;
    }

    .error {
        color: #ff6b6b;
        word-break: break-all;
    }
</style>
