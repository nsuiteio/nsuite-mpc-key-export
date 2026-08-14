<script>
    import {onDestroy} from 'svelte'
    import * as app from '../../wailsjs/go/main/App.js'

    let password = ''
    let keyType = 'ECDSA'
    let index = 0

    // アドレス確認時のパラメータを固定し、秘密鍵の取得はこのスナップショット
    // だけを使う。入力欄の後からの変更が取得対象に影響しないようにする。
    let confirmed = null // { password, keyType, index, address }

    let privateKey = ''
    let revealed = false
    let acknowledged = false
    let error = ''
    let copied = false
    let clipboardWarning = ''

    // 古い非同期応答を破棄するためのリクエスト連番。
    let requestSeq = 0

    let clearTimer = null
    // コピー操作の世代番号。古いコピーの消去処理が新しいコピーの追跡値を
    // 上書きしないよう、消去関数には値と世代を引数で渡す。
    let copyGen = 0
    // ページ破棄時の即時消去に使う「最後にコピーした値」。
    let lastCopied = ''

    async function deriveAddress() {
        reset()
        const seq = ++requestSeq
        const params = {password, keyType, index: Number(index)}
        try {
            const address = await app.DeriveAddress(
                params.password, params.keyType, params.index)
            if (seq !== requestSeq) return // 入力が変わった後の古い応答は捨てる
            confirmed = {...params, address}
        } catch (e) {
            if (seq !== requestSeq) return
            error = String(e)
        }
    }

    // 秘密鍵の取得は confirmed のパラメータのみを使う。
    async function revealPrivateKey() {
        if (!confirmed) return
        error = ''
        privateKey = '' // 失敗時に以前の鍵が残らないよう先にクリア
        revealed = false
        const seq = ++requestSeq
        try {
            // 確認済みアドレスをバックエンドに渡し、導出結果との一致を
            // サーバー側でも検証する（確認後の root 鍵差し替え対策）。
            const key = await app.GetPrivateKey(
                confirmed.password, confirmed.keyType, confirmed.index,
                confirmed.address)
            if (seq !== requestSeq) return
            privateKey = key
        } catch (e) {
            if (seq !== requestSeq) return
            error = String(e)
        }
    }

    async function copyPrivateKey() {
        if (!privateKey) return
        clipboardWarning = ''
        // writeText の待機中に reset 等で privateKey が変わっても消去対象を
        // 見失わないよう、コピーする値をローカル定数に固定する。
        const value = privateKey
        const gen = ++copyGen
        try {
            await navigator.clipboard.writeText(value)
            lastCopied = value
            copied = true
            if (clearTimer) clearTimeout(clearTimer)
            clearTimer = setTimeout(
                () => clearClipboardIfUnchanged(value, gen), 20000)
        } catch (e) {
            error = String(e)
        }
    }

    // コピーした秘密鍵がクリップボードに残っている場合だけ消去する。
    // 利用者が別の内容をコピーしていた場合はそれを壊さない。
    // 値と世代を引数で受けるため、後続のコピーと状態を共有しない。
    async function clearClipboardIfUnchanged(value, gen) {
        if (gen === copyGen) copied = false
        try {
            const current = await navigator.clipboard.readText()
            if (current === value) {
                await navigator.clipboard.writeText('')
            }
            if (gen === copyGen) lastCopied = ''
        } catch (e) {
            if (gen === copyGen) {
                clipboardWarning =
                    'クリップボードの自動クリアに失敗しました。' +
                    '手動で別の内容をコピーするなどしてクリアしてください。'
            }
        }
    }

    // 入力（password / curve / index）が変わったら結果を無効化する。
    function reset() {
        confirmed = null
        privateKey = ''
        revealed = false
        acknowledged = false
        error = ''
        copied = false
        clipboardWarning = ''
        requestSeq++
    }

    // ページ離脱時は画面上の秘密情報を破棄し、処理中の応答を無効化する。
    // コピー済みの秘密鍵が残っていれば、タイマーを待たずに即時消去を試みる。
    onDestroy(() => {
        if (clearTimer) clearTimeout(clearTimer)
        requestSeq++
        copyGen++
        confirmed = null
        privateKey = ''
        password = ''
        if (lastCopied) {
            const value = lastCopied
            lastCopied = ''
            clearClipboardIfUnchanged(value, copyGen).catch(() => {})
        }
    })

    $: masked = privateKey
        ? privateKey.slice(0, 6) + '…'.repeat(4) + privateKey.slice(-4)
        : ''
</script>

<div class="derive">
    <div class="row">
        <label for="password">Password</label>
        <input autocomplete="off" bind:value={password} id="password"
               type="password" on:input={reset}/>
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
        <input bind:value={index} id="index" type="number" min="0" step="1"
               on:input={reset}/>
    </div>

    <button class="btn" on:click={deriveAddress}>Derive address</button>

    {#if confirmed}
        <div class="result">
            <div class="label">
                Address ({confirmed.keyType} / index {confirmed.index})
            </div>
            <code class="address">{confirmed.address}</code>
        </div>

        <div class="warning">
            <p>
                この秘密鍵は非 hardened 導出のため、漏洩すると root
                鍵（このグループの全アドレスの秘密鍵）の復元につながります。
                root 鍵と同等の機密として扱ってください。
            </p>
            <label>
                <input type="checkbox" bind:checked={acknowledged}/>
                理解した上で取り出します
            </label>
        </div>

        <button class="btn" disabled={!acknowledged}
                on:click={revealPrivateKey}>
            Extract private key
        </button>
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

    {#if clipboardWarning}
        <p class="error">{clipboardWarning}</p>
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

    .btn:disabled {
        opacity: 0.5;
        cursor: not-allowed;
    }

    .btn:hover:not(:disabled) {
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

    .warning {
        background-color: rgba(255, 180, 0, 0.12);
        border: 1px solid rgba(255, 180, 0, 0.5);
        border-radius: 4px;
        padding: 0.75rem;
        font-size: 0.9rem;
    }

    .warning p {
        margin: 0 0 0.5rem;
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
