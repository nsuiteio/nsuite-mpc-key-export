<script>
    import {onDestroy} from 'svelte'
    import * as app from '../../wailsjs/go/main/App.js'
    import {
        ClipboardGetText,
        ClipboardSetText,
    } from '../../wailsjs/runtime/runtime.js'

    // ---- Step 1: キーペアファイルの選択 ----
    let keyPairInfo = null // { fingerprint, publicKeyHex, filePath }
    let keyPairError = ''

    // ---- Step 2: zip の復号（root 鍵の復元） ----
    let restoring = false
    let restored = false
    let restoreError = ''

    // ---- Step 3: 導出・取り出し ----
    let keyType = 'ECDSA'
    let index = 0

    // アドレス確認時のパラメータを固定し、秘密鍵の取得はこのスナップショット
    // だけを使う。入力欄の後からの変更が取得対象に影響しないようにする。
    let confirmed = null // { keyType, index, address }

    let privateKey = ''
    let revealed = false
    let acknowledged = false
    let error = ''
    let copied = false
    let clipboardWarning = ''
    let busy = false

    // 古い非同期応答を破棄するためのリクエスト連番。
    let requestSeq = 0

    let clearTimer = null
    // コピー操作の世代番号。古いコピーの消去処理が新しいコピーの追跡値を
    // 上書きしないよう、消去関数には値と世代を引数で渡す。
    let copyGen = 0
    // ページ破棄時の即時消去に使う「最後にコピーした値」。
    let lastCopied = ''

    async function chooseKeyPairFile() {
        if (busy || restoring) return
        busy = true
        keyPairError = ''
        try {
            // 選択キャンセルは null が返る。何もしない。
            const info = await app.ChooseKeyPairFile()
            if (!info) return
            keyPairInfo = info
            // キーペアを選び直すとバックエンド側で復元セッションが
            // リセットされるため、画面状態も合わせてリセットする。
            restored = false
            restoreError = ''
            resetDerived()
        } catch (e) {
            // キーペア以外のファイルを選んだ場合などはここに出る。
            keyPairError = String(e)
        } finally {
            busy = false
        }
    }

    async function restoreFromZip() {
        if (busy || restoring) return
        restoring = true
        restoreError = ''
        try {
            // ファイル選択ダイアログをキャンセルした場合は空文字が返る。
            // その場合は何もしない（エラー表示もしない）。
            const result = await app.ChooseKeyShares()
            if (result !== 'OK') return
            restored = true
            resetDerived()
        } catch (e) {
            // キーペア不一致・zip 復号失敗などはここに出る。
            restoreError = String(e)
        } finally {
            restoring = false
        }
    }

    async function deriveAddress() {
        resetDerived()
        const seq = ++requestSeq
        const params = {keyType, index: Number(index)}
        try {
            const address = await app.DeriveAddress(
                params.keyType, params.index)
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
                confirmed.keyType, confirmed.index, confirmed.address)
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
            // WebView の navigator.clipboard は環境により使えないため、
            // Wails ランタイムのクリップボード API を使う（読み書き統一。
            // 書き込みだけ成功して自動消去が失敗する片肺状態を防ぐ）。
            const ok = await ClipboardSetText(value)
            if (ok === false) throw new Error('clipboard write failed')
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
            const current = await ClipboardGetText()
            if (current === value) {
                const ok = await ClipboardSetText('')
                if (ok === false) throw new Error('clipboard clear failed')
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

    // 入力（curve / index）が変わったら結果を無効化する。
    function resetDerived() {
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
        if (lastCopied) {
            const value = lastCopied
            lastCopied = ''
            clearClipboardIfUnchanged(value, copyGen).catch(() => {})
        }
    })

    $: masked = privateKey
        ? privateKey.slice(0, 6) + '…'.repeat(4) + privateKey.slice(-4)
        : ''

    // HDPath index は非負整数のみ許可（空値・負数・小数は導出ボタンを無効化。
    // バックエンドでも index < 0 は拒否されるが、誤操作を入力段階で防ぐ）。
    $: indexValid = index !== '' && index !== null &&
        Number.isInteger(Number(index)) && Number(index) >= 0
</script>

<div class="flex flex-col gap-6">
    <div>
        <h2 class="m-0 text-xl font-bold text-fore-black">
            ウォレット秘密鍵の復元
        </h2>
        <p class="mt-2 text-sm leading-relaxed text-fore-gray">
            受取用キーペアファイルとエクスポート zip の 2
            つのファイルを入力に、ウォレットの root
            鍵をメモリ上でのみ復元し、アドレスを確認したうえで秘密鍵を取り出します。
            復元結果はこのアプリのどこにも保存されず、終了するとすべて消えます。
        </p>
    </div>

    <div class="rounded-xl border border-informational-main
                bg-informational-light p-4 text-sm leading-relaxed
                text-fore-black">
        <strong>バックアップ検証として使う場合:</strong>
        Step 3 のアドレス確認まで行い、導出されたアドレスが N Suite
        上のウォレットアドレスと一致することを確認できれば、バックアップは
        正しく復元可能です。秘密鍵の表示までは行わずに終了してください。
    </div>

    <!-- ステップ表示 -->
    <div class="flex items-center gap-3 text-sm">
        <div class="flex items-center gap-2">
            <span class="flex h-7 w-7 items-center justify-center rounded-full
                         font-bold text-fore-white
                         {keyPairInfo ? 'bg-success-main' : 'bg-brand-main'}">
                {keyPairInfo ? '✓' : '1'}
            </span>
            <span class="{!keyPairInfo ? 'font-bold text-fore-black'
                : 'text-fore-gray'}">キーペアファイル</span>
        </div>
        <span class="h-px w-8 bg-fore-line"></span>
        <div class="flex items-center gap-2">
            <span class="flex h-7 w-7 items-center justify-center rounded-full
                         font-bold text-fore-white
                         {restored ? 'bg-success-main' : keyPairInfo
                             ? 'bg-brand-main' : 'bg-fore-lightGray'}">
                {restored ? '✓' : '2'}
            </span>
            <span class="{keyPairInfo && !restored
                ? 'font-bold text-fore-black'
                : 'text-fore-gray'}">zip の復号（root 鍵の復元）</span>
        </div>
        <span class="h-px w-8 bg-fore-line"></span>
        <div class="flex items-center gap-2">
            <span class="flex h-7 w-7 items-center justify-center rounded-full
                         font-bold text-fore-white
                         {restored ? 'bg-brand-main' : 'bg-fore-lightGray'}">
                3
            </span>
            <span class="{restored ? 'font-bold text-fore-black'
                : 'text-fore-gray'}">アドレス確認と取り出し</span>
        </div>
    </div>

    <!-- Step 1 -->
    <div class="rounded-xl border border-fore-line bg-fore-white p-6 shadow-sm">
        <h3 class="m-0 text-base font-bold text-fore-black">
            Step 1. 受取用キーペアファイルを選択する
        </h3>
        <p class="mt-1 mb-4 text-xs leading-relaxed text-fore-gray">
            キーペア担当者から受け取ったキーペアファイル（*.nstkey）を
            選択してください。
        </p>
        <button
            class="cursor-pointer rounded-lg bg-brand-main px-5 py-2
                   text-sm font-bold text-fore-white transition
                   hover:bg-brand-dark disabled:cursor-not-allowed
                   disabled:opacity-50"
            disabled={busy || restoring} on:click={chooseKeyPairFile}>
            {busy ? '読込中...' : 'キーペアファイルを選択'}
        </button>
        {#if keyPairInfo}
            <div class="mt-4 rounded-md bg-back-lightGray p-3">
                <div class="text-xs font-bold text-fore-gray">
                    ファイル
                </div>
                <code class="break-all text-xs">{keyPairInfo.filePath}</code>
                <div class="mt-2 text-xs font-bold text-fore-gray">
                    Fingerprint（鍵ペア生成時の記録と一致することを確認してください）
                </div>
                <code class="break-all text-sm">{keyPairInfo.fingerprint}</code>
            </div>
        {/if}
        {#if keyPairError}
            <p class="mt-3 break-all text-sm text-critical-main">
                {keyPairError}
            </p>
        {/if}
    </div>

    <!-- Step 2 -->
    {#if keyPairInfo}
        <div class="rounded-xl border border-fore-line bg-fore-white p-6
                    shadow-sm">
            <h3 class="m-0 text-base font-bold text-fore-black">
                Step 2. エクスポートした zip を選択して復号する
            </h3>
            <p class="mt-1 mb-4 text-xs leading-relaxed text-fore-gray">
                N Suite のエクスポートでダウンロードした zip
                ファイルを選択してください。3 つの KeyShare から root
                鍵をメモリ上に復元します。
            </p>
            <button
                class="cursor-pointer rounded-lg bg-brand-main px-5 py-2
                       text-sm font-bold text-fore-white transition
                       hover:bg-brand-dark disabled:cursor-not-allowed
                       disabled:opacity-50"
                disabled={restoring || busy} on:click={restoreFromZip}>
                {restoring ? '復号中...' : 'zip ファイルを選択して復号'}
            </button>
            {#if restored}
                <p class="mt-3 text-sm text-fore-black">
                    ✓ root 鍵を復元しました。続けてアドレスを確認してください。
                </p>
            {/if}
            {#if restoreError}
                <p class="mt-3 break-all text-sm text-critical-main">
                    {restoreError}
                </p>
            {/if}
        </div>
    {/if}

    <!-- Step 3 -->
    {#if restored}
        <div class="rounded-xl border border-fore-line bg-fore-white p-6
                    shadow-sm">
            <h3 class="m-0 text-base font-bold text-fore-black">
                Step 3. アドレスを確認して秘密鍵を取り出す
            </h3>
            <p class="mt-1 mb-4 text-xs leading-relaxed text-fore-gray">
                チェーンの種類と HDPath index を指定してアドレスを導出し、
                取り出したいアドレスと一致することを確認してから秘密鍵を表示します。
            </p>

            <div class="flex flex-col gap-3">
                <div class="flex items-center gap-3">
                    <label class="w-32 text-sm text-fore-black" for="keyType">
                        チェーン種別
                    </label>
                    <select bind:value={keyType} id="keyType"
                            class="flex-1 rounded-md border border-fore-line
                                   bg-fore-white px-3 py-2 text-sm
                                   focus:border-brand-main focus:outline-none"
                            on:change={resetDerived}>
                        <option value="ECDSA">ECDSA（EVM 系）</option>
                        <option value="EdDSA">EdDSA（Solana）</option>
                    </select>
                </div>

                <div class="flex items-center gap-3">
                    <label class="w-32 text-sm text-fore-black" for="index">
                        HDPath index
                    </label>
                    <input bind:value={index} id="index" type="number" min="0"
                           step="1"
                           class="flex-1 rounded-md border border-fore-line
                                  px-3 py-2 text-sm focus:border-brand-main
                                  focus:outline-none"
                           on:input={resetDerived}/>
                </div>
            </div>

            <button
                class="mt-4 cursor-pointer rounded-lg bg-brand-main px-5 py-2
                       text-sm font-bold text-fore-white transition
                       hover:bg-brand-dark disabled:cursor-not-allowed
                       disabled:opacity-50"
                disabled={!indexValid} on:click={deriveAddress}>
                アドレスを導出する
            </button>
            {#if !indexValid}
                <p class="mt-2 text-xs text-critical-main">
                    HDPath index には 0 以上の整数を入力してください。
                </p>
            {/if}

            {#if confirmed}
                <div class="mt-4 rounded-md bg-back-lightGray p-3">
                    <div class="text-xs font-bold text-fore-gray">
                        アドレス（{confirmed.keyType} / index {confirmed.index}）
                    </div>
                    <code class="break-all text-sm">{confirmed.address}</code>
                </div>

                <div class="mt-4 rounded-md border border-warning-main
                            bg-warning-light p-4 text-sm">
                    <p class="m-0 leading-relaxed">
                        この秘密鍵は非 hardened 導出のため、漏洩すると root
                        鍵（このグループの全アドレスの秘密鍵）の復元につながります。
                        root 鍵と同等の機密として扱ってください。
                    </p>
                    <label class="mt-2 flex items-center gap-2">
                        <input type="checkbox" bind:checked={acknowledged}/>
                        理解した上で取り出します
                    </label>
                </div>

                <button
                    class="mt-4 cursor-pointer rounded-lg bg-brand-main px-5
                           py-2 text-sm font-bold text-fore-white transition
                           hover:bg-brand-dark disabled:cursor-not-allowed
                           disabled:opacity-50"
                    disabled={!acknowledged} on:click={revealPrivateKey}>
                    秘密鍵を取り出す
                </button>
            {/if}

            {#if privateKey}
                <div class="mt-4 rounded-md bg-back-lightGray p-3">
                    <div class="text-xs font-bold text-fore-gray">秘密鍵</div>
                    <code class="break-all text-sm">
                        {revealed ? privateKey : masked}
                    </code>
                    <div class="mt-2 flex gap-2">
                        <button
                            class="cursor-pointer rounded-md border
                                   border-fore-line bg-fore-white px-3 py-1
                                   text-xs text-fore-gray
                                   hover:border-brand-main
                                   hover:text-brand-main"
                            on:click={() => (revealed = !revealed)}>
                            {revealed ? '隠す' : '表示する'}
                        </button>
                        <button
                            class="cursor-pointer rounded-md border
                                   border-fore-line bg-fore-white px-3 py-1
                                   text-xs text-fore-gray
                                   hover:border-brand-main
                                   hover:text-brand-main"
                            on:click={copyPrivateKey}>
                            {copied ? 'コピーしました（20秒後に自動クリア）'
                                : 'コピー'}
                        </button>
                    </div>
                </div>
            {/if}

            {#if clipboardWarning}
                <p class="mt-3 break-all text-sm text-critical-main">
                    {clipboardWarning}
                </p>
            {/if}

            {#if error}
                <p class="mt-3 break-all text-sm text-critical-main">{error}</p>
            {/if}
        </div>
    {/if}
</div>
