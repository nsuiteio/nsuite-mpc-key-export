<script>
    import {onDestroy} from 'svelte'
    import * as app from '../../wailsjs/go/main/App.js'
    import Fingerprint from '../components/Fingerprint.svelte'
    import {
        ClipboardGetText,
        ClipboardSetText,
    } from '../../wailsjs/runtime/runtime.js'

    // ---- Step 1: キーペアファイルの選択 ----
    let keyPairInfo = null // { fingerprint, filePath }
    let keyPairError = ''

    // ---- Step 2: 暗号化ウォレット秘密鍵ファイルの復号（root 鍵の復元） ----
    let restoring = false
    let restored = false
    let restoreError = ''

    // ---- Step 3: 導出・取り出し ----
    let keyType = 'ECDSA'

    // アドレス一覧（1ページ分）。8件ずつ前へ/次へでページングする。
    const PAGE_SIZE = 8
    let page = 0
    let addressList = [] // [{ index, address }]
    let listLoading = false
    let listError = ''
    // 一覧取得の古い応答を破棄するための連番。取り出し系のrequestSeqとは
    // 独立させ、選択操作のリセットが一覧の読み込みを打ち消さないようにする。
    let listSeq = 0

    // 一覧から選択したパラメータを固定し、秘密鍵の取得はこのスナップショット
    // だけを使う。選択後のページ移動やcurve切替が取得対象に影響しないようにする。
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
            resetList()
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
            resetList()
            resetDerived()
            await loadAddresses()
        } catch (e) {
            // キーペア不一致・復号失敗などはここに出る。
            // バックエンド側で復元済みroot鍵は破棄されているため、
            // 画面状態も復元前に戻す（成功表示とStep 3を残さない）。
            restored = false
            resetList()
            resetDerived()
            restoreError = String(e)
        } finally {
            restoring = false
        }
    }

    // 現在のcurve種別とページに対応するアドレス一覧を取得する。
    async function loadAddresses() {
        const seq = ++listSeq
        listLoading = true
        listError = ''
        try {
            const entries = await app.DeriveAddresses(
                keyType, page * PAGE_SIZE, PAGE_SIZE)
            if (seq !== listSeq) return // 切替後の古い応答は捨てる
            addressList = entries
        } catch (e) {
            if (seq !== listSeq) return
            addressList = []
            listError = String(e)
        } finally {
            if (seq === listSeq) listLoading = false
        }
    }

    // 一覧の行を選択して確認済みスナップショットを作る。
    // アドレスは一覧取得時の値をそのまま使い、取り出し時にバックエンドが
    // 再導出して一致を検証する（GetPrivateKeyのexpectedAddress突合）。
    function selectAddress(entry) {
        if (isSelected(confirmed, keyType, entry)) return // 再選択は無視
        resetDerived()
        confirmed = {keyType, index: entry.index, address: entry.address}
    }

    function isSelected(current, currentKeyType, entry) {
        return !!current &&
            current.keyType === currentKeyType &&
            current.index === entry.index
    }

    // curve種別の切替: 選択・取得済みの秘密鍵を破棄し、先頭ページから
    // 一覧を取り直す。
    function changeKeyType() {
        page = 0
        resetDerived()
        loadAddresses()
    }

    // HDPath indexの上限（int32の最大値。バックエンドと揃える）。
    const MAX_INDEX = 2147483647

    // ページ移動の共通処理。前ページで選択したアドレス・表示済みの秘密鍵を
    // 破棄し（進行中の取得もresetDerivedのrequestSeq++で無効化）、
    // 新しいページの一覧を取り直す。
    function changePage(delta) {
        if (listLoading) return
        const next = page + delta
        if (next < 0 || next * PAGE_SIZE > MAX_INDEX) return
        page = next
        resetDerived()
        loadAddresses()
    }

    // 一覧の状態を初期化し、進行中の取得を無効化する。
    function resetList() {
        addressList = []
        page = 0
        listError = ''
        listLoading = false
        listSeq++
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

    // 選択（curve / アドレス）が変わったら結果を無効化する。
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

    // 表示中ページのHDPath index範囲（例: #8〜#15）。
    $: rangeStart = page * PAGE_SIZE
    $: rangeEnd = rangeStart + PAGE_SIZE - 1
</script>

<div class="flex flex-col gap-6">
    <div>
        <h2 class="m-0 text-xl font-bold text-fore-black">
            ウォレット秘密鍵の復元
        </h2>
        <p class="mt-2 text-sm leading-relaxed text-fore-gray">
            取出用キーペアファイルと暗号化ウォレット秘密鍵ファイル（zip）の
            2 つのファイルを入力に、ウォレットの root
            鍵をメモリ上でのみ復元し、アドレスを確認したうえで秘密鍵を取り出します。
            復元結果はこのアプリのどこにも保存されず、終了するとすべて消えます。
        </p>
    </div>

    <div class="rounded-xl border border-informational-main
                bg-informational-light p-4 text-sm leading-relaxed
                text-fore-black">
        <strong>復元リハーサルとして使う場合:</strong>
        Step 3 のアドレス確認まで行い、導出されたアドレスが N Suite
        上のウォレットアドレスと一致すれば、暗号化ウォレット秘密鍵ファイル
        から正しく復元できることを確認できます。秘密鍵の表示までは
        行わずに終了してください。
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
                : 'text-fore-gray'}">ファイルの復号（root 鍵の復元）</span>
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
            Step 1. 取出用キーペアファイルを選択する
        </h3>
        <p class="mt-1 mb-4 text-xs leading-relaxed text-fore-gray">
            エクスポート準備担当者から受け取ったキーペアファイル
            （*.nstkey）を選択してください。
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
                    Fingerprint（キーペア生成時の記録と一致することを確認してください）
                </div>
                <Fingerprint
                    fingerprint={keyPairInfo.fingerprint}
                    id="keypair-fingerprint"/>
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
                Step 2. 暗号化ウォレット秘密鍵ファイルを選択して復号する
            </h3>
            <p class="mt-1 mb-4 text-xs leading-relaxed text-fore-gray">
                N Suite のエクスポートでダウンロードした暗号化ウォレット
                秘密鍵ファイル（zip）を選択してください。3 つの署名鍵
                （KeyShare）から root 鍵（ウォレット秘密鍵）を
                メモリ上に復元します。
            </p>
            <button
                class="cursor-pointer rounded-lg bg-brand-main px-5 py-2
                       text-sm font-bold text-fore-white transition
                       hover:bg-brand-dark disabled:cursor-not-allowed
                       disabled:opacity-50"
                disabled={restoring || busy} on:click={restoreFromZip}>
                {restoring ? '復号中...' : 'ファイルを選択して復号'}
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
                チェーンの種類を選び、一覧から取り出したいアドレスを選択して
                ください。選択したアドレスを確認してから秘密鍵を表示します。
            </p>

            <div class="flex items-center gap-3">
                <label class="w-32 text-sm text-fore-black" for="keyType">
                    チェーン種別
                </label>
                <select bind:value={keyType} id="keyType"
                        class="flex-1 rounded-md border border-fore-line
                               bg-fore-white px-3 py-2 text-sm
                               focus:border-brand-main focus:outline-none"
                        on:change={changeKeyType}>
                    <option value="ECDSA">ECDSA（EVM 系）</option>
                    <option value="EdDSA">EdDSA（Solana）</option>
                </select>
            </div>

            <div class="mt-4 rounded-md border border-fore-line">
                <div class="flex items-center justify-between border-b
                            border-fore-line bg-back-lightGray px-3 py-2">
                    <span class="text-xs font-bold text-fore-gray">
                        アドレス一覧（HDPath index #{rangeStart}〜#{rangeEnd}）
                    </span>
                    <div class="flex items-center gap-2">
                        <button
                            class="cursor-pointer rounded-md border
                                   border-fore-line bg-fore-white px-3 py-1
                                   text-xs text-fore-gray
                                   hover:border-brand-main
                                   hover:text-brand-main
                                   disabled:cursor-not-allowed
                                   disabled:opacity-50"
                            disabled={page === 0 || listLoading}
                            on:click={() => changePage(-1)}>
                            ← 前へ
                        </button>
                        <button
                            class="cursor-pointer rounded-md border
                                   border-fore-line bg-fore-white px-3 py-1
                                   text-xs text-fore-gray
                                   hover:border-brand-main
                                   hover:text-brand-main
                                   disabled:cursor-not-allowed
                                   disabled:opacity-50"
                            disabled={listLoading ||
                                (page + 1) * PAGE_SIZE > MAX_INDEX}
                            on:click={() => changePage(1)}>
                            次へ →
                        </button>
                    </div>
                </div>
                {#if listLoading}
                    <p class="m-0 px-3 py-4 text-sm text-fore-gray">
                        アドレスを導出中...
                    </p>
                {:else if listError}
                    <p class="m-0 break-all px-3 py-4 text-sm
                              text-critical-main">
                        {listError}
                    </p>
                {:else}
                    <ul class="m-0 list-none divide-y divide-fore-line p-0">
                        {#each addressList as entry (entry.index)}
                            <li>
                                <button
                                    class="flex w-full cursor-pointer
                                           items-center gap-3 border-0 px-3
                                           py-2 text-left text-sm transition
                                           {isSelected(confirmed, keyType, entry)
                                               ? 'bg-brand-light'
                                               : 'bg-fore-white hover:bg-back-lightGray'}"
                                    aria-pressed={isSelected(
                                        confirmed, keyType, entry)}
                                    on:click={() => selectAddress(entry)}>
                                    <span class="w-14 shrink-0 text-xs
                                                 text-fore-gray">
                                        #{entry.index}
                                    </span>
                                    <code class="break-all text-sm
                                                 text-fore-black">
                                        {entry.address}
                                    </code>
                                    {#if isSelected(confirmed, keyType, entry)}
                                        <span class="ml-auto shrink-0 text-xs
                                                     font-bold
                                                     text-brand-main">
                                            選択中
                                        </span>
                                    {/if}
                                </button>
                            </li>
                        {/each}
                    </ul>
                {/if}
            </div>

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
