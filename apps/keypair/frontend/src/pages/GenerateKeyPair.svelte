<script>
    import * as app from '../../wailsjs/go/main/App.js'
    import PubkeyPopup from '../components/PubkeyPopup.svelte'

    let keyPair = null // GeneratedKeyPair（生成 or 再表示の結果）
    let showPopup = false
    let busy = false
    let error = ''

    async function genKeyPair() {
        if (busy) return
        busy = true
        error = ''
        try {
            // 生成した鍵はユーザーが選んだファイルにのみ保存される。
            // 保存ダイアログをキャンセルした場合は null が返り、
            // 鍵はどこにも残らない。
            const result = await app.GenerateKeyPair()
            if (!result) return
            keyPair = result
            showPopup = true
        } catch (e) {
            error = String(e)
        } finally {
            busy = false
        }
    }

    async function showKeyPairFile() {
        if (busy) return
        busy = true
        error = ''
        try {
            // 選択キャンセルは null が返る。何もしない。
            const result = await app.ShowKeyPairFile()
            if (!result) return
            keyPair = result
            showPopup = true
        } catch (e) {
            // キーペア以外のファイルを選んだ場合などはここに出る。
            error = String(e)
        } finally {
            busy = false
        }
    }

    function closePopup() {
        showPopup = false
    }
</script>

<div class="flex flex-col gap-6">
    <div>
        <h2 class="m-0 text-xl font-bold text-fore-black">
            エクスポート準備（取出用キーペアの生成）
        </h2>
        <p class="mt-2 text-sm leading-relaxed text-fore-gray">
            秘密鍵の取り出しに使う取出用キーペアを生成し、
            キーペアファイルとして保存します。生成後に表示される
            取出用公開鍵をエクスポート実行者に渡し、N Suite
            モバイルアプリの MPC秘密鍵のエクスポート画面で
            入力してもらうと、署名鍵（KeyShare）がこの公開鍵で
            暗号化されます。
        </p>
    </div>

    <div class="rounded-xl border border-warning-main bg-warning-light p-4
                text-sm leading-relaxed text-fore-black">
        <strong>保管ルール:</strong>
        キーペアファイルは暗号化されていません。暗号化ウォレット秘密鍵
        ファイル（zip）とは別の担当者が、別のストレージ
        （オフラインメディア推奨）で保管してください。キーペアファイルと
        暗号化ウォレット秘密鍵ファイルの両方が揃うと、
        ウォレット秘密鍵を復元できます。
    </div>

    <div class="rounded-xl border border-fore-line bg-fore-white p-6
                shadow-sm">
        <h3 class="m-0 text-base font-bold text-fore-black">
            新しいキーペアを生成する
        </h3>
        <p class="mt-1 mb-4 text-xs leading-relaxed text-fore-gray">
            生成したキーペアは、保存先を選択したファイルにのみ書き出されます。
            このアプリ自体は何も記憶しません。ファイルを失うと、
            その公開鍵で作成した暗号化ウォレット秘密鍵ファイルは
            復号できなくなります（ウォレットが N Suite で稼働中であれば、
            新しいキーペアで再エクスポートすれば暗号化ウォレット秘密鍵
            ファイルを作り直せます）。
        </p>
        <button
            class="cursor-pointer rounded-lg bg-brand-main px-5 py-2
                   text-sm font-bold text-fore-white transition
                   hover:bg-brand-dark disabled:cursor-not-allowed
                   disabled:opacity-50"
            disabled={busy} on:click={genKeyPair}>
            {busy ? '処理中...' : 'キーペアを生成してファイルに保存'}
        </button>
    </div>

    <div class="rounded-xl border border-fore-line bg-fore-white p-6
                shadow-sm">
        <h3 class="m-0 text-base font-bold text-fore-black">
            保存済みキーペアの公開鍵を再表示する
        </h3>
        <p class="mt-1 mb-4 text-xs leading-relaxed text-fore-gray">
            保存済みのキーペアファイルを選択すると、取出用公開鍵と
            フィンガープリントを再表示できます。2
            回目以降のエクスポートで公開鍵を再提示する場合に使います。
        </p>
        <button
            class="cursor-pointer rounded-lg border border-fore-line
                   bg-fore-white px-5 py-2 text-sm font-bold text-fore-gray
                   transition hover:border-brand-main hover:text-brand-main
                   disabled:cursor-not-allowed disabled:opacity-50"
            disabled={busy} on:click={showKeyPairFile}>
            {busy ? '処理中...' : 'キーペアファイルを選択して表示'}
        </button>
    </div>

    {#if keyPair && !showPopup}
        <div class="rounded-xl border border-success-main bg-success-light p-4
                    text-sm text-fore-black">
            <div>✓ キーペアファイル: <code class="break-all">{keyPair.filePath}</code></div>
            <div class="mt-1">
                Fingerprint: <code class="break-all">{keyPair.fingerprint}</code>
            </div>
            <button
                class="mt-2 cursor-pointer rounded-md border border-fore-line
                       bg-fore-white px-3 py-1 text-xs text-fore-gray
                       hover:border-brand-main hover:text-brand-main"
                on:click={() => (showPopup = true)}>
                公開鍵を再表示
            </button>
        </div>
    {/if}

    {#if error}
        <p class="break-all text-sm text-critical-main">{error}</p>
    {/if}
</div>

{#if showPopup && keyPair}
    <PubkeyPopup
        qrImage={keyPair.qrImage}
        fingerprint={keyPair.fingerprint}
        pubkeyHex={keyPair.publicKeyHex}
        filePath={keyPair.filePath}
        onClose={closePopup}
    />
{/if}
