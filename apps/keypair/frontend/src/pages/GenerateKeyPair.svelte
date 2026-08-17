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
            受取用キーペアの生成（エクスポートの準備）
        </h2>
        <p class="mt-2 text-sm leading-relaxed text-fore-gray">
            エクスポートを受け取るための専用キーペアを生成し、
            キーペアファイルとして保存します。生成後に表示される QR
            コード（受取用公開鍵）を N Suite モバイルアプリで読み取ると、
            KeyShare がこの公開鍵で暗号化されてエクスポートされます。
        </p>
    </div>

    <div class="rounded-xl border border-warning-main bg-warning-light p-4
                text-sm leading-relaxed text-fore-black">
        <strong>保管ルール:</strong>
        キーペアファイルは暗号化されていません。エクスポート zip
        とは別の担当者が、別のストレージ（オフラインメディア推奨）で
        保管してください。キーペアファイルと zip
        の両方が揃うと、ウォレット秘密鍵を復元できます。
    </div>

    <div class="rounded-xl border border-fore-line bg-fore-white p-6
                shadow-sm">
        <h3 class="m-0 text-base font-bold text-fore-black">
            新しいキーペアを生成する
        </h3>
        <p class="mt-1 mb-4 text-xs leading-relaxed text-fore-gray">
            生成したキーペアは、保存先を選択したファイルにのみ書き出されます。
            このアプリ自体は何も記憶しません。ファイルを失うと、
            その公開鍵でエクスポートした zip は復号できなくなります
            （ウォレットが N Suite で稼働中であれば、新しいキーペアで
            再エクスポートすればバックアップを作り直せます）。
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
            保存済みのキーペアファイルを選択すると、QR
            コードとフィンガープリントを再表示できます。2
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
                QR コードを再表示
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
