<script>
    import * as app from '../../wailsjs/go/main/App.js'
    import {ClipboardSetText} from '../../wailsjs/runtime/runtime.js'
    import {onMount} from "svelte";
    import PubkeyPopup from '../components/PubkeyPopup.svelte'

    let password = ''
    let keyPair = null
    let showPopup = false
    let isGenerated = false
    let generating = false
    let error = ''

    // 生成済み鍵ペアの公開鍵情報の再表示用。
    let viewPassword = ''
    let viewInfo = null // { fingerprint, pubkeyHex }
    let viewError = ''
    let copied = false

    // 再生成（危険操作）用。
    let regenAcknowledged = false

    onMount(async () => {
        try {
            isGenerated = await app.CheckKeyPair()
        } catch (e) {
            console.log(e)
        }
    })

    async function genKeyPair(force) {
        if (generating) return
        generating = true
        error = ''
        try {
            // QR・フィンガープリント・公開鍵 hex は同一鍵のスナップショット
            // として単一レスポンスで受け取る。
            keyPair = await app.GenerateKeyPair(password, force)
            showPopup = true
            isGenerated = true
            viewInfo = null
            regenAcknowledged = false
        } catch (e) {
            // エラーを画面に表示する（パスワード未入力・鍵ペア重複など）。
            error = String(e)
        } finally {
            generating = false
        }
    }

    async function showPubkeyInfo() {
        viewError = ''
        viewInfo = null
        copied = false
        try {
            const fingerprint = await app.GetKeyPairFingerprint(viewPassword)
            const pubkeyHex = await app.GetPublicKeyHex(viewPassword)
            viewInfo = {fingerprint, pubkeyHex}
        } catch (e) {
            // パスワード誤りなどはここに出る。
            viewError = String(e)
        }
    }

    async function copyPubkeyHex() {
        if (!viewInfo) return
        try {
            // WebView の navigator.clipboard は環境により使えないため、
            // Wails ランタイムのクリップボード API を使う。
            const ok = await ClipboardSetText(viewInfo.pubkeyHex)
            if (ok === false) throw new Error('clipboard write failed')
            copied = true
        } catch (e) {
            viewError = 'コピーに失敗しました。もう一度お試しください。'
        }
    }

    function closePopup() {
        showPopup = false
    }
</script>

<div class="flex flex-col gap-6">
    <div>
        <h2 class="m-0 text-xl font-bold text-fore-black">
            鍵ペアの生成（エクスポートの準備）
        </h2>
        <p class="mt-2 text-sm leading-relaxed text-fore-gray">
            このツール専用の鍵ペアを生成します。生成後に表示される QR
            コード（公開鍵）を N Suite モバイルアプリで読み取ると、KeyShare
            がこの公開鍵で暗号化されてエクスポートされます。
            ここで入力するパスワードは鍵ペアの保護に使われ、
            以後のすべての操作で必要になります。
        </p>
    </div>

    {#if !isGenerated}
        <div class="rounded-xl border border-fore-line bg-fore-white p-6
                    shadow-sm">
            <label class="mb-1 block text-sm font-bold text-fore-black"
                   for="password">
                パスワード
            </label>
            <p class="mt-0 mb-3 text-xs text-fore-gray">
                このパスワードを忘れると、生成した鍵ペアもエクスポートした
                KeyShare も復号できなくなります。安全に保管してください。
            </p>
            <input autocomplete="off" bind:value={password}
                   class="w-full rounded-md border border-fore-line px-3 py-2
                          text-sm focus:border-brand-main focus:outline-none"
                   id="password" type="password"/>
            <button
                class="mt-4 cursor-pointer rounded-lg bg-brand-main px-5 py-2
                       text-sm font-bold text-fore-white transition
                       hover:bg-brand-dark disabled:cursor-not-allowed
                       disabled:opacity-50"
                disabled={generating} on:click={() => genKeyPair(false)}>
                {generating ? '生成中...' : '鍵ペアを生成する'}
            </button>
        </div>
    {:else}
        <div class="rounded-xl border border-success-main bg-success-light p-4
                    text-sm text-fore-black">
            ✓ 鍵ペアは生成済みです。QR
            コードをまだ読み取っていない場合は、下記からフィンガープリントと公開鍵を確認できます。
        </div>

        <div class="rounded-xl border border-fore-line bg-fore-white p-6
                    shadow-sm">
            <h3 class="m-0 text-base font-bold text-fore-black">
                公開鍵情報の確認
            </h3>
            <p class="mt-1 mb-3 text-xs text-fore-gray">
                鍵ペア生成時のパスワードを入力すると、フィンガープリントと公開鍵
                hex を再表示できます。
            </p>
            <div class="flex gap-2">
                <input autocomplete="off" bind:value={viewPassword}
                       class="min-w-0 flex-1 rounded-md border border-fore-line
                              px-3 py-2 text-sm focus:border-brand-main
                              focus:outline-none"
                       id="view-password" type="password"
                       placeholder="パスワード"/>
                <button
                    class="cursor-pointer rounded-lg bg-brand-main px-4 py-2
                           text-sm font-bold text-fore-white transition
                           hover:bg-brand-dark"
                    on:click={showPubkeyInfo}>
                    表示する
                </button>
            </div>
            {#if viewInfo}
                <div class="mt-4 rounded-md bg-back-lightGray p-3">
                    <div class="text-xs font-bold text-fore-gray">
                        Fingerprint（モバイルアプリの表示と一致することを確認してください）
                    </div>
                    <code class="break-all text-sm">{viewInfo.fingerprint}</code>
                    <div class="mt-3 text-xs font-bold text-fore-gray">
                        公開鍵（hex）
                    </div>
                    <code class="break-all text-xs">{viewInfo.pubkeyHex}</code>
                    <div class="mt-2">
                        <button
                            class="cursor-pointer rounded-md border
                                   border-fore-line bg-fore-white px-3 py-1
                                   text-xs text-fore-gray
                                   hover:border-brand-main
                                   hover:text-brand-main"
                            on:click={copyPubkeyHex}>
                            {copied ? 'コピーしました' : '公開鍵 hex をコピー'}
                        </button>
                    </div>
                </div>
            {/if}
            {#if viewError}
                <p class="mt-3 break-all text-sm text-critical-main">
                    {viewError}
                </p>
            {/if}
        </div>

        <div class="rounded-xl border border-critical-main bg-critical-light
                    p-6">
            <h3 class="m-0 text-base font-bold text-critical-dark">
                鍵ペアの再生成（危険な操作）
            </h3>
            <p class="mt-1 mb-3 text-xs leading-relaxed text-fore-black">
                再生成すると既存の鍵ペアは上書きされ、
                <strong>以前の公開鍵でエクスポートした zip
                は復号できなくなります</strong>。
                通常は必要ありません。
            </p>
            <label class="flex items-center gap-2 text-sm text-fore-black">
                <input bind:checked={regenAcknowledged} type="checkbox"/>
                影響を理解した上で再生成します
            </label>
            <div class="mt-3">
                <label class="mb-1 block text-xs font-bold text-fore-black"
                       for="regen-password">
                    新しいパスワード
                </label>
                <input autocomplete="off" bind:value={password}
                       class="w-full rounded-md border border-fore-line
                              bg-fore-white px-3 py-2 text-sm
                              focus:border-critical-main focus:outline-none"
                       id="regen-password" type="password"/>
            </div>
            <button
                class="mt-4 cursor-pointer rounded-lg bg-critical-main px-5
                       py-2 text-sm font-bold text-fore-white transition
                       hover:bg-critical-dark disabled:cursor-not-allowed
                       disabled:opacity-50"
                disabled={!regenAcknowledged || generating}
                on:click={() => genKeyPair(true)}>
                {generating ? '生成中...' : '鍵ペアを再生成する'}
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
        onClose={closePopup}
    />
{/if}
