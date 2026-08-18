<script>
    import {onMount} from 'svelte'
    import {ClipboardSetText} from '../../wailsjs/runtime/runtime.js'

    // GenerateKeyPair の単一レスポンス（qrImage / fingerprint / publicKeyHex）。
    // すべて同一の公開鍵に由来する値を受け取る。
    export let qrImage
    export let fingerprint
    export let pubkeyHex
    export let filePath = ''
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

    // 「コピーしました」は現在表示中の公開鍵をコピーした場合のみ表示する
    // （鍵を再生成した後に古いコピー状態を引き継がない）。
    $: copied = copiedValue !== '' && copiedValue === pubkeyHex

    // キーボード操作対応: 表示時に閉じるボタンへフォーカスし、
    // Escape キーで閉じられるようにする。
    let closeButton
    onMount(() => {
        closeButton?.focus()
    })

    function handleKeydown(event) {
        if (event.key === 'Escape') onClose()
    }
</script>

<svelte:window on:keydown={handleKeydown}/>

<div role="dialog" aria-modal="true" aria-label="鍵ペアの生成結果"
     class="fixed inset-0 z-50 flex items-center justify-center bg-fore-black/50">
    <div class="mx-4 flex max-w-md flex-col items-center gap-4 rounded-xl
                bg-fore-white p-6 shadow-lg">
        <h3 class="m-0 text-base font-bold text-fore-black">
            受取用キーペア
        </h3>
        {#if filePath}
            <p class="m-0 w-full break-all text-center text-xs
                      text-fore-gray">
                ファイル: <code>{filePath}</code>
            </p>
        {/if}
        <p class="m-0 text-center text-xs leading-relaxed text-fore-gray">
            N Suite モバイルアプリのエクスポート画面でこの QR
            コードを読み取ってください。
        </p>
        <img alt="公開鍵の QR コード" id="qr" src="{qrImage}"
             width="200" height="200"
             class="rounded-md border border-fore-line"/>
        <div class="w-full rounded-md bg-back-lightGray p-3 text-center">
            <p class="m-0 mb-1 text-xs font-bold text-fore-gray">
                Fingerprint（モバイルアプリの表示と一致することを確認してください）
            </p>
            <code class="text-sm">{fingerprint}</code>
        </div>
        <div class="flex gap-2">
            <button
                class="cursor-pointer rounded-lg border border-fore-line
                       bg-fore-white px-4 py-2 text-sm text-fore-gray
                       hover:border-brand-main hover:text-brand-main"
                on:click={copyPublicKeyHex}>
                {copied ? 'コピーしました' : '公開鍵 hex をコピー'}
            </button>
            <button
                bind:this={closeButton}
                class="cursor-pointer rounded-lg bg-brand-main px-4 py-2
                       text-sm font-bold text-fore-white hover:bg-brand-dark"
                on:click={onClose}>
                閉じる
            </button>
        </div>
        {#if copyError}
            <p class="m-0 text-sm text-critical-main">{copyError}</p>
        {/if}
    </div>
</div>
