<script>
    import {onMount, tick} from 'svelte'
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

    // QR はセカンダリ導線（対面でモバイルアプリから直接読み取る場合のみ）。
    // デフォルト表示にすると「この場でスキャンする」のがメインルートに
    // 見えてしまうため、明示的なワンクリックの先に置く。
    let showQR = false
    let qrImg

    // QR はダイアログ下部にあるため、表示直後に見える位置までスクロールする
    // （押しても何も変わらないように見えるのを防ぐ）。
    // 動きの抑制設定（prefers-reduced-motion）時は即時スクロールにする。
    async function toggleQR() {
        showQR = !showQR
        if (showQR) {
            await tick()
            const reduceMotion = window.matchMedia?.(
                '(prefers-reduced-motion: reduce)'
            )?.matches
            qrImg?.scrollIntoView({
                behavior: reduceMotion ? 'auto' : 'smooth',
                block: 'nearest',
            })
        }
    }

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
    <div class="mx-4 flex max-h-[90vh] max-w-md flex-col items-center gap-4
                overflow-y-auto rounded-xl bg-fore-white p-6 shadow-lg">
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
            受取用公開鍵をコピーして、エクスポートを実行する担当者に
            渡してください。担当者は N Suite モバイルアプリの
            エクスポート画面でこの公開鍵を入力します。
        </p>
        <div class="w-full rounded-md bg-back-lightGray p-3">
            <p class="m-0 mb-1 text-center text-xs font-bold text-fore-gray">
                受取用公開鍵
            </p>
            <code class="block max-h-20 overflow-y-auto break-all
                         text-center text-xs leading-relaxed">
                {pubkeyHex}
            </code>
        </div>
        <button
            class="cursor-pointer rounded-lg bg-brand-main px-5 py-2
                   text-sm font-bold text-fore-white transition
                   hover:bg-brand-dark"
            on:click={copyPublicKeyHex}>
            {copied ? 'コピーしました' : '公開鍵をコピー'}
        </button>
        <!-- コピー結果はボタン文言の変化だけでは支援技術に通知されないため、
             成功は role="status"（polite）、失敗は role="alert" で読み上げる -->
        <span class="sr-only" role="status">
            {copied ? '公開鍵をコピーしました' : ''}
        </span>
        {#if copyError}
            <p role="alert" class="m-0 text-sm text-critical-main">
                {copyError}
            </p>
        {/if}
        <div class="w-full rounded-md bg-back-lightGray p-3 text-center">
            <p class="m-0 mb-1 text-xs font-bold text-fore-gray">
                Fingerprint
            </p>
            <code class="text-sm">{fingerprint}</code>
            <p class="m-0 mt-1 text-xs leading-relaxed text-fore-gray">
                公開鍵を渡した経路とは別の経路（電話・対面など）で
                読み合わせ、モバイルアプリの表示と一致することを
                確認してください。公開鍵自体は秘密情報ではありませんが、
                受け渡し経路でのすり替えを検知するためにこの照合が必要です。
            </p>
        </div>
        <div class="flex gap-2">
            <button
                class="cursor-pointer rounded-lg border border-fore-line
                       bg-fore-white px-4 py-2 text-sm text-fore-gray
                       hover:border-brand-main hover:text-brand-main"
                aria-expanded={showQR}
                aria-controls="qr-section"
                on:click={toggleQR}>
                {showQR ? 'QR コードを隠す' : 'QR コードを表示'}
            </button>
            <button
                bind:this={closeButton}
                class="cursor-pointer rounded-lg border border-fore-line
                       bg-fore-white px-4 py-2 text-sm font-bold
                       text-fore-gray hover:border-brand-main
                       hover:text-brand-main"
                on:click={onClose}>
                閉じる
            </button>
        </div>
        {#if showQR}
            <div id="qr-section"
                 class="flex flex-col items-center gap-4">
                <p class="m-0 text-center text-xs leading-relaxed
                          text-fore-gray">
                    対面でモバイルアプリから直接読み取る場合のみ
                    使用してください。
                </p>
                <img bind:this={qrImg}
                     alt="公開鍵の QR コード" id="qr" src="{qrImage}"
                     width="200" height="200"
                     class="rounded-md border border-fore-line"/>
            </div>
        {/if}
    </div>
</div>
