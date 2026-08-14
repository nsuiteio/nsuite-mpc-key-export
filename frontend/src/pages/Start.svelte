<script>
    import {navigate} from '../router.js';
</script>

<div class="flex flex-col gap-6">
    <div>
        <h2 class="m-0 text-xl font-bold text-fore-black">
            何をしますか？
        </h2>
        <p class="mt-2 text-sm leading-relaxed text-fore-gray">
            このツールは、N Suite からエクスポートした MPC の KeyShare
            から秘密鍵を取り出すためのオフラインツールです。
            初めて使う場合は、まず「鍵ペアの生成」からエクスポートの準備をしてください。
        </p>
    </div>

    <button
        class="cursor-pointer rounded-xl border border-fore-line bg-fore-white
               p-6 text-left shadow-sm transition
               hover:border-brand-main hover:shadow-md"
        on:click={() => navigate('/generate')}>
        <div class="flex items-center gap-3">
            <span class="flex h-10 w-10 items-center justify-center rounded-full
                         bg-informational-light text-lg">🔑</span>
            <span class="text-lg font-bold text-fore-black">
                1. 鍵ペアの生成（エクスポートの準備）
            </span>
        </div>
        <p class="mb-0 mt-3 text-sm leading-relaxed text-fore-gray">
            このツール専用の鍵ペアを生成し、公開鍵の QR コードを表示します。
            N Suite モバイルアプリで QR コードを読み取ると、KeyShare
            がこの公開鍵で暗号化されてエクスポートされます。
        </p>
    </button>

    <button
        class="cursor-pointer rounded-xl border border-fore-line bg-fore-white
               p-6 text-left shadow-sm transition
               hover:border-brand-main hover:shadow-md"
        on:click={() => navigate('/extract')}>
        <div class="flex items-center gap-3">
            <span class="flex h-10 w-10 items-center justify-center rounded-full
                         bg-success-light text-lg">📤</span>
            <span class="text-lg font-bold text-fore-black">
                2. 秘密鍵の取り出し
            </span>
        </div>
        <p class="mb-0 mt-3 text-sm leading-relaxed text-fore-gray">
            エクスポートした zip ファイルを復号して root 鍵を復元し、
            アドレスを確認したうえで秘密鍵を取り出します。
            事前に「鍵ペアの生成」とエクスポートが完了している必要があります。
        </p>
    </button>
</div>
