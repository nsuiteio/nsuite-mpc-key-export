<script>
    // バックエンドは全長（64 桁・4 文字区切り）のフィンガープリントを返す。
    // 既定表示は読み上げやすい先頭 8 桁だが、短縮値は 32bit しかないため
    // 厳密な照合には全桁が要る。トグルで全桁を開けるようにしている
    // （モバイルアプリ側の表示仕様と同じ）。
    export let fingerprint = ''
    export let id = 'fingerprint-value'

    let showFull = false

    const compact = (value) => value.replace(/\s/g, '')

    // 4 文字区切り・大文字（Go 側 FormatFingerprint と同じ整形）。
    const group = (value) =>
        value.toUpperCase().match(/.{1,4}/g)?.join(' ') ?? value.toUpperCase()

    $: short = group(compact(fingerprint).slice(0, 8))
    $: full = group(compact(fingerprint))
    $: shown = showFull ? full : short
</script>

<code class="block break-all text-sm" {id}>{shown}</code>
<button
    class="mt-1 cursor-pointer border-none bg-transparent p-0 text-xs
           font-bold text-brand-main underline"
    type="button"
    aria-expanded={showFull}
    aria-controls={id}
    on:click={() => (showFull = !showFull)}>
    {showFull ? '短縮表示に戻す' : '全桁を表示'}
</button>
