<script>
    import GenerateKeyPair from './pages/GenerateKeyPair.svelte';
</script>

<div class="flex min-h-screen flex-col">
    <header class="flex items-center gap-3 border-b border-fore-line
                   bg-fore-white px-6 py-3 shadow-sm">
        <span class="inline-block h-3 w-3 rounded-full bg-brand-main"></span>
        <h1 class="m-0 text-base font-bold text-fore-black">
            N Suite MPC Key Export — 受取用キーペア生成
        </h1>
    </header>

    <main class="mx-auto w-full max-w-3xl flex-1 px-6 py-8">
        <GenerateKeyPair/>
    </main>
</div>
