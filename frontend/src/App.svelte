<script>
    import {Router} from 'sv-router';
    import {route, navigate} from './router.js';
</script>

<div class="flex min-h-screen flex-col">
    <header class="flex items-center gap-3 border-b border-fore-line
                   bg-fore-white px-6 py-3 shadow-sm">
        <span class="inline-block h-3 w-3 rounded-full bg-brand-main"></span>
        <h1 class="m-0 text-base font-bold text-fore-black">
            N Suite MPC Key Export
        </h1>
        {#if route.pathname !== '/'}
            <button
                class="ml-auto cursor-pointer rounded-md border border-fore-line
                       bg-fore-white px-3 py-1 text-sm text-fore-gray
                       hover:border-brand-main hover:text-brand-main"
                on:click={() => navigate('/')}>
                ← 最初の画面に戻る
            </button>
        {/if}
    </header>

    <main class="mx-auto w-full max-w-3xl flex-1 px-6 py-8">
        <Router/>
    </main>
</div>
