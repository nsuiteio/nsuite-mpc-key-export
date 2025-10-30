<script>
    import {Router} from 'sv-router';
    import './router.js';

    let open = $state(true);

    const menuItems = [
        { label: 'Home', href: '/' },
        { label: 'Generate Key Pair', href: '/generate-key-pair' },
        { label: 'Reconstruct', href: '/reconstruct' }
    ];
</script>

<div class="flex h-screen">
    <!-- Sidebar -->
    {#if open}
        <nav class="w-64 bg-gray-800 text-white flex flex-col">
            <div class="p-4 border-b border-gray-700 flex justify-between items-center">
                <h2 class="text-xl font-bold">Menu</h2>
                <button
                    type="button"
                    class="px-3 py-1 bg-gray-700 rounded hover:bg-gray-600"
                    onclick={() => open = false}
                >
                    ✕
                </button>
            </div>
            <ul class="flex-1 px-2 py-2">
                {#each menuItems as item}
                    <li>
                        <a href={item.href} class="block px-4 py-2 rounded hover:bg-gray-700">
                            {item.label}
                        </a>
                    </li>
                {/each}
            </ul>
        </nav>
    {/if}

    <!-- Main content -->
    <div class="flex-1 flex flex-col">
        <header class="p-4 bg-gray-100 border-b">
            {#if !open}
                <button
                    type="button"
                    class="px-4 py-2 bg-blue-600 text-white rounded hover:bg-blue-700"
                    onclick={() => open = true}
                >
                    ☰ Open Menu
                </button>
            {/if}
        </header>
        <main class="flex-1 p-6 overflow-auto">
            <Router/>
        </main>
    </div>
</div>