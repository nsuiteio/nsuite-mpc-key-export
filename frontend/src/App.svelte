<script>
    import {Router} from 'sv-router';
    import './router.js';

    const menuItems = [
        { label: 'Home', href: '/' },
        { label: 'Generate Key Pair', href: '/generate-key-pair' },
        { label: 'Reconstruct', href: '/reconstruct' }
    ];
</script>

<div class="flex h-screen">
    <!-- Sidebar -->
    <nav class="w-64 bg-gray-800 text-white flex flex-col">
        <div class="p-4 border-b border-gray-700">
            <h2 class="text-xl font-bold">Menu</h2>
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

    <!-- Main content -->
    <div class="flex-1 flex flex-col">
        <main class="flex-1 p-6 overflow-auto">
            <Router/>
        </main>
    </div>
</div>