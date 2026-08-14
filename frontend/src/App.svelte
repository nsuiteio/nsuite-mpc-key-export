<script>
    import {Router} from 'sv-router';
    import './router.js';

    const menuItems = [
        { label: 'Home', href: '/' },
        { label: 'Generate Key Pair', href: '/generate-key-pair' },
        { label: 'Reconstruct', href: '/reconstruct' },
        { label: 'Derive', href: '/derive' }
    ];
</script>

<div id="app-container">
    <!-- Sidebar -->
    <nav id="sidebar">
        <div id="sidebar-header">
            <h2>Menu</h2>
        </div>
        <ul id="sidebar-menu">
            {#each menuItems as item}
                <li>
                    <a href={item.href}>
                        {item.label}
                    </a>
                </li>
            {/each}
        </ul>
    </nav>

    <!-- Main content -->
    <div id="main-container">
        <main id="main">
            <Router/>
        </main>
    </div>
</div>