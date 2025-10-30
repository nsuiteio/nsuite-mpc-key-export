<script>
    import { Router, Link, Route } from "svelte-routing";
    import Home from "./pages/Home.svelte";
    import GenerateKeyPair from "./pages/GenerateKeyPair.svelte";
    import Reconstruct from "./pages/Reconstruct.svelte";

    let open = false;

</script>

<Router>
    <Route path="/" component="{Home}" />
    <Route path="/generate-key-pair" component="{GenerateKeyPair}" />
    <Route path="/reconstruct" component="{Reconstruct}" />
</Router>

<!-- ハンバーガーなど開閉トグルのボタン -->
<button on:click={() => open = !open} class="menu-btn">☰</button>

<!-- オーバーレイ（メニュー外クリックで閉じる） -->
{#if open}
    <div class="overlay" on:click={() => open = false}></div>
{/if}

<!-- サイドメニュー本体 -->
<aside class:show={open}>
    <nav>
        <a href="/">Home</a>
        <a href="/generate-key-pair">KeyPair</a>
        <a href="/reconstruct">Reconstruct</a>
    </nav>
</aside>

<style>
    nav {
        gap: 1rem;
        margin: 1rem;
    }
    .menu-btn {
        position: fixed;
        top: 1rem;
        left: 1rem;
        z-index: 1001;
        font-size: 2rem;
        background: #fff;
        border: none;
        padding: 0.5em;
        border-radius: 4px;
        cursor: pointer;
    }

    .overlay {
        position: fixed;
        inset: 0;
        background: rgba(0,0,0,0.3);
        z-index: 1000;
    }

    aside {
        position: fixed;
        left: 0;
        top: 0;
        width: 220px;
        height: 100%;
        background: #fff;
        box-shadow: 2px 0 12px rgba(0,0,0,0.15);
        transform: translateX(-100%);
        transition: transform 0.25s cubic-bezier(.33,.66,.66,1);
        z-index: 1001;
        display: flex;
        flex-direction: column;
        padding: 2rem 1rem;
    }
    aside.show {
        transform: translateX(0);
    }

    nav a {
        display: block;
        padding: 1em;
        color: #222;
        text-decoration: none;
        border-radius: 0.25em;
        margin-bottom: 0.25em;
        transition: background 0.1s;
    }
    nav a:hover {
        background: #f0f0f0;
    }
</style>
