<script>
    import logo from './assets/images/logo-universal.png'
    import { Router, Link, Route } from "svelte-routing";
    import Reconstruct from "./pages/Reconstruct.svelte";
    import GenerateKeyPair from "./pages/GenerateKeyPair.svelte";
</script>

<Router>
    <img alt="Wails logo" id="logo" src="{logo}">
    <nav>
        <Link to="/">Home</Link>
        <Link to="/reconstruct">Reconstruct</Link>
        <Link to="/generate-key-pair">Generate Key Pair</Link>

        <Route path="/reconstruct" component="{Reconstruct}" />
        <Route path="/generate-key-pair" component="{GenerateKeyPair}" />
    </nav>
</Router>

<style>
    #logo {
        display: block;
        width: 50%;
        height: 50%;
        margin: auto;
        padding: 10% 0 0;
        background-position: center;
        background-repeat: no-repeat;
        background-size: 100% 100%;
        background-origin: content-box;
    }
</style>
