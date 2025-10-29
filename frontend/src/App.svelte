<script>
    import { Router, Link, Route } from "svelte-routing";
    import Home from "./pages/Home.svelte";
    import GenerateKeyPair from "./pages/GenerateKeyPair.svelte";
    import Reconstruct from "./pages/Reconstruct.svelte";
</script>

<Router>
    <nav>
        <Link to="/">Home</Link>
        <Link to="/generate-key-pair">KeyPair</Link>
        <Link to="/reconstruct">Reconstruct</Link>

        <Route path="/" component="{Home}" />
        <Route path="/generate-key-pair" component="{GenerateKeyPair}" />
        <Route path="/reconstruct" component="{Reconstruct}" />
    </nav>
</Router>

<style>
    nav {
        gap: 1rem;
        margin: 1rem;
    }
</style>
