<script>
    import { Router, Link, Route } from "svelte-routing";
    import Reconstruct from "./pages/Reconstruct.svelte";
    import GenerateKeyPair from "./pages/GenerateKeyPair.svelte";
</script>

<Router>
    <nav>
        <Link to="/">Home</Link>
        <Link to="/reconstruct">Reconstruct</Link>
        <Link to="/generate-key-pair">Generate Key Pair</Link>

        <Route path="/reconstruct" component="{Reconstruct}" />
        <Route path="/generate-key-pair" component="{GenerateKeyPair}" />
    </nav>
</Router>

<style>
    nav {
        gap: 1rem;
        margin: 1rem;
    }
</style>
