import { createRouter } from 'sv-router';
import Home from './pages/Home.svelte';
import GenerateKeyPair from './pages/GenerateKeyPair.svelte';
import Reconstruct from './pages/Reconstruct.svelte';
import Derive from './pages/Derive.svelte';

export const { p, navigate, isActive, route } = createRouter({
    '/': Home,
    '/generate-key-pair': GenerateKeyPair,
    '/reconstruct': Reconstruct,
    '/derive': Derive,
});
