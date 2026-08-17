import { createRouter } from 'sv-router';
import Start from './pages/Start.svelte';
import GenerateKeyPair from './pages/GenerateKeyPair.svelte';
import Extract from './pages/Extract.svelte';

export const { p, navigate, isActive, route } = createRouter({
    '/': Start,
    '/generate': GenerateKeyPair,
    '/extract': Extract,
});
