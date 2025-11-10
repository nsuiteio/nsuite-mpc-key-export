import { createRouter } from 'sv-router';
import Home from './pages/Home.svelte';
import GenerateKeyPair from './pages/GenerateKeyPair.svelte';
import LoadZipFile from './pages/LoadZipFile.svelte';

export const { p, navigate, isActive, route } = createRouter({
    '/': Home,
    '/generate-key-pair': GenerateKeyPair,
    '/load-zip-file': LoadZipFile,
});
