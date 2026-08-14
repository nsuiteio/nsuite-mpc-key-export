<script>
    import * as app from '../../wailsjs/go/main/App.js'
    import {onMount} from "svelte";
    import PubkeyPopup from '../components/PubkeyPopup.svelte'

    let password
    let keyPair = null
    let showPopup = false
    let isGenerated = false
    let generating = false
    let error = ''

    onMount(async () => {
        try {
            isGenerated = await app.CheckKeyPair()
        } catch (e) {
            console.log(e)
        }
    })

    async function genKeyPair() {
        if (generating) return
        generating = true
        error = ''
        try {
            // QR・フィンガープリント・公開鍵 hex は同一鍵のスナップショット
            // として単一レスポンスで受け取る。
            keyPair = await app.GenerateKeyPair(password, true)
            showPopup = true
            isGenerated = true
        } catch (e) {
            // エラーを画面に表示する（パスワード未入力など）。
            error = String(e)
        } finally {
            generating = false
        }
    }

    function closePopup() {
        showPopup = false
    }
</script>

{#if isGenerated}
    <div>
        <h1>Key Pair Generated</h1>
    </div>
{:else}
    <div class="input-box" id="input">
        <div>
            <label for="password">Password</label>
            <input autocomplete="off" bind:value={password} class="input" id="password" type="password"/>
        </div>
        <button class="btn" disabled={generating} on:click={genKeyPair}>
            {generating ? 'Generating...' : 'Generate Key Pair'}
        </button>
    </div>
{/if}

{#if error}
    <p class="error">{error}</p>
{/if}

{#if showPopup && keyPair}
    <PubkeyPopup
        qrImage={keyPair.qrImage}
        fingerprint={keyPair.fingerprint}
        pubkeyHex={keyPair.publicKeyHex}
        onClose={closePopup}
    />
{/if}

<style>
    .error {
        color: #ff6b6b;
        max-width: 640px;
        margin: 1rem auto;
        word-break: break-all;
    }
</style>
