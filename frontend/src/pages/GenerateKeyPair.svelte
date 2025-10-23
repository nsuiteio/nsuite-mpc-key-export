<script>
    import * as app from '../../wailsjs/go/main/App.js'

    let password
    let qrImage
    let showPopup = false

    async function genKeyPair() {
        try {
            qrImage = await app.GenerateKeyPair(password)
            showPopup = true
        } catch (e) {
            console.log(e)
        }
    }

    function closePopup() {
        showPopup = false
    }
</script>

<style>
    .overlay {
        position: fixed;
        top: 0; left: 0;
        width: 100%; height: 100%;
        background-color: rgba(0, 0, 0, 0.5);
        display: flex; justify-content: center; align-items: center;
        z-index: 999;
    }
</style>

<div class="input-box" id="input">
    <input autocomplete="off" bind:value={password} class="input" id="password" type="password"/>
    <button class="btn" on:click={genKeyPair}>Generate Key Pair</button>
</div>

{#if showPopup}
    <div class="overlay">
        <button class="btn" on:click={closePopup}>
            <img alt="QR code" id="qr" src="{qrImage}" width="200" height="200">
        </button>
    </div>
{/if}