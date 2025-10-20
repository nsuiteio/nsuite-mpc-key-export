<script>
    import logo from './assets/images/logo-universal.png'
    import * as app from '../wailsjs/go/main/App.js'

    let resultText = "Please enter key type (ECDSA/EdDSA) 👇"
    let password
    let qrImage
    let showPopup = false

    async function reconstruct() {
        try {
            resultText = await app.Reconstruct()
        } catch (e) {
            console.log(e)
        }
    }

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

<main>
    <img alt="Wails logo" id="logo" src="{logo}">
    <div class="result" id="result">{resultText}</div>
    <div class="input-box" id="input">
        <button class="btn" on:click={reconstruct}>Greet</button>
    </div>
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
</main>

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

    .result {
        height: 20px;
        line-height: 20px;
        margin: 1.5rem auto;
    }

    .input-box .btn {
        width: 60px;
        height: 30px;
        line-height: 30px;
        border-radius: 3px;
        border: none;
        margin: 0 0 0 20px;
        padding: 0 8px;
        cursor: pointer;
    }

    .input-box .btn:hover {
        background-image: linear-gradient(to top, #cfd9df 0%, #e2ebf0 100%);
        color: #333333;
    }

    .input-box .input {
        border: none;
        border-radius: 3px;
        outline: none;
        height: 30px;
        line-height: 30px;
        padding: 0 10px;
        background-color: rgba(240, 240, 240, 1);
        -webkit-font-smoothing: antialiased;
    }

    .input-box .input:hover {
        border: none;
        background-color: rgba(255, 255, 255, 1);
    }

    .input-box .input:focus {
        border: none;
        background-color: rgba(255, 255, 255, 1);
    }

    .overlay {
        position: fixed;
        top: 0; left: 0;
        width: 100%; height: 100%;
        background-color: rgba(0, 0, 0, 0.5);
        display: flex; justify-content: center; align-items: center;
        z-index: 999;
    }
</style>
