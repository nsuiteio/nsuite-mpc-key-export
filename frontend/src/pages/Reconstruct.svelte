<script>
    import * as app from '../../wailsjs/go/main/App.js'

    let password
    let result

    async function chooseKeyShares() {
        try {
            result = await app.ChooseKeyShares(password)
        } catch (e) {
            console.log(e)
        }
    }
</script>

<div class="result" id="result">{result}</div>
<div class="input-box" id="input">
    <input autocomplete="off" bind:value={password} class="input" id="password" type="password"/>
    <button class="btn" on:click={chooseKeyShares}>Choose file</button>
</div>

<style>
    .result {
        height: 20px;
        line-height: 20px;
        margin: 1.5rem auto;
    }

    .input-box .btn {
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
</style>