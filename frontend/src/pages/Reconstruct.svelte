<script>
    import * as app from '../../wailsjs/go/main/App.js'

    let resultText

    async function reconstruct() {
        try {
            resultText = await app.Reconstruct()
        } catch (e) {
            console.log(e)
        }
    }
</script>

<div class="result" id="result">{resultText}</div>
<div class="input-box" id="input">
    <button class="btn" on:click={reconstruct}>Greet</button>
</div>

<style>
    .result {
        height: 20px;
        line-height: 20px;
        margin: 1.5rem auto;
    }
</style>