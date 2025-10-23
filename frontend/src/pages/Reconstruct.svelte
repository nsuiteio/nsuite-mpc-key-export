<script>
    import * as app from '../../wailsjs/go/main/App.js'

    let result

    async function reconstruct() {
        try {
            result = await app.Reconstruct()
        } catch (e) {
            console.log(e)
        }
    }
</script>

<div class="result" id="result">{result}</div>
<div class="input-box" id="input">
    <button class="btn" on:click={reconstruct}>Choose file</button>
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