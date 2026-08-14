<script>
    import * as app from '../../wailsjs/go/main/App.js'

    let password
    let result = ""
    let error = ""

    async function chooseKeyShares() {
        result = ""
        error = ""
        try {
            result = await app.ChooseKeyShares(password)
        } catch (e) {
            // エラーを画面に表示する（パスワード誤り・鍵ペア未生成・
            // zip 復号失敗などはここに出る）。
            error = String(e)
        }
    }
</script>

<div class="input-box" id="input">
    <div>
        <label for="password">Password</label>
        <input autocomplete="off" bind:value={password} class="input" id="password" type="password"/>
    </div>
    <button class="btn" on:click={chooseKeyShares}>Choose file</button>
</div>
{#if result}
    <div class="result" id="result">{result}</div>
{/if}
{#if error}
    <p class="error">{error}</p>
{/if}

<style>
    .result {
        height: 20px;
        line-height: 20px;
        margin: 1.5rem auto;
    }

    .error {
        color: #ff6b6b;
        max-width: 640px;
        margin: 1.5rem auto;
        word-break: break-all;
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