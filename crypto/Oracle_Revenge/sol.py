from pwn import *
from Crypto.Util.number import bytes_to_long, long_to_bytes
from Crypto.Cipher import AES
from tqdm import tqdm
from random import randbytes
from math import log, ceil
from secret import aes_key

N = 69214008498642035761243756357619851816607540327248468473247478342523127723748756926949706235406640562827724567100157104972969498385528097714986614165867074449238186426536742677816881849038677123630836686152379963670139334109846133566156815333584764063197379180877984670843831985941733688575703811651087495223
e = 65537
encrypted_flag = 67448907891721241368838325896320122397092733550961191069708016032244349188684070793897519352151466622385197077064799553157879456334546372809948272281247935498288157941438709402245513879910090372080411345199729220479271018326225319584057160895804120944126979515126944833368164622466123481816185794224793277249
cipher = AES.new(aes_key, AES.MODE_ECB)

r = remote("10.113.184.121", 10031)


def asymmetric_encryption(message, N, e):
    # encrypt message with RSA
    # message must be 16 bytes
    # padding 100 bytes random value
    padded_message = randbytes(100) + message
    return pow(bytes_to_long(padded_message), e, N)


encrypted_key = asymmetric_encryption(aes_key, N, e)


def test(enc, c):
    global r
    s = b""
    
    while True:
        try:
            r.recvuntil("Give me the encrypted key: ")
            r.sendline(bytes(str(encrypted_key), "utf-8"))
            r.recvuntil("Give me the encrypted iv: ")
            r.sendline(bytes(str(enc), "utf-8"))
            r.recvuntil("Give me the ciphertext: ")
            r.sendline(c.hex())
            s = r.recvline().decode()
            break
        except EOFError:
            r = remote("10.113.184.121", 10031)
            continue

    if s[0] == "O":
        return True
    return False


def try_c(enc, c):
    m1 = b"\x01" * 15 + bytes([c ^ 1])
    m2 = b"\x02" * 15 + bytes([c ^ 1])
    c1 = cipher.encrypt(m1)
    c2 = cipher.encrypt(m2)
    return test(enc, c1) and test(enc, c2)


def interactor(enc):
    for c in tqdm(range(256)):
        suc = try_c(enc, c)
        if suc:
            return c
    return -1


def lsb(n, e, enc, base, interactor):
    inv = pow(base, -1, n)
    inv_e = pow(base, -e, n)

    rst, tmp, digit = 0, 0, 1

    for _ in tqdm(range(ceil(log(n, base)))):
        b = interactor(enc)

        b = b - tmp % base
        b += base
        b %= base

        rst += b * digit
        rst %= n

        digit = digit * base % n
        tmp = (tmp + b) * inv % n
        enc = enc * inv_e % n

        print(long_to_bytes(rst))

    return rst


def main():
    rst = lsb(N, e, encrypted_flag, 256, interactor)
    print(long_to_bytes(rst))


if __name__ == "__main__":
    main()
