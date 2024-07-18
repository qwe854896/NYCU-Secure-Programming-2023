from Crypto.Util.number import bytes_to_long, long_to_bytes
from Crypto.Cipher import AES
from pwn import *
from tqdm import tqdm
from random import randbytes
from math import log, ceil
from secret import aes_key
import string

N = 69214008498642035761243756357619851816607540327248468473247478342523127723748756926949706235406640562827724567100157104972969498385528097714986614165867074449238186426536742677816881849038677123630836686152379963670139334109846133566156815333584764063197379180877984670843831985941733688575703811651087495223
e = 65537

encrypted_flag_ = 67448907891721241368838325896320122397092733550961191069708016032244349188684070793897519352151466622385197077064799553157879456334546372809948272281247935498288157941438709402245513879910090372080411345199729220479271018326225319584057160895804120944126979515126944833368164622466123481816185794224793277249
encrypted_key_ = 65690013242775728459842109842683020587149462096059598501313133592635945234121561534622365974927219223034823754673718159579772056712404749324225325531206903216411508240699572153162745754564955215041783396329242482406426376133687186983187563217156659178000486342335478915053049498619169740534463504372971359692
encrypted_iv_ = 35154524936059729204581782839781987236407179504895959653768093617367549802652967862418906182387861924584809825831862791349195432705129622783580000716829283234184762744224095175044663151370869751957952842383581513986293064879608592662677541628813345923397286253057417592725291925603753086190402107943880261658


r = remote("10.113.184.121", 10031)


def asymmetric_encryption(message, N, e):
    # encrypt message with RSA
    # message must be 16 bytes
    # padding 100 bytes random value
    padded_message = randbytes(100) + message
    return pow(bytes_to_long(padded_message), e, N)


encrypted_key = asymmetric_encryption(aes_key, N, e)


def test(enc, c):
    r.recvuntil(b"Give me the encrypted key: ")
    r.sendline(bytes(str(encrypted_key), "utf-8"))
    r.recvuntil(b"Give me the encrypted iv: ")
    r.sendline(bytes(str(enc), "utf-8"))
    r.recvuntil(b"Give me the ciphertext: ")
    r.sendline(bytes(c.hex(), "utf-8"))
    s = r.recvline().decode()
    if s[0] == "O":
        return True
    return False


cipher = AES.new(aes_key, AES.MODE_ECB)


def try_c(enc, c):
    m1 = b"\x01" * 15 + bytes([c ^ 1])
    m2 = b"\x02" * 15 + bytes([c ^ 1])
    c1 = cipher.encrypt(m1)
    c2 = cipher.encrypt(m2)
    return test(enc, c1) and test(enc, c2)


def interactor(enc, _):
    for c in range(256):
        suc = try_c(enc, c)
        if suc:
            return c
    return -1


def interactor_flag(enc, offset):
    for c in string.printable:
        c = (ord(c) + offset) % 256
        suc = try_c(enc, c)
        if suc:
            return c
    return -1


def lsb(n, e, enc, base, interactor, rounds=None):
    if rounds is None:
        rounds = ceil(log(n, base))

    inv = pow(base, -1, n)
    inv_e = pow(base, -e, n)

    rst, tmp, digit = 0, 0, 1

    for _ in tqdm(range(rounds)):
        b = interactor(enc, tmp)

        b = b - tmp % base
        b += base
        b %= base

        rst += b * digit
        rst %= n

        digit = digit * base % n
        tmp = (tmp + b) * inv % n
        enc = enc * inv_e % n

        # Debug
        # print(long_to_bytes(rst))

    return rst


def unpad(c):
    length = c[-1]
    for char in c[-length:]:
        if char != length:
            raise ValueError
    return c[:-length]


def main():
    rst_flag = lsb(N, e, encrypted_flag_, 256, interactor_flag, 128)
    print(long_to_bytes(rst_flag))

    rst_key = lsb(N, e, encrypted_key_, 256, interactor, 16)
    rst_iv = lsb(N, e, encrypted_iv_, 256, interactor, 16)

    key = long_to_bytes(rst_key)
    iv = long_to_bytes(rst_iv)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    print("key: ", key)
    print("iv: ", iv)

    ct = open("encrypted_flag.not_png", "rb").read()
    pt = unpad(cipher.decrypt(ct))
    open("flag.png", "wb").write(pt)


if __name__ == "__main__":
    main()
