from pwn import *
from Crypto.Util.number import bytes_to_long, long_to_bytes
from tqdm import tqdm
from math import log, ceil

# r = process("./LSB_60b067f6b6dbd2c1.py")
r = remote("edu-ctf.zoolab.org", 10005)


def interactor(enc):
    r.sendline(bytes(str(enc), "utf-8"))
    return int(r.recvline().decode())


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

    return rst


def main():
    n = int(r.recvline().decode())
    e = int(r.recvline().decode())
    enc = int(r.recvline().decode())
    enc_bkp = enc

    rst = lsb(n, e, enc, 3, interactor)

    assert pow(rst, e, n) == enc_bkp
    print(long_to_bytes(rst))


if __name__ == "__main__":
    main()
