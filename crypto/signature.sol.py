#!/usr/bin/env python3
from pwn import *
from Crypto.Util.number import *
from hashlib import sha256
from ecdsa import SECP256k1
from ecdsa.ecdsa import Public_key, Private_key

MSG = b"Don't give me the FLAG."

# r = process("./signature.py")
r = remote("10.113.184.121", 10033)

r.sendlineafter(b"3) exit\n", str(1).encode())
r.sendlineafter(b"What do you want? ", MSG)
r.recvuntil(b"sig = ")
r1, s1 = eval(r.recvline().decode())
h1 = bytes_to_long(sha256(MSG).digest())

r.sendlineafter(b"3) exit\n", str(1).encode())
r.sendlineafter(b"What do you want? ", MSG)
r.recvuntil(b"sig = ")
r2, s2 = eval(r.recvline().decode())
h2 = bytes_to_long(sha256(MSG).digest())

E = SECP256k1
G, n = E.generator, E.order

# s * k = (H + d * r) % n
# k = H * s^-1 + r * s^-1 * d
# 1337 * h1 * pow(s1, -1, n) + 1337 * d * r1 * pow(s1, -1, n) = h2 * pow(s2, -1, n) + d * r2 * pow(s2, -1, n)
# d * ( r2 * pow(s2, -1, n) - 1337 * r1 * pow(s1, -1, n) ) = 1337 * h1 * pow(s1, -1, n) - h2 * pow(s2, -1, n)

d = (
    pow((r2 * pow(s2, -1, n) - 1337 * r1 * pow(s1, -1, n)), -1, n)
    * (1337 * h1 * pow(s1, -1, n) - h2 * pow(s2, -1, n))
    % n
)

pub_key = Public_key(G, G * d)
pri_key = Private_key(pub_key, d)

m = "Give me the FLAG."
h = sha256(m.encode()).digest()
k = 0x1337

signature = pri_key.sign(bytes_to_long(h), k)

r.sendlineafter(b"3) exit\n", str(2).encode())
r.sendlineafter(b"r: ", str(signature.r).encode())
r.sendlineafter(b"s: ", str(signature.s).encode())

r.interactive()
