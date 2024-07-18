#!/usr/bin/env python3
from sage.all import *
from Crypto.Util.number import isPrime, getPrime, long_to_bytes
from random import choice
from pwn import *

# N = 2
# while True:
#     bit_len = N.bit_length()
#     if bit_len > 1024:
#         N = 2
#     if bit_len == 1024:
#         if isPrime(N + 1):
#             print(N + 1)
#             break
#     N *= getPrime(10)

N = 111618604367606440584261832363716662615360874816883998698115416433450403359249986832966063863920250602179952835756915183110877991997285245421834848286588923794361612527965303119497789898966993754856572630346296476761438702376182329855671571142662545889224533933428782946205670185537079528056464568365071487343
g = 7

# r = process("./dlog.py")
r = remote("10.113.184.121", 10032)

r.sendlineafter(b"give me a prime: ", str(N).encode())
r.sendlineafter(b"give me a number: ", str(g).encode())

ret = r.recvline().decode()

m = int(ret.lstrip("The hint about my secret: "))

FLAG = discrete_log( Mod(m, N), Mod(g, N) )
print(m, g, FLAG)

print(long_to_bytes(FLAG))