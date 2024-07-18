#!/usr/bin/env python3
from Crypto.Util.number import bytes_to_long, getPrime, isPrime
from Crypto.Cipher import AES
from hashlib import sha256
from sage.all import *
from z3 import *
from output import xor_mods, hint, ct_hex


# print(len(xor_mods))
# print(len(hint))

# for i in range(num):
#     # print bit length of hint[i] and xor_mods[i]
#     print(i, len(bin(hint[i])[2:]), len(bin(xor_mods[i])[2:]))


num = 1337


# mods_sum = BitVec("mods_sum", 48)

# s = Solver()
# s.add(And([ULT(hint[i], mods_sum ^ xor_mods[i]) for i in range(num)]))

# anses = []

# while s.check() == sat:
#     ans = s.model()[mods_sum]
#     s.add(mods_sum != ans)

#     ans = int(str(ans))
#     mods_candidate = [ans ^ xor_mods[i] for i in range(num)]

#     if all([isPrime(mod) for mod in mods_candidate]):
#         print(ans)
#         anses.append(ans)


# print(len(anses))
