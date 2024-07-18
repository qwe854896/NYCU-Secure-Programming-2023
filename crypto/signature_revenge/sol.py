#!/usr/bin/env python3
from Crypto.Util.number import *
from hashlib import sha256
from ecdsa import SECP256k1
from sage.all import *
import random


E = SECP256k1
G, n = E.generator, E.order


# Load the public key, signatures, and messages
P = (
    70427896289635684269185763735464004880272487387417064603929487585697794861713,
    83106938517126976838986116917338443942453391221542116900720022828358221631968,
)
sig1 = (
    26150478759659181410183574739595997895638116875172347795980556499925372918857,
    50639168022751577246163934860133616960953696675993100806612269138066992704236,
)
sig2 = (
    8256687378196792904669428303872036025324883507048772044875872623403155644190,
    90323515158120328162524865800363952831516312527470472160064097576156608261906,
)
h1 = sha256(b"https://www.youtube.com/watch?v=IBnrn2pnPG8").digest()
h2 = sha256(b"https://www.youtube.com/watch?v=1H2cyhWYXrE").digest()
h1, h2 = bytes_to_long(h1), bytes_to_long(h2)

# Calculate t and u
r1, s1 = sig1
r2, s2 = sig2

s1_inv = pow(s1, -1, n)
r2_inv = pow(r2, -1, n)

t = -s1_inv * s2 * r1 * r2_inv
u = s1_inv * r1 * h2 * r2_inv - s1_inv * h1

# k1 = 2 ** 128 * magic1 + magic2
# k2 = 2 ** 128 * magic2 + magic1
# k1 + t * k2 + u = 0 (mod n)
# (2 ** 128 + t) * magic1 + (2 ** 128 * t + 1) * magic2 + u = 0 (mod n)

two_128 = pow(2, 128, n)
t_128_inv = pow(two_128 + t, -1, n)

t = t_128_inv * (two_128 * t + 1)
u = t_128_inv * u

# LLL algorithm to find the shortest vector in lattice basis
while True:
    K = int(2**127 * random.uniform(1, 2))
    B = matrix(ZZ, [[n, 0, 0], [t, 1, 0], [u, 0, K]])
    B = B.LLL()

    if B[0][2] == K:
        break

print("K: ", K)
print(B)


# Apply linear combination on B[0], B[1], B[2]
V = 3
is_k1_found = False
for i in range(-V, V):
    for j in range(-V, V):
        new_B = B[0] + i * B[1] + j * B[2]

        magic1, magic2 = -new_B[0], new_B[1]
        k1 = two_128 * magic1 + magic2
        k1 = (k1 % n + n) % n

        if r1 == (k1 * G).x() % n:
            is_k1_found = True
            break

    if is_k1_found:
        break


d = k1 * s1 - h1
d *= pow(r1, -1, n)
d %= n
print(long_to_bytes(d))
