#!/usr/bin/env python3
from Crypto.Cipher import AES
from Crypto.Util.number import long_to_bytes as l2b, bytes_to_long as b2l
from secret import FLAG
from os import urandom
from base64 import b64encode, b64decode

from pwn import *

"""
c1_CFB: (b'WSGlgEb2pGtmI75XgXkpnQ==', b'0owkeaDgS+QTS/4m54IcaenFoSVzgLItzKV1h4CrMz8=')
c2_OFB: (b'WSGlgEb2pGtmI75XgXkpng==', b'2MDZMh7zq1n3PTaZiBC7DEyfaHugL83Y1eUaiUdH4sU=')
c3_CTR: (b'WSGlgEb2pGtmI75XgXkpnw==', b'8+b5DzQPU2KMjaq2nsehXqf0A14riLkMgyNBhlkOSfg=')
What operation mode do you want for encryption? CTR
What message do you want to encrypt (in base64)? 8+b5DzQPU2KMjaq2nsehXqf0A14riLkMgyNBhlkOSfg=
b'WSGlgEb2pGtmI75XgXkpoA==' b'uSVg4zm2v+92U15ZF5+woIDHDMhb09iZ1LRY8lksXtE='
What operation mode do you want for encryption? 
"""


def XOR(a, b):
    return l2b(b2l(a) ^ b2l(b)).rjust(len(a), b"\x00")


def counter_add(iv):
    return l2b(b2l(iv) + 1).rjust(16, b"\x00")


def get_conn():
    # return process(b"./aes.py")
    return remote("chal1.eof.ais3.org", 10003)


# First stage
r = get_conn()


r.recvuntil(b"c1_CFB: ")
cnt_1, ct_1 = map(b64decode, eval(r.recvline().strip()))
c10, c11 = ct_1[:16], ct_1[16:]
print(cnt_1, c10, c11)

r.recvuntil(b"c2_OFB: ")
cnt_2, ct_2 = map(b64decode, eval(r.recvline().strip()))
c20, c21 = ct_2[:16], ct_2[16:]
print(cnt_2, c20, c21)

r.recvuntil(b"c3_CTR: ")
cnt_3, ct_3 = map(b64decode, eval(r.recvline().strip()))
c30, c31 = ct_3[:16], ct_3[16:]
print(cnt_3, c30, c31)

# Debug
# print(r.recvline())
# print(r.recvline())
# print(r.recvline())

round_iv = [counter_add(cnt_3)]
for i in range(4):
    round_iv.append(counter_add(round_iv[-1]))


print(round_iv)


def send_payload(payload, mode):
    r.recvuntil(b"What operation mode do you want for encryption? ")
    r.sendline(mode)
    r.recvuntil(b"What message do you want to encrypt (in base64)? ")
    r.sendline(b64encode(payload))

    line = r.recvline().strip()
    line = "(" + ",".join(line.decode().split(" ")) + ")"
    return map(b64decode, eval(line))


payload = c31 + cnt_1 + cnt_2 + cnt_3 + c10
cnt_4, ct_4 = send_payload(payload, b"CTR")

p31, k1, k2, k3, k4 = ct_4[:16], ct_4[16:32], ct_4[32:48], ct_4[48:64], ct_4[64:]
print("p31: ", p31)


payload = k1 + c10
cnt_5, ct_5 = send_payload(payload, b"CFB")

cnt_1, p10 = ct_5[:16], ct_5[16:]
print("p10: ", p10)


payload = k2 + c20
cnt_6, ct_6 = send_payload(payload, b"CFB")

cnt_2, p20 = ct_6[:16], ct_6[16:]
print("p20: ", p20)


payload = k3 + c30
cnt_7, ct_7 = send_payload(payload, b"CFB")

cnt_3, p30 = ct_7[:16], ct_7[16:]
print("p30: ", p30)


flag_0 = XOR(XOR(p10, p20), p30)
print("flag: ", flag_0)


payload = k4 + c11
cnt_8, ct_8 = send_payload(payload, b"CFB")

c10, p11 = ct_8[:16], ct_8[16:]
print("p11: ", p11)

r.close()


# Second stage

r = get_conn()


r.recvuntil(b"c1_CFB: ")
cnt_1, ct_1 = map(b64decode, eval(r.recvline().strip()))
c10, c11 = ct_1[:16], ct_1[16:]
print(cnt_1, c10, c11)

r.recvuntil(b"c2_OFB: ")
cnt_2, ct_2 = map(b64decode, eval(r.recvline().strip()))
c20, c21 = ct_2[:16], ct_2[16:]
print(cnt_2, c20, c21)

r.recvuntil(b"c3_CTR: ")
cnt_3, ct_3 = map(b64decode, eval(r.recvline().strip()))
c30, c31 = ct_3[:16], ct_3[16:]
print(cnt_3, c30, c31)

# Debug
# print(r.recvline())
# print(r.recvline())
# print(r.recvline())

round_iv = [counter_add(cnt_3)]
for i in range(4):
    round_iv.append(counter_add(round_iv[-1]))


print(round_iv)


payload = c31 + c10 + cnt_2
cnt_4, ct_4 = send_payload(payload, b"CTR")

p31, k1, k2 = ct_4[:16], ct_4[16:32], ct_4[32:48]
print("p31: ", p31)


payload = k1 + c11
cnt_5, ct_5 = send_payload(payload, b"CFB")

c10, p11 = ct_5[:16], ct_5[16:]

print("p11: ", p11)


payload = k2 + c20
cnt_6, ct_6 = send_payload(payload, b"CFB")

cnt_2, p20 = ct_6[:16], ct_6[16:]
print("p20: ", p20)


p20c20 = XOR(p20, c20)

payload = k3 + p20c20
cnt_7, ct_7 = send_payload(payload, b"CTR")
not_p31, k1 = ct_7[:16], ct_7[16:32]


payload = k1 + c21
cnt_8, ct_8 = send_payload(payload, b"CFB")

p20c20, p21 = ct_8[:16], ct_8[16:]

print("p21: ", p21)

flag_1 = XOR(XOR(p11, p21), p31)
print("flag_1: ", flag_1)


print("flag: ", flag_0 + flag_1)
