#!/usr/bin/env python3
from pwn import *
from sage.all import *
from Crypto.Util.number import *


# NIST P-256
p = 0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF
a = 0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFC
b = 0x5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B
n = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551

# Constants
THRESHOLD = 2**30


def new_data(Gx, Gy):
    # r = process("./invalid_curve_attack.py")
    r = remote("10.113.184.121", 10034)

    r.sendlineafter(b"Gx: ", Gx)
    r.sendlineafter(b"Gy: ", Gy)
    point = eval(r.recvline().decode())
    r.close()

    return point


def solve_dlog():
    b = randint(1, p - 1)
    E = EllipticCurve(Zmod(p), [a, b])
    order = E.order()
    factors = prime_factors(order)

    valid = []
    for factor in factors:
        if factor < THRESHOLD:
            valid.append(factor)

    prime = valid[-1]

    G = E.gen(0) * int(order / prime)
    x, y = map(str, G.xy())

    point = new_data(x.encode(), y.encode())

    try:
        K = E(point[0], point[1])
        print("Solving DLOG...")
        log = discrete_log(K, G, operation="+")
        print("Solved DLOG! {}/{}".format(log, prime))
        return log, prime
    except Exception as e:
        print(e)
        return None, None


def solve():
    rs = []
    ms = []

    while True:
        dlog, prime = solve_dlog()

        if dlog != None:
            rs.append(dlog)
            ms.append(prime)

            flag = long_to_bytes(CRT_list(rs, ms))
            print(flag)

            if b"FLAG" in flag:
                return flag


if __name__ == "__main__":
    # FLAG{YouAreARealECDLPMaster}
    print(solve())
