def decrypt_1B0A(szUrl):
    rst = b""
    for i in range(7, 23, 4):
        v2 = int.from_bytes(szUrl[i : i + 4], "little")
        for j in range(4):
            v2 = (v2 - 43) & 0xFFFFFFFF
            v2 = ((v2 >> 8) | (v2 << 24)) & 0xFFFFFFFF
        v2 ^= 0x6F6F6F6F
        rst += v2.to_bytes(4, "little")

    return rst


def decrypt_1992(szUrl):
    rst = b""
    for i in range(24, 120, 4):
        v4 = int.from_bytes(szUrl[i : i + 4], "little")
        for j in range(4):
            v4 = (v4 - 2) & 0xFFFFFFFF
            v4 = ((v4 >> 8) | (v4 << 24)) & 0xFFFFFFFF
        v4 ^= 0x7070707
        rst += v4.to_bytes(4, "little")
    return rst


url = b"http://M17H+G+4FzeJ69F5.*f)vfquhvnv)*fwdhud)*vf)lpktud)*lj)4)*uk)'Lpfwjvjcu)Rpkejrv)Tyehud')*uw)'$v)uqpvpvuqdvuhwu((')*c.mobm.com"
suffix = decrypt_1B0A(url)
print(suffix)

unknown = decrypt_1992(url)
print(unknown)
