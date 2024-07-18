from pwn import *
import pow_solver

SERVER_IP = "10.113.184.121"
MAX_PATH_LENGTH = 128
MAX_NOTE_LENGTH = 128
MAX_CONTENT_LENGTH = 1024

COMMAND_LENGTH = 164
RESPONSE_LENGTH = 260


def get_service_port():
    r = remote(SERVER_IP, 10044)

    # Solve the proof of work to continue the challenge.
    # sha256(6elZXLRJ5TDPHUqG + ???) == 0000000000000000000000(22)...
    r.recvuntil(b"sha256(")
    prefix = r.recvuntil(b" + ")[:-3].decode()
    r.recvuntil(b"0(")
    difficulty = int(r.recvuntil(b")")[:-1])
    print(prefix, difficulty)
    answer = pow_solver.solve_pow(prefix, difficulty)

    # Answer:
    r.recvuntil(b"Answer: ")
    r.sendline(bytes(str(answer), "utf-8"))

    # Your service is running on port 24054.
    r.recvuntil(b"port ")
    port = int(r.recvuntil(b".")[:-1])

    r.close()

    return port


def reply(r, prompt, reply):
    r.recvuntil(prompt)
    r.sendline(reply)


def get_server_message(r):
    header = b"+==========      Notepad       ==========+"
    msg = r.recvuntil(header)
    return msg[: -len(header)]


def login(r, username, password):
    reply(r, b"> ", b"1")
    reply(r, b"Username: ", username)
    reply(r, b"Password: ", password)
    return get_server_message(r)


def register(r, username, password):
    reply(r, b"> ", b"2")
    reply(r, b"Username: ", username)
    reply(r, b"Password: ", password)
    return get_server_message(r)


def new_note(r, note_name, content_length, content):
    reply(r, b"> ", b"3")
    reply(r, b"Note Name: ", note_name)
    reply(r, b"Content Length: ", bytes(str(content_length), "utf-8"))
    reply(r, b"Content: ", content)
    return get_server_message(r)


def edit_note(r, note_name, offset, content_length, content):
    reply(r, b"> ", b"4")
    reply(r, b"Note Name: ", note_name)
    reply(r, b"Offset: ", bytes(str(offset), "utf-8"))
    reply(r, b"Content Length: ", bytes(str(content_length), "utf-8"))
    reply(r, b"Content: ", content)
    return get_server_message(r)


def show_note(r, note_name, offset):
    reply(r, b"> ", b"5")
    reply(r, b"Note Name: ", note_name)
    reply(r, b"Offset: ", bytes(str(offset), "utf-8"))
    return get_server_message(r)
