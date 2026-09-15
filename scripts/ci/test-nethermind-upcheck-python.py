#!/usr/bin/env python3
"""Exercise supplied public proxy source in its candidate Python container."""
import io
import socket
import sys

code = sys.stdin.read()
start = "HTTPServer(('0.0.0.0', 8080), Handler).serve_forever()"
assert code.rstrip().endswith(start), "unexpected server startup contract"
scope = {}
exec(code.rstrip()[:-len(start)], scope)
Handler = scope["Handler"]
connections = []


class Connection:
    # No send/write interface: the health check may only connect and close.
    def close(self):
        connections.append("closed")


def connect(address, timeout):
    assert address == ("nethermind-execution", 30303)
    assert timeout == 5
    connections.append("connected")
    return Connection()


class Request:
    def __init__(self, method, path):
        self.input = io.BytesIO(
            f"{method} {path} HTTP/1.1\r\nHost: localhost\r\n\r\n".encode()
        )
        self.output = io.BytesIO()

    def makefile(self, *args):
        return self.input

    def sendall(self, value):
        self.output.write(value)


def check(method, path, status):
    request = Request(method, path)
    Handler(request, ("127.0.0.1", 1), None)
    headers = request.output.getvalue().split(b"\r\n\r\n", 1)[0].lower()
    assert headers.startswith(f"http/1.0 {status} ".encode()), headers
    assert b"\r\ndate:" in headers
    assert b"\r\nserver:" not in headers and b"python" not in headers


socket.create_connection = connect
check("GET", "/upcheck", 200)
assert connections == ["connected", "closed"]
for method in ("POST", "PUT", "PATCH", "DELETE"):
    check(method, "/upcheck", 405)
for path in ("/jsonrpc", "/upcheck?target=evil", "/api/v1/eth2/sign/0x00"):
    check("GET", path, 404)
assert connections == ["connected", "closed"], "denied request contacted upstream"


def unavailable(*args, **kwargs):
    raise OSError("synthetic upstream unavailable")


socket.create_connection = unavailable
check("GET", "/upcheck", 503)
print("PASS: actual proxy code on candidate Python: fixed TCP target, no application bytes, denied routes/methods, unavailable=503, no runtime header disclosure")
