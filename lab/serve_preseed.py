#!/usr/bin/env python3
"""Мини-HTTP сервер для раздачи preseed лабораторной VM (только 127.0.0.1:8088)."""
import http.server
import functools

DIRECTORY = "/var/lib/libvirt/images"

if __name__ == "__main__":
    handler = functools.partial(http.server.SimpleHTTPRequestHandler, directory=DIRECTORY)
    server = http.server.ThreadingHTTPServer(("0.0.0.0", 8088), handler)
    print("serving on 127.0.0.1:8088")
    server.serve_forever()
