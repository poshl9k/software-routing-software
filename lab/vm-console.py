#!/usr/bin/env python3
"""Подключение к serial-консоли VM через libvirt pty и ввод команд отладки.

Использование: python3 vm-console-fix.py [--restore]
"""
import os
import pty
import select
import subprocess
import sys
import time

VM = "vs-router"
USER_PASS = ["123qwe123***"]


def find_ttyconsole(vm: str) -> str:
    out = subprocess.run(["virsh", "ttyconsole", vm], capture_output=True, text=True)
    path = out.stdout.strip()
    return path


def run(vm: str, commands: list[str]) -> None:
    path = find_ttyconsole(vm)
    if not path:
        print("serial console не PTY — переключите serial на pty")
        sys.exit(1)
    pid, fd = pty.fork()
    if pid == 0:
        os.execvp("cat", ["cat", path])
    # родитель: пишем в pty slave через отдельный открытый файл
    pass


if __name__ == "__main__":
    print(find_ttyconsole(sys.argv[1] if len(sys.argv) > 1 else VM))
