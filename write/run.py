#!/usr/bin/env python3
"""Script for hosting a binary on a port."""
import subprocess

PRELOAD = 'dist/libc-2.27.so'
LD = ''
BINARY = 'dist/write'

PORT = 2222
PORT_DBG = 2223
PORT_DBG_GDB = 2224

# TODO: add --no-disable-randomization

def main():
    """Starts two socat instances for hosting the binary."""

    print(f'Staring binary <{BINARY}>.')
    print('Use ^C for termination.')

    socat = 'socat'

    socat_config = f'tcp-l:{PORT},fork,reuseaddr'
    socat_config_dbg = f'tcp-l:{PORT_DBG},fork,reuseaddr'

    if LD:
        socat_exec = f'./{LD} ./{BINARY}'
        socat_exec_dbg = f'./{LD} ./{BINARY}'
    else:
        socat_exec = f'./{BINARY}'
        socat_exec_dbg = f'./{BINARY}'

    if PRELOAD:
        socat_exec = f'EXEC:"env LD_PRELOAD={PRELOAD} {socat_exec}"'
        socat_exec_dbg = f'EXEC:"stdbuf -o0 gdbserver --wrapper env \'LD_PRELOAD={PRELOAD}\' -- :{PORT_DBG_GDB} {socat_exec_dbg}"'
    else:
        socat_exec = f'EXEC:"{socat_exec}"'
        socat_exec_dbg = f'EXEC:"gdbserver :{PORT_DBG_GDB} {socat_exec_dbg}"'

    try:
        p_socat = subprocess.Popen([socat, socat_config, socat_exec])
        p_socat_dbg = subprocess.Popen([socat, socat_config_dbg, socat_exec_dbg])
        p_socat.wait()
        p_socat_dbg.wait()
    except KeyboardInterrupt:
        print('\nShutting down.')

if __name__ == '__main__':

    main()
