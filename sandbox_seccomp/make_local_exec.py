#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""为 pwnable.tw `orw` 生成本地可执行版（把 .bss 所在 PT_LOAD 加上 PF_X）

背景：
  题目的 shellcode 被 `read` 到硬编码地址 `0x804a060`，它落在第二个 PT_LOAD
  （p_flags = RW，不可执行）。pwnable.tw 当年跑在 2.6.32 老内核上，RW 段实际
  可执行，所以原版能直接 `call 0x804a060`；现代内核严格 NX，本地跑会 SIGSEGV。

做法：
  只改 program header 里的 p_flags（加 PF_X），不改任何代码。生成 `orw_local_exec`，
  原版 `orw` 保持不动（归档/远程用原版）。

用法：
  python make_local_exec.py            # 生成 orw_local_exec
"""

import shutil
import struct

SRC = "orw"
DST = "orw_local_exec"

PF_X = 0x1
PT_LOAD = 0x1


def main() -> None:
    data = bytearray(open(SRC, "rb").read())

    e_phoff = struct.unpack_from("<I", data, 0x1C)[0]
    e_phentsize = struct.unpack_from("<H", data, 0x2A)[0]
    e_phnum = struct.unpack_from("<H", data, 0x2C)[0]

    patched = 0
    for i in range(e_phnum):
        off = e_phoff + i * e_phentsize
        p_type, p_off, p_vaddr, p_paddr, p_filesz, p_memsz, p_flags, p_align = (
            struct.unpack_from("<IIIIIIII", data, off)
        )
        if p_type == PT_LOAD and p_vaddr == 0x08049F08:
            print(
                "PT_LOAD vaddr=%#x flags=%#x -> %#x"
                % (p_vaddr, p_flags, p_flags | PF_X)
            )
            struct.pack_into("<I", data, off + 24, p_flags | PF_X)
            patched += 1

    if not patched:
        raise SystemExit("没找到目标 PT_LOAD，二进制可能不是预期的 orw")

    with open(DST, "wb") as f:
        f.write(data)
    shutil.copymode(SRC, DST)
    print("written:", DST)


if __name__ == "__main__":
    main()
