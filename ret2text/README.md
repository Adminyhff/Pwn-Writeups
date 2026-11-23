# ret2text

> 共同模式特征：**栈溢出 + 返回地址跳转到二进制内已有代码（后门函数 / 代码片段）**
> 不注入 shellcode，不泄露 libc，`NX` 是否开启都不影响。
> 目标通常是一个 `system(...)` 后门，或读取 flag 的隐藏函数。

---

## 1. 模式特征

```text
存在无边界输入（gets / read 等）
+ 可覆盖 saved RIP
+ 二进制内已有可复用的后门函数或 system@plt + 字符串
+ No PIE（或地址可知）
= ret2text
```

标准流程：

1. `file` / `checksec`：确认位数、PIE、Canary、NX、是否 stripped。
2. `nm` / `objdump` / `strings`：找后门函数、`system@plt`、`/bin/sh`、`flag.txt`。
3. 反汇编漏洞函数：从 buffer 起址算到 saved RIP 的偏移。
4. 构造返回地址；64 位下注意跳过 `push rbp` 保证 `system` 的 16 字节栈对齐。
5. 需要参数时按调用约定伪造栈帧；需要刷新 stdout 时把返回地址接到 `exit`。
6. 发送 payload，接收并正则提取 flag。

---

## 2. 本模式题目

| 题目 | 架构 / 链接 | 输入点 | 偏移 | 目标 | 备注 |
| --- | --- | --- | --- | --- | --- |
| `02_rip` | amd64 / 动态 / not stripped | `gets(buf)`，`buf=rbp-0xf` | **23** | `fun+1 = 0x401187` | `fun` 内 `system("/bin/sh")`；跳 `0x401186` 会因 `push rbp` 破坏栈对齐 |
| `03_warmup_csaw_2016` | amd64 / 动态 / stripped | `gets(buf)`，`buf=rbp-0x40` | **72** | `0x40060e` | 程序主动泄露后门 `WOW:0x40060d`；后门执行 `system("cat flag.txt")` |
| `05_get_started_3dsctf_2016` | i386 / **静态** / not stripped | `gets(buf)`，`buf=esp+4` | **56** | `get_flag = 0x080489a0` | 隐藏后门要求两个 magic 参数；返回地址接 `exit` 刷新 stdio |
| `06_jarvisoj_level0` | amd64 / 动态 / not stripped | `read(0, buf, 0x200)`，`buf=rbp-0x80` | **136** | `callsystem+1 = 0x400597` | `callsystem` 内 `system("/bin/sh")`；跳 `0x400596` 会 `push rbp` 破坏栈对齐 |
| `09_canary` | amd64 / 动态 / PIE | 三次 `read`，`buf=rbp-0x30`；canary `%11$p` | **56**（canary 40） | `system@plt`（PIE） | 格式化字符串 leak canary/PIE，`%256c%9$n` 把 `money` 改成 256，再 canary-safe ROP |
| `27_jarvisoj_http` | amd64 / 动态 / No PIE / No canary | 服务端逐字节 `read(fd,&c,1)` 直到 `\r\n\r\n`，`buf=rbp-0x210` | saved RIP 在字节流 **0x216** | `__libc_csu_init` 链：`read`→`popen`→`waitpid` | 栈溢出在 httpd 请求读取里；计数器 `cnt` 位于 `buf+0x20C`，需要先绕过回卷 |

### 共同点与差异

共同点：

- 漏洞都来自无边界输入（`gets` / `read`），并覆盖 saved RIP。
- 02 / 03 / 05 / 06 都是 **No PIE + No Canary**，可直接硬编码地址。
- 都通过覆盖返回地址进入二进制内已有代码，而不是执行栈上 shellcode。

`09_canary` 是本模式的 PIE + Canary 变体：先 leak canary / PIE，再用格式化字符串把全局 `money` 改成 256，最后做 canary-safe ROP；它仍然跳到二进制内的 `system@plt`，所以归入 ret2text。

`27_jarvisoj_http` 是本模式的“无后门”变体：栈溢出发生在服务端读请求的函数里，
二进制里没有现成的 `system("/bin/sh")`，但 `No PIE + 无 canary` 让它可以直接用
`__libc_csu_init` 的 `call qword ptr [r12+rbx*8]` 依次调 `read` / `popen` / `waitpid`，
等价于“返回到二进制内已有代码 + 自己拼调用”，因此同样归入 ret2text。

差异：

| 维度 | 02 / 03 | 05 | 06 |
| --- | --- | --- | --- |
| 架构 | amd64 | i386 | amd64 |
| 输入函数 | `gets` | `gets` | `read` |
| 参数传递 | 后门内部已准备好 `rdi` | cdecl，需要在栈上伪造 arg1/arg2 | `callsystem` 内部准备好 `rdi` |
| 栈对齐 | 需要跳过 `push rbp`（跳到 `+1`） | i386 无 16 字节对齐要求 | 需要跳过 `push rbp`（跳到 `+1`） |
| 输出 | 直接拿 shell / 直接 `cat flag.txt` | 必须接 `exit` 刷新全缓冲 stdout | 直接拿 shell |

---

## 3. 文件说明

| 题目 | 速通 | 详细 writeup | EXP | 二进制 |
| --- | --- | --- | --- | --- |
| `02_rip` | `02_rip_speedrun.md` | `02_rip_writeup.md` | `02_rip_exp.py` | `rip` |
| `03_warmup_csaw_2016` | `03_warmup_csaw_2016_speedrun.md` | `03_warmup_csaw_2016_writeup.md` | `03_warmup_csaw_2016_exp.py` | `warmup_csaw_2016` |
| `05_get_started_3dsctf_2016` | `05_get_started_3dsctf_2016_speedrun.md` | `05_get_started_3dsctf_2016_writeup.md` | `05_get_started_3dsctf_2016_exp.py` | `get_started_3dsctf_2016` |
| `06_jarvisoj_level0` | `06_jarvisoj_level0_speedrun.md` | 无（speedrun 已含完整逆向） | `06_jarvisoj_level0_exp.py` | `jarvisoj_level0` |
| `09_canary` | `09_canary_speedrun.md` | 无（speedrun 已含完整逆向） | `09_canary_exp.py` | `[NewStarCTF 公开赛赛道]canary/pwn` |
| `27_jarvisoj_http` | `27_jarvisoj_http_speedrun.md` | 无（speedrun 已含完整逆向） | `27_jarvisoj_http_exp.py` | `jarvisoj_http`（+ `../tools/loopback_unix_shim.c`） |

---

## 4. 使用方式

```bash
cd '/home/yfhd5/Pwn Writeups/ret2text'

# 02
python 02_rip_exp.py

# 03
python 03_warmup_csaw_2016_exp.py

# 05：远端 / 本地（本地模式要求当前目录存在 flag.txt）
python 05_get_started_3dsctf_2016_exp.py
python 05_get_started_3dsctf_2016_exp.py LOCAL

# 06：本地验证 shell / 远程
python 06_jarvisoj_level0_exp.py LOCAL
HOST=target.example.com PORT=9999 python 06_jarvisoj_level0_exp.py

# 09：PIE + canary + format string；本地直接跑
python 09_canary_exp.py LOCAL
HOST=target.example.com PORT=9999 python 09_canary_exp.py

# 27：httpd 自身监听 127.0.0.1:3847，EXP 起进程后连回环
python 27_jarvisoj_http_exp.py LOCAL
HOST=target.example.com PORT=3847 python 27_jarvisoj_http_exp.py
# WSL2 loopback TCP 不可用时（宿主网络栈问题）：
gcc -shared -fPIC -O2 -o ../tools/loopback_unix_shim.so ../tools/loopback_unix_shim.c -ldl
USE_UNIX=1 python 27_jarvisoj_http_exp.py LOCAL   # LD_PRELOAD 改 AF_UNIX，fd 编号不变

# 一键本地矩阵（05 / 27）
bash ../tools/verify_all.sh 05 27
```

> EXP 中硬编码的远程地址会随靶机变化，运行前替换 `HOST`。

---

## 5. 题型识别卡

```text
gets / read + 可覆盖 RIP
+ 二进制里有 system("/bin/sh") / system("cat flag") / 隐藏 get_flag
+ 通常 No PIE + No Canary
= ret2text
（09 例外：有 canary/PIE，先 leak 再 ROP）
（27 例外：没有后门函数，用 __libc_csu_init gadget 自己拼 read/popen 调用）
```

一句话：**先找后门，再算偏移；64 位记得跳 `push rbp` 的下一条指令；
没有后门时，No PIE 的 CSU 链就是“通用后门”。**
