# L11 · pie_partial_overwrite → 1 字节局部覆盖 saved RIP（自造靶场）

> PIE 把基址随机化了，却没随机化**页内偏移**。所以当溢出只够覆盖返回地址的
> **最低 1 字节**、又拿不到任何泄漏时，答案不是爆破，而是把返回地址改到
> **同一个 256 字节块内**的另一条指令 —— 高 7 字节一个都不用动。

## 1. 环境

| 项 | 值 |
| --- | --- |
| 平台 | linux / amd64 |
| libc | **与 glibc 版本无关**（本题不碰堆，也不用 libc 里的任何函数地址） |
| 编译 | `gcc -O0 -g -fPIE -pie -fno-stack-protector` |
| 依赖 | 只要主机 gcc + `objdump`（exp 用它自动解析两个地址） |

```bash
cd labs/lab_pie_partial_overwrite
make
printf '__PWNED__{pie_partial_ok}\n' > flag.txt
python exp.py      # 期望输出 __PWNED__{pie_partial_ok} 与 "PIE 局部覆盖（1 字节）OK"
```

远程验证（可选）：

```bash
socat TCP-LISTEN:9999,reuseaddr,fork EXEC:./chal
HOST=127.0.0.1 PORT=9999 python exp.py
```

`checksec` 结果（`make` 之后）：

```text
PIE: enabled    NX: enabled    Canary: disabled    RELRO: Partial
```

* 调试开关：`ERRLOG=/tmp/e11.log python exp.py` 会把子进程 stderr 落盘
  （与 L9 / L10 的 exp 保持一致的调试接口；本题正常路径不会触发 glibc 的
  `malloc_printerr`，所以日志通常是空的，只在改坏布局时有用）。

## 2. 漏洞

`vuln()` 里唯一的 bug：

```c
char buf[0x40];
read(0, buf, 0x40 + 8 + 1);   /* ← 多读 9 字节 */
```

- `buf[0x40]`：`0x40` 字节；
- `+8`：吃掉 saved rbp；
- 最后的 `+1`：**正好是 saved rip 的最低字节**。

于是我们能把这 1 个字节改成任意值，返回地址的高 7 字节保持不变。

## 3. 利用链

```text
main  = 0x1400                    # aligned(256)，函数体 0x5e < 0x100 → 不变量结构性成立
call vuln          @ main+0x35    # 返回地址 = main+0x3a = 0x143a
puts("nope")       @ main+0x3a
if (never) win_path();            # 目标 = main+0x53 = 0x1453（call win_path）
payload = b"A"*0x48 + p8(0x53)    # 只改最低字节 0x3a -> 0x53，长度正好 0x49
```

| 量 | 值 |
| --- | --- |
| 偏移到 saved RIP | `0x48`（`0x40` buf + `0x8` saved rbp） |
| 返回地址 | `0x143a` |
| 目标地址 | `0x1453` |
| 同块判定 | `0x143a >> 8 == 0x1453 >> 8 == 0x14` |
| payload 长度 | `0x49`（= `read` 的长度，必须正好） |

`0x143a` 与 `0x1453` 都在 `0x1400..0x14ff` 这一块里，只差最低字节，
所以 **1 字节覆盖 100% 命中**，不需要 1/16 的 nibble 爆破。

## 4. 关键坑点（实测）

1. **必须正好发 0x49 字节**：`read` 是定长读。少发会让 `read` 提前返回
   （saved rbp 都没补全，返回地址根本没被碰到）；多发则多余字节留在
   stdin 缓冲里，下一次读取错位（本程序读一次就退出，所以表现为"看起来没反应"）。
2. **同块是硬约束**：如果 `main` 函数体超过 `0x100` 字节，返回地址和 win 分支
   会跨到相邻的 256 字节块，此时 1 字节覆盖**必然失败**。两种对策：
   ① 像本 lab 一样 `__attribute__((aligned(256)))` + 保持 `main` 短小；
   ② 覆盖 1.5 字节（第 2 字节只改低 4 bit）并做 1/16 nibble 爆破。
3. **`-fno-stack-protector` 必须显式给**：否则这 1 字节先撞 canary，
   `__stack_chk_fail` 直接 abort，连返回地址都到不了。
4. **`-fPIE -pie` 必须显式给**：Ubuntu 默认虽然是 PIE，但脚本化编译时常被
   `-no-pie` 覆盖；退化成 No PIE 之后本题就变成普通的 `ret2text`（直接写绝对地址），
   失去教学意义。
5. **不可达分支不能被优化掉**：`never` 必须是 `static volatile int`（或等价的
   外部可见写法），`-O0` 下 `if (never) win_path();` 才会生成真实的 `call`。
   写成 `return` 之后的死代码、`#if 0`、或 `if (0)`，GCC 会直接删掉目标代码。
6. **exp 不写死偏移**：`exp.py` 每次用 `objdump -d -M intel` 解析
   `call <vuln>` 的下一条指令（返回地址）与 `call <win_path>`（目标），
   并断言 `(ret >> 8) == (win >> 8)`。改了 `chal.c` 之后要么自动跟上，
   要么明确报错，不会静默失效。

## 5. 为什么归类为 `pie_partial_overwrite`（而不是 ret2text / ret2libc）

| 候选 | 为什么不是 |
| --- | --- |
| `ret2text` | 经典 ret2text 要求 No PIE 或已知基址；这里基址随机且**无任何泄漏点**，无法写绝对地址 |
| `ret2libc` | 溢出只有 1 字节，装不下 ROP 链；也没有任何 leak 原语 |
| `canary_bruteforce` | 本题没有 canary，也没有 fork server，爆破无从谈起 |
| `stack_pivot` | 1 字节改不了 `rsp`（`leave; ret` 需要覆盖更多字节） |

它的判定特征是：**PIE + 溢出长度只够改地址低字节 + 无泄漏**，
利用点是"镜像内部相对布局固定"。

## 6. 复现自检

```bash
cd '/home/yfhd5/Pwn_Writeups' && source .venv/bin/activate
bash tools/verify_all.sh L11       # 期望 PASS=1 FAIL=0 SKIP=0
python tools/repro_audit.py L11    # 编译/二进制/环境变量/文档块全部通过
```

## 7. 变体：什么时候需要 1.5 字节 + 爆破

把 `main` 写长一点（例如在里面直接内联读 flag 的代码）就能人为造出跨块场景：

- 第 1 个字节改 `rip` 的低 8 位；
- 第 2 个字节只能改低 4 bit（高 4 bit 来自 PIE 基址的第 12–15 位，随机）；
- 于是命中概率 `1/16`，用 `for _ in range(16): try_connect()` 一直重试即可。

真实赛题里 1.5 字节覆盖常用于"PIE + 只能溢出一个字节多一点点"的场景，
识别卡是：**溢出长度落在 1~2 字节之间、且目标与返回地址在同一个 4KB 页**。
