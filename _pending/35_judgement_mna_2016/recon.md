# 35 · `judgement_mna_2016` 侦察记录（PENDING）

> MNA 2016「flag 判定器」。**格式化字符串**，但输入被 `isprint` 逐字节过滤，
> 这条过滤直接把"往格式串里塞 4 字节地址"的唯一常规路线堵死。
> 记录日期：2026-11-23 首轮，2026-11-26 归档复核（本轮只复核可运行性，未重跑 arg 扫描）。

## 0. 可运行性（2026-11-26 实测）

```bash
cd '/home/yfhd5/Pwn_Writeups/_pending/35_judgement_mna_2016'
printf 'FLAG{test}\n' > flag.txt          # load_flag 读 ./flag.txt，缺文件则 flag 全 0
printf 'AAAA\n' | \
  ../../labs/lab_ret2dlresolve_i386/libc/ld-2.24.so \
  --library-path ../../labs/lab_ret2dlresolve_i386/libc ./judgement_mna_2016
rm -f flag.txt
```

实测输出：

```text
Flag judgment system
Input flag >> AAAA
Wrong flag...
```

（用仓库内 `labs/lab_ret2dlresolve_i386/libc/` 的 i386 glibc 2.24 loader，
不需要 `/tmp` 下的解包目录；`/tmp/libc224i32` 也可用。）

## 1. 二进制事实

| 项 | 值 |
| --- | --- |
| 架构 | ELF 32-bit i386，动态链接，not stripped |
| 保护 | No PIE（`0x8048000` 基址固定）、NX、Canary、Partial RELRO |
| 符号 | `main@0x804872b`、`init@0x804868d`、`load_flag@0x80487f3`、`getnline@0x8048869` |
| flag 缓冲 | `0x804a0a0`（`0x40` 字节，`.bss`，与 `strchr@GOT=0x804a030`、GOT 基址 `0x804a000` 同页） |

## 2. 程序逻辑（`objdump -d -M intel` 复核）

```text
init():   setbuf(stdin/stdout, NULL); load_flag("flag.txt", 0x804a0a0, 0x40)

main @0x804872b:
  printf("Flag judgment system\nInput flag >>")
  buf = ebp-0x4c  (0x40)
  getnline(buf, 0x40)
      -> fgets(buf, 0x40, stdin)      @0x8048885
      -> strchr(buf, '\n'); *p = 0    @0x8048898 / 0x80488a9
      -> strlen(buf)
      -> for i in range(len): if (!isprint(buf[i])) return 0;   @0x80488d4
  if (!getnline(...)) { puts("Unprintable character"); return -1; }
  printf(buf)                          @0x80487a2   <-- 唯一的漏洞点
  strcmp(buf, 0x804a0a0)               @0x80487b5
  puts("Correct flag!!") / puts("Wrong flag...")
  __stack_chk_fail 保护
```

`getnline` 的 `isprint` 循环是硬约束：只要出现 `>=0x80`、`<0x20` 或 `0x7f` 的字节，
函数返回 0，`main` 打印 "Unprintable character" 后退出 —— **`printf` 根本执行不到**。

## 3. 已经验证过的结论（不要重复）

本地 i386 loader + `%1$p` … `%264$p` 全扫（首轮日志 `/tmp/audit/probe_judge.log`）：

```text
arg 43  = buf 起始（输入 "AAAA"）
arg 35  = 0x804a030  = strchr@GOT（_dl_runtime_resolve 残留）
arg 72  = 0x804a000  = _GLOBAL_OFFSET_TABLE_
arg 105 = 0x804872b  = main
args 1..264 中不存在 0x804a0a0（flag），也不存在 0x804a010（strcmp@GOT）
```

另外已排除：

- `%35$s` 顺读：只吐出 4 个 GOT 指针就被 `0x804a040` 的零字节截断；`%72$s` 只吐 3 字节，
  **跨不到** `0x804a0a0`。
- "把 `0x804a0a0` 写进格式串"：地址字节含 `0x08` / `0x80` / `0xa0`，全部被 `isprint` 拒绝。

## 4. 阻塞点

1. `isprint` 过滤 = 只能发可打印 ASCII（`0x20..0x7e`），**无法构造任何绝对地址**，
   所以 `%n` 写任意地址这条路被切断 —— 除非目标地址的 4 个字节恰好全可打印（`0x804a0a0` 不是）。
2. `strcmp` / `puts` / `printf` 之外，`.GOT` 里能用的指针槽只有 `strchr@GOT`，
   而 `strchr` 在 `printf(buf)` **之后**才被调用（`getnline` 里），算"还有一次调用机会"。
3. 没有栈溢出（canary + `fgets` 长度受控），也没有 leak 通道输出 flag 本身。

## 5. 下一步（按性价比排序）

1. **`%n` 改 `strchr@GOT` → 让程序跑第二轮**：目标值写 `main`（`0x804872b` ≈ 1.34e8，
   `%134514475c%N$n` 可行但输出量巨大；也可写 `getnline` / `fgets` 等更近的函数）。
   第二轮里 `strcmp@GOT` / `puts@GOT` 已经完成惰性绑定，栈上才会出现
   `0x804a010` 这类新指针槽 → 那时才有 `%N$s` 直读 flag 的可能。
2. `strchr@GOT` LSB 单字节改写（`0x804a030` 的低字节可打印 → 能被 `%hhn` 命中）：
   把 `strchr` 重定向到同页内的可用函数（例如 `fgets` / `strlen`），观察第二轮行为。
3. 若上面都不通，考虑 `printf` 的 `%s` + `arg 43`（buf 自身）构造"把栈上当指针用"的链；
   但注意 `isprint` 也限制 buf 内容，二进制地址无法直接出现在栈上。

**重开提示**：不要重新扫栈（§3 的全扫结论仍然有效），直接从第 1 条开始。
