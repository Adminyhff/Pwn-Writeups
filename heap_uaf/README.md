# heap_uaf

> 共同模式特征：**堆块释放后指针仍被引用（Use-After-Free）**
> 典型目标：让新分配的数据落回旧对象，改写函数指针 / vtable / GOT。

---

## 1. 模式特征

```text
delete 只 free，不清空全局表 / 指针
+ note 对象本身包含函数指针
+ 存在同尺寸的重新分配入口
= UAF -> 重占旧对象 -> 劫持控制流
```

本题的分配器语义：

| 操作 | 实际行为 |
| --- | --- |
| `add(size)` | `malloc(8)` 分配 note 结构，再 `malloc(size)` 分配 content |
| `delete(idx)` | 先 `free(content)`，再 `free(struct)`，但不置空 `notelist[idx]` |
| `show(idx)` | 调用 `notelist[idx]->print(notelist[idx])` |

note 结构：

```c
struct note {
    void (*print)(struct note *);   // +0
    char *content;                  // +4
};                                  // 8 字节
```

---

## 2. 本模式题目

| 题目 | 架构 | 关键地址 | 利用 |
| --- | --- | --- | --- |
| `14_hitcontraining_uaf` | i386 / No PIE | `magic=0x8048945` | 0x10 tcache/fastbin LIFO，让新 content 落回旧 struct，改写 `print=magic` |

---

## 3. 文件说明

| 文件 | 作用 |
| --- | --- |
| `14_hitcontraining_uaf_speedrun.md` | 结构、tcache 顺序、完整 EXP 与坑点 |
| `14_hitcontraining_uaf_exp.py` | 武器化 EXP：`add(8)` ×2 → `delete` ×2 → `add(16)` → `add(8, magic)` |
| `hitcontraining_uaf` | 题目二进制 |

---

## 4. 使用方式

```bash
cd '/home/yfhd5/Pwn Writeups/heap_uaf'

I386_LD=/tmp/libc32/root/usr/lib/i386-linux-gnu/ld-linux.so.2 \
I386_LIBPATH=/tmp/libc32/root/usr/lib/i386-linux-gnu \
../.venv/bin/python 14_hitcontraining_uaf_exp.py LOCAL
```

远程：

```bash
HOST=target.example.com PORT=9999 \
python 14_hitcontraining_uaf_exp.py
# CTF² 平台设置 SSL=1
```

---

## 5. 题型识别卡

```text
delete 后不置空全局指针
+ note 里有 print 函数指针
+ 有可控大小的重新 add
= UAF：重占旧 note，改写 print 为 magic / system
```

一句话：**`delete` 不置空是入口；用 tcache/fastbin LIFO 把新 content 落回旧 struct，写 `p32(magic)`。**
