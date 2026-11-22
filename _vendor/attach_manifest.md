# 外部附件清单（`_vendor/`）

> 这里放从公开源下载的**原始附件**，只作为取证/复现材料，不参与 git 跟踪
> （`.gitignore` 默认忽略无扩展名 ELF、`*.so`、`*.zip`，只有本文件会被提交）。
> 归档时把二进制复制到对应模式目录，并用 `git add -f` 显式加入。

## 1. 来源

| 源 | 方式 | 说明 |
| --- | --- | --- |
| pwnable.tw | `https://pwnable.tw/static/chall/<name>` | 直接 `curl -O`，返回 200 |
| pwnable.tw libc | `https://pwnable.tw/static/libc/<file>` | `libc-4e5dfd83…so` = Ubuntu 18.04 glibc 2.27 |
| ROP Emporium | `https://ropemporium.com/binary/<name>.zip` | zip 内是二进制 + `libpivot.so` + `flag.txt` |

## 2. 保护矩阵（实测）

| 文件 | 架构 / 链接 | PIE | NX | Canary | RELRO | 拟归类 | 状态 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `start` | i386 / 静态汇编 / 564 B | No | **EXECSTACK (RWE)** | 无 | — | `ret2shellcode` | ✅ 已归档为 `21_pwnable_start` |
| `pivot/pivot` | amd64 / 动态 / not stripped | No | NX | 无 | partial | `stack_pivot` | ✅ 已归档为 `22_ropemporium_pivot` |
| `pivot/libpivot.so` | amd64 / 共享库 | — | NX | 无 | partial | 同上（含 `ret2win@0xa81`、`foothold_function@0x96a`） | ✅ 已归档 |
| `orw` | i386 / 动态 | No | **EXECSTACK (RWE)** | 有 | partial | `sandbox_seccomp` | ✅ 已归档为 `23_pwnable_orw`（本地需 `orw_local_exec`） |
| `tcache_tear` | amd64 / 动态 | No | NX | 有 | Full | `tcache_poisoning` | 待做 |
| `seethefile` | i386 / 动态 | No | NX | 无 | partial | `fsop` | 待做 |
| `death_note` | i386 / 动态 | No | **EXECSTACK (RWE)** | 有 | partial | `shellcode` / heap | 待做 |
| `libc-4e5dfd83….so` | amd64 glibc 2.27 | — | — | — | — | `tcache_tear` 配套 libc | — |

## 3. 备注

- `start` 的 `GNU_STACK` 是 `RWE`，所以它天然是 **ret2shellcode** 而不是 SROP：
  `int 0x80` 前的 `mov al,3/4` 写死，`eax` 无法置成 11。
- `orw` / `death_note` 同样是栈可执行，但要先过 seccomp 或走堆上 shellcode，单独归类。
- `seethefile` 是 32 位，需要 32 位 libc；归档前先确认是否需要额外下载 `libc_32.so.6`。
- `_vendor/` 下的二进制只用于分析；正式归档的副本在模式目录里，用 `git add -f` 提交。
- `labs/lab_srop_baby` 为**自造实验**（无外部来源），只需 `as` + `ld` 即可复现，
  用来补齐 `srop` 模式；不依赖上表中的任何附件或 libc。
