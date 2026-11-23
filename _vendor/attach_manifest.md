# 外部附件清单（`_vendor/`）

> 这里放从公开源下载的**原始附件**，只作为取证/复现材料，不参与 git 跟踪
> （`.gitignore` 默认忽略无扩展名 ELF、`*.so`、`*.zip`，只有本文件会被提交）。
> 归档时把二进制复制到对应模式目录，并用 `git add -f` 显式加入。

## 1. 来源

| 源 | 方式 | 说明 |
| --- | --- | --- |
| pwnable.tw | `https://pwnable.tw/static/chall/<name>` | 直接 `curl -O`，返回 200 |
| pwnable.tw libc | `https://pwnable.tw/static/libc/<file>` | 下载的 `libc-4e5dfd83…so` 经 `strings` + `readelf -n` 校验实际是 **Ubuntu GLIBC 2.24-9ubuntu2.2**（build-id `aad7dbe330…`），文件名里的哈希与 build-id 不符 |
| ROP Emporium | `https://ropemporium.com/binary/<name>.zip` | zip 内是二进制 + `libpivot.so` + `flag.txt` |
| Ubuntu old-releases | `http://old-releases.ubuntu.com/ubuntu/pool/main/g/glibc/libc6_2.24-3ubuntu2.2_i386.deb` | 33C3 CTF 2016 `rec` 的本地复现代替品：`dpkg -x` 后取 `lib/ld-linux.so.2` + `lib/i386-linux-gnu/libc.so.6`（md5 `79f8c0d940ae393b3ad1be40892c9c84`），已归档为 `ret2libc/libc-2.24.so` |

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
| `libc-4e5dfd83….so` | amd64 glibc **2.24**（Ubuntu 2.24-9ubuntu2.2） | — | — | — | — | 实测 build-id `aad7dbe330…`，与文件名不符；**不能**当 `tcache_tear` 的 2.27 libc 用 | — |
| `libc6_2.24-3ubuntu2.2_i386.deb`（解包） | i386 glibc **2.24-3ubuntu2.2**（md5 `79f8c0d9…`） | — | — | — | — | `ret2libc`（33C3 `rec` 本地复现） | ✅ 已归档为 `ret2libc/libc-2.24.so` |

## 3. 备注

- `start` 的 `GNU_STACK` 是 `RWE`，所以它天然是 **ret2shellcode** 而不是 SROP：
  `int 0x80` 前的 `mov al,3/4` 写死，`eax` 无法置成 11。
- `orw` / `death_note` 同样是栈可执行，但要先过 seccomp 或走堆上 shellcode，单独归类。
- `seethefile` 是 32 位，需要 32 位 libc；归档前先确认是否需要额外下载 `libc_32.so.6`。
- `_vendor/` 下的二进制只用于分析；正式归档的副本在模式目录里，用 `git add -f` 提交。
- `_vendor/libc-4e5dfd83….so` 版本是 **2.24**（build-id `aad7dbe330…`），不是 pwnable.tw
  `tcache_tear` 配套的 2.27；做 `tcache_tear` 需另下 libc 2.27（仓库内 `card/libc.so` 是
  2.27-3ubuntu1，build-id `b417c0ba…`，可作同代参考）。
- `labs/lab_srop_baby` 为**自造实验**（无外部来源），只需 `as` + `ld` 即可复现，
  用来补齐 `srop` 模式；不依赖上表中的任何附件或 libc。
- 33C3 CTF 2016 `rec` 没有官方 libc 附件：原题跑在 Ubuntu 16.10
  （glibc **2.24-3ubuntu2**）。仓库归档的 `ret2libc/libc-2.24.so` 是
  old-releases 的 `libc6_2.24-3ubuntu2.2_i386.deb` 解包结果（md5 `79f8c0d9…`），
  `__libc_start_main` 偏移与 2ubuntu2 相同（`0x18180`），但 `system`
  （`0x3b020` vs 原版 `0x3a8b0`）与 `/bin/sh`（`0x15f7cf` vs `0x15cbcf`）不同；
  打远程时以 leak 出来的 `__libc_start_main` 为准换对应 libc。
- i386 loader 也要一并解包：`lib/ld-linux.so.2` + `lib/i386-linux-gnu/`，
  EXP 里用 `I386_LD` / `I386_LIBPATH` 指过去（`--library-path` 方式启动）。
