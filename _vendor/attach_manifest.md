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
| ctfs/write-ups-2016（33C3 `rec`） | `https://raw.githubusercontent.com/ctfs/write-ups-2016/master/33c3-ctf/pwn/rec-200/rec` | 33C3 CTF 2016 `rec` 原题二进制，9564 B / sha256 `cc549fbc6045151381eae842b8f4b7a3130c1bcf0e22d5f2093ad92008ebed49`，与本仓库归档副本逐字节一致；若 raw 被 RST，可用 GitHub blob API（blob sha `90f74f94…`）取 base64 解码 |

## 2. 保护矩阵（实测）

| 文件 | 架构 / 链接 | PIE | NX | Canary | RELRO | 拟归类 | 状态 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `start` | i386 / 静态汇编 / 564 B | No | **EXECSTACK (RWE)** | 无 | — | `ret2shellcode` | ✅ 已归档为 `21_pwnable_start` |
| `pivot/pivot` | amd64 / 动态 / not stripped | No | NX | 无 | partial | `stack_pivot` | ✅ 已归档为 `22_ropemporium_pivot` |
| `pivot/libpivot.so` | amd64 / 共享库 | — | NX | 无 | partial | 同上（含 `ret2win@0xa81`、`foothold_function@0x96a`） | ✅ 已归档 |
| `orw` | i386 / 动态 | No | **EXECSTACK (RWE)** | 有 | partial | `sandbox_seccomp` | ✅ 已归档为 `23_pwnable_orw`（本地需 `orw_local_exec`） |
| `tcache_tear` | amd64 / 动态 | No | NX | 有 | Full | `tcache_poisoning` | **PENDING**（2026-11-26 降级：2.27 无 key 但 free≤8 次 < 链路需 9 次；见 `_pending/README.md`） |
| `seethefile` | i386 / 动态 | No | NX | 无 | partial | `fsop` | ✅ 已归档为 `fsop/29_pwnable_tw_seethefile`（`_IO_str_finish` FSOP） |
| `death_note` | i386 / 动态 | No | **EXECSTACK (RWE)** | 有 | partial | `shellcode` / heap | **PENDING**（未展开；需 i386 2.24/2.23 无 tcache 环境，见 `_pending/README.md`） |
| `libc-4e5dfd83….so` | amd64 glibc **2.24**（Ubuntu 2.24-9ubuntu2.2） | — | — | — | — | 实测 build-id `aad7dbe330…`，与文件名不符；**不能**当 `tcache_tear` 的 2.27 libc 用 | — |
| `libc6_2.24-3ubuntu2.2_i386.deb`（解包） | i386 glibc **2.24-3ubuntu2.2**（md5 `79f8c0d9…`） | — | — | — | — | `ret2libc`（33C3 `rec` 本地复现） | ✅ 已归档为 `ret2libc/libc-2.24.so` |
| `rec`（33C3） | i386 / 动态 / stripped / 9564 B | **Yes** | NX | 有 | **Full** | `ret2libc`（未初始化函数指针 + Polish `esp` 泄漏） | ✅ 已归档为 `ret2libc/rec_33c3_2016`（sha256 `cc549fbc…`） |

## 3. 备注

- `start` 的 `GNU_STACK` 是 `RWE`，所以它天然是 **ret2shellcode** 而不是 SROP：
  `int 0x80` 前的 `mov al,3/4` 写死，`eax` 无法置成 11。
- `orw` / `death_note` 同样是栈可执行，但要先过 seccomp 或走堆上 shellcode，单独归类。
- `seethefile` 是 32 位，需要 32 位 libc；归档后本地复现用 `ret2libc/libc-2.24.so`
  （2.24-3ubuntu2.2 i386，md5 `79f8c0d9…`）+ 同 deb 的 `ld-linux.so.2`。
  该 libc 的 `_IO_str_jumps = 0x1B49C0`、`system = 0x3B020`；EXP 会从 `LIBC` 文件里
  自己在 `__libc_IO_vtables` 段定位 `_IO_str_jumps`，换版本只需换 `LIBC`。
- `_vendor/` 下的二进制只用于分析；正式归档的副本在模式目录里，用 `git add -f` 提交。
- **未解题目统一收口（2026-11-26）**：原顶层 `To Be Continued/` 已解散，
  `judgement_mna_2016` → `_pending/35_judgement_mna_2016/`、`publibc/bf` → `_pending/36_publibc_bf/`，
  各带一份 `recon.md`。`_pending/` 的二进制同样是 deny-all 白名单外，归档用 `git add -f`。
  本清单上表中 `tcache_tear` / `death_note` 的 PENDING 状态也以 `_pending/README.md` 为准。
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
- **`_vendor/ret2csu/`（2026-11-25 补档）**：ROP Emporium `ret2csu.zip`
  （`https://ropemporium.com/binary/ret2csu.zip`）的原始四件套
  `ret2csu` / `libret2csu.so` / `key.dat` / `encrypted_flag.dat`。
  背景：`ret2csu/` 目录里的 `key.dat` 与 `encrypted_flag.dat` 在本轮某次矩阵跑完后不见了
  （二进制本身没有 `unlink`/`remove` 导入，原因未定位），导致 `30` 一度 FAIL：
  `Failed to open encrypted_flag.dat`。把它们从 zip 复原后 `cmp` 确认 `ret2csu` 与仓库内二进制完全一致（sha256 `8891368e…`），`libret2csu.so` 也一致（`c8916f77…`）。
  以后再丢就从这里 `cp` 回去：
  `cp _vendor/ret2csu/{key.dat,encrypted_flag.dat} ret2csu/`。
- **`_vendor/ropemporium/`（2026-11-25 新增，同日晚补 `callme` / `fluff`）**：
  ROP Emporium 的 `write4.zip` / `badchars.zip` / `callme.zip` / `fluff.zip` 原始压缩包
  （`https://ropemporium.com/binary/<name>.zip`，下载时均为 HTTP 200）。
  `write4` / `badchars` / `fluff` 各含 3 个文件：主程序、`lib<solver>.so`、`flag.txt`
  （33 字节，内容 `ROPE{a_placeholder_32byte_flag!}` + `\n`，三份完全相同）；
  `callme` 含 5 个文件：主程序、`libcallme.so`、`key1.dat`、`key2.dat`、`encrypted_flag.dat`
  （**没有明文 flag.txt**，flag 由 `callme_three` 用两个 key 解密后打印）。
  注意 `python -c "zipfile.ZipFile(...).extractall()"` **不保留可执行位**，
  解出后必须 `chmod +x`，否则 `process('./write4')` 报
  `not marked as executable (+x)`。

  | 文件 | sha256 |
  | --- | --- |
  | `_vendor/ropemporium/write4.zip` | `3925c857cf71cbd218604f733faa7beafe520459bdfdee46d02c3c9033ad042f` |
  | `_vendor/ropemporium/badchars.zip` | `f6e8d54c004a5ad658bbd85c55777f82de897f863313d8a1c31d8417ce114425` |
  | `rop_write_memory/write4`（解出） | `15c9fc1d4dff1874633caebd212d4990243b072f9352baa23daf07f39a93f8cd` |
  | `rop_write_memory/libwrite4.so` | `9e3233c955c3abedb9a2940e5357b9eade80800d6864cbd1d8dbade038166dcc` |
  | `badchars_encoding/badchars`（解出） | `5308289f3937a34e4c5eac818e394217f5f22c6f21fbb0f6dc6b8e3f771deb8b` |
  | `badchars_encoding/libbadchars.so` | `8765298372d1752663010530db5d6c744e746c0a0cf7d978abb28ab0a3b28f78` |
  | 两个目录的 `flag.txt`（同一份） | `04ccfeba117d050cc8d4d86db473d042295896cd808e54d7c12833d6327f104f` |
  | `_vendor/ropemporium/callme.zip` | `a32deecd2f018bca0d2cce7e4ece2f60c08e3915e97f30f4d30e8d61ebf20741` |
  | `_vendor/ropemporium/fluff.zip` | `a2d3ab1dbc201d5064845ae3ca1230b2da9f75aabd5f83bf46b92918a2769a76` |
  | `ret2csu/callme_lab/callme`（解出） | `38b3aac5f11e673ecfbe344f9330d7dfa7d6921be506a948ab9d0347af756acb` |
  | `ret2csu/callme_lab/libcallme.so` | `3163a8e07f0a199e3b64eb7da43830b97ece4476d051f265adeacdd1a35913f3` |
  | `ret2csu/callme_lab/key1.dat` | `5dfbabeedf318bf33c0927c43d7630f51b82f351740301354fa3d7fc51f0132e` |
  | `ret2csu/callme_lab/key2.dat` | `72055d73b96127ded060a77d59fcf8740ced6dbdddbe9e102836a8092e837589` |
  | `ret2csu/callme_lab/encrypted_flag.dat` | `3160bfe63155c8f9f0d8ff0e508dda005c94bf2e5b76c2f872b87e322f07739b` |
  | `badchars_encoding/fluff`（解出） | `e5335795104d861dc5e54c8734e090f1c7dfd5b642e4607c2747aed7529c724d` |
  | `badchars_encoding/libfluff.so` | `09fbb5844522ee3f38a929245e4744eabed52f988c54e6b53ed26540ab3bfa55` |

  四题都是 No PIE + `RUNPATH=b'.'`：EXP 里先 `chdir` 到脚本目录，否则 loader 找不到
  `libwrite4.so` / `libbadchars.so` / `libcallme.so` / `libfluff.so`；
  `print_file` 也从 cwd 打开 `flag.txt`，`callme` 则从 cwd 读三个 `.dat`。
  归档副本：`rop_write_memory/{write4,libwrite4.so,flag.txt}`、
  `badchars_encoding/{badchars,libbadchars.so,flag.txt,fluff,libfluff.so}`、
  `ret2csu/callme_lab/{callme,libcallme.so,key1.dat,key2.dat,encrypted_flag.dat}`
  （ELF 为 deny-all 白名单外，需 `git add -f`）。
  注意 `ret2csu/encrypted_flag.dat`（30 用，`37aa4baf…`）与
  `ret2csu/callme_lab/encrypted_flag.dat`（33 用，`3160bfe6…`）**同名不同内容**，
  不能互换，也不要合成一份。
