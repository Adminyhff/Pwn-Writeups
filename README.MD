*"Started in Nov, Freshman Year. Goal: Top 100 on BUUCTF Pwn Leaderboard. Solo. No teams."*

## Environment
- OS: WSL2 Ubuntu
- Toolchain: GCC, GDB + pwndbg, pwntools
- Python Virtual Environment: `.venv`

## Repository Layout

本仓库按 **题型模式特征（pattern）** 组织，而不是按单道题目建文件夹。
同一模式下的题目文件统一放在以该模式命名的目录中，文件名使用 `<题号>_<题目名>_<类型>` 前缀避免冲突。

```text
Pwn Writeups/
├── README.MD
├── PATTERN_CLASSIFICATION.md          # 全部题目的模式分类与判定依据
├── notes.md                           # Python / Linux / pwntools Cheat Sheet
├── requirements.txt
├── network_interaction_free_shell/    # 网络交互 / 白给 Shell
│   ├── README.md
│   ├── 01_test_your_nc_{speedrun,writeup,exp}.*
│   ├── 17_others_shellcode_{speedrun,exp}.*
│   ├── test_your_nc
│   └── others_shellcode
├── ret2text/                          # 栈溢出返回二进制已有代码
│   ├── README.md
│   ├── 02_rip_{speedrun,writeup,exp}.*
│   ├── 03_warmup_csaw_2016_{speedrun,writeup,exp}.*
│   ├── 05_get_started_3dsctf_2016_{speedrun,writeup,exp}.*
│   ├── 06_jarvisoj_level0_{speedrun,exp}.*
│   ├── 09_canary_{speedrun,exp}.*
│   ├── rip
│   ├── warmup_csaw_2016
│   ├── get_started_3dsctf_2016
│   ├── jarvisoj_level0
│   └── [NewStarCTF 公开赛赛道]canary/pwn
├── ret2libc/                          # 栈溢出 + leak libc + 返回到 system
│   ├── README.md
│   ├── 07_newstarctf_2023_ret2libc_{speedrun,exp}.*
│   ├── 10_jarvisoj_level4_{speedrun,exp}.*
│   ├── 11_2018_rop_{speedrun,exp}.*
│   ├── 12_bjdctf_2020_babyrop_{speedrun,exp}.*
│   ├── 13_putsorsys_{speedrun,exp}.*
│   ├── 18_repeater_{speedrun,exp}.*
│   ├── 19_pwnable_silverbullet_{speedrun,exp}.*
│   ├── 20_bbbaby_pwn1_{speedrun,exp}.*
│   ├── 25_rec_33c3_2016_{speedrun,exp}.*
│   └── 对应二进制 + libc.so.6 / libc-2.23.so / libc-2.24.so
├── ret2shellcode/                     # NX 关闭 + 栈上 shellcode
│   ├── README.md
│   ├── 21_pwnable_start_{speedrun,exp}.*
│   └── pwnable_start
├── stack_pivot/                       # 栈空间不足 -> 迁移到堆/可控内存
│   ├── README.md
│   ├── 22_ropemporium_pivot_{speedrun,exp}.*
│   ├── pivot
│   └── libpivot.so
├── sandbox_seccomp/                   # seccomp 沙箱 -> ORW
│   ├── README.md
│   ├── 23_pwnable_orw_{speedrun,exp}.*
│   ├── 24_easyroptocol_{speedrun,exp}.*
│   ├── make_local_exec.py
│   ├── orw
│   ├── easyroptocol
│   ├── libc-2.31.so
│   └── orw_local_exec                 # 本地补丁版（PT_LOAD 加 PF_X）
├── srop/                              # rt_sigreturn 一次设置全部寄存器
│   └── README.md                      # 该模式的判定条件与 sigframe 布局说明
├── labs/                              # 自造靶场（非真实赛题，用于补齐缺失题型）
│   └── lab_srop_baby/                 # L1：只能靠 SROP 解的最小靶子
│       ├── README.md
│       ├── src/chal.S
│       ├── Makefile
│       └── exp.py
├── format_string_write/               # printf(user_input) + %n 任意写
│   ├── README.md
│   ├── 08_fifth_space_2019_pwn5_{speedrun,exp}.*
│   └── [第五空间2019决赛]PWN5
├── stack_local_var_overwrite/         # 栈溢出改局部变量 / 条件绕过
│   ├── README.md
│   ├── 04_ciscn_2019_n_1_speedrun.md
│   ├── 04_ciscn_2019_n_1_exp.py
│   └── ciscn_2019_n_1
├── heap_uaf/                          # 释放后使用 / 函数指针劫持
│   ├── README.md
│   ├── 14_hitcontraining_uaf_{speedrun,exp}.*
│   └── hitcontraining_uaf
├── heap_exploitation/                 # 堆布局 / 分配器元数据 / 对象指针
    ├── README.md
    ├── 15_babyheap_Octf_2017_{speedrun,exp}.*
    ├── 16_babyfengshui_33c3_2016_{speedrun,exp}.*
    ├── babyheap_Octf_2017
    └── babyfengshui_33c3_2016
└── tools/                             # 仓库自检脚本（非题目）
    └── repro_audit.py                 # 01–24 复现性静态审计（见 README 文末）
```

## Pattern Index

| 模式目录 | 共同模式特征 | 包含题目 |
| --- | --- | --- |
| `network_interaction_free_shell` | 程序正常逻辑直接给 shell，无内存破坏点 | `01_test_your_nc`、`17_others_shellcode` |
| `ret2text` | 栈溢出（`gets` / `read`），覆盖返回地址跳到二进制内已有后门 | `02_rip`、`03_warmup_csaw_2016`、`05_get_started_3dsctf_2016`、`06_jarvisoj_level0`、`09_canary` |
| `ret2libc` | 栈溢出 leak libc，返回 `main` 后二阶段 `system("/bin/sh")`（25 是“未初始化函数指针 + `esp` 泄漏栈喷”的变体，无栈溢出） | `07_newstarctf_2023_ret2libc`、`10_jarvisoj_level4`、`11_2018_rop`、`12_bjdctf_2020_babyrop`、`13_putsorsys`、`18_repeater`、`19_pwnable_silverbullet`、`20_bbbaby_pwn1`、`25_rec_33c3_2016` |
| `ret2shellcode` | NX 关闭（`GNU_STACK=RWE`），leak 可执行内存地址后执行栈/堆上 shellcode | `21_pwnable_start` |
| `stack_pivot` | 溢出空间不足，用 `xchg rsp,rax` / `leave;ret` 把栈迁到堆 / `.bss` 再执行长链 | `22_ropemporium_pivot` |
| `sandbox_seccomp` | 程序装 seccomp BPF，`execve` 被拦，只能 `open`+`read`+`write` 读 flag | `23_pwnable_orw`、`24_easyroptocol` |
| `srop` | `rax=15` + `syscall` 触发 `rt_sigreturn`，用 248 字节 sigframe 一次设置全部寄存器 | `L1_lab_srop_baby`（自造） |
| `format_string_write` | `printf(user_input)`，用 `%n` 改全局变量或 GOT | `08_fifth_space_2019_pwn5` |
| `stack_local_var_overwrite` | 栈溢出改相邻局部变量，绕过条件判断 | `04_ciscn_2019_n_1` |
| `heap_uaf` | free 后指针仍被引用，重新分配旧对象改写函数指针 | `14_hitcontraining_uaf` |
| `heap_exploitation` | 堆布局 / 分配器元数据 / 对象指针改写 | `15_babyheap_Octf_2017`、`16_babyfengshui_33c3_2016` |

逐题的判定依据、偏移、目标地址与关键坑点见 [PATTERN_CLASSIFICATION.md](PATTERN_CLASSIFICATION.md)。

## File Conventions

- `*_speedrun.md` : 2 分钟速通笔记，强调定性质、关键偏移、坑点与识别卡。
- `*_writeup.md` : 深入分析内存布局、控制流与绕过策略。
- `*_exp.py` : 武器化 exploit 脚本。
- 无前缀的 ELF 文件 : 题目原始二进制，保留原始文件名，便于 `file` / `checksec` / `objdump` 直接使用。
- 每个模式目录的 `README.md` 汇总该模式的共同特征、题目差异与运行方式。

## Quick Start

```bash
cd '/home/yfhd5/Pwn Writeups'
source .venv/bin/activate

# 按模式进入目录
cd ret2text
python 02_rip_exp.py
python 03_warmup_csaw_2016_exp.py
python 05_get_started_3dsctf_2016_exp.py LOCAL   # 本地验证，当前目录需有 flag.txt
python 06_jarvisoj_level0_exp.py LOCAL
python 09_canary_exp.py LOCAL

cd ../ret2libc
python 07_newstarctf_2023_ret2libc_exp.py LOCAL
python 12_bjdctf_2020_babyrop_exp.py LOCAL

# 32 位需要用 i386 loader
I386_LD=/tmp/libc32/root/usr/lib32/ld-linux.so.2 \
I386_LIBPATH=/tmp/libc32/root/usr/lib32 \
python 10_jarvisoj_level4_exp.py LOCAL

# 13 用附件 libc + 2.35 loader
LIBC=./libc.so.6 \
LD_SO=/tmp/libc235/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2 \
LIBC_DIR=. python 13_putsorsys_exp.py LOCAL

# 18 是 canary leak + ret2libc（64 位，本机 libc 即可）
python 18_repeater_exp.py LOCAL

# 19 是 32 位逻辑 bug 越界，需要 i386 loader
I386_LD=/tmp/libc32/root/usr/lib32/ld-linux.so.2 \
I386_LIBPATH=/tmp/libc32/root/usr/lib32 \
python 19_pwnable_silverbullet_exp.py LOCAL

# 20 是任意写 + canary 绕过（改 __stack_chk_fail@got）
python 20_bbbaby_pwn1_exp.py LOCAL

# 25 是 32 位 PIE + FULL RELRO，无栈溢出：未初始化函数指针 + Polish esp 泄漏
# LOCAL 必须给出 i386 loader（I386_LD / I386_LIBPATH），否则退回本机 /lib/ld-linux.so.2
I386_LD=/tmp/libc224/root/lib/ld-linux.so.2 \
I386_LIBPATH=/tmp/libc224/root/lib/i386-linux-gnu \
python 25_rec_33c3_2016_exp.py LOCAL
LIBC=./libc-2.24.so HOST=target.example.com PORT=9999 \
python 25_rec_33c3_2016_exp.py

cd ../ret2shellcode
# 21 是 32 位静态汇编，栈可执行，直接 ret2shellcode
python 21_pwnable_start_exp.py            # 当前目录需有 flag.txt

cd ../stack_pivot
# 22 是栈迁移（pivot），RUNPATH=. 已内置
python 22_ropemporium_pivot_exp.py        # 当前目录需有 flag.txt

cd ../sandbox_seccomp
# 23 是 seccomp ORW；现代内核需要先给 .bss 段加 PF_X
python make_local_exec.py
python 23_pwnable_orw_exp.py              # 当前目录需有 flag.txt

# 24 是 seccomp + 4 槽 message 双阶段 ORW（本地自动建临时 flag.txt）
python 24_easyroptocol_exp.py
python 24_easyroptocol_exp.py remote HOST PORT

cd ../format_string_write
python 08_fifth_space_2019_pwn5_exp.py LOCAL     # 本地需要 i386 loader

cd ../heap_uaf
I386_LD=/tmp/libc32/root/usr/lib32/ld-linux.so.2 \
I386_LIBPATH=/tmp/libc32/root/usr/lib32 \
python 14_hitcontraining_uaf_exp.py LOCAL

cd ../heap_exploitation
LD_SO=/tmp/libc223/lib/x86_64-linux-gnu/ld-2.23.so \
LIBC_DIR=/tmp/libc223/lib/x86_64-linux-gnu \
python 15_babyheap_Octf_2017_exp.py LOCAL

# 16 是 32 位，需要 i386 loader
I386_LD=/tmp/libc32/root/usr/lib32/ld-linux.so.2 \
I386_LIBPATH=/tmp/libc32/root/usr/lib32 \
python 16_babyfengshui_33c3_2016_exp.py LOCAL

cd ../network_interaction_free_shell
python 17_others_shellcode_exp.py LOCAL

cd ../labs/lab_srop_baby
# L1 是自造 SROP 靶场：make 只用 as + ld，无 libc 依赖
make
python exp.py
```

> 远程 EXP 中的 `HOST` / `PORT` 会随靶机变化；CTF² 平台需要 `ssl=True`。

---

## 复现自检（01–24 + 25，2026-11-23）

不逐题实跑（成本高），改用**静态审计**回答一个问题：把仓库重新 clone 下来、备齐附件后，
每道题是否都能按文档跑起来。审计脚本：[`tools/repro_audit.py`](tools/repro_audit.py)。

它检查五项，全部是“缺了就跑不起来”的硬条件：

1. `*_exp.py` 能否 `compile()` 通过（不落 `__pycache__`）；
2. 脚本引用的题目二进制是否在**同目录**；
3. 脚本读取的每个环境变量（`I386_LD` / `I386_LIBPATH` / `LIBC` / `LD_SO` / `LIBC_DIR` / `SSL` / `HOST` / `PORT`）
   是否写进了对应的 `*_speedrun.md`；
4. 文档是否含 ```` ```bash ```` 运行块、是否残留 `TODO` / `待补` / `???`；
5. 标出“`HOST` 写死在脚本里”的题（2019 年 CTF² 临时靶机，早已下线）。

```bash
cd '/home/yfhd5/Pwn Writeups' && source .venv/bin/activate
python tools/repro_audit.py          # 文本表；有文档缺口时退出码 1
python tools/repro_audit.py --md     # Markdown 表（本节的表就是它生成的）
python tools/repro_audit.py 08 19    # 只审指定题号
```

### 32 位题的公共前置（i386 loader）

所有 `I386_LD` 相关命令都假设 `/tmp/libc32` 已存在。它不在仓库里（附件不入库），
重建方式与本机实测校验：

```bash
mkdir -p /tmp/libc32 && cd /tmp/libc32
apt-get download libc6:i386                     # 本机：2.43-2ubuntu2
dpkg-deb -x libc6_*_i386.deb root
find root -name ld-linux.so.2                   # 先定位，别照抄路径
md5sum root/usr/lib/i386-linux-gnu/libc.so.6    # 7fde74420b72b39b43abdce782ade03c
```

**解包路径随 deb 不同**，文档里的 `I386_LD` 以 `find` 结果为准：

| deb | loader 实际位置 |
| --- | --- |
| `libc6:i386` | `/tmp/libc32/root/usr/lib/i386-linux-gnu/ld-linux.so.2` |
| `libc6-i386` | `/tmp/libc6i386/usr/lib32/ld-linux.so.2`（08 用这个） |

> 若 `python xx_exp.py LOCAL` 报 `FileNotFoundError: './xxx'`，先怀疑 **32 位 loader 缺失**
> （ELF 的 `interp` 不存在），而不是二进制丢了。

| 题 | 脚本 | 二进制（同目录） | 依赖环境变量 | 文档补齐 | 备注 |
| --- | --- | --- | --- | --- | --- |
| 01 | `01_test_your_nc_exp.py` | — | — | ✅ | OK;远程HOST写死(靶机已下线) |
| 02 | `02_rip_exp.py` | — | — | ✅ | OK;远程HOST写死(靶机已下线) |
| 03 | `03_warmup_csaw_2016_exp.py` | — | — | ✅ | OK;远程HOST写死(靶机已下线) |
| 04 | `04_ciscn_2019_n_1_exp.py` | — | — | ✅ | OK;远程HOST写死(靶机已下线) |
| 05 | `05_get_started_3dsctf_2016_exp.py` | ./get_started_3dsctf_2016 | — | ✅ | OK;远程HOST写死(靶机已下线) |
| 06 | `06_jarvisoj_level0_exp.py` | ./jarvisoj_level0 | HOST, PORT, SSL | ✅ | OK |
| 07 | `07_newstarctf_2023_ret2libc_exp.py` | ./[NewStarCTF 2023 公开赛道]ret2libc | HOST, LIBC, LOCAL_LIBC, PORT, SSL | ✅ | OK |
| 08 | `08_fifth_space_2019_pwn5_exp.py` | ./[第五空间2019决赛]PWN5 ❌未归档 | HOST, I386_LD, I386_LIBPATH, PORT, SSL | ✅ | 附件需自备（文档已写四项校验） |
| 09 | `09_canary_exp.py` | ./[NewStarCTF 公开赛赛道]canary/pwn | HOST, PORT, SSL | ✅ | OK |
| 10 | `10_jarvisoj_level4_exp.py` | ./jarvisoj_level4 | HOST, I386_LD, I386_LIBPATH, LIBC, PORT, SSL | ✅ | OK |
| 11 | `11_2018_rop_exp.py` | ./铁人三项（第五赛区）2018_rop | HOST, I386_LD, I386_LIBPATH, LIBC, PORT, SSL | ✅ | OK |
| 12 | `12_bjdctf_2020_babyrop_exp.py` | ./bjdctf_2020_babyrop | HOST, LIBC, PORT, SSL | ✅ | 实跑通过 |
| 13 | `13_putsorsys_exp.py` | ./putsorsys | HOST, LD_SO, LIBC, LIBC_DIR, PORT, SSL | ✅ | OK |
| 14 | `14_hitcontraining_uaf_exp.py` | ./hitcontraining_uaf | HOST, I386_LD, I386_LIBPATH, PORT, SSL | ✅ | OK |
| 15 | `15_babyheap_Octf_2017_exp.py` | ./babyheap_Octf_2017 | HOST, LD_SO, LIBC_DIR, PORT, SSL | ✅ | OK |
| 16 | `16_babyfengshui_33c3_2016_exp.py` | ./babyfengshui_33c3_2016 | HOST, I386_LD, I386_LIBPATH, LIBC, PORT, SSL | ✅ | OK |
| 17 | `17_others_shellcode_exp.py` | ./others_shellcode | HOST, I386_LD, I386_LIBPATH, PORT, SSL | ✅ | OK |
| 18 | `18_repeater_exp.py` | ./repeater | HOST, LIBC, PORT, SSL | ✅ | OK |
| 19 | `19_pwnable_silverbullet_exp.py` | ./pwnable_silverbullet | HOST, I386_LD, I386_LIBPATH, LIBC, PORT, SSL | ✅ | 本次补 `SSL=1` |
| 20 | `20_bbbaby_pwn1_exp.py` | ./bbbaby_pwn1 | HOST, LIBC, PORT | ✅ | OK |
| 21 | `21_pwnable_start_exp.py` | ./pwnable_start | — | ✅ | OK |
| 22 | `22_ropemporium_pivot_exp.py` | ./pivot | — | ✅ | 实跑通过 |
| 23 | `23_pwnable_orw_exp.py` | ./orw, ./orw_local_exec | I386_LD, I386_LIBPATH | ✅ | 本次补复跑方法 |
| 24 | `24_easyroptocol_exp.py` | —（用同目录 libc-2.31.so） | — | ✅ | 实跑通过 |
| 25 | `25_rec_33c3_2016_exp.py` | ./rec_33c3_2016 | HOST, I386_LD, I386_LIBPATH, LIBC, PORT, SSL | ✅ | 另有 §8 从零清单 |

审计结论（本次实际补齐的内容已写回各题文档）：

- **25 个 EXP 全部可编译**；文档缺口 **0**；无 TODO/占位符。
- **01–04** 的 EXP 只有远程分支且 `HOST` 已下线：文档已加提示，本地按
  `process('./<bin>')` 复跑（`test_your_nc` / `rip` / `warmup_csaw_2016` / `ciscn_2019_n_1` 都在库）。
  **05** 的 EXP 自带 `LOCAL` 分支，可直接
  `python 05_get_started_3dsctf_2016_exp.py LOCAL` 验证 `get_flag` 分支。
- **08** 是唯一附件未归档的题：`.gitignore` 只跟踪文档/脚本，当年没 `git add -f`。
  文档已写明自备附件时的四项校验（`file` / `checksec` / `strings` 偏移 / `0x804c044`、`%10$n`）。
- **19** 补了 `SSL=1`（TLS 平台）；**23** 补了 `make_local_exec.py` + i386 loader 的复跑命令。
- 全局修正：文档里 i386 loader 原写作 `/tmp/libc32/root/usr/lib32`，本机实际是
  `/tmp/libc32/root/usr/lib/i386-linux-gnu`（`libc6:i386` deb）；已批量替换并补了
  `find` 自查法。23 的 EXP 默认值、19 的 `LIBC` 推导也同步改为“以 `I386_LD` 同目录为准”。
- 实跑抽查（2026-11-23，本机 glibc）：`05`、`12`、`19`、`22`、`23`、`24` 全部通过，
  分别为 `flag{LOCAL_SMOKE}`、`flag{smoke12}`、`flag{SILVER_LOCAL}`、
  `__PWNED__{pivot_local_ok}`、`__PWNED__{orw_local_ok}`、`__PWNED__{easyroptocol_local_ok}`。
- 审计只证明“静态可复现”；逻辑是否仍成功以各题 `speedrun.md` 的实测输出为准。