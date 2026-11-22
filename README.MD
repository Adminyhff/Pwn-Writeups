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
│   └── 对应二进制 + libc.so.6 / libc-2.23.so
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
│   ├── make_local_exec.py
│   ├── orw
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
└── heap_exploitation/                 # 堆布局 / 分配器元数据 / 对象指针
    ├── README.md
    ├── 15_babyheap_Octf_2017_{speedrun,exp}.*
    ├── 16_babyfengshui_33c3_2016_{speedrun,exp}.*
    ├── babyheap_Octf_2017
    └── babyfengshui_33c3_2016
```

## Pattern Index

| 模式目录 | 共同模式特征 | 包含题目 |
| --- | --- | --- |
| `network_interaction_free_shell` | 程序正常逻辑直接给 shell，无内存破坏点 | `01_test_your_nc`、`17_others_shellcode` |
| `ret2text` | 栈溢出（`gets` / `read`），覆盖返回地址跳到二进制内已有后门 | `02_rip`、`03_warmup_csaw_2016`、`05_get_started_3dsctf_2016`、`06_jarvisoj_level0`、`09_canary` |
| `ret2libc` | 栈溢出 leak libc，返回 `main` 后二阶段 `system("/bin/sh")` | `07_newstarctf_2023_ret2libc`、`10_jarvisoj_level4`、`11_2018_rop`、`12_bjdctf_2020_babyrop`、`13_putsorsys`、`18_repeater`、`19_pwnable_silverbullet`、`20_bbbaby_pwn1` |
| `ret2shellcode` | NX 关闭（`GNU_STACK=RWE`），leak 可执行内存地址后执行栈/堆上 shellcode | `21_pwnable_start` |
| `stack_pivot` | 溢出空间不足，用 `xchg rsp,rax` / `leave;ret` 把栈迁到堆 / `.bss` 再执行长链 | `22_ropemporium_pivot` |
| `sandbox_seccomp` | 程序装 seccomp BPF，`execve` 被拦，只能 `open`+`read`+`write` 读 flag | `23_pwnable_orw` |
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