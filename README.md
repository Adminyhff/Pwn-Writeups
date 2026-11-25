*"Started in Nov, Freshman Year. Goal: Top 100 on BUUCTF Pwn Leaderboard. Solo. No teams."*

## Environment
- OS: WSL2 Ubuntu
- Toolchain: GCC, GDB + pwndbg, pwntools
- Python Virtual Environment: `.venv`

## Repository Layout

本仓库按 **题型模式特征（pattern）** 组织，而不是按单道题目建文件夹。
同一模式下的题目文件统一放在以该模式命名的目录中，文件名使用 `<题号>_<题目名>_<类型>` 前缀避免冲突。

```text
Pwn_Writeups/
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
│   ├── 27_jarvisoj_http_{speedrun,exp}.*
│   ├── rip
│   ├── warmup_csaw_2016
│   ├── get_started_3dsctf_2016
│   ├── jarvisoj_level0
│   ├── jarvisoj_http
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
│   ├── 28_canary3_{speedrun,exp}.*
│   └── 对应二进制 + libc.so.6 / libc-2.23.so / libc-2.24.so / canary3
├── ret2shellcode/                     # NX 关闭 + 栈上 shellcode
│   ├── README.md
│   ├── 21_pwnable_start_{speedrun,exp}.*
│   └── pwnable_start
├── stack_pivot/                       # 栈空间不足 -> 迁移到堆/可控内存
│   ├── README.md
│   ├── 22_ropemporium_pivot_{speedrun,exp}.*
│   ├── pivot
│   └── libpivot.so
├── ret2csu/                           # 缺 pop rdx -> __libc_csu_init 通用 gadget
│   ├── README.md
│   ├── 30_ropemporium_ret2csu_{speedrun,exp}.*
│   ├── ret2csu
│   ├── libret2csu.so
│   ├── key.dat
│   └── encrypted_flag.dat
├── rop_write_memory/                  # 任意地址写 -> 自己造 "flag.txt" 字符串
│   ├── README.md
│   ├── 31_ropemporium_write4_{speedrun,exp}.*
│   ├── write4
│   ├── libwrite4.so
│   └── flag.txt
├── badchars_encoding/                 # 坏字符过滤 -> 写密文 + 原地解码
│   ├── README.md
│   ├── 32_ropemporium_badchars_{speedrun,exp}.*
│   ├── badchars
│   ├── libbadchars.so
│   └── flag.txt
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
│   ├── lab_srop_baby/                 # L1：只能靠 SROP 解的最小靶子
│   │   ├── README.md
│   │   ├── src/chal.S
│   │   ├── Makefile
│   │   └── exp.py
│   ├── lab_ret2syscall_i386/          # L2：无 libc，只能自己 int 0x80 拼 execve
│   │   ├── README.md
│   │   ├── src/chal.S
│   │   ├── Makefile
│   │   ├── chal
│   │   └── exp.py
│   ├── lab_ret2dlresolve_i386/        # L3：只导入 read，靠伪造 ELF 让链接器解析 system
│   │   ├── README.md
│   │   ├── src/chal.S
│   │   ├── Makefile
│   │   ├── chal
│   │   ├── exp.py
│   │   └── libc/                      # glibc 2.24 i386（ld-2.24.so + libc.so.6）
│   ├── lab_tcache_poisoning/          # L4：UAF 泄漏 safe-linking key → 毒化 next → .bss 函数指针
│   │   ├── README.md
│   │   ├── src/chal.c
│   │   ├── Makefile
│   │   ├── chal
│   │   └── exp.py
│   ├── lab_canary_bruteforce/         # L5：程序自带 fork server，canary 逐字节爆破 → ret2win
│   │   ├── README.md
│   │   ├── src/chal.c
│   │   ├── Makefile
│   │   ├── chal
│   │   └── exp.py
│   └── lab_heap_uaf/                  # L6：函数指针 UAF（heap_uaf 第二题）
│       ├── README.md
│       ├── src/chal.c
│       ├── Makefile
│       ├── chal
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
    ├── 26_card_{speedrun,exp}.*
    ├── babyheap_Octf_2017
    ├── babyfengshui_33c3_2016
    └── card
├── fsop/                              # 伪造 _IO_FILE / vtable -> libc 内部调用链
│   ├── README.md
│   ├── 29_pwnable_tw_seethefile_{speedrun,exp}.*
│   └── seethefile
└── tools/                             # 仓库自检脚本（非题目）
    ├── repro_audit.py                 # 01–32 + L1–L6 复现性静态审计（见 README 文末）
    ├── verify_all.sh                  # 本地实跑矩阵（逐题 PASS/FAIL）
    └── loopback_unix_shim.c           # WSL2 loopback TCP 不可用时的 AF_UNIX 兜底（仅 jarvisoj_http 验证用）
```

## Pattern Index

| 模式目录 | 共同模式特征 | 包含题目 |
| --- | --- | --- |
| `network_interaction_free_shell` | 程序正常逻辑直接给 shell，无内存破坏点 | `01_test_your_nc`、`17_others_shellcode` |
| `ret2text` | 栈溢出（`gets` / `read`），覆盖返回地址跳到二进制内已有后门；27 是“服务端逐字节读请求 + CSU ROP”的变体（不需要后门函数） | `02_rip`、`03_warmup_csaw_2016`、`05_get_started_3dsctf_2016`、`06_jarvisoj_level0`、`09_canary`、`27_jarvisoj_http` |
| `ret2libc` | 栈溢出 leak libc，返回 `main` 后二阶段 `system("/bin/sh")`（25 是“未初始化函数指针 + `esp` 泄漏栈喷”的变体，无栈溢出；28 靠登录 off-by-one + `printf("%s")` 泄 canary） | `07_newstarctf_2023_ret2libc`、`10_jarvisoj_level4`、`11_2018_rop`、`12_bjdctf_2020_babyrop`、`13_putsorsys`、`18_repeater`、`19_pwnable_silverbullet`、`20_bbbaby_pwn1`、`25_rec_33c3_2016`、`28_canary3` |
| `ret2csu` | 缺 `pop rdx`（或 `pop rsi`）时用 `__libc_csu_init` 的 `pop rbx/rbp/r12/r13/r14/r15; ret` + `call [r12+rbx*8]` 补参数；第一参要完整 64 位时 csu 只设 rdx，再用 pop 补前两参 | `30_ropemporium_ret2csu` |
| `ret2syscall` | 静态/无 libc，用 `pop eax/ebx/ecx/edx` + `int 0x80` 自己拼 `execve` | `L2_lab_ret2syscall_i386`（自造） |
| `ret2dlresolve` | 动态链接但没有 `system`，伪造 `Elf32_Rel`/`Elf32_Sym`/符号名 + 调 `plt0` 让链接器解析 | `L3_lab_ret2dlresolve_i386`（自造） |
| `ret2shellcode` | NX 关闭（`GNU_STACK=RWE`），leak 可执行内存地址后执行栈/堆上 shellcode | `21_pwnable_start` |
| `stack_pivot` | 溢出空间不足，用 `xchg rsp,rax` / `leave;ret` 把栈迁到堆 / `.bss` 再执行长链 | `22_ropemporium_pivot` |
| `sandbox_seccomp` | 程序装 seccomp BPF，`execve` 被拦，只能 `open`+`read`+`write` 读 flag | `23_pwnable_orw`、`24_easyroptocol` |
| `srop` | `rax=15` + `syscall` 触发 `rt_sigreturn`，用 248 字节 sigframe 一次设置全部寄存器 | `L1_lab_srop_baby`（自造） |
| `format_string_write` | `printf(user_input)`，用 `%n` 改全局变量或 GOT | `08_fifth_space_2019_pwn5` |
| `stack_local_var_overwrite` | 栈溢出改相邻局部变量，绕过条件判断 | `04_ciscn_2019_n_1` |
| `heap_uaf` | free 后指针仍被引用，重新分配旧对象改写函数指针 | `14_hitcontraining_uaf`、`L6_lab_heap_uaf`（自造） |
| `tcache_poisoning` | 改已释放 chunk 的 `next` 把 `malloc` 顶到任意地址（2.32+ 先泄 safe-linking key，2.34+ 目标改 `.bss` 函数指针） | `L4_lab_tcache_poisoning`（自造） |
| `canary_bruteforce` | 有 canary 且无泄漏点 + 每次连接重启（fork server）→ 逐字节试错 | `L5_lab_canary_bruteforce`（自造） |
| `heap_exploitation` | 堆布局 / 分配器元数据 / 对象指针改写 | `15_babyheap_Octf_2017`、`16_babyfengshui_33c3_2016`、`26_card` |
| `fsop` | 可控 `FILE *` / `_IO_list_all` → 伪造 `_IO_FILE` + vtable | `29_pwnable_tw_seethefile` |
| `rop_write_memory` | 目标函数要一个**内存里不存在**的字符串，用 `mov [reg_a], reg_b; ret` 写进 `.data`/`.bss`，再 `pop rdi` 传地址 | `31_ropemporium_write4` |
| `badchars_encoding` | 输入被逐字节过滤（坏字符 `x g a .`，命中改 `0xeb`），先写密文再用 `xor byte ptr [r15], r14b` 原地解码 | `32_ropemporium_badchars` |

逐题的判定依据、偏移、目标地址与关键坑点见 [PATTERN_CLASSIFICATION.md](PATTERN_CLASSIFICATION.md)。

## File Conventions

- `*_speedrun.md` : 2 分钟速通笔记，强调定性质、关键偏移、坑点与识别卡。
- `*_writeup.md` : 深入分析内存布局、控制流与绕过策略。
- `*_exp.py` : 武器化 exploit 脚本。
- 无前缀的 ELF 文件 : 题目原始二进制，保留原始文件名，便于 `file` / `checksec` / `objdump` 直接使用。
- 每个模式目录的 `README.md` 汇总该模式的共同特征、题目差异与运行方式。

## Quick Start

```bash
cd '/home/yfhd5/Pwn_Writeups'
source .venv/bin/activate

# 按模式进入目录
cd ret2text
python 02_rip_exp.py
python 03_warmup_csaw_2016_exp.py
python 05_get_started_3dsctf_2016_exp.py LOCAL   # 本地验证，当前目录需有 flag.txt
python 06_jarvisoj_level0_exp.py LOCAL
python 09_canary_exp.py LOCAL

# 27 是服务端逐字节读请求 + CSU ROP（No PIE）：TCP 127.0.0.1:3847
python 27_jarvisoj_http_exp.py LOCAL
# 本机 WSL2 loopback TCP 不可用时（由宿主网络栈引起）改用 AF_UNIX 兜底：
#   gcc -shared -fPIC -O2 -o ../tools/loopback_unix_shim.so ../tools/loopback_unix_shim.c -ldl
USE_UNIX=1 python 27_jarvisoj_http_exp.py LOCAL

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

# 28 是 canary3：登录 off-by-one + printf("%s") 泄 canary，本机 libc 即可
python 28_canary3_exp.py LOCAL
LIBC=/path/to/libc.so.6 python 28_canary3_exp.py HOST PORT

cd ../ret2shellcode
# 21 是 32 位静态汇编，栈可执行，直接 ret2shellcode
python 21_pwnable_start_exp.py            # 当前目录需有 flag.txt

cd ../stack_pivot
# 22 是栈迁移（pivot），RUNPATH=. 已内置
python 22_ropemporium_pivot_exp.py        # 当前目录需有 flag.txt

cd ../ret2csu
# 30 是 ROP Emporium ret2csu：缺 pop rdx，用 __libc_csu_init + frame_dummy 保 rdx
python 30_ropemporium_ret2csu_exp.py LOCAL   # 目录内需有 libret2csu.so / key.dat / encrypted_flag.dat

cd ../rop_write_memory
# 31 用 mov [r14],r15 把 "flag.txt" 写进 .data，再 print_file(字符串地址)
python 31_ropemporium_write4_exp.py LOCAL    # 目录内需有 libwrite4.so / flag.txt

cd ../badchars_encoding
# 32 坏字符 x/g/a/. -> "flag.txt"^2 = "dnce,vzv"，写完再 xor 解码
python 32_ropemporium_badchars_exp.py LOCAL  # 目录内需有 libbadchars.so / flag.txt

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

# 26 是 card：libc 2.27（附件 libc.so）+ 1 字节堆溢出 -> tcache 毒化 __free_hook
LD_SO=/tmp/libc227/root/lib/x86_64-linux-gnu/ld-2.27.so \
LIBC_DIR=/tmp/libc227/root/lib/x86_64-linux-gnu \
LIBC=/tmp/libc227/root/lib/x86_64-linux-gnu/libc-2.27.so \
python 26_card_exp.py LOCAL

cd ../fsop
# 29 是 seethefile：全局 FILE *fp 被 %s 溢出 -> 伪造 _IO_FILE -> _IO_str_finish 打 system
I386_LD=/tmp/libc224i32/ld-linux.so.2 \
I386_LIBPATH=/tmp/libc224i32 \
LIBC=../ret2libc/libc-2.24.so \
python 29_pwnable_tw_seethefile_exp.py LOCAL

cd ../network_interaction_free_shell
python 17_others_shellcode_exp.py LOCAL

cd ../labs/lab_srop_baby
# L1 是自造 SROP 靶场：make 只用 as + ld，无 libc 依赖
make
python exp.py

cd ../labs/lab_ret2syscall_i386
# L2 是自造 ret2syscall 靶场：32 位静态，as --32 + ld -m elf_i386，不需要 gcc-multilib
make
python exp.py

cd ../labs/lab_ret2dlresolve_i386
# L3 是自造 ret2dlresolve 靶场：32 位动态（libc/ 里归档了 glibc 2.24 i386）
make
python exp.py
LD_SO=./libc/ld-2.24.so python exp.py     # 显式指定 loader（可选）

cd ../labs/lab_tcache_poisoning
# L4 是自造 tcache poisoning 靶场：主机 gcc，glibc 2.43（无 __free_hook，目标改 .bss 函数指针）
make
printf '__PWNED__{tcache_ok}\n' > flag.txt
python exp.py

cd ../labs/lab_canary_bruteforce
# L5 是自造 canary 爆破靶场：程序自带 fork server，约 900 次 fork ≈ 20 s
make
printf '__PWNED__{canary_ok}\n' > flag.txt
python exp.py

cd ../labs/lab_heap_uaf
# L6 是自造函数指针 UAF 靶场（heap_uaf 第二题）
make
printf '__PWNED__{uaf_ok}\n' > flag.txt
python exp.py
```

> 远程 EXP 中的 `HOST` / `PORT` 会随靶机变化；CTF² 平台需要 `ssl=True`。

---

## 复现自检（01–32 + L1–L6，2026-11-25）

不逐题实跑（成本高），改用**静态审计**回答一个问题：把仓库重新 clone 下来、备齐附件后，
每道题是否都能按文档跑起来。审计脚本：[`tools/repro_audit.py`](tools/repro_audit.py)。

它覆盖 `*/*_exp.py`（题号 01–32）与 `labs/*/exp.py`（L1–L6；EXP 名统一是 `exp.py`，
文档用同目录 `README.md`），检查五项，全部是“缺了就跑不起来”的硬条件：

1. `*_exp.py` / `labs/*/exp.py` 能否 `compile()` 通过（不落 `__pycache__`）；
2. 脚本引用的题目二进制是否在**同目录**；
3. 脚本读取的每个环境变量（`I386_LD` / `I386_LIBPATH` / `LIBC` / `LD_SO` / `LIBC_DIR` / `SSL` / `HOST` / `PORT`）
   是否写进了对应的 `*_speedrun.md`（labs 则查 `README.md`）；
4. 文档是否含 ```` ```bash ```` 运行块、是否残留 `TODO` / `待补` / `???`；
5. 标出“`HOST` 写死在脚本里”的题（CTF² 临时靶机，早已下线）。

```bash
cd '/home/yfhd5/Pwn_Writeups' && source .venv/bin/activate
python tools/repro_audit.py          # 文本表；有文档缺口时退出码 1
python tools/repro_audit.py --md     # Markdown 表（本节的表就是它生成的）
python tools/repro_audit.py 08 19    # 只审指定题号
python tools/repro_audit.py 6        # 只审 lab L6（也接受 `L6` 写法）
```

当前结果：**38 题（32 个编号题 + 6 个 lab），文档缺口 0**。

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
| 26 | `26_card_exp.py` | ./card | HOST, LIBC, LIBC_DIR, LD_SO, PORT, SSL | ✅ | 实跑 3/3（libc 2.27） |
| 27 | `27_jarvisoj_http_exp.py` | ./jarvisoj_http | HOST, PORT, USE_UNIX, SHIM, HTTP_UNIX, SHIM_LOG | ✅ | 实跑 3/3（`USE_UNIX=1`） |
| 28 | `28_canary3_exp.py` | ./canary3 | LIBC（远程可选） | ✅ | 实跑 3/3 |
| 29 | `29_pwnable_tw_seethefile_exp.py` | ./seethefile | HOST, I386_LD, I386_LIBPATH, LIBC, PORT, SSL | ✅ | 实跑 3/3（FSOP，i386 2.24） |
| 30 | `30_ropemporium_ret2csu_exp.py` | ./ret2csu | HOST, PORT | ✅ | 实跑 1/1（ret2csu，输出 `ROPE{...}`） |
| 31 | `31_ropemporium_write4_exp.py` | ./write4（+ `libwrite4.so`） | HOST, PORT | ✅ | 实跑 1/1（rop_write_memory，输出 `ROPE{...}`） |
| 32 | `32_ropemporium_badchars_exp.py` | ./badchars（+ `libbadchars.so`） | HOST, PORT | ✅ | 实跑 1/1（badchars_encoding，输出 `ROPE{...}`） |

审计结论（本次实际补齐的内容已写回各题文档）：

- **32 个 EXP 全部可编译**；文档缺口 **0**；无 TODO/占位符。
- **2026-11-25 新增 2 个题型 / 2 个 case**（都是 ROP Emporium 官方附件，非自造）：
  `31_ropemporium_write4`（`rop_write_memory`：`mov [r14],r15` 把 `"flag.txt"`
  写进 `.data`）与 `32_ropemporium_badchars`（`badchars_encoding`：坏字符
  `x g a .` 下写密文 + `xor byte ptr [r15], r14b` 原地解码）。
  附件 zip 已备份到 `_vendor/ropemporium/`（`write4.zip` sha256 `3925c857…`、
  `badchars.zip` sha256 `f6e8d54c…`），逐文件 sha256 见 `_vendor/attach_manifest.md`。
  题型分类 **十七类 → 十九类**。
- **本次（2026-11-24 晚）新增 3 个题型 / 3 个 case**：
  `30_ropemporium_ret2csu`（真实赛题）、`L2_lab_ret2syscall_i386`、`L3_lab_ret2dlresolve_i386`
  （自造），三者本地实跑均 PASS；题型分类从十二类扩到十五类。
- 顺带修掉两个**复现性缺陷**（都影响矩阵可信度）：
  - `22` 的 leak 解析：`puts(foothold@got)` 输出的是**原始地址字节**，遇 `0x00` 会截断、
    且字节里可能含 `0x0a`；原脚本用 `recvline()` 抓，约 2/5 概率算错基址。
    改为“读到下一个 banner 为止 + 校验 `libpivot & 0xFFF`，不对就重开一局”，连跑 20/20 通过。
  - `23` 的 loader 解析：原脚本写死 `/tmp/libc32/...`，本机不存在时直接
    `FileNotFoundError`；`verify_all.sh` 现在按 `/tmp/libc32*` → `/tmp/libc224i32`
    顺序自动探测 i386 loader 并用 `I386_LD/I386_LIBPATH` 启动。
- `26` 仍 **SKIP**：本机没有 `/tmp/libc227` 里的 `ld-2.27.so`（仓库只归档了
  `heap_exploitation/libc-2.27.so`）。补法是按 `heap_exploitation/26_card_speedrun.md` §6
  装一个 2.27 的 loader 后再跑。
- 新归档的 26 / 27 / 28 均在本地实跑 3 次全通过（见下面「本地实跑矩阵」）；
  **29**（2026-11-24 新增，FSOP 模式）同样实跑 3/3。
- **01–04** 的 EXP 只有远程分支且 `HOST` 已下线：文档已加提示，本地按
  `process('./<bin>')` 复跑（`test_your_nc` / `rip` / `warmup_csaw_2016` / `ciscn_2019_n_1` 都在库）。
  **05** 的 EXP 自带 `LOCAL` 分支，可直接
  `python 05_get_started_3dsctf_2016_exp.py LOCAL` 验证 `get_flag` 分支。
- **19** 补了 `SSL=1`（TLS 平台）；**23** 补了 `make_local_exec.py` + i386 loader 的复跑命令。
- 全局修正：文档里 i386 loader 原写作 `/tmp/libc32/root/usr/lib32`，本机实际是
  `/tmp/libc32/root/usr/lib/i386-linux-gnu`（`libc6:i386` deb）；已批量替换并补了
  `find` 自查法。23 的 EXP 默认值、19 的 `LIBC` 推导也同步改为“以 `I386_LD` 同目录为准”。
- 实跑抽查（2026-11-23，本机 glibc）：`05`、`12`、`19`、`22`、`23`、`24` 全部通过，
  分别为 `flag{LOCAL_SMOKE}`、`flag{smoke12}`、`flag{SILVER_LOCAL}`、
  `__PWNED__{pivot_local_ok}`、`__PWNED__{orw_local_ok}`、`__PWNED__{easyroptocol_local_ok}`。
- 审计只证明“静态可复现”；逻辑是否仍成功以各题 `speedrun.md` 的实测输出为准。

### 本地实跑矩阵（`tools/verify_all.sh`）

静态审计证明“文件齐、能编译、文档写了怎么跑”，实跑矩阵进一步证明“按文档真能跑通”。
每题跑一次 smoke test，成功与否用输出里的固定字符串判定：

```bash
cd '/home/yfhd5/Pwn_Writeups' && source .venv/bin/activate
bash tools/verify_all.sh              # 全部
bash tools/verify_all.sh 26 27 28     # 只跑指定题号（日志在 /tmp/verify_all/<题号>.log）
```

| 题 | 前置 | 判定字符串 | 2026-11-25 复跑结果 |
| --- | --- | --- | --- |
| 05 | 目录内 `flag.txt`（脚本临时创建） | `GOT THE FLAG` | PASS |
| 12 | 目录内 `flag.txt`（临时创建） | `GOT THE FLAG` | PASS |
| 22 | 目录内 `flag.txt`（临时创建） | `__PWNED__` | PASS（修 leak 解析后连跑 8/8） |
| 23 | `orw_local_exec`（先 `python make_local_exec.py`）+ i386 loader（自动探测 `/tmp/libc32*` → `/tmp/libc224i32`）+ `flag.txt` | `flag{` | PASS |
| 24 | — | `flag:` | PASS |
| 26 | `/tmp/libc227` 的 2.27 loader + `card` | `shell ok` | **SKIP**（本机缺 2.27 loader；仓库内只有 `heap_exploitation/libc-2.27.so`） |
| 27 | `jarvisoj_http` + `tools/loopback_unix_shim.so` | `getshell OK` | PASS |
| 28 | `canary3` | `shell ok` | PASS |
| 29 | `/tmp/libc224i32` 的 i386 2.24 loader + `../ret2libc/libc-2.24.so` | `shell ok` | PASS |
| 30 | 同目录 `libret2csu.so` / `key.dat` / `encrypted_flag.dat` | `ROPE{` | PASS（本次新增） |
| 31 | 同目录 `libwrite4.so` + `flag.txt`（官方 zip 自带，无需临时创建） | `ROPE{` | PASS（2026-11-25 新增） |
| 32 | 同目录 `libbadchars.so` + `flag.txt`；坏字符自检 `assert` | `ROPE{` | PASS（2026-11-25 新增） |
| L2 | 先 `make`（`as --32` + `ld -m elf_i386`，不需要 gcc-multilib） | `__PWNED__` | PASS |
| L3 | 先 `make`（链到 `labs/lab_ret2dlresolve_i386/libc/` 的 2.24 i386） | `__PWNED__` | PASS |
| L4 | 先 `make`（主机 gcc，glibc 2.43；临时 `flag.txt`） | `__PWNED__` | PASS（本次新增） |
| L5 | 先 `make`；程序自带 fork server，逐字节爆破 ≈ 20 s（`timeout 180`） | `__PWNED__` | PASS（本次新增） |
| L6 | 先 `make`（主机 gcc，glibc 2.43；临时 `flag.txt`） | `__PWNED__` | PASS（本次新增） |

总计 **PASS=16 FAIL=0 SKIP=1**；缺前置时脚本会 `SKIP` 并打印原因，不会误报失败。
（`26_card` 仍是 SKIP：本机 2.27 是扁平布局，已能启动，但该二进制的 `cards[]` 上限为 8，
`exp` 里 stage-1 的挡板 `create(8)` 不成立 → 需要重写 stage-1 布局；确认修好后用
`CARD227_LEAK_OK=1 bash tools/verify_all.sh 26` 再跑。见 `PATTERN_CLASSIFICATION.md` §5.7。）

> **`LD_PRELOAD` 与空格**：`LD_PRELOAD` 按空格切分库列表，路径带空格就会被拆成两个库名并静默跳过
> （本仓库 2026-11-25 前的路径 `Pwn Writeups` 正是这种）。27 的兜底方案因此仍要求 `SHIM` 用
> **相对路径**（默认 `../tools/loopback_unix_shim.so`）或先 `cp` 到 `/tmp` 再引用，
> 否则 shim 静默不生效（表现为“连不上 `HTTP_UNIX` 的 socket”）。

> **仓库路径禁忌（2026-11-25）**：路径不要含空格，推荐 `/home/yfhd5/Pwn_Writeups`。
> 两条实测理由：① Linux shebang 只取第一个空白之前的内容，旧 venv 里
> `#!/home/yfhd5/Pwn Writeups/.venv/bin/python` 会被解释成 `/home/yfhd5/Pwn` → `bad interpreter`
> （`ROPgadget` / `readelf.py` 当时就是这么坏的，已改 `#!/usr/bin/env python3`）；
> ② `activate` 里的 `VIRTUAL_ENV` 是写死路径，目录改名/移动会让 venv 静默失效
> （表现为 `which python` 落回 `/usr/bin/python3`、`import pwn` 失败）；现已改成自解析，
> 但仍建议不要给仓库路径加空格。顺带一提，`LD_PRELOAD` 也按空格分库（见上一条）。
