# rop_write_memory / return-oriented write —— 先用 gadget 把字符串写进可写段，再当参数用

> 典型触发条件：**目标函数要一个字符串指针，而二进制里没有这个字符串**。
> 常见形态：`print_file("flag.txt")`、`system("/bin/sh")`、`open("/flag")`。
> 与 `ret2csu`（补第三个参数）不同，这里缺的是**数据**，不是**寄存器**；
> 与 `format_string_write` 也不同，后者用 `%n` 写数值，这里用 ROP 搬一段字节。

## 1. 判据（什么时候选它）

| 现象 | 结论 |
| --- | --- |
| 有 `mov [reg_a], reg_b ; ret`（或 `mov [reg_a], reg_b` + 单独 `ret`） | 可以自己做任意写 |
| 目标函数参数是 `char *`（文件名 / 命令 / 路径），且串不在 `.rodata`、`.data`、GOT 里 | 必须先写字符串再传指针 |
| 只有 `pop rdi` 没有写内存 gadget，但能调 `read`/`gets` | 也可以"再用一次 read 写 .bss"，属于同一模式的另一条路 |
| 字符串里含坏字符 | 改用 `badchars_encoding`（写密文 + 解码） |

标准三段式：

```text
[pop reg_a ; pop reg_b ; ret][目标地址][8 字节字符串]
[mov [reg_a], reg_b ; ret]                       # 任意地址写
[pop rdi ; ret][目标地址][目标函数@plt]           # 参数是字符串地址
```

## 2. 本模式题目

| 题目 | 架构 / 保护 | gadget | 目标 |
| --- | --- | --- | --- |
| `31_ropemporium_write4` | amd64 / No PIE / NX / Partial RELRO | `pop r14;pop r15;ret` @`0x400690`、`mov [r14],r15;ret` @`0x400628`、`pop rdi;ret` @`0x400693` | `print_file@plt(0x601028)`，把 `"flag.txt"` 写到 `.data` |

## 3. 通用坑点

1. **写到哪儿**：优先 `.data`（初值全 0，紧跟的字节天然是 `\0`）。
   `.bss` 若紧邻 heap（`_end` = brk 起点），写满 8 字节后目标函数内部的
   `malloc` 会把我们写的字节当成 chunk header。
2. **8 字节字符串 + 1 字节 `\0`**：`mov qword [addr], reg` 一次只能写 8 字节，
   要么选一个"下一个 8 字节本来就为 0"的地址，要么再写一次 0。
3. **`ROP().find_gadget` 搜不到就手读 objdump**：本文的两条关键 gadget 都在
   `usefulGadgets` 函数体里（前后是 `nop`），pwntools 的 gadget 扫描会漏。
4. **参数是地址不是内容**：`print_file(0x601028)` 传的是字符串地址；
   把字符串本身当成整数传进去会得到 `Failed to open file: <乱码>`。
5. **输入函数是 `read` 还是 `gets`**：`read` 允许 payload 里出现 `\x00`
   （写 `p64(0)` 时很关键），`gets` 遇 `\x00` 直接截断。

## 4. 运行方式

```bash
cd '/home/yfhd5/Pwn_Writeups/rop_write_memory'
source ../.venv/bin/activate
python 31_ropemporium_write4_exp.py LOCAL

# 一键矩阵
bash ../tools/verify_all.sh 31
```

EXP 里 `chdir` 到脚本目录，保证 `libwrite4.so`（`RUNPATH=b'.'`）与 `flag.txt` 都能找到。
远程：`HOST=... PORT=... python 31_ropemporium_write4_exp.py`（官方无公开靶机）。

## 5. 文件说明

| 文件 | 作用 |
| --- | --- |
| `31_ropemporium_write4_speedrun.md` | 判据、gadget、链、坑点、复现 |
| `31_ropemporium_write4_exp.py` | 武器化 EXP（`LOCAL` 与 `HOST`+`PORT` 双模） |
| `write4` / `libwrite4.so` / `flag.txt` | 官方附件（`write4` 需 `git add -f`，zip 原件在 `../_vendor/ropemporium/`） |

## 6. 识别卡

```text
目标要一个"内存里不存在的字符串" + 有 mov [reg], reg 型 gadget
  -> rop_write_memory：写字符串到 .data/.bss（后面留 \0），再 pop rdi 传地址
没有写内存 gadget 但有 read/gets 且能控制参数
  -> 用第二次 read 写 .bss，效果相同
字符串含坏字符
  -> 跳到 badchars_encoding
```
