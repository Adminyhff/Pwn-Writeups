# sandbox_seccomp

> 共同模式特征：**程序自己装 seccomp 沙箱，`execve` 被拦，只能用 `open`/`read`/`write` 读文件**
> 判定不看保护，而看"能不能拿到 shell"：装了 BPF 之后 `system("/bin/sh")` 和
> `execve` shellcode 都会被 KILL/ENOSYS，必须写 ORW 链。

---

## 1. 模式特征

```text
程序里有 prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &prog)
+ .rodata 里有一段 8 字节一条的 BPF 数组（code/jt/jf/k）
+ 输入内容会被直接 call（shellcode）或 ROP 到栈/堆
= sandbox_seccomp（ORW）
```

拿不到源码时，直接按 `struct sock_filter { u16 code; u8 jt; u8 jf; u32 k; }`
解析那段数组，就能得到"允许哪些 syscall"：

```python
import struct
data = open('orw','rb').read()
off = 0x640                     # vaddr 0x8048640 -> file offset
for i in range(12):
    code, jt, jf, k = struct.unpack('<HBBI', data[off+i*8: off+i*8+8])
    print(f'{i:2d}: code={code:#06x} jt={jt} jf={jf} k={k:#x}')
```

`code` 常见取值：

| code | 含义 |
| --- | --- |
| `0x20` | `BPF_LD | BPF_W | BPF_ABS`（加载 seccomp_data 字段） |
| `0x15` | `BPF_JMP | BPF_JEQ | BPF_K`（比较 syscall 号 / arch） |
| `0x06` | `BPF_RET | BPF_K`（返回动作） |

返回动作：

| k | 含义 |
| --- | --- |
| `0x7fff0000` | `SECCOMP_RET_ALLOW` |
| `0x00050000 | errno` | `SECCOMP_RET_ERRNO`（如 `0x50026` = 返回 `ENOSYS`） |
| `0x00000000` | `SECCOMP_RET_KILL` |

标准 ORW 流程：

1. dump BPF，确认 `open`(32 位旧号 5 / 64 位 2)、`read`(3/0)、`write`(4/1) 放行。
2. 写 shellcode / ROP：`open("flag.txt") -> read(fd, buf, n) -> write(1, buf, n)`。
3. 64 位注意用 `openat`（很多沙箱只放行 `openat`）和 `syscall; ret` gadget。

---

## 2. 本模式题目

| 题目 | 架构 / 链接 | 沙箱内容 | 输入方式 | 放行的 syscall |
| --- | --- | --- | --- | --- |
| `23_pwnable_orw` | i386 / 动态 / 栈可执行 | `prctl` + 12 条 BPF | `read(0, 0x804a060, 0xc8)` 后 `call` | `open(5)`、`read(3)`、`write(4)`、`exit(1)`、`exit_group(252)`、`rt_sigreturn(173)`、`sigreturn(119)` |

关键地址：

| 题目 | 关键量 |
| --- | --- |
| `23_pwnable_orw` | shellcode 落点 `0x804a060`、上限 `0xc8`、BPF 表 `0x8048640` |

---

## 3. 运行

```bash
cd '/home/yfhd5/Pwn Writeups/sandbox_seccomp'

# 1) 生成本地可执行版（现代内核 .bss 是 RW，需要给 PT_LOAD 加 PF_X）
python make_local_exec.py

# 2) 当前目录需有 flag.txt，然后跑
python 23_pwnable_orw_exp.py
```

> 本地必须用 `orw_local_exec`；原版 `orw` 只用于远程/取证。
> 原因见下节。

---

## 4. 环境差异：为什么本地需要补丁

原版 `orw` 的第二个 `PT_LOAD` 是 `RW`（`.bss` 所在），程序把 shellcode 读到
`0x804a060` 后直接 `call`。pwnable.tw 当年跑在 **2.6.32 老内核**上，RW 段实际可执行；
现代内核严格 NX，本地执行会立刻 `SIGSEGV`。

`make_local_exec.py` 只改 program header 的 `p_flags |= PF_X`（不改任何代码），
生成 `orw_local_exec`：

```text
PT_LOAD vaddr=0x8049f08 flags=0x6 -> 0x7
LOAD  0x000f08 0x08049f08 ... RWE 0x1000
```

这样本地行为和当年服务器一致，exp 的远程分支仍然用原版 `orw`。

---

## 5. 常见误区

1. **以为有 canary 就不能 shellcode**：这题的溢出点其实是"直接 call 读进来的缓冲区"，
   canary 完全无关。
2. **shellcode 里用 `execve`**：被沙箱拦（`ENOSYS` 或 KILL），必须 ORW。
3. **缓冲区放在 `.bss` 之外**：`0x804a500` 这类地址没有映射，`read` 直接失败；
   用栈（`sub esp,0x100`）最稳。
4. **32 位/64 位 syscall 号混用**：32 位 `open`=5、`read`=3、`write`=4；
   64 位是 `open`=2、`read`=0、`write`=1，而且很多沙箱只给 `openat`(257)。
5. **本地跑不动就以为 exp 错**：先看 `readelf -lW` 的段 flags 和内核 NX 行为。
