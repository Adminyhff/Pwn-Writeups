# ret2shellcode

> 共同模式特征：**栈（或堆）可执行 + 把 shellcode 写到可执行内存再跳过去**
> 关键前提是 `GNU_STACK` 为 `RWE`（NX 关闭），所以不需要 ROP/leak libc，只需要一次
> 「可执行内存地址」泄漏，就能直接 `execve("/bin/sh")`。

---

## 1. 模式特征

```text
NX 关闭（GNU_STACK = RWE / `readelf -lW | grep STACK` 看到 RWE）
+ 存在可控写 + 可覆盖返回地址（或可写函数指针 / 可执行堆块）
+ 需要知道 shellcode 落地地址
= ret2shellcode
```

与 `ret2text` / `ret2libc` 的区别：

| 模式 | 落点 | 是否需要 leak | 是否需要 libc |
| --- | --- | --- | --- |
| `ret2text` | 二进制里现成的后门代码 | 否（No PIE） | 否 |
| `ret2libc` | libc 的 `system` | 是（leak libc） | 是 |
| **`ret2shellcode`** | 自己写的机器码（栈/堆/mmap） | 是（leak 可执行内存地址） | **否** |

标准流程：

1. `readelf -lW <bin> | grep GNU_STACK` → 必须是 `RWE`，否则本模式不成立。
2. 找可控写的落点：栈（`read(0, esp, n)`）、堆（`malloc` 后 `read`）、或 `mmap(PROT_EXEC)`。
3. 找地址泄漏点：栈地址（`push esp` + `write`）、堆地址（`printf("%p", ptr)`）、
   或固定地址（No PIE + `.bss` / `mmap(MAP_FIXED)`）。
4. 把 shellcode 与返回地址拼在一次或两次输入里。
5. shellcode 优先选**短**的：`execve("/bin/sh",0,0)` 只要 21~23 字节。

---

## 2. 本模式题目

| 题目 | 架构 / 链接 | 可执行落点 | 地址泄漏 | shellcode 位置 |
| --- | --- | --- | --- | --- |
| `21_pwnable_start` | i386 / 静态 / 564 B | 栈（GNU_STACK=RWE） | `push esp` + `write(1,esp,20)` | `leak-4+0x18` |

关键地址：

| 题目 | 关键量 |
| --- | --- |
| `21_pwnable_start` | leak gadget `0x08048087`、返回地址偏移 `0x14`、shellcode 偏移 `0x18` |

---

## 3. 运行

```bash
cd '/home/yfhd5/Pwn Writeups/ret2shellcode'
echo 'flag{LOCAL}' > flag.txt
python 21_pwnable_start_exp.py            # 本地
python 21_pwnable_start_exp.py REMOTE     # 远程 chall.pwnable.tw:10000
```

> 32 位静态程序在本机可直接执行，不需要 i386 loader；但如果换成动态链接的 32 位题，
> 仍按仓库惯例加 `I386_LD=/tmp/libc32/root/usr/lib32/ld-linux.so.2`。

---

## 4. 常见误区

1. **把 `push esp` 的值当成 payload 地址**：它比 payload 起点大 4（payload 从 `E-4` 开始写）。
2. **以为可以顺手做 SROP**：SROP 要求能把 `eax` 置成 11 且紧接 `int 0x80`，
   这题 `int 0x80` 前面的指令全是写死的，做不到。
3. **shellcode 太长**：一次 `read` 的字节数往往很小（这题 0x3c），
   优先手写短 shellcode，不要用 `shellcraft.sh()`（生成 40+ 字节）。
4. **本机没有 32 位 libc**：`asm()` / `gcc -m32` 会失败，手写 `bytes.fromhex(...)` 最稳。
