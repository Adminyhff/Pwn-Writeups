# stack_pivot

> 共同模式特征：**栈上可用空间不足（或栈地址不可控）→ 把 `rsp` 换到可控内存，再执行长 ROP 链**
> 关键不是"溢出多少"，而是"溢出之后栈在哪"：`xchg rsp, rax` / `leave; ret` /
> `pop rsp` / `mov rsp, rbp` 都是迁移入口，目标内存通常是堆、`.bss`、或 mmap 区。

---

## 1. 模式特征

```text
read/gets 的长度很小，装不下完整 ROP 链
或 栈地址随机但程序会打印某个可写地址（堆 / mmap / .bss）
+ 存在 rsp 改写 gadget
= stack_pivot
```

常见迁移 gadget：

| gadget | 说明 |
| --- | --- |
| `xchg rsp, rax; ret` | rax 通常由前一步 `pop rax` 控制，最干净 |
| `leave; ret` | `mov rsp,rbp; pop rbp; ret`，配合可控 saved rbp |
| `pop rsp; ret` | 直接弹栈指针，最直白 |
| `mov rsp, rbp; ...` | 变形，注意中间指令副作用 |
| `add rsp, X; ret` | 小幅度调整，用来跳过不可用槽位 |

标准流程：

1. 确认溢出字节数 < 需要的链长（否则不需要迁移）。
2. 找可控且**地址已知**的内存：程序打印的堆地址、`%p` 泄漏、`.bss`（No PIE）。
3. 第一段输入写长链到该内存；第二段输入只写"迁移三步"。
4. 迁移后长链照常 ROP：leak / 二次迁移 / 调 `system` 或题目后门。

---

## 2. 本模式题目

| 题目 | 架构 / 链接 | 溢出空间 | 迁移 gadget | 迁移目标 |
| --- | --- | --- | --- | --- |
| `22_ropemporium_pivot` | amd64 / 动态 + `libpivot.so` | `read(0, rbp-0x20, 0x40)`，仅 `0x18` 可用 | `pop rax` + `xchg rsp, rax; ret` | `heap+0xFFFF00`（程序打印） |

关键地址：

| 题目 | 关键量 |
| --- | --- |
| `22_ropemporium_pivot` | `pop rax=0x4009bb`、`xchg rsp,rax=0x4009bd`、CSU `pop=0x400a2a`/`call=0x400a10`、`foothold@0x96a`、`ret2win@0xa81` |

---

## 3. 运行

```bash
cd '/home/yfhd5/Pwn_Writeups/stack_pivot'
# RUNPATH=. 已内置，libpivot.so 与 pivot 放同目录即可
echo '__PWNED__{LOCAL}' > flag.txt
python 22_ropemporium_pivot_exp.py
```

---

## 4. 常见误区

1. **把 PLT 地址当函数指针传给 CSU**：`call [r12+rbx*8]` 是内存间接调用，
   `r12` 必须是 GOT 项地址。传 `@plt` 会变成"把 PLT 代码字节当地址"。
2. **忘了懒绑定**：没被调用过的外部函数，GOT 里是 PLT 桩，leak 出来算基址会错。
3. **`mov edi, r13d` 截断 32 位**：CSU 传参不能用来传堆/libc 高地址。
4. **迁移后忘了栈对齐**：个别 libc 版本里 `_dl_runtime_resolve` / `printf` 会有 `movaps`，
   必要时在链首插一个裸 `ret` 调整奇偶。
5. **`read` 上限**：迁移的前提就是空间有限，长链长度要按上限算，别写超。
