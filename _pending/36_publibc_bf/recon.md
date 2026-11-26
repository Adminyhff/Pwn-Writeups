# 36 · `publibc/bf` 侦察记录（PENDING）

> 名字里的 `bf` 指 **brainfuck 风格的自定义 tape 解释器**（不是纯 brainfuck：指令是
> ASCII `!`..`@` 映射到 `0x21..0x40`，执行期读 `.bss` 的 word 数组）。
> **本轮（2026-11-26）修正了旧结论**：旧记录写"需要 hook / FSOP"，实际不是——
> 程序里有一个**硬编码 `system("/bin/sh")` 的不可达后门**（`0x19d8`，字符串 `"/bin/sh"@0x2120`），
> 真正缺的是**一个 RIP 控制点**，而不是 FSOP 原语。

## 0. 可运行性（2026-11-26 实测）

```bash
cd '/home/yfhd5/Pwn_Writeups/_pending/36_publibc_bf'
printf '5\n' | ./bf        # 输出 Hello, world! / Give me your choice: / Bye~
```

`choice=5` 是**退出**（`Bye~`），**不是**那个后门 —— 后门没有任何调用点。

## 1. 二进制事实

| 项 | 值 |
| --- | --- |
| 架构 | ELF 64-bit amd64，PIE，动态链接，**stripped**（无符号表），≈14 KB |
| 保护 | PIE、NX、Canary、**Full RELRO**（`.got` 只读 → 排除 GOT 改写） |
| 导入 | `read`、`malloc`、`getchar`、`setvbuf`、`puts`、`printf`、`scanf`、`putchar`、`system`、`__stack_chk_fail` |
| 入口 | `0x1180` → `__libc_start_main(main=0x16f8, …)` |

## 2. 菜单（`scanf("%d", &choice)`，`cmp eax,5; ja` + jump table）

jump table 在文件偏移 `0x20e0`，实测解析结果（PIE 相对偏移）：

| choice | 目标 | 行为 |
| --- | --- | --- |
| 0 | `0x17df` | 默认分支（直接跳结束） |
| 1 | `0x178f` → `0x1800` | **add**：`scanf("%u", &size)`；`size <= 0xfff` 才 `malloc(size)`；指针写全局 `0x4060`，size 写 `0x4068` |
| 2 | `0x179b` → `0x18c2` | **edit**：`printf("text: ")`；`read(0, ptr, size)`；返回后 `ptr[ret-1] = 0` |
| 3 | `0x17a7` → `0x191d` | **compile**：`0x1269(ptr)` 把文本编译成 tape 指令，返回 1 → `Error`，否则 `OK` |
| 4 | `0x17b3` → `0x1964` | **exec**：栈上开 `0x20000` 缓冲，`0x151d(buf)` 解释执行 tape |
| 5 | `0x17bf` → `0x19be` | `puts("Bye~")` 结束 |

字符串实测（按文件偏移读 `.rodata`）：`0x20a8 "Hello, world!"`、`0x20b6 "Give me your choice: "`、
`0x20cc "%d"`、`0x20f8 "size: "`、`0x20ff "%u"`、`0x2102 "success!"`、`0x210b "text: "`、
`0x2112 "Error"`、`0x2118 "OK"`、`0x211b "Bye~"`、`0x2120 "/bin/sh"`。

## 3. 关键布局与代码事实

| 地址（PIE 相对） | 含义 |
| --- | --- |
| `0x4060` | 全局 `char *ptr`（只有一个槽，add 会直接覆盖旧指针，**不 free → 无 UAF**） |
| `0x4068` | 全局 `int size`（与 `ptr` 配对，edit 的读长度就是它） |
| `0x4080` | **tape**：word 数组（`mov WORD PTR [rdx+rax*1]`，索引 `*4`） |
| `0x19d8` | `system("/bin/sh")` —— **死代码后门** |

已验证的三条硬事实：

1. **后门不可达**：`objdump -d | grep -E '(call|jmp)[a-z ]*19d8'` 为空；菜单 jump table
   6 项里也没有 `0x19d8`。它是一个"编译器没删掉、但没人调"的函数。
2. **edit 的零字节写**：`read` 返回 0（EOF，例如 `sendline("")` 后立刻关闭）时，
   `ptr[ret-1] = ptr[-1] = 0` → 清掉 `ptr` 所在 chunk 的 **size 最低字节**
   （0x21 → 0x00 之类），属于"零字节 off-by-one"，但全局只有一个 `ptr`，没有第二个块可叠。
3. **tape 越界受限**：解释器用 `movzx` 读 16 位指针（`[rbp-0x8]`，类型是无符号 word），
   所以只能向高地址越界，最大 `0xffff*4 ≈ 0x40000`；`0x4080+0x40000` 已在 `.bss` 之后
   未映射区域 → 单靠 tape 越界改不到 `.bss` 低处的 `0x4060/0x4068`。

## 4. 阻塞点（为什么还是 PENDING）

- **Full RELRO**：`.got` 只读，`__free_hook` 在 glibc 2.43 已移除 → 老 writeup 的
  "hook / FSOP" 路线在本机**物理不可复现**（这也是旧结论需要更正的原因）。
- **没有可用的栈溢出**：所有栈缓冲都带 canary（`0x1800` / `0x1964` 都有 `fs:0x28` 检查），
  唯一的栈缓冲 `0x20000` 由解释器内部使用，写入长度不由输入直接控制。
- **只有一次控制的堆指针**：`add` 直接覆盖 `0x4060`，也没有 free/show，
  构不成 tcache poisoning / UAF 所需的"两个可控块"。
- 于是链路卡在"**缺一个 RIP 控制点**"：后门已经在二进制里，只要能改 1~2 字节控制流就能进。

## 5. 下一步（按性价比排序）

1. **找部分覆盖点**（与仓库 L11 同思路）：PIE 下镜像内部偏移固定，
   检查 `0x191d`（compile）与 `0x1964`（exec）的返回地址附近有没有可被"1 字节写"改到的
   `call`；`0x19d8` 与这些调用点若落在同一个 256 字节块，1 字节 LSB 覆盖即可进后门。
2. 精读 `0x1269`（compile）与 `0x151d`（exec）的指令分派：tape 单元是 `enum 0..8`，
   `0x151d` 里先 `memset(buf, 0, 0xffff*2)` 再逐条执行；若有"输出/输入"指令
   （对应 `putchar` / `getchar`），可考虑用它做任意地址读（leak PIE / libc）。
3. `ptr[-1]=0` 的零字节写单独评估：若能通过 `add` 的 `size` 选择把 `ptr[-1]` 落在
   下一个块的 `size` 上（例如先 `malloc` 一个小块再 `add` 一个大块），可以伪造
   "跨 size class"的块；但当前程序没有 free，需先确认 `size<=0xfff` 与 tcache 上限 16 的交互。

**重开提示**：不要重新做菜单/jump table 解析（§2 的表格已实测），直接从第 1 条
（同 256 字节块的部分覆盖）开始。
