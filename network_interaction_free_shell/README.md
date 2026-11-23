# network_interaction_free_shell

> 共同模式特征：**网络交互 / 白给 Shell**
> 核心判断：二进制正常逻辑本身就执行 `system("/bin/sh")` 或 `execve("/bin//sh")`，不存在需要利用的内存破坏点。
> 利用工作全部在“网络层交互”上，而不是 RIP 劫持或 ROP。

---

## 1. 模式特征

出现下面组合时，直接归入本模式：

```text
main 中直接执行 system("/bin/sh") 或 execve("/bin//sh")
+ 没有 gets / read / scanf 等可控输入点
+ PIE / Canary / NX 与利用无关
+ 远程服务直接暴露交互式 shell
= 连上就是 shell，不需要 PWN
```

关键点：

| 观察 | 含义 |
| --- | --- |
| `main` 调用 `system("/bin/sh")` 或 `getShell` | 程序正常业务就是给 shell |
| 没有输入函数 | 不存在栈/堆破坏面 |
| 保护机制齐全 | 干扰项，本题不需要绕过 |
| 平台强制 TLS | 真正的“门槛”在网络握手 |

---

## 2. 本模式题目

| 题目 | speedrun 题型 | 关键结论 |
| --- | --- | --- |
| `01_test_your_nc` | 网络交互 / 白给 Shell | `main` 直接 `system("/bin/sh")`，TLS 连上后执行 `ls`、`cat flag*` |
| `17_others_shellcode` | 网络交互 / 白给 Shell（execve shellcode） | `main` 直接 `call getShell`，`getShell` 用 `int 0x80` 执行 `execve("/bin//sh")` |

---

## 3. 文件说明

| 文件 | 作用 |
| --- | --- |
| `01_test_your_nc_speedrun.md` | 2 分钟速通笔记：定性质、交互、坑点、识别卡 |
| `01_test_your_nc_writeup.md` | 完整分析：目标侦察、漏洞解剖、利用策略 |
| `01_test_your_nc_exp.py` | 武器化 EXP：TLS 连接 + 交互式 shell |
| `test_your_nc` | 01 的题目二进制（未改名，保持原始文件名） |
| `01_test_your_nc_image*.png` | writeup 中引用的逆向截图 |
| `17_others_shellcode_speedrun.md` | 17 速通：`getShell` 的 `int 0x80` shellcode |
| `17_others_shellcode_exp.py` | 17 武器化 EXP：本地 / 远程交互 |
| `others_shellcode` | 17 的题目二进制 |

---

## 4. 使用方式

```bash
cd '/home/yfhd5/Pwn Writeups/network_interaction_free_shell'

# 静态确认“白给 shell”
file test_your_nc
checksec --file=test_your_nc
objdump -d -M intel test_your_nc | sed -n '/<main>:/,/^$/p'

# 运行 EXP（会连接远端，需要可用的靶机地址）
python 01_test_your_nc_exp.py

# 17：本地验证 execve shellcode
I386_LD=/tmp/libc32/root/usr/lib/i386-linux-gnu/ld-linux.so.2 \
I386_LIBPATH=/tmp/libc32/root/usr/lib/i386-linux-gnu \
python 17_others_shellcode_exp.py LOCAL
```

> `01_test_your_nc_exp.py` 中的 `host` 需要替换为当前靶机地址；CTF² 必须使用 `ssl=True`。
