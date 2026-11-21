# stack_local_var_overwrite

> 共同模式特征：**栈溢出只改相邻局部变量 / 条件绕过**
> 不需要覆盖返回地址，也不需要 ROP；目标是让某个比较条件成立，从而进入成功分支。

---

## 1. 模式特征

```text
存在无边界输入（gets / read 等）
+ 缓冲区旁边紧邻一个参与条件判断的局部变量
+ 成功分支执行 system("cat /flag") 等敏感操作
+ 不需要控制 RIP
= 溢出改局部变量 / 条件绕过
```

与 `ret2text` 的区别：

| 维度 | ret2text | stack_local_var_overwrite |
| --- | --- | --- |
| 覆盖目标 | saved RIP | 相邻局部变量 |
| 控制流 | 跳到后门函数 | 让原程序走成功分支 |
| 是否需要地址 | 需要 | 通常不需要 |
| 典型输入 | 垃圾填充 + 函数地址 | 缓冲区长度 + 变量正确取值 |

---

## 2. 本模式题目

| 题目 | 输入点 | 局部变量布局 | 覆盖偏移 | 目标值 | 成功分支 |
| --- | --- | --- | --- | --- | --- |
| `04_ciscn_2019_n_1` | `gets(buf)`，`buf=rbp-0x30` | `char buf[44]` @ `rbp-0x30`；`float v2` @ `rbp-0x4` | **44** | `11.28125`（IEEE-754 单精度 `0x41348000`） | `system("cat /flag")` |

Payload：

```python
b'A' * 44 + p32(0x41348000)
# 等价于
b'A' * 44 + struct.pack("<f", 11.28125)
```

---

## 3. 关键坑点

1. **偏移是 44，不是 56**：`v2` 在 `rbp-0x4`，不是 saved RIP。
2. **写 float 位模式，不是字符串**：`b"11.28125"` 是 ASCII，比较不会通过。
3. **`p32(11.28125)` 会报错**：`p32` 只接受整数，使用 `p32(0x41348000)` 或 `struct.pack("<f", ...)`。
4. **不需要继续覆盖 saved rbp / RIP**：覆盖到 `v2` 即停止。

---

## 4. 文件说明

| 文件 | 作用 |
| --- | --- |
| `04_ciscn_2019_n_1_speedrun.md` | 2 分钟速通笔记：偏移、float 位模式、坑点 |
| `04_ciscn_2019_n_1_exp.py` | 武器化 EXP |
| `ciscn_2019_n_1` | 题目二进制（未改名，保持原始文件名） |

> 本题没有单独留 `writeup.md`；`speedrun.md` 已包含完整的逆向、栈布局与利用说明。

---

## 5. 使用方式

```bash
cd '/home/yfhd5/Pwn Writeups/stack_local_var_overwrite'

file ciscn_2019_n_1
checksec --file=ciscn_2019_n_1
objdump -d -M intel ciscn_2019_n_1 | sed -n '/<func>:/,/^$/p'

python 04_ciscn_2019_n_1_exp.py
```

> 远程 `system("cat /flag")` 使用绝对路径；本地一般没有 `/flag`，只验证成功分支是否被走到。

---

## 6. 题型识别卡

```text
gets(buf) + 附近有参与比较的局部变量
+ 成功分支有 system("cat /flag")
+ 不需要改 RIP
= 栈溢出改局部变量，按变量类型精确构造字节
```
