# badchars_encoding / 字符过滤下的编码规避 —— 写密文、原地解码、再当参数用

> 典型触发条件：**程序会检查输入里的坏字符**（命中就丢弃 / 改成 `0xeb` / 直接退出），
> 而 exploit 需要的字符串（`"flag.txt"`、`"/bin/sh"`）或 gadget 地址恰好命中。
> 解法固定：**先写编码后的数据，再用 `xor/add/sub byte ptr [reg], regb` 原地还原**。

## 1. 判据（什么时候选它）

| 现象 | 结论 |
| --- | --- |
| `pwnme` 里有"逐字节 vs 坏字符表"的循环 | 输入里不能出现坏字符 |
| 需要的字符串含坏字符（`/bin/sh` 含 `a`、`/`；`flag.txt` 含 `g a .`） | 必须编码 |
| gadget 地址 / 栈上常量也含坏字符 | 换 gadget 或换目标地址，不能只编码字符串 |
| 有 `xor/add/sub byte ptr [r15], r14b` 之类单字节运算 gadget | 原地解码，最省字节 |
| 没有任何 mem-arithmetic gadget，但能再调 `read` | 让第二次 `read` 直接读明文（若第二次不过滤） |

标准两段式：

```text
[写内存 gadget] 把 encode("flag.txt") 写到 .data
[pop r14; pop r15; ret] + [xor byte [r15], r14b; ret]  × len(str)    # 原地解码
[pop rdi; ret][.data][print_file@plt]
```

## 2. 本模式题目

| 题目 | 架构 / 保护 | 坏字符 | 编码 | 目标 |
| --- | --- | --- | --- | --- |
| `32_ropemporium_badchars` | amd64 / No PIE / NX / Partial RELRO | `x` `g` `a` `.` | `^2` → `"dnce,vzv"`，8 次 `xor [r15], r14b` | `print_file@plt(0x601030)` |

## 3. 选 key / 选地址的三条自检

1. **密文**不含坏字符（`set(enc) & BAD == ∅`）；
2. **gadget 地址与栈上常量**（key、0 填充、写目标地址）不含坏字符；
3. **解码时的每个 `DATA + i`** 也不含坏字符——最容易漏的是这里：
   `0x60102e` 的低字节 `0x2e` 就是 `.`，于是目标只能从 `0x601030` 起。

EXP 里把三条合成一句：

```python
assert not set(payload) & set(b"xga.")
```

## 4. 通用坑点

1. **地址字节撞坏字符**：`0x...2e`、`0x...61`(`a`)、`0x...67`(`g`)、`0x...78`(`x`)
   在 `.data`/`.bss` 附近很容易出现（`0x60102e` 实测必撞）。
2. **长度预算**：`read` 上限是硬约束。用 4-pop 的 `pop r12..r15` 做 8 次解码会
   多花 192 字节（568 > 512），必须换成 2-pop 的 `pop r14; pop r15`。
3. **被改写的不是"坏字符位置"，而是整条链任意字节**：padding、返回地址都在检查范围内。
4. **坏字符表可能是字符串而非单字节集合**：先 `objdump -s -j .rodata` 看清
   `badcharacters` 的真实内容和长度，再决定编码表。
5. `add`/`sub` 也能当编码；若 XOR 后仍有坏字符，换 key 比换运算更快。

## 5. 运行方式

```bash
cd '/home/yfhd5/Pwn_Writeups/badchars_encoding'
source ../.venv/bin/activate
python 32_ropemporium_badchars_exp.py LOCAL

# 一键矩阵
bash ../tools/verify_all.sh 32
```

EXP 里 `chdir` 到脚本目录（`RUNPATH=b'.'` → `libbadchars.so`），并保证 `flag.txt` 存在。
远程：`HOST=... PORT=... python 32_ropemporium_badchars_exp.py`（官方无公开靶机）。

## 6. 文件说明

| 文件 | 作用 |
| --- | --- |
| `32_ropemporium_badchars_speedrun.md` | 过滤循环反汇编、编码表、长度账、三个坑 |
| `32_ropemporium_badchars_exp.py` | 武器化 EXP（含 `assert` 自检、本地/远程双模） |
| `badchars` / `libbadchars.so` / `flag.txt` | 官方附件（`badchars` 需 `git add -f`） |

## 7. 识别卡

```text
输入被逐字节和坏字符表比对（改了 / 丢了）
  -> badchars_encoding：写密文 + 原地解码
先做三件核对：密文、所有常量与 gadget 地址、每个解码地址
长度先算再写；解码循环用最短的 pop 组合
```
