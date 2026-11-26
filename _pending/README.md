# PENDING · 未解档案（不计入 24 类 / 不进可复现矩阵）

> **题型已冻结**：`PATTERN_CLASSIFICATION.md` §1 的 24 类不再新增。本目录只做一件事——
> 把「做过侦察、写了过程记录、但没解出来」的题原样留住，保证重开时不用重新推导。
>
> 这些题**不进** `tools/verify_all.sh`、**不计入** `README.md` 的 44 题矩阵，
> 因此 `PASS=23 / 题数=44` 的口径不受影响。除 `35` / `36` 两个本地二进制外，
> 其余条目的材料仍在原位置（只在这里索引）。

## 1. 索引

| 编号 / 来源 | 二进制 | 拟定模式 | 状态 | 卡点（一句话） | 详细记录 |
| --- | --- | --- | --- | --- | --- |
| 35 | `35_judgement_mna_2016/judgement_mna_2016` | `format_string_write` | **PENDING** | `getnline` 的 `isprint` 逐字节过滤使"把 `0x804a0a0` 塞进格式串"不可能；栈上可用指针槽只有 `strchr@GOT` | [`35_judgement_mna_2016/recon.md`](35_judgement_mna_2016/recon.md) |
| 36 | `36_publibc_bf/bf` | `heap_exploitation`（原判 `fsop`，**已更正**，见 recon） | **PENDING** | PIE + Full RELRO + Canary，且**缺一个 RIP 控制点**；`system("/bin/sh")@0x19d8` 是**不可达后门** | [`36_publibc_bf/recon.md`](36_publibc_bf/recon.md) |
| 26 | `heap_exploitation/card` | `heap_exploitation` | **PENDING**（主动放弃） | 2.27 下 `__free_hook` 写入后 `free()` 不触发；stage-1 的 libc 泄漏已跑通 | `heap_exploitation/26_card_speedrun(pending).md` §10；`PATTERN_CLASSIFICATION.md` §3.26 |
| pwnable.tw | `_vendor/tcache_tear` | `tcache_poisoning` | **PENDING**（2026-11-26 降级） | glibc 2.27 无 `tcache_entry.key` → tcache dup 可行，但 **free 上限 8 次 < 链路需要 9 次**（省一次只能靠 one_gadget，本机无该工具） | `PATTERN_CLASSIFICATION.md` §5.6 的 `tcache_tear` 行（含完整 `.bss` 布局与重开步骤） |
| pwnable.tw | `_vendor/death_note` | `heap_uaf` + `ret2shellcode` | 未展开 | 32 位 + EXECSTACK，需要 i386 2.24/2.23（无 tcache）跑 UAF → 堆上 shellcode | `PATTERN_CLASSIFICATION.md` §5.6 |
| （外部，未入库） | pwnable.tw `unexploitable` | `ret2dlresolve` | **负结果（已定论）** | amd64 + 现代 glibc 上 `ret2dlresolve` 不可用：version lookup 用未受控 `sym index` 读 `DT_VERSYM` → `SIGSEGV`（2.24 / 2.27 / 2.43 均复现）；同思路在 i386 2.24 上可成功（L3） | `PATTERN_CLASSIFICATION.md` §5.6 |

## 2. 重开规则（避免二次浪费）

1. **先读 recon，再动手**。每份 `recon.md` 都写明了"已经验证过什么、不要再推什么"。
2. **20 分钟规则照旧**：从 recon 的最后一步开始，20 分钟内拿不出可执行思路就继续挂着。
3. **新结论必须回写**到对应 `recon.md` 或 `PATTERN_CLASSIFICATION.md` §5，不要只留在终端历史里。
4. **解出来后**：把二进制 + exp + 文档移到对应模式目录（`NN_` 编号顺延），
   从本索引删除该行，并在 `README.md` 的 changelog 里记一笔；**不要**顺手新增题型。

## 3. 复现提示

`35` / `36` 的原始二进制没有扩展名，被 `.gitignore` 的 deny-all 规则忽略，
归档时用了 `git add -f`（与 `_vendor/attach_manifest.md` 的说明一致）。本地执行命令均为**实测**：

```bash
cd '/home/yfhd5/Pwn_Writeups'
source .venv/bin/activate

# 35：i386，用仓库内自带的 i386 glibc 2.24 loader（不依赖 /tmp 解包目录）
cd _pending/35_judgement_mna_2016
printf 'FLAG{test}\n' > flag.txt
printf 'AAAA\n' | ../../labs/lab_ret2dlresolve_i386/libc/ld-2.24.so \
  --library-path ../../labs/lab_ret2dlresolve_i386/libc ./judgement_mna_2016
rm -f flag.txt            # 期望：Input flag >> AAAA / Wrong flag...
cd ../..

# 36：amd64，直接跑（本机 glibc 2.43）
printf '5\n' | ./_pending/36_publibc_bf/bf    # 期望：Hello, world! / Give me your choice: / Bye~
```
