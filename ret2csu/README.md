# ret2csu / return-to-csu —— 用 `__libc_csu_init` 的通用 gadget 补齐缺失的传参寄存器

> 典型触发条件：**溢出可控，但二进制里没有 `pop rdx`**，而目标函数需要第三个参数
> （`system` 之后的 `write` / `read` / 自定义三参函数）。x86-64 的 `__libc_csu_init`
> 自带一段 `mov rdx, r15 ; mov rsi, r14 ; mov edi, r13d ; call [r12+rbx*8]`，
> 配合前面的 `pop rbx/rbp/r12/r13/r14/r15 ; ret`，就是常说的 "Universal ROP"。

## 1. 判据（什么时候选它）

| 现象 | 结论 |
| --- | --- |
| 缺 `pop rdx`（或 `pop rsi`），但存在 `pop rbx; pop rbp; pop r12; pop r13; pop r14; pop r15; ret` | 可以用 ret2csu |
| 目标函数 3 个参数，且第一个参数是**真正的 64 位常量** | 注意 `mov edi, r13d` 是 32 位写，见 §3 |
| 目标函数 3 个参数，参数都是小整数 / 指针 | 标准两段式即可 |
| 二进制被 `-fno-plt` 编译过（没有 `__libc_csu_init`） | 改用 `__init_array`/`_dl_runtime_resolve` 或找其他 gadget |

标准两段式：

```text
[csu_pop][rbx=0][rbp=1][r12=函数指针地址][r13=arg1][r14=arg2][r15=arg3][csu_call]
         └ r12 必须是"存着函数地址的内存"（GOT 项 / .init_array 项），
           因为 csu 用的是 `call [r12+rbx*8]` 而不是 `call r12`
[csu_call] = mov rdx,r15 ; mov rsi,r14 ; mov edi,r13d ; call [r12+rbx*8]
             add rbx,1 ; cmp rbp,rbx ; jne csu_call
             add rsp,8 ; pop rbx; pop rbp; pop r12; pop r13; pop r14; pop r15 ; ret
```

`rbx=0 / rbp=1` 让循环只跑一轮；`csu_call` 之后要再垫 **7 个 qword** 才轮到返回地址
（1 个 `add rsp,8` + 6 个 pop）。

## 2. 本模式题目

| 题目 | 架构 / 保护 | 缺口 | 解法 |
| --- | --- | --- | --- |
| `30_ropemporium_ret2csu` | amd64 / No PIE / NX / Partial RELRO | 没有 `pop rdx` | csu 两段式 + 无害跳板（见 §3） |
| `33_ropemporium_callme` | 同上 | 寄存器不缺，但每个函数都要重装 3 个参数 | 合并 gadget `pop rdi; pop rsi; pop rdx; ret`（0x40093c），不走 csu |

> 33 归到这个目录是因为**识别特征相同**（连续调用多个同签名三参函数）；
> 但它的最优解不是 csu——先找"一条 gadget 装多个参数"，找不到才退回 csu。
> 细节见 `33_ropemporium_callme_speedrun.md`。

## 3. 30 `ret2csu` 与标准型的差异

| 项 | 值 |
| --- | --- |
| 目标 | libret2csu.so 里的 `ret2win(0xdeadbeefdeadbeef, 0xcafebabecafebabe, 0xd00df00dd00df00d)` |
| 可用 gadget | `pop rdi ; ret`（0x4006a3）、`pop rsi ; pop r15 ; ret`（0x4006a1）、**无 `pop rdx`** |
| csu 形态 | 第一参走 `mov edi, r13d`（32 位写，会清零 rdi 高 32 位） |
| 关键点 | 标准链会在 `call [r12]` 时把 rdi 截断成 `0x00000000deadbeef` → 第一项检查就失败 |

所以这里要**把 csu 的 `call` 指向一个"不碰 rdx 的无害函数"**，让 gadget 安全走完
epilogue、`rdx` 存活，再用 `pop rdi` / `pop rsi` 补前两个参数，最后 `ret` 到
`ret2win@plt`。本仓库选的是 `.init_array[0]`（`0x600df0` → `frame_dummy`）：

```text
frame_dummy -> register_tm_clones   全程只用 rax/rsi/rdi/rbp，不写 rdx
            末尾 pop rbp ; ret     正好回到 0x40068d 继续 csu 收尾
```

## 4. 通用坑点

1. **`call [r12+rbx*8]` 是内存间接调用**：`r12` 必须是"指针的地址"。直接放
   `xxx@plt` 会把 PLT 的指令字节当地址 → 崩。
2. **`mov edi, r13d` 截断**：需要 64 位第一参时，不能用 csu 的 call 直接打目标；
   先让 csu 只负责 `rdx`，再用 `pop rdi` 覆盖（`rdi` 的写入不会影响 `rsi/rdx`）。
3. **rdx 会被大部分函数破坏**：无害跳板必须挑"不碰 rdx"的（`frame_dummy` /
   `register_tm_clones` / `__do_global_dtors_aux` 都满足；`pwnme`、`puts`、`printf`
   这类会调用 libc 的绝对不行）。
4. **GOT 懒绑定**：`ret` 到 `ret2win@plt` 时 GOT 可能还没解析，PLT 会自己触发
   `_dl_runtime_resolve`，参数不受影响。

## 5. 运行方式

```bash
cd '/home/yfhd5/Pwn_Writeups/ret2csu'
source ../.venv/bin/activate
python 30_ropemporium_ret2csu_exp.py LOCAL     # 需要 libret2csu.so / key.dat 在同目录
python 33_ropemporium_callme_exp.py LOCAL      # 运行文件在 callme_lab/，EXP 自动切 cwd
```

`ret2csu`/`callme` 的 `RUNPATH` 都是 `b'.'`（相对 cwd），所以 EXP 里先 `chdir` 到
附件所在目录。**两题的 `encrypted_flag.dat` 同名不同内容**（`37aa4baf…` vs `3160bfe6…`），
不能放同一目录，否则后拷的会覆盖前者、30 会解不出 flag——所以 callme 的 5 个文件
单独放在 `ret2csu/callme_lab/`。

> **附件复原**：原始的 `ret2csu.zip` 四件套已补档到 `_vendor/ret2csu/`，需要时：
> `cp ../_vendor/ret2csu/{key.dat,encrypted_flag.dat} .`

## 6. 识别卡

```text
看到"没有 pop rdx / pop rsi" + 有 __libc_csu_init 的长 pop 序列
  → ret2csu
看到"要连续调用多个三参函数"（寄存器够用但每个函数都要重装参数）
  → 先找合并 gadget（pop rdi; pop rsi; pop rdx），找不到才退回 ret2csu
第一参必须是 64 位常量？
  → 是：csu 只设 rdx（call 指向不碰 rdx 的无害函数）+ pop rdi/rsi 补前两参
  → 否：标准 [csu_pop + csu_call] 两段式，call 后垫 7 个 qword
参数宽度以 lib 里 cmp 的立即数为准，别照抄老 writeup（新版常改成 64 位双写）
```
