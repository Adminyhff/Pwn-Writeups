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

## 2. 本题（ROP Emporium `ret2csu`）与标准型的差异

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

## 3. 通用坑点

1. **`call [r12+rbx*8]` 是内存间接调用**：`r12` 必须是"指针的地址"。直接放
   `xxx@plt` 会把 PLT 的指令字节当地址 → 崩。
2. **`mov edi, r13d` 截断**：需要 64 位第一参时，不能用 csu 的 call 直接打目标；
   先让 csu 只负责 `rdx`，再用 `pop rdi` 覆盖（`rdi` 的写入不会影响 `rsi/rdx`）。
3. **rdx 会被大部分函数破坏**：无害跳板必须挑"不碰 rdx"的（`frame_dummy` /
   `register_tm_clones` / `__do_global_dtors_aux` 都满足；`pwnme`、`puts`、`printf`
   这类会调用 libc 的绝对不行）。
4. **GOT 懒绑定**：`ret` 到 `ret2win@plt` 时 GOT 可能还没解析，PLT 会自己触发
   `_dl_runtime_resolve`，参数不受影响。

## 4. 运行方式

```bash
cd '/home/yfhd5/Pwn Writeups/ret2csu'
source ../.venv/bin/activate
python 30_ropemporium_ret2csu_exp.py LOCAL     # 需要 libret2csu.so / key.dat 在同目录
```

`ret2csu` 的 `RUNPATH` 是 `b'.'`，所以 EXP 里先 `chdir` 到脚本目录，保证
`libret2csu.so`、`key.dat`、`encrypted_flag.dat` 都能被找到。

> **附件复原**：`key.dat` / `encrypted_flag.dat` 曾在 2026-11-25 的一次矩阵跑完后丢失
> （二进制没有 `unlink`/`remove` 导入，原因未定位），表现为 `Failed to open encrypted_flag.dat`
> → `30` FAIL。原始的 `ret2csu.zip` 四件套已补档到 `_vendor/ret2csu/`，需要时：
> `cp ../_vendor/ret2csu/{key.dat,encrypted_flag.dat} .`

## 5. 识别卡

```text
看到"没有 pop rdx / pop rsi" + 有 __libc_csu_init 的长 pop 序列
  → ret2csu
第一参必须是 64 位常量？
  → 是：csu 只设 rdx（call 指向不碰 rdx 的无害函数）+ pop rdi/rsi 补前两参
  → 否：标准 [csu_pop + csu_call] 两段式，call 后垫 7 个 qword
```
