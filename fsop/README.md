# fsop

> 共同模式特征：**可控 `FILE *`（或可控 `_IO_list_all`）→ 伪造 `_IO_FILE`/vtable → 借 libc 内部调用链执行任意函数**
> 典型落地：`fclose(fp)` / `exit()` 触发 `_IO_FINISH`，命中 libc 里的 `_IO_str_finish`，把 `_s._free_buffer` 当成函数指针。

---

## 1. 模式特征

```text
程序里存在全局 FILE *（或可写 _IO_list_all）
+ 有一个"写固定 .bss 缓冲区"的入口，且长度/次数可控
+ 该缓冲区能与 fp 指针或 FILE 结构本身重叠
= 伪造 _IO_FILE -> vtable 槽位 -> _IO_str_finish / _IO_file_xsputn 等 -> 控制流
```

和堆题的差别：**不依赖分配器元数据**，只依赖 libc 的 `_IO_*` 实现细节，因此
判定顺序里它排在 `heap_uaf` / `heap_exploitation` 之前——看到 `fopen/fread/fclose`
加一个可覆盖的全局 `FILE *`，就先想 FSOP。

本题的 libc 侧调用链（i386 / glibc 2.24）：

```text
fclose(fp)
  -> _IO_fclose(fp)                  # _vtable_offset == 0 -> 老接口
     -> CHECK_FILE: (fp->_flags & 0xffff0000) == 0xFBAD0000
     -> _IO_un_link(fp)              # _IO_LINKED 不在全局链表里，无副作用
     -> _IO_file_close_it(fp)        # _fileno == -1 时立刻返回 EOF，不碰真实 fd
     -> _IO_vtable_check(vtable)     # vtable 必须落在 __libc_IO_vtables 段内
     -> _IO_FINISH(fp) == vtable->__finish(fp, 0)
        -> _IO_str_finish:
             if (fp->_IO_buf_base && !(fp->_flags & _IO_USER_BUF))
                 ((_IO_strfile *)fp)->_s._free_buffer(fp->_IO_buf_base);
```

---

## 2. 本模式题目

| 题目 | 架构 / libc | 关键地址 | 利用 |
| --- | --- | --- | --- |
| `29_pwnable_tw_seethefile` | i386 / 2.24（2.23 同理） | `magicbuf=0x804b0c0`、`name=0x804b260`、`fp=0x804b280` | 隐藏菜单 5 的 `scanf("%s", name)` 溢出覆盖 `fp`；用 `fopen("/dev/stdin")` + `fread` 把假 `_IO_FILE` 灌进 `magicbuf`；`fclose` 走 `_IO_str_finish` → `system("/bin/sh")` |

---

## 3. 文件说明

| 文件 | 作用 |
| --- | --- |
| `29_pwnable_tw_seethefile_speedrun.md` | 假 FILE 布局、交互顺序、坑点与实测输出 |
| `29_pwnable_tw_seethefile_exp.py` | 武器化 EXP：`/proc/self/maps` 泄漏 → `/dev/stdin` 灌 blob → 菜单 5 劫持 `fp` |
| `seethefile` | 题目二进制（原始文件名） |

libc 复用 `../ret2libc/libc-2.24.so`（i386，md5 `79f8c0d940ae393b3ad1be40892c9c84`），
loader 不入库，按下面命令解包 `libc6_2.24-3ubuntu2.2_i386.deb` 得到 `ld-linux.so.2`。

---

## 4. 使用方式

```bash
cd '/home/yfhd5/Pwn_Writeups/fsop'
source ../.venv/bin/activate

# 本地：I386_LD / I386_LIBPATH 指向 i386 loader 目录，LIBC 指向 2.24 附件
I386_LD=/tmp/libc224i32/ld-linux.so.2 \
I386_LIBPATH=/tmp/libc224i32 \
LIBC=../ret2libc/libc-2.24.so \
python 29_pwnable_tw_seethefile_exp.py LOCAL
```

远程（pwnable.tw 用 2.23，必须提供对应 `LIBC`，脚本会自己扫出 `_IO_str_jumps`）：

```bash
HOST=chall.pwnable.tw PORT=10200 LIBC=/path/to/i386/libc-2.23.so \
python 29_pwnable_tw_seethefile_exp.py
```

---

## 5. 题型识别卡

```text
程序自己 fopen/fread/fclose，且 FILE * 是全局变量
+ 有 "写 .bss 固定缓冲区" 的菜单项（read/fread 长度受限但可重复）
+ 某个 %s 输入能溢到 fp 指针
= FSOP：伪造 _IO_FILE，vtable 指 libc 的 _IO_str_jumps，__finish 槽换成 system
```

一句话：**`fp` 可改是入口；能让 `fread` 把二进制灌进已知 .bss 是关键；
最后靠 `_IO_str_finish` 的 `_s._free_buffer(buf_base)` 打出 `system("/bin/sh")`。**
