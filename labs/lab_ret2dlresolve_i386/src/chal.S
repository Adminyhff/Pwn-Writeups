/* lab_ret2dlresolve_i386 —— 最小 ret2dlresolve 靶场（自造，非真实赛题）
 *
 * 设计目标：二进制里**只导入 read**，没有 system、没有 /bin/sh，但又是动态链接的
 * （存在 .dynsym / .dynstr / .rel.plt / PLT0），于是只能伪造 ELF 结构让动态链接器
 * 自己去 libc 里解析 system：
 *
 *   data:   read(0, esp, 0x200)   -> 栈溢出，chain[0] 就在栈顶
 *
 * 链（pwntools 的 Ret2dlresolvePayload + ROP.ret2dlresolve 会生成）：
 *   1) read(0, dlresolve.data_addr, len)   把伪造的 .dynstr/.dynsym/.rel.plt 写进 bss
 *   2) plt0(reloc_offset) -> _dl_runtime_resolve -> system("/bin/sh")
 *
 * 链接：系统没装 gcc-multilib、也没有 32 位 crt，所以用裸 as/ld（见 Makefile），
 *       libc 用随目录归档的 glibc 2.24 (i386)。
 *       注意 i386 的 read 系统调用号是 3（0 是 restart_syscall，会返回 -EINTR）。
 */
    .section .text
    .global _start

_start:
    /* write(1, "data: ", 6) —— 走 syscall，不引入多余符号 */
    mov     $4, %eax
    mov     $1, %ebx
    mov     $msg1, %ecx
    mov     $6, %edx
    int     $0x80

    /* 读 0x200 字节到栈顶（read 走 PLT，保证 .rel.plt/.dynsym 存在）*/
    sub     $0x200, %esp
    mov     %esp, %ebx
    push    $0x200
    push    %ebx
    push    $0
    call    read
    add     $12, %esp
    ret

    .section .rodata
msg1:
    .ascii "data: "

    .section .bss
    .balign 16
    .lcomm rdl_bss, 0x400

    .section .note.GNU-stack,"",@progbits
