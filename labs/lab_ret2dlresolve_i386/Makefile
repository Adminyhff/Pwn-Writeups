# lab_ret2dlresolve_i386 —— 自造 ret2dlresolve 靶场
#
#   make          # 生成 chal（32 位动态链接，仅导入 read）
#   make clean
#
# 系统没有 gcc-multilib / 32 位 crt，所以用裸 as --32 + ld -m elf_i386，
# 直接链到随目录归档的 glibc 2.24 (i386)：libc/libc.so.6
#
# 说明：interpreter 写成相对路径 ./libc/ld-2.24.so，
#       这样在 lab 目录下直接 ./chal 就能跑；exp.py 里也会显式用 loader 启动。

AS       = as
LD       = ld
LIBC_DIR = libc

all: chal

chal: src/chal.S
	$(AS) --32 -o chal.o src/chal.S
	$(LD) -m elf_i386 --allow-shlib-undefined -o chal chal.o \
	    --dynamic-linker ./$(LIBC_DIR)/ld-2.24.so \
	    -rpath '$$ORIGIN/$(LIBC_DIR)' \
	    -rpath-link $(LIBC_DIR) -L$(LIBC_DIR) -l:libc.so.6
	rm -f chal.o

clean:
	rm -f chal chal.o

.PHONY: all clean
