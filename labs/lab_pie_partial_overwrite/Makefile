# lab_pie_partial_overwrite —— 自造「PIE + 1 字节溢出 → 局部覆盖返回地址」靶场
#
#   make          # 生成 chal
#   make clean
#
# 只用主机 gcc：本题不碰堆，也不依赖 glibc 版本，任何 amd64 + PIE 后的
# 发行版都能跑。刻意 **不加** -fstack-protector：1 字节溢出必须能碰到
# saved rip；NX 默认开启，所以只能跳到已有的代码（win 分支）。
# PIE 由 -fPIE -pie 强制打开（即使发行版默认 no-pie）。

CC     = gcc
CFLAGS = -O0 -g -fPIE -pie -fno-stack-protector -D_GNU_SOURCE

all: chal

chal: src/chal.c
	$(CC) $(CFLAGS) -o chal src/chal.c

clean:
	rm -f chal

.PHONY: all clean
