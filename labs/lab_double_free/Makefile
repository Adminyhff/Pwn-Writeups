# lab_double_free —— 自造 double free 靶场（glibc 2.29+：绕 tcache key 检测）
#
#   make          # 生成 chal
#   make clean
#
# -no-pie：handlers[] / win 地址固定，exp 里直接用符号；
# tcache 的 LIFO 顺序和 safe-linking 混淆值都依赖“没有额外优化”，别加 -O2。

CC     = gcc
CFLAGS = -O0 -g -fno-pie -no-pie -fstack-protector-strong -D_GNU_SOURCE

all: chal

chal: src/chal.c
	$(CC) $(CFLAGS) -o chal src/chal.c

clean:
	rm -f chal

.PHONY: all clean
