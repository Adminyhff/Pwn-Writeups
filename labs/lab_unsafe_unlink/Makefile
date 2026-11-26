# lab_unsafe_unlink —— 自造 unsafe unlink 靶场
#
#   make          # 生成 chal
#   make clean
#
# 只用主机 gcc（glibc 2.43）：2.29+ 的 unlink 加了
#   chunksize(p) != prev_size(next) && FD->bk != P || BK->fd != P
# 两组检查，本题用「指向自己的全局指针」把它们都糊弄过去 —— 这正是
# unsafe unlink 在 2.29 之后仍然可用的原因。
# -no-pie 让 slots / handlers / win 的地址可写死在 exp 里。

CC     = gcc
CFLAGS = -O0 -g -fno-pie -no-pie -fstack-protector-strong -D_GNU_SOURCE

all: chal

chal: src/chal.c
	$(CC) $(CFLAGS) -o chal src/chal.c

clean:
	rm -f chal

.PHONY: all clean
