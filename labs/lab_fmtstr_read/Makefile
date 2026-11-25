# lab_fmtstr_read —— 自造格式化字符串“读”靶场
#
#   make          # 生成 chal
#   make clean
#
# -no-pie：secret[] / GOT 地址固定，EXP 直接取符号；
# -fstack-protector-strong：留出 canary 供 %p 扫描演示（本题没有栈溢出，canary 只是素材）。

CC     = gcc
CFLAGS = -O0 -g -fno-pie -no-pie -fstack-protector-strong -D_GNU_SOURCE

all: chal

chal: src/chal.c
	$(CC) $(CFLAGS) -o chal src/chal.c

clean:
	rm -f chal

.PHONY: all clean
