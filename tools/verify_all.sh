#!/usr/bin/env bash
# tools/verify_all.sh —— 本地实跑矩阵（每题一次 smoke test，PASS/FAIL 汇总）
#
# 用途：把仓库里的 exploit 在本地逐题跑一遍，确认“文档写的运行方式真的能跑”。
#      不做远程打靶，不依赖 BUUCTF 靶机。
#
# 用法：
#   cd '/home/yfhd5/Pwn_Writeups'
#   bash tools/verify_all.sh              # 全部
#   bash tools/verify_all.sh 26 27 28     # 只跑指定题号
#
# 约定：
#   * 所有产物写到 /tmp/verify_all/<题号>.log，失败时先看这里；
#   * 本地缺 flag.txt 的题会临时创建一个，跑完删除（不污染 git status）；
#   * 缺前置（libc loader / 二进制 / 补丁版）的题直接 SKIP 并说明原因；
#   * 退出码 = FAIL 数量。
set -u

# 不产生 core 文件：exploit 正常收尾时常常故意跳到一个垃圾返回地址（例如
# ret2dlresolve 链的 0xdeadbeef），会在题目目录里堆一大堆 core.*。
ulimit -c 0 2>/dev/null || true

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUT=/tmp/verify_all
mkdir -p "$OUT"
cd "$ROOT" || exit 1

PY=python
if [ -x "$ROOT/.venv/bin/python" ]; then
  # shellcheck disable=SC1091
  source "$ROOT/.venv/bin/activate"
  PY="$ROOT/.venv/bin/python"
fi

WANT=("$@")
want() {
  [ ${#WANT[@]} -eq 0 ] && return 0
  local id
  for id in "${WANT[@]}"; do [ "$id" = "$1" ] && return 0; done
  return 1
}

PASS=0; FAIL=0; SKIP=0
FAILED=""

# run_case <题号> <目录> <成功正则> <命令...>
run_case() {
  local id="$1" dir="$2" pat="$3"; shift 3
  want "$id" || return 0
  printf '%-4s %-22s ' "$id" "$dir"
  ( cd "$dir" && "$@" ) > "$OUT/$id.log" 2>&1
  if grep -qE "$pat" "$OUT/$id.log"; then
    echo "PASS  ($OUT/$id.log)"; PASS=$((PASS+1))
  else
    echo "FAIL  ($OUT/$id.log)"; FAIL=$((FAIL+1)); FAILED="$FAILED $id"
  fi
}

# need_file <路径> <题号> <原因>
need() {
  want "$2" || return 1          # 被题号过滤掉的题不打印 SKIP
  [ -e "$1" ] && return 0
  echo "$2    SKIP  ($3: 缺 $1)"; SKIP=$((SKIP+1)); return 1
}

# 临时 flag.txt：仅当仓库里本来没有时创建，跑完删除
TMPFLAGS=()
mk_flag() {  # mk_flag <目录> <内容>
  [ -e "$1/flag.txt" ] && return 0
  printf '%s\n' "$2" > "$1/flag.txt"
  TMPFLAGS+=("$1/flag.txt")
}
cleanup() {
  local f
  for f in "${TMPFLAGS[@]:-}"; do [ -n "$f" ] && rm -f "$f"; done
}
trap cleanup EXIT

echo "== 本地实跑矩阵（$(date '+%F %T')，pwntools: $("$PY" -c 'import pwn;print(pwn.version)' 2>/dev/null || echo '?')） =="

# ---- ret2text ----
mk_flag ret2text 'flag{LOCAL_SMOKE}'
run_case 05 ret2text 'GOT THE FLAG' "$PY" 05_get_started_3dsctf_2016_exp.py LOCAL
if need ret2text/jarvisoj_http 27 '缺少题目二进制'; then
  if need tools/loopback_unix_shim.so 27 '先编译: gcc -shared -fPIC -O2 -o tools/loopback_unix_shim.so tools/loopback_unix_shim.c -ldl'; then
    run_case 27 ret2text 'getshell OK' env USE_UNIX=1 SHIM="../tools/loopback_unix_shim.so" \
      HTTP_UNIX=/tmp/verify_all/http.sock "$PY" 27_jarvisoj_http_exp.py LOCAL
  fi
fi

# ---- ret2libc ----
mk_flag ret2libc 'flag{smoke12}'
run_case 12 ret2libc 'GOT THE FLAG' "$PY" 12_bjdctf_2020_babyrop_exp.py LOCAL
if need ret2libc/canary3 28 '缺少题目二进制'; then
  run_case 28 ret2libc 'shell ok' "$PY" 28_canary3_exp.py LOCAL
fi

# ---- stack_pivot ----
mk_flag stack_pivot '__PWNED__{pivot_local_ok}'
run_case 22 stack_pivot '__PWNED__' "$PY" 22_ropemporium_pivot_exp.py

# ---- sandbox_seccomp ----
mk_flag sandbox_seccomp 'flag{orw_local_ok}'
# 23 是 32 位静态 seccomp 题，本机只给 loader/libc 目录，让 EXP 用 I386_LD 启动
I386_DIR=""
for d in /tmp/libc32/root/usr/lib/i386-linux-gnu /tmp/libc32/root/usr/lib32 /tmp/libc224i32; do
  [ -x "$d/ld-linux.so.2" ] && { I386_DIR="$d"; break; }
done
if need sandbox_seccomp/orw_local_exec 23 '先跑 python make_local_exec.py'; then
  if [ -n "$I386_DIR" ]; then
    run_case 23 sandbox_seccomp 'flag\{' env \
      I386_LD="$I386_DIR/ld-linux.so.2" I386_LIBPATH="$I386_DIR" \
      "$PY" 23_pwnable_orw_exp.py
  else
    run_case 23 sandbox_seccomp 'flag\{' "$PY" 23_pwnable_orw_exp.py
  fi
fi
run_case 24 sandbox_seccomp 'flag:' "$PY" 24_easyroptocol_exp.py

# ---- heap_exploitation ----
# 2.27 环境有两种常见落地形状：deb 解包（root/lib/x86_64-linux-gnu）与扁平目录（libc227/ 下直接放）。
LIB227=""
for d in /tmp/libc227/root/lib/x86_64-linux-gnu /tmp/libc227; do
  [ -x "$d/ld-2.27.so" ] && { LIB227="$d"; break; }
done
LIB227="${LIB227:-/tmp/libc227/root/lib/x86_64-linux-gnu}"
if need heap_exploitation/card 26 '缺少题目二进制'; then
  if need "$LIB227/ld-2.27.so" 26 '缺 libc 2.27 loader（见 26_card_speedrun.md §6）'; then
    if [ "${CARD227_LEAK_OK:-0}" = "1" ]; then
      run_case 26 heap_exploitation 'shell ok|GOT THE FLAG' env \
        LD_SO="$LIB227/ld-2.27.so" LIBC_DIR="$LIB227" LIBC="$LIB227/libc-2.27.so" \
        "$PY" 26_card_exp.py LOCAL
    else
      want 26 && { echo "26    SKIP  (已知缺陷：本二进制 cards 索引上限为 8，stage-1 挡板 create(8) 不成立 → leak 取不到 main_arena；见 26_card_speedrun.md §9；确认修复后 CARD227_LEAK_OK=1 再跑)"; SKIP=$((SKIP+1)); }
    fi
  fi
fi

# ---- fsop ----
LIB224=/tmp/libc224i32
if need fsop/seethefile 29 '缺少题目二进制'; then
  if need "$LIB224/ld-linux.so.2" 29 '缺 i386 2.24 loader（见 29 的 speedrun §7）'; then
    run_case 29 fsop 'shell ok' env \
      I386_LD="$LIB224/ld-linux.so.2" I386_LIBPATH="$LIB224" \
      LIBC=../ret2libc/libc-2.24.so \
      "$PY" 29_pwnable_tw_seethefile_exp.py LOCAL
  fi
fi

# ---- ret2csu ----
# 主程序 No PIE，ret2win 在 libret2csu.so 里（RUNPATH=b'.'，EXP 自己 chdir）
run_case 30 ret2csu 'ROPE\{' "$PY" 30_ropemporium_ret2csu_exp.py LOCAL
if need ret2csu/callme_lab/callme 33 '缺少题目二进制（见 _vendor/ropemporium/）'; then
  run_case 33 ret2csu 'ROPE\{' "$PY" 33_ropemporium_callme_exp.py LOCAL
fi

# ---- rop_write_memory / badchars_encoding ----
# 两题都自带 flag.txt（官方 zip 附件），print_file 直接读它，不需要 mk_flag。
if need rop_write_memory/write4 31 '缺少题目二进制（见 _vendor/ropemporium/）'; then
  run_case 31 rop_write_memory 'ROPE\{' "$PY" 31_ropemporium_write4_exp.py LOCAL
fi
if need badchars_encoding/badchars 32 '缺少题目二进制（见 _vendor/ropemporium/）'; then
  run_case 32 badchars_encoding 'ROPE\{' "$PY" 32_ropemporium_badchars_exp.py LOCAL
fi
if need badchars_encoding/fluff 34 '缺少题目二进制（见 _vendor/ropemporium/）'; then
  run_case 34 badchars_encoding 'ROPE\{' "$PY" 34_ropemporium_fluff_exp.py LOCAL
fi


# ---- labs（自造靶场：先 make）----
if need labs/lab_ret2syscall_i386/chal L2 '先 cd labs/lab_ret2syscall_i386 && make'; then
  run_case L2 labs/lab_ret2syscall_i386 '__PWNED__' "$PY" exp.py
fi
if need labs/lab_ret2dlresolve_i386/chal L3 '先 cd labs/lab_ret2dlresolve_i386 && make'; then
  run_case L3 labs/lab_ret2dlresolve_i386 '__PWNED__' "$PY" exp.py
fi

# ---- labs 第二梯队（heap_uaf / tcache_poisoning / canary_bruteforce）----
if need labs/lab_heap_uaf/chal L6 '先 cd labs/lab_heap_uaf && make'; then
  mk_flag labs/lab_heap_uaf '__PWNED__{uaf_ok}'
  run_case L6 labs/lab_heap_uaf '__PWNED__' "$PY" exp.py
fi
if need labs/lab_tcache_poisoning/chal L4 '先 cd labs/lab_tcache_poisoning && make'; then
  mk_flag labs/lab_tcache_poisoning '__PWNED__{tcache_ok}'
  run_case L4 labs/lab_tcache_poisoning '__PWNED__' "$PY" exp.py
fi
if need labs/lab_canary_bruteforce/chal L5 '先 cd labs/lab_canary_bruteforce && make'; then
  mk_flag labs/lab_canary_bruteforce '__PWNED__{canary_ok}'
  # 逐字节爆破约 900 次 fork ≈ 20 s，别用默认的短超时
  run_case L5 labs/lab_canary_bruteforce '__PWNED__' timeout 180 "$PY" exp.py
fi

# ---- labs 第三梯队（double_free / fmtstr_read）----
if need labs/lab_double_free/chal L7 '先 cd labs/lab_double_free && make'; then
  mk_flag labs/lab_double_free '__PWNED__{dfree_ok}'
  run_case L7 labs/lab_double_free '__PWNED__' "$PY" exp.py
fi
if need labs/lab_fmtstr_read/chal L8 '先 cd labs/lab_fmtstr_read && make'; then
  mk_flag labs/lab_fmtstr_read '__PWNED__{fmt_read_ok}'
  run_case L8 labs/lab_fmtstr_read '__PWNED__' "$PY" exp.py
fi

echo "----------------------------------------------------------------"
echo "PASS=$PASS FAIL=$FAIL SKIP=$SKIP"
[ -n "$FAILED" ] && echo "失败题号:$FAILED（日志在 $OUT/）"
exit "$FAIL"
