#!/usr/bin/env bash
# tools/verify_all.sh —— 本地实跑矩阵（每题一次 smoke test，PASS/FAIL 汇总）
#
# 用途：把仓库里的 exploit 在本地逐题跑一遍，确认“文档写的运行方式真的能跑”。
#      不做远程打靶，不依赖 BUUCTF 靶机。
#
# 用法：
#   cd '/home/yfhd5/Pwn Writeups'
#   bash tools/verify_all.sh              # 全部
#   bash tools/verify_all.sh 26 27 28     # 只跑指定题号
#
# 约定：
#   * 所有产物写到 /tmp/verify_all/<题号>.log，失败时先看这里；
#   * 本地缺 flag.txt 的题会临时创建一个，跑完删除（不污染 git status）；
#   * 缺前置（libc loader / 二进制 / 补丁版）的题直接 SKIP 并说明原因；
#   * 退出码 = FAIL 数量。
set -u

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
if need sandbox_seccomp/orw_local_exec 23 '先跑 python make_local_exec.py'; then
  run_case 23 sandbox_seccomp 'flag\{' "$PY" 23_pwnable_orw_exp.py
fi
run_case 24 sandbox_seccomp 'flag:' "$PY" 24_easyroptocol_exp.py

# ---- heap_exploitation ----
LIB227=/tmp/libc227/root/lib/x86_64-linux-gnu
if need heap_exploitation/card 26 '缺少题目二进制'; then
  if need "$LIB227/ld-2.27.so" 26 '缺 libc 2.27 loader（见 26_card_speedrun.md §6）'; then
    run_case 26 heap_exploitation 'shell ok|GOT THE FLAG' env \
      LD_SO="$LIB227/ld-2.27.so" LIBC_DIR="$LIB227" LIBC="$LIB227/libc-2.27.so" \
      "$PY" 26_card_exp.py LOCAL
  fi
fi

echo "----------------------------------------------------------------"
echo "PASS=$PASS FAIL=$FAIL SKIP=$SKIP"
[ -n "$FAILED" ] && echo "失败题号:$FAILED（日志在 $OUT/）"
exit "$FAIL"
