#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""复现性静态审计（不执行 exploit）

用途：一次性检查所有 `<模式>/<NN>_*_exp.py` 与 `labs/*/exp.py`（L1–L11）是否“随时可复现”：
  1. 脚本能否通过语法编译（compile，不落 __pycache__）
  2. 脚本引用的题目二进制是否就在同目录
  3. 脚本读取的环境变量 / 二进制名是否写进了对应 `*_speedrun.md` / `*_writeup.md`
  4. 文档是否含 bash 运行块、是否残留 TODO/待补 之类占位符

用法（先激活仓库 .venv）：
    cd '/home/yfhd5/Pwn_Writeups'
    source .venv/bin/activate
    python tools/repro_audit.py          # 文本表 + 汇总，有缺口时退出码 1
    python tools/repro_audit.py --md     # Markdown 表，可直接贴进 README
    python tools/repro_audit.py 08 19    # 只看指定题号

局限：这是“静态可复现性”检查，不判断 exploit 逻辑是否仍然成功；
实跑请按各题 `*_speedrun.md` 的本地验证段执行。
"""

import glob
import os
import re
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PLACEHOLDERS = ("TODO", "FIXME", "待补", "待定", "???")

# labs/ 下的自造靶场没有题号，用 README 里约定的 L 编号（与 verify_all.sh 的 run_case 一致）。
# 这些目录的 EXP 统一叫 exp.py，文档是 README.md，因此 audit() 需要允许覆盖。
LAB_IDS = {
    "lab_srop_baby": "L1",
    "lab_ret2syscall_i386": "L2",
    "lab_ret2dlresolve_i386": "L3",
    "lab_tcache_poisoning": "L4",
    "lab_canary_bruteforce": "L5",
    "lab_heap_uaf": "L6",
    "lab_double_free": "L7",
    "lab_fmtstr_read": "L8",
    "lab_off_by_one": "L9",
    "lab_unsafe_unlink": "L10",
    "lab_pie_partial_overwrite": "L11",
}


def rel(path: str) -> str:
    return os.path.relpath(path, ROOT)


def audit(exp: str, case_id: str = "", doc_override=None) -> dict:
    src = open(exp, encoding="utf-8", errors="replace").read()
    d = os.path.dirname(exp)

    try:
        compile(src, exp, "exec")
        compiles, compile_err = True, ""
    except SyntaxError as exc:
        compiles, compile_err = False, f"{exc.lineno}: {exc.msg}"

    bins = set(re.findall(r"\b(?:BIN|BINARY|EXE|TARGET_FILE)\s*=\s*['\"]([^'\"]+)['\"]", src))
    bins |= set(re.findall(r"['\"](\./[^'\"]+)['\"]", src))
    bins = sorted(b for b in bins if not re.search(r"\.(so|so\.\d+|txt|py)$", b))
    bins = [(b, os.path.exists(os.path.normpath(os.path.join(d, b)))) for b in bins]

    envs = set(re.findall(r"getenv\(\s*['\"](\w+)", src))
    envs |= set(re.findall(r"environ\.get\(\s*['\"](\w+)", src))
    envs |= set(re.findall(r"environ\[\s*['\"](\w+)", src))
    envs = sorted(envs)

    docs = [exp.replace("_exp.py", suffix) for suffix in ("_speedrun.md", "_writeup.md")]
    if doc_override:
        docs = list(doc_override)
    docs = [p for p in docs if os.path.exists(p)]
    text = "".join(open(p, encoding="utf-8", errors="replace").read() for p in docs)

    host = re.search(r"(?:HOST|host)\s*=\s*['\"]([a-z0-9.\-]+)['\"]", src)

    return dict(
        id=case_id or (re.search(r"/(\d\d)_", exp) or [None, "??"])[1],
        exp=rel(exp),
        compiles=compiles,
        compile_err=compile_err,
        bins=bins,
        envs=envs,
        docs=[rel(p) for p in docs],
        has_bash="```bash" in text,
        doc_missing_env=[e for e in envs if e not in text],
        doc_missing_bin=[b for b, ok in bins if ok and os.path.basename(b) not in text],
        missing_bin=[b for b, ok in bins if not ok],
        placeholders=[t for t in PLACEHOLDERS if t in text],
        doc_lines=text.count("\n"),
        hardcoded_host=bool(host) and not os.getenv("REPRO_ALLOW_HOST"),
    )


def main() -> int:
    only = {a.lstrip("0") or "0" for a in sys.argv[1:] if not a.startswith("-")}
    only |= {"L" + x for x in only if x.isdigit()}   # 允许用 6 / L6 两种写法选 lab
    md = "--md" in sys.argv
    rows = []
    cases = []          # (exp, case_id, doc_override)
    for exp in sorted(glob.glob(os.path.join(ROOT, "*", "*_exp.py"))):
        cases.append((exp, "", None))
    for exp in sorted(glob.glob(os.path.join(ROOT, "labs", "*", "exp.py"))):
        lab = os.path.basename(os.path.dirname(exp))
        cases.append((exp, LAB_IDS.get(lab, "??"),
                      [os.path.join(os.path.dirname(exp), "README.md")]))
    for exp, cid, doc_override in cases:
        if not cid:
            cid = (re.search(r"/(\d\d)_", exp) or [None, "??"])[1]
        if only and cid.lstrip("0") not in only:
            continue
        rows.append(audit(exp, cid, doc_override))

    if md:
        print("| 题 | 脚本 | 二进制（同目录） | 依赖环境变量 | 文档补齐 | 备注 |")
        print("| --- | --- | --- | --- | --- | --- |")
    else:
        print(f"{'题':>3} {'编译':^4} {'二进制':^30} {'环境变量':^28} {'bash':^4} "
              f"{'文档缺':^10} {'备注':^14}")
    gaps = 0
    warns = 0
    for r in rows:
        bins = ", ".join(b + ("" if ok else " ❌未归档") for b, ok in r["bins"]) or "—"
        miss = []
        if not r["compiles"]:
            miss.append("编译失败")
        if r["doc_missing_env"]:
            miss.append("文档缺env:" + "/".join(r["doc_missing_env"]))
        if r["doc_missing_bin"]:
            miss.append("文档缺bin名")
        if not r["has_bash"]:
            miss.append("无bash块")
        if r["placeholders"]:
            miss.append("占位符:" + "/".join(r["placeholders"]))
        if len(r["docs"]) == 0:
            miss.append("缺文档")
        note = ";".join(miss) if miss else "OK"
        if r["missing_bin"]:
            note += ";附件未归档(需自备)"
            warns += 1
        if r["hardcoded_host"]:
            note += ";远程HOST写死(靶机已下线)"
            warns += 1
        gaps += bool(miss)
        if md:
            print(f"| {r['id']} | `{os.path.basename(r['exp'])}` | {bins} | "
                  f"{', '.join(r['envs']) or '—'} | {'✅' if not miss else '⚠️'} | {note} |")
        else:
            print(f"{r['id']:>3} {('OK' if r['compiles'] else 'FAIL'):^4} {bins:^32} "
                  f"{','.join(r['envs']) or '—':^28} {('Y' if r['has_bash'] else 'N'):^4} "
                  f"{','.join(r['doc_missing_env']) or '—':^10} {note}")

    print()
    print(f"共 {len(rows)} 题；文档缺口 {gaps} 题；另有 {warns} 处“附件未归档 / 靶机下线”提示。")
    if gaps:
        print("文档缺口多为“没写 env / 没写二进制名 / 无 bash 块”，按题补文档即可。")
    return 1 if gaps else 0


if __name__ == "__main__":
    sys.exit(main())
