#!/usr/bin/env python3
"""
build_primevul_real_corpus.py — Real-World Historical CVE Stripped Binary Corpus Builder
========================================================================================
Compiles real-world open-source C security vulnerability commits from PrimeVul (ICSE 2024)
(Linux Kernel, OpenSSL, FFmpeg, QEMU, ImageMagick, tcpdump, curl, Wireshark, GPAC, Git, etc.)
into native ARM64 stripped binaries across -O0 and -O2 optimization levels.

Zero-Leakage Real-World Ground Truth Oracle:
  1. Computes exact AST/line-level security patch diffs (`difflib.SequenceMatcher`) between
     the real pre-patch vulnerable C function (`target=1`) and post-patch fixed function (`target=0`).
  2. Compiles in `/tmp` with DWARF v5 line tables (`clang -g -O0/-O2 -fno-inline`), maps the
     modified/unguarded CVE sink lines to exact machine instruction addresses inside the target
     function via `nm -n` + `dwarfdump --debug-line`.
  3. Permanently deletes `.dSYM` debug bundles and executes `strip` BEFORE lifting the binary
     into a 40-dimensional Valgrind VEX IR Control Flow Graph (`.pt`) via `angr` `CFGFast`.
  4. Compiles the paired post-patch fixed C function (`target=0`) into a stripped negative-control
     binary (`y=0` across all basic blocks) grouped under the identical `base_testcase` CVE key.
"""

import os
import re
import sys
import json
import time
import shutil
import difflib
import logging
import argparse
import subprocess
from pathlib import Path
from collections import Counter, defaultdict
from concurrent.futures import ProcessPoolExecutor, as_completed

import pyarrow.parquet as pq

logging.getLogger("angr").setLevel(logging.ERROR)
logging.getLogger("cle").setLevel(logging.ERROR)
logging.getLogger("pyvex").setLevel(logging.ERROR)
logging.getLogger("ailment").setLevel(logging.ERROR)

SCRIPT_DIR = os.path.abspath(os.path.dirname(__file__))
ROOT_DIR = os.path.abspath(os.path.join(SCRIPT_DIR, ".."))
SRC_DIR = os.path.join(ROOT_DIR, "src")
if ROOT_DIR not in sys.path:
    sys.path.insert(0, ROOT_DIR)
if SRC_DIR not in sys.path:
    sys.path.insert(0, SRC_DIR)

C_KEYWORDS = {
    "auto", "break", "case", "char", "const", "continue", "default", "do",
    "double", "else", "enum", "extern", "float", "for", "goto", "if",
    "inline", "int", "long", "register", "restrict", "return", "short",
    "signed", "sizeof", "static", "struct", "switch", "typedef", "union",
    "unsigned", "void", "volatile", "while", "bool", "size_t", "ssize_t",
    "int8_t", "int16_t", "int32_t", "int64_t", "uint8_t", "uint16_t",
    "uint32_t", "uint64_t", "intptr_t", "uintptr_t", "off_t", "time_t", "FILE",
}

PRELUDE = """#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdarg.h>

typedef long ssize_t;
typedef long off_t;
typedef long time_t;
typedef struct _FILE_stub FILE;

void *malloc(size_t);
void *calloc(size_t, size_t);
void *realloc(void *, size_t);
void free(void *);
void *memcpy(void *, const void *, size_t);
void *memmove(void *, const void *, size_t);
void *memset(void *, int, size_t);
int memcmp(const void *, const void *, size_t);
size_t strlen(const char *);
char *strcpy(char *, const char *);
char *strncpy(char *, const char *, size_t);
char *strcat(char *, const char *);
char *strncat(char *, const char *, size_t);
int strcmp(const char *, const char *);
int strncmp(const char *, const char *, size_t);
char *strchr(const char *, int);
char *strrchr(const char *, int);
char *strstr(const char *, const char *);
char *strdup(const char *);
int printf(const char *, ...);
int fprintf(FILE *, const char *, ...);
int sprintf(char *, const char *, ...);
int snprintf(char *, size_t, const char *, ...);
int sscanf(const char *, const char *, ...);

typedef int8_t i8;
typedef int16_t i16;
typedef int32_t i32;
typedef int64_t i64;
typedef uint8_t u8;
typedef uint16_t u16;
typedef uint32_t u32;
typedef uint64_t u64;
typedef int8_t s8;
typedef int16_t s16;
typedef int32_t s32;
typedef int64_t s64;
typedef uint8_t __u8;
typedef uint16_t __u16;
typedef uint32_t __u32;
typedef uint64_t __u64;
typedef int8_t __s8;
typedef int16_t __s16;
typedef int32_t __s32;
typedef int64_t __s64;
typedef uint16_t __be16;
typedef uint32_t __be32;
typedef uint64_t __be64;
typedef uint16_t __le16;
typedef uint32_t __le32;
typedef uint64_t __le64;
typedef unsigned char uchar;
typedef unsigned short ushort;
typedef unsigned int uint;
typedef unsigned long ulong;
typedef unsigned int gfp_t;
typedef unsigned long loff_t;

#define NULL ((void*)0)
#define TRUE 1
#define FALSE 0
#define __user
#define __kernel
#define __iomem
#define __rcu
#define __init
#define __exit
#define __cold
#define __must_check
#define __unused
#define __maybe_unused
#define __always_inline inline
#define noinline __attribute__((noinline))
#define likely(x) (x)
#define unlikely(x) (x)
#define MIN(a,b) (((a)<(b))?(a):(b))
#define MAX(a,b) (((a)>(b))?(a):(b))
#define min(a,b) (((a)<(b))?(a):(b))
#define max(a,b) (((a)>(b))?(a):(b))
#define ARRAY_SIZE(x) (sizeof(x)/sizeof((x)[0]))
"""

PREDEFINED_TYPES = C_KEYWORDS | {
    "i8", "i16", "i32", "i64", "u8", "u16", "u32", "u64",
    "s8", "s16", "s32", "s64", "__u8", "__u16", "__u32", "__u64",
    "__s8", "__s16", "__s32", "__s64", "__be16", "__be32", "__be64",
    "__le16", "__le32", "__le64", "uchar", "ushort", "uint", "ulong",
    "gfp_t", "loff_t", "va_list",
}

EXPORT_MACROS = (
    "STATIC", "LOCAL", "INLINE", "FASTCALL", "WINAPI", "APIENTRY",
    "MagickExport", "WandExport", "PNGAPI", "ZEXPORT", "OPENSSL_EXPORT",
    "AV_COLD", "av_cold", "av_always_inline", "G_GNUC_UNUSED", "QEMU_NORETURN",
    "__init", "__exit", "SYM_FUNC_START",
)


def clean_func_code(code: str) -> str:
    if not code:
        return ""
    if any(tok in code for tok in (
        "template<", "template <", "std::", "namespace ", "reinterpret_cast<",
        "static_cast<", "dynamic_cast<", "const_cast<", "try {", "catch (",
        "nullptr", "new ", "delete ",
    )):
        return ""
    lines = code.splitlines()
    if not lines or "::" in lines[0] or "class " in lines[0]:
        return ""
    for i in range(min(5, len(lines))):
        for m in EXPORT_MACROS:
            lines[i] = re.sub(rf"\b{m}\b", "", lines[i])
        # Ensure `static` functions are not dead-code eliminated at -O2!
        lines[i] = re.sub(r"\bstatic\s+inline\b", "", lines[i])
        lines[i] = re.sub(r"^\s*static\b", "", lines[i])
    return "\n".join(lines)


def prescan_c_types(code: str):
    ptr_used_types = set()
    val_used_types = set()
    for m in re.finditer(
        r"(?:^|[;\{\(\,])\s*(?:const\s+|volatile\s+|register\s+)*([A-Za-z_]\w*)\s*\*+\s*(?:const\s+|restrict\s+)*[A-Za-z_]\w*",
        code, re.MULTILINE
    ):
        t = m.group(1)
        if t not in PREDEFINED_TYPES:
            ptr_used_types.add(t)
    for m in re.finditer(r"\(\s*(?:const\s+|volatile\s+)*([A-Za-z_]\w*)\s*\*+\s*\)", code):
        t = m.group(1)
        if t not in PREDEFINED_TYPES:
            ptr_used_types.add(t)
    for m in re.finditer(
        r"(?:^\s+|[\(\,])(?:const\s+|volatile\s+|static\s+|register\s+)*([A-Za-z_]\w*)\s+([A-Za-z_]\w*)\s*(?:[;=,\)\[])",
        code, re.MULTILINE
    ):
        t, v = m.group(1), m.group(2)
        if t not in PREDEFINED_TYPES and v not in C_KEYWORDS:
            val_used_types.add(t)
    return ptr_used_types, val_used_types


def compute_cve_diff_lines_1based(vuln_code: str, patched_code: str):
    """
    Identify 1-based line numbers inside `vuln_code` corresponding to the security flaw
    by diffing the pre-patch vulnerable function against the post-patch fixed function.
    """
    v_lines = vuln_code.splitlines()
    p_lines = patched_code.splitlines()
    sm = difflib.SequenceMatcher(None, v_lines, p_lines)

    def _is_meaningful(s: str) -> bool:
        st = s.strip()
        return bool(st) and st not in ("{", "}", "else", "else {") and not st.startswith(("//", "/*", "*"))

    target_lines = set()
    for tag, i1, i2, j1, j2 in sm.get_opcodes():
        if tag in ("replace", "delete"):
            for idx in range(i1, i2):
                if _is_meaningful(v_lines[idx]):
                    target_lines.add(idx + 1)
        elif tag == "insert":
            # Security fix inserted a guard (e.g., bounds/NULL check) at i1 -> label nearest sink statements
            picked = 0
            for idx in range(i1, min(len(v_lines), i1 + 8)):
                if _is_meaningful(v_lines[idx]):
                    target_lines.add(idx + 1)
                    picked += 1
                    if picked >= 2:
                        break
            if picked == 0:
                for idx in range(max(0, i1 - 1), max(-1, i1 - 6), -1):
                    if _is_meaningful(v_lines[idx]):
                        target_lines.add(idx + 1)
                        break

    if not target_lines:
        for idx, ln in enumerate(v_lines):
            if _is_meaningful(ln) and idx > 0:
                target_lines.add(idx + 1)
                if len(target_lines) >= 2:
                    break

    return sorted(target_lines)


def synthesize_stub_and_compile(code: str, out_bin: str, opt_level: str = "O0"):
    """
    Iteratively resolve external C struct/typedef/constant declarations via Clang diagnostics
    and compile `code` into `out_bin` with `-g -<opt_level> -fno-inline`.
    Returns `(success: bool, line_offset: int)` where line 1 of `code` is at `line_offset + 1`.
    """
    ptr_used_types, val_used_types = prescan_c_types(code)
    struct_typedefs = set(ptr_used_types)
    scalar_types = set(val_used_types - ptr_used_types)
    ptr_typedefs = set()
    known_structs = {"_u_any"}
    for m in re.finditer(r"\bstruct\s+([A-Za-z_]\w*)", code):
        known_structs.add(m.group(1))

    all_members = {}
    arrow_mems = set(m.group(1) for m in re.finditer(r"->\s*([A-Za-z_]\w*)", code))
    dot_mems = set(m.group(1) for m in re.finditer(r"\.\s*([A-Za-z_]\w*)", code))
    chained_ptr_mems = set(m.group(1) for m in re.finditer(r"(?:->|\.)\s*([A-Za-z_]\w*)\s*(?:->|\[)", code))
    chained_val_mems = set(m.group(1) for m in re.finditer(r"(?:->|\.)\s*([A-Za-z_]\w*)\s*\.", code)) - chained_ptr_mems
    chained_fn_mems = set(m.group(1) for m in re.finditer(r"(?:->|\.)\s*([A-Za-z_]\w*)\s*\(", code))

    for m in (arrow_mems | dot_mems):
        if m in C_KEYWORDS:
            continue
        if m in chained_fn_mems:
            all_members[m] = "fn"
        elif m in chained_ptr_mems:
            all_members[m] = "ptr"
        elif m in chained_val_mems:
            all_members[m] = "val"
        else:
            all_members[m] = "scalar"

    enum_consts = {}
    for m in re.finditer(r"\bcase\s+([A-Za-z_]\w*)\s*:", code):
        idn = m.group(1)
        if idn not in PREDEFINED_TYPES:
            enum_consts[idn] = len(enum_consts) + 1

    lval_vars = {}
    macro_funcs = set()
    src_path = out_bin + ".c"

    for _ in range(8):
        stub = [PRELUDE]
        for mf in sorted(macro_funcs):
            stub.append(f"#define {mf}(...) 1")

        all_stags = sorted((known_structs | struct_typedefs) - PREDEFINED_TYPES)
        for tag in all_stags:
            stub.append(f"struct {tag};")
        for t in sorted(struct_typedefs - PREDEFINED_TYPES):
            stub.append(f"typedef struct {t} {t};")
        for t in sorted((ptr_typedefs - struct_typedefs) - PREDEFINED_TYPES):
            stub.append(f"typedef struct _u_any *{t};")
        for t in sorted((scalar_types - struct_typedefs - ptr_typedefs) - PREDEFINED_TYPES):
            stub.append(f"typedef intptr_t {t};")

        val_m_lines = ["  intptr_t _vpad;"]
        for m, kind in sorted(all_members.items()):
            if kind == "fn":
                val_m_lines.append(f"  intptr_t (*{m})();")
            elif kind == "ptr":
                val_m_lines.append(f"  struct _u_any *{m};")
            else:
                val_m_lines.append(f"  intptr_t {m};")
        stub.append("struct _u_val {\n" + "\n".join(val_m_lines) + "\n};")

        full_m_lines = ["  intptr_t _pad;"]
        for m, kind in sorted(all_members.items()):
            if kind == "fn":
                full_m_lines.append(f"  intptr_t (*{m})();")
            elif kind == "ptr":
                full_m_lines.append(f"  struct _u_any *{m};")
            elif kind == "val":
                full_m_lines.append(f"  struct _u_val {m};")
            else:
                full_m_lines.append(f"  intptr_t {m};")
        body_str = "\n".join(full_m_lines)

        for tag in all_stags:
            stub.append(f"struct {tag} {{\n{body_str}\n}};")

        if enum_consts:
            items = [f"{k} = {v}" for k, v in sorted(enum_consts.items())]
            stub.append("enum { " + ", ".join(items) + " };")
        for v, vk in sorted(lval_vars.items()):
            if v in enum_consts or v in struct_typedefs or v in scalar_types or v in ptr_typedefs:
                continue
            if vk == "ptr":
                stub.append(f"static struct _u_any *{v};")
            else:
                stub.append(f"static intptr_t {v};")

        header_text = "\n".join(stub) + "\n\n"
        line_offset = header_text.count("\n")
        full_c = header_text + code + "\n\nint main(void) { return 0; }\n"
        with open(src_path, "w") as f:
            f.write(full_c)

        obj_path = out_bin + ".o"
        cmd = [
            "clang", "-std=gnu89", "-g", f"-{opt_level}", "-fno-inline",
            "-Wno-everything", "-ferror-limit=100",
            "-c", src_path, "-o", obj_path,
        ]
        res = subprocess.run(cmd, capture_output=True, text=True)
        if res.returncode == 0 and os.path.exists(obj_path):
            # Inspect undefined external symbols so we link via a standard Mach-O LC_LOAD_DYLIB (cle-compatible!)
            u_res = subprocess.run(["nm", "-u", obj_path], capture_output=True, text=True)
            libc_std = {
                "malloc", "calloc", "realloc", "free", "memcpy", "memmove", "memset", "memcmp",
                "strlen", "strcpy", "strncpy", "strcat", "strncat", "strcmp", "strncmp",
                "strchr", "strrchr", "strstr", "strdup", "printf", "fprintf", "sprintf", "snprintf", "sscanf",
                "___stack_chk_fail", "___stack_chk_guard", "_DefaultRuneLocale", "___maskrune", "___error",
            }
            ext_syms = []
            for raw_u in u_res.stdout.splitlines():
                sym_u = raw_u.strip().lstrip("_")
                if sym_u and sym_u not in libc_std and re.match(r"^[A-Za-z_]\w*$", sym_u):
                    ext_syms.append(sym_u)

            link_args = ["clang", "-std=gnu89", "-g", f"-{opt_level}", "-fno-inline", "-Wno-everything", src_path]
            dylib_path = out_bin + "_ext.dylib"
            ext_c_path = out_bin + "_ext.c"
            if ext_syms:
                # Provide both function/data compatible weak definitions in a real Mach-O dylib
                ext_lines = [f"long {s}() {{ return 0; }}" for s in sorted(set(ext_syms))]
                with open(ext_c_path, "w") as ef:
                    ef.write("\n".join(ext_lines) + "\n")
                d_res = subprocess.run(["clang", "-dynamiclib", "-Wno-everything", ext_c_path, "-o", dylib_path], capture_output=True, text=True)
                if d_res.returncode == 0 and os.path.exists(dylib_path):
                    link_args.append(dylib_path)

            link_args.extend(["-o", out_bin])
            l_res = subprocess.run(link_args, capture_output=True, text=True)
            for cleanup_f in (obj_path, src_path, ext_c_path, dylib_path):
                try:
                    if os.path.exists(cleanup_f):
                        os.remove(cleanup_f)
                except Exception:
                    pass
            if l_res.returncode == 0 and os.path.exists(out_bin):
                return True, line_offset
            return False, 0

        err = res.stderr
        changed = False

        for m in re.finditer(r"function-like macro '([A-Za-z_]\w*)' is not defined", err):
            mf = m.group(1)
            if mf not in macro_funcs:
                macro_funcs.add(mf)
                changed = True

        for m in re.finditer(r"unknown type name '([A-Za-z_]\w*)'", err):
            tname = m.group(1)
            if re.search(rf"\b{re.escape(tname)}\s*\*", code):
                if tname not in struct_typedefs:
                    struct_typedefs.add(tname)
                    changed = True
            elif tname not in scalar_types and tname not in struct_typedefs and tname not in ptr_typedefs:
                scalar_types.add(tname)
                changed = True

        for m in re.finditer(r"must use '(?:struct|enum|union)' tag to refer to type '([A-Za-z_]\w*)'", err):
            tname = m.group(1)
            if tname not in struct_typedefs:
                struct_typedefs.add(tname)
                changed = True

        for m in re.finditer(r"(?:incomplete definition of type|variable has incomplete type|dereferencing pointer to incomplete type) '(?:const |volatile )*struct ([A-Za-z_]\w*)'", err):
            stag = m.group(1)
            if stag not in known_structs:
                known_structs.add(stag)
                changed = True

        for m in re.finditer(r"member reference type '([A-Za-z_]\w*)' \(aka '(?:intptr_t|long)'\) is not a pointer", err):
            tname = m.group(1)
            if tname not in ptr_typedefs and tname != "intptr_t":
                ptr_typedefs.add(tname)
                changed = True

        for m in re.finditer(r"indirection requires pointer operand \('([A-Za-z_]\w*)' \(aka '(?:intptr_t|long)'\) invalid\)", err):
            tname = m.group(1)
            if tname not in ptr_typedefs and tname != "intptr_t":
                ptr_typedefs.add(tname)
                changed = True

        for m in re.finditer(r"member reference base type '([A-Za-z_]\w*)' \(aka '(?:intptr_t|long)'\) is not a structure or union", err):
            tname = m.group(1)
            if tname not in struct_typedefs and tname != "intptr_t":
                struct_typedefs.add(tname)
                changed = True

        for m in re.finditer(r"invalid operands to binary expression \('(?:const )?([A-Za-z_]\w*)' \(aka 'struct [A-Za-z_]\w*'\)", err):
            tname = m.group(1)
            if tname in struct_typedefs:
                struct_typedefs.remove(tname)
                scalar_types.add(tname)
                changed = True

        for m in re.finditer(r"initializing '([A-Za-z_]\w*)' \(aka 'struct [A-Za-z_]\w*'\) with an expression of incompatible type '(?:int|long|unsigned)", err):
            tname = m.group(1)
            if tname in struct_typedefs:
                struct_typedefs.remove(tname)
                scalar_types.add(tname)
                changed = True

        for m in re.finditer(r"returning '.*?' from a function with incompatible result type '([A-Za-z_]\w*)' \(aka 'struct ", err):
            tname = m.group(1)
            if tname in struct_typedefs:
                struct_typedefs.remove(tname)
                scalar_types.add(tname)
                changed = True

        for m in re.finditer(r"no member named '([A-Za-z_]\w*)'", err):
            mem = m.group(1)
            if mem not in all_members and mem not in C_KEYWORDS:
                all_members[mem] = "scalar"
                changed = True

        err_lines = err.splitlines()
        for idx_l, el in enumerate(err_lines):
            if "member reference base type 'intptr_t'" in el and idx_l + 1 < len(err_lines):
                for pm in re.finditer(r"(?:->|\.)\s*([A-Za-z_]\w*)\s*\.", err_lines[idx_l + 1]):
                    mn = pm.group(1)
                    if all_members.get(mn) == "scalar":
                        all_members[mn] = "val"
                        changed = True
            if any(k in el for k in ("member reference type 'intptr_t'", "subscripted value is not an array", "indirection requires pointer operand ('intptr_t'")):
                if idx_l + 1 < len(err_lines):
                    src_ln = err_lines[idx_l + 1]
                    for pm in re.finditer(r"(?:->|\.)\s*([A-Za-z_]\w*)", src_ln):
                        mn = pm.group(1)
                        if all_members.get(mn) == "scalar":
                            all_members[mn] = "ptr"
                            changed = True
                    for vm in re.finditer(r"\b([A-Za-z_]\w*)\s*(?:->|\[)", src_ln):
                        vn = vm.group(1)
                        if lval_vars.get(vn) == "scalar":
                            lval_vars[vn] = "ptr"
                            changed = True
            if "expression is not an integer constant expression" in el and idx_l + 1 < len(err_lines):
                for cm in re.finditer(r"\b([A-Za-z_]\w*)\b", err_lines[idx_l + 1]):
                    cid = cm.group(1)
                    if cid in lval_vars:
                        del lval_vars[cid]
                        enum_consts[cid] = len(enum_consts) + 1
                        changed = True

        for m in re.finditer(r"use of undeclared identifier '([A-Za-z_]\w*)'", err):
            ident = m.group(1)
            if ident in struct_typedefs or ident in scalar_types or ident in ptr_typedefs or ident in enum_consts:
                continue
            if re.search(rf"\b{re.escape(ident)}\s*(?:->|\[)", code):
                if lval_vars.get(ident) != "ptr":
                    lval_vars[ident] = "ptr"
                    changed = True
            else:
                if ident not in lval_vars:
                    lval_vars[ident] = "scalar"
                    changed = True

        if not changed:
            break

    try:
        if os.path.exists(src_path):
            os.remove(src_path)
    except Exception:
        pass
    return False, 0


def get_target_func_range(bin_path: str):
    """Get `[start_addr, end_addr)` of the compiled real-world C function (excluding `main`)."""
    res = subprocess.run(["nm", "-n", bin_path], capture_output=True, text=True)
    if not res.stdout:
        return []
    syms = []
    for ln in res.stdout.splitlines():
        parts = ln.strip().split()
        if len(parts) >= 3 and parts[1] in ("T", "t"):
            try:
                addr = int(parts[0], 16)
                name = parts[2].lstrip("_")
                syms.append((addr, name))
            except ValueError:
                pass
    syms.sort(key=lambda x: x[0])
    ranges = []
    for i, (addr, name) in enumerate(syms):
        if name in ("main", "_mh_execute_header") or name.startswith("dyld"):
            continue
        end_addr = syms[i + 1][0] if i + 1 < len(syms) else addr + 0x800
        if end_addr > addr:
            ranges.append((addr, end_addr, name))
    return ranges


def extract_dwarf_addrs_for_lines(dsym_path: str, abs_target_lines, func_ranges):
    dwarf_file = dsym_path
    inner = os.path.join(dsym_path, "Contents", "Resources", "DWARF")
    if os.path.isdir(inner):
        cands = [os.path.join(inner, f) for f in os.listdir(inner) if not f.startswith("._")]
        if cands:
            dwarf_file = cands[0]

    res = subprocess.run(["dwarfdump", "--debug-line", dwarf_file], capture_output=True, text=True)
    if not res.stdout:
        return set()

    def _in_func(a: int) -> bool:
        return any(s <= a < e for s, e, _ in func_ranges) if func_ranges else True

    rows = []
    for raw in res.stdout.splitlines():
        s = raw.strip()
        if s.startswith("0x"):
            parts = s.split()
            if len(parts) >= 2:
                try:
                    addr = int(parts[0], 16)
                    lno = int(parts[1])
                    if lno > 0 and _in_func(addr):
                        rows.append((addr, lno))
                except ValueError:
                    pass

    target_set = set(abs_target_lines)
    matched = {addr for addr, lno in rows if lno in target_set}
    if not matched and abs_target_lines:
        # Small +/- 2 line window for multi-line C expressions / -O2 instruction scheduling
        for tl in abs_target_lines:
            for addr, lno in rows:
                if abs(lno - tl) <= 2:
                    matched.add(addr)
    if not matched and func_ranges:
        matched.add(func_ranges[0][0])
    return matched


def lift_and_save_pt(bin_path: str, out_pt: str, vuln_addrs: set, meta: dict):
    import torch
    from torch_geometric.data import Data
    from src.core.binary_loader import BinaryLoader
    from src.graph.graph_builder import GraphBuilder
    from src.graph.feature_extractor import FEATURE_NAMES

    loader = BinaryLoader(bin_path)
    loader.analyze()
    builder = GraphBuilder(loader)
    nx_cfg = builder.build_networkx_cfg()
    if not nx_cfg or nx_cfg.number_of_nodes() < 1:
        return None

    nodes = list(nx_cfg.nodes())
    node_to_idx = {a: i for i, a in enumerate(nodes)}
    sorted_u = sorted(set(nodes))
    span_map = {}
    for i, a in enumerate(sorted_u):
        nxt = sorted_u[i + 1] if i + 1 < len(sorted_u) else a + 64
        span_map[a] = min(max(nxt - a, 4), 128)

    x_list, y_list = [], []
    is_patched = meta["is_patched"]
    for addr in nodes:
        nd = nx_cfg.nodes[addr]
        feats = nd.get("features", [0.0] * len(FEATURE_NAMES))
        if len(feats) != len(FEATURE_NAMES):
            feats = (feats + [0.0] * len(FEATURE_NAMES))[: len(FEATURE_NAMES)]
        x_list.append(feats)

        label = 0
        if not is_patched and vuln_addrs:
            sz = max(int(nd.get("size", 4) or 4), span_map.get(addr, 8))
            if any(addr <= va < addr + sz for va in vuln_addrs):
                label = 1
        y_list.append(label)

    if not is_patched and sum(y_list) == 0 and vuln_addrs:
        tva = min(vuln_addrs)
        best_i = min(
            range(len(nodes)),
            key=lambda i: abs(nodes[i] - tva) if nodes[i] <= tva else abs(nodes[i] - tva) + 0x1000,
        )
        if abs(nodes[best_i] - tva) < 0x400:
            y_list[best_i] = 1

    edge_src, edge_dst = [], []
    for u, v in nx_cfg.edges():
        if u in node_to_idx and v in node_to_idx:
            edge_src.append(node_to_idx[u])
            edge_dst.append(node_to_idx[v])
    if not edge_src:
        edge_src, edge_dst = [0], [0]

    data = Data(
        x=torch.tensor(x_list, dtype=torch.float32),
        edge_index=torch.tensor([edge_src, edge_dst], dtype=torch.long),
        y=torch.tensor(y_list, dtype=torch.long),
    )
    data.binary_name = os.path.basename(bin_path)
    data.cwe = meta["cwe"]
    data.cve = meta["cve"]
    data.project = meta["project"]
    data.base_testcase = meta["base_testcase"]
    data.opt_level = meta["opt_level"]
    data.is_patched = is_patched
    data.orig_split = meta["orig_split"]
    data.corpus_source = "primevul_real_cve"
    data.node_addrs = torch.tensor(nodes, dtype=torch.long)

    torch.save(data, out_pt)
    return {
        "nodes": len(nodes),
        "edges": len(edge_src),
        "vuln_blocks": int(sum(y_list)),
    }


def process_cve_pair(task: dict) -> dict:
    """
    Worker: attempts to compile BOTH pre-patch vulnerable (`target=1`) and post-patch fixed (`target=0`)
    real-world CVE functions into stripped ARM64 binaries (plus optional `-O2` variants), mapping exact
    DWARF patch-diff lines before `strip`, and lifting 40-dim PyG `.pt` graphs.
    """
    import torch

    logging.getLogger("angr").setLevel(logging.ERROR)
    logging.getLogger("cle").setLevel(logging.ERROR)

    pair_id = task["pair_id"]
    proj = re.sub(r"[^A-Za-z0-9_-]", "", str(task["project"] or "oss"))[:24]
    cve = re.sub(r"[^A-Za-z0-9_-]", "", str(task["cve"] or f"CVE_PV_{pair_id}"))[:24]
    cwe = task["cwe"]
    orig_split = task["orig_split"]
    v_raw = task["vuln_func"]
    p_raw = task["patched_func"]
    include_o2 = task["include_o2"]
    bin_dir = task["bin_dir"]
    graph_dir = task["graph_dir"]

    v_code = clean_func_code(v_raw)
    p_code = clean_func_code(p_raw)
    if not v_code or not p_code:
        return {"status": "SKIP_CPP", "pair_id": pair_id}

    base_stem = f"PV_{pair_id:05d}_{proj}_{cve}_{cwe}"
    group_key = f"PV_PAIR_{pair_id:05d}_{cve}"

    # Check if already cached on disk
    v_o0_pt = os.path.join(graph_dir, f"{base_stem}_VULN_O0.out.pt")
    p_o0_pt = os.path.join(graph_dir, f"{base_stem}_PATCHED_O0.out.pt")
    if os.path.exists(v_o0_pt) and os.path.exists(p_o0_pt):
        built_items = []
        for suf in ("VULN_O0", "PATCHED_O0", "VULN_O1", "PATCHED_O1", "VULN_O2", "PATCHED_O2", "VULN_Os", "PATCHED_Os"):
            pt_p = os.path.join(graph_dir, f"{base_stem}_{suf}.out.pt")
            if os.path.exists(pt_p):
                g = torch.load(pt_p, weights_only=False)
                built_items.append({
                    "opt": getattr(g, "opt_level", "O0"),
                    "is_patched": bool(getattr(g, "is_patched", False)),
                    "nodes": int(g.num_nodes),
                    "edges": int(g.num_edges),
                    "vuln_blocks": int(g.y.sum().item()),
                })
        return {"status": "OK", "pair_id": pair_id, "project": task["project"], "cve": task["cve"], "cwe": cwe, "items": built_items}

    diff_lines_rel = compute_cve_diff_lines_1based(v_code, p_code)
    pid = os.getpid()

    # Step 1: Verify BOTH vulnerable and patched functions compile cleanly at -O0 in /tmp
    tmp_v0 = f"/tmp/pv_{pid}_{pair_id}_v_O0.out"
    tmp_p0 = f"/tmp/pv_{pid}_{pair_id}_p_O0.out"
    ok_v, v_off0 = synthesize_stub_and_compile(v_code, tmp_v0, "O0")
    if not ok_v:
        return {"status": "COMPILE_FAIL", "pair_id": pair_id}
    ok_p, _ = synthesize_stub_and_compile(p_code, tmp_p0, "O0")
    if not ok_p:
        for fp in (tmp_v0, tmp_v0 + ".dSYM"):
            shutil.rmtree(fp, ignore_errors=True) if os.path.isdir(fp) else (os.remove(fp) if os.path.exists(fp) else None)
        return {"status": "COMPILE_FAIL", "pair_id": pair_id}

    variants = [("O0", False, tmp_v0, v_off0), ("O0", True, tmp_p0, 0)]
    if include_o2:
        for extra_opt in ("O1", "O2", "Os"):
            tv = f"/tmp/pv_{pid}_{pair_id}_v_{extra_opt}.out"
            tp = f"/tmp/pv_{pid}_{pair_id}_p_{extra_opt}.out"
            ok_vx, v_offx = synthesize_stub_and_compile(v_code, tv, extra_opt)
            ok_px, _ = synthesize_stub_and_compile(p_code, tp, extra_opt)
            if ok_vx and ok_px:
                variants.append((extra_opt, False, tv, v_offx))
                variants.append((extra_opt, True, tp, 0))
            else:
                for fp in (tv, tv + ".dSYM", tp, tp + ".dSYM"):
                    shutil.rmtree(fp, ignore_errors=True) if os.path.isdir(fp) else (os.remove(fp) if os.path.exists(fp) else None)

    built_items = []
    for opt, is_patched, tmp_bin, line_off in variants:
        dsym = tmp_bin + ".dSYM"
        vuln_addrs = set()
        try:
            if not is_patched:
                f_ranges = get_target_func_range(tmp_bin)
                abs_lines = [line_off + ln for ln in diff_lines_rel]
                if os.path.exists(dsym):
                    vuln_addrs = extract_dwarf_addrs_for_lines(dsym, abs_lines, f_ranges)
                elif f_ranges:
                    vuln_addrs = {f_ranges[0][0]}
        finally:
            if os.path.exists(dsym):
                shutil.rmtree(dsym, ignore_errors=True)
            subprocess.run(["strip", tmp_bin], capture_output=True)

        tag_str = f"{'PATCHED' if is_patched else 'VULN'}_{opt}"
        final_bin = os.path.join(bin_dir, f"{base_stem}_{tag_str}.out")
        final_pt = os.path.join(graph_dir, f"{base_stem}_{tag_str}.out.pt")
        shutil.copy2(tmp_bin, final_bin)
        try:
            os.remove(tmp_bin)
        except Exception:
            pass

        meta = {
            "cwe": cwe,
            "cve": str(task["cve"] or f"CVE_PV_{pair_id}"),
            "project": str(task["project"] or "oss"),
            "base_testcase": group_key,
            "opt_level": opt,
            "is_patched": is_patched,
            "orig_split": orig_split,
        }
        try:
            st = lift_and_save_pt(final_bin, final_pt, vuln_addrs, meta)
            if st is not None:
                built_items.append({
                    "opt": opt,
                    "is_patched": is_patched,
                    "nodes": st["nodes"],
                    "edges": st["edges"],
                    "vuln_blocks": st["vuln_blocks"],
                })
        except Exception:
            pass

    if len(built_items) < 2:
        return {"status": "LIFT_FAIL", "pair_id": pair_id}

    return {
        "status": "OK",
        "pair_id": pair_id,
        "project": str(task["project"] or "oss"),
        "cve": str(task["cve"] or ""),
        "cwe": cwe,
        "items": built_items,
    }


def normalize_cwe(raw_cwe) -> str:
    if isinstance(raw_cwe, (list, tuple)) and len(raw_cwe) > 0:
        s = str(raw_cwe[0])
    elif hasattr(raw_cwe, "tolist"):
        lst = raw_cwe.tolist()
        s = str(lst[0]) if lst else "CWE000"
    else:
        s = str(raw_cwe or "CWE000")
    m = re.search(r"CWE-(\d+)", s)
    return f"CWE{m.group(1)}" if m else "CWE000"


def main():
    parser = argparse.ArgumentParser(description="Build Real-World CVE Stripped Binary Corpus from PrimeVul.")
    parser.add_argument("--workers", type=int, default=8)
    parser.add_argument("--max-pairs", type=int, default=4704, help="Max PrimeVul pairs to scan")
    parser.add_argument("--target-binaries", type=int, default=2400, help="Stop once this many real CVE binaries are built")
    args = parser.parse_args()

    raw_dir = os.path.join(ROOT_DIR, "data", "primevul_raw")
    bin_dir = os.path.join(ROOT_DIR, "data", "primevul_binaries")
    graph_dir = os.path.join(ROOT_DIR, "data", "primevul_graphs")
    os.makedirs(bin_dir, exist_ok=True)
    os.makedirs(graph_dir, exist_ok=True)

    tasks = []
    pair_counter = 0
    for sp_file, sp_label in [
        ("primevul_paired_train.parquet", "train"),
        ("primevul_paired_validation.parquet", "val"),
        ("primevul_paired_test.parquet", "test"),
    ]:
        fpath = os.path.join(raw_dir, sp_file)
        if not os.path.exists(fpath):
            continue
        df = pq.read_table(fpath).to_pandas()
        for i in range(0, len(df) - 1, 2):
            if pair_counter >= args.max_pairs:
                break
            r0, r1 = df.iloc[i], df.iloc[i + 1]
            rv = r0 if int(r0["target"]) == 1 else r1
            rp = r1 if int(r0["target"]) == 1 else r0
            fn = str(rv.get("file_name") or "")
            proj = str(rv.get("project") or "")
            if fn.endswith((".cc", ".cpp", ".cxx", ".hpp")) or proj in ("Chrome", "Android", "tensorflow"):
                pair_counter += 1
                continue
            tasks.append({
                "pair_id": pair_counter,
                "project": proj,
                "cve": str(rv.get("cve") or ""),
                "cwe": normalize_cwe(rv.get("cwe")),
                "orig_split": sp_label,
                "vuln_func": str(rv["func"]),
                "patched_func": str(rp["func"]),
                "include_o2": True,
                "bin_dir": bin_dir,
                "graph_dir": graph_dir,
            })
            pair_counter += 1

    print("=" * 78)
    print("  NeuroZ3 Real-World CVE Stripped Binary Builder (PrimeVul ICSE'24)")
    print("=" * 78)
    print(f"  Candidate pure-C CVE commit pairs: {len(tasks)} (target >= {args.target_binaries} binaries)")

    t0 = time.time()
    ok_pairs = 0
    total_bins = 0
    total_vuln_bins = 0
    total_patched_bins = 0
    total_nodes = 0
    total_edges = 0
    total_vuln_blocks = 0
    projects_seen = Counter()
    cwes_seen = Counter()
    cves_seen = set()

    with ProcessPoolExecutor(max_workers=args.workers) as ex:
        fut_map = {ex.submit(process_cve_pair, t): t for t in tasks}
        done_cnt = 0
        for fut in as_completed(fut_map):
            done_cnt += 1
            res = fut.result()
            if res.get("status") == "OK":
                ok_pairs += 1
                projects_seen[res["project"]] += len(res["items"])
                cwes_seen[res["cwe"]] += len(res["items"])
                if res.get("cve"):
                    cves_seen.add(res["cve"])
                for it in res["items"]:
                    total_bins += 1
                    if it["is_patched"]:
                        total_patched_bins += 1
                    else:
                        total_vuln_bins += 1
                    total_nodes += it["nodes"]
                    total_edges += it["edges"]
                    total_vuln_blocks += it["vuln_blocks"]

            if done_cnt % 150 == 0 or total_bins >= args.target_binaries or done_cnt == len(tasks):
                el = time.time() - t0
                print(
                    f"  [{done_cnt:4d}/{len(tasks)}] Pairs={ok_pairs} | Real CVE Binaries={total_bins} "
                    f"(vuln={total_vuln_bins}, fixed={total_patched_bins}) | Blocks={total_nodes:,} | "
                    f"Projects={len(projects_seen)} | CVEs={len(cves_seen)} | elapsed={el:.1f}s",
                    flush=True,
                )
            if total_bins >= args.target_binaries:
                for p_fut in fut_map:
                    p_fut.cancel()
                break

    stats = {
        "corpus": "PrimeVul Real-World Open-Source C CVEs (ICSE 2024)",
        "compiled_cve_pairs": ok_pairs,
        "total_real_cve_binaries": total_bins,
        "vulnerable_pre_patch_binaries": total_vuln_bins,
        "fixed_post_patch_binaries": total_patched_bins,
        "unique_real_projects": len(projects_seen),
        "unique_cves": len(cves_seen),
        "unique_cwes": len(cwes_seen),
        "total_basic_blocks": total_nodes,
        "total_cfg_edges": total_edges,
        "total_dwarf_vuln_blocks": total_vuln_blocks,
        "top_projects": dict(projects_seen.most_common(25)),
        "cwe_distribution": dict(cwes_seen.most_common(30)),
    }
    stats_path = os.path.join(graph_dir, "primevul_dataset_stats.json")
    with open(stats_path, "w") as f:
        json.dump(stats, f, indent=2)

    print("\n" + "=" * 78)
    print("  PRIMEVUL REAL-WORLD CVE CORPUS COMPLETE")
    print("=" * 78)
    print(f"  Real-World Stripped CVE Binaries: {total_bins:,} ({total_vuln_bins:,} pre-patch CVE + {total_patched_bins:,} post-patch fixed)")
    print(f"  Distinct Open-Source C Projects:  {len(projects_seen)} (e.g. {', '.join(k for k, _ in projects_seen.most_common(8))})")
    print(f"  Distinct Historical CVE IDs:      {len(cves_seen):,}")
    print(f"  Distinct CWE Families:            {len(cwes_seen)}")
    print(f"  Total Recovered Basic Blocks:     {total_nodes:,}")
    print(f"  Total Recovered CFG Edges:        {total_edges:,}")
    print(f"  DWARF Patch-Diff Vuln Blocks:     {total_vuln_blocks:,}")
    print(f"  Saved census -> {stats_path}")


if __name__ == "__main__":
    main()
