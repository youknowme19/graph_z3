"""
fix_advisor.py  —  LLM-powered (Gemini) vulnerability fix advisor.

For each vulnerability found by scan_vulnerabilities(), this module:
  1. Walks back through nearby basic blocks to detect the specific unsafe call
  2. Sends vulnerability context to Google Gemini for a structured fix suggestion
  3. Falls back to rule-based templates if no API key is configured

Environment variable: GEMINI_API_KEY  (or GOOGLE_API_KEY)
"""

from __future__ import annotations

import json
import os
import re
from typing import Any, Dict, List, Optional

# ---------------------------------------------------------------------------
# LLM prompt
# ---------------------------------------------------------------------------

_PROMPT = """\
You are a senior binary security engineer. A Z3 symbolic execution tool has
mathematically proven that the following vulnerability is reachable.

=== VULNERABILITY ===
Type      : {vuln_type}
Severity  : {vuln_severity}
Address   : {address}
Function  : {function_name}
Details   : {vuln_details}

=== Z3-SOLVED CRASH INPUT ===
{exploit_summary}

=== NEARBY DISASSEMBLY (crash site) ===
{disasm}

=== TASK ===
Provide a precise, actionable fix recommendation.
Respond ONLY with a single valid JSON object - no markdown fences, no extra text.

{{
  "summary": "One-sentence fix",
  "cwe": "CWE-XXX: Name",
  "unsafe_pattern": "Specific unsafe call or pattern found",
  "safe_alternative": "Exact safer replacement",
  "steps": ["Step 1", "Step 2", "Step 3"],
  "before": "Minimal pseudocode showing the vulnerable pattern",
  "after": "Minimal pseudocode showing the fixed version",
  "prevention": "General rule to prevent this class of bug"
}}
"""

# ---------------------------------------------------------------------------
# Rule-based fallback templates
# ---------------------------------------------------------------------------

_RULES: Dict[str, Dict] = {
    # ── Stack / control-flow ──────────────────────────────────────────────────
    "CANARY": {
        "summary": "Stack buffer overflow — replace unbounded string ops with bounded variants.",
        "cwe": "CWE-121: Stack-based Buffer Overflow",
        "unsafe_pattern": "strcpy / strcat / gets / sprintf (no length limit)",
        "safe_alternative": "strncpy(dst, src, sizeof(dst)-1) + explicit null-termination",
        "steps": [
            "Find the overflowed buffer and its declared byte size.",
            "Replace strcpy→strncpy, strcat→strncat, gets→fgets, sprintf→snprintf.",
            "Explicitly null-terminate after every bounded copy.",
            "Validate input length before any copy: if (len >= sizeof(buf)) { reject(); }",
            "Compile with -fstack-protector-all -D_FORTIFY_SOURCE=2.",
        ],
        "before": 'char buf[32];\nstrcpy(buf, user_input);  // no bounds check',
        "after": 'char buf[32];\nstrncpy(buf, user_input, sizeof(buf) - 1);\nbuf[sizeof(buf) - 1] = \'\\0\';',
        "prevention": "Never copy external data into a fixed buffer without enforcing a length limit.",
    },
    "STACK_OVERFLOW": {
        "summary": "Stack buffer overflow — the stack frame boundary is overwritten by user-controlled data.",
        "cwe": "CWE-121: Stack-based Buffer Overflow",
        "unsafe_pattern": "memcpy / strcpy / read() writing past stack buffer end",
        "safe_alternative": "Bounded copy with explicit length check before every write",
        "steps": [
            "Identify the stack-allocated buffer and its declared byte size.",
            "Add: if (user_len > sizeof(buf)) { return -EINVAL; } before every copy.",
            "Replace strcpy→strncpy, gets→fgets, sprintf→snprintf.",
            "Compile with -fstack-protector-all -D_FORTIFY_SOURCE=2.",
            "Enable AddressSanitizer (-fsanitize=address) in CI.",
        ],
        "before": "char buf[8];\nmemcpy(buf, user_data, 32);  // overflows stack frame",
        "after": "char buf[8];\nif (user_len > sizeof(buf)) { return -EINVAL; }\nmemcpy(buf, user_data, user_len);",
        "prevention": "Treat all size values from external sources as untrusted; validate before any copy.",
    },
    "SYMBOLIC_PC": {
        "summary": "Control-flow hijack — the instruction pointer is attacker-controlled.",
        "cwe": "CWE-822: Untrusted Pointer Dereference",
        "unsafe_pattern": "Function pointer or return address derived from user input",
        "safe_alternative": "Allow-list validation of code pointers; enable CFI",
        "steps": [
            "Trace the symbolic value back to its source in user input.",
            "Validate against a strict allow-list before using as a code pointer.",
            "Enable Control-Flow Integrity (-fsanitize=cfi with LTO).",
            "Compile as PIE + enable ASLR (-pie -fPIE).",
            "Enable full RELRO (-Wl,-z,relro,-z,now) to protect GOT/PLT.",
        ],
        "before": "void (*fn)(void) = (void*)user_value;\nfn();  // attacker controls target",
        "after": "if (!in_allowlist(user_value)) { abort(); }\nvoid (*fn)(void) = (void*)user_value;\nfn();",
        "prevention": "Never use external data as a code pointer without allow-list validation.",
    },
    # ── Heap memory safety ────────────────────────────────────────────────────
    "NULL_DEREF": {
        "summary": "Null pointer dereference — pointer is not validated before use.",
        "cwe": "CWE-476: NULL Pointer Dereference",
        "unsafe_pattern": "Pointer used without null check after malloc/function call",
        "safe_alternative": "Validate every pointer is non-null before dereferencing",
        "steps": [
            "Find every allocation or function call that can return NULL.",
            "Add: if (ptr == NULL) { handle_error(); return -ENOMEM; }",
            "Apply the check before every dereference of the pointer.",
            "Use static analysis (clang-tidy, cppcheck) to find all missing null checks.",
        ],
        "before": "int *p = malloc(sizeof(int));\n*p = 42;  // crash if malloc returned NULL",
        "after": "int *p = malloc(sizeof(int));\nif (!p) { return -ENOMEM; }\n*p = 42;",
        "prevention": "Assume every pointer-returning function can fail; always check before use.",
    },
    "OOB_WRITE": {
        "summary": "Out-of-bounds write — memory write exceeds the allocated object boundary.",
        "cwe": "CWE-787: Out-of-bounds Write",
        "unsafe_pattern": "memcpy / array indexing without length validation",
        "safe_alternative": "Explicit length check before every memory write operation",
        "steps": [
            "Identify the allocated buffer size.",
            "Before every write: assert(offset + length <= sizeof(buffer)).",
            "Use safe wrappers: strlcpy instead of strcpy, snprintf instead of sprintf.",
            "Enable AddressSanitizer (-fsanitize=address) in CI.",
            "Consider bounds-checked container types where possible.",
        ],
        "before": "char *buf = malloc(8);\nmemcpy(buf, user_data, user_len);  // user controls length",
        "after": "char *buf = malloc(8);\nif (user_len > 8) { return -EINVAL; }\nmemcpy(buf, user_data, user_len);",
        "prevention": "Never use a user-controlled value as a copy length without validating it first.",
    },
    "OOB_READ": {
        "summary": "Out-of-bounds read — memory read beyond the allocated object boundary leaks data.",
        "cwe": "CWE-125: Out-of-bounds Read",
        "unsafe_pattern": "Array or pointer read with user-controlled offset",
        "safe_alternative": "Validate read offset is within [0, object_size) before every read",
        "steps": [
            "Identify all reads where the index or offset is user-supplied.",
            "Add: if (offset >= object_size) { return -ERANGE; }",
            "Use bounded APIs that enforce limits.",
            "Enable AddressSanitizer (-fsanitize=address) in CI.",
        ],
        "before": "char val = buf[user_index];  // no bounds check",
        "after": "if (user_index >= buf_size) { return -ERANGE; }\nchar val = buf[user_index];",
        "prevention": "Validate all user-controlled indices before memory reads.",
    },
    "USE_AFTER_FREE": {
        "summary": "Use-after-free — a freed heap object is accessed, enabling heap corruption or RCE.",
        "cwe": "CWE-416: Use After Free",
        "unsafe_pattern": "Pointer used after free() without setting to NULL",
        "safe_alternative": "Set pointer to NULL immediately after free(); check before use",
        "steps": [
            "Locate every free() call and immediately set the pointer to NULL: free(p); p = NULL;",
            "Audit all code paths between the free() and any subsequent dereference.",
            "Use smart pointers (C++) or ownership models to enforce lifetime semantics.",
            "Enable AddressSanitizer + LeakSanitizer (-fsanitize=address,leak) in CI.",
            "Consider using a memory-safe allocator (jemalloc with hardening) in production.",
        ],
        "before": "free(buf);\nbuf[0] = 'x';  // UAF — heap is now corrupted",
        "after": "free(buf);\nbuf = NULL;\n// never access buf again after this point",
        "prevention": "Enforce single-owner semantics; always null freed pointers immediately.",
    },
    "DOUBLE_FREE": {
        "summary": "Double free — freeing the same pointer twice corrupts the heap allocator.",
        "cwe": "CWE-415: Double Free",
        "unsafe_pattern": "free() called twice on the same pointer without nulling it",
        "safe_alternative": "Set pointer to NULL after every free(); guard free() with a null check",
        "steps": [
            "After every free(p), immediately set p = NULL.",
            "Before every free(p), add: if (p == NULL) { return; }",
            "Audit all error-handling code paths for duplicate free().",
            "Enable AddressSanitizer (-fsanitize=address) which catches double-free at runtime.",
        ],
        "before": "free(buf);\n// ... error path ...\nfree(buf);  // double free — undefined behavior",
        "after": "free(buf);\nbuf = NULL;\n// ... error path ...\nif (buf) { free(buf); buf = NULL; }",
        "prevention": "A pointer that has been freed must never be freed again; null it on first free.",
    },
    "INTEGER_OVERFLOW": {
        "summary": "Integer overflow — arithmetic wraps around and produces an incorrect allocation size.",
        "cwe": "CWE-190: Integer Overflow or Wraparound",
        "unsafe_pattern": "Multiplication or addition of user-controlled values used as allocation size",
        "safe_alternative": "Use overflow-checked arithmetic before computing allocation sizes",
        "steps": [
            "Identify every multiplication/addition that feeds into malloc/calloc/realloc.",
            "Use safe integer helpers: if (__builtin_mul_overflow(a, b, &result)) { return -EOVERFLOW; }",
            "Cap all user-supplied size values to a reasonable maximum before arithmetic.",
            "Use calloc(n, size) instead of malloc(n * size) when allocating arrays.",
        ],
        "before": "size_t total = user_n * user_size;  // wraps if large\nchar *buf = malloc(total);",
        "after": "if (user_size && user_n > SIZE_MAX / user_size) { return -EOVERFLOW; }\nsize_t total = user_n * user_size;\nchar *buf = malloc(total);",
        "prevention": "Treat all size computations involving user input as untrusted arithmetic.",
    },
    "INVALID_FREE": {
        "summary": "Invalid free — freeing a pointer that was not returned by the allocator.",
        "cwe": "CWE-590: Free of Memory Not on the Heap",
        "unsafe_pattern": "free() called on a stack pointer, global, or mid-buffer pointer",
        "safe_alternative": "Only free() pointers returned directly by malloc/calloc/realloc",
        "steps": [
            "Audit all free() calls to ensure the pointer originated from a heap allocator.",
            "Never call free() on: stack variables, global arrays, or pointer arithmetic results.",
            "Use static analysis to track pointer provenance.",
        ],
        "before": "char buf[16];\nfree(buf);  // stack — undefined behavior",
        "after": "char *buf = malloc(16);\nif (buf) { /* use */ free(buf); buf = NULL; }",
        "prevention": "Only pass heap-allocated pointers to free(); never free stack or global memory.",
    },
    # ── Generic ───────────────────────────────────────────────────────────────
    "OVERFLOW": {
        "summary": "Out-of-bounds memory access — validate all lengths before memory operations.",
        "cwe": "CWE-119: Improper Restriction of Operations within Buffer Bounds",
        "unsafe_pattern": "memcpy / read / write without length validation",
        "safe_alternative": "Explicit length check before every memory operation",
        "steps": [
            "Identify the buffer declared byte size.",
            "Before every write: check offset + length <= sizeof(buffer).",
            "Return an error code instead of proceeding with invalid lengths.",
            "Enable AddressSanitizer (-fsanitize=address) during testing.",
        ],
        "before": "memcpy(dst, src, user_len);  // user controls length",
        "after": "if (user_len > sizeof(dst)) { return -EINVAL; }\nmemcpy(dst, src, user_len);",
        "prevention": "Treat all size values from external sources as untrusted.",
    },
    "WRITE_WHAT_WHERE": {
        "summary": "Arbitrary write primitive — destination address is attacker-controlled.",
        "cwe": "CWE-123: Write-what-where Condition",
        "unsafe_pattern": "Memory store with symbolic destination address",
        "safe_alternative": "Use offset-from-validated-base patterns",
        "steps": [
            "Identify where the write destination comes from.",
