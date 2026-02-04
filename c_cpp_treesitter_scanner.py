#!/usr/bin/env python3
"""
C/C++ AST Vulnerability Scanner (Tree-sitter)
==============================================
A standalone C/C++ security scanner using tree-sitter for AST-based analysis.
Detects memory safety issues, integer bugs, dangerous functions, and pointer/array problems.

Supported Checks:
  [MEM-UNSAFE-COPY]    Unsafe string/memory copy functions (strcpy, gets, sprintf, etc.)
  [MEM-BUFFER-OOB]     Potential buffer overflow via suspicious array indexing
  [MEM-USE-AFTER-FREE] Use-after-free heuristic (free then use in same scope)
  [MEM-DOUBLE-FREE]    Double free heuristic (free same pointer twice, no reassign)
  [MEM-RETURN-LOCAL]   Returning address of stack/local variable (direct & indirect)
  [MEM-DANGLING-PTR]   Returning pointer to stack-local struct via intermediate variable
  [MEM-NULL-DEREF]     Missing NULL check after malloc/calloc/realloc/new (incl. casts)
  [MEM-UNVALIDATED-SIZE] memcpy/memdup with size from network byte-order conversion, no bounds check
  [PTR-ARITH]          Suspicious pointer arithmetic (*(p + i) patterns)
  [PTR-OOB-INDEX]      Out-of-bounds risk: negative constant or subtraction in index
  [INT-SIGN-COMPARE]   Signed/unsigned mismatch in comparisons or loop bounds
  [INT-NARROW]         Narrowing conversion (larger type assigned to smaller type)
  [INT-OVERFLOW-ALLOC] Integer overflow risk in allocation size (malloc(a*b))
  [INT-UNDERFLOW]      Unsigned integer subtraction that may wrap (e.g., size_t a - b)
  [DANGER-EXEC]        system/popen/exec* usage
  [DANGER-FORMAT]      Format string: printf-family with non-literal format argument

Default output: Only CRITICAL severity + HIGH confidence findings are shown.
Use --all to display all findings regardless of severity/confidence.

Known False Positives / Limitations:
  - No full dataflow or inter-procedural analysis; heuristics are scope-local.
  - Use-after-free / double-free only detected within the same compound_statement.
  - Narrowing conversion checks use a static type-width table; typedefs are not resolved.
  - Pointer arithmetic flagging may fire on safe iterator patterns.
  - NULL-deref check tracks simple aliases (p = malloc; q = p) but not deeper chains.
  - signed/unsigned comparison may miss typedef'd types (e.g., ssize_t).
  - MEM-RETURN-LOCAL may false-positive when &local is passed as arg inside a return expr
    (e.g., return func(&local)); the dangling-ptr rule is more precise for indirect cases.

Requirements:
    pip install tree-sitter tree-sitter-c tree-sitter-cpp rich

Usage:
    python3 c_cpp_treesitter_scanner.py target.c
    python3 c_cpp_treesitter_scanner.py /path/to/project --ext .c,.cpp,.h,.hpp
    python3 c_cpp_treesitter_scanner.py src/ --output json -o report.json
    python3 c_cpp_treesitter_scanner.py file.cpp --jsonl

Unit-test-like examples (expected matches shown in comments):

    // MEM-UNSAFE-COPY: strcpy without bounds
    // char buf[10]; strcpy(buf, argv[1]);  -> MATCH

    // MEM-BUFFER-OOB: negative index
    // int a[10]; a[-1] = 0;  -> MATCH

    // MEM-USE-AFTER-FREE:
    // free(p); p->x = 1;  -> MATCH

    // MEM-DOUBLE-FREE:
    // free(p); ... free(p);  -> MATCH

    // MEM-RETURN-LOCAL:
    // int x; return &x;  -> MATCH

    // MEM-NULL-DEREF:
    // int *p = malloc(4); *p = 1;  -> MATCH (no NULL check)

    // INT-OVERFLOW-ALLOC:
    // malloc(n * sizeof(int));  -> MATCH (n is variable)

    // DANGER-EXEC:
    // system(cmd);  -> MATCH

    // DANGER-FORMAT:
    // printf(user_input);  -> MATCH (non-literal format)

    // INT-NARROW:
    // size_t sz = len; int narrow = sz;  -> MATCH

    // INT-SIGN-COMPARE:
    // if (len < size) ...  where len is int and size is size_t  -> heuristic MATCH

    // PTR-ARITH:
    // *(buf + offset)  -> MATCH

    // MEM-DANGLING-PTR:
    // thing_t local; thing_t* p = &local; return p;  -> MATCH

    // INT-UNDERFLOW:
    // size_t remaining = commandLength - 4;  -> MATCH (unsigned subtraction)

    // MEM-NULL-DEREF (with cast):
    // char* p = (char*)malloc(n); *p = 'x';  -> MATCH

    // MEM-UNVALIDATED-SIZE:
    // uint32_t len = ntohl(*(uint32_t*)buf);
    // memcpy(dst, src, len);  -> MATCH (no bounds check on len)
"""

import os
import sys
import json
import argparse
import re
import time
from pathlib import Path
from dataclasses import dataclass, field, asdict
from typing import List, Dict, Set, Optional, Tuple, Generator
from enum import Enum
from datetime import datetime
from collections import defaultdict

import tree_sitter_c as tsc
import tree_sitter_cpp as tscpp
from tree_sitter import Language, Parser, Node

from rich.console import Console, Group
from rich.panel import Panel
from rich.table import Table
from rich.tree import Tree
from rich.syntax import Syntax
from rich.columns import Columns
from rich.text import Text
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, MofNCompleteColumn
from rich.align import Align
from rich.rule import Rule
from rich import box

console = Console()

C_LANG = Language(tsc.language())
CPP_LANG = Language(tscpp.language())

# ============================================================================
# Enums & Data Classes
# ============================================================================

class Severity(Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"

SEVERITY_ORDER = {
    Severity.CRITICAL: 4,
    Severity.HIGH: 3,
    Severity.MEDIUM: 2,
    Severity.LOW: 1,
    Severity.INFO: 0,
}

CONFIDENCE_ORDER = {"HIGH": 3, "MEDIUM": 2, "LOW": 1}


class VulnCategory(Enum):
    MEMORY_SAFETY = "Memory Safety"
    POINTER_ARRAY = "Pointer/Array Issue"
    INTEGER_ISSUE = "Integer Issue"
    DANGEROUS_FUNCTION = "Dangerous Function"


@dataclass
class Finding:
    file_path: str
    line_number: int
    col_offset: int
    line_content: str
    vulnerability_name: str
    rule_id: str
    category: VulnCategory
    severity: Severity
    confidence: str
    evidence: str = ""
    description: str = ""

    def to_jsonl(self) -> str:
        return json.dumps({
            "rule_id": self.rule_id,
            "severity": self.severity.value,
            "confidence": self.confidence,
            "message": self.vulnerability_name,
            "file": self.file_path,
            "line": self.line_number,
            "col": self.col_offset,
            "snippet": self.line_content.strip(),
            "evidence": self.evidence,
        })


# ============================================================================
# AST Helpers
# ============================================================================

def get_node_text(node: Node) -> str:
    """Get the UTF-8 source text of a node."""
    return node.text.decode("utf-8") if node.text else ""


def node_location(node: Node) -> Tuple[int, int]:
    """Return (1-based line, 0-based col)."""
    return (node.start_point[0] + 1, node.start_point[1])


def is_string_literal(node: Node) -> bool:
    """Check if node is a string literal (including concatenated)."""
    return node.type in ("string_literal", "concatenated_string", "string_content",
                         "raw_string_literal", "char_literal")


def is_identifier(node: Node) -> bool:
    return node.type == "identifier"


def is_number_literal(node: Node) -> bool:
    return node.type == "number_literal"


def find_nodes(node: Node, type_name: str) -> List[Node]:
    """Recursively find all descendant nodes of a given type."""
    results = []
    if node.type == type_name:
        results.append(node)
    for child in node.children:
        results.extend(find_nodes(child, type_name))
    return results


def find_nodes_multi(node: Node, type_names: Set[str]) -> List[Node]:
    """Recursively find all descendant nodes matching any of the given types."""
    results = []
    if node.type in type_names:
        results.append(node)
    for child in node.children:
        results.extend(find_nodes_multi(child, type_names))
    return results


def get_child_by_type(node: Node, type_name: str) -> Optional[Node]:
    for child in node.children:
        if child.type == type_name:
            return child
    return None


def get_children_by_type(node: Node, type_name: str) -> List[Node]:
    return [c for c in node.children if c.type == type_name]


def find_calls(root: Node, func_name: str) -> List[Node]:
    """Find all call_expression nodes calling the given function name."""
    results = []
    for call in find_nodes(root, "call_expression"):
        fn = call.children[0] if call.children else None
        if fn and get_node_text(fn) == func_name:
            results.append(call)
    return results


def find_calls_any(root: Node, func_names: Set[str]) -> List[Node]:
    """Find all call_expression nodes calling any of the given function names."""
    results = []
    for call in find_nodes(root, "call_expression"):
        fn = call.children[0] if call.children else None
        if fn:
            name = get_node_text(fn)
            # Handle qualified names like std::copy
            if name in func_names:
                results.append(call)
            elif fn.type == "qualified_identifier":
                # e.g., std::system
                last = fn.children[-1] if fn.children else None
                if last and get_node_text(last) in func_names:
                    results.append(call)
    return results


def get_call_name(call_node: Node) -> str:
    """Extract the function name from a call_expression node."""
    fn = call_node.children[0] if call_node.children else None
    if not fn:
        return ""
    if fn.type == "qualified_identifier":
        return get_node_text(fn)
    return get_node_text(fn)


def get_call_args(call_node: Node) -> List[Node]:
    """Get the argument nodes from a call_expression."""
    arg_list = get_child_by_type(call_node, "argument_list")
    if not arg_list:
        return []
    return [c for c in arg_list.children if c.type not in ("(", ")", ",")]


def find_enclosing_function(node: Node) -> Optional[Node]:
    """Walk up to the enclosing function_definition."""
    cur = node.parent
    while cur:
        if cur.type == "function_definition":
            return cur
        cur = cur.parent
    return None


def find_enclosing_compound(node: Node) -> Optional[Node]:
    """Walk up to the enclosing compound_statement (block scope)."""
    cur = node.parent
    while cur:
        if cur.type == "compound_statement":
            return cur
        cur = cur.parent
    return None


def get_source_line(source_bytes: bytes, line_1based: int) -> str:
    """Extract a single source line (1-based)."""
    lines = source_bytes.split(b"\n")
    idx = line_1based - 1
    if 0 <= idx < len(lines):
        return lines[idx].decode("utf-8", errors="replace")
    return ""


def get_declared_type(decl_node: Node) -> str:
    """Best-effort extraction of the declared type from a declaration node."""
    # declaration -> first child is usually the type specifier
    for child in decl_node.children:
        if child.type in ("primitive_type", "sized_type_specifier", "type_identifier"):
            return get_node_text(child)
        if child.type == "qualified_identifier":
            return get_node_text(child)
    return ""


def iter_statements_in_compound(compound: Node) -> List[Node]:
    """Iterate direct statement children of a compound_statement."""
    return [c for c in compound.children if c.type not in ("{", "}")]


# ============================================================================
# Type width knowledge for narrowing / sign checks
# ============================================================================

# Maps type name -> (bit width, is_signed). Conservative; platform-dependent types
# use common 64-bit Linux values. Unresolved typedefs won't match.
TYPE_INFO: Dict[str, Tuple[int, bool]] = {
    "char": (8, True), "signed char": (8, True), "unsigned char": (8, False),
    "short": (16, True), "unsigned short": (16, False),
    "int": (32, True), "unsigned int": (32, False), "unsigned": (32, False),
    "long": (64, True), "unsigned long": (64, False),
    "long long": (64, True), "unsigned long long": (64, False),
    "int8_t": (8, True), "uint8_t": (8, False),
    "int16_t": (16, True), "uint16_t": (16, False),
    "int32_t": (32, True), "uint32_t": (32, False),
    "int64_t": (64, True), "uint64_t": (64, False),
    "size_t": (64, False), "ssize_t": (64, True),
    "ptrdiff_t": (64, True), "uintptr_t": (64, False), "intptr_t": (64, True),
    "float": (32, True), "double": (64, True),
}


def type_width(t: str) -> int:
    info = TYPE_INFO.get(t.strip())
    return info[0] if info else 0


def type_signed(t: str) -> Optional[bool]:
    info = TYPE_INFO.get(t.strip())
    return info[1] if info else None


# ============================================================================
# Rule implementations
# Each rule is a generator function: rule(tree, source_bytes, filename) -> Finding
# ============================================================================

# --- Rule 1: Unsafe copies ---------------------------------------------------

UNSAFE_COPY_FUNCS = {
    # Unconditionally unsafe (no size parameter)
    "strcpy", "strcat", "sprintf", "vsprintf", "gets",
    "wcscpy", "wcscat", "wsprintf",
    # Wide variants
    "lstrcpy", "lstrcpyA", "lstrcpyW", "lstrcat", "lstrcatA", "lstrcatW",
    "_tcscpy", "_tcscat",
    # POSIX / BSD / multibyte variants
    "stpcpy", "_mbscpy", "_mbscat",
}

# memcpy/memmove/strncpy/strncat are "suspicious" if the size arg is a raw variable
# (not sizeof, not a constant, not obviously bounded)
BOUNDED_COPY_FUNCS = {
    "memcpy", "memmove", "strncpy", "strncat", "wmemcpy", "wmemmove",
    "CopyMemory", "RtlCopyMemory",
    # Wide / BSD / legacy variants
    "wcsncpy", "wcsncat", "strlcpy", "strlcat", "bcopy",
}


def _size_arg_looks_safe(arg_node: Node) -> bool:
    """Heuristic: is the size argument obviously safe (sizeof, constant, etc.)?"""
    text = get_node_text(arg_node)
    if is_number_literal(arg_node):
        return True
    if "sizeof" in text:
        return True
    # sizeof(...) calls appear as call_expression with "sizeof" or as sizeof_expression
    if arg_node.type == "sizeof_expression":
        return True
    # ALL_CAPS identifiers are likely enum constants or #define constants
    if is_identifier(arg_node) and re.match(r"^[A-Z][A-Z0-9_]+$", text):
        return True
    # Ternary expression with a constant bound: (n < 64 ? n : 64) or (n > 64 ? 64 : n)
    if arg_node.type == "conditional_expression":
        children = arg_node.children
        # conditional_expression: condition ? consequence : alternative
        # At least 5 children: cond, ?, consequence, :, alternative
        if len(children) >= 5:
            consequence = children[2]
            alternative = children[4]
            if is_number_literal(consequence) or is_number_literal(alternative):
                return True
            if "sizeof" in get_node_text(consequence) or "sizeof" in get_node_text(alternative):
                return True
    return False


# Sprintf format specifiers that produce bounded output (no %s or %n)
_BOUNDED_FMT_SPEC = re.compile(
    r"%"                     # literal %
    r"[-+ #0]*"              # optional flags
    r"(?:\d+|\*)?"           # optional width
    r"(?:\.(?:\d+|\*))?"     # optional precision
    r"[diouxXeEfFgGaAcpn%]" # bounded conversion (no 's')
)

_ALL_FMT_SPEC = re.compile(r"%(?:[-+ #0]*(?:\d+|\*)?(?:\.(?:\d+|\*))?(?:hh?|ll?|[Lqjzt])?[diouxXeEfFgGaAcpns%])")


def _sprintf_format_is_bounded(fmt_text: str) -> bool:
    """Return True if a sprintf format string contains NO %s (only bounded specifiers).
    Requires the format to be a string literal we can inspect."""
    # Strip surrounding quotes
    if fmt_text.startswith('"') and fmt_text.endswith('"'):
        fmt_text = fmt_text[1:-1]
    elif fmt_text.startswith("L\"") and fmt_text.endswith('"'):
        fmt_text = fmt_text[2:-1]
    else:
        return False  # Not a literal we can analyse

    # If it contains %s or %n, it's not bounded
    specs = _ALL_FMT_SPEC.findall(fmt_text)
    if not specs:
        return True  # No format specifiers at all → pure literal, bounded
    for s in specs:
        if s.endswith("s"):
            # Check if precision is set: %.Ns limits output
            if ".%" not in s and re.match(r"%[-+ #0]*(?:\d+|\*)?\.(\d+)", s):
                continue  # precision-limited %s is bounded
            return False
        if s.endswith("n"):
            return False  # %n is dangerous
    return True


def _source_arg_is_string_literal(call_node: Node, base_name: str) -> Optional[str]:
    """For strcpy/strcat, check if the source (second arg) is a string literal.
    Returns the literal text if it is, None otherwise."""
    if base_name not in ("strcpy", "strcat", "lstrcpy", "lstrcpyA", "lstrcpyW",
                         "lstrcat", "lstrcatA", "lstrcatW", "wcscpy", "wcscat",
                         "_tcscpy", "_tcscat", "stpcpy", "_mbscpy", "_mbscat"):
        return None
    args = get_call_args(call_node)
    if len(args) >= 2 and is_string_literal(args[1]):
        return get_node_text(args[1])
    return None


def _sprintf_format_arg(call_node: Node, base_name: str) -> Optional[Node]:
    """For sprintf/vsprintf/wsprintf, return the format argument node if it's a literal."""
    if base_name in ("sprintf", "wsprintf"):
        args = get_call_args(call_node)
        if len(args) >= 2 and is_string_literal(args[1]):
            return args[1]
    elif base_name == "vsprintf":
        args = get_call_args(call_node)
        if len(args) >= 2 and is_string_literal(args[1]):
            return args[1]
    return None


def _strcpy_dst_has_strlen_malloc(call_node: Node, base_name: str) -> bool:
    """Check if the destination of strcpy was allocated with malloc(strlen(src) + 1).
    Handles both direct and indirect patterns:
      Direct:   dst = malloc(strlen(src) + 1);  strcpy(dst, src);
      Indirect: len = strlen(src); dst = malloc(len + 1); strcpy(dst, src);"""
    if base_name not in ("strcpy", "stpcpy", "_mbscpy"):
        return False
    args = get_call_args(call_node)
    if len(args) < 2:
        return False
    dst_name = get_node_text(args[0])
    src_name = get_node_text(args[1])
    compound = find_enclosing_compound(call_node)
    if not compound:
        return False
    call_line = call_node.start_point[0]

    # Collect all statement texts before the call for analysis
    pre_stmts = []
    for child in compound.children:
        if child.start_point[0] >= call_line:
            break
        pre_stmts.append(get_node_text(child))

    # Also check declarations from enclosing function
    func = find_enclosing_function(call_node)
    if func:
        for decl in find_nodes(func, "declaration"):
            if decl.start_point[0] >= call_line:
                continue
            pre_stmts.append(get_node_text(decl))

    all_text = "\n".join(pre_stmts)

    # Direct pattern: dst = malloc(strlen(src) + 1)
    if dst_name in all_text and "malloc" in all_text and "strlen(" + src_name + ")" in all_text:
        return True

    # Indirect pattern: len_var = strlen(src); ... dst = malloc(len_var + ...)
    # Find variables assigned from strlen(src)
    strlen_call = "strlen(" + src_name + ")"
    for stmt_text in pre_stmts:
        if strlen_call in stmt_text and "=" in stmt_text:
            # Extract LHS variable: "type var = strlen(src)" or "var = strlen(src)"
            eq_idx = stmt_text.index("=")
            lhs = stmt_text[:eq_idx].strip().split()
            if lhs:
                len_var = lhs[-1].strip("* ")
                if len_var and len_var.isidentifier():
                    # Now check if dst = malloc(len_var + ...) exists
                    for s2 in pre_stmts:
                        if dst_name in s2 and "malloc" in s2 and len_var in s2:
                            return True
    return False


def _strcpy_src_is_strlen_guarded(call_node: Node, base_name: str) -> bool:
    """Check if the source of strcpy/strcat has a strlen guard before the call.
    Pattern: if (strlen(src) < N) { ... strcpy(dst, src); ... }"""
    if base_name not in ("strcpy", "strcat", "stpcpy", "lstrcpy", "lstrcpyA", "lstrcpyW",
                         "lstrcat", "lstrcatA", "lstrcatW", "wcscpy", "wcscat",
                         "_tcscpy", "_tcscat", "_mbscpy", "_mbscat"):
        return False
    args = get_call_args(call_node)
    if len(args) < 2:
        return False
    src_name = get_node_text(args[1])
    if not src_name or not src_name.isidentifier():
        return False
    # Walk up to find an enclosing if with strlen(src) in the condition
    cur = call_node.parent
    while cur:
        if cur.type == "if_statement":
            cond = get_child_by_type(cur, "parenthesized_expression")
            if cond is None:
                cond = get_child_by_type(cur, "binary_expression")
            if cond:
                cond_text = get_node_text(cond)
                if "strlen(" + src_name + ")" in cond_text or "strlen( " + src_name + " )" in cond_text:
                    return True
        cur = cur.parent
    return False


def _var_is_guarded_before_call(call_node: Node, var_name: str) -> bool:
    """Check if var_name has a guard (if/return/abort/assert) in the same compound
    statement before this call.  Patterns:
      if (var > N) return;
      if (var > N) abort();
      if (var >= N) { ... return; }
      assert(var <= N);
    """
    compound = find_enclosing_compound(call_node)
    if not compound:
        return False
    call_line = call_node.start_point[0]
    for child in compound.children:
        if child.start_point[0] >= call_line:
            break
        if child.type == "if_statement":
            cond_text = ""
            for c in child.children:
                if c.type in ("binary_expression", "parenthesized_expression"):
                    cond_text = get_node_text(c)
                    break
            if var_name in cond_text:
                # Check if the body of the if is a return/abort/break/exit
                body_text = get_node_text(child)
                if any(kw in body_text for kw in ("return", "abort()", "exit(", "break", "goto")):
                    return True
        elif child.type == "expression_statement":
            text = get_node_text(child)
            if "assert" in text and var_name in text:
                return True
    return False


def rule_unsafe_copy(tree: Node, source_bytes: bytes, filename: str) -> Generator[Finding, None, None]:
    """MEM-UNSAFE-COPY: Detect unsafe string/memory copy functions."""
    all_calls = find_nodes(tree, "call_expression")
    for call in all_calls:
        name = get_call_name(call)
        base_name = name.split("::")[-1] if "::" in name else name

        if base_name in UNSAFE_COPY_FUNCS:
            line, col = node_location(call)
            severity = Severity.HIGH
            confidence = "HIGH"
            desc_extra = ""

            # --- FP reduction: string-literal source for strcpy/strcat variants ---
            lit = _source_arg_is_string_literal(call, base_name)
            if lit is not None:
                # strcat(buf, "") is a noop — suppress entirely
                if lit in ('""', "''", 'L""'):
                    continue
                # Short known literal → lower severity/confidence
                severity = Severity.LOW
                confidence = "LOW"
                desc_extra = f" Source is a string literal ({lit}); overflow risk is low if destination is adequately sized."

            # --- FP reduction: sprintf with only bounded format specifiers ---
            fmt_node = _sprintf_format_arg(call, base_name)
            if fmt_node is not None:
                fmt_text = get_node_text(fmt_node)
                if _sprintf_format_is_bounded(fmt_text):
                    severity = Severity.LOW
                    confidence = "LOW"
                    desc_extra = f" Format string {fmt_text} produces bounded output (no %s)."

            # --- FP reduction: strcpy where dst was malloc'd with strlen(src)+1 ---
            if severity == Severity.HIGH and _strcpy_dst_has_strlen_malloc(call, base_name):
                severity = Severity.LOW
                confidence = "LOW"
                desc_extra = " Destination buffer appears to be allocated with strlen(src)+1."

            # --- FP reduction: strcpy/strcat where source is strlen-guarded ---
            if severity == Severity.HIGH and _strcpy_src_is_strlen_guarded(call, base_name):
                severity = Severity.LOW
                confidence = "LOW"
                desc_extra = " Source string length is checked before copy."

            yield Finding(
                file_path=filename, line_number=line, col_offset=col,
                line_content=get_source_line(source_bytes, line),
                vulnerability_name=f"Unsafe function: {base_name}() has no bounds checking",
                rule_id="MEM-UNSAFE-COPY",
                category=VulnCategory.MEMORY_SAFETY,
                severity=severity,
                confidence=confidence,
                evidence=get_node_text(call),
                description=f"Replace {base_name}() with a bounded alternative (e.g., strncpy, snprintf).{desc_extra}",
            )
        elif base_name in BOUNDED_COPY_FUNCS:
            args = get_call_args(call)
            # The size argument is typically the last one
            if args:
                size_arg = args[-1]
                if not _size_arg_looks_safe(size_arg):
                    # --- FP reduction: check if size variable is guarded ---
                    size_text = get_node_text(size_arg)
                    # Extract the base variable name for guard checking
                    # Handle expressions like "n * 4" → check "n"; plain "n" → "n"
                    guard_var = None
                    if is_identifier(size_arg):
                        guard_var = size_text
                    elif size_arg.type == "binary_expression":
                        for ch in size_arg.children:
                            if is_identifier(ch):
                                guard_var = get_node_text(ch)
                                break
                    if guard_var and _var_is_guarded_before_call(call, guard_var):
                        continue  # Size is validated; suppress finding

                    line, col = node_location(call)
                    yield Finding(
                        file_path=filename, line_number=line, col_offset=col,
                        line_content=get_source_line(source_bytes, line),
                        vulnerability_name=f"{base_name}() with variable size argument",
                        rule_id="MEM-UNSAFE-COPY",
                        category=VulnCategory.MEMORY_SAFETY,
                        severity=Severity.MEDIUM,
                        confidence="MEDIUM",
                        evidence=get_node_text(call),
                        description=f"Size argument '{get_node_text(size_arg)}' is not obviously bounded. "
                                    "Verify it cannot exceed destination buffer size.",
                    )


# --- Rule 2: Potential buffer overflow (suspicious array index) ---------------

def _is_for_loop_iterator(node: Node, var_name: str) -> bool:
    """Check if var_name is the iterator of a for loop enclosing this node.
    Looks for patterns like: for(i=0; i<n; i++) or for(int i=0; i<n; i++)."""
    current = node.parent
    while current:
        if current.type == "for_statement":
            # Check if var_name appears in the for's condition (comparison with bound)
            children = current.children
            # for_statement children: 'for' '(' init ';' condition ';' update ')' body
            # In tree-sitter, the condition is typically a binary_expression
            for child in children:
                if child.type == "binary_expression":
                    ops = [c for c in child.children if c.type in ("<", "<=", ">", ">=", "!=")]
                    if ops:
                        operands = [c for c in child.children if c != ops[0]]
                        for op in operands:
                            if is_identifier(op) and get_node_text(op) == var_name:
                                return True
        current = current.parent
    return False


def _build_alloc_size_map(func_body: Node) -> Dict[str, str]:
    """Build a map of variable_name -> allocation size base variable.
    For patterns like: buf = malloc(n + 1), records buf -> "n".
    For patterns like: buf = malloc(n * sizeof(int)), records buf -> "n".
    Used to suppress FP when buf[n] is accessed after malloc(n + K)."""
    alloc_map: Dict[str, str] = {}
    for decl in find_nodes(func_body, "declaration"):
        for init in find_nodes(decl, "init_declarator"):
            children = init.children
            if len(children) < 3:
                continue
            rhs = children[-1]
            # Unwrap cast: (char*)malloc(...)
            call_node = None
            if rhs.type == "call_expression":
                call_node = rhs
            elif rhs.type == "cast_expression":
                for child in rhs.children:
                    if child.type == "call_expression":
                        call_node = child
                        break
            if not call_node:
                continue
            fname = get_call_name(call_node)
            if fname not in {"malloc", "calloc", "realloc", "aligned_alloc", "valloc"}:
                continue
            args = get_call_args(call_node)
            if not args:
                continue
            size_arg = args[0]
            # Extract the base variable from size expressions like "n + 1", "n * sizeof(...)"
            if size_arg.type == "binary_expression":
                ops = [c for c in size_arg.children if c.type in ("+", "*")]
                operands = [c for c in size_arg.children if c.type not in ("+", "*")]
                for op in operands:
                    if is_identifier(op) and get_node_text(op) != "sizeof":
                        lhs = children[0]
                        var_names = [get_node_text(i) for i in find_nodes(lhs, "identifier")]
                        if var_names:
                            alloc_map[var_names[-1]] = get_node_text(op)
                        break
            elif is_identifier(size_arg):
                lhs = children[0]
                var_names = [get_node_text(i) for i in find_nodes(lhs, "identifier")]
                if var_names:
                    alloc_map[var_names[-1]] = get_node_text(size_arg)
    return alloc_map


def rule_buffer_oob(tree: Node, source_bytes: bytes, filename: str) -> Generator[Finding, None, None]:
    """MEM-BUFFER-OOB: Writes to arrays via index where index is not obviously bounded.
    Heuristic: flag subscript_expression inside assignment LHS where index is a variable
    (not a small constant). This is conservative and will have false positives on
    well-bounded loops."""
    # Pre-build allocation size map per function to suppress FP like buf[n] after malloc(n+1)
    func_alloc_maps: Dict[int, Dict[str, str]] = {}
    for func in find_nodes_multi(tree, {"function_definition"}):
        body = get_child_by_type(func, "compound_statement")
        if body:
            func_alloc_maps[func.start_byte] = _build_alloc_size_map(body)

    for sub in find_nodes(tree, "subscript_expression"):
        # Check if this subscript is the target of an assignment (write)
        parent = sub.parent
        is_write = False
        if parent and parent.type == "assignment_expression":
            if parent.children and parent.children[0] == sub:
                is_write = True
        if parent and parent.type == "update_expression":
            is_write = True

        if not is_write:
            continue

        # Get index (second meaningful child after '[')
        children = [c for c in sub.children if c.type not in ("[", "]")]
        if len(children) < 2:
            continue
        array_node = children[0]
        index_node = children[1]
        index_text = get_node_text(index_node)
        array_text = get_node_text(array_node)

        # Skip if index is a small non-negative constant
        if is_number_literal(index_node):
            try:
                val = int(index_text, 0)
                if 0 <= val < 4096:
                    continue
            except ValueError:
                pass

        # Skip if index is a for-loop iterator (bounded by the loop condition)
        if is_identifier(index_node) and _is_for_loop_iterator(sub, index_text):
            continue

        # Skip if array was allocated with malloc(index_var + K) — index is within bounds
        if is_identifier(index_node):
            enclosing_func = find_enclosing_function(sub)
            if enclosing_func:
                alloc_map = func_alloc_maps.get(enclosing_func.start_byte, {})
                if alloc_map.get(array_text) == index_text:
                    continue

        # Flag if index is a variable or complex expression
        if is_identifier(index_node) or index_node.type in ("binary_expression", "call_expression"):
            line, col = node_location(sub)
            yield Finding(
                file_path=filename, line_number=line, col_offset=col,
                line_content=get_source_line(source_bytes, line),
                vulnerability_name="Potential buffer overflow: array write with variable index",
                rule_id="MEM-BUFFER-OOB",
                category=VulnCategory.MEMORY_SAFETY,
                severity=Severity.MEDIUM,
                confidence="LOW",
                evidence=get_node_text(sub),
                description=f"Index '{index_text}' is not statically bounded. "
                            "Ensure it is validated against the array size.",
            )


# --- Rule 3: Use-after-free (heuristic) --------------------------------------

# Functions that deallocate memory (free() and common wrappers/macros).
# Tree-sitter parses raw source, so macro names appear as call_expression.
FREE_LIKE_FUNCS = {
    "free",
    # POSIX / libc
    "cfree",
    # GLib
    "g_free", "g_slice_free",
    # Linux kernel
    "kfree", "vfree", "kzfree", "kvfree",
    # Common project conventions
    "xfree", "safe_free", "safefree",
    # FFmpeg / libav
    "av_free", "av_freep",
    # OpenSSL / crypto
    "OPENSSL_free", "CRYPTO_free",
    # libxml2
    "xmlFree",
    # Talloc
    "talloc_free",
    # Win32
    "HeapFree", "GlobalFree", "LocalFree",
    "CoTaskMemFree", "SysFreeString",
}


def _has_ancestor_type(node: Node, ancestor_type: str) -> bool:
    """Check if any ancestor of node has the given type."""
    cur = node.parent
    while cur:
        if cur.type == ancestor_type:
            return True
        cur = cur.parent
    return False


def _node_contains(ancestor: Node, descendant: Node) -> bool:
    """Check if descendant is within ancestor's byte range."""
    return (ancestor.start_byte <= descendant.start_byte and
            ancestor.end_byte >= descendant.end_byte)


def _are_in_exclusive_branches(free_node: Node, use_node: Node) -> bool:
    """Check if free_node and use_node are in mutually exclusive if/else branches.
    Returns True if one is in the 'if' body and the other in the 'else' body
    of the same if_statement."""
    cur = free_node.parent
    while cur:
        if cur.type == "compound_statement":
            parent = cur.parent
            if parent and parent.type == "if_statement":
                # free is in the 'then' branch — check if use is in the else clause
                else_clause = get_child_by_type(parent, "else_clause")
                if else_clause and _node_contains(else_clause, use_node):
                    return True
            elif parent and parent.type == "else_clause":
                # free is in the 'else' branch — check if use is in the 'then' body
                if_gparent = parent.parent
                if if_gparent and if_gparent.type == "if_statement":
                    for child in if_gparent.children:
                        if child.type == "compound_statement" and _node_contains(child, use_node):
                            return True
        cur = cur.parent
    return False


def _free_is_in_returning_branch(free_node: Node, use_node: Node) -> bool:
    """Check if free_node is inside an if-block that also contains a return/exit
    statement, AND the use_node is AFTER that entire if_statement.
    Pattern: if(err) { free(p); return; }  use(p); — use is safe."""
    cur = free_node.parent
    while cur:
        if cur.type == "compound_statement":
            parent = cur.parent
            if parent and parent.type in ("if_statement", "else_clause"):
                # Check if this compound has a return/exit/abort
                has_exit = bool(find_nodes(cur, "return_statement"))
                if not has_exit:
                    has_exit = bool(find_nodes(cur, "goto_statement"))
                if not has_exit:
                    for call in find_nodes(cur, "call_expression"):
                        cname = get_call_name(call)
                        if cname in ("exit", "_exit", "abort", "_Exit", "die"):
                            has_exit = True
                            break
                if has_exit:
                    # Find the enclosing if_statement
                    if_stmt = parent if parent.type == "if_statement" else parent.parent
                    if if_stmt and if_stmt.type == "if_statement":
                        # Use must be AFTER the entire if_statement
                        if use_node.start_byte > if_stmt.end_byte:
                            return True
            # Stop at function body level
            if parent and parent.type == "function_definition":
                break
        cur = cur.parent
    return False


def _is_shadowed_in_inner_scope(ident_node: Node, func_body: Node) -> bool:
    """Check if ident_node's variable name is re-declared in an inner
    compound_statement (not the function body) before the use point.
    Pattern: free(p); { char* p = malloc(128); use(p); } — inner p shadows."""
    var_name = get_node_text(ident_node)
    cur = ident_node.parent
    while cur and cur != func_body:
        if cur.type == "compound_statement":
            for decl in find_nodes(cur, "declaration"):
                if decl.start_byte >= ident_node.start_byte:
                    continue
                for init in find_nodes(decl, "init_declarator"):
                    lhs = init.children[0] if init.children else None
                    if lhs:
                        for li in find_nodes(lhs, "identifier"):
                            if get_node_text(li) == var_name and li.start_byte <= ident_node.start_byte:
                                return True
        cur = cur.parent
    return False


def _collect_free_and_delete(compound: Node) -> List[Tuple[str, int, Node]]:
    """Collect (var_name, byte_offset, node) for free(x) / delete x calls in a compound."""
    results = []
    for call in find_nodes(compound, "call_expression"):
        name = get_call_name(call)
        if name in FREE_LIKE_FUNCS:
            args = get_call_args(call)
            if args and is_identifier(args[0]):
                results.append((get_node_text(args[0]), call.start_byte, call))
    # Also check delete_expression (C++)
    for dexpr in find_nodes(compound, "delete_expression"):
        for child in dexpr.children:
            if is_identifier(child):
                results.append((get_node_text(child), dexpr.start_byte, dexpr))
    return results


def _identifier_used_after(compound: Node, var_name: str, after_byte: int,
                           before_byte: int = None) -> Optional[Node]:
    """Check if 'var_name' is referenced (read) in compound after after_byte.
    Skips if the use is inside another free() call (that's double-free, not UAF).
    Optionally stop before before_byte."""
    for ident in find_nodes(compound, "identifier"):
        if get_node_text(ident) != var_name:
            continue
        if ident.start_byte <= after_byte:
            continue
        if before_byte is not None and ident.start_byte >= before_byte:
            continue
        # Skip if this identifier is the argument of free/delete (handled by double-free rule)
        parent = ident.parent
        if parent and parent.type == "argument_list":
            grandparent = parent.parent
            if grandparent and grandparent.type == "call_expression":
                fname = get_call_name(grandparent)
                if fname in FREE_LIKE_FUNCS:
                    continue
        if parent and parent.type == "delete_expression":
            continue
        # Skip if it's being reassigned (LHS of assignment or init_declarator)
        if parent and parent.type == "assignment_expression":
            if parent.children and parent.children[0] == ident:
                continue
        if parent and parent.type == "init_declarator":
            continue
        # Also skip if inside pointer_declarator within init_declarator (char* p = ...)
        if parent and parent.type == "pointer_declarator":
            gp = parent.parent
            if gp and gp.type == "init_declarator":
                continue
        # Skip if inside sizeof() — compile-time, not a runtime dereference
        if _has_ancestor_type(ident, "sizeof_expression"):
            continue
        # Skip if variable name is shadowed by an inner-scope declaration
        if _is_shadowed_in_inner_scope(ident, compound):
            continue
        return ident
    return None


def rule_use_after_free(tree: Node, source_bytes: bytes, filename: str) -> Generator[Finding, None, None]:
    """MEM-USE-AFTER-FREE: free(x) / delete x then x used later in same scope.
    Limitation: only checks within same compound_statement, no cross-scope tracking."""
    for func in find_nodes_multi(tree, {"function_definition"}):
        body = get_child_by_type(func, "compound_statement")
        if not body:
            continue

        # Build alias map: alias_name -> original_name (e.g., q = p means alias_map["q"] = "p")
        # Also build reverse map: original -> [aliases]
        alias_map: Dict[str, str] = {}
        for decl in find_nodes(body, "declaration"):
            for init in find_nodes(decl, "init_declarator"):
                children = init.children
                if len(children) < 3:
                    continue
                rhs = children[-1]
                if is_identifier(rhs):
                    lhs = children[0]
                    lhs_names = [get_node_text(i) for i in find_nodes(lhs, "identifier")]
                    if lhs_names:
                        alias_map[lhs_names[-1]] = get_node_text(rhs)
        # Also track assignment-based aliases: q = p;
        for assign in find_nodes(body, "assignment_expression"):
            children = assign.children
            if len(children) >= 3 and children[1].type == "=":
                lhs, rhs = children[0], children[-1]
                if is_identifier(lhs) and is_identifier(rhs):
                    alias_map[get_node_text(lhs)] = get_node_text(rhs)

        # Resolve transitive alias chains: if c->b and b->a, then c->a
        for _ in range(10):
            changed = False
            for alias, target in list(alias_map.items()):
                if target in alias_map and alias_map[target] != alias:
                    alias_map[alias] = alias_map[target]
                    changed = True
            if not changed:
                break

        frees = _collect_free_and_delete(body)
        reported_uses: Set[int] = set()  # track byte offsets of already-reported uses
        for var_name, free_byte, free_node in frees:
            # Check the freed variable itself, all its aliases, and the original it aliases
            names_to_check = [var_name] + [k for k, v in alias_map.items() if v == var_name]
            # Reverse direction: if freed var is itself an alias, also check the original.
            # Only follow if var_name is NOT reassigned after the free (otherwise the
            # alias relationship was established post-free and is irrelevant).
            if var_name in alias_map and \
                    not _is_reassigned_between(body, var_name, free_byte, body.end_byte):
                original = alias_map[var_name]
                if original not in names_to_check:
                    names_to_check.append(original)
                # And all siblings (other aliases of the same original)
                for k, v in alias_map.items():
                    if v == original and k not in names_to_check:
                        names_to_check.append(k)
            for check_name in names_to_check:
                use = _identifier_used_after(body, check_name, free_byte)
                if use and use.start_byte not in reported_uses and \
                        not _is_reassigned_between(body, check_name, free_byte, use.start_byte) and \
                        not _are_in_exclusive_branches(free_node, use) and \
                        not _free_is_in_returning_branch(free_node, use):
                    line, col = node_location(use)
                    free_line = node_location(free_node)[0]
                    via = f" (via alias '{check_name}')" if check_name != var_name else ""
                    yield Finding(
                        file_path=filename, line_number=line, col_offset=col,
                        line_content=get_source_line(source_bytes, line),
                        vulnerability_name=f"Potential use-after-free: '{var_name}' freed at line {free_line}{via}",
                        rule_id="MEM-USE-AFTER-FREE",
                        category=VulnCategory.MEMORY_SAFETY,
                        severity=Severity.CRITICAL,
                        confidence="MEDIUM",
                        evidence=f"free({var_name}) at line {free_line}, {check_name} used at line {line}",
                        description="Pointer used after being freed. This can lead to arbitrary code execution.",
                    )
                    reported_uses.add(use.start_byte)
                    break  # one finding per (free, name) pair


# --- Rule 4: Double free (heuristic) -----------------------------------------

def _is_reassigned_between(compound: Node, var_name: str, start_byte: int, end_byte: int) -> bool:
    """Check if var_name is reassigned between start_byte and end_byte."""
    for ident in find_nodes(compound, "identifier"):
        if get_node_text(ident) != var_name:
            continue
        if ident.start_byte <= start_byte or ident.start_byte >= end_byte:
            continue
        parent = ident.parent
        # Assignment LHS
        if parent and parent.type == "assignment_expression":
            if parent.children and parent.children[0] == ident:
                return True
        # init_declarator
        if parent and parent.type == "init_declarator":
            return True
    return False


def rule_double_free(tree: Node, source_bytes: bytes, filename: str) -> Generator[Finding, None, None]:
    """MEM-DOUBLE-FREE: free(x) twice in same function without reassignment of x in between.
    Limitation: only same compound_statement; does not track across branches."""
    for func in find_nodes_multi(tree, {"function_definition"}):
        body = get_child_by_type(func, "compound_statement")
        if not body:
            continue
        frees = _collect_free_and_delete(body)
        # Group by var name
        by_var: Dict[str, List[Tuple[int, Node]]] = defaultdict(list)
        for var_name, byte_off, node in frees:
            by_var[var_name].append((byte_off, node))

        for var_name, free_list in by_var.items():
            if len(free_list) < 2:
                continue
            free_list.sort(key=lambda x: x[0])
            for i in range(len(free_list) - 1):
                byte1, node1 = free_list[i]
                byte2, node2 = free_list[i + 1]
                if not _is_reassigned_between(body, var_name, byte1, byte2):
                    line2, col2 = node_location(node2)
                    line1 = node_location(node1)[0]
                    yield Finding(
                        file_path=filename, line_number=line2, col_offset=col2,
                        line_content=get_source_line(source_bytes, line2),
                        vulnerability_name=f"Potential double free: '{var_name}' already freed at line {line1}",
                        rule_id="MEM-DOUBLE-FREE",
                        category=VulnCategory.MEMORY_SAFETY,
                        severity=Severity.CRITICAL,
                        confidence="MEDIUM",
                        evidence=f"First free at line {line1}, second at line {line2}",
                        description="Freeing the same pointer twice causes heap corruption.",
                    )


# --- Rule 5: Returning address of stack/local variable -----------------------

def rule_return_local_addr(tree: Node, source_bytes: bytes, filename: str) -> Generator[Finding, None, None]:
    """MEM-RETURN-LOCAL: Detect returning &local_var from a function."""
    for func in find_nodes_multi(tree, {"function_definition"}):
        body = get_child_by_type(func, "compound_statement")
        if not body:
            continue
        # Collect local variable names declared in this function (skip static)
        local_vars: Set[str] = set()
        for decl in find_nodes(body, "declaration"):
            # Skip declarations with 'static' storage class — static vars have permanent storage
            has_static = any(
                get_node_text(c) == "static"
                for c in decl.children if c.type == "storage_class_specifier"
            )
            if has_static:
                continue
            for ident in find_nodes(decl, "identifier"):
                local_vars.add(get_node_text(ident))
            for arr in find_nodes(decl, "array_declarator"):
                for ident in find_nodes(arr, "identifier"):
                    local_vars.add(get_node_text(ident))

        # Find return statements with & (address-of)
        for ret in find_nodes(body, "return_statement"):
            for pexpr in find_nodes(ret, "pointer_expression"):
                # pointer_expression with & operator
                has_ampersand = any(c.type == "&" for c in pexpr.children)
                if not has_ampersand:
                    continue
                # Skip if &local is inside a function call (return(func(&local,...)))
                # — the function's return value is returned, not the address
                parent_of_pexpr = pexpr.parent
                if parent_of_pexpr and parent_of_pexpr.type == "argument_list":
                    continue
                for ident in find_nodes(pexpr, "identifier"):
                    if get_node_text(ident) not in local_vars:
                        continue
                    # Skip &ptr->member — this is address of a heap struct member, not the local pointer
                    ident_parent = ident.parent
                    if ident_parent and ident_parent.type == "field_expression":
                        continue
                    if get_node_text(ident) in local_vars:
                        line, col = node_location(ret)
                        yield Finding(
                            file_path=filename, line_number=line, col_offset=col,
                            line_content=get_source_line(source_bytes, line),
                            vulnerability_name=f"Returning address of local variable '{get_node_text(ident)}'",
                            rule_id="MEM-RETURN-LOCAL",
                            category=VulnCategory.MEMORY_SAFETY,
                            severity=Severity.HIGH,
                            confidence="HIGH",
                            evidence=get_node_text(ret),
                            description="The local variable's memory is invalid after the function returns.",
                        )


# --- Rule 5b: Dangling pointer — returning stack-local via intermediate ptr ---

def rule_dangling_ptr_return(tree: Node, source_bytes: bytes, filename: str) -> Generator[Finding, None, None]:
    """MEM-DANGLING-PTR: Detect when a pointer is assigned &stack_local and later returned.
    Catches the pattern: type local; type* ptr = &local; ... return ptr;
    Also catches: ptr = &local; (assignment, not just init).
    This is distinct from MEM-RETURN-LOCAL which only catches direct 'return &var'."""
    for func in find_nodes_multi(tree, {"function_definition"}):
        body = get_child_by_type(func, "compound_statement")
        if not body:
            continue

        # Step 1: Collect local variable names (non-pointer, non-heap declarations)
        local_vars: Set[str] = set()
        for decl in find_nodes(body, "declaration"):
            for child in decl.children:
                name = _extract_declarator_name(child)
                if name:
                    # Exclude pointer declarations (they're not stack objects themselves
                    # unless they point to a local — handled below)
                    if child.type not in ("init_declarator",):
                        local_vars.add(name)
                    else:
                        # init_declarator: check if RHS is an alloc (heap) — skip those
                        rhs = child.children[-1] if len(child.children) >= 3 else None
                        if rhs and rhs.type == "call_expression":
                            fname = get_call_name(rhs)
                            if fname in ("malloc", "calloc", "realloc", "new"):
                                continue
                        if rhs and rhs.type == "cast_expression":
                            for inner in find_nodes(rhs, "call_expression"):
                                if get_call_name(inner) in ("malloc", "calloc", "realloc"):
                                    break
                            else:
                                local_vars.add(name)
                        else:
                            local_vars.add(name)

        # Step 2: Track pointer variables assigned &local_var
        # Pattern A: init_declarator with pointer_expression(&local) on RHS
        # Pattern B: assignment_expression: ptr = &local
        ptrs_to_local: Dict[str, Tuple[str, int, Node]] = {}  # ptr_name -> (local_name, byte, node)

        for decl in find_nodes(body, "declaration"):
            for init in find_nodes(decl, "init_declarator"):
                if len(init.children) < 3:
                    continue
                lhs = init.children[0]
                rhs = init.children[-1]
                ptr_name = _extract_declarator_name(lhs)
                if not ptr_name:
                    ptr_name = _extract_declarator_name(init)
                if not ptr_name:
                    continue
                # Check if RHS is &local_var
                if rhs.type == "pointer_expression":
                    has_amp = any(c.type == "&" for c in rhs.children)
                    if has_amp:
                        for ident in find_nodes(rhs, "identifier"):
                            ref_name = get_node_text(ident)
                            if ref_name in local_vars:
                                ptrs_to_local[ptr_name] = (ref_name, init.start_byte, init)

        for assign in find_nodes(body, "assignment_expression"):
            if len(assign.children) < 3:
                continue
            lhs = assign.children[0]
            rhs = assign.children[-1]
            if is_identifier(lhs) and rhs.type == "pointer_expression":
                has_amp = any(c.type == "&" for c in rhs.children)
                if has_amp:
                    ptr_name = get_node_text(lhs)
                    for ident in find_nodes(rhs, "identifier"):
                        ref_name = get_node_text(ident)
                        if ref_name in local_vars:
                            ptrs_to_local[ptr_name] = (ref_name, assign.start_byte, assign)

        if not ptrs_to_local:
            continue

        # Step 3: Check if any of these pointer variables are returned
        for ret in find_nodes(body, "return_statement"):
            for child in ret.children:
                if child.type == "return":
                    continue
                if child.type == ";":
                    continue
                # The returned expression — check if it's one of our tracked pointers
                ret_text = get_node_text(child)
                for ptr_name, (local_name, assign_byte, assign_node) in ptrs_to_local.items():
                    if ret_text == ptr_name:
                        # Verify the pointer wasn't reassigned between the &local and the return
                        reassigned = False
                        for ident in find_nodes(body, "identifier"):
                            if get_node_text(ident) != ptr_name:
                                continue
                            if ident.start_byte <= assign_byte or ident.start_byte >= ret.start_byte:
                                continue
                            parent = ident.parent
                            if parent and parent.type == "assignment_expression":
                                if parent.children and parent.children[0] == ident:
                                    reassigned = True
                                    break
                        if reassigned:
                            continue

                        line, col = node_location(ret)
                        assign_line = node_location(assign_node)[0]
                        yield Finding(
                            file_path=filename, line_number=line, col_offset=col,
                            line_content=get_source_line(source_bytes, line),
                            vulnerability_name=f"Dangling pointer: '{ptr_name}' points to stack-local '{local_name}' (line {assign_line})",
                            rule_id="MEM-DANGLING-PTR",
                            category=VulnCategory.MEMORY_SAFETY,
                            severity=Severity.CRITICAL,
                            confidence="HIGH",
                            evidence=f"{ptr_name} = &{local_name} at line {assign_line}, returned at line {line}",
                            description=f"'{ptr_name}' holds the address of stack variable '{local_name}'. "
                                        "After the function returns, this memory is invalid. "
                                        "Allocate on the heap instead.",
                        )


# --- Rule 6: Missing NULL check after malloc/new -----------------------------

ALLOC_FUNCS = {"malloc", "calloc", "realloc", "aligned_alloc", "valloc", "pvalloc"}


def _has_null_check_before_use(compound: Node, var_name: str, alloc_byte: int,
                               before_byte: int = None) -> bool:
    """Heuristic: check if there's an if-statement checking var_name for NULL/0
    between the allocation and the first dereference.
    If before_byte is given, only consider checks that appear before that byte offset."""
    # Look for if(...var_name...) or if(!var_name) patterns
    for if_stmt in find_nodes(compound, "if_statement"):
        if if_stmt.start_byte <= alloc_byte:
            continue
        if before_byte is not None and if_stmt.start_byte >= before_byte:
            continue
        cond = get_child_by_type(if_stmt, "parenthesized_expression")
        if cond and var_name in get_node_text(cond):
            return True
        cond2 = get_child_by_type(if_stmt, "condition_clause")
        if cond2 and var_name in get_node_text(cond2):
            return True
    return False


def _is_inside_ternary_guard(node: Node, var_name: str) -> bool:
    """Check if node is inside the 'true' or 'false' branch of a ternary
    (conditional_expression) where var_name is the condition.
    e.g., 'buf ? buf[0] : 0' — the subscript buf[0] is guarded by the condition."""
    current = node.parent
    while current:
        if current.type == "conditional_expression":
            children = [c for c in current.children if c.type not in ("?", ":")]
            if len(children) >= 1:
                condition = children[0]
                cond_text = get_node_text(condition)
                # Condition is the variable itself, or a comparison involving it
                if cond_text == var_name or var_name in cond_text.split():
                    return True
        current = current.parent
    return False


def _find_first_deref(compound: Node, var_name: str, after_byte: int) -> Optional[Node]:
    """Find the first dereference of var_name after after_byte.
    Dereference patterns: *var, var->field, var[i], or passing var to a function
    (functions like recv/memcpy/read write through the pointer)."""
    candidates = []
    # pointer dereference: *var
    for pexpr in find_nodes(compound, "pointer_expression"):
        if pexpr.start_byte <= after_byte:
            continue
        has_star = any(c.type == "*" for c in pexpr.children)
        if has_star:
            for ident in find_nodes(pexpr, "identifier"):
                if get_node_text(ident) == var_name:
                    candidates.append(pexpr)
    # field access: var->field
    for fexpr in find_nodes(compound, "field_expression"):
        if fexpr.start_byte <= after_byte:
            continue
        if fexpr.children and get_node_text(fexpr.children[0]) == var_name:
            candidates.append(fexpr)
    # subscript: var[i]
    for sub in find_nodes(compound, "subscript_expression"):
        if sub.start_byte <= after_byte:
            continue
        arr_children = [c for c in sub.children if c.type not in ("[", "]")]
        if arr_children and get_node_text(arr_children[0]) == var_name:
            candidates.append(sub)
    # Passed as argument to a function (implicit dereference — the callee
    # will read/write through the pointer, e.g., recv(fd, ptr, len, 0))
    for call in find_nodes(compound, "call_expression"):
        if call.start_byte <= after_byte:
            continue
        args = get_call_args(call)
        for arg in args:
            if is_identifier(arg) and get_node_text(arg) == var_name:
                # Skip if this is a NULL-checking function (e.g., free, assert)
                call_name = get_call_name(call)
                if call_name in ("free", "assert", "sizeof"):
                    continue
                candidates.append(call)
                break

    # Filter out candidates inside ternary guards (e.g., buf ? buf[0] : 0)
    candidates = [c for c in candidates if not _is_inside_ternary_guard(c, var_name)]

    if not candidates:
        return None
    candidates.sort(key=lambda n: n.start_byte)
    return candidates[0]


def _extract_alloc_call(rhs: Node) -> Optional[Tuple[str, Node]]:
    """Extract (alloc_func_name, call_node) from an RHS that may be a direct call or
    a cast_expression wrapping a call — e.g., (char*)malloc(n)."""
    if rhs.type == "call_expression":
        fname = get_call_name(rhs)
        if fname in ALLOC_FUNCS:
            return (fname, rhs)
    if rhs.type == "cast_expression":
        for child in rhs.children:
            if child.type == "call_expression":
                fname = get_call_name(child)
                if fname in ALLOC_FUNCS:
                    return (fname, child)
    return None


def rule_null_deref(tree: Node, source_bytes: bytes, filename: str) -> Generator[Finding, None, None]:
    """MEM-NULL-DEREF: malloc/calloc/realloc/new without NULL check before dereference.
    Handles cast expressions like (char*)malloc(n), and tracks simple aliases (q = p)."""
    for func in find_nodes_multi(tree, {"function_definition"}):
        body = get_child_by_type(func, "compound_statement")
        if not body:
            continue

        # Collect all alloc sites: var_name -> (fname, alloc_byte, call_node)
        alloc_sites: List[Tuple[str, str, int, Node]] = []

        for decl in find_nodes(body, "declaration"):
            for init in find_nodes(decl, "init_declarator"):
                children = init.children
                if len(children) < 3:
                    continue
                rhs = children[-1]
                result = _extract_alloc_call(rhs)
                if not result:
                    continue
                fname, call_node = result
                lhs = children[0]
                var_names = [get_node_text(i) for i in find_nodes(lhs, "identifier")]
                if not var_names:
                    continue
                var_name = var_names[-1]
                alloc_sites.append((var_name, fname, call_node.start_byte, call_node))

        # Also track simple aliases: char* q = p; where p is an alloc'd variable
        alloc_var_names = {name for name, _, _, _ in alloc_sites}
        alias_map: Dict[str, str] = {}  # alias -> original alloc var
        for decl in find_nodes(body, "declaration"):
            for init in find_nodes(decl, "init_declarator"):
                children = init.children
                if len(children) < 3:
                    continue
                rhs = children[-1]
                if is_identifier(rhs):
                    rhs_name = get_node_text(rhs)
                    if rhs_name in alloc_var_names:
                        lhs = children[0]
                        lhs_names = [get_node_text(i) for i in find_nodes(lhs, "identifier")]
                        if lhs_names:
                            alias_map[lhs_names[-1]] = rhs_name

        for var_name, fname, alloc_byte, call_node in alloc_sites:
            # Check all names (original + aliases) for NULL checks and derefs
            names_to_check = [var_name] + [k for k, v in alias_map.items() if v == var_name]

            # Find first deref across original and aliases FIRST,
            # then check if there's a NULL guard between alloc and that deref.
            first_deref = None
            deref_name = var_name
            for n in names_to_check:
                d = _find_first_deref(body, n, alloc_byte)
                if d and (first_deref is None or d.start_byte < first_deref.start_byte):
                    first_deref = d
                    deref_name = n

            if not first_deref:
                continue

            # Only count NULL checks that appear BETWEEN alloc and first deref
            has_null_check = any(
                _has_null_check_before_use(body, n, alloc_byte, before_byte=first_deref.start_byte)
                for n in names_to_check
            )
            if has_null_check:
                continue

            if first_deref:
                line, col = node_location(first_deref)
                alloc_line = node_location(call_node)[0]
                via_alias = f" (via alias '{deref_name}')" if deref_name != var_name else ""
                yield Finding(
                    file_path=filename, line_number=line, col_offset=col,
                    line_content=get_source_line(source_bytes, line),
                    vulnerability_name=f"Potential NULL dereference: '{var_name}' from {fname}() at line {alloc_line}{via_alias}",
                    rule_id="MEM-NULL-DEREF",
                    category=VulnCategory.MEMORY_SAFETY,
                    severity=Severity.CRITICAL,
                    confidence="HIGH",
                    evidence=f"{fname}() at line {alloc_line}, dereferenced at line {line} without NULL check",
                    description=f"If {fname}() returns NULL, dereferencing causes a crash. Add a NULL check.",
                )

        # C++ new_expression: new can throw, but new(std::nothrow) returns NULL
        for decl in find_nodes(body, "declaration"):
            for init in find_nodes(decl, "init_declarator"):
                rhs_nodes = find_nodes(init, "new_expression")
                if not rhs_nodes:
                    continue
                new_node = rhs_nodes[0]
                new_text = get_node_text(new_node)
                # Only flag if nothrow is used (plain new throws, not NULL)
                if "nothrow" not in new_text:
                    continue
                lhs = init.children[0]
                var_names = [get_node_text(i) for i in find_nodes(lhs, "identifier")]
                if not var_names:
                    continue
                var_name = var_names[-1]
                alloc_byte = new_node.start_byte
                if _has_null_check_before_use(body, var_name, alloc_byte):
                    continue
                deref = _find_first_deref(body, var_name, alloc_byte)
                if deref:
                    line, col = node_location(deref)
                    yield Finding(
                        file_path=filename, line_number=line, col_offset=col,
                        line_content=get_source_line(source_bytes, line),
                        vulnerability_name=f"Potential NULL dereference: '{var_name}' from new(nothrow)",
                        rule_id="MEM-NULL-DEREF",
                        category=VulnCategory.MEMORY_SAFETY,
                        severity=Severity.HIGH,
                        confidence="MEDIUM",
                        evidence=f"new(nothrow) result dereferenced without NULL check at line {line}",
                        description=f"new(std::nothrow) can return nullptr. Check before dereferencing.",
                    )


# --- Rule 7: Pointer arithmetic in suspicious contexts ------------------------

def rule_pointer_arith(tree: Node, source_bytes: bytes, filename: str) -> Generator[Finding, None, None]:
    """PTR-ARITH: Flag *(ptr + expr) or *(ptr - expr) patterns where expr is a variable.
    This is a heuristic; many such uses are safe in practice."""
    for pexpr in find_nodes(tree, "pointer_expression"):
        has_star = any(c.type == "*" for c in pexpr.children)
        if not has_star:
            continue
        # Check if operand is (ptr + var) wrapped in parenthesized_expression
        for child in pexpr.children:
            inner = child
            if inner.type == "parenthesized_expression":
                inner_children = [c for c in inner.children if c.type not in ("(", ")")]
                if inner_children:
                    inner = inner_children[0]
            if inner.type == "binary_expression":
                ops = [c for c in inner.children if c.type in ("+", "-")]
                operands = [c for c in inner.children if c.type not in ("+", "-")]
                if ops and len(operands) == 2:
                    # At least one operand should be an identifier (the offset)
                    has_var_offset = any(is_identifier(o) for o in operands)
                    if has_var_offset:
                        line, col = node_location(pexpr)
                        yield Finding(
                            file_path=filename, line_number=line, col_offset=col,
                            line_content=get_source_line(source_bytes, line),
                            vulnerability_name="Pointer arithmetic dereference with variable offset",
                            rule_id="PTR-ARITH",
                            category=VulnCategory.POINTER_ARRAY,
                            severity=Severity.MEDIUM,
                            confidence="LOW",
                            evidence=get_node_text(pexpr),
                            description="Dereferencing pointer with computed offset. "
                                        "Ensure the offset is bounds-checked.",
                        )

    # --- Sub-rule: ptr += N; ... *ptr = val; (pointer increment then dereference) ---
    for func in find_nodes_multi(tree, {"function_definition"}):
        body = get_child_by_type(func, "compound_statement")
        if not body:
            continue

        # Track pointer variables advanced via compound assignment (ptr += expr)
        # or plain assignment (ptr = ptr + expr)
        advanced_ptrs: Dict[str, Tuple[int, Node, str]] = {}  # name -> (byte, node, offset_text)

        for assign in find_nodes(body, "assignment_expression"):
            children = assign.children
            if len(children) < 3:
                continue
            lhs = children[0]
            op_node = children[1] if len(children) > 1 else None
            rhs = children[-1]
            if not op_node:
                continue
            op_text = get_node_text(op_node)

            # Pattern A: ptr += expr
            if op_text == "+=" and is_identifier(lhs):
                ptr_name = get_node_text(lhs)
                advanced_ptrs[ptr_name] = (assign.start_byte, assign, get_node_text(rhs))
            # Pattern B: ptr = ptr + expr
            elif op_text == "=" and is_identifier(lhs) and rhs.type == "binary_expression":
                ptr_name = get_node_text(lhs)
                rhs_ops = [c for c in rhs.children if c.type in ("+",)]
                rhs_operands = [c for c in rhs.children if c.type not in ("+",)]
                if rhs_ops and len(rhs_operands) == 2:
                    for i, op in enumerate(rhs_operands):
                        if is_identifier(op) and get_node_text(op) == ptr_name:
                            other = rhs_operands[1 - i]
                            advanced_ptrs[ptr_name] = (assign.start_byte, assign, get_node_text(other))
                            break

        # Check if any advanced pointer is subsequently dereferenced: *ptr
        for ptr_name, (adv_byte, adv_node, offset_text) in advanced_ptrs.items():
            for pexpr in find_nodes(body, "pointer_expression"):
                if pexpr.start_byte <= adv_byte:
                    continue
                has_star = any(c.type == "*" for c in pexpr.children)
                if not has_star:
                    continue
                for child in pexpr.children:
                    if is_identifier(child) and get_node_text(child) == ptr_name:
                        # Check the pointer wasn't reassigned between advance and deref
                        if _is_reassigned_between(body, ptr_name, adv_byte, pexpr.start_byte):
                            continue
                        line, col = node_location(pexpr)
                        adv_line = node_location(adv_node)[0]
                        yield Finding(
                            file_path=filename, line_number=line, col_offset=col,
                            line_content=get_source_line(source_bytes, line),
                            vulnerability_name=f"Pointer arithmetic: '{ptr_name}' advanced by {offset_text} (line {adv_line}) then dereferenced",
                            rule_id="PTR-ARITH",
                            category=VulnCategory.POINTER_ARRAY,
                            severity=Severity.MEDIUM,
                            confidence="MEDIUM",
                            evidence=f"{ptr_name} += {offset_text} at line {adv_line}, *{ptr_name} at line {line}",
                            description=f"Pointer '{ptr_name}' is advanced by '{offset_text}' then dereferenced. "
                                        "If the offset exceeds the buffer bounds, this causes memory corruption.",
                        )
                        break  # one finding per deref


# --- Rule 8: Out-of-bounds risk: negative constant or subtraction in index ----

def rule_oob_index(tree: Node, source_bytes: bytes, filename: str) -> Generator[Finding, None, None]:
    """PTR-OOB-INDEX: Array subscript with negative constant, very large constant,
    or subtraction in index expression."""
    for sub in find_nodes(tree, "subscript_expression"):
        children = [c for c in sub.children if c.type not in ("[", "]")]
        if len(children) < 2:
            continue
        index_node = children[1]
        index_text = get_node_text(index_node)

        flagged = False
        reason = ""

        # Negative literal
        if is_number_literal(index_node):
            try:
                val = int(index_text, 0)
                if val < 0:
                    flagged = True
                    reason = f"Negative index {val}"
                elif val >= 65536:
                    flagged = True
                    reason = f"Very large constant index {val}"
            except ValueError:
                pass
        # Unary minus: -(expr)
        elif index_node.type == "unary_expression":
            if any(c.type == "-" for c in index_node.children):
                flagged = True
                reason = f"Negative index expression: {index_text}"
        # Subtraction in index
        elif index_node.type == "binary_expression":
            if any(c.type == "-" for c in index_node.children):
                flagged = True
                reason = f"Subtraction in array index: {index_text}"

        if flagged:
            line, col = node_location(sub)
            yield Finding(
                file_path=filename, line_number=line, col_offset=col,
                line_content=get_source_line(source_bytes, line),
                vulnerability_name=f"Out-of-bounds risk: {reason}",
                rule_id="PTR-OOB-INDEX",
                category=VulnCategory.POINTER_ARRAY,
                severity=Severity.MEDIUM,
                confidence="MEDIUM",
                evidence=get_node_text(sub),
                description="Array index may be out of bounds. Validate index before use.",
            )


# --- Rule 9: Signed/unsigned mismatch ----------------------------------------

SIGNED_TYPES = {"int", "short", "long", "long long", "char", "signed char",
                "int8_t", "int16_t", "int32_t", "int64_t", "ssize_t", "ptrdiff_t"}
UNSIGNED_TYPES = {"unsigned", "unsigned int", "unsigned short", "unsigned long",
                  "unsigned long long", "unsigned char", "size_t",
                  "uint8_t", "uint16_t", "uint32_t", "uint64_t", "uintptr_t"}


def _extract_declarator_name(node: Node) -> Optional[str]:
    """Extract the variable name from a declarator node (init_declarator, plain identifier,
    pointer_declarator, array_declarator). Returns the declared name, not RHS values."""
    if node.type == "identifier":
        return get_node_text(node)
    if node.type == "pointer_declarator":
        # pointer_declarator -> * identifier  OR  * pointer_declarator
        for child in node.children:
            if child.type == "identifier":
                return get_node_text(child)
            if child.type in ("pointer_declarator", "function_declarator", "array_declarator"):
                return _extract_declarator_name(child)
    if node.type == "array_declarator":
        # array_declarator -> identifier [ size ]
        for child in node.children:
            if child.type == "identifier":
                return get_node_text(child)
    if node.type == "init_declarator":
        # init_declarator -> declarator = initializer
        # The declarator is the first child (before '=')
        if node.children:
            return _extract_declarator_name(node.children[0])
    if node.type == "function_declarator":
        for child in node.children:
            if child.type == "identifier":
                return get_node_text(child)
    return None


def _build_var_type_map(func_body: Node) -> Dict[str, str]:
    """Build a variable-name -> type-string map from declarations in a function body."""
    type_map: Dict[str, str] = {}
    for decl in find_nodes(func_body, "declaration"):
        dtype = get_declared_type(decl)
        if not dtype:
            continue
        # Extract declarator names from direct children (not recursing into RHS)
        for child in decl.children:
            if child.type in ("init_declarator", "identifier", "pointer_declarator",
                              "array_declarator"):
                name = _extract_declarator_name(child)
                if name:
                    type_map[name] = dtype
    # Also check function parameters
    func_node = func_body.parent
    if func_node and func_node.type == "function_definition":
        for param_decl in find_nodes(func_node, "parameter_declaration"):
            ptype = get_declared_type(param_decl)
            if not ptype:
                continue
            for child in param_decl.children:
                name = _extract_declarator_name(child)
                if name:
                    type_map[name] = ptype
    return type_map


def rule_sign_compare(tree: Node, source_bytes: bytes, filename: str) -> Generator[Finding, None, None]:
    """INT-SIGN-COMPARE: Signed/unsigned comparison mismatch.
    Limitation: relies on declared type names; typedef'd types are not resolved."""
    for func in find_nodes_multi(tree, {"function_definition"}):
        body = get_child_by_type(func, "compound_statement")
        if not body:
            continue
        type_map = _build_var_type_map(body)

        for binexpr in find_nodes(body, "binary_expression"):
            ops = [c for c in binexpr.children if c.type in ("<", ">", "<=", ">=", "==", "!=")]
            if not ops:
                continue
            operands = [c for c in binexpr.children if c.type not in ("<", ">", "<=", ">=", "==", "!=")]
            if len(operands) != 2:
                continue
            types = []
            for op in operands:
                if is_identifier(op):
                    t = type_map.get(get_node_text(op), "")
                    types.append(t)
                else:
                    types.append("")
            if not types[0] or not types[1]:
                continue
            sign0 = type_signed(types[0])
            sign1 = type_signed(types[1])
            if sign0 is None or sign1 is None:
                continue
            if sign0 != sign1:
                line, col = node_location(binexpr)
                yield Finding(
                    file_path=filename, line_number=line, col_offset=col,
                    line_content=get_source_line(source_bytes, line),
                    vulnerability_name=f"Signed/unsigned comparison: {types[0]} vs {types[1]}",
                    rule_id="INT-SIGN-COMPARE",
                    category=VulnCategory.INTEGER_ISSUE,
                    severity=Severity.MEDIUM,
                    confidence="MEDIUM",
                    evidence=get_node_text(binexpr),
                    description="Comparing signed and unsigned integers can produce unexpected results "
                                "when the signed value is negative.",
                )


# --- Rule 10: Narrowing conversions ------------------------------------------

def rule_narrowing(tree: Node, source_bytes: bytes, filename: str) -> Generator[Finding, None, None]:
    """INT-NARROW: Assigning a wider type to a narrower type, or casting larger to smaller.
    Limitation: only catches assignments where both sides have known types."""
    for func in find_nodes_multi(tree, {"function_definition"}):
        body = get_child_by_type(func, "compound_statement")
        if not body:
            continue
        type_map = _build_var_type_map(body)

        # Check init_declarator: type narrow_var = wide_var;
        for decl in find_nodes(body, "declaration"):
            dst_type = get_declared_type(decl)
            dst_width = type_width(dst_type)
            if dst_width == 0:
                continue
            # Skip char-width and float destinations — too noisy for real codebases
            if dst_width == 8 or dst_type == "float":
                continue
            for init in find_nodes(decl, "init_declarator"):
                children = init.children
                if len(children) < 3:
                    continue
                rhs = children[-1]
                if is_identifier(rhs):
                    src_type = type_map.get(get_node_text(rhs), "")
                    src_width = type_width(src_type)
                    if src_width > dst_width and src_width > 0:
                        line, col = node_location(init)
                        yield Finding(
                            file_path=filename, line_number=line, col_offset=col,
                            line_content=get_source_line(source_bytes, line),
                            vulnerability_name=f"Narrowing conversion: {src_type} ({src_width}-bit) -> {dst_type} ({dst_width}-bit)",
                            rule_id="INT-NARROW",
                            category=VulnCategory.INTEGER_ISSUE,
                            severity=Severity.MEDIUM,
                            confidence="MEDIUM",
                            evidence=get_node_text(init),
                            description="Value may be truncated. Use explicit bounds check or safe cast.",
                        )

        # Check cast_expression: (int)size_t_var  (C-style)
        for cast in find_nodes(body, "cast_expression"):
            type_desc = get_child_by_type(cast, "type_descriptor")
            if not type_desc:
                continue
            cast_type_node = get_child_by_type(type_desc, "primitive_type")
            if not cast_type_node:
                # tree-sitter parses 'short', 'long', etc. as sized_type_specifier
                cast_type_node = get_child_by_type(type_desc, "sized_type_specifier")
            if not cast_type_node:
                continue
            dst_type = get_node_text(cast_type_node)
            dst_width = type_width(dst_type)
            if dst_width == 0:
                continue
            # Skip casts to char/unsigned char — almost always intentional byte operations
            # e.g., (unsigned char) ReadBlobByte(), (char) c
            if dst_width == 8:
                continue
            # Skip float←double casts — intentional precision reduction, not a vulnerability
            if dst_type == "float":
                continue
            # The casted expression
            operand = cast.children[-1] if cast.children else None
            if operand and is_identifier(operand):
                src_type = type_map.get(get_node_text(operand), "")
                src_width = type_width(src_type)
                if src_width > dst_width and src_width > 0:
                    line, col = node_location(cast)
                    yield Finding(
                        file_path=filename, line_number=line, col_offset=col,
                        line_content=get_source_line(source_bytes, line),
                        vulnerability_name=f"Narrowing cast: {src_type} ({src_width}-bit) -> {dst_type} ({dst_width}-bit)",
                        rule_id="INT-NARROW",
                        category=VulnCategory.INTEGER_ISSUE,
                        severity=Severity.MEDIUM,
                        confidence="HIGH",
                        evidence=get_node_text(cast),
                        description="Explicit cast truncates value. Ensure upper bits are not significant.",
                    )


# --- Rule 11: Integer overflow in allocation size ----------------------------

def rule_alloc_overflow(tree: Node, source_bytes: bytes, filename: str) -> Generator[Finding, None, None]:
    """INT-OVERFLOW-ALLOC: malloc(a * b) or similar where a or b are variables,
    risking integer overflow before allocation.
    Also catches patterns like malloc(n + k) with variable n."""
    alloc_names = ALLOC_FUNCS | {"realloc"}
    for call in find_nodes(tree, "call_expression"):
        fname = get_call_name(call)
        if fname not in alloc_names:
            continue
        args = get_call_args(call)
        if not args:
            continue
        # For realloc, size is second arg; for others, first (or only)
        size_arg = args[1] if fname == "realloc" and len(args) > 1 else args[0]

        # Check if size_arg contains a binary * or + with at least one variable operand
        if size_arg.type == "binary_expression":
            ops = [c for c in size_arg.children if c.type in ("*", "+")]
            operands = [c for c in size_arg.children if c.type not in ("*", "+")]
            if ops:
                has_variable = any(
                    is_identifier(o) and get_node_text(o) != "sizeof"
                    for o in operands
                )
                # At least one operand is not sizeof and not a constant
                non_const = [o for o in operands
                             if not is_number_literal(o)
                             and o.type != "sizeof_expression"
                             and not (o.type == "call_expression" and get_call_name(o) == "sizeof")]
                if has_variable and non_const:
                    line, col = node_location(call)
                    yield Finding(
                        file_path=filename, line_number=line, col_offset=col,
                        line_content=get_source_line(source_bytes, line),
                        vulnerability_name=f"Integer overflow risk in allocation: {fname}({get_node_text(size_arg)})",
                        rule_id="INT-OVERFLOW-ALLOC",
                        category=VulnCategory.INTEGER_ISSUE,
                        severity=Severity.HIGH,
                        confidence="MEDIUM",
                        evidence=get_node_text(call),
                        description="Arithmetic in allocation size may overflow, causing undersized allocation. "
                                    "Use safe multiplication (e.g., calloc, or check overflow before malloc).",
                    )


# --- Rule 11b: Unsigned integer underflow (subtraction wrap) ------------------

UNSIGNED_TYPES_SET = {"size_t", "unsigned", "unsigned int", "unsigned long",
                      "unsigned long long", "unsigned short", "unsigned char",
                      "uint8_t", "uint16_t", "uint32_t", "uint64_t", "uintptr_t"}


def rule_unsigned_underflow(tree: Node, source_bytes: bytes, filename: str) -> Generator[Finding, None, None]:
    """INT-UNDERFLOW: Unsigned subtraction that may wrap to a huge value.
    Detects: unsigned_type x = a - b; or x = a - CONST where x is unsigned.
    Limitation: only catches declarations with init, not bare assignments, unless
    the variable type is known from a prior declaration."""
    for func in find_nodes_multi(tree, {"function_definition"}):
        body = get_child_by_type(func, "compound_statement")
        if not body:
            continue
        type_map = _build_var_type_map(body)

        # Pattern A: size_t remaining = commandLength - DWORD;
        for decl in find_nodes(body, "declaration"):
            dtype = get_declared_type(decl)
            if dtype not in UNSIGNED_TYPES_SET:
                continue
            for init in find_nodes(decl, "init_declarator"):
                if len(init.children) < 3:
                    continue
                rhs = init.children[-1]
                if rhs.type != "binary_expression":
                    continue
                has_minus = any(c.type == "-" for c in rhs.children)
                if not has_minus:
                    continue
                operands = [c for c in rhs.children if c.type != "-"]
                # At least one operand should be a variable (not both constants)
                has_variable = any(is_identifier(o) for o in operands)
                if not has_variable:
                    continue
                line, col = node_location(init)
                var_name = _extract_declarator_name(init)
                yield Finding(
                    file_path=filename, line_number=line, col_offset=col,
                    line_content=get_source_line(source_bytes, line),
                    vulnerability_name=f"Unsigned integer underflow: {dtype} subtraction may wrap",
                    rule_id="INT-UNDERFLOW",
                    category=VulnCategory.INTEGER_ISSUE,
                    severity=Severity.CRITICAL,
                    confidence="HIGH",
                    evidence=get_node_text(init),
                    description=f"'{get_node_text(rhs)}' is stored in unsigned type '{dtype}'. "
                                "If the subtrahend exceeds the minuend, the result wraps to a "
                                "very large value. Validate operands before subtraction.",
                )

        # Pattern B: assignment where LHS variable is known to be unsigned
        for assign in find_nodes(body, "assignment_expression"):
            if len(assign.children) < 3:
                continue
            lhs = assign.children[0]
            op = assign.children[1] if len(assign.children) > 1 else None
            rhs = assign.children[-1]
            # Handle x = a - b  (op is "=")
            # Handle x -= b     (op is "-=")
            if op and get_node_text(op) == "-=" and is_identifier(lhs):
                lhs_type = type_map.get(get_node_text(lhs), "")
                if lhs_type in UNSIGNED_TYPES_SET:
                    line, col = node_location(assign)
                    yield Finding(
                        file_path=filename, line_number=line, col_offset=col,
                        line_content=get_source_line(source_bytes, line),
                        vulnerability_name=f"Unsigned integer underflow: {lhs_type} -= may wrap",
                        rule_id="INT-UNDERFLOW",
                        category=VulnCategory.INTEGER_ISSUE,
                        severity=Severity.CRITICAL,
                        confidence="HIGH",
                        evidence=get_node_text(assign),
                        description=f"Subtracting from unsigned variable '{get_node_text(lhs)}' ({lhs_type}) "
                                    "can wrap to a huge value if the subtrahend exceeds it.",
                    )


# --- Rule 11c: Unvalidated size from network byte conversion -----------------

# Functions that convert raw bytes to integers (network/wire format parsing).
# If the result is used as a size in memcpy/memdup without bounds checking,
# an attacker can cause heap over-read/over-write.
BYTE_CONVERSION_FUNCS = {
    "dwordToIntBe", "ntohl", "ntohs", "htonl", "htons",
    "be32toh", "be16toh", "le32toh", "le16toh",
    "be64toh", "le64toh",
    "ntohll", "htonll",
    "ByteSwap32", "ByteSwap16",
    # Common custom patterns — snake_case and camelCase variants
    "readUint32", "readUint16", "readInt32", "readInt16",
    "readU32BE", "readU16BE", "readU32LE", "readU16LE",
    "readU32", "readU16", "readU64",
    "read_u32", "read_u16", "read_be32", "read_le32",
    "read_uint32", "read_uint16",
    "decode_u32", "decode_u16", "decode_uint32", "decode_uint16",
    "parseU32", "parseU16", "parse_u32", "parse_u16",
    "getUint32", "getUint16", "get_u32", "get_u16",
}

MEMCPY_LIKE = {"memcpy", "memmove", "memdup", "wmemcpy", "wmemmove",
               "CopyMemory", "RtlCopyMemory", "bcopy",
               # Custom memory-copy wrappers
               "safedup", "safe_memcpy", "mem_dup", "xmemdup"}


def rule_unvalidated_size(tree: Node, source_bytes: bytes, filename: str) -> Generator[Finding, None, None]:
    """MEM-UNVALIDATED-SIZE: memcpy/memdup/memmove using a size derived from a
    network byte-order conversion function without an intervening bounds check.
    Catches patterns like:
        uint32_t len = ntohl(*(uint32_t*)buf);
        memcpy(dst, src, len);   // <-- no check that len <= buffer_size
    Limitation: only detects within same function. The conversion->use chain is
    identified by variable name tracking, not full dataflow."""
    for func in find_nodes_multi(tree, {"function_definition"}):
        body = get_child_by_type(func, "compound_statement")
        if not body:
            continue

        # Step 1: Find variables assigned from byte-conversion calls
        # e.g., uint32_t outputFileLengthInt = dwordToIntBe(outputFileLength);
        converted_vars: Dict[str, Tuple[int, Node]] = {}  # var_name -> (byte_offset, decl_node)

        for decl in find_nodes(body, "declaration"):
            for init in find_nodes(decl, "init_declarator"):
                if len(init.children) < 3:
                    continue
                rhs = init.children[-1]
                # Direct call: dwordToIntBe(buf)
                if rhs.type == "call_expression":
                    fname = get_call_name(rhs)
                    base = fname.split("::")[-1] if "::" in fname else fname
                    if base in BYTE_CONVERSION_FUNCS:
                        var_name = _extract_declarator_name(init)
                        if var_name:
                            converted_vars[var_name] = (init.start_byte, init)
                # Cast wrapping call: (uint32_t)ntohl(...)
                if rhs.type == "cast_expression":
                    for inner_call in find_nodes(rhs, "call_expression"):
                        fname = get_call_name(inner_call)
                        base = fname.split("::")[-1] if "::" in fname else fname
                        if base in BYTE_CONVERSION_FUNCS:
                            var_name = _extract_declarator_name(init)
                            if var_name:
                                converted_vars[var_name] = (init.start_byte, init)

        if not converted_vars:
            continue

        # Step 2: Find memcpy/memdup/memmove calls where a converted variable
        # appears in the size argument (or in an expression containing it)
        for call in find_nodes(body, "call_expression"):
            fname = get_call_name(call)
            base = fname.split("::")[-1] if "::" in fname else fname
            if base not in MEMCPY_LIKE:
                continue
            args = get_call_args(call)
            if not args:
                continue
            # Size is typically the last argument
            size_arg = args[-1]
            size_text = get_node_text(size_arg)

            # Check if any converted variable appears in the size argument
            for cv_name, (cv_byte, cv_node) in converted_vars.items():
                if cv_name not in size_text:
                    continue
                # Check if there's a bounds-checking if-statement between conversion and use
                has_check = False
                for if_stmt in find_nodes(body, "if_statement"):
                    if if_stmt.start_byte <= cv_byte:
                        continue
                    if if_stmt.start_byte >= call.start_byte:
                        continue
                    cond = get_child_by_type(if_stmt, "parenthesized_expression")
                    if cond and cv_name in get_node_text(cond):
                        has_check = True
                        break
                if has_check:
                    continue

                line, col = node_location(call)
                cv_line = node_location(cv_node)[0]
                yield Finding(
                    file_path=filename, line_number=line, col_offset=col,
                    line_content=get_source_line(source_bytes, line),
                    vulnerability_name=f"Heap over-read/write: {base}() with unvalidated size from network data",
                    rule_id="MEM-UNVALIDATED-SIZE",
                    category=VulnCategory.MEMORY_SAFETY,
                    severity=Severity.CRITICAL,
                    confidence="HIGH",
                    evidence=f"'{cv_name}' from byte conversion at line {cv_line}, used as size in {base}() at line {line}",
                    description=f"'{cv_name}' is derived from a byte-conversion function (line {cv_line}) "
                                f"and used as a size in {base}() without bounds validation. "
                                "An attacker-controlled length can cause heap over-read/write.",
                )
                break  # one finding per call


# --- Rule 12a: system/popen/exec* usage --------------------------------------

EXEC_FUNCS = {
    "system", "popen", "execl", "execlp", "execle",
    "execv", "execvp", "execvpe", "execve",
    "_popen", "_wsystem", "WinExec", "ShellExecute", "ShellExecuteA", "ShellExecuteW",
    "CreateProcess", "CreateProcessA", "CreateProcessW",
}


def rule_dangerous_exec(tree: Node, source_bytes: bytes, filename: str) -> Generator[Finding, None, None]:
    """DANGER-EXEC: Calls to system(), popen(), exec*() family."""
    for call in find_nodes(tree, "call_expression"):
        name = get_call_name(call)
        base = name.split("::")[-1] if "::" in name else name
        if base in EXEC_FUNCS:
            args = get_call_args(call)
            # Lower severity if argument is a string literal (less likely injection)
            is_literal = args and is_string_literal(args[0]) if args else False
            line, col = node_location(call)
            yield Finding(
                file_path=filename, line_number=line, col_offset=col,
                line_content=get_source_line(source_bytes, line),
                vulnerability_name=f"Dangerous function: {base}()",
                rule_id="DANGER-EXEC",
                category=VulnCategory.DANGEROUS_FUNCTION,
                severity=Severity.HIGH if not is_literal else Severity.MEDIUM,
                confidence="HIGH" if not is_literal else "MEDIUM",
                evidence=get_node_text(call),
                description=f"{base}() can execute arbitrary commands. "
                            "Avoid if possible, or sanitize all inputs.",
            )


# --- Rule 12b: Format string issues ------------------------------------------

PRINTF_FUNCS = {
    "printf", "fprintf", "sprintf", "snprintf", "vprintf", "vfprintf",
    "vsprintf", "vsnprintf", "syslog", "wprintf", "fwprintf", "swprintf",
    "_tprintf",
}

# For printf-family, the format arg index varies:
# printf(fmt, ...)          -> fmt is arg 0
# fprintf(stream, fmt, ...) -> fmt is arg 1
# sprintf(buf, fmt, ...)    -> fmt is arg 1
# snprintf(buf, n, fmt, ...)->fmt is arg 2
FORMAT_ARG_INDEX = {
    "printf": 0, "vprintf": 0, "wprintf": 0, "syslog": 1, "_tprintf": 0,
    "fprintf": 1, "vfprintf": 1, "fwprintf": 1,
    "sprintf": 1, "vsprintf": 1, "swprintf": 1,
    "snprintf": 2, "vsnprintf": 2,
}


def rule_format_string(tree: Node, source_bytes: bytes, filename: str) -> Generator[Finding, None, None]:
    """DANGER-FORMAT: printf-family called with non-literal format string."""
    for call in find_nodes(tree, "call_expression"):
        name = get_call_name(call)
        base = name.split("::")[-1] if "::" in name else name
        if base not in PRINTF_FUNCS:
            continue
        args = get_call_args(call)
        fmt_idx = FORMAT_ARG_INDEX.get(base, 0)
        if fmt_idx >= len(args):
            continue
        fmt_arg = args[fmt_idx]
        if not is_string_literal(fmt_arg):
            line, col = node_location(call)
            yield Finding(
                file_path=filename, line_number=line, col_offset=col,
                line_content=get_source_line(source_bytes, line),
                vulnerability_name=f"Format string vulnerability: {base}() with non-literal format",
                rule_id="DANGER-FORMAT",
                category=VulnCategory.DANGEROUS_FUNCTION,
                severity=Severity.HIGH,
                confidence="HIGH",
                evidence=get_node_text(call),
                description=f"The format argument to {base}() is not a string literal. "
                            "An attacker-controlled format string enables arbitrary read/write.",
            )


# ============================================================================
# Rule registry
# ============================================================================

ALL_RULES = [
    rule_unsafe_copy,          # MEM-UNSAFE-COPY
    rule_buffer_oob,           # MEM-BUFFER-OOB
    rule_use_after_free,       # MEM-USE-AFTER-FREE
    rule_double_free,          # MEM-DOUBLE-FREE
    rule_return_local_addr,    # MEM-RETURN-LOCAL
    rule_dangling_ptr_return,  # MEM-DANGLING-PTR
    rule_null_deref,           # MEM-NULL-DEREF
    rule_unvalidated_size,     # MEM-UNVALIDATED-SIZE
    rule_pointer_arith,        # PTR-ARITH
    rule_oob_index,            # PTR-OOB-INDEX
    rule_sign_compare,         # INT-SIGN-COMPARE
    rule_narrowing,            # INT-NARROW
    rule_alloc_overflow,       # INT-OVERFLOW-ALLOC
    rule_unsigned_underflow,   # INT-UNDERFLOW
    rule_dangerous_exec,       # DANGER-EXEC
    rule_format_string,        # DANGER-FORMAT
]

# ============================================================================
# Scanner core
# ============================================================================

DEFAULT_EXTENSIONS = {".c", ".cpp", ".cc", ".cxx", ".h", ".hpp", ".hxx", ".hh"}
DEFAULT_MAX_BYTES = 5 * 1024 * 1024  # 5 MB

# Directories to always skip
SKIP_DIRS = {
    "node_modules", ".git", ".svn", "vendor", "third_party", "thirdparty",
    "build", "dist", "out", ".vscode", ".idea", "__pycache__",
}


def _choose_language(filename: str) -> Language:
    """Choose C or C++ grammar based on file extension."""
    ext = Path(filename).suffix.lower()
    if ext in (".cpp", ".cc", ".cxx", ".hpp", ".hxx", ".hh"):
        return CPP_LANG
    return C_LANG


def scan_file(file_path: str, max_bytes: int = DEFAULT_MAX_BYTES) -> List[Finding]:
    """Scan a single C/C++ file and return findings."""
    try:
        raw = Path(file_path).read_bytes()
    except (IOError, OSError) as e:
        print(f"Error reading {file_path}: {e}", file=sys.stderr)
        return []

    if len(raw) > max_bytes:
        print(f"Skipping {file_path}: exceeds {max_bytes} bytes", file=sys.stderr)
        return []

    lang = _choose_language(file_path)
    parser = Parser(lang)
    tree = parser.parse(raw)

    if tree.root_node.has_error:
        # Continue scanning despite parse errors; tree-sitter does error recovery
        pass

    findings: List[Finding] = []
    for rule_fn in ALL_RULES:
        try:
            for finding in rule_fn(tree.root_node, raw, file_path):
                findings.append(finding)
        except Exception as e:
            print(f"Rule {rule_fn.__name__} failed on {file_path}: {e}", file=sys.stderr)

    return findings


def scan_path(target: str, extensions: Set[str] = None,
              max_bytes: int = DEFAULT_MAX_BYTES,
              show_progress: bool = True) -> Tuple[List[Finding], int, float]:
    """Scan a file or directory. Returns (findings, file_count, elapsed_seconds)."""
    if extensions is None:
        extensions = DEFAULT_EXTENSIONS

    all_findings: List[Finding] = []
    target_path = Path(target)
    file_count = 0
    start = time.time()

    if target_path.is_file():
        if target_path.suffix.lower() in extensions:
            if show_progress:
                with Progress(
                    SpinnerColumn("moon"),
                    TextColumn("[bold cyan]Parsing AST...[/bold cyan]"),
                    TextColumn("[dim]{task.fields[file]}[/dim]"),
                    console=console, transient=True,
                ) as progress:
                    task = progress.add_task("Scanning", total=1, file=target_path.name)
                    all_findings.extend(scan_file(str(target_path), max_bytes))
                    progress.advance(task)
            else:
                all_findings.extend(scan_file(str(target_path), max_bytes))
            file_count = 1
        else:
            console.print(f"[bold yellow]Warning:[/bold yellow] {target} does not match extensions {extensions}")
    elif target_path.is_dir():
        c_files = []
        for ext in extensions:
            for p in sorted(target_path.rglob(f"*{ext}")):
                # Skip vendor / build directories
                parts = set(p.parts)
                if parts & SKIP_DIRS:
                    continue
                c_files.append(p)
        # Deduplicate (in case rglob returns overlapping results)
        c_files = sorted(set(c_files))
        file_count = len(c_files)

        if show_progress and c_files:
            with Progress(
                SpinnerColumn("moon"),
                TextColumn("[bold cyan]{task.description}[/bold cyan]"),
                BarColumn(bar_width=30, style="cyan", complete_style="green"),
                MofNCompleteColumn(),
                TextColumn("[dim]{task.fields[current_file]}[/dim]"),
                console=console, transient=True,
            ) as progress:
                task = progress.add_task("Scanning", total=len(c_files), current_file="")
                for cf in c_files:
                    progress.update(task, current_file=cf.name)
                    all_findings.extend(scan_file(str(cf), max_bytes))
                    progress.advance(task)
        else:
            for cf in c_files:
                all_findings.extend(scan_file(str(cf), max_bytes))
    else:
        console.print(f"[bold red]Error:[/bold red] {target} does not exist")

    elapsed = time.time() - start
    return all_findings, file_count, elapsed


def filter_findings(findings: List[Finding], min_severity: str = None,
                    min_confidence: str = None) -> List[Finding]:
    result = findings
    if min_severity:
        sev = Severity[min_severity.upper()]
        min_sev_order = SEVERITY_ORDER[sev]
        result = [f for f in result if SEVERITY_ORDER[f.severity] >= min_sev_order]
    if min_confidence:
        min_conf_order = CONFIDENCE_ORDER.get(min_confidence.upper(), 0)
        result = [f for f in result if CONFIDENCE_ORDER.get(f.confidence, 0) >= min_conf_order]
    return result


# ============================================================================
# Output: Rich terminal UI
# ============================================================================

def _print_banner():
    banner_lines = [
        " ██████╗ ██████╗██████╗ ██████╗ ",
        "██╔════╝██╔════╝██╔══██╗██╔══██╗",
        "██║     ██║     ██████╔╝██████╔╝",
        "██║     ██║     ██╔═══╝ ██╔═══╝ ",
        "╚██████╗╚██████╗██║     ██║     ",
        " ╚═════╝ ╚═════╝╚═╝     ╚═╝     ",
    ]
    banner_text = "\n".join(banner_lines)

    title_content = Text()
    title_content.append(banner_text, style="bold red")
    title_content.append("\n\n")
    title_content.append("C/C++ Tree-sitter AST Vulnerability Scanner v1.0\n", style="bold white")
    title_content.append("Memory Safety | Integer Issues | Pointer Bugs | Dangerous Functions", style="dim")

    console.print()
    console.print(Panel(
        Align.center(title_content),
        border_style="red",
        box=box.DOUBLE,
        padding=(1, 4),
    ))
    console.print()


def _build_stats_sidebar(findings: List[Finding], file_count: int, elapsed: float) -> Panel:
    stats = Table(show_header=False, box=None, padding=(0, 1), expand=True)
    stats.add_column("key", style="bold cyan", no_wrap=True, ratio=3)
    stats.add_column("value", style="white", ratio=1)

    stats.add_row("Files Scanned", str(file_count))
    stats.add_row("Total Findings", str(len(findings)))
    stats.add_row("Scan Time", f"{elapsed:.2f}s")
    stats.add_row("Engine", "tree-sitter AST (C/C++)")
    stats.add_row("", "")

    sev_counts = defaultdict(int)
    for f in findings:
        sev_counts[f.severity.value] += 1

    sev_styles = {
        "CRITICAL": "bold red", "HIGH": "red",
        "MEDIUM": "yellow", "LOW": "green", "INFO": "dim",
    }
    for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
        count = sev_counts.get(sev, 0)
        if count > 0:
            stats.add_row(Text(sev, style=sev_styles.get(sev, "white")), str(count))

    stats.add_row("", "")

    cat_counts = defaultdict(int)
    for f in findings:
        cat_counts[f.category.value] += 1
    for cat, count in sorted(cat_counts.items(), key=lambda x: -x[1]):
        stats.add_row(Text(cat, style="cyan"), str(count))

    return Panel(
        stats,
        title="[bold white]Scan Statistics[/bold white]",
        border_style="cyan",
        box=box.ROUNDED,
        padding=(1, 1),
    )


def _syntax_lang(filename: str) -> str:
    ext = Path(filename).suffix.lower()
    if ext in (".cpp", ".cc", ".cxx", ".hpp", ".hxx", ".hh"):
        return "cpp"
    return "c"


def _build_finding_panel(f: Finding, source_code: Optional[str] = None) -> Panel:
    sev = f.severity.value
    border_map = {
        "CRITICAL": "bold red", "HIGH": "red",
        "MEDIUM": "yellow", "LOW": "green", "INFO": "dim white",
    }
    border_style = border_map.get(sev, "white")

    sev_style_map = {
        "CRITICAL": "bold white on red", "HIGH": "bold red",
        "MEDIUM": "bold yellow", "LOW": "bold green", "INFO": "dim",
    }

    title = Text()
    title.append(f" {sev} ", style=sev_style_map.get(sev, "white"))
    title.append(f" [{f.rule_id}] {f.vulnerability_name} ", style="bold white")
    title.append(f" Confidence: {f.confidence} ", style="dim")

    content_parts = []

    source_text = Text()
    source_text.append("Source: ", style="bold cyan")
    source_text.append(f"Line {f.line_number}", style="white")
    if f.col_offset:
        source_text.append(f", Col {f.col_offset}", style="dim")

    cat_text = Text()
    cat_text.append("Category: ", style="bold magenta")
    cat_text.append(f"{f.category.value}", style="white")

    content_parts.append(Columns([source_text, cat_text], padding=(0, 4)))

    if f.description:
        desc = Text()
        desc.append(f"\n{f.description}", style="italic white")
        content_parts.append(desc)

    if f.evidence:
        ev = Text()
        ev.append("\nEvidence: ", style="bold cyan")
        ev.append(f.evidence, style="white")
        content_parts.append(ev)

    code_line = f.line_content.strip()
    if code_line:
        lang = _syntax_lang(f.file_path)
        if source_code:
            src_lines = source_code.split("\n")
            start = max(0, f.line_number - 3)
            end = min(len(src_lines), f.line_number + 2)
            snippet = "\n".join(src_lines[start:end])
            syntax = Syntax(
                snippet, lang, theme="monokai",
                line_numbers=True, start_line=start + 1,
                highlight_lines={f.line_number},
            )
        else:
            syntax = Syntax(
                code_line, lang, theme="monokai",
                line_numbers=True, start_line=f.line_number,
            )
        content_parts.append(Text(""))
        content_parts.append(syntax)

    panel_content = Group(*content_parts)

    return Panel(
        panel_content,
        title=title,
        border_style=border_style,
        box=box.ROUNDED,
        padding=(1, 2),
    )


def output_rich(findings: List[Finding], target: str, file_count: int,
                elapsed: float, min_confidence: str):
    scan_date = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    header_text = Text()
    header_text.append("Target: ", style="bold cyan")
    header_text.append(f"{target}  ", style="white")
    header_text.append("Date: ", style="bold cyan")
    header_text.append(f"{scan_date}  ", style="white")
    header_text.append("Confidence: ", style="bold cyan")
    header_text.append(f">= {min_confidence}", style="white")

    console.print(Panel(
        Align.center(header_text),
        title="[bold white]Scan Info[/bold white]",
        border_style="blue",
        box=box.ROUNDED,
    ))
    console.print()

    sidebar = _build_stats_sidebar(findings, file_count, elapsed)
    console.print(sidebar)
    console.print()

    if findings:
        console.print(Rule("[bold white]Vulnerability Findings[/bold white]", style="red"))
        console.print()

        source_cache: Dict[str, str] = {}
        findings_by_file = defaultdict(list)
        for f in findings:
            findings_by_file[f.file_path].append(f)

        for file_path, file_findings in sorted(findings_by_file.items()):
            console.print(Text(f"FILE: {file_path}", style="bold underline cyan"))
            console.print()

            if file_path not in source_cache:
                try:
                    source_cache[file_path] = Path(file_path).read_text(
                        encoding="utf-8", errors="ignore"
                    )
                except Exception:
                    pass

            src = source_cache.get(file_path)
            for f in sorted(file_findings, key=lambda x: x.line_number):
                panel = _build_finding_panel(f, source_code=src)
                console.print(panel)
                console.print()
    else:
        console.print(Panel(
            Align.center(Text("No vulnerabilities found.", style="bold green")),
            border_style="green",
            box=box.ROUNDED,
            padding=(1, 4),
        ))


def output_text_plain(findings: List[Finding], file_path: str):
    with open(file_path, "w", encoding="utf-8") as out:
        for f in findings:
            out.write(f"\n{'='*70}\n")
            out.write(f"  [{f.severity.value}] [{f.confidence}] [{f.rule_id}] {f.vulnerability_name}\n")
            out.write(f"  File: {f.file_path}:{f.line_number}\n")
            out.write(f"  Code: {f.line_content.strip()}\n")
            out.write(f"  Category: {f.category.value}\n")
            if f.evidence:
                out.write(f"  Evidence: {f.evidence}\n")
            if f.description:
                out.write(f"  Description: {f.description}\n")

        out.write(f"\n{'='*70}\n")
        out.write(f"Total findings: {len(findings)}\n")

        by_sev = defaultdict(int)
        by_cat = defaultdict(int)
        for f in findings:
            by_sev[f.severity.value] += 1
            by_cat[f.category.value] += 1

        if by_sev:
            out.write("\nBy severity:\n")
            for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
                if sev in by_sev:
                    out.write(f"  {sev}: {by_sev[sev]}\n")
        if by_cat:
            out.write("\nBy category:\n")
            for cat, count in sorted(by_cat.items()):
                out.write(f"  {cat}: {count}\n")


def output_json(findings: List[Finding], file_path: str = None):
    data = {
        "scan_date": datetime.now().isoformat(),
        "scanner": "c_cpp-treesitter v1.0",
        "files_scanned": len(set(f.file_path for f in findings)) if findings else 0,
        "total_findings": len(findings),
        "findings": [
            {
                "rule_id": f.rule_id,
                "file": f.file_path,
                "line": f.line_number,
                "column": f.col_offset,
                "code": f.line_content.strip(),
                "vulnerability": f.vulnerability_name,
                "category": f.category.value,
                "severity": f.severity.value,
                "confidence": f.confidence,
                "evidence": f.evidence,
                "description": f.description,
            }
            for f in findings
        ],
        "summary": {
            "by_severity": {k: v for k, v in sorted(
                {sev: sum(1 for f in findings if f.severity.value == sev)
                 for sev in set(f.severity.value for f in findings)}.items()
            )} if findings else {},
            "by_category": {k: v for k, v in sorted(
                {cat: sum(1 for f in findings if f.category.value == cat)
                 for cat in set(f.category.value for f in findings)}.items()
            )} if findings else {},
            "by_rule": {k: v for k, v in sorted(
                {rid: sum(1 for f in findings if f.rule_id == rid)
                 for rid in set(f.rule_id for f in findings)}.items()
            )} if findings else {},
        },
    }

    json_str = json.dumps(data, indent=2)
    if file_path:
        with open(file_path, "w", encoding="utf-8") as fout:
            fout.write(json_str)
    else:
        print(json_str)


def output_jsonl(findings: List[Finding]):
    """Print one JSON finding per line (JSON Lines format)."""
    for f in findings:
        print(f.to_jsonl())
    # Summary line
    summary = {
        "_summary": True,
        "total": len(findings),
        "by_severity": {},
        "by_rule": {},
    }
    for f in findings:
        summary["by_severity"][f.severity.value] = summary["by_severity"].get(f.severity.value, 0) + 1
        summary["by_rule"][f.rule_id] = summary["by_rule"].get(f.rule_id, 0) + 1
    print(json.dumps(summary))


# ============================================================================
# CLI
# ============================================================================

def main():
    parser = argparse.ArgumentParser(
        description="C/C++ AST Vulnerability Scanner using Tree-sitter",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""\
vulnerability rules (16):
  Memory Safety
    MEM-UNSAFE-COPY       strcpy/strcat/sprintf/gets without bounds checking
    MEM-BUFFER-OOB        Array write with variable or unbounded index
    MEM-USE-AFTER-FREE    Pointer used after being freed
    MEM-DOUBLE-FREE       Same pointer freed twice
    MEM-RETURN-LOCAL      Return address of stack-local variable
    MEM-DANGLING-PTR      Pointer to stack-local returned via intermediate variable
    MEM-NULL-DEREF        malloc/calloc/realloc result used without NULL check
    MEM-UNVALIDATED-SIZE  Network byte-conversion value used as allocation/copy size

  Pointer / Array
    PTR-ARITH             Pointer dereference with computed offset *(p + n)
    PTR-OOB-INDEX         Negative constant or subtraction in array index

  Integer
    INT-SIGN-COMPARE      Signed vs unsigned comparison
    INT-NARROW            Implicit or explicit narrowing cast (e.g. long -> int)
    INT-OVERFLOW-ALLOC    Multiplication in malloc size argument may overflow
    INT-UNDERFLOW         Unsigned subtraction that may wrap around

  Dangerous Functions
    DANGER-EXEC           system()/popen()/exec*() with variable command string
    DANGER-FORMAT         printf-family call with non-literal format string

default: only CRITICAL severity + HIGH confidence findings are shown.
use --all to display every finding regardless of severity/confidence.
""",
    )
    parser.add_argument("target", help="C/C++ file or directory to scan")
    parser.add_argument("--output", choices=["text", "json"], default="text",
                        help="Output format (default: text)")
    parser.add_argument("-o", "--output-file", help="Write output to file")
    parser.add_argument("--jsonl", action="store_true",
                        help="Output JSON Lines (one finding per line)")
    parser.add_argument("--ext", default=None,
                        help="Comma-separated extensions to scan (default: .c,.cpp,.cc,.cxx,.h,.hpp,.hxx,.hh)")
    parser.add_argument("--max-bytes", type=int, default=DEFAULT_MAX_BYTES,
                        help=f"Skip files larger than N bytes (default: {DEFAULT_MAX_BYTES})")
    parser.add_argument("--min-severity",
                        choices=["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"],
                        help="Minimum severity to report")
    parser.add_argument("--min-confidence", choices=["HIGH", "MEDIUM", "LOW"],
                        help="Minimum confidence to report")
    parser.add_argument("--all", action="store_true",
                        help="Show all findings (no default filters)")
    parser.add_argument("--no-banner", action="store_true",
                        help="Suppress banner output")

    args = parser.parse_args()

    # Parse extensions
    extensions = DEFAULT_EXTENSIONS
    if args.ext:
        extensions = set()
        for e in args.ext.split(","):
            e = e.strip()
            if not e.startswith("."):
                e = "." + e
            extensions.add(e.lower())

    # Default filters
    min_severity = args.min_severity
    min_confidence = args.min_confidence
    if not args.all and not min_severity and not min_confidence:
        min_severity = "CRITICAL"
        min_confidence = "HIGH"

    is_json = args.output == "json" or args.jsonl

    if not args.no_banner and not is_json:
        _print_banner()

    findings, file_count, elapsed = scan_path(
        args.target,
        extensions=extensions,
        max_bytes=args.max_bytes,
        show_progress=not is_json,
    )
    findings = filter_findings(findings, min_severity, min_confidence)
    findings.sort(key=lambda f: (f.file_path, f.line_number))

    if args.jsonl:
        output_jsonl(findings)
    elif is_json:
        output_json(findings, args.output_file)
    else:
        output_rich(findings, args.target, file_count, elapsed, min_confidence or "HIGH")
        if args.output_file:
            output_text_plain(findings, args.output_file)
            console.print(f"\n[bold green]Report saved to {args.output_file}[/bold green]")

    # Exit with error code if critical/high findings
    critical_high = sum(1 for f in findings if f.severity in (Severity.CRITICAL, Severity.HIGH))
    if critical_high > 0:
        sys.exit(1)


if __name__ == "__main__":
    main()
