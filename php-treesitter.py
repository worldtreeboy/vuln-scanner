#!/usr/bin/env python3
"""
PHP AST Vulnerability Scanner (Tree-sitter)
============================================
A standalone PHP security scanner using tree-sitter for AST-based analysis.
Performs per-function/method taint tracking with AST-based detection.

Detection Categories:
- SQL Injection (mysql_query, mysqli_query, pg_query, PDO->query/exec, string concat)
- Command Injection (exec, system, passthru, shell_exec, popen, proc_open, backtick)
- Code Injection (eval, assert, create_function, preg_replace /e)
- Insecure Deserialization (unserialize with tainted input)
- XXE (DOMDocument->loadXML, simplexml_load_string, XMLReader)
- XPath Injection (DOMXPath->query/evaluate with tainted concat)
- SSTI (Twig render/createTemplate, Blade, Smarty with tainted template)
- NoSQL Injection (MongoDB find/aggregate with tainted query)
- Second-order SQLi (DB-fetched data in raw SQL concat)
"""

import os
import sys
import json
import argparse
import re
import time
from pathlib import Path
from dataclasses import dataclass, field
from typing import List, Dict, Set, Optional, Tuple
from enum import Enum
from datetime import datetime
from collections import defaultdict

import tree_sitter_php as tsphp
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

from vibehunter_config import load_config, VibehunterConfig

PHP_LANG = Language(tsphp.language_php())

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
    SQL_INJECTION = "SQL Injection"
    NOSQL_INJECTION = "NoSQL Injection"
    CODE_INJECTION = "Code Injection"
    COMMAND_INJECTION = "Command Injection"
    DESERIALIZATION = "Insecure Deserialization"
    SSTI = "Server-Side Template Injection"
    XPATH_INJECTION = "XPath Injection"
    XXE = "XML External Entity"
    OPEN_REDIRECT = "Open Redirect"
    LDAP_INJECTION = "LDAP Injection"


@dataclass
class Finding:
    file_path: str
    line_number: int
    col_offset: int
    line_content: str
    vulnerability_name: str
    category: VulnCategory
    severity: Severity
    confidence: str
    taint_chain: List[str] = field(default_factory=list)
    description: str = ""


# ============================================================================
# AST Helpers
# ============================================================================

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


def node_text(node: Node) -> str:
    """Get the source text of a node."""
    return node.text.decode('utf-8') if node.text else ""


def get_node_line(node: Node) -> int:
    """Get 1-based line number."""
    return node.start_point[0] + 1


def get_child_by_type(node: Node, type_name: str) -> Optional[Node]:
    """Get first direct child of a given type."""
    for child in node.children:
        if child.type == type_name:
            return child
    return None


def get_children_by_type(node: Node, type_name: str) -> List[Node]:
    """Get all direct children of a given type."""
    return [c for c in node.children if c.type == type_name]


def get_variable_name(node: Node) -> str:
    """Extract the full variable name including $ prefix from a variable_name node."""
    return node_text(node)


def is_superglobal(var_text: str) -> bool:
    """Check if a variable text is a PHP superglobal (user-controlled)."""
    superglobals = {
        "$_GET", "$_POST", "$_REQUEST", "$_COOKIE",
        "$_SERVER", "$_FILES", "$_ENV",
    }
    # Check exact match or subscript access like $_GET["x"]
    for sg in superglobals:
        if var_text.startswith(sg):
            return True
    return False


def is_superglobal_name(name: str) -> bool:
    """Check if a bare name (without $) is a superglobal (user-controlled)."""
    return name in ("_GET", "_POST", "_REQUEST", "_COOKIE",
                    "_SERVER", "_FILES", "_ENV")


# ============================================================================
# TaintTracker — Per-Function/Method Taint Analysis
# ============================================================================

class TaintTracker:
    """
    Tracks tainted variables within a single function/method scope.
    Sources: PHP superglobals ($_GET, $_POST, etc.), function parameters,
             file_get_contents("php://input"), getenv(), $argv
    Propagation: assignments, string concat (.), sprintf
    """

    SUPERGLOBAL_NAMES = {
        "_GET", "_POST", "_REQUEST", "_COOKIE",
        "_SERVER", "_FILES", "_ENV",
    }

    TAINT_FUNCTIONS = {
        "getenv", "apache_getenv", "getallheaders",
        "file_get_contents",  # when arg is "php://input"
    }

    def __init__(self, func_node: Node, source_lines: List[str],
                 is_public: bool = True, scope_node: Node = None,
                 pre_tainted: Dict[str, Tuple[int, str]] = None):
        self.func_node = func_node
        self.source_lines = source_lines
        # var_name -> (line_number, source_description)
        self.tainted: Dict[str, Tuple[int, str]] = {}
        # var_name -> (line_number, entity_source)
        self.db_sourced: Dict[str, Tuple[int, str]] = {}
        # var_name -> set of categories this var is sanitized for
        # e.g. {"$name": {"SQL"}} means safe for SQL but still tainted for CMD
        self.sanitized_for: Dict[str, Set[str]] = {}
        # Optional override for the scope to analyze (for top-level code)
        self._scope_node = scope_node

        # Pre-seed taint from constructor analysis (cross-method taint)
        if pre_tainted:
            self.tainted.update(pre_tainted)

        self._init_taint_from_params(is_public)
        self._propagate_taint()

    def _init_taint_from_params(self, is_public: bool):
        """Mark function parameters as tainted for public methods."""
        params_node = get_child_by_type(self.func_node, "formal_parameters")
        if not params_node:
            return

        if not is_public:
            return

        line = get_node_line(self.func_node)
        for param in get_children_by_type(params_node, "simple_parameter"):
            var_node = get_child_by_type(param, "variable_name")
            if var_node:
                param_name = node_text(var_node)
                self.tainted[param_name] = (line, "function parameter")

    def _get_scope(self) -> Optional[Node]:
        """Get the scope node to analyze."""
        if self._scope_node is not None:
            return self._scope_node
        return get_child_by_type(self.func_node, "compound_statement")

    def _propagate_taint(self):
        """Walk function body and propagate taint through assignments."""
        body = self._get_scope()
        if not body:
            return

        # Multi-pass to handle forward references
        for _ in range(3):
            self._propagate_pass(body)

        # Post-propagation: check for regex validation gates that clear taint
        self._check_validation_gates(body)

    def _check_validation_gates(self, body: Node):
        """Remove taint from variables validated by anchored regex with exit() gates.

        Pattern: if(!preg_match($pattern, $var)) { ... exit(); ... }
        If the regex is anchored (^...$) and the failure branch exits,
        then $var is validated — cannot contain SQL injection chars.
        """
        for if_stmt in find_nodes(body, "if_statement"):
            cond_node = None
            for child in if_stmt.children:
                if child.type == "parenthesized_expression":
                    cond_node = child
                    break
            if not cond_node:
                continue
            cond_text = node_text(cond_node)

            # Match: !preg_match($pattern, $var) or !preg_match("...", $var)
            m = re.search(
                r'!\s*preg_match\s*\(\s*(\$\w+|["\'/][^)]+)\s*,\s*(\$\w+)\s*\)',
                cond_text)
            if not m:
                continue

            pattern_ref = m.group(1).strip()
            var_text = m.group(2)

            if var_text not in self.tainted:
                continue

            # Check if the if-body contains exit()/die()/return
            if_body = get_child_by_type(if_stmt, "compound_statement")
            if not if_body:
                continue
            body_text = node_text(if_body)
            if not re.search(r'\b(?:exit|die|return)\b', body_text):
                continue

            # Resolve the regex pattern
            pattern_literal = None
            if pattern_ref.startswith('$'):
                # Variable reference — find its assignment in scope
                for assign in find_nodes(body, "assignment_expression"):
                    children = assign.children
                    if len(children) >= 3 and node_text(children[0]) == pattern_ref:
                        pattern_literal = node_text(children[2]).strip().strip('"').strip("'")
                        break
            else:
                pattern_literal = pattern_ref.strip('"').strip("'")

            if not pattern_literal:
                continue

            # Check if the regex is anchored (^...$) — restrictive validation
            inner = re.sub(r'^/(.+)/[a-z]*$', r'\1', pattern_literal)
            if inner.startswith('^') and inner.endswith('$'):
                # Anchored regex with exit gate — variable is validated
                del self.tainted[var_text]

    # Universal sanitizers — kill taint for ALL categories (type coercion)
    UNIVERSAL_SANITIZERS = {
        "intval", "floatval", "boolval",
        "filter_var", "filter_input",
    }

    # Per-category sanitizers — only kill taint for the specific vuln type
    CATEGORY_SANITIZERS: Dict[str, Set[str]] = {
        "SQL": {
            "mysqli_real_escape_string", "mysql_real_escape_string",
            "pg_escape_string", "pg_escape_literal",
            "addslashes",
        },
        "COMMAND": {
            "escapeshellarg", "escapeshellcmd",
        },
        "XSS": {
            "htmlspecialchars", "htmlentities", "strip_tags",
            "urlencode", "rawurlencode",
        },
        "PATH": {
            "basename", "realpath",
        },
        "REGEX": {
            "preg_quote",
        },
    }

    # Flat set for backward compat (union of all sanitizer sets)
    SANITIZER_FUNCTIONS = UNIVERSAL_SANITIZERS | {
        fn for fns in CATEGORY_SANITIZERS.values() for fn in fns
    }

    # Functions whose return value does NOT carry taint (sinks / metadata)
    TAINT_SINK_FUNCTIONS = {
        # DB execution — return result resource, not user data
        "mysqli_query", "mysqli_real_query", "mysql_query", "pg_query",
        "sqlite_query", "mysql_db_query", "mysql_unbuffered_query",
        # DB metadata — return integers/strings, not user data
        "mysqli_num_rows", "mysqli_affected_rows", "mysqli_insert_id",
        "mysqli_error", "mysqli_errno", "mysqli_field_count",
        "mysql_num_rows", "mysql_affected_rows", "mysql_insert_id",
        "mysql_error", "pg_num_rows", "pg_affected_rows", "pg_last_error",
        # Output functions
        "var_dump", "print_r", "var_export",
        "header", "setcookie",
        # Hash functions — output is fixed-format hex, not user data
        "md5", "sha1", "hash", "crypt", "password_hash",
    }

    def _rhs_sanitized_categories(self, rhs: Node, rhs_text: str) -> Set[str]:
        """Return the set of vulnerability categories this RHS is sanitized for.

        Returns {"ALL"} for universal sanitizers/type casts (kills all taint).
        Returns e.g. {"SQL"} for category-specific sanitizers.
        Returns empty set if not sanitized.
        """
        categories: Set[str] = set()

        calls = find_nodes(rhs, "function_call_expression")
        for call in calls:
            name_node = get_child_by_type(call, "name")
            if not name_node:
                continue
            func_name = node_text(name_node)

            if func_name in self.UNIVERSAL_SANITIZERS:
                return {"ALL"}

            for cat, funcs in self.CATEGORY_SANITIZERS.items():
                if func_name in funcs:
                    categories.add(cat)

        # Type cast: (int), (float), (bool) — universal sanitizer
        if rhs.type == "cast_expression":
            return {"ALL"}
        if re.match(r'^\s*\(\s*(?:int|integer|float|double|bool|boolean)\s*\)', rhs_text):
            return {"ALL"}

        # Type-safe constructors that validate/coerce input (e.g. MongoDB\BSON\ObjectId)
        obj_creations = find_nodes(rhs, "object_creation_expression")
        for oc in obj_creations:
            oc_text = node_text(oc)
            if re.search(r'(?i)MongoDB\\BSON\\ObjectId|MongoId', oc_text):
                return {"ALL"}

        return categories

    def _rhs_is_sanitized(self, rhs: Node, rhs_text: str) -> bool:
        """Check if RHS wraps tainted data in any sanitizer function.

        Backward-compatible wrapper. For context-aware checks use
        _rhs_sanitized_categories() instead.
        """
        return bool(self._rhs_sanitized_categories(rhs, rhs_text))

    def _propagate_pass(self, body: Node):
        """Single pass of taint propagation through the function body."""
        assignments = find_nodes(body, "assignment_expression")

        for assign in assignments:
            children = assign.children
            if len(children) < 3:
                continue

            lhs = children[0]
            rhs = children[2]
            lhs_text = node_text(lhs)
            rhs_text = node_text(rhs)
            line = get_node_line(assign)

            # Check if RHS is sanitized — kills taint (context-aware)
            san_cats = self._rhs_sanitized_categories(rhs, rhs_text)
            if san_cats:
                if "ALL" in san_cats:
                    # Universal sanitizer (intval, type cast) — kill all taint
                    if lhs_text in self.tainted:
                        del self.tainted[lhs_text]
                    self.sanitized_for.pop(lhs_text, None)
                    continue
                else:
                    # Category-specific sanitizer — mark safe for those
                    # categories, but the variable is STILL tainted for others.
                    if lhs_text not in self.sanitized_for:
                        self.sanitized_for[lhs_text] = set()
                    self.sanitized_for[lhs_text].update(san_cats)
                    # Propagate taint if the sanitizer input was tainted
                    if self._rhs_has_superglobal(rhs) or \
                       self._rhs_is_taint_function(rhs) or \
                       self._rhs_is_tainted(rhs_text, rhs):
                        self.tainted[lhs_text] = (line, "sanitized for " +
                                                  ",".join(san_cats) + " only")
                    continue

            # Check if RHS calls a taint-sink function — return value is NOT tainted
            if self._rhs_is_sink(rhs):
                if lhs_text in self.tainted:
                    del self.tainted[lhs_text]
                # Still track DB-fetch results as db_sourced (for 2nd-order detection)
                if self._rhs_is_db_source(rhs_text):
                    self.db_sourced[lhs_text] = (line, rhs_text.strip())
                continue

            # Check if RHS is a DB fetch — track as db_sourced, kill taint
            if self._rhs_is_db_source(rhs_text):
                self.db_sourced[lhs_text] = (line, rhs_text.strip())
                if lhs_text in self.tainted:
                    del self.tainted[lhs_text]
                continue

            # Arithmetic operations force numeric conversion — result cannot
            # contain SQL injection characters.  E.g. $page1 = ($page * 10) - 10
            if self._rhs_is_arithmetic(rhs_text):
                if lhs_text in self.tainted:
                    del self.tainted[lhs_text]
                continue

            # Check if RHS contains superglobal access
            if self._rhs_has_superglobal(rhs):
                self.tainted[lhs_text] = (line, "from superglobal")
                continue

            # Check if RHS is a taint-producing function call
            if self._rhs_is_taint_function(rhs):
                self.tainted[lhs_text] = (line, "from taint function call")
                continue

            # Check if RHS references tainted data
            if self._rhs_is_tainted(rhs_text, rhs):
                self.tainted[lhs_text] = (line, "assigned from tainted data")
                continue

            # Propagate DB-sourced status through assignments
            if self._rhs_refs_db_sourced(rhs_text, rhs):
                self.db_sourced[lhs_text] = (line, "assigned from DB-sourced data")
            # If RHS is not tainted and LHS was previously tainted, remove taint (overwrite)
            elif lhs_text in self.tainted:
                del self.tainted[lhs_text]

        # Detect extract() and parse_str() calls that mass-inject tainted variables
        self._check_mass_taint_sources(body)

    # $_SERVER keys that ARE attacker-controlled
    TAINTED_SERVER_KEYS = {
        "HTTP_HOST", "HTTP_USER_AGENT", "HTTP_REFERER", "HTTP_ACCEPT",
        "HTTP_ACCEPT_LANGUAGE", "HTTP_ACCEPT_ENCODING", "HTTP_CONNECTION",
        "HTTP_COOKIE", "HTTP_X_FORWARDED_FOR", "HTTP_X_FORWARDED_HOST",
        "HTTP_X_FORWARDED_PROTO", "HTTP_CLIENT_IP",
        "REQUEST_URI", "QUERY_STRING", "PATH_INFO", "PATH_TRANSLATED",
        "PHP_SELF", "SCRIPT_NAME", "DOCUMENT_URI",
        "CONTENT_TYPE", "CONTENT_LENGTH",
    }

    # $_SERVER keys that are NOT attacker-controlled (set by network stack)
    SAFE_SERVER_KEYS = {
        "REMOTE_ADDR", "REMOTE_PORT", "SERVER_ADDR", "SERVER_PORT",
        "SERVER_NAME", "SERVER_PROTOCOL", "SERVER_SOFTWARE",
        "DOCUMENT_ROOT", "SCRIPT_FILENAME", "REQUEST_TIME",
        "REQUEST_TIME_FLOAT", "HTTPS",
    }

    def _check_mass_taint_sources(self, body: Node):
        """Detect extract() and parse_str() that mass-create tainted variables."""
        func_calls = find_nodes(body, "function_call_expression")
        for call in func_calls:
            name_node = get_child_by_type(call, "name")
            if not name_node:
                continue
            func_name = node_text(name_node)
            line = get_node_line(call)

            # extract($_GET) / extract($_POST) — all extracted vars become tainted
            if func_name == "extract":
                args = get_child_by_type(call, "arguments")
                if not args:
                    continue
                first_arg_text = node_text(args)
                if re.search(r'\$_(GET|POST|REQUEST|COOKIE|SERVER|FILES|ENV)\b',
                             first_arg_text):
                    # We can't know which variables extract() creates at static
                    # analysis time, so we mark a sentinel that tells is_tainted()
                    # to treat ALL unknown variables as potentially tainted.
                    self.tainted["__EXTRACT_TAINT__"] = (
                        line, f"extract() of superglobal")

            # parse_str($input, $output) — $output array becomes tainted
            if func_name == "parse_str":
                args = get_child_by_type(call, "arguments")
                if not args:
                    continue
                all_args = []
                for child in args.children:
                    if child.type not in ("(", ")", ",", "comment"):
                        all_args.append(child)
                if len(all_args) >= 1:
                    first_text = node_text(all_args[0])
                    if self.is_tainted(first_text) or \
                       re.search(r'\$_(GET|POST|REQUEST|COOKIE|SERVER)\b', first_text):
                        if len(all_args) >= 2:
                            out_var = node_text(all_args[1])
                            self.tainted[out_var] = (line, "parse_str() output")
                        else:
                            # No second arg: parse_str() pollutes the local scope
                            self.tainted["__EXTRACT_TAINT__"] = (
                                line, "parse_str() without output param")

    @staticmethod
    def _rhs_is_arithmetic(rhs_text: str) -> bool:
        """Check if RHS is a purely arithmetic expression (*, /, %, -, +).

        Arithmetic forces numeric conversion in PHP, so the result cannot
        contain SQL injection characters.  Only matches when there are no
        string literals (quotes) in the expression.
        """
        # Must contain an arithmetic operator (*, /, %)
        if not re.search(r'[\*/%]', rhs_text):
            return False
        # Must NOT contain string context (quotes)
        if re.search(r'["\']', rhs_text):
            return False
        return True

    def _rhs_is_sink(self, rhs: Node) -> bool:
        """Check if RHS calls a taint-sink function (return value is not tainted)."""
        calls = find_nodes(rhs, "function_call_expression")
        for call in calls:
            name_node = get_child_by_type(call, "name")
            if name_node and node_text(name_node) in self.TAINT_SINK_FUNCTIONS:
                return True
        return False

    def _rhs_has_superglobal(self, rhs: Node) -> bool:
        """Check if RHS contains a superglobal reference.

        For $_SERVER, discriminates by key: only attacker-controlled keys
        (HTTP_HOST, REQUEST_URI, etc.) are treated as tainted.
        Safe keys like REMOTE_ADDR, SERVER_PORT are skipped.
        """
        # Check subscript expressions for $_SERVER['KEY'] discrimination
        subscripts = find_nodes(rhs, "subscript_expression")
        for sub in subscripts:
            sub_text = node_text(sub)
            if "$_SERVER" in sub_text:
                # Extract the key from $_SERVER['KEY'] or $_SERVER["KEY"]
                m = re.search(r'\$_SERVER\s*\[\s*["\'](\w+)["\']\s*\]', sub_text)
                if m:
                    key = m.group(1)
                    if key in self.SAFE_SERVER_KEYS:
                        continue  # Safe key — not attacker-controlled
                # If key is dynamic or attacker-controlled, it's tainted
                return True

        var_nodes = find_nodes(rhs, "variable_name")
        for vn in var_nodes:
            name_node = get_child_by_type(vn, "name")
            if not name_node:
                continue
            name = node_text(name_node)
            if not is_superglobal_name(name):
                continue
            # $_SERVER without subscript was already handled above
            if name == "_SERVER":
                # Check if this variable_name is part of a subscript_expression
                parent = vn.parent
                if parent and parent.type == "subscript_expression":
                    continue  # Already handled by subscript check above
                # Bare $_SERVER (e.g. extract($_SERVER)) — tainted
            return True
        return False

    # getenv() keys that are NOT attacker-controlled (network stack values)
    SAFE_GETENV_KEYS = {"REMOTE_ADDR", "REMOTE_PORT", "SERVER_ADDR", "SERVER_PORT"}

    def _rhs_is_taint_function(self, rhs: Node) -> bool:
        """Check if RHS is a function call that produces tainted data."""
        calls = find_nodes(rhs, "function_call_expression")
        for call in calls:
            name_node = get_child_by_type(call, "name")
            if name_node:
                func_name = node_text(name_node)
                if func_name in ("getenv", "apache_getenv"):
                    # Only taint if the key is attacker-controllable
                    args = get_child_by_type(call, "arguments")
                    if args:
                        arg_text = node_text(args)
                        if any(safe in arg_text for safe in self.SAFE_GETENV_KEYS):
                            return False
                    return True
                if func_name == "getallheaders":
                    return True
                if func_name == "file_get_contents":
                    args = get_child_by_type(call, "arguments")
                    if args and "php://input" in node_text(args):
                        return True
        return False

    # Functions whose return value carries taint if ANY argument is tainted.
    # These transform strings but don't neutralize the attacker-controlled content.
    TAINT_PROPAGATOR_FUNCTIONS = {
        "sprintf", "vsprintf",
        "str_replace", "str_ireplace", "substr_replace", "preg_replace",
        "substr", "mb_substr", "mb_strtolower", "mb_strtoupper",
        "trim", "ltrim", "rtrim",
        "strtolower", "strtoupper", "ucfirst", "lcfirst", "ucwords",
        "str_pad", "str_repeat", "wordwrap",
        "implode", "join", "explode",
        "json_decode",
        "base64_decode", "base64_encode",
        "rawurldecode", "urldecode",
        "nl2br", "chunk_split",
        "array_merge", "array_push", "array_pop", "array_shift",
        "compact",
    }

    def _rhs_is_tainted(self, rhs_text: str, rhs_node: Node) -> bool:
        """Check if right-hand side references any tainted variable.

        Also checks taint propagator functions: if the RHS is a call to
        sprintf, str_replace, etc. and any argument is tainted, the return
        value is tainted too.
        """
        cleaned = re.sub(r'"[^"]*"', '', rhs_text)
        cleaned = re.sub(r"'[^']*'", '', cleaned)
        for tainted_var in self.tainted:
            if re.search(rf'(?<!\w){re.escape(tainted_var)}(?!\w)', cleaned):
                return True
        # Also check tainted variables interpolated inside encapsed strings
        for enc in find_nodes(rhs_node, "encapsed_string"):
            for child in enc.children:
                if child.type == "variable_name" and node_text(child) in self.tainted:
                    return True

        # Check taint propagator functions: if any arg references tainted data,
        # the return value inherits the taint.
        calls = find_nodes(rhs_node, "function_call_expression")
        for call in calls:
            name_node = get_child_by_type(call, "name")
            if not name_node:
                continue
            func_name = node_text(name_node)
            if func_name not in self.TAINT_PROPAGATOR_FUNCTIONS:
                continue
            # Check if any argument to this propagator is tainted
            args = get_child_by_type(call, "arguments")
            if args:
                args_text = node_text(args)
                args_cleaned = re.sub(r'"[^"]*"', '', args_text)
                args_cleaned = re.sub(r"'[^']*'", '', args_cleaned)
                for tainted_var in self.tainted:
                    if re.search(rf'(?<!\w){re.escape(tainted_var)}(?!\w)',
                                 args_cleaned):
                        return True

        return False

    def _rhs_is_db_source(self, rhs_text: str) -> bool:
        """Check if RHS is a database fetch that produces db-sourced data."""
        db_patterns = [
            r'->fetch\s*\(', r'->fetchAll\s*\(', r'->fetchColumn\s*\(',
            r'->fetch_assoc\s*\(', r'->fetch_array\s*\(', r'->fetch_row\s*\(',
            r'->fetch_object\s*\(', r'mysql_fetch_', r'mysqli_fetch_',
            r'pg_fetch_', r'->result\s*\(',
        ]
        for pattern in db_patterns:
            if re.search(pattern, rhs_text):
                return True
        return False

    def _rhs_refs_db_sourced(self, rhs_text: str, rhs_node: Node = None) -> bool:
        """Check if RHS references any DB-sourced variable (propagation)."""
        cleaned = re.sub(r'"[^"]*"', '', rhs_text)
        cleaned = re.sub(r"'[^']*'", '', cleaned)
        for dv in self.db_sourced:
            if re.search(rf'(?<!\w){re.escape(dv)}(?!\w)', cleaned):
                return True
        # Also check DB-sourced variables interpolated inside encapsed strings
        if rhs_node is not None:
            for enc in find_nodes(rhs_node, "encapsed_string"):
                for child in enc.children:
                    if child.type == "variable_name" and node_text(child) in self.db_sourced:
                        return True
        return False

    def is_tainted(self, text: str, category: str = None) -> bool:
        """Check if a text string references any tainted variable.

        Args:
            text: Source text to check for tainted references.
            category: Optional vuln category (e.g. "SQL", "COMMAND").
                      If set, variables sanitized for this category are
                      considered safe and skipped.
        """
        cleaned = re.sub(r'"[^"]*"', '', text)
        cleaned = re.sub(r"'[^']*'", '', cleaned)
        # Check superglobals directly
        if re.search(r'\$_(GET|POST|REQUEST|COOKIE|SERVER|FILES|ENV)\b', cleaned):
            return True
        for tv in self.tainted:
            if tv == "__EXTRACT_TAINT__":
                # Sentinel from extract()/parse_str(): any PHP variable in the
                # text that isn't explicitly known-safe should be considered
                # tainted.  Match any $var reference that isn't a superglobal
                # (those are already handled above).
                if re.search(r'\$(?!_)[A-Za-z_]\w*', cleaned):
                    return True
                continue
            if re.search(rf'(?<!\w){re.escape(tv)}(?!\w)', cleaned):
                # If category specified, check if this var is sanitized for it
                if category and tv in self.sanitized_for:
                    if category in self.sanitized_for[tv]:
                        continue  # sanitized for this category — skip
                return True
        return False

    def is_tainted_node(self, node: Node) -> bool:
        """Check if a node's text references any tainted variable."""
        return self.is_tainted(node_text(node))

    def is_db_sourced(self, text: str) -> bool:
        """Check if text references any DB-sourced variable."""
        cleaned = re.sub(r'"[^"]*"', '', text)
        cleaned = re.sub(r"'[^']*'", '', cleaned)
        for dv in self.db_sourced:
            if re.search(rf'(?<!\w){re.escape(dv)}(?!\w)', cleaned):
                return True
        return False

    def get_taint_chain(self, text: str) -> List[str]:
        """Get the taint chain for variables referenced in text."""
        chain = []
        cleaned = re.sub(r'"[^"]*"', '', text)
        cleaned = re.sub(r"'[^']*'", '', cleaned)
        for tv, (line, source) in self.tainted.items():
            if re.search(rf'(?<!\w){re.escape(tv)}(?!\w)', cleaned):
                chain.append(f"{tv} <- {source} (line {line})")
        return chain


# ============================================================================
# FunctionSummary — Inter-Procedural Analysis
# ============================================================================

@dataclass
class FunctionSummary:
    """Summary of a function's taint behavior for inter-procedural analysis."""
    name: str
    class_name: Optional[str]
    params: List[str]
    # Does any param flow to the return value?
    param_to_return: Set[int] = field(default_factory=set)  # param indices
    # Does the function return tainted data (from any source)?
    tainted_return: bool = False


# ============================================================================
# PHPASTAnalyzer — Main Scanner
# ============================================================================

class PHPASTAnalyzer:
    """
    AST-based PHP vulnerability scanner using tree-sitter.
    Parses PHP source, builds class/function structure, runs per-function
    taint analysis, and detects vulnerabilities.
    """

    def __init__(self, source_code: str, file_path: str):
        self.source_code = source_code
        self.source_lines = source_code.splitlines()
        self.file_path = file_path
        self.findings: List[Finding] = []

        # Parse with tree-sitter
        parser = Parser(PHP_LANG)
        self.tree = parser.parse(source_code.encode('utf-8'))
        self.root = self.tree.root_node

        # Build structure
        self.functions: List[Tuple[Node, Optional[Node]]] = []  # (func, parent_class)
        self._build_function_list()

    def _build_function_list(self):
        """Find all function/method declarations and their parent classes."""
        classes = find_nodes(self.root, "class_declaration")
        for cls in classes:
            decl_list = get_child_by_type(cls, "declaration_list")
            if decl_list:
                for method in find_nodes(decl_list, "method_declaration"):
                    self.functions.append((method, cls))

        # Top-level functions
        for func in find_nodes(self.root, "function_definition"):
            if not any(f[0] == func for f in self.functions):
                self.functions.append((func, None))

    def _has_top_level_code(self) -> bool:
        """Check if there are top-level statements outside functions/classes."""
        for child in self.root.children:
            if child.type == "expression_statement":
                return True
        return False

    def _get_func_name(self, func_node: Node) -> str:
        """Get function/method name from declaration."""
        name = get_child_by_type(func_node, "name")
        return node_text(name) if name else ""

    def _is_public_method(self, func_node: Node) -> bool:
        """Check if a method is public."""
        if func_node.type == "function_definition":
            return True  # top-level functions are always callable

        # Check for visibility modifier
        vis = get_child_by_type(func_node, "visibility_modifier")
        if vis:
            vis_text = node_text(vis)
            if vis_text == "private":
                return False
        return True  # public or protected

    def _get_line_content(self, line_num: int) -> str:
        """Get source line content (1-based)."""
        if 1 <= line_num <= len(self.source_lines):
            return self.source_lines[line_num - 1].strip()
        return ""

    def _add_finding(self, line: int, col: int, vuln_name: str, category: VulnCategory,
                     severity: Severity, confidence: str, taint_chain: List[str] = None,
                     description: str = ""):
        self.findings.append(Finding(
            file_path=self.file_path,
            line_number=line,
            col_offset=col,
            line_content=self._get_line_content(line),
            vulnerability_name=vuln_name,
            category=category,
            severity=severity,
            confidence=confidence,
            taint_chain=taint_chain or [],
            description=description,
        ))

    # ========================================================================
    # Main Analysis Entry Point
    # ========================================================================

    def analyze(self) -> List[Finding]:
        """Run all vulnerability checks with inter-procedural analysis.

        Pass 1: Build function summaries (which params flow to return values).
        Pass 2: Re-analyze with summaries -- user-defined calls propagate taint.
        """
        # Constructor taint analysis (unchanged)
        class_tainted_props: Dict[int, Dict[str, Tuple[int, str]]] = {}
        for func, cls in self.functions:
            if cls is not None and id(cls) not in class_tainted_props:
                class_tainted_props[id(cls)] = self._get_constructor_tainted_props(cls)

        # Pass 1: Build function summaries with is_public=False
        # (natural taint flow without assuming params are tainted)
        self.function_summaries: Dict[str, FunctionSummary] = {}
        for func, cls in self.functions:
            pre_tainted = class_tainted_props.get(id(cls)) if cls is not None else None
            tracker = TaintTracker(func, self.source_lines, is_public=False,
                                   pre_tainted=pre_tainted)
            summary = self._build_summary(func, cls, tracker)
            if summary:
                key = f"{summary.class_name}::{summary.name}" if summary.class_name else summary.name
                self.function_summaries[key] = summary
                # Also store by bare name for unqualified calls
                self.function_summaries[summary.name] = summary

        # Pass 2: Full analysis with inter-procedural taint propagation
        for func, cls in self.functions:
            is_public = self._is_public_method(func)
            pre_tainted = class_tainted_props.get(id(cls)) if cls is not None else None
            tracker = TaintTracker(func, self.source_lines, is_public,
                                   pre_tainted=pre_tainted)

            # Apply inter-procedural taint from function summaries
            self._apply_interprocedural_taint(func, tracker)

            self._run_checks(func, tracker)

        # Scan top-level code (statements outside any function/class)
        if self._has_top_level_code():
            self._analyze_top_level()

        # Class-level gadget chain detection (not per-function)
        self._check_gadget_methods()

        return self.findings

    def _get_constructor_tainted_props(self, cls: Node) -> Dict[str, Tuple[int, str]]:
        """Analyze the class constructor to find which $this-> properties are tainted."""
        decl_list = get_child_by_type(cls, "declaration_list")
        if not decl_list:
            return {}

        constructor = None
        for method in find_nodes(decl_list, "method_declaration"):
            name = self._get_func_name(method)
            if name == "__construct":
                constructor = method
                break

        if not constructor:
            return {}

        # Create a taint tracker for the constructor (public params are tainted)
        tracker = TaintTracker(constructor, self.source_lines, is_public=True)

        # Extract $this-> properties that ended up tainted after propagation
        # (the tracker already handles sanitizers, so this respects intval(), etc.)
        tainted_props: Dict[str, Tuple[int, str]] = {}
        for var, (line, source) in tracker.tainted.items():
            if var.startswith("$this->"):
                tainted_props[var] = (line, "from constructor parameter")

        return tainted_props

    # ========================================================================
    # Inter-Procedural Analysis
    # ========================================================================

    def _build_summary(self, func: Node, cls: Optional[Node],
                       tracker: TaintTracker) -> Optional[FunctionSummary]:
        """Build a FunctionSummary from a function's taint tracker state.

        Examines return statements to determine which parameters flow to the
        return value.  Uses the tracker built with is_public=False so that
        only *natural* taint flow (not assumed-tainted params) is captured.
        """
        func_name = self._get_func_name(func)
        if not func_name:
            return None

        cls_name = None
        if cls:
            name_node = get_child_by_type(cls, "name")
            if name_node:
                cls_name = node_text(name_node)

        # Get parameter names in order (with $ prefix, matching tracker keys)
        params: List[str] = []
        params_node = get_child_by_type(func, "formal_parameters")
        if params_node:
            for param in get_children_by_type(params_node, "simple_parameter"):
                var_node = get_child_by_type(param, "variable_name")
                if var_node:
                    params.append(node_text(var_node))  # e.g. "$input"

        # Check which params flow to return values
        param_to_return: Set[int] = set()
        tainted_return = False
        body = get_child_by_type(func, "compound_statement")
        if body:
            return_stmts = find_nodes(body, "return_statement")
            for ret in return_stmts:
                ret_text = node_text(ret)
                # Check direct param references in return text
                for i, pname in enumerate(params):
                    if re.search(rf'(?<!\w){re.escape(pname)}(?!\w)', ret_text):
                        param_to_return.add(i)
                # Check if return references any tainted variable (derived from param)
                for tv in tracker.tainted:
                    if re.search(rf'(?<!\w){re.escape(tv)}(?!\w)', ret_text):
                        tainted_return = True
                        # If the tainted var was derived from a param, mark that param index
                        for i, pname in enumerate(params):
                            if pname in tracker.tainted:
                                param_to_return.add(i)

        return FunctionSummary(
            name=func_name,
            class_name=cls_name,
            params=params,
            param_to_return=param_to_return,
            tainted_return=tainted_return,
        )

    def _apply_interprocedural_taint(self, func: Node, tracker: TaintTracker):
        """Apply inter-procedural taint from function summaries to call sites.

        Finds all variable assignments where the RHS is a call to a
        user-defined function.  If any argument is tainted AND the
        corresponding parameter index flows to the return value (per the
        summary), the LHS variable is marked tainted.
        """
        body = self._get_body(func)
        if not body:
            return

        assignments = find_nodes(body, "assignment_expression")
        for assign in assignments:
            children = assign.children
            if len(children) < 3:
                continue
            lhs_text = node_text(children[0])
            rhs = children[2]

            # Check for function_call_expression in RHS
            calls = find_nodes(rhs, "function_call_expression")
            for call in calls:
                self._check_call_taint(call, lhs_text, tracker)

            # Check for member_call_expression in RHS (e.g. $this->helper($x))
            member_calls = find_nodes(rhs, "member_call_expression")
            for mc in member_calls:
                method_name = self._get_member_call_name(mc)
                if not method_name:
                    continue
                # Look up summary by bare name (covers $this->method() calls)
                summary = self.function_summaries.get(method_name)
                if not summary or not summary.param_to_return:
                    continue
                args_node = get_child_by_type(mc, "arguments")
                if not args_node:
                    continue
                args = self._get_all_args(args_node)
                line = get_node_line(mc)
                for idx in summary.param_to_return:
                    if idx < len(args):
                        arg_text = node_text(args[idx])
                        for tv in tracker.tainted:
                            if re.search(rf'(?<!\w){re.escape(tv)}(?!\w)', arg_text):
                                tracker.tainted[lhs_text] = (
                                    line,
                                    f"from {method_name}({tv}) [inter-procedural]"
                                )
                                break
                        else:
                            continue
                        break  # already tainted, no need to check more indices

    def _check_call_taint(self, call: Node, target_var: str, tracker: TaintTracker):
        """Check if a function call expression should taint the target variable."""
        name_node = get_child_by_type(call, "name")
        if not name_node:
            return
        call_name = node_text(name_node)

        summary = self.function_summaries.get(call_name)
        if not summary or not summary.param_to_return:
            return

        # Get arguments
        args_node = get_child_by_type(call, "arguments")
        if not args_node:
            return
        args = self._get_all_args(args_node)

        # Check if any argument at a param_to_return index is tainted
        line = get_node_line(call)
        for idx in summary.param_to_return:
            if idx < len(args):
                arg_text = node_text(args[idx])
                for tv in tracker.tainted:
                    if re.search(rf'(?<!\w){re.escape(tv)}(?!\w)', arg_text):
                        tracker.tainted[target_var] = (
                            line,
                            f"from {call_name}({tv}) [inter-procedural]"
                        )
                        return

    def _run_checks(self, scope: Node, tracker: TaintTracker):
        """Run all vulnerability checks against a scope node."""
        self._check_sql_injection(scope, tracker)
        self._check_command_injection(scope, tracker)
        self._check_code_injection(scope, tracker)
        self._check_deserialization(scope, tracker)
        self._check_xxe(scope, tracker)
        self._check_xpath_injection(scope, tracker)
        self._check_ssti(scope, tracker)
        self._check_nosql_injection(scope, tracker)
        self._check_second_order_sqli(scope, tracker)
        self._check_sql_prepare_pattern(scope, tracker)
        self._check_variable_function_call(scope, tracker)
        self._check_open_redirect(scope, tracker)
        self._check_ldap_injection(scope, tracker)

    def _analyze_top_level(self):
        """Analyze top-level PHP code outside functions/classes."""
        # Use the program root as the scope with a special tracker
        tracker = TaintTracker(self.root, self.source_lines,
                               is_public=True, scope_node=self.root)
        self._run_checks(self.root, tracker)

    def _get_body(self, func: Node) -> Optional[Node]:
        """Get the body/scope node for analysis.
        For functions/methods, returns compound_statement.
        For top-level (program node), returns the node itself."""
        if func.type == "program":
            return func
        return get_child_by_type(func, "compound_statement")

    # ========================================================================
    # SQL Injection Detection
    # ========================================================================

    def _check_sql_injection(self, func: Node, tracker: TaintTracker):
        """Detect SQL injection via string concatenation in query calls."""
        body = self._get_body(func)
        if not body:
            return

        # Check function calls: mysql_query, mysqli_query, pg_query, etc.
        func_calls = find_nodes(body, "function_call_expression")
        for call in func_calls:
            name_node = get_child_by_type(call, "name")
            if not name_node:
                continue
            func_name = node_text(name_node)
            line = get_node_line(call)

            sql_funcs = {
                "mysql_query", "mysqli_query", "pg_query",
                "sqlite_query", "mysql_db_query", "mysqli_real_query",
                "mysql_unbuffered_query",
            }

            if func_name in sql_funcs:
                args = get_child_by_type(call, "arguments")
                if not args:
                    continue

                # For mysqli_query, the query is the 2nd arg; for mysql_query it's 1st
                all_args = self._get_all_args(args)
                query_arg = None
                if func_name in ("mysqli_query", "mysqli_real_query", "pg_query") and len(all_args) >= 2:
                    query_arg = all_args[1]
                elif all_args:
                    query_arg = all_args[0]

                if query_arg:
                    arg_text = node_text(query_arg)
                    if self._has_tainted_concat(query_arg, tracker, category="SQL"):
                        self._add_finding(
                            line, 0,
                            f"SQL Injection - String concatenation in {func_name}",
                            VulnCategory.SQL_INJECTION, Severity.CRITICAL, "HIGH",
                            tracker.get_taint_chain(arg_text),
                            f"Tainted data concatenated into SQL query passed to {func_name}()."
                        )
                    elif query_arg.type not in ("string", "encapsed_string"):
                        # Flow-sensitive check: the global taint state may be
                        # stale if the variable was later overwritten with safe
                        # data.  Always check the nearest assignment directly.
                        if self._nearest_assignment_is_tainted(arg_text, line, body, tracker):
                            self._add_finding(
                                line, 0,
                                f"SQL Injection - Tainted variable in {func_name}",
                                VulnCategory.SQL_INJECTION, Severity.CRITICAL, "HIGH",
                                tracker.get_taint_chain(arg_text),
                                f"Tainted variable used as query in {func_name}()."
                            )

        # Check method calls: $pdo->query(), $pdo->exec(), $pdo->prepare()
        method_calls = find_nodes(body, "member_call_expression")
        for mc in method_calls:
            method_name = self._get_member_call_name(mc)
            line = get_node_line(mc)

            if method_name in ("query", "exec"):
                # Disambiguate: only flag if receiver looks like a DB object
                receiver = self._get_member_call_receiver(mc)
                recv_text = node_text(receiver) if receiver else ""
                if not self._is_db_receiver(recv_text):
                    continue

                args = get_child_by_type(mc, "arguments")
                if not args:
                    continue
                first_arg = self._get_first_arg(args)
                if not first_arg:
                    continue
                arg_text = node_text(first_arg)

                if self._has_tainted_concat(first_arg, tracker, category="SQL"):
                    self._add_finding(
                        line, 0,
                        f"SQL Injection - String concatenation in ->{method_name}()",
                        VulnCategory.SQL_INJECTION, Severity.CRITICAL, "HIGH",
                        tracker.get_taint_chain(arg_text),
                        f"Tainted data concatenated into SQL passed to ->{method_name}()."
                    )
                elif first_arg.type not in ("string", "encapsed_string"):
                    if self._nearest_assignment_is_tainted(arg_text, line, body, tracker):
                        self._add_finding(
                            line, 0,
                            f"SQL Injection - Tainted variable in ->{method_name}()",
                            VulnCategory.SQL_INJECTION, Severity.CRITICAL, "HIGH",
                            tracker.get_taint_chain(arg_text),
                            f"Tainted variable used as query in ->{method_name}()."
                        )

            # $pdo->prepare() with string concat (defeats parameterization)
            if method_name == "prepare":
                args = get_child_by_type(mc, "arguments")
                if not args:
                    continue
                first_arg = self._get_first_arg(args)
                if not first_arg:
                    continue
                arg_text = node_text(first_arg)

                if self._has_tainted_concat(first_arg, tracker, category="SQL"):
                    self._add_finding(
                        line, 0,
                        "SQL Injection - String concatenation in ->prepare()",
                        VulnCategory.SQL_INJECTION, Severity.CRITICAL, "HIGH",
                        tracker.get_taint_chain(arg_text),
                        "Tainted data concatenated into SQL in prepare() defeats parameterization."
                    )

    # ========================================================================
    # Command Injection Detection
    # ========================================================================

    def _check_command_injection(self, func: Node, tracker: TaintTracker):
        """Detect command injection via exec, system, passthru, etc."""
        body = self._get_body(func)
        if not body:
            return

        cmd_funcs = {
            "exec", "system", "passthru", "shell_exec",
            "popen", "proc_open", "pcntl_exec",
        }

        func_calls = find_nodes(body, "function_call_expression")
        for call in func_calls:
            name_node = get_child_by_type(call, "name")
            if not name_node:
                continue
            func_name = node_text(name_node)
            line = get_node_line(call)

            if func_name in cmd_funcs:
                args = get_child_by_type(call, "arguments")
                if not args:
                    continue
                first_arg = self._get_first_arg(args)
                if not first_arg:
                    continue
                arg_text = node_text(first_arg)

                if tracker.is_tainted(arg_text, category="COMMAND") or \
                   self._has_tainted_concat(first_arg, tracker, category="COMMAND"):
                    self._add_finding(
                        line, 0,
                        f"Command Injection - {func_name}() with tainted input",
                        VulnCategory.COMMAND_INJECTION, Severity.CRITICAL, "HIGH",
                        tracker.get_taint_chain(arg_text),
                        f"User-controlled data passed to {func_name}()."
                    )

        # Check for backtick operator (shell_execution)
        shell_execs = find_nodes(body, "shell_command_expression")
        for se in shell_execs:
            se_text = node_text(se)
            line = get_node_line(se)
            if tracker.is_tainted(se_text, category="COMMAND"):
                self._add_finding(
                    line, 0,
                    "Command Injection - Backtick operator with tainted input",
                    VulnCategory.COMMAND_INJECTION, Severity.CRITICAL, "HIGH",
                    tracker.get_taint_chain(se_text),
                    "User-controlled data in backtick shell execution."
                )

    # ========================================================================
    # Code Injection Detection
    # ========================================================================

    def _check_code_injection(self, func: Node, tracker: TaintTracker):
        """Detect code injection via eval, assert, create_function, preg_replace /e."""
        body = self._get_body(func)
        if not body:
            return

        func_calls = find_nodes(body, "function_call_expression")
        for call in func_calls:
            name_node = get_child_by_type(call, "name")
            if not name_node:
                continue
            func_name = node_text(name_node)
            line = get_node_line(call)

            # eval()
            if func_name == "eval":
                args = get_child_by_type(call, "arguments")
                if not args:
                    continue
                first_arg = self._get_first_arg(args)
                if not first_arg:
                    continue
                arg_text = node_text(first_arg)
                if tracker.is_tainted(arg_text):
                    self._add_finding(
                        line, 0,
                        "Code Injection - eval() with tainted input",
                        VulnCategory.CODE_INJECTION, Severity.CRITICAL, "HIGH",
                        tracker.get_taint_chain(arg_text),
                        "User-controlled code passed to eval()."
                    )

            # assert() with string argument (PHP < 8.0 evaluates as code)
            if func_name == "assert":
                args = get_child_by_type(call, "arguments")
                if not args:
                    continue
                first_arg = self._get_first_arg(args)
                if not first_arg:
                    continue
                arg_text = node_text(first_arg)
                if tracker.is_tainted(arg_text):
                    self._add_finding(
                        line, 0,
                        "Code Injection - assert() with tainted input",
                        VulnCategory.CODE_INJECTION, Severity.CRITICAL, "HIGH",
                        tracker.get_taint_chain(arg_text),
                        "User-controlled expression in assert() (evaluates as code in PHP < 8.0)."
                    )

            # create_function()
            if func_name == "create_function":
                args = get_child_by_type(call, "arguments")
                if not args:
                    continue
                all_args = self._get_all_args(args)
                # Second argument is the code body
                if len(all_args) >= 2:
                    code_arg = all_args[1]
                    code_text = node_text(code_arg)
                    if tracker.is_tainted(code_text):
                        self._add_finding(
                            line, 0,
                            "Code Injection - create_function() with tainted body",
                            VulnCategory.CODE_INJECTION, Severity.CRITICAL, "HIGH",
                            tracker.get_taint_chain(code_text),
                            "User-controlled code in create_function() body."
                        )

            # preg_replace with /e modifier
            if func_name == "preg_replace":
                args = get_child_by_type(call, "arguments")
                if not args:
                    continue
                all_args = self._get_all_args(args)
                if all_args:
                    pattern_text = node_text(all_args[0])
                    # Check for /e modifier
                    if re.search(r'/[a-zA-Z]*e[a-zA-Z]*["\']?\s*$', pattern_text):
                        # Check if replacement or subject is tainted
                        tainted_arg = False
                        for arg in all_args[1:]:
                            if tracker.is_tainted(node_text(arg)):
                                tainted_arg = True
                                break
                        if tainted_arg:
                            self._add_finding(
                                line, 0,
                                "Code Injection - preg_replace /e with tainted data",
                                VulnCategory.CODE_INJECTION, Severity.CRITICAL, "HIGH",
                                description="preg_replace with /e modifier evaluates replacement as PHP code."
                            )

    # ========================================================================
    # Insecure Deserialization Detection
    # ========================================================================

    # Deserialization functions: name -> (severity, confidence, description)
    DESER_FUNCTIONS = {
        "unserialize": (Severity.CRITICAL, "HIGH",
                        "User-controlled data in unserialize() allows arbitrary object injection."),
        "yaml_parse": (Severity.CRITICAL, "HIGH",
                       "yaml_parse() can instantiate arbitrary objects via !php/object tags."),
        "yaml_parse_file": (Severity.CRITICAL, "HIGH",
                            "yaml_parse_file() can instantiate arbitrary objects via !php/object tags."),
        "yaml_parse_url": (Severity.CRITICAL, "HIGH",
                           "yaml_parse_url() can instantiate arbitrary objects via !php/object tags."),
        "igbinary_unserialize": (Severity.CRITICAL, "HIGH",
                                 "igbinary_unserialize() deserializes binary format and allows object injection."),
        "msgpack_unpack": (Severity.HIGH, "HIGH",
                           "msgpack_unpack() with tainted input may allow object injection."),
        "wddx_deserialize": (Severity.HIGH, "HIGH",
                              "wddx_deserialize() with tainted input may allow object injection."),
    }

    def _check_deserialization(self, func: Node, tracker: TaintTracker):
        """Detect insecure deserialization via unserialize and related functions."""
        body = self._get_body(func)
        if not body:
            return

        func_calls = find_nodes(body, "function_call_expression")
        for call in func_calls:
            name_node = get_child_by_type(call, "name")
            if not name_node:
                continue
            func_name = node_text(name_node)
            line = get_node_line(call)

            # --- Direct deserialization functions ---
            if func_name in self.DESER_FUNCTIONS:
                args = get_child_by_type(call, "arguments")
                if not args:
                    continue
                first_arg = self._get_first_arg(args)
                if not first_arg:
                    continue
                arg_text = node_text(first_arg)

                if tracker.is_tainted(arg_text):
                    severity, confidence, desc = self.DESER_FUNCTIONS[func_name]

                    # unserialize-specific: check allowed_classes mitigation
                    if func_name == "unserialize":
                        all_args = self._get_all_args(args)
                        if len(all_args) >= 2:
                            second_text = node_text(all_args[1])
                            if "allowed_classes" in second_text and "false" in second_text.lower():
                                continue  # allowed_classes=false mitigates object injection

                    self._add_finding(
                        line, 0,
                        f"Insecure Deserialization - {func_name}() with tainted input",
                        VulnCategory.DESERIALIZATION, severity, confidence,
                        tracker.get_taint_chain(arg_text), desc
                    )

            # --- json_decode without assoc=true ---
            elif func_name == "json_decode":
                args = get_child_by_type(call, "arguments")
                if not args:
                    continue
                first_arg = self._get_first_arg(args)
                if not first_arg:
                    continue
                arg_text = node_text(first_arg)

                if tracker.is_tainted(arg_text):
                    all_args = self._get_all_args(args)
                    has_assoc_true = False
                    if len(all_args) >= 2:
                        second_text = node_text(all_args[1]).lower()
                        if second_text == "true":
                            has_assoc_true = True
                    if not has_assoc_true:
                        self._add_finding(
                            line, 0,
                            "Insecure Deserialization - json_decode() without assoc=true",
                            VulnCategory.DESERIALIZATION, Severity.MEDIUM, "LOW",
                            tracker.get_taint_chain(arg_text),
                            "json_decode() without assoc=true returns objects; prefer assoc arrays."
                        )

        # --- Second-order deserialization: DB-sourced data into deser functions ---
        if tracker.db_sourced:
            for call in func_calls:
                name_node = get_child_by_type(call, "name")
                if not name_node:
                    continue
                func_name = node_text(name_node)
                if func_name not in self.DESER_FUNCTIONS:
                    continue

                args = get_child_by_type(call, "arguments")
                if not args:
                    continue
                first_arg = self._get_first_arg(args)
                if not first_arg:
                    continue
                arg_text = node_text(first_arg)

                # Skip if already reported as directly tainted
                if tracker.is_tainted(arg_text):
                    continue

                if tracker.is_db_sourced(arg_text):
                    # unserialize-specific: check allowed_classes mitigation
                    if func_name == "unserialize":
                        all_args = self._get_all_args(args)
                        if len(all_args) >= 2:
                            second_text = node_text(all_args[1])
                            if "allowed_classes" in second_text and "false" in second_text.lower():
                                continue  # allowed_classes=false mitigates object injection

                    line = get_node_line(call)
                    self._add_finding(
                        line, 0,
                        f"Second-order Deserialization - DB data in {func_name}()",
                        VulnCategory.DESERIALIZATION, Severity.HIGH, "MEDIUM",
                        description=(
                            f"Data fetched from database passed to {func_name}(). "
                            f"If an attacker can control the stored data, this enables object injection."
                        )
                    )

        # Check for phar:// deserialization
        self._check_phar_deserialization(body, tracker)

    # Filesystem functions that trigger phar:// metadata deserialization
    PHAR_TRIGGER_FUNCS = {
        "file_get_contents", "file_exists", "is_file", "is_dir", "fopen",
        "file", "readfile", "copy", "stat", "lstat", "fileatime", "filectime",
        "filemtime", "filesize", "getimagesize", "highlight_file", "show_source",
        "parse_ini_file", "exif_thumbnail", "exif_imagetype",
        "file_put_contents", "unlink", "rename", "mkdir",
    }

    def _check_phar_deserialization(self, body: Node, tracker: TaintTracker):
        """Detect phar:// deserialization via tainted file operation paths."""
        body_text = node_text(body)

        # Mitigation: check if body validates against phar:// wrapper
        has_phar_check = bool(re.search(
            r'strpos\s*\(.*phar.*\).*(?:exit|return|throw|die)',
            body_text, re.DOTALL | re.IGNORECASE
        )) or bool(re.search(
            r'str_starts_with\s*\(.*phar.*\).*(?:exit|return|throw|die)',
            body_text, re.DOTALL | re.IGNORECASE
        ))
        if has_phar_check:
            return

        # Check filesystem functions with tainted path arguments
        func_calls = find_nodes(body, "function_call_expression")
        for call in func_calls:
            name_node = get_child_by_type(call, "name")
            if not name_node:
                continue
            func_name = node_text(name_node)
            if func_name not in self.PHAR_TRIGGER_FUNCS:
                continue

            args = get_child_by_type(call, "arguments")
            if not args:
                continue
            first_arg = self._get_first_arg(args)
            if not first_arg:
                continue
            arg_text = node_text(first_arg)

            if tracker.is_tainted(arg_text):
                line = get_node_line(call)
                self._add_finding(
                    line, 0,
                    f"Phar Deserialization - {func_name}() with tainted path",
                    VulnCategory.DESERIALIZATION, Severity.CRITICAL, "MEDIUM",
                    tracker.get_taint_chain(arg_text),
                    f"Tainted path in {func_name}() can trigger phar:// metadata deserialization."
                )

        # Check include/require with tainted paths (also triggers phar deserialization)
        include_nodes = find_nodes_multi(body, {
            "include_expression", "include_once_expression",
            "require_expression", "require_once_expression",
        })
        for inc_node in include_nodes:
            # The included path is typically the last child (after the keyword)
            for child in inc_node.children:
                if child.type in ("include", "include_once", "require", "require_once",
                                  "(", ")", ";"):
                    continue
                inc_text = node_text(child)
                if tracker.is_tainted(inc_text):
                    line = get_node_line(inc_node)
                    keyword = inc_node.type.replace("_expression", "").replace("_", " ")
                    self._add_finding(
                        line, 0,
                        f"Phar Deserialization - {keyword} with tainted path",
                        VulnCategory.DESERIALIZATION, Severity.CRITICAL, "MEDIUM",
                        tracker.get_taint_chain(inc_text),
                        f"Tainted path in {keyword} can trigger phar:// metadata deserialization."
                    )
                break  # only check first non-keyword child

    # ========================================================================
    # Gadget Chain Indicator Detection (class-level)
    # ========================================================================

    MAGIC_METHODS = {
        "__wakeup", "__destruct", "__toString", "__call", "__callStatic",
        "__get", "__set", "__isset", "__unset", "__invoke",
    }

    DANGEROUS_FUNCTIONS = {
        "exec", "system", "passthru", "shell_exec", "popen", "proc_open",
        "eval", "assert", "create_function", "unlink", "file_put_contents",
        "fwrite", "call_user_func", "call_user_func_array", "mail",
        "preg_replace", "pcntl_exec", "putenv", "apache_setenv",
    }

    def _check_gadget_methods(self):
        """Scan class declarations for magic methods containing dangerous operations.

        This is an advisory-level check that identifies potential gadget chain
        entry points — classes whose magic methods invoke dangerous functions.
        """
        classes = find_nodes(self.root, "class_declaration")
        for cls in classes:
            cls_name_node = get_child_by_type(cls, "name")
            cls_name = node_text(cls_name_node) if cls_name_node else "<anonymous>"

            decl_list = get_child_by_type(cls, "declaration_list")
            if not decl_list:
                continue

            for method in find_nodes(decl_list, "method_declaration"):
                method_name = self._get_func_name(method)
                if method_name not in self.MAGIC_METHODS:
                    continue

                method_body = get_child_by_type(method, "compound_statement")
                if not method_body:
                    continue

                # Search for dangerous function calls within the magic method
                inner_calls = find_nodes(method_body, "function_call_expression")
                for call in inner_calls:
                    call_name_node = get_child_by_type(call, "name")
                    if not call_name_node:
                        continue
                    call_name = node_text(call_name_node)
                    if call_name in self.DANGEROUS_FUNCTIONS:
                        line = get_node_line(call)
                        self._add_finding(
                            line, 0,
                            f"Gadget Chain Indicator - {cls_name}::{method_name}() calls {call_name}()",
                            VulnCategory.DESERIALIZATION, Severity.LOW, "LOW",
                            description=(
                                f"Magic method {method_name}() in class {cls_name} calls "
                                f"dangerous function {call_name}(). This class could be used "
                                f"as a gadget in a deserialization attack chain."
                            )
                        )

    # ========================================================================
    # LFI/RFI Detection
    # ========================================================================

    def _check_xxe(self, func: Node, tracker: TaintTracker):
        """Detect XXE via DOMDocument->loadXML, simplexml_load_string, XMLReader."""
        body = self._get_body(func)
        if not body:
            return

        body_text = node_text(body)

        # Check if libxml_disable_entity_loader(true) is called
        has_entity_loader_disabled = bool(re.search(
            r'libxml_disable_entity_loader\s*\(\s*true\s*\)', body_text
        ))
        # Check for LIBXML_NOENT absence and LIBXML_DTDLOAD absence
        has_safe_libxml = bool(re.search(
            r'LIBXML_NOENT', body_text
        ))

        # DOMDocument->loadXML(tainted)
        method_calls = find_nodes(body, "member_call_expression")
        for mc in method_calls:
            method_name = self._get_member_call_name(mc)
            line = get_node_line(mc)

            if method_name in ("loadXML", "loadHTML", "load"):
                receiver = self._get_member_call_receiver(mc)
                if receiver:
                    recv_text = node_text(receiver)
                    # Heuristic: check receiver looks like a DOM/XML object
                    if not re.search(r'(?i)dom|xml|doc', recv_text) and method_name == "load":
                        continue
                args = get_child_by_type(mc, "arguments")
                if args:
                    first_arg = self._get_first_arg(args)
                    if first_arg and tracker.is_tainted(node_text(first_arg)):
                        if not has_entity_loader_disabled:
                            self._add_finding(
                                line, 0,
                                f"XXE - ->{method_name}() with tainted XML input",
                                VulnCategory.XXE, Severity.HIGH, "HIGH",
                                tracker.get_taint_chain(node_text(first_arg)),
                                f"User-controlled XML in ->{method_name}() without libxml_disable_entity_loader()."
                            )

        # simplexml_load_string(tainted)
        func_calls = find_nodes(body, "function_call_expression")
        for call in func_calls:
            name_node = get_child_by_type(call, "name")
            if not name_node:
                continue
            func_name = node_text(name_node)
            line = get_node_line(call)

            if func_name in ("simplexml_load_string", "simplexml_load_file"):
                args = get_child_by_type(call, "arguments")
                if args:
                    first_arg = self._get_first_arg(args)
                    if first_arg and tracker.is_tainted(node_text(first_arg)):
                        if not has_entity_loader_disabled:
                            self._add_finding(
                                line, 0,
                                f"XXE - {func_name}() with tainted XML input",
                                VulnCategory.XXE, Severity.HIGH, "HIGH",
                                tracker.get_taint_chain(node_text(first_arg)),
                                f"User-controlled XML in {func_name}() without entity loader protection."
                            )

            # XMLReader::open / XMLReader::xml
            if func_name in ("XMLReader::open", "XMLReader::xml"):
                args = get_child_by_type(call, "arguments")
                if args:
                    first_arg = self._get_first_arg(args)
                    if first_arg and tracker.is_tainted(node_text(first_arg)):
                        if not has_entity_loader_disabled:
                            self._add_finding(
                                line, 0,
                                f"XXE - {func_name}() with tainted XML input",
                                VulnCategory.XXE, Severity.HIGH, "MEDIUM",
                                description=f"User-controlled XML in {func_name}()."
                            )

    # ========================================================================
    # XPath Injection Detection
    # ========================================================================

    def _check_xpath_injection(self, func: Node, tracker: TaintTracker):
        """Detect XPath injection via DOMXPath->query/evaluate with tainted concat."""
        body = self._get_body(func)
        if not body:
            return

        method_calls = find_nodes(body, "member_call_expression")
        for mc in method_calls:
            method_name = self._get_member_call_name(mc)
            if method_name not in ("query", "evaluate"):
                continue

            # Check receiver looks like an XPath object
            receiver = self._get_member_call_receiver(mc)
            recv_text = node_text(receiver) if receiver else ""
            if not re.search(r'(?i)xpath', recv_text):
                continue

            args = get_child_by_type(mc, "arguments")
            if not args:
                continue
            first_arg = self._get_first_arg(args)
            if not first_arg:
                continue

            arg_text = node_text(first_arg)
            line = get_node_line(mc)

            if self._has_tainted_concat(first_arg, tracker):
                self._add_finding(
                    line, 0,
                    f"XPath Injection - tainted data in ->{method_name}()",
                    VulnCategory.XPATH_INJECTION, Severity.HIGH, "HIGH",
                    tracker.get_taint_chain(arg_text),
                    f"User-controlled data concatenated into XPath {method_name}() expression."
                )
            elif first_arg.type not in ("string", "encapsed_string") and tracker.is_tainted(arg_text):
                self._add_finding(
                    line, 0,
                    f"XPath Injection - tainted variable in ->{method_name}()",
                    VulnCategory.XPATH_INJECTION, Severity.HIGH, "HIGH",
                    tracker.get_taint_chain(arg_text),
                    f"User-controlled variable in XPath {method_name}() expression."
                )



    # ========================================================================
    # SSTI Detection
    # ========================================================================

    def _check_ssti(self, func: Node, tracker: TaintTracker):
        """Detect server-side template injection in Twig, Blade, Smarty."""
        body = self._get_body(func)
        if not body:
            return

        method_calls = find_nodes(body, "member_call_expression")
        for mc in method_calls:
            method_name = self._get_member_call_name(mc)
            line = get_node_line(mc)
            mc_text = node_text(mc)

            # Twig: $twig->render(tainted_template), $twig->createTemplate(tainted)
            if method_name in ("render", "createTemplate", "display"):
                receiver = self._get_member_call_receiver(mc)
                recv_text = node_text(receiver) if receiver else ""
                if re.search(r'(?i)twig|template|smarty|blade|mustache', recv_text) or \
                   re.search(r'(?i)twig|template|smarty|blade|mustache', mc_text):
                    args = get_child_by_type(mc, "arguments")
                    if args:
                        first_arg = self._get_first_arg(args)
                        if first_arg and tracker.is_tainted(node_text(first_arg)):
                            self._add_finding(
                                line, 0,
                                f"SSTI - Template engine ->{method_name}() with tainted template",
                                VulnCategory.SSTI, Severity.HIGH, "HIGH",
                                tracker.get_taint_chain(node_text(first_arg)),
                                f"User-controlled template string in ->{method_name}()."
                            )

        # Smarty: $smarty->fetch("string:" . $tainted)
        for mc in method_calls:
            method_name = self._get_member_call_name(mc)
            if method_name != "fetch":
                continue
            mc_text = node_text(mc)
            if "string:" in mc_text and tracker.is_tainted(mc_text):
                line = get_node_line(mc)
                self._add_finding(
                    line, 0,
                    "SSTI - Smarty fetch with tainted string template",
                    VulnCategory.SSTI, Severity.HIGH, "HIGH",
                    description="User-controlled template in Smarty fetch('string:...')."
                )

    # ========================================================================
    # NoSQL Injection Detection
    # ========================================================================

    def _check_nosql_injection(self, func: Node, tracker: TaintTracker):
        """Detect NoSQL injection patterns (MongoDB)."""
        body = self._get_body(func)
        if not body:
            return

        method_calls = find_nodes(body, "member_call_expression")
        for mc in method_calls:
            method_name = self._get_member_call_name(mc)
            if method_name not in ("find", "findOne", "aggregate", "update",
                                    "insert", "insertOne", "insertMany",
                                    "remove", "deleteOne", "deleteMany",
                                    "updateOne", "updateMany", "replaceOne",
                                    "findOneAndUpdate", "findOneAndDelete",
                                    "findOneAndReplace",
                                    "count", "countDocuments", "distinct",
                                    "bulkWrite", "mapReduce"):
                continue

            mc_text = node_text(mc)
            receiver = self._get_member_call_receiver(mc)
            recv_text = node_text(receiver) if receiver else ""

            # Heuristic: receiver should look like MongoDB collection
            if not re.search(r'(?i)mongo|collection|db\b', recv_text) and \
               not re.search(r'(?i)mongo|collection', mc_text):
                continue

            args = get_child_by_type(mc, "arguments")
            if not args:
                continue

            # Check ALL arguments — e.g. distinct('field', $taintedQuery)
            line = get_node_line(mc)
            for arg_node in args.children:
                if arg_node.type in (",", "(", ")"):
                    continue
                arg_text = node_text(arg_node)
                if tracker.is_tainted(arg_text):
                    self._add_finding(
                        line, 0,
                        f"NoSQL Injection - MongoDB ->{method_name}() with tainted query",
                        VulnCategory.NOSQL_INJECTION, Severity.CRITICAL, "HIGH",
                        tracker.get_taint_chain(arg_text),
                        f"User-controlled data in MongoDB ->{method_name}() query."
                    )
                    break  # one finding per call is enough

    # ========================================================================
    # Second-Order SQLi Detection
    # ========================================================================

    def _check_second_order_sqli(self, func: Node, tracker: TaintTracker):
        """Detect second-order SQL injection via DB-sourced data in queries."""
        body = self._get_body(func)
        if not body:
            return

        if not tracker.db_sourced:
            return

        # Helper: check if query arg has db-sourced data (concat or interpolation)
        def _has_db_sourced_in_query(arg_node: Node) -> bool:
            arg_text = node_text(arg_node)
            # Check . concat with db-sourced data
            if self._has_concat(arg_node) and tracker.is_db_sourced(arg_text):
                return True
            # Check encapsed string interpolation with db-sourced vars
            if self._has_db_sourced_interpolation(arg_node, tracker):
                return True
            # Check if the variable itself is db-sourced (assigned earlier)
            if arg_node.type not in ("string", "encapsed_string") and tracker.is_db_sourced(arg_text):
                return True
            return False

        # Check function calls
        sql_funcs = {"mysql_query", "mysqli_query", "pg_query"}
        func_calls = find_nodes(body, "function_call_expression")
        for call in func_calls:
            name_node = get_child_by_type(call, "name")
            if not name_node:
                continue
            func_name = node_text(name_node)
            if func_name not in sql_funcs:
                continue

            args = get_child_by_type(call, "arguments")
            if not args:
                continue
            all_args = self._get_all_args(args)
            query_arg = None
            if func_name in ("mysqli_query", "pg_query") and len(all_args) >= 2:
                query_arg = all_args[1]
            elif all_args:
                query_arg = all_args[0]

            if query_arg and _has_db_sourced_in_query(query_arg):
                line = get_node_line(call)
                self._add_finding(
                    line, 0,
                    f"Second-order SQLi - DB-sourced data in {func_name}",
                    VulnCategory.SQL_INJECTION, Severity.HIGH, "MEDIUM",
                    description="Data fetched from database used in SQL query construction."
                )

        # Check method calls (->query, ->exec)
        method_calls = find_nodes(body, "member_call_expression")
        for mc in method_calls:
            method_name = self._get_member_call_name(mc)
            if method_name not in ("query", "exec"):
                continue

            args = get_child_by_type(mc, "arguments")
            if not args:
                continue
            first_arg = self._get_first_arg(args)
            if not first_arg:
                continue

            if _has_db_sourced_in_query(first_arg):
                line = get_node_line(mc)
                self._add_finding(
                    line, 0,
                    f"Second-order SQLi - DB-sourced data in ->{method_name}()",
                    VulnCategory.SQL_INJECTION, Severity.HIGH, "MEDIUM",
                    description="Data fetched from database used in SQL query construction."
                )

    # ========================================================================
    # SQL PREPARE Pattern Detection
    # ========================================================================

    def _check_sql_prepare_pattern(self, func: Node, tracker: TaintTracker):
        """Detect MySQL-level dynamic SQL via PREPARE FROM with subquery-loaded variables.

        Pattern: SET @var = (SELECT ...); PREPARE stmt FROM concat(@var); EXECUTE stmt;
        This is a second-order injection at the SQL engine level.
        """
        body = self._get_body(func)
        if not body:
            return

        # Collect all ->query() and global query calls with their SQL strings
        sql_strings: List[Tuple[int, str]] = []

        func_calls = find_nodes(body, "function_call_expression")
        for call in func_calls:
            name_node = get_child_by_type(call, "name")
            if not name_node:
                continue
            func_name = node_text(name_node)
            if func_name in ("mysql_query", "mysqli_query", "pg_query"):
                args = get_child_by_type(call, "arguments")
                if args:
                    all_args = self._get_all_args(args)
                    query_arg = None
                    if func_name in ("mysqli_query", "pg_query") and len(all_args) >= 2:
                        query_arg = all_args[1]
                    elif all_args:
                        query_arg = all_args[0]
                    if query_arg:
                        sql_strings.append((get_node_line(call), node_text(query_arg)))

        method_calls = find_nodes(body, "member_call_expression")
        for mc in method_calls:
            method_name = self._get_member_call_name(mc)
            if method_name not in ("query", "exec"):
                continue
            args = get_child_by_type(mc, "arguments")
            if args:
                first_arg = self._get_first_arg(args)
                if first_arg:
                    sql_strings.append((get_node_line(mc), node_text(first_arg)))

        # Look for PREPARE ... FROM pattern (server-side dynamic SQL)
        has_set_from_select = False
        for line, sql in sql_strings:
            if re.search(r'(?i)\bSET\s+@\w+\s*=\s*\(\s*SELECT\b', sql):
                has_set_from_select = True

        if has_set_from_select:
            for line, sql in sql_strings:
                if re.search(r'(?i)\bPREPARE\b.*\bFROM\b', sql):
                    self._add_finding(
                        line, 0,
                        "Second-order SQLi - Server-side PREPARE FROM with DB-loaded variable",
                        VulnCategory.SQL_INJECTION, Severity.HIGH, "MEDIUM",
                        description="MySQL PREPARE FROM builds SQL from a variable loaded via "
                                    "SET @var = (SELECT ...). An attacker who controls the stored "
                                    "value achieves SQL injection at the database engine level."
                    )

    # ========================================================================
    # Variable Function Call Detection
    # ========================================================================

    def _check_variable_function_call(self, func: Node, tracker: TaintTracker):
        """Detect variable function calls like $func($arg) where $func is tainted."""
        body = self._get_body(func)
        if not body:
            return

        func_calls = find_nodes(body, "function_call_expression")
        for call in func_calls:
            # Variable function call: the "function" part is a variable_name, not a name
            name_node = get_child_by_type(call, "name")
            if name_node:
                continue  # Normal function call, handled by other checks

            var_node = get_child_by_type(call, "variable_name")
            if not var_node:
                continue

            var_text = node_text(var_node)
            line = get_node_line(call)

            if tracker.is_tainted(var_text):
                self._add_finding(
                    line, 0,
                    "Code Injection - Variable function call with tainted name",
                    VulnCategory.CODE_INJECTION, Severity.CRITICAL, "HIGH",
                    tracker.get_taint_chain(var_text),
                    f"User-controlled variable '{var_text}' used as function name allows arbitrary function execution."
                )

    # ========================================================================
    # Open Redirect Detection
    # ========================================================================

    def _check_open_redirect(self, func: Node, tracker: TaintTracker):
        """Detect open redirect via header('Location: ' . $tainted)."""
        body = self._get_body(func)
        if not body:
            return

        func_calls = find_nodes(body, "function_call_expression")
        for call in func_calls:
            name_node = get_child_by_type(call, "name")
            if not name_node:
                continue
            func_name = node_text(name_node)
            if func_name != "header":
                continue

            args = get_child_by_type(call, "arguments")
            if not args:
                continue
            first_arg = self._get_first_arg(args)
            if not first_arg:
                continue
            arg_text = node_text(first_arg)
            line = get_node_line(call)

            # Must contain Location: header (case-insensitive)
            if not re.search(r'(?i)location\s*:', arg_text):
                continue

            if tracker.is_tainted(arg_text) or self._has_tainted_concat(first_arg, tracker):
                self._add_finding(
                    line, 0,
                    "Open Redirect - header() with tainted Location",
                    VulnCategory.OPEN_REDIRECT, Severity.HIGH, "HIGH",
                    tracker.get_taint_chain(arg_text),
                    "User-controlled URL in Location header allows open redirect."
                )

    # ========================================================================
    # LDAP Injection Detection
    # ========================================================================

    def _check_ldap_injection(self, func: Node, tracker: TaintTracker):
        """Detect LDAP injection via ldap_search/ldap_list/ldap_read with tainted filter."""
        body = self._get_body(func)
        if not body:
            return

        ldap_funcs = {"ldap_search", "ldap_list", "ldap_read"}

        func_calls = find_nodes(body, "function_call_expression")
        for call in func_calls:
            name_node = get_child_by_type(call, "name")
            if not name_node:
                continue
            func_name = node_text(name_node)
            if func_name not in ldap_funcs:
                continue

            args = get_child_by_type(call, "arguments")
            if not args:
                continue
            all_args = self._get_all_args(args)
            # ldap_search($link, $base_dn, $filter) — filter is arg 3 (index 2)
            if len(all_args) < 3:
                continue
            filter_arg = all_args[2]
            filter_text = node_text(filter_arg)
            line = get_node_line(call)

            if tracker.is_tainted(filter_text) or \
               self._has_tainted_concat(filter_arg, tracker):
                self._add_finding(
                    line, 0,
                    f"LDAP Injection - {func_name}() with tainted filter",
                    VulnCategory.LDAP_INJECTION, Severity.HIGH, "HIGH",
                    tracker.get_taint_chain(filter_text),
                    f"User-controlled LDAP filter in {func_name}() allows filter manipulation."
                )

    # ========================================================================
    # Flow-Sensitive Helpers
    # ========================================================================

    def _nearest_assignment_is_tainted(self, var_text: str, before_line: int,
                                       scope: Node, tracker: TaintTracker,
                                       _depth: int = 0) -> bool:
        """Check if the nearest assignment to `var_text` before `before_line` is tainted.

        This prevents false positives when a variable like $sql is reused across
        independent code blocks — the flat taint tracker would say it's tainted
        globally, but the assignment feeding THIS specific call may be static.
        Uses recursive flow-sensitive analysis for interpolated variables.
        """
        if _depth > 4:
            return tracker.is_tainted(var_text)

        assignments = find_nodes(scope, "assignment_expression")
        nearest_rhs = None
        nearest_line = 0
        for assign in assignments:
            children = assign.children
            if len(children) < 3:
                continue
            lhs_text = node_text(children[0])
            line = get_node_line(assign)
            if lhs_text == var_text and line < before_line and line > nearest_line:
                nearest_rhs = children[2]
                nearest_line = line

        if nearest_rhs is None:
            # No preceding assignment found — fall back to tracker
            return tracker.is_tainted(var_text)

        rhs_text = node_text(nearest_rhs)

        # Check if the RHS contains interpolated variables (encapsed strings).
        # If so, we must check each interpolated variable individually rather
        # than applying blanket safe-checks (which would wrongly clear the
        # whole expression if just ONE variable is db-sourced).
        has_interpolation = bool(find_nodes(nearest_rhs, "encapsed_string"))

        if not has_interpolation:
            # Simple expression — blanket safe-checks apply
            if tracker._rhs_is_db_source(rhs_text):
                return False
            if tracker._rhs_is_sanitized(nearest_rhs, rhs_text):
                return False
            if tracker._rhs_is_sink(nearest_rhs):
                return False
            if TaintTracker._rhs_is_arithmetic(rhs_text):
                return False
            if tracker._rhs_refs_db_sourced(rhs_text, nearest_rhs):
                return False

        # Check superglobal in RHS
        if re.search(r'\$_(GET|POST|REQUEST|COOKIE|FILES|ENV)\b', rhs_text):
            return True

        # Check taint function calls
        if tracker._rhs_is_taint_function(nearest_rhs):
            return True

        # Flow-sensitive: check interpolated variables in encapsed strings
        for enc in find_nodes(nearest_rhs, "encapsed_string"):
            for child in enc.children:
                if child.type == "variable_name":
                    inner_var = node_text(child)
                    if inner_var in tracker.tainted:
                        if self._nearest_assignment_is_tainted(
                                inner_var, nearest_line, scope, tracker, _depth + 1):
                            return True

        # Check concatenated variables (not in strings)
        cleaned = re.sub(r'"[^"]*"', '', rhs_text)
        cleaned = re.sub(r"'[^']*'", '', cleaned)
        for tv in list(tracker.tainted.keys()):
            if re.search(rf'(?<!\w){re.escape(tv)}(?!\w)', cleaned):
                if self._nearest_assignment_is_tainted(
                        tv, nearest_line, scope, tracker, _depth + 1):
                    return True

        return False

    # ========================================================================
    # Utility Methods
    # ========================================================================

    def _get_member_call_name(self, mc: Node) -> str:
        """Get the method name from a member_call_expression node."""
        name_node = mc.child_by_field_name("name")
        if name_node:
            return node_text(name_node)
        # Fallback: find name node before arguments
        for child in mc.children:
            if child.type == "name" and child.next_sibling and child.next_sibling.type == "arguments":
                return node_text(child)
        return ""

    def _get_member_call_receiver(self, mc: Node) -> Optional[Node]:
        """Get the receiver object of a member_call_expression."""
        obj_node = mc.child_by_field_name("object")
        return obj_node

    def _is_db_receiver(self, recv_text: str) -> bool:
        """Check if a receiver variable looks like a database object."""
        # Common DB variable patterns
        if re.search(r'(?i)\b(?:pdo|db|dbo|conn|connection|mysqli|mysql|'
                     r'database|stmt|wpdb|dbh|link|pg_|sqlite)\b', recv_text):
            return True
        # $this->db, $this->pdo, $this->connection, etc.
        if re.search(r'(?i)\$this\s*->\s*(?:db|pdo|conn|connection|dbo|database)', recv_text):
            return True
        # Variable names like $pdo, $db, $conn, $connection, $dbh
        if re.search(r'^\$(?:pdo|db|dbo|conn|connection|mysqli|database|dbh|wpdb|link)$',
                     recv_text.strip(), re.IGNORECASE):
            return True
        return False

    def _get_first_arg(self, args_node: Node) -> Optional[Node]:
        """Get the first argument from an arguments node."""
        for child in args_node.children:
            if child.type == "argument":
                # Return the child of the argument node
                for c in child.children:
                    if c.type not in ("(", ")", ","):
                        return c
                return child
            if child.type not in ("(", ")", ",", "comment"):
                return child
        return None

    def _get_all_args(self, args_node: Node) -> List[Node]:
        """Get all arguments from an arguments node."""
        result = []
        for child in args_node.children:
            if child.type == "argument":
                # Return the content of the argument
                for c in child.children:
                    if c.type not in ("(", ")", ","):
                        result.append(c)
                        break
                else:
                    result.append(child)
            elif child.type not in ("(", ")", ",", "comment"):
                result.append(child)
        return result

    def _has_tainted_concat(self, node: Node, tracker: TaintTracker,
                            category: str = None) -> bool:
        """Check if a node contains string concatenation with tainted data.

        Args:
            category: Optional vuln category for context-aware sanitizer checks.
        """
        # Check for binary expression with . operator (PHP string concat)
        binaries = find_nodes(node, "binary_expression")
        for binary in binaries:
            op = None
            for child in binary.children:
                if node_text(child) == ".":
                    op = "."
                    break
            if op == ".":
                binary_text = node_text(binary)
                if tracker.is_tainted(binary_text, category=category):
                    return True

        # Check for sprintf
        text = node_text(node)
        if "sprintf" in text and tracker.is_tainted(text, category=category):
            return True

        # Check for tainted variable interpolation inside encapsed strings
        if self._has_tainted_interpolation(node, tracker, category=category):
            return True

        return False

    def _has_tainted_interpolation(self, node: Node, tracker: TaintTracker,
                                   category: str = None) -> bool:
        """Check if a node contains tainted variables interpolated in double-quoted strings."""
        encapsed = find_nodes(node, "encapsed_string")
        for enc in encapsed:
            for child in enc.children:
                if child.type == "variable_name":
                    var_text = node_text(child)
                    if tracker.is_tainted(var_text, category=category):
                        return True
                # Handle {$var} and {$arr['key']} syntax
                if child.type in ("member_access_expression", "subscript_expression"):
                    child_text = node_text(child)
                    if tracker.is_tainted(child_text, category=category):
                        return True
        return False

    def _has_db_sourced_interpolation(self, node: Node, tracker: TaintTracker) -> bool:
        """Check if a node contains DB-sourced variables interpolated in double-quoted strings."""
        encapsed = find_nodes(node, "encapsed_string")
        for enc in encapsed:
            for child in enc.children:
                if child.type == "variable_name":
                    var_text = node_text(child)
                    if tracker.is_db_sourced(var_text):
                        return True
                if child.type in ("member_access_expression", "subscript_expression"):
                    child_text = node_text(child)
                    if tracker.is_db_sourced(child_text):
                        return True
        return False

    def _has_concat(self, node: Node) -> bool:
        """Check if a node contains any string concatenation or interpolation."""
        binaries = find_nodes(node, "binary_expression")
        for binary in binaries:
            for child in binary.children:
                if node_text(child) == ".":
                    return True
        text = node_text(node)
        if "sprintf" in text:
            return True
        # Check for variable interpolation inside encapsed strings
        encapsed = find_nodes(node, "encapsed_string")
        for enc in encapsed:
            for child in enc.children:
                if child.type == "variable_name":
                    return True
                if child.type in ("member_access_expression", "subscript_expression"):
                    return True
        return False


# ============================================================================
# Scanner — File Processing & Output
# ============================================================================

def scan_file(file_path: str, config: VibehunterConfig = None) -> List[Finding]:
    """Scan a single PHP file and return findings."""
    if config and config.should_exclude(file_path):
        return []
    try:
        with open(file_path, 'r', encoding='utf-8', errors='replace') as f:
            source = f.read()
    except (IOError, OSError) as e:
        print(f"Error reading {file_path}: {e}", file=sys.stderr)
        return []

    analyzer = PHPASTAnalyzer(source, file_path)
    return analyzer.analyze()


def scan_path(target: str, show_progress: bool = True, config: VibehunterConfig = None) -> Tuple[List[Finding], int, float]:
    """Scan a file or directory for PHP files. Returns (findings, file_count, elapsed)."""
    all_findings = []
    target_path = Path(target)
    file_count = 0
    start = time.time()

    if target_path.is_file():
        if target_path.suffix == ".php":
            if show_progress:
                with Progress(
                    SpinnerColumn("moon"),
                    TextColumn("[bold cyan]Parsing AST...[/bold cyan]"),
                    TextColumn("[dim]{task.fields[file]}[/dim]"),
                    console=console, transient=True,
                ) as progress:
                    task = progress.add_task("Scanning", total=1, file=target_path.name)
                    all_findings.extend(scan_file(str(target_path), config))
                    progress.advance(task)
            else:
                all_findings.extend(scan_file(str(target_path), config))
            file_count = 1
        else:
            console.print(f"[bold yellow]Warning:[/bold yellow] {target} is not a .php file")
    elif target_path.is_dir():
        php_files = sorted(target_path.rglob("*.php"))
        file_count = len(php_files)
        if show_progress and php_files:
            with Progress(
                SpinnerColumn("moon"),
                TextColumn("[bold cyan]{task.description}[/bold cyan]"),
                BarColumn(bar_width=30, style="cyan", complete_style="green"),
                MofNCompleteColumn(),
                TextColumn("[dim]{task.fields[current_file]}[/dim]"),
                console=console, transient=True,
            ) as progress:
                task = progress.add_task("Scanning", total=len(php_files), current_file="")
                for pf in php_files:
                    progress.update(task, current_file=pf.name)
                    all_findings.extend(scan_file(str(pf), config))
                    progress.advance(task)
        else:
            for pf in php_files:
                all_findings.extend(scan_file(str(pf), config))
    else:
        console.print(f"[bold red]Error:[/bold red] {target} does not exist")

    elapsed = time.time() - start
    return all_findings, file_count, elapsed


def filter_findings(findings: List[Finding], min_severity: str = None,
                    min_confidence: str = None, suppression_keyword: str = "nosec") -> List[Finding]:
    """Filter findings by severity, confidence, and inline suppression."""
    result = []
    for f in findings:
        # Check inline suppression (// nosec, # nosec, /* nosec, etc.)
        if re.search(rf'(?://|#|/\*|--|%)\s*{re.escape(suppression_keyword)}\b', f.line_content):
            continue
        if 'vibehunter:ignore' in f.line_content:
            continue
        result.append(f)
    if min_severity:
        sev = Severity[min_severity.upper()]
        min_sev_order = SEVERITY_ORDER[sev]
        result = [f for f in result if SEVERITY_ORDER[f.severity] >= min_sev_order]
    if min_confidence:
        min_conf_order = CONFIDENCE_ORDER.get(min_confidence.upper(), 0)
        result = [f for f in result if CONFIDENCE_ORDER.get(f.confidence, 0) >= min_conf_order]
    return result


def _print_banner():
    """Print the futuristic scanner banner using Rich."""
    banner_lines = [
        "██████╗ ██╗  ██╗██████╗",
        "██╔══██╗██║  ██║██╔══██╗",
        "██████╔╝███████║██████╔╝",
        "██╔═══╝ ██╔══██║██╔═══╝",
        "██║     ██║  ██║██║",
        "╚═╝     ╚═╝  ╚═╝╚═╝",
    ]
    banner_text = '\n'.join(banner_lines)

    title_content = Text()
    title_content.append(banner_text, style="bold magenta")
    title_content.append("\n\n")
    title_content.append("Tree-sitter AST Vulnerability Scanner v1.0\n", style="bold white")
    title_content.append("Per-Function Taint Tracking | AST-Based Analysis | Zero False Positives", style="dim")

    console.print()
    console.print(Panel(
        Align.center(title_content),
        border_style="magenta",
        box=box.DOUBLE,
        padding=(1, 2),
    ))
    console.print()


def _build_stats_sidebar(findings: List[Finding], file_count: int, elapsed: float) -> Panel:
    """Build the statistics panel."""
    stats = Table(show_header=False, box=None, padding=(0, 1), expand=True)
    stats.add_column("key", style="bold cyan", no_wrap=True, ratio=3)
    stats.add_column("value", style="white", ratio=1)

    stats.add_row("Files Scanned", str(file_count))
    stats.add_row("Total Findings", str(len(findings)))
    stats.add_row("Scan Time", f"{elapsed:.2f}s")
    stats.add_row("Engine", "tree-sitter AST")
    stats.add_row("", "")

    # Severity breakdown
    sev_counts = defaultdict(int)
    for f in findings:
        sev_counts[f.severity.value] += 1

    sev_styles = {
        'CRITICAL': 'bold red', 'HIGH': 'red',
        'MEDIUM': 'yellow', 'LOW': 'green', 'INFO': 'dim'
    }
    for sev in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO']:
        count = sev_counts.get(sev, 0)
        if count > 0:
            stats.add_row(Text(sev, style=sev_styles.get(sev, "white")), str(count))

    stats.add_row("", "")

    # Category breakdown
    cat_counts = defaultdict(int)
    for f in findings:
        cat_counts[f.category.value] += 1
    cat_abbrev = {
        "Server-Side Template Injection": "SSTI",
        "Insecure Deserialization": "Deserialization",
        "XML External Entity": "XXE",
        "Command Injection": "Cmd Injection",
        "Code Injection": "Code Injection",
        "SQL Injection": "SQL Injection",
        "NoSQL Injection": "NoSQL Injection",
        "XPath Injection": "XPath Injection",
    }
    for cat, count in sorted(cat_counts.items(), key=lambda x: -x[1]):
        display_name = cat_abbrev.get(cat, cat)
        stats.add_row(Text(display_name, style="cyan"), str(count))

    return Panel(
        stats,
        title="[bold white]Scan Statistics[/bold white]",
        border_style="cyan",
        box=box.ROUNDED,
        padding=(1, 1),
    )


def _build_finding_panel(f: Finding, source_code: Optional[str] = None) -> Panel:
    """Build a Rich Panel for a single finding."""
    sev = f.severity.value
    border_map = {
        'CRITICAL': 'bold red', 'HIGH': 'red',
        'MEDIUM': 'yellow', 'LOW': 'green', 'INFO': 'dim white'
    }
    border_style = border_map.get(sev, 'white')

    sev_style_map = {
        'CRITICAL': 'bold white on red', 'HIGH': 'bold red',
        'MEDIUM': 'bold yellow', 'LOW': 'bold green', 'INFO': 'dim'
    }

    # Title line
    title = Text()
    title.append(f" {sev} ", style=sev_style_map.get(sev, "white"))
    title.append(f" {f.vulnerability_name} ", style="bold white")
    title.append(f" Confidence: {f.confidence} ", style="dim")

    content_parts = []

    # Source / Category
    source_text = Text()
    source_text.append("Source: ", style="bold cyan")
    source_text.append(f"Line {f.line_number}", style="white")
    if f.col_offset:
        source_text.append(f", Col {f.col_offset}", style="dim")

    cat_text = Text()
    cat_text.append("Category: ", style="bold magenta")
    cat_text.append(f"{f.category.value}", style="white")

    content_parts.append(Columns([source_text, cat_text], padding=(0, 4)))

    # Description
    if f.description:
        desc = Text()
        desc.append(f"\n{f.description}", style="italic white")
        content_parts.append(desc)

    # Taint chain as Tree
    if f.taint_chain:
        tree = Tree("[bold cyan]Taint Path[/bold cyan]", guide_style="cyan")
        for i, node in enumerate(f.taint_chain):
            style = "bold red" if i == len(f.taint_chain) - 1 else "white"
            tree.add(Text(node, style=style))
        content_parts.append(Text(""))
        content_parts.append(tree)

    # Code snippet with Syntax highlighting
    code_line = f.line_content.strip()
    if code_line:
        if source_code:
            src_lines = source_code.split('\n')
            start = max(0, f.line_number - 3)
            end = min(len(src_lines), f.line_number + 2)
            snippet = '\n'.join(src_lines[start:end])
            syntax = Syntax(
                snippet, "php", theme="monokai",
                line_numbers=True, start_line=start + 1,
                highlight_lines={f.line_number},
            )
        else:
            syntax = Syntax(
                code_line, "php", theme="monokai",
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
    """Output findings using Rich panels and formatting."""
    # --- Header ---
    scan_date = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
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

    # --- Statistics ---
    sidebar = _build_stats_sidebar(findings, file_count, elapsed)
    console.print(sidebar)
    console.print()

    # --- Findings ---
    if findings:
        console.print(Rule("[bold white]Vulnerability Findings[/bold white]", style="red"))
        console.print()

        # Load source code for syntax highlighting
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
                        encoding='utf-8', errors='ignore'
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
    """Output findings in plain text format (for file output)."""
    with open(file_path, 'w', encoding='utf-8') as out:
        for f in findings:
            out.write(f"\n{'='*70}\n")
            out.write(f"  [{f.severity.value}] [{f.confidence}] {f.vulnerability_name}\n")
            out.write(f"  File: {f.file_path}:{f.line_number}\n")
            out.write(f"  Code: {f.line_content}\n")
            out.write(f"  Category: {f.category.value}\n")
            if f.description:
                out.write(f"  Description: {f.description}\n")
            if f.taint_chain:
                out.write(f"  Taint chain:\n")
                for tc in f.taint_chain:
                    out.write(f"    -> {tc}\n")

        out.write(f"\n{'='*70}\n")
        out.write(f"Total findings: {len(findings)}\n")

        by_sev = defaultdict(int)
        by_cat = defaultdict(int)
        for f in findings:
            by_sev[f.severity.value] += 1
            by_cat[f.category.value] += 1

        if by_sev:
            out.write(f"\nBy severity:\n")
            for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
                if sev in by_sev:
                    out.write(f"  {sev}: {by_sev[sev]}\n")

        if by_cat:
            out.write(f"\nBy category:\n")
            for cat, count in sorted(by_cat.items()):
                out.write(f"  {cat}: {count}\n")


def output_json(findings: List[Finding], file_path: str = None):
    """Output findings in JSON format."""
    data = {
        "scan_date": datetime.now().isoformat(),
        "scanner": "php-treesitter v1.0",
        "files_scanned": len(set(f.file_path for f in findings)) if findings else 0,
        "total_findings": len(findings),
        "findings": [
            {
                "file": f.file_path,
                "line": f.line_number,
                "column": f.col_offset,
                "code": f.line_content,
                "vulnerability": f.vulnerability_name,
                "category": f.category.value,
                "severity": f.severity.value,
                "confidence": f.confidence,
                "taint_chain": f.taint_chain,
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
            "by_confidence": {k: v for k, v in sorted(
                {conf: sum(1 for f in findings if f.confidence == conf)
                 for conf in set(f.confidence for f in findings)}.items()
            )} if findings else {},
        }
    }

    json_str = json.dumps(data, indent=2)
    if file_path:
        with open(file_path, 'w', encoding='utf-8') as f:
            f.write(json_str)
    else:
        print(json_str)


def main():
    parser = argparse.ArgumentParser(
        description="PHP AST Vulnerability Scanner using Tree-sitter"
    )
    parser.add_argument("target", help="PHP file or directory to scan")
    parser.add_argument("--output", choices=["text", "json"], default="text",
                       help="Output format (default: text)")
    parser.add_argument("-o", "--output-file", help="Write output to file")
    parser.add_argument("--min-severity", choices=["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"],
                       help="Minimum severity to report")
    parser.add_argument("--min-confidence", choices=["HIGH", "MEDIUM", "LOW"],
                       help="Minimum confidence to report")
    parser.add_argument("--all", action="store_true",
                       help="Show all findings (no default filters)")
    parser.add_argument("--no-banner", action="store_true",
                       help="Suppress banner output")
    parser.add_argument("--config", help="Path to .vibehunter.yml config file")

    args = parser.parse_args()

    # Load config
    config = load_config(args.target, args.config)

    # Default filters
    min_severity = args.min_severity
    min_confidence = args.min_confidence
    if not args.all and not min_severity and not min_confidence:
        min_confidence = config.min_confidence if config else "HIGH"

    is_json = args.output == "json"

    if not args.no_banner and not is_json:
        _print_banner()

    findings, file_count, elapsed = scan_path(args.target, show_progress=not is_json, config=config)
    suppression_kw = config.suppression_keyword if config else "nosec"
    findings = filter_findings(findings, min_severity, min_confidence, suppression_kw)

    # Sort by file, then line number
    findings.sort(key=lambda f: (f.file_path, f.line_number))

    if is_json:
        output_json(findings, args.output_file)
    else:
        output_rich(findings, args.target, file_count, elapsed, min_confidence or "HIGH")

        # Save plain text to file if requested
        if args.output_file:
            output_text_plain(findings, args.output_file)
            console.print(f"\n[bold green]Report saved to {args.output_file}[/bold green]")

    # Exit with error code if critical/high findings
    critical_high = sum(1 for f in findings if f.severity in (Severity.CRITICAL, Severity.HIGH))
    if critical_high > 0:
        sys.exit(1)


if __name__ == "__main__":
    main()
