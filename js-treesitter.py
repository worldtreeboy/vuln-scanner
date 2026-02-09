#!/usr/bin/env python3
"""
js-treesitter - AST-Based JavaScript/TypeScript Vulnerability Scanner
=====================================================================
A structural analysis scanner for JavaScript/TypeScript files using tree-sitter AST parsing.

Features:
- JavaScript/TypeScript AST parsing via tree-sitter (ES6+ with error recovery)
- Source-to-sink taint tracking with multi-pass propagation
- SQL injection detection (mysql, pg, sequelize, knex, prisma)
- XSS detection (reflected, DOM-based)
- Server-side template injection (SSTI) detection
- Prototype pollution detection (for-in, Object.assign, spread, merge, etc.)
- Command injection detection
- NoSQL injection detection (MongoDB/Mongoose)
- Open redirect detection (including res.redirect)
- Async/await and Promise .then() taint propagation
- Inter-procedural taint flow analysis
- Rich terminal UI with syntax highlighting

Requirements:
    pip install tree-sitter tree-sitter-javascript rich

Usage:
    python3 js-treesitter.py target.js
    python3 js-treesitter.py /path/to/project --verbose
    python3 js-treesitter.py app.js --output json -o report.json
"""

import os
import sys
import json
import argparse
import re
import time
import shutil
import subprocess
from pathlib import Path
from dataclasses import dataclass, field
from typing import List, Dict, Set, Optional, Tuple
from enum import Enum
from datetime import datetime
from collections import defaultdict

import tree_sitter_javascript as tsjs
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

JS_LANG = Language(tsjs.language())

# ============================================================================
# Enums & Data Classes
# ============================================================================

class Severity(Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"

SEVERITY_ORDER = {
    Severity.CRITICAL: 4, Severity.HIGH: 3,
    Severity.MEDIUM: 2, Severity.LOW: 1,
}

CONFIDENCE_ORDER = {"HIGH": 3, "MEDIUM": 2, "LOW": 1}


class VulnCategory(Enum):
    DOM_XSS = "DOM-based XSS"
    REFLECTED_XSS = "Reflected XSS"
    PROTOTYPE_POLLUTION = "Prototype Pollution"
    DANGEROUS_EVAL = "Dangerous Eval"
    OPEN_REDIRECT = "Open Redirect"
    COMMAND_INJECTION = "Command Injection"
    SQL_INJECTION = "SQL Injection"
    NOSQL_INJECTION = "NoSQL Injection"
    SSTI = "Server-Side Template Injection"
    UNSAFE_DESERIALIZATION = "Unsafe Deserialization"
    VULNERABLE_DEPENDENCY = "Vulnerable Dependency"


@dataclass
class TaintedVar:
    """Represents a variable tainted by user-controlled data."""
    name: str
    line: int
    source_type: str
    source_code: str


@dataclass
class Finding:
    """Represents a vulnerability finding."""
    file_path: str
    line_number: int
    col_offset: int
    line_content: str
    vulnerability_name: str
    category: VulnCategory
    severity: Severity
    confidence: str
    description: str = ""
    source: Optional[str] = None
    sink: Optional[str] = None
    taint_chain: List[str] = field(default_factory=list)
    cwe_id: str = ""
    remediation: str = ""


# ============================================================================
# Source/Sink/Pattern Constants
# ============================================================================

MEMBER_SOURCES = {
    ('location', 'href'): ('url', 'HIGH'),
    ('location', 'search'): ('query', 'HIGH'),
    ('location', 'hash'): ('hash', 'HIGH'),
    ('location', 'pathname'): ('url', 'MEDIUM'),
    ('location', 'host'): ('url', 'LOW'),
    ('location', 'hostname'): ('url', 'LOW'),
    ('location', 'origin'): ('url', 'LOW'),
    ('location', 'protocol'): ('url', 'LOW'),
    ('document', 'URL'): ('url', 'HIGH'),
    ('document', 'documentURI'): ('url', 'HIGH'),
    ('document', 'referrer'): ('referrer', 'HIGH'),
    ('document', 'cookie'): ('cookie', 'HIGH'),
    ('document', 'location'): ('url', 'HIGH'),
    ('document', 'domain'): ('url', 'LOW'),
    ('window', 'location'): ('url', 'HIGH'),
    ('window', 'name'): ('window_name', 'HIGH'),
    ('localStorage', 'getItem'): ('storage', 'MEDIUM'),
    ('sessionStorage', 'getItem'): ('storage', 'MEDIUM'),
    ('req', 'query'): ('express_query', 'HIGH'),
    ('req', 'body'): ('express_body', 'HIGH'),
    ('req', 'params'): ('express_params', 'HIGH'),
    ('req', 'headers'): ('express_headers', 'HIGH'),
    ('req', 'cookies'): ('express_cookies', 'HIGH'),
    ('request', 'query'): ('express_query', 'HIGH'),
    ('request', 'body'): ('express_body', 'HIGH'),
    ('request', 'params'): ('express_params', 'HIGH'),
    ('process', 'argv'): ('process_argv', 'HIGH'),
    ('process', 'env'): ('process_env', 'MEDIUM'),
}

CALL_SOURCES = {
    'URLSearchParams': ('query', 'HIGH'),
    'URL': ('url', 'HIGH'),
    'val': ('input', 'MEDIUM'),
    'getItem': ('storage', 'MEDIUM'),
    'getElementById': ('dom', 'LOW'),
    'querySelector': ('dom', 'LOW'),
    'querySelectorAll': ('dom', 'LOW'),
    'getElementsByClassName': ('dom', 'LOW'),
    'getElementsByTagName': ('dom', 'LOW'),
}

PROPERTY_SINKS = {
    'innerHTML': (VulnCategory.DOM_XSS, Severity.CRITICAL, 'CWE-79'),
    'outerHTML': (VulnCategory.DOM_XSS, Severity.CRITICAL, 'CWE-79'),
    'srcdoc': (VulnCategory.DOM_XSS, Severity.CRITICAL, 'CWE-79'),
}

NAVIGATION_SINKS = {
    'href': (VulnCategory.OPEN_REDIRECT, Severity.HIGH, 'CWE-601'),
    'src': (VulnCategory.DOM_XSS, Severity.HIGH, 'CWE-79'),
    'action': (VulnCategory.OPEN_REDIRECT, Severity.MEDIUM, 'CWE-601'),
}

CALL_SINKS = {
    'eval': (VulnCategory.DANGEROUS_EVAL, Severity.CRITICAL, 'CWE-95'),
    'Function': (VulnCategory.DANGEROUS_EVAL, Severity.CRITICAL, 'CWE-95'),
    'execScript': (VulnCategory.DANGEROUS_EVAL, Severity.CRITICAL, 'CWE-95'),
    'setTimeout': (VulnCategory.DANGEROUS_EVAL, Severity.HIGH, 'CWE-95'),
    'setInterval': (VulnCategory.DANGEROUS_EVAL, Severity.HIGH, 'CWE-95'),
    'setImmediate': (VulnCategory.DANGEROUS_EVAL, Severity.HIGH, 'CWE-95'),
    'unserialize': (VulnCategory.UNSAFE_DESERIALIZATION, Severity.CRITICAL, 'CWE-502'),
    'deserialize': (VulnCategory.UNSAFE_DESERIALIZATION, Severity.CRITICAL, 'CWE-502'),
    'write': (VulnCategory.DOM_XSS, Severity.CRITICAL, 'CWE-79'),
    'writeln': (VulnCategory.DOM_XSS, Severity.CRITICAL, 'CWE-79'),
    'insertAdjacentHTML': (VulnCategory.DOM_XSS, Severity.CRITICAL, 'CWE-79'),
    'assign': (VulnCategory.OPEN_REDIRECT, Severity.HIGH, 'CWE-601'),
    'replace': (VulnCategory.OPEN_REDIRECT, Severity.HIGH, 'CWE-601'),
    'open': (VulnCategory.OPEN_REDIRECT, Severity.MEDIUM, 'CWE-601'),
    'html': (VulnCategory.DOM_XSS, Severity.CRITICAL, 'CWE-79'),
    'append': (VulnCategory.DOM_XSS, Severity.HIGH, 'CWE-79'),
    'prepend': (VulnCategory.DOM_XSS, Severity.HIGH, 'CWE-79'),
    'after': (VulnCategory.DOM_XSS, Severity.HIGH, 'CWE-79'),
    'before': (VulnCategory.DOM_XSS, Severity.HIGH, 'CWE-79'),
    'replaceWith': (VulnCategory.DOM_XSS, Severity.HIGH, 'CWE-79'),
    'wrapAll': (VulnCategory.DOM_XSS, Severity.HIGH, 'CWE-79'),
    'wrapInner': (VulnCategory.DOM_XSS, Severity.HIGH, 'CWE-79'),
}

EXPRESS_SINKS = {
    'send': (VulnCategory.REFLECTED_XSS, Severity.HIGH, 'CWE-79'),
    'end': (VulnCategory.REFLECTED_XSS, Severity.HIGH, 'CWE-79'),
    'render': (VulnCategory.REFLECTED_XSS, Severity.MEDIUM, 'CWE-79'),
}

COMMAND_SINKS = {
    'exec': (VulnCategory.COMMAND_INJECTION, Severity.CRITICAL, 'CWE-78'),
    'execSync': (VulnCategory.COMMAND_INJECTION, Severity.CRITICAL, 'CWE-78'),
    'spawn': (VulnCategory.COMMAND_INJECTION, Severity.CRITICAL, 'CWE-78'),
    'spawnSync': (VulnCategory.COMMAND_INJECTION, Severity.CRITICAL, 'CWE-78'),
    'execFile': (VulnCategory.COMMAND_INJECTION, Severity.CRITICAL, 'CWE-78'),
    'execFileSync': (VulnCategory.COMMAND_INJECTION, Severity.CRITICAL, 'CWE-78'),
    'fork': (VulnCategory.COMMAND_INJECTION, Severity.HIGH, 'CWE-78'),
}

VM_SINKS = {
    'runInContext': (VulnCategory.DANGEROUS_EVAL, Severity.CRITICAL, 'CWE-95'),
    'runInNewContext': (VulnCategory.DANGEROUS_EVAL, Severity.CRITICAL, 'CWE-95'),
    'runInThisContext': (VulnCategory.DANGEROUS_EVAL, Severity.CRITICAL, 'CWE-95'),
    'compileFunction': (VulnCategory.DANGEROUS_EVAL, Severity.CRITICAL, 'CWE-95'),
}

# SQL query methods that accept raw SQL strings (Node.js database drivers)
SQL_QUERY_METHODS = {
    'query', 'execute',       # mysql, mysql2, pg, better-sqlite3
}

SQL_RAW_METHODS = {
    'raw', 'whereRaw', 'havingRaw', 'orderByRaw', 'joinRaw', 'groupByRaw',  # knex
    '$queryRaw', '$executeRaw', '$queryRawUnsafe', '$executeRawUnsafe',       # prisma
}

# Known SQL database object names (from require/import aliases)
SQL_DB_OBJECTS = {
    'db', 'database', 'connection', 'conn', 'client', 'pool',
    'mysql', 'pg', 'knex', 'sequelize', 'prisma',
}

# Template engine methods that accept template strings (SSTI sinks)
SSTI_SINKS = {
    'render': ('ejs', 'pug', 'jade', 'nunjucks', 'mustache', 'dust'),
    'compile': ('ejs', 'pug', 'jade', 'Handlebars', 'handlebars', 'hbs', 'nunjucks', 'doT', 'dot'),
    'renderString': ('nunjucks',),
    'precompile': ('Handlebars', 'handlebars', 'hbs'),
    'renderFile': ('ejs', 'pug', 'jade'),
    'template': ('doT', 'dot', 'lodash', '_'),
    'renderSource': ('dust',),
}

# NoSQL / MongoDB / Mongoose query methods that accept filter objects
NOSQL_QUERY_METHODS = {
    'find', 'findOne', 'findById', 'findOneAndUpdate', 'findOneAndReplace',
    'findOneAndDelete', 'findByIdAndUpdate', 'findByIdAndDelete',
    'updateOne', 'updateMany', 'deleteOne', 'deleteMany',
    'count', 'countDocuments', 'estimatedDocumentCount',
    'distinct', 'where', 'replaceOne', 'aggregate',
    'bulkWrite', 'insertMany', 'insertOne', 'mapReduce',
}

PROTO_POLLUTION_PROPS = {'__proto__', 'constructor', 'prototype'}

DANGEROUS_MERGE_FUNCS = {
    'merge', 'mergeWith', 'defaultsDeep', 'set', 'setWith',
    'extend', 'assign',
    'deepMerge', 'deepExtend', 'deepClone',
}

SAFE_FUNCTIONS = {
    'encodeURIComponent', 'encodeURI', 'escape',
    'sanitize', 'sanitizeHtml', 'sanitizeHTML', 'sanitizeUrl',
    'escapeHtml', 'escapeHTML', 'htmlEncode', 'htmlEscape',
    'DOMPurify', 'xss', 'validator',
}

# DOM object hints: when a method like append/before/after is called on these,
# treat as DOM sink. Otherwise skip to reduce FPs on array/string methods.
_DOM_OBJECT_HINTS = {
    'el', 'elem', 'element', 'node', 'container', 'wrapper', 'div', 'span',
    'body', 'head', 'form', 'section', 'article', 'header', 'footer', 'nav',
    'main', 'aside', 'parent', 'child', 'target', 'root', 'content',
}

# DOM call sinks that require DOM context verification
_DOM_CONTEXT_SINKS = {'append', 'prepend', 'before', 'after'}

# Functions/methods that do NOT propagate taint to their return value
_NON_PROPAGATING = frozenset({
    'log', 'warn', 'error', 'info', 'debug', 'trace',  # logging
    'assert', 'expect', 'should',  # testing
    'emit', 'on', 'once', 'addEventListener',  # events
    'push', 'unshift', 'pop', 'shift', 'splice',  # array mutation
    'set', 'delete', 'clear', 'add',  # collection mutation
    'validate', 'check', 'verify', 'test',  # validation
    'write', 'send', 'end', 'json', 'render',  # output sinks
    'resolve', 'reject',  # promise
})

# Functions that neutralize taint (output is safe regardless of tainted input)
TAINT_NEUTRALIZING_FUNCS = SAFE_FUNCTIONS | {
    'parseInt', 'parseFloat', 'Number', 'Boolean',
    'isNaN', 'isFinite',
}

# Methods that return non-string/non-HTML values (boolean, number) – taint doesn't survive
TAINT_TERMINATING_METHODS = {
    'test', 'indexOf', 'lastIndexOf', 'includes',
    'startsWith', 'endsWith', 'search', 'every', 'some',
    'localeCompare',
}

SAFE_SINKS = {'textContent', 'innerText', 'text'}

TAINT_PROPAGATING_METHODS = {
    'join', 'toString', 'valueOf', 'concat', 'slice', 'substring',
    'substr', 'split', 'replace', 'replaceAll', 'trim', 'trimStart',
    'trimEnd', 'toLowerCase', 'toUpperCase', 'normalize', 'repeat',
    'padStart', 'padEnd', 'charAt', 'charCodeAt', 'at',
    'map', 'filter', 'reduce', 'find', 'flat', 'flatMap',
    'get', 'getAll', 'entries', 'values',  # accessor methods on tainted containers
}

REMEDIATION_MAP = {
    'innerHTML': "Use textContent for text, or sanitize with DOMPurify.sanitize() for HTML",
    'outerHTML': "Use textContent or sanitize with DOMPurify.sanitize()",
    'write': "Avoid document.write(). Use DOM APIs like createElement() and appendChild()",
    'writeln': "Avoid document.writeln(). Use DOM APIs instead",
    'eval': "Never use eval() with user input. Use JSON.parse() for JSON data",
    'Function': "Avoid the Function constructor with user input",
    'setTimeout': "Pass a function reference instead of a string",
    'setInterval': "Pass a function reference instead of a string",
    'href': "Validate URLs against an allowlist. Reject javascript: URLs",
    'src': "Validate URLs against an allowlist of trusted domains",
    'html': "Use .text() for text content, or sanitize with DOMPurify",
    'append': "Sanitize HTML content before appending",
    'insertAdjacentHTML': "Sanitize HTML content with DOMPurify.sanitize()",
    'assign': "Validate redirect URLs against an allowlist",
    'replace': "Validate redirect URLs against an allowlist",
    'exec': "Use parameterized commands or an allowlist. Never interpolate user input into shell strings",
    'execSync': "Use parameterized commands or an allowlist. Never interpolate user input into shell strings",
    'spawn': "Pass arguments as an array, not a shell string. Avoid {shell: true} with user input",
    'spawnSync': "Pass arguments as an array, not a shell string. Avoid {shell: true} with user input",
    'execFile': "Validate the executable path and arguments against an allowlist",
    'execFileSync': "Validate the executable path and arguments against an allowlist",
    'fork': "Validate the module path against an allowlist. Never allow user input to control forked modules",
    'unserialize': "Never deserialize untrusted data. Use JSON.parse() instead of node-serialize",
    'deserialize': "Never deserialize untrusted data. Use JSON.parse() instead",
    'redirect': "Validate redirect URLs against an allowlist of trusted paths/domains",
    'sql_query': "Use parameterized queries (? placeholders) instead of string concatenation",
    'sql_raw': "Use parameterized queries. For knex, use knex.raw('SELECT ? FROM ?', [val, table])",
    'ssti': "Never pass user input as the template string. Pass it as template data instead",
    'runInContext': "Never pass user-controlled code to vm module. The vm module is not a security sandbox",
    'runInNewContext': "Never pass user-controlled code to vm module. The vm module is not a security sandbox",
    'runInThisContext': "Never pass user-controlled code to vm module. The vm module is not a security sandbox",
    'compileFunction': "Never pass user-controlled code to vm.compileFunction(). Use a safe sandbox instead",
    'Script': "Never pass user-controlled code to new vm.Script(). The vm module is not a security sandbox",
    'load': "Use yaml.safeLoad() or yaml.load(data, { schema: SAFE_SCHEMA }) instead of yaml.load()",
    'nosql_find': "Never pass user-controlled objects directly to MongoDB queries. Use explicit field selection: {field: String(value)}",
    'nosql_update': "Never pass user-controlled objects to MongoDB update operations. Validate and whitelist fields.",
}


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


def get_node_col(node: Node) -> int:
    """Get 0-based column offset."""
    return node.start_point[1]


def get_child_by_type(node: Node, type_name: str) -> Optional[Node]:
    """Get first direct child of a given type."""
    for child in node.children:
        if child.type == type_name:
            return child
    return None


def get_children_by_type(node: Node, type_name: str) -> List[Node]:
    """Get all direct children of a given type."""
    return [c for c in node.children if c.type == type_name]


def get_child_by_field(node: Node, field_name: str) -> Optional[Node]:
    """Get child node by tree-sitter field name."""
    return node.child_by_field_name(field_name)


def get_call_args(node: Node) -> List[Node]:
    """Extract argument nodes from a call_expression's arguments list."""
    args_node = get_child_by_field(node, 'arguments')
    if not args_node:
        return []
    return [c for c in args_node.children if c.type not in ('(', ')', ',')]


def check_proto_in_text(text: str) -> Optional[str]:
    """Check if text contains __proto__, constructor.prototype access."""
    if '.__proto__' in text or "['__proto__']" in text or '["__proto__"]' in text:
        return '__proto__'
    if '.constructor.prototype' in text or "['constructor']['prototype']" in text:
        return 'constructor.prototype'
    return None


# ============================================================================
# TaintTracker
# ============================================================================

class TaintTracker:
    """Tracks tainted variables through JavaScript code using tree-sitter nodes."""

    def __init__(self, root: Node, source_lines: List[str]):
        self.root = root
        self.source_lines = source_lines
        self.tainted: Dict[str, TaintedVar] = {}
        self.function_params: Set[str] = set()
        # Set by JSASTAnalyzer after _build_function_summaries for inter-procedural analysis
        self.function_summaries: Dict[str, 'FunctionSummary'] = {}
        # Track variables assigned from pure literals — these are provably safe
        self.safe_literals: Set[str] = set()
        self._collect_safe_literals(root)
        self._propagate_taint()

    def _collect_safe_literals(self, root: Node):
        """Identify variables that are assigned from pure string/number literals.

        This allows us to suppress FPs like: const cmd = 'ls'; exec(cmd)
        since `cmd` is provably not user-controlled.
        """
        _LITERAL_TYPES = {'string', 'number', 'true', 'false', 'null', 'undefined'}

        for decl in find_nodes_multi(root, {'variable_declarator'}):
            name_node = get_child_by_field(decl, 'name')
            value_node = get_child_by_field(decl, 'value')
            if not name_node or not value_node:
                continue
            if name_node.type != 'identifier':
                continue
            var_name = node_text(name_node)
            # Direct literal: const cmd = 'ls'
            if value_node.type in _LITERAL_TYPES:
                self.safe_literals.add(var_name)
            # Template string with no substitutions: const cmd = `ls`
            elif value_node.type == 'template_string':
                if not any(True for _ in find_nodes(value_node, 'template_substitution')):
                    self.safe_literals.add(var_name)

        # Remove any that get reassigned to non-literals
        for assign in find_nodes(root, 'assignment_expression'):
            left = get_child_by_field(assign, 'left')
            right = get_child_by_field(assign, 'right')
            if left and left.type == 'identifier' and right:
                var_name = node_text(left)
                if var_name in self.safe_literals:
                    if right.type not in _LITERAL_TYPES:
                        # Reassigned to non-literal — no longer safe
                        self.safe_literals.discard(var_name)

    def _propagate_taint(self):
        """Multi-pass taint propagation through the AST."""
        for _ in range(3):
            self._propagation_pass(self.root)

    def repropagate_taint(self):
        """Re-run taint propagation from scratch.

        Called after function_summaries are set on this tracker so that
        is_tainted_node uses precise inter-procedural flow instead of
        the generic "any tainted arg" heuristic for user-defined functions.
        """
        self.tainted.clear()
        self.function_params.clear()
        self._propagate_taint()

    def _propagation_pass(self, root: Node):
        """Single pass: walk variable declarations and assignments to propagate taint."""
        # Variable declarations (var/let/const)
        for decl in find_nodes_multi(root, {'variable_declarator'}):
            name_node = get_child_by_field(decl, 'name')
            value_node = get_child_by_field(decl, 'value')
            if not name_node or not value_node:
                continue

            # Object destructuring: const { a, b } = source
            if name_node.type == 'object_pattern':
                self._handle_object_destructuring(name_node, value_node)
                continue

            # Array destructuring: const [a, b] = source
            if name_node.type == 'array_pattern':
                self._handle_array_destructuring(name_node, value_node)
                continue

            if name_node.type != 'identifier':
                continue

            var_name = node_text(name_node)
            source = self._check_source(value_node)
            if source:
                self.tainted[var_name] = TaintedVar(
                    name=var_name, line=get_node_line(decl),
                    source_type=source[0], source_code=node_text(value_node)
                )
                continue

            taint = self.is_tainted_node(value_node)
            if taint and var_name not in self.tainted:
                self.tainted[var_name] = TaintedVar(
                    name=var_name, line=get_node_line(decl),
                    source_type=taint.source_type, source_code=taint.source_code
                )

        # Assignment expressions
        for assign in find_nodes(root, 'assignment_expression'):
            left = get_child_by_field(assign, 'left')
            right = get_child_by_field(assign, 'right')
            if not left or not right:
                continue
            if left.type != 'identifier':
                continue

            var_name = node_text(left)
            source = self._check_source(right)
            if source:
                self.tainted[var_name] = TaintedVar(
                    name=var_name, line=get_node_line(assign),
                    source_type=source[0], source_code=node_text(right)
                )
            elif var_name not in self.tainted:
                taint = self.is_tainted_node(right)
                if taint:
                    self.tainted[var_name] = TaintedVar(
                        name=var_name, line=get_node_line(assign),
                        source_type=taint.source_type, source_code=taint.source_code
                    )

        # Track function params
        for func in find_nodes_multi(root, {'function_declaration', 'function', 'arrow_function'}):
            params_node = get_child_by_field(func, 'parameters')
            if not params_node:
                params_node = get_child_by_field(func, 'parameter')
                if params_node and params_node.type == 'identifier':
                    self.function_params.add(node_text(params_node))
                    continue
            if params_node:
                for child in params_node.children:
                    if child.type == 'identifier':
                        self.function_params.add(node_text(child))
                    elif child.type == 'assignment_pattern':
                        left = get_child_by_field(child, 'left')
                        if left and left.type == 'identifier':
                            self.function_params.add(node_text(left))

        # .then() callback taint propagation:
        # taintedPromise.then(data => ...) → taint 'data'
        for call in find_nodes(root, 'call_expression'):
            callee = get_child_by_field(call, 'function')
            if not callee or callee.type != 'member_expression':
                continue
            method_node = get_child_by_field(callee, 'property')
            if not method_node or node_text(method_node) != 'then':
                continue
            obj_node = get_child_by_field(callee, 'object')
            if not obj_node:
                continue
            taint = self.is_tainted_node(obj_node)
            if not taint:
                continue
            # Taint the first parameter of the .then() callback
            then_args = get_call_args(call)
            if then_args and then_args[0].type in ('arrow_function', 'function'):
                cb = then_args[0]
                cb_params = get_child_by_field(cb, 'parameters')
                if not cb_params:
                    cb_param = get_child_by_field(cb, 'parameter')
                    if cb_param and cb_param.type == 'identifier':
                        pname = node_text(cb_param)
                        if pname not in self.tainted:
                            self.tainted[pname] = TaintedVar(
                                name=pname, line=get_node_line(cb),
                                source_type=taint.source_type,
                                source_code=f".then({pname})"
                            )
                elif cb_params:
                    for child in cb_params.children:
                        if child.type == 'identifier':
                            pname = node_text(child)
                            if pname not in self.tainted:
                                self.tainted[pname] = TaintedVar(
                                    name=pname, line=get_node_line(cb),
                                    source_type=taint.source_type,
                                    source_code=f".then({pname})"
                                )
                            break  # only first param

    def _handle_object_destructuring(self, pattern: Node, value_node: Node):
        """Handle const { a, b } = taintedSource."""
        source = self._check_source(value_node)
        taint = self.is_tainted_node(value_node) if not source else None
        if not source and not taint:
            return

        source_type = source[0] if source else taint.source_type
        source_code = node_text(value_node)

        for child in pattern.children:
            var_name = None
            if child.type == 'shorthand_property_identifier_pattern':
                var_name = node_text(child)
            elif child.type == 'pair_pattern':
                val = get_child_by_field(child, 'value')
                if val and val.type == 'identifier':
                    var_name = node_text(val)
                elif not val:
                    key = get_child_by_field(child, 'key')
                    if key:
                        var_name = node_text(key)

            if var_name:
                self.tainted[var_name] = TaintedVar(
                    name=var_name, line=get_node_line(pattern),
                    source_type=source_type, source_code=f"{source_code}.{var_name}"
                )

    def _handle_array_destructuring(self, pattern: Node, value_node: Node):
        """Handle const [a, b] = taintedSource."""
        source = self._check_source(value_node)
        taint = self.is_tainted_node(value_node) if not source else None
        if not source and not taint:
            return

        source_type = source[0] if source else taint.source_type
        source_code = node_text(value_node)

        for i, child in enumerate(c for c in pattern.children if c.type == 'identifier'):
            var_name = node_text(child)
            self.tainted[var_name] = TaintedVar(
                name=var_name, line=get_node_line(pattern),
                source_type=source_type, source_code=f"{source_code}[{i}]"
            )

    def _check_source(self, node: Node) -> Optional[Tuple[str, str]]:
        """Check if node is a taint source. Returns (source_type, confidence) or None."""
        if not node:
            return None

        if node.type == 'member_expression':
            obj = get_child_by_field(node, 'object')
            prop = get_child_by_field(node, 'property')
            if not obj or not prop:
                return None
            obj_name = node_text(obj)
            prop_name = node_text(prop)

            key = (obj_name, prop_name)
            if key in MEMBER_SOURCES:
                return MEMBER_SOURCES[key]

            # Nested: window.location.hash, req.query.name
            if obj.type == 'member_expression':
                inner_obj = get_child_by_field(obj, 'object')
                inner_prop = get_child_by_field(obj, 'property')
                if inner_obj and inner_prop:
                    io = node_text(inner_obj)
                    ip = node_text(inner_prop)
                    if io in ('window', 'document', 'self') and ip == 'location':
                        if prop_name in ('href', 'search', 'hash', 'pathname'):
                            return ('url', 'HIGH')
                    if io in ('req', 'request'):
                        if ip in ('query', 'body', 'params', 'headers', 'cookies'):
                            return (f'express_{ip}', 'HIGH')

            # PostMessage: event.data
            if prop_name == 'data' and obj_name in ('event', 'e', 'evt', 'message', 'msg'):
                return ('postmessage', 'HIGH')

            # .value — only flag as taint source in DOM contexts
            if prop_name == 'value':
                # Check if the object looks like a DOM element access
                if obj.type == 'call_expression':
                    callee = get_child_by_field(obj, 'function')
                    callee_text = node_text(callee) if callee else ''
                    if any(dom_fn in callee_text for dom_fn in (
                        'getElementById', 'querySelector', 'getElementsBy',
                        'closest', 'find',  # jQuery
                    )):
                        return ('input', 'MEDIUM')
                    # jQuery $() selector
                    if callee_text in ('$', 'jQuery'):
                        return ('input', 'MEDIUM')
                # Direct DOM variable names (heuristic)
                if any(hint in obj_name.lower() for hint in (
                    'input', 'element', 'el', 'field', 'form', 'select', 'textarea',
                )):
                    return ('input', 'LOW')
                # Not a DOM context — don't treat as source
                return None

        elif node.type == 'subscript_expression':
            # Only treat as source when index is genuinely dynamic (not a literal)
            index = get_child_by_field(node, 'index')
            if index and index.type not in ('string', 'number', 'true', 'false', 'null'):
                obj = get_child_by_field(node, 'object')
                obj_name = node_text(obj) if obj else ''
                # Subscript on known taint containers is a source
                if obj_name in ('req', 'request'):
                    return ('express_dynamic', 'HIGH')
                return ('computed', 'LOW')
            # Literal index: not a taint source (e.g., arr[0], obj['key'])
            return None

        elif node.type == 'call_expression':
            callee = get_child_by_field(node, 'function')
            if not callee:
                return None
            if callee.type == 'identifier':
                func_name = node_text(callee)
                if func_name in CALL_SOURCES:
                    return CALL_SOURCES[func_name]
            elif callee.type == 'member_expression':
                method = node_text(get_child_by_field(callee, 'property') or callee)
                obj_name = node_text(get_child_by_field(callee, 'object') or callee)
                if method == 'get' and ('URLSearchParams' in obj_name or 'searchParams' in obj_name):
                    return ('query', 'HIGH')
                if method == 'getItem' and obj_name in ('localStorage', 'sessionStorage'):
                    return ('storage', 'MEDIUM')
                if method in ('json', 'text'):
                    return ('fetch_response', 'MEDIUM')
                # JSON.parse: only a source if its argument is tainted
                if obj_name == 'JSON' and method == 'parse':
                    parse_args = get_call_args(node)
                    if parse_args:
                        arg = parse_args[0]
                        # If argument is a literal string, JSON.parse is safe
                        if arg.type == 'string':
                            return None
                        # If argument references a tainted var, propagate
                        if arg.type == 'identifier':
                            if arg.text and arg.text.decode('utf-8') in getattr(self, 'tainted', {}):
                                return ('json_parse', 'HIGH')
                            # Check for known source patterns in the arg
                            inner = self._check_source(arg) if hasattr(self, '_check_source') else None
                            if inner:
                                return ('json_parse', 'HIGH')
                        # Non-literal arg — conservatively treat as potential source
                        if arg.type not in ('string', 'number', 'true', 'false', 'null'):
                            return ('json_parse', 'MEDIUM')
                    return None

        elif node.type == 'new_expression':
            constructor = get_child_by_field(node, 'constructor')
            if constructor and constructor.type == 'identifier':
                name = node_text(constructor)
                if name == 'URLSearchParams':
                    return ('query', 'HIGH')
                if name == 'URL':
                    return ('url', 'MEDIUM')

        return None

    def is_tainted_node(self, node: Node) -> Optional[TaintedVar]:
        """Recursively check if a tree-sitter node references tainted data."""
        if not node:
            return None

        if node.type == 'identifier':
            name = node_text(node)
            return self.tainted.get(name)

        if node.type == 'member_expression':
            obj = get_child_by_field(node, 'object')
            if obj:
                t = self.is_tainted_node(obj)
                if t:
                    return t
            full = node_text(node)
            base = full.split('.')[0].split('[')[0]
            t = self.tainted.get(base)
            if t:
                return t
            # Fall through to _check_source at bottom

        if node.type == 'subscript_expression':
            obj = get_child_by_field(node, 'object')
            if obj:
                t = self.is_tainted_node(obj)
                if t:
                    return t

        if node.type == 'binary_expression':
            left = get_child_by_field(node, 'left')
            right = get_child_by_field(node, 'right')
            return self.is_tainted_node(left) or self.is_tainted_node(right)

        if node.type in ('augmented_assignment_expression',):
            right = get_child_by_field(node, 'right')
            return self.is_tainted_node(right)

        if node.type == 'template_string':
            for sub in find_nodes(node, 'template_substitution'):
                for child in sub.children:
                    if child.type not in ('${', '}'):
                        t = self.is_tainted_node(child)
                        if t:
                            return t

        if node.type == 'call_expression':
            callee = get_child_by_field(node, 'function')
            if callee:
                # Safe/neutralizing functions break taint chain
                if callee.type == 'identifier':
                    if node_text(callee) in TAINT_NEUTRALIZING_FUNCS:
                        return None
                elif callee.type == 'member_expression':
                    obj_name = node_text(get_child_by_field(callee, 'object') or callee)
                    method_name = node_text(get_child_by_field(callee, 'property') or callee)
                    if obj_name in SAFE_FUNCTIONS:
                        return None
                    if method_name in ('sanitize', 'escape', 'encode', 'stringify'):
                        return None
                    if obj_name == 'JSON' and method_name == 'stringify':
                        return None
                    # Methods that return boolean/number – taint dies here
                    if method_name in TAINT_TERMINATING_METHODS:
                        return None
                # Taint-propagating methods
                if callee.type == 'member_expression':
                    method = node_text(get_child_by_field(callee, 'property') or callee)
                    if method in TAINT_PROPAGATING_METHODS:
                        obj = get_child_by_field(callee, 'object')
                        t = self.is_tainted_node(obj)
                        if t:
                            return t
                    # .then(callback) — propagate taint from the promise chain
                    # e.g., fetch(url).then(res => res.json()).then(data => ...)
                    if method == 'then':
                        obj = get_child_by_field(callee, 'object')
                        if obj:
                            t = self.is_tainted_node(obj)
                            if t:
                                return t
            # For generic calls, only propagate taint for known data-transforming
            # patterns (not every function that receives tainted args).
            # Functions like console.log, assert, validate, emit do NOT
            # produce tainted return values.
            callee_text = node_text(callee) if callee else ''
            # Extract the method/function name
            _callee_name = ''
            if callee.type == 'identifier':
                _callee_name = node_text(callee)
            elif callee.type == 'member_expression':
                _prop = get_child_by_field(callee, 'property')
                _callee_name = node_text(_prop) if _prop else ''

            if _callee_name not in _NON_PROPAGATING:
                # Inter-procedural: if we have a summary for this function,
                # only propagate taint through params that flow to return
                if (callee and callee.type == 'identifier'
                        and _callee_name in self.function_summaries):
                    summary = self.function_summaries[_callee_name]
                    if summary.param_to_return:
                        call_args = get_call_args(node)
                        for idx in summary.param_to_return:
                            if idx < len(call_args):
                                t = self.is_tainted_node(call_args[idx])
                                if t:
                                    return t
                    # Function exists but no param flows to return — not tainted
                    return None

                # Generic fallback for unknown functions
                for arg in get_call_args(node):
                    t = self.is_tainted_node(arg)
                    if t:
                        return t

        if node.type == 'await_expression':
            # await taintedPromise — propagate taint through await
            for child in node.children:
                if child.type != 'await':
                    t = self.is_tainted_node(child)
                    if t:
                        return t

        if node.type == 'ternary_expression':
            cons = get_child_by_field(node, 'consequence')
            alt = get_child_by_field(node, 'alternative')
            return self.is_tainted_node(cons) or self.is_tainted_node(alt)

        if node.type == 'parenthesized_expression':
            for child in node.children:
                if child.type not in ('(', ')'):
                    t = self.is_tainted_node(child)
                    if t:
                        return t

        if node.type == 'object':
            for child in node.children:
                if child.type == 'spread_element':
                    for sc in child.children:
                        if sc.type not in ('...', ):
                            t = self.is_tainted_node(sc)
                            if t:
                                return t
                elif child.type == 'pair':
                    val = get_child_by_field(child, 'value')
                    if val:
                        t = self.is_tainted_node(val)
                        if t:
                            return t

        if node.type == 'array':
            for child in node.children:
                if child.type not in ('[', ']', ','):
                    t = self.is_tainted_node(child)
                    if t:
                        return t

        # Check if node itself is a source
        source = self._check_source(node)
        if source:
            return TaintedVar(
                name=node_text(node), line=get_node_line(node),
                source_type=source[0], source_code=node_text(node)
            )

        return None

    def is_tainted_text(self, text: str) -> Optional[TaintedVar]:
        """Check if text references any tainted variable."""
        cleaned = re.sub(r'["\'][^"\']*["\']', '', text)
        for name, tv in self.tainted.items():
            if re.search(rf'\b{re.escape(name)}\b', cleaned):
                return tv
        return None

    def get_taint_chain(self, node: Node) -> List[str]:
        """Build taint chain for a node."""
        chain = []
        text = node_text(node)
        cleaned = re.sub(r'["\'][^"\']*["\']', '', text)
        for name, tv in self.tainted.items():
            if re.search(rf'\b{re.escape(name)}\b', cleaned):
                chain.append(f"{name} <- {tv.source_type} (line {tv.line})")
        return chain


@dataclass
class FunctionSummary:
    """Summary of a user-defined function for inter-procedural taint analysis."""
    name: str
    params: List[str]
    param_to_return: Set[int] = field(default_factory=set)  # param indices that flow to return
    tainted_return: bool = False


# ============================================================================
# JSASTAnalyzer - Main Scanner
# ============================================================================

class JSASTAnalyzer:
    """AST-based JavaScript vulnerability scanner using tree-sitter."""

    def __init__(self, source_code: str, file_path: str):
        self.source_code = source_code
        self.source_lines = source_code.splitlines()
        self.file_path = file_path
        self.findings: List[Finding] = []

        parser = Parser(JS_LANG)
        self.tree = parser.parse(source_code.encode('utf-8'))
        self.root = self.tree.root_node

        self.tracker = TaintTracker(self.root, self.source_lines)

        # Inter-procedural analysis: summarize user-defined functions
        self.function_summaries: Dict[str, FunctionSummary] = {}
        self._build_function_summaries()
        # Share summaries with tracker for precise call-expression taint checks,
        # then re-propagate taint so is_tainted_node uses the summaries
        self.tracker.function_summaries = self.function_summaries
        self.tracker.repropagate_taint()

        # Track require() aliases: variable → module name
        # e.g., const cp = require('child_process') → cp_aliases = {'cp'}
        self.child_process_aliases: Set[str] = self._find_require_aliases(
            'child_process'
        )

        # Track SQL database module aliases
        self.sql_aliases: Set[str] = set()
        for mod in ('mysql', 'mysql2', 'pg', 'better-sqlite3', 'sqlite3'):
            self.sql_aliases |= self._find_require_aliases(mod)
        self.knex_aliases: Set[str] = self._find_require_aliases('knex')
        self.sequelize_aliases: Set[str] = self._find_require_aliases('sequelize')
        self.prisma_aliases: Set[str] = self._find_require_aliases('@prisma/client')

        # Track template engine aliases for SSTI
        self.template_aliases: Dict[str, Set[str]] = {}
        for engine in ('ejs', 'pug', 'jade', 'nunjucks', 'mustache', 'handlebars',
                        'hbs', 'dot', 'doT', 'dust'):
            aliases = self._find_require_aliases(engine)
            if aliases:
                self.template_aliases[engine] = aliases

        # Track ES module import aliases
        self._collect_import_aliases()

    def _find_require_aliases(self, module_name: str) -> Set[str]:
        """Find all variable names that alias a require() call for a module.

        Matches patterns:
          const cp = require('child_process')
          const { exec, spawn } = require('child_process')
          import cp from 'child_process'  (handled by tree-sitter)
        """
        aliases: Set[str] = set()
        for decl in find_nodes(self.root, 'variable_declarator'):
            name_node = get_child_by_field(decl, 'name')
            value_node = get_child_by_field(decl, 'value')
            if not name_node or not value_node:
                continue
            if value_node.type == 'call_expression':
                callee = get_child_by_field(value_node, 'function')
                if callee and node_text(callee) == 'require':
                    req_args = get_call_args(value_node)
                    if req_args and node_text(req_args[0]).strip("'\"") == module_name:
                        if name_node.type == 'identifier':
                            aliases.add(node_text(name_node))
                        elif name_node.type == 'object_pattern':
                            # const { exec, spawn } = require('child_process')
                            for child in name_node.children:
                                if child.type == 'shorthand_property_identifier_pattern':
                                    aliases.add(node_text(child))
                                elif child.type == 'pair_pattern':
                                    val = get_child_by_field(child, 'value')
                                    if val and val.type == 'identifier':
                                        aliases.add(node_text(val))
        return aliases

    def _collect_import_aliases(self):
        """Track ES module import aliases for all relevant modules.

        Handles: import ejs from 'ejs'; import * as pg from 'pg';
                 import { render } from 'ejs';
        """
        for imp in find_nodes(self.root, 'import_statement'):
            source_node = get_child_by_field(imp, 'source')
            if not source_node:
                continue
            mod_name = node_text(source_node).strip("'\"")

            # Check for default import: import ejs from 'ejs'
            for child in imp.children:
                if child.type == 'identifier':
                    alias = node_text(child)
                    # SQL modules
                    if mod_name in ('mysql', 'mysql2', 'pg', 'better-sqlite3', 'sqlite3'):
                        self.sql_aliases.add(alias)
                    elif mod_name == 'knex':
                        self.knex_aliases.add(alias)
                    elif mod_name == 'sequelize':
                        self.sequelize_aliases.add(alias)
                    elif mod_name == '@prisma/client':
                        self.prisma_aliases.add(alias)
                    elif mod_name == 'child_process':
                        self.child_process_aliases.add(alias)
                    # Template engines
                    if mod_name in ('ejs', 'pug', 'jade', 'nunjucks', 'mustache',
                                    'handlebars', 'hbs', 'dot', 'doT', 'dust'):
                        self.template_aliases.setdefault(mod_name, set()).add(alias)

                elif child.type == 'import_clause':
                    for sub in child.children:
                        if sub.type == 'identifier':
                            alias = node_text(sub)
                            if mod_name in ('mysql', 'mysql2', 'pg', 'better-sqlite3', 'sqlite3'):
                                self.sql_aliases.add(alias)
                            elif mod_name == 'child_process':
                                self.child_process_aliases.add(alias)
                            if mod_name in ('ejs', 'pug', 'jade', 'nunjucks', 'mustache',
                                            'handlebars', 'hbs', 'dot', 'doT', 'dust'):
                                self.template_aliases.setdefault(mod_name, set()).add(alias)
                        elif sub.type == 'named_imports':
                            for spec in sub.children:
                                if spec.type == 'import_specifier':
                                    name_n = get_child_by_field(spec, 'name')
                                    alias_n = get_child_by_field(spec, 'alias')
                                    actual = node_text(alias_n or name_n) if (alias_n or name_n) else ''
                                    if actual and mod_name == 'child_process':
                                        self.child_process_aliases.add(actual)

    # ------------------------------------------------------------------
    # Inter-procedural analysis: function summaries
    # ------------------------------------------------------------------

    def _build_function_summaries(self):
        """Summarize user-defined functions: which params flow to return values.

        Handles:
          - function declarations:      function foo(a, b) { return a; }
          - variable-assigned functions: const foo = (a, b) => a;
          - variable-assigned function expressions: const foo = function(a, b) { return a; }
        """
        # --- function_declaration nodes ---
        for func_node in find_nodes(self.root, 'function_declaration'):
            name_node = get_child_by_field(func_node, 'name')
            if not name_node:
                continue
            func_name = node_text(name_node)
            params = self._extract_param_names(func_node)
            param_to_return = self._find_param_return_flow(func_node, params)
            self.function_summaries[func_name] = FunctionSummary(
                name=func_name,
                params=params,
                param_to_return=param_to_return,
                tainted_return=False,
            )

        # --- variable_declarator with arrow_function or function (expression) ---
        for decl in find_nodes(self.root, 'variable_declarator'):
            name_node = get_child_by_field(decl, 'name')
            value_node = get_child_by_field(decl, 'value')
            if not name_node or not value_node:
                continue
            if name_node.type != 'identifier':
                continue
            if value_node.type not in ('arrow_function', 'function'):
                continue

            func_name = node_text(name_node)
            params = self._extract_param_names(value_node)
            param_to_return = self._find_param_return_flow(value_node, params)
            self.function_summaries[func_name] = FunctionSummary(
                name=func_name,
                params=params,
                param_to_return=param_to_return,
                tainted_return=False,
            )

    def _extract_param_names(self, func_node: Node) -> List[str]:
        """Extract ordered parameter names from a function/arrow_function node."""
        params: List[str] = []
        params_node = get_child_by_field(func_node, 'parameters')
        if not params_node:
            # Single-param arrow: x => x + 1  (parameter field instead)
            param_node = get_child_by_field(func_node, 'parameter')
            if param_node and param_node.type == 'identifier':
                params.append(node_text(param_node))
            return params

        for child in params_node.children:
            if child.type == 'identifier':
                params.append(node_text(child))
            elif child.type == 'assignment_pattern':
                left = get_child_by_field(child, 'left')
                if left and left.type == 'identifier':
                    params.append(node_text(left))
            elif child.type == 'rest_pattern':
                # ...args
                for sc in child.children:
                    if sc.type == 'identifier':
                        params.append(node_text(sc))
            elif child.type == 'object_pattern':
                # Destructured param — treat as single opaque param
                params.append(node_text(child))
            elif child.type == 'array_pattern':
                params.append(node_text(child))
        return params

    def _find_param_return_flow(self, func_node: Node, params: List[str]) -> Set[int]:
        """Determine which parameter indices flow to a return value.

        Handles:
          - Explicit return statements:  return a;
          - Arrow expression bodies:     (a) => a + 1
          - Ternary / binary with params in return expressions
        """
        param_set = set(params)
        flowing_indices: Set[int] = set()

        # Arrow function with expression body (no block): (a) => a + 1
        body = get_child_by_field(func_node, 'body')
        if body and body.type != 'statement_block':
            # The body IS the return expression
            self._collect_param_refs_in_node(body, params, param_set, flowing_indices)
            return flowing_indices

        # Explicit return statements in function body
        for ret_node in find_nodes(func_node, 'return_statement'):
            # return_statement children: 'return' keyword + optional expression
            for child in ret_node.children:
                if child.type not in ('return', ';'):
                    self._collect_param_refs_in_node(child, params, param_set, flowing_indices)

        return flowing_indices

    def _collect_param_refs_in_node(
        self, node: Node, params: List[str],
        param_set: Set[str], flowing_indices: Set[int]
    ):
        """Recursively find identifiers in node that match function params."""
        if node.type == 'identifier':
            name = node_text(node)
            if name in param_set:
                for i, p in enumerate(params):
                    if p == name:
                        flowing_indices.add(i)
            return

        for child in node.children:
            self._collect_param_refs_in_node(child, params, param_set, flowing_indices)

    def _apply_interprocedural_taint(self):
        """Propagate taint through user-defined function calls.

        For every variable declaration or assignment where the RHS is a call
        to a summarised user-defined function, check whether any tainted
        argument sits at a parameter index that flows to the return value.
        If so, taint the LHS variable.

        This runs AFTER the TaintTracker has built its initial taint set and
        BEFORE the vulnerability check methods execute, so that downstream
        checks see the propagated taint.
        """
        if not self.function_summaries:
            return

        # Multiple passes to handle chains: f(g(tainted))
        for _ in range(3):
            new_taints = 0

            # --- Variable declarations: const result = userFunc(taintedArg) ---
            for decl in find_nodes(self.root, 'variable_declarator'):
                name_node = get_child_by_field(decl, 'name')
                value_node = get_child_by_field(decl, 'value')
                if not name_node or not value_node:
                    continue
                if name_node.type != 'identifier':
                    continue
                var_name = node_text(name_node)
                if var_name in self.tracker.tainted:
                    continue  # already tainted

                taint_info = self._check_interprocedural_call(value_node)
                if taint_info:
                    self.tracker.tainted[var_name] = taint_info
                    new_taints += 1

            # --- Assignment expressions: result = userFunc(taintedArg) ---
            for assign in find_nodes(self.root, 'assignment_expression'):
                left = get_child_by_field(assign, 'left')
                right = get_child_by_field(assign, 'right')
                if not left or not right:
                    continue
                if left.type != 'identifier':
                    continue
                var_name = node_text(left)
                if var_name in self.tracker.tainted:
                    continue

                taint_info = self._check_interprocedural_call(right)
                if taint_info:
                    self.tracker.tainted[var_name] = taint_info
                    new_taints += 1

            if new_taints == 0:
                break  # fixed point reached

    def _check_interprocedural_call(self, node: Node) -> Optional[TaintedVar]:
        """Check if a call_expression node invokes a user-defined function
        with tainted arguments at positions that flow to the return value.

        Returns a TaintedVar if taint propagates, None otherwise.
        """
        if node.type != 'call_expression':
            return None

        callee = get_child_by_field(node, 'function')
        if not callee or callee.type != 'identifier':
            return None

        func_name = node_text(callee)
        summary = self.function_summaries.get(func_name)
        if not summary:
            return None

        if not summary.param_to_return:
            return None  # function never returns a param-derived value

        args = get_call_args(node)
        for idx in summary.param_to_return:
            if idx < len(args):
                taint = self.tracker.is_tainted_node(args[idx])
                if taint:
                    return TaintedVar(
                        name=f"{func_name}(...)",
                        line=get_node_line(node),
                        source_type=taint.source_type,
                        source_code=f"{func_name}({taint.source_code})",
                    )
        return None

    def _get_line_content(self, line_num: int) -> str:
        if 0 < line_num <= len(self.source_lines):
            return self.source_lines[line_num - 1].strip()
        return ""

    def _is_sanitized(self, node: Node) -> bool:
        """Check if node appears to be sanitized."""
        if not node or node.type != 'call_expression':
            return False
        callee = get_child_by_field(node, 'function')
        if not callee:
            return False
        if callee.type == 'identifier':
            if node_text(callee) in SAFE_FUNCTIONS:
                return True
        elif callee.type == 'member_expression':
            obj = node_text(get_child_by_field(callee, 'object') or callee)
            method = node_text(get_child_by_field(callee, 'property') or callee)
            if obj in SAFE_FUNCTIONS or method in ('sanitize', 'escape', 'encode'):
                return True
            full = f"{obj}.{method}"
            if any(safe in full for safe in SAFE_FUNCTIONS):
                return True
        return False

    def _has_dynamic_content(self, node: Node) -> bool:
        """Check if a node contains any dynamic (non-literal) content.

        Returns True for template strings with substitutions, identifiers,
        member expressions, binary concatenation, call expressions, etc.
        Returns False only for plain string/number literals, template
        strings with no interpolation, and identifiers known to hold literals.
        """
        if node.type in ('string', 'number', 'true', 'false', 'null', 'undefined'):
            return False
        if node.type == 'template_string':
            subs = find_nodes(node, 'template_substitution')
            if not subs:
                return False  # No interpolation → pure literal
            # Check if every substitution is itself safe
            for sub in subs:
                for child in sub.children:
                    if child.type not in ('${', '}'):
                        if self._has_dynamic_content(child):
                            return True
            return False  # All substitutions are safe literals
        if node.type == 'identifier':
            name = node_text(node)
            # Well-known safe globals
            if name in ('undefined', 'NaN', 'Infinity', 'globalThis'):
                return False
            # Variable assigned from a literal — provably safe
            if name in self.tracker.safe_literals:
                return False
        if node.type == 'binary_expression':
            left = get_child_by_field(node, 'left')
            right = get_child_by_field(node, 'right')
            # 'prefix' + 'suffix' is still a literal
            if left and right:
                return self._has_dynamic_content(left) or self._has_dynamic_content(right)
        return True

    def _check_sink(self, node: Node, value_node: Node, sink_name: str,
                     sink_info: tuple, extra_desc: str = ""):
        """Check if a sink receives tainted data and report finding."""
        category, severity, cwe = sink_info

        if self._is_sanitized(value_node):
            return

        taint = self.tracker.is_tainted_node(value_node)
        if not taint:
            source = self.tracker._check_source(value_node)
            if source:
                taint = TaintedVar(
                    name=node_text(value_node), line=get_node_line(value_node),
                    source_type=source[0], source_code=node_text(value_node)
                )

        if taint:
            line = get_node_line(node)
            col = get_node_col(node)
            confidence = 'HIGH' if taint.source_type in (
                'url', 'query', 'hash', 'postmessage', 'cookie',
                'express_query', 'express_body', 'express_params',
                'express_headers', 'express_cookies'
            ) else 'MEDIUM'

            desc = extra_desc or f"Tainted data from '{taint.source_type}' source flows to sink '{sink_name}'"

            self.findings.append(Finding(
                file_path=self.file_path,
                line_number=line,
                col_offset=col,
                line_content=self._get_line_content(line),
                vulnerability_name=f"{category.value} via {sink_name}",
                category=category,
                severity=severity,
                confidence=confidence,
                description=desc,
                source=taint.source_code,
                sink=sink_name,
                taint_chain=self.tracker.get_taint_chain(value_node),
                cwe_id=cwe,
                remediation=REMEDIATION_MAP.get(sink_name, "Validate and sanitize user input before use")
            ))

    def _add_finding(self, node: Node, name: str, category: VulnCategory,
                      severity: Severity, confidence: str, description: str,
                      cwe: str, remediation: str, source: str = None,
                      sink: str = None, taint_chain: List[str] = None):
        """Helper to add a finding."""
        line = get_node_line(node)
        self.findings.append(Finding(
            file_path=self.file_path,
            line_number=line,
            col_offset=get_node_col(node),
            line_content=self._get_line_content(line),
            vulnerability_name=name,
            category=category,
            severity=severity,
            confidence=confidence,
            description=description,
            source=source,
            sink=sink,
            taint_chain=taint_chain or [],
            cwe_id=cwe,
            remediation=remediation
        ))

    def analyze(self) -> List[Finding]:
        """Run all vulnerability checks."""
        # Inter-procedural taint propagation: push taint through user-defined
        # function calls BEFORE running sink checks so that downstream checks
        # see the propagated taint.
        self._apply_interprocedural_taint()

        self._check_assignments()
        self._check_call_expressions()
        self._check_new_expressions()
        self._check_sql_injection()
        self._check_ssti()
        self._check_forin_pollution()
        self._check_function_param_pollution()
        return self.findings

    # ------------------------------------------------------------------
    # Assignment checks (innerHTML=, __proto__=, computed prop, spread)
    # ------------------------------------------------------------------

    def _check_assignments(self):
        """Check all assignment expressions for sink usage and prototype pollution."""
        for assign in find_nodes(self.root, 'assignment_expression'):
            left = get_child_by_field(assign, 'left')
            right = get_child_by_field(assign, 'right')
            if not left or not right:
                continue

            if left.type == 'member_expression':
                prop_node = get_child_by_field(left, 'property')
                prop_name = node_text(prop_node) if prop_node else ''

                # Property sinks: innerHTML, outerHTML, srcdoc
                if prop_name in PROPERTY_SINKS:
                    self._check_sink(assign, right, prop_name, PROPERTY_SINKS[prop_name])

                # Navigation sinks: href, src, action
                elif prop_name in NAVIGATION_SINKS:
                    obj_str = node_text(get_child_by_field(left, 'object') or left)
                    if 'location' in obj_str or prop_name == 'src':
                        self._check_sink(assign, right, prop_name, NAVIGATION_SINKS[prop_name])

                elif prop_name in SAFE_SINKS:
                    pass

                # __proto__ in member chain
                proto = check_proto_in_text(node_text(left))
                if proto:
                    self._add_finding(
                        assign, "Prototype Pollution",
                        VulnCategory.PROTOTYPE_POLLUTION, Severity.CRITICAL, 'HIGH',
                        f"Access to '{proto}' in property chain allows prototype pollution",
                        "CWE-1321", "Never allow __proto__ or constructor.prototype access from user input",
                        sink=proto
                    )

            elif left.type == 'subscript_expression':
                # obj[key] = value
                index_node = get_child_by_field(left, 'index')
                if index_node:
                    # Literal __proto__ access
                    idx_text = node_text(index_node).strip("'\"")
                    if idx_text in PROTO_POLLUTION_PROPS:
                        self._add_finding(
                            assign, "Prototype Pollution",
                            VulnCategory.PROTOTYPE_POLLUTION, Severity.CRITICAL, 'HIGH',
                            f"Direct access to '{idx_text}' allows prototype pollution",
                            "CWE-1321", "Never allow direct __proto__ or constructor.prototype access",
                            sink=idx_text
                        )
                    # Tainted key
                    elif self.tracker.is_tainted_node(index_node):
                        key_taint = self.tracker.is_tainted_node(index_node)
                        # Confidence based on taint source: only flag with
                        # HIGH/MEDIUM when the key is genuinely user-controlled
                        _HIGH_TAINT = (
                            'express_query', 'express_body', 'express_params',
                            'express_headers', 'express_cookies',
                            'url', 'query', 'hash', 'postmessage', 'cookie',
                        )
                        _MED_TAINT = ('input', 'storage', 'json_parse', 'fetch_response')
                        if key_taint.source_type in _HIGH_TAINT:
                            pp_conf = 'HIGH'
                        elif key_taint.source_type in _MED_TAINT:
                            pp_conf = 'MEDIUM'
                        else:
                            pp_conf = 'LOW'
                        self._add_finding(
                            assign, "Potential Prototype Pollution",
                            VulnCategory.PROTOTYPE_POLLUTION, Severity.HIGH, pp_conf,
                            f"Dynamic property assignment with tainted key. If key is '__proto__', prototype pollution occurs.",
                            "CWE-1321", "Validate keys against '__proto__', 'constructor', 'prototype'. Use Object.create(null) or Map.",
                            source=key_taint.source_code, sink="computed property assignment"
                        )

        # Check spread in variable declarations: const x = { ...tainted }
        for decl in find_nodes(self.root, 'variable_declarator'):
            value_node = get_child_by_field(decl, 'value')
            if value_node and value_node.type == 'object':
                for child in value_node.children:
                    if child.type == 'spread_element':
                        for sc in child.children:
                            if sc.type not in ('...', ):
                                taint = self.tracker.is_tainted_node(sc)
                                if taint:
                                    self._add_finding(
                                        child, "Prototype Pollution via Spread Operator",
                                        VulnCategory.PROTOTYPE_POLLUTION, Severity.HIGH, 'HIGH',
                                        f"Spreading tainted object '{taint.name}' can cause prototype pollution if it contains __proto__",
                                        "CWE-1321", "Sanitize object before spreading, or use Object.assign with Object.create(null)",
                                        source=taint.source_code, sink="{ ...obj }"
                                    )

    # ------------------------------------------------------------------
    # Call expression checks (eval, document.write, jQuery, express, fs, exec)
    # ------------------------------------------------------------------

    def _check_call_expressions(self):
        """Check all call expressions for sink usage."""
        for call in find_nodes(self.root, 'call_expression'):
            callee = get_child_by_field(call, 'function')
            args = get_call_args(call)
            if not callee:
                continue

            # Dynamic method invocation: obj[taintedKey]()
            if callee.type == 'subscript_expression':
                index_node = get_child_by_field(callee, 'index')
                if index_node:
                    key_taint = self.tracker.is_tainted_node(index_node)
                    if key_taint:
                        self._add_finding(
                            call, "Dynamic Method Invocation",
                            VulnCategory.PROTOTYPE_POLLUTION, Severity.CRITICAL, 'HIGH',
                            f"User-controlled method name '{key_taint.name}' allows invoking arbitrary methods.",
                            "CWE-94", "Validate method names against an allowlist.",
                            source=key_taint.source_code, sink="obj[userInput]()"
                        )

            # Direct function call: eval(), setTimeout()
            if callee.type == 'identifier':
                func_name = node_text(callee)
                if func_name in CALL_SINKS and args:
                    if func_name in ('setTimeout', 'setInterval', 'setImmediate'):
                        first_arg = args[0]
                        # Function expressions / arrow functions are always safe
                        _SAFE_CALLBACK_TYPES = {
                            'arrow_function', 'function_expression', 'function',
                            'generator_function',
                        }
                        if first_arg.type in _SAFE_CALLBACK_TYPES:
                            pass  # Safe: setTimeout(() => {...}, 1000)
                        elif first_arg.type == 'string':
                            # String literal passed to setTimeout IS code eval
                            self._check_sink(call, first_arg, func_name, CALL_SINKS[func_name])
                        elif self.tracker.is_tainted_node(first_arg):
                            # Tainted data as first arg — definitely dangerous
                            self._check_sink(call, first_arg, func_name, CALL_SINKS[func_name])
                        elif first_arg.type == 'identifier':
                            # Bare identifier: likely a function reference
                            # e.g., setTimeout(doSomething, 1000) — this is SAFE
                            # Only flag if it's a known tainted variable
                            pass
                        elif first_arg.type in ('binary_expression', 'template_string'):
                            # String concatenation/template → code eval pattern
                            # e.g., setTimeout('do(' + x + ')', 100)
                            if self._has_dynamic_content(first_arg) and not self._is_sanitized(first_arg):
                                self._add_finding(
                                    call,
                                    f"Dangerous Eval via {func_name}",
                                    VulnCategory.DANGEROUS_EVAL, Severity.HIGH, 'MEDIUM',
                                    f"{func_name}() called with string concatenation/template. "
                                    f"If the first argument is a string, it will be evaluated as code.",
                                    "CWE-95",
                                    REMEDIATION_MAP.get(func_name, f"Pass a function reference to {func_name}() instead of a string."),
                                    source=node_text(first_arg)[:120],
                                    sink=f"{func_name}()"
                                )
                        elif first_arg.type == 'call_expression':
                            # Result of a function call — could be a string builder
                            # Only flag if tainted data flows in
                            taint = self.tracker.is_tainted_node(first_arg)
                            if taint:
                                self._check_sink(call, first_arg, func_name, CALL_SINKS[func_name])
                    else:
                        before = len(self.findings)
                        self._check_sink(call, args[0], func_name, CALL_SINKS[func_name])

                        # Dangerous direct calls with dynamic (non-literal) args
                        # even without a proven taint chain
                        if (len(self.findings) == before
                                and not self._is_sanitized(args[0])
                                and self._has_dynamic_content(args[0])):
                            if func_name in ('eval', 'Function', 'execScript'):
                                self._add_finding(
                                    call,
                                    f"Dangerous Eval via {func_name}",
                                    VulnCategory.DANGEROUS_EVAL, Severity.CRITICAL, 'HIGH',
                                    f"{func_name}() called with dynamic content that may include "
                                    f"user-controlled data. Any non-literal argument to {func_name}() "
                                    f"enables arbitrary code injection.",
                                    "CWE-95",
                                    REMEDIATION_MAP.get(func_name,
                                        "Never use eval() with dynamic content. "
                                        "Use JSON.parse() for JSON data or a safe parser for expressions."),
                                    source=node_text(args[0])[:120],
                                    sink=f"{func_name}()"
                                )
                            elif func_name in ('unserialize', 'deserialize'):
                                cat, sev, cwe = CALL_SINKS[func_name]
                                self._add_finding(
                                    call,
                                    f"Unsafe Deserialization via {func_name}()",
                                    cat, sev, 'MEDIUM',
                                    f"{func_name}() called with dynamic content. "
                                    f"Deserializing untrusted data can lead to remote code execution.",
                                    cwe,
                                    REMEDIATION_MAP.get(func_name, "Never deserialize untrusted data."),
                                    source=node_text(args[0])[:120],
                                    sink=f"{func_name}()"
                                )

                if func_name == 'Function' and args:
                    self._check_sink(call, args[-1], 'Function', CALL_SINKS['Function'])

                # ── Direct calls to command sinks ──────────────────────
                # Handles: const { exec } = require('child_process');
                #          exec(userCmd);
                # Also handles: execSync, spawn, spawnSync, execFile, fork
                if func_name in COMMAND_SINKS and args:
                    cat, sev, cwe = COMMAND_SINKS[func_name]

                    # Check if first arg is tainted
                    taint = None
                    for a in args:
                        taint = self.tracker.is_tainted_node(a)
                        if taint:
                            break

                    if taint:
                        # Proven taint → always flag
                        self._add_finding(
                            call, f"Command Injection via {func_name}()",
                            cat, sev, 'HIGH',
                            f"Tainted data from '{taint.source_type}' used in "
                            f"command execution via {func_name}().",
                            cwe,
                            REMEDIATION_MAP.get(func_name,
                                "Never pass user input directly to command execution."),
                            source=taint.source_code, sink=f"{func_name}()"
                        )
                    elif (self._has_dynamic_content(args[0])
                          and not self._is_sanitized(args[0])):
                        # Dynamic content without proven taint
                        # For ambiguous 'exec', only flag if it's a known
                        # child_process alias (avoids regex.exec FP)
                        if func_name == 'exec' and func_name not in self.child_process_aliases:
                            pass  # Might be regex exec or other — skip
                        else:
                            self._add_finding(
                                call, f"Command Injection via {func_name}()",
                                cat, sev, 'MEDIUM',
                                f"{func_name}() called with dynamic content. "
                                f"Non-literal arguments enable injection.",
                                cwe,
                                REMEDIATION_MAP.get(func_name,
                                    "Never pass user input directly to command execution."),
                                source=node_text(args[0])[:120],
                                sink=f"{func_name}()"
                            )

            # Method calls
            elif callee.type == 'member_expression':
                method_node = get_child_by_field(callee, 'property')
                obj_node = get_child_by_field(callee, 'object')
                method = node_text(method_node) if method_node else ''
                obj_str = node_text(obj_node) if obj_node else ''

                # Object.defineProperty
                if obj_str == 'Object' and method == 'defineProperty' and len(args) >= 2:
                    target_proto = check_proto_in_text(node_text(args[0]))
                    key_taint = self.tracker.is_tainted_node(args[1]) if len(args) > 1 else None
                    if target_proto or key_taint:
                        desc = f"Using {target_proto} as defineProperty target" if target_proto else f"User-controlled property name"
                        self._add_finding(
                            call, "Prototype Pollution via Object.defineProperty()",
                            VulnCategory.PROTOTYPE_POLLUTION, Severity.CRITICAL, 'HIGH',
                            f"{desc} allows prototype pollution via Object.defineProperty().",
                            "CWE-1321", "Never use __proto__ with Object.defineProperty(). Validate property names.",
                            source=key_taint.source_code if key_taint else target_proto,
                            sink="Object.defineProperty()"
                        )

                # Object.assign
                elif obj_str == 'Object' and method == 'assign' and len(args) >= 2:
                    target_proto = check_proto_in_text(node_text(args[0]))
                    if target_proto:
                        for arg in args[1:]:
                            taint = self.tracker.is_tainted_node(arg)
                            if taint:
                                self._add_finding(
                                    call, "Prototype Pollution via Object.assign() to __proto__",
                                    VulnCategory.PROTOTYPE_POLLUTION, Severity.CRITICAL, 'HIGH',
                                    f"Object.assign() directly modifying {target_proto} with tainted data.",
                                    "CWE-1321", "Never use __proto__ as Object.assign target.",
                                    source=taint.source_code, sink=f"Object.assign({target_proto}, ...)"
                                )
                                break
                    else:
                        for arg in args[1:]:
                            is_json = (arg.type == 'call_expression' and
                                       'JSON.parse' in node_text(get_child_by_field(arg, 'function') or arg))
                            taint = self.tracker.is_tainted_node(arg)
                            if is_json or taint:
                                source_desc = "JSON.parse()" if is_json else (taint.source_code if taint else "unknown")
                                conf = 'HIGH' if (is_json or (taint and taint.source_type == 'json_parse')) else 'MEDIUM'
                                self._add_finding(
                                    call, "Prototype Pollution via Object.assign()",
                                    VulnCategory.PROTOTYPE_POLLUTION, Severity.HIGH, conf,
                                    f"Object.assign() with potentially tainted source from {source_desc}.",
                                    "CWE-1321", "Use Object.create(null) as target, or filter __proto__ from source.",
                                    source=source_desc, sink="Object.assign()"
                                )
                                break

                # document.write/writeln
                elif method in ('write', 'writeln') and 'document' in obj_str:
                    if args:
                        self._check_sink(call, args[0], method, CALL_SINKS[method])

                # insertAdjacentHTML
                elif method == 'insertAdjacentHTML' and len(args) >= 2:
                    self._check_sink(call, args[1], method, CALL_SINKS[method])

                # jQuery/DOM methods (not Object.assign, not deserialization)
                elif method in CALL_SINKS and args and not (obj_str == 'Object' and method == 'assign') and method not in ('unserialize', 'deserialize'):
                    # location.assign/replace
                    if method in ('assign', 'replace') and 'location' in obj_str:
                        self._check_sink(call, args[0], method, CALL_SINKS[method])
                    elif method == 'open' and obj_str in ('window', 'self'):
                        self._check_sink(call, args[0], 'open', CALL_SINKS['open'])
                    elif method in _DOM_CONTEXT_SINKS:
                        # Only flag append/prepend/before/after when object looks
                        # like a DOM element or jQuery selector to reduce FPs
                        _is_dom = False
                        if obj_node and obj_node.type == 'call_expression':
                            oc = get_child_by_field(obj_node, 'function')
                            oc_text = node_text(oc) if oc else ''
                            if oc_text in ('$', 'jQuery') or 'getElementById' in oc_text or 'querySelector' in oc_text:
                                _is_dom = True
                        if obj_str.lower().rstrip('0123456789') in _DOM_OBJECT_HINTS:
                            _is_dom = True
                        if 'document' in obj_str or '$' in obj_str:
                            _is_dom = True
                        if _is_dom:
                            self._check_sink(call, args[0], method, CALL_SINKS[method])
                    elif method not in ('assign', 'replace', 'open'):
                        self._check_sink(call, args[0], method, CALL_SINKS[method])

                # Dangerous merge functions
                elif method in DANGEROUS_MERGE_FUNCS and method != 'assign':
                    is_deep = (method == 'extend' and args and
                               node_text(args[0]) == 'true')
                    base_conf = 'HIGH' if is_deep or method in ('merge', 'mergeWith', 'defaultsDeep') else 'MEDIUM'
                    for arg in args:
                        taint = self.tracker.is_tainted_node(arg)
                        if taint:
                            # Elevate confidence when source is known user-controlled
                            conf = base_conf
                            if taint.source_type in (
                                'express_body', 'express_query', 'express_params',
                                'express_headers', 'express_cookies',
                                'json_parse', 'postmessage',
                            ):
                                conf = 'HIGH'
                            self._add_finding(
                                call, f"Prototype Pollution via {method}()",
                                VulnCategory.PROTOTYPE_POLLUTION, Severity.HIGH, conf,
                                f"Tainted data passed to {method}() can cause prototype pollution",
                                "CWE-1321", f"Validate input before passing to {method}().",
                                source=taint.source_code, sink=method
                            )
                            break

                # Express sinks: res.send(), res.end(), res.render()
                elif method in EXPRESS_SINKS and obj_str in ('res', 'response'):
                    if args:
                        arg = args[0]
                        taint = self.tracker.is_tainted_node(arg)
                        if taint:
                            cat, sev, cwe = EXPRESS_SINKS[method]
                            self._add_finding(
                                call, f"Reflected XSS via {method}()",
                                cat, sev, 'HIGH',
                                f"Tainted data from '{taint.source_type}' reflected in HTTP response via {method}()",
                                cwe, "Escape HTML entities before including in response, or use res.json()",
                                source=taint.source_code, sink=f"res.{method}()"
                            )

                # Express res.redirect() — open redirect
                elif method == 'redirect' and obj_str in ('res', 'response'):
                    if args:
                        # res.redirect(url) or res.redirect(status, url)
                        url_arg = args[-1] if len(args) >= 2 else args[0]
                        # Skip if first arg is status code and only arg
                        if len(args) == 1 and url_arg.type == 'number':
                            pass
                        else:
                            taint = self.tracker.is_tainted_node(url_arg)
                            if taint:
                                self._add_finding(
                                    call, "Open Redirect via res.redirect()",
                                    VulnCategory.OPEN_REDIRECT, Severity.HIGH, 'HIGH',
                                    f"Tainted data from '{taint.source_type}' used as redirect URL in res.redirect().",
                                    "CWE-601",
                                    REMEDIATION_MAP.get('redirect',
                                        "Validate redirect URLs against an allowlist."),
                                    source=taint.source_code, sink="res.redirect()"
                                )

                # Command sinks
                # Distinguish child_process.exec() from Mongoose Query.exec()
                # Skip exec() unless the object is a known child_process alias
                elif method in COMMAND_SINKS and not (
                    method == 'exec' and obj_node and (
                        # Mongoose pattern: Model.find().exec()
                        obj_node.type == 'call_expression'
                        # Not a child_process alias
                        or (obj_node.type == 'identifier'
                            and node_text(obj_node) not in self.child_process_aliases
                            and node_text(obj_node) not in ('child_process', 'cp', 'proc'))
                    )
                ):
                    if args:
                        cat, sev, cwe = COMMAND_SINKS[method]

                        # Detect {shell: true} in options argument
                        _has_shell_true = False
                        _opts_idx = 2 if method in ('spawn', 'spawnSync', 'execFile', 'execFileSync') else 1
                        if len(args) > _opts_idx:
                            opts_text = node_text(args[_opts_idx])
                            if 'shell' in opts_text and 'true' in opts_text:
                                _has_shell_true = True

                        # For spawn/spawnSync WITHOUT shell:true, args are passed
                        # directly to the process — NOT through a shell. This is
                        # safe against injection by design.
                        _is_safe_spawn = (
                            method in ('spawn', 'spawnSync', 'execFile', 'execFileSync')
                            and not _has_shell_true
                            and len(args) >= 2
                            and args[1].type == 'array'  # args passed as array
                        )

                        # Check ALL arguments for taint
                        taint = None
                        taint_arg = args[0]
                        for a in args:
                            taint = self.tracker.is_tainted_node(a)
                            if taint:
                                taint_arg = a
                                break

                        if taint:
                            if _is_safe_spawn and taint_arg != args[0]:
                                # Taint is only in the args array, not the command
                                # spawn(cmd, [taintedArg]) without shell is lower risk
                                self._add_finding(
                                    call, f"Command Injection via {method}()",
                                    cat, Severity.MEDIUM, 'MEDIUM',
                                    f"Tainted data from '{taint.source_type}' in args array of {method}(). "
                                    f"Without {{shell: true}}, injection risk is reduced but args may still be dangerous.",
                                    cwe, REMEDIATION_MAP.get(method, "Validate arguments against an allowlist."),
                                    source=taint.source_code, sink=f"{method}()"
                                )
                            else:
                                shell_note = " with {shell: true}" if _has_shell_true else ""
                                self._add_finding(
                                    call, f"Command Injection via {method}()",
                                    cat, sev, 'HIGH',
                                    f"Tainted data from '{taint.source_type}' used in command execution via {method}(){shell_note}.",
                                    cwe, REMEDIATION_MAP.get(method, "Never pass user input directly to command execution."),
                                    source=taint.source_code, sink=f"{method}()"
                                )
                        elif not _is_safe_spawn:
                            # Dynamic content without proven taint — only flag
                            # for exec/execSync or spawn with shell:true
                            dynamic_arg = None
                            for a in args:
                                if self._has_dynamic_content(a) and not self._is_sanitized(a):
                                    dynamic_arg = a
                                    break
                            if dynamic_arg:
                                conf = 'HIGH' if _has_shell_true or method in ('exec', 'execSync') else 'MEDIUM'
                                shell_note = " with {shell: true}" if _has_shell_true else ""
                                self._add_finding(
                                    call, f"Command Injection via {method}()",
                                    cat, sev, conf,
                                    f"{method}() called with dynamic content{shell_note}. "
                                    f"Non-literal arguments to command execution functions enable injection.",
                                    cwe, REMEDIATION_MAP.get(method, "Never pass user input directly to command execution."),
                                    source=node_text(dynamic_arg)[:120], sink=f"{method}()"
                                )

                # vm module sinks: vm.runInContext(), vm.runInNewContext(), etc.
                elif method in VM_SINKS:
                    if args:
                        cat, sev, cwe = VM_SINKS[method]
                        taint = self.tracker.is_tainted_node(args[0])
                        if taint:
                            self._add_finding(
                                call, f"Dangerous Eval via vm.{method}()",
                                cat, sev, 'HIGH',
                                f"Tainted data from '{taint.source_type}' passed to vm.{method}(). "
                                f"The vm module is not a security sandbox.",
                                cwe, REMEDIATION_MAP.get(method, "Never pass user-controlled code to the vm module."),
                                source=taint.source_code, sink=f"vm.{method}()"
                            )
                        elif self._has_dynamic_content(args[0]) and not self._is_sanitized(args[0]):
                            self._add_finding(
                                call, f"Dangerous Eval via vm.{method}()",
                                cat, sev, 'HIGH',
                                f"vm.{method}() called with dynamic content. "
                                f"Any non-literal argument enables arbitrary code execution.",
                                cwe, REMEDIATION_MAP.get(method, "Never pass user-controlled code to the vm module."),
                                source=node_text(args[0])[:120], sink=f"vm.{method}()"
                            )

                # Deserialization sinks: unserialize(), deserialize()
                elif method in ('unserialize', 'deserialize'):
                    if args:
                        cat, sev, cwe = CALL_SINKS.get(method, (VulnCategory.UNSAFE_DESERIALIZATION, Severity.CRITICAL, 'CWE-502'))
                        taint = self.tracker.is_tainted_node(args[0])
                        if taint:
                            self._add_finding(
                                call, f"Unsafe Deserialization via {method}()",
                                cat, sev, 'HIGH',
                                f"Tainted data from '{taint.source_type}' passed to {method}(). "
                                f"Deserializing untrusted data can lead to remote code execution.",
                                cwe, REMEDIATION_MAP.get(method, "Never deserialize untrusted data."),
                                source=taint.source_code, sink=f"{method}()"
                            )
                        elif self._has_dynamic_content(args[0]) and not self._is_sanitized(args[0]):
                            self._add_finding(
                                call, f"Unsafe Deserialization via {method}()",
                                cat, sev, 'MEDIUM',
                                f"{method}() called with dynamic content. "
                                f"Deserializing untrusted data can lead to remote code execution.",
                                cwe, REMEDIATION_MAP.get(method, "Never deserialize untrusted data."),
                                source=node_text(args[0])[:120], sink=f"{method}()"
                            )

                # js-yaml load(): only when object looks like a yaml reference
                elif method == 'load' and re.match(r'(?i)^(?:ya?ml|jsyaml|jsYaml|YAML)$', obj_str):
                    if args:
                        # Check if safeLoad or safe schema is used nearby
                        call_text = node_text(call)
                        if 'safeLoad' not in call_text and 'SAFE_SCHEMA' not in call_text:
                            taint = self.tracker.is_tainted_node(args[0])
                            conf = 'HIGH' if taint else 'MEDIUM'
                            source = taint.source_code if taint else node_text(args[0])[:120]
                            self._add_finding(
                                call, "Unsafe Deserialization via yaml.load()",
                                VulnCategory.UNSAFE_DESERIALIZATION, Severity.CRITICAL, conf,
                                "yaml.load() can execute arbitrary code via YAML deserialization. "
                                "Use yaml.safeLoad() or pass { schema: SAFE_SCHEMA }.",
                                "CWE-502", REMEDIATION_MAP.get('load', "Use yaml.safeLoad() instead."),
                                source=source, sink="yaml.load()"
                            )

                # ── NoSQL Injection (MongoDB / Mongoose) ────────────────
                # Detects: User.find(req.body), db.collection.findOne(tainted)
                # Safe:    User.find({ type: 'admin' }) — hardcoded literal object
                elif method in NOSQL_QUERY_METHODS and args:
                    self._check_nosql_injection(call, method, obj_str, args)

            # Inter-procedural check
            self._check_interprocedural(call, callee, args)

    def _is_safe_object_literal(self, node: Node) -> bool:
        """Check if an object literal contains ONLY static/literal values.

        Returns True for: { type: 'admin', active: true }
        Returns False for: { username: req.body.username }
        Returns False for: anything that is not an object literal
        """
        if node.type != 'object':
            return False
        _LITERAL_TYPES = {'string', 'number', 'true', 'false', 'null', 'undefined'}
        for child in node.children:
            if child.type == 'pair':
                val = get_child_by_field(child, 'value')
                if not val:
                    continue
                if val.type in _LITERAL_TYPES:
                    continue  # Safe literal value
                if val.type == 'array':
                    # Check if all elements in array are literals
                    if all(
                        el.type in _LITERAL_TYPES
                        for el in val.children
                        if el.type not in ('[', ']', ',')
                    ):
                        continue
                    return False
                if val.type == 'object':
                    # Nested object — recurse
                    if self._is_safe_object_literal(val):
                        continue
                    return False
                # Non-literal value (identifier, member_expression, etc.)
                return False
            elif child.type == 'spread_element':
                return False  # Spread could inject anything
            # Ignore punctuation: { } ,
        return True

    # Type-coercion functions that prevent NoSQL operator injection
    _NOSQL_SANITIZER_CALLS = {'String', 'Number', 'Boolean', 'parseInt', 'parseFloat'}

    def _check_nosql_injection(self, call: Node, method: str, obj_str: str,
                                args: List[Node]):
        """Check MongoDB/Mongoose query calls for NoSQL injection.

        Strategy:
        - Direct tainted object as query: CRITICAL
          e.g., User.find(req.body)
        - Object literal with tainted values: HIGH
          e.g., User.find({ user: req.body.user })
        - Hardcoded object literal: SAFE (no finding)
          e.g., User.find({ type: 'admin' })
        - Check ALL args, not just the first (e.g. distinct('field', query))
        """
        # Check all arguments — e.g. distinct('field', taintedQuery)
        # Stop after the first finding per call to avoid duplicates
        for query_arg in args:
            if self._check_nosql_arg(call, method, obj_str, query_arg):
                break

    def _is_sanitized_nosql_value(self, node: Node) -> bool:
        """Check if a node is wrapped in a type-coercion call like String()."""
        if node.type == 'call_expression':
            callee = get_child_by_field(node, 'function')
            if callee and node_text(callee) in self._NOSQL_SANITIZER_CALLS:
                return True
        return False

    def _check_nosql_arg(self, call: Node, method: str, obj_str: str,
                          query_arg: Node) -> bool:
        """Check a single argument for NoSQL injection. Returns True if finding added."""
        # Case 1: Hardcoded object literal with all-literal values → SAFE
        if self._is_safe_object_literal(query_arg):
            return False

        # Case 1b: Object literal where ALL values are type-coerced → SAFE
        # e.g., { username: String(req.body.user) }
        if query_arg.type == 'object':
            all_safe = True
            for child in query_arg.children:
                if child.type == 'pair':
                    val = get_child_by_field(child, 'value')
                    if val and not self._is_sanitized_nosql_value(val) and \
                       val.type not in ('string', 'number', 'true', 'false', 'null', 'undefined'):
                        all_safe = False
                        break
                elif child.type == 'spread_element':
                    all_safe = False
                    break
            if all_safe:
                return False

        # Case 2: Direct tainted variable/expression → CRITICAL
        taint = self.tracker.is_tainted_node(query_arg)
        if taint:
            # Direct pass-through of tainted object is worst case
            if query_arg.type != 'object':
                # e.g., User.find(req.body) — entire tainted object as query
                self._add_finding(
                    call, f"NoSQL Injection via {obj_str}.{method}()",
                    VulnCategory.NOSQL_INJECTION, Severity.CRITICAL, 'HIGH',
                    f"Tainted data from '{taint.source_type}' passed directly "
                    f"as query filter to {method}(). An attacker can inject "
                    f"MongoDB operators like {{$gt: ''}} to bypass authentication.",
                    "CWE-943",
                    REMEDIATION_MAP.get('nosql_find',
                        "Never pass user objects directly to queries. "
                        "Validate/cast individual fields."),
                    source=taint.source_code, sink=f"{obj_str}.{method}()"
                )
            else:
                # Object literal with at least one tainted value
                # e.g., User.find({ username: req.body.username })
                self._add_finding(
                    call, f"NoSQL Injection via {obj_str}.{method}()",
                    VulnCategory.NOSQL_INJECTION, Severity.HIGH, 'HIGH',
                    f"Tainted data from '{taint.source_type}' used as query "
                    f"value in {method}(). If the value is an object instead "
                    f"of a string, MongoDB operators can be injected.",
                    "CWE-943",
                    "Cast values to expected types: {{ field: String(value) }}, "
                    "or use mongoose-sanitize / express-mongo-sanitize.",
                    source=taint.source_code, sink=f"{obj_str}.{method}()"
                )
            return True

        # Case 3: Non-literal, non-tracked variable → MEDIUM
        # e.g., User.find(filters) where filters origin is unknown
        if query_arg.type == 'identifier':
            var_name = node_text(query_arg)
            if var_name not in self.tracker.safe_literals:
                # Not a safe literal AND not tainted — could be either
                # Only flag if it's a function parameter (externally controlled)
                if var_name in self.tracker.function_params:
                    self._add_finding(
                        call, f"Potential NoSQL Injection via {obj_str}.{method}()",
                        VulnCategory.NOSQL_INJECTION, Severity.HIGH, 'MEDIUM',
                        f"Function parameter '{var_name}' passed as query "
                        f"to {method}(). If caller passes user input, "
                        f"NoSQL injection is possible.",
                        "CWE-943",
                        "Validate query objects before passing to database methods.",
                        source=f"parameter: {var_name}",
                        sink=f"{obj_str}.{method}()"
                    )
                    return True
        return False

    def _check_interprocedural(self, call: Node, callee: Node, args: List[Node]):
        """Check for inter-procedural taint flow to wrapper functions."""
        func_name = None
        if callee.type == 'identifier':
            func_name = node_text(callee)
        elif callee.type == 'member_expression':
            prop = get_child_by_field(callee, 'property')
            func_name = node_text(prop) if prop else None

        if not func_name or not args:
            return

        dangerous_wrappers = {'respond', 'sendresponse', 'senderror', 'writeresponse',
                              'output', 'render', 'senddata'}

        if func_name.lower() in dangerous_wrappers:
            for arg in args:
                taint = self.tracker.is_tainted_node(arg)
                if taint:
                    self._add_finding(
                        call, f"Potential XSS via {func_name}()",
                        VulnCategory.REFLECTED_XSS, Severity.MEDIUM, 'MEDIUM',
                        f"Tainted data from '{taint.source_type}' passed to function '{func_name}()' which may output to response.",
                        "CWE-79", "Ensure the function properly escapes data before outputting.",
                        source=taint.source_code, sink=f"{func_name}()"
                    )
                    break

    # ------------------------------------------------------------------
    # New expressions: new Function(tainted)
    # ------------------------------------------------------------------

    def _check_new_expressions(self):
        for new_expr in find_nodes(self.root, 'new_expression'):
            constructor = get_child_by_field(new_expr, 'constructor')
            args = get_call_args(new_expr)
            if not constructor or not args:
                continue

            if constructor.type == 'identifier':
                name = node_text(constructor)
                if name == 'Function':
                    before = len(self.findings)
                    self._check_sink(new_expr, args[-1], 'Function', CALL_SINKS['Function'])
                    if (len(self.findings) == before
                            and self._has_dynamic_content(args[-1])
                            and not self._is_sanitized(args[-1])):
                        self._add_finding(
                            new_expr, "Dangerous Eval via new Function()",
                            VulnCategory.DANGEROUS_EVAL, Severity.CRITICAL, 'HIGH',
                            "new Function() called with dynamic content. "
                            "Any non-literal argument enables arbitrary code injection.",
                            "CWE-95", REMEDIATION_MAP.get('Function', "Avoid the Function constructor with user input."),
                            source=node_text(args[-1])[:120], sink="new Function()"
                        )

            elif constructor.type == 'member_expression':
                obj = get_child_by_field(constructor, 'object')
                prop = get_child_by_field(constructor, 'property')
                if obj and prop:
                    prop_name = node_text(prop)
                    # new vm.Script(code)
                    if prop_name == 'Script':
                        taint = self.tracker.is_tainted_node(args[0])
                        if taint:
                            self._add_finding(
                                new_expr, "Dangerous Eval via new vm.Script()",
                                VulnCategory.DANGEROUS_EVAL, Severity.CRITICAL, 'HIGH',
                                f"Tainted data from '{taint.source_type}' passed to new vm.Script(). "
                                f"The vm module is not a security sandbox.",
                                "CWE-95", REMEDIATION_MAP.get('Script', "Never pass user-controlled code to vm.Script()."),
                                source=taint.source_code, sink="new vm.Script()"
                            )
                        elif self._has_dynamic_content(args[0]) and not self._is_sanitized(args[0]):
                            self._add_finding(
                                new_expr, "Dangerous Eval via new vm.Script()",
                                VulnCategory.DANGEROUS_EVAL, Severity.CRITICAL, 'HIGH',
                                "new vm.Script() called with dynamic content. "
                                "Any non-literal argument enables arbitrary code execution.",
                                "CWE-95", REMEDIATION_MAP.get('Script', "Never pass user-controlled code to vm.Script()."),
                                source=node_text(args[0])[:120], sink="new vm.Script()"
                            )

    # ------------------------------------------------------------------
    # SQL Injection
    # ------------------------------------------------------------------

    def _check_sql_injection(self):
        """Detect SQL injection in Node.js database queries.

        Checks: mysql/mysql2, pg, sequelize, knex, prisma, better-sqlite3.
        Safe patterns: parameterized queries with ? or $1 placeholders.
        """
        all_sql_objects = SQL_DB_OBJECTS | self.sql_aliases | self.sequelize_aliases

        for call in find_nodes(self.root, 'call_expression'):
            callee = get_child_by_field(call, 'function')
            args = get_call_args(call)
            if not callee or not args:
                continue

            if callee.type != 'member_expression':
                continue

            method_node = get_child_by_field(callee, 'property')
            obj_node = get_child_by_field(callee, 'object')
            if not method_node or not obj_node:
                continue

            method = node_text(method_node)
            obj_str = node_text(obj_node)
            # Get the base object name for chained calls like db.query(...)
            base_obj = obj_str.split('.')[0].split('[')[0]

            # --- Standard SQL query methods (mysql, pg, sequelize) ---
            if method in SQL_QUERY_METHODS and base_obj in all_sql_objects:
                first_arg = args[0]
                # Safe: parameterized query with second arg (placeholders)
                # db.query('SELECT * FROM users WHERE id = ?', [id])
                if len(args) >= 2 and first_arg.type == 'string':
                    continue  # Literal query + params array = safe
                if first_arg.type == 'string':
                    continue  # Fully static query string = safe

                taint = self.tracker.is_tainted_node(first_arg)
                if taint:
                    self._add_finding(
                        call, f"SQL Injection via {base_obj}.{method}()",
                        VulnCategory.SQL_INJECTION, Severity.CRITICAL, 'HIGH',
                        f"Tainted data from '{taint.source_type}' used in SQL query "
                        f"via {method}(). Use parameterized queries instead.",
                        "CWE-89",
                        REMEDIATION_MAP.get('sql_query',
                            "Use parameterized queries (? placeholders) instead of string concatenation."),
                        source=taint.source_code, sink=f"{base_obj}.{method}()"
                    )
                elif self._has_dynamic_content(first_arg) and not self._is_sanitized(first_arg):
                    # Template literal or concatenation in query
                    self._add_finding(
                        call, f"SQL Injection via {base_obj}.{method}()",
                        VulnCategory.SQL_INJECTION, Severity.HIGH, 'MEDIUM',
                        f"Dynamic content in SQL query via {method}(). "
                        f"Use parameterized queries instead of string interpolation.",
                        "CWE-89",
                        REMEDIATION_MAP.get('sql_query',
                            "Use parameterized queries (? placeholders) instead of string concatenation."),
                        source=node_text(first_arg)[:120], sink=f"{base_obj}.{method}()"
                    )

            # --- Knex raw methods ---
            elif method in SQL_RAW_METHODS and (base_obj in (self.knex_aliases | {'knex'}) or base_obj in all_sql_objects):
                first_arg = args[0]
                # Safe: knex.raw('SELECT ?', [val]) — has bindings
                if len(args) >= 2 and first_arg.type == 'string':
                    continue
                if first_arg.type == 'string':
                    continue

                taint = self.tracker.is_tainted_node(first_arg)
                if taint:
                    self._add_finding(
                        call, f"SQL Injection via {method}()",
                        VulnCategory.SQL_INJECTION, Severity.CRITICAL, 'HIGH',
                        f"Tainted data from '{taint.source_type}' in raw SQL via {method}().",
                        "CWE-89",
                        REMEDIATION_MAP.get('sql_raw',
                            "Use parameterized queries with knex.raw('...?', [val])."),
                        source=taint.source_code, sink=f"{method}()"
                    )
                elif self._has_dynamic_content(first_arg):
                    self._add_finding(
                        call, f"SQL Injection via {method}()",
                        VulnCategory.SQL_INJECTION, Severity.HIGH, 'MEDIUM',
                        f"Dynamic content in raw SQL via {method}().",
                        "CWE-89",
                        REMEDIATION_MAP.get('sql_raw',
                            "Use parameterized queries with knex.raw('...?', [val])."),
                        source=node_text(first_arg)[:120], sink=f"{method}()"
                    )

            # --- Prisma raw methods ---
            elif method in ('$queryRaw', '$executeRaw', '$queryRawUnsafe', '$executeRawUnsafe'):
                if base_obj in (self.prisma_aliases | {'prisma'}):
                    first_arg = args[0]
                    # $queryRawUnsafe and $executeRawUnsafe are always dangerous with taint
                    # $queryRaw with tagged template (prisma.$queryRaw`...`) is safe
                    if 'Unsafe' in method:
                        taint = self.tracker.is_tainted_node(first_arg)
                        if taint:
                            self._add_finding(
                                call, f"SQL Injection via prisma.{method}()",
                                VulnCategory.SQL_INJECTION, Severity.CRITICAL, 'HIGH',
                                f"Tainted data from '{taint.source_type}' in {method}().",
                                "CWE-89",
                                "Use prisma.$queryRaw with tagged template literals instead.",
                                source=taint.source_code, sink=f"prisma.{method}()"
                            )
                    elif first_arg.type != 'tagged_template_expression':
                        taint = self.tracker.is_tainted_node(first_arg)
                        if taint:
                            self._add_finding(
                                call, f"SQL Injection via prisma.{method}()",
                                VulnCategory.SQL_INJECTION, Severity.HIGH, 'HIGH',
                                f"Tainted data from '{taint.source_type}' in {method}(). "
                                f"Use tagged template literal: prisma.$queryRaw`...`.",
                                "CWE-89",
                                "Use prisma.$queryRaw with tagged template literals.",
                                source=taint.source_code, sink=f"prisma.{method}()"
                            )

    # ------------------------------------------------------------------
    # Server-Side Template Injection (SSTI)
    # ------------------------------------------------------------------

    def _check_ssti(self):
        """Detect SSTI in Node.js template engines.

        Checks: ejs, pug, jade, nunjucks, Handlebars, mustache, doT, dust.
        The key pattern: tainted data used as the TEMPLATE string (1st arg),
        not as template data (2nd arg which is safe).
        """
        # Build a set of all known template engine object names
        template_objects: Set[str] = set()
        for engine, aliases in self.template_aliases.items():
            template_objects.update(aliases)
        # Add well-known direct names
        template_objects.update({'ejs', 'pug', 'jade', 'nunjucks', 'Handlebars',
                                  'handlebars', 'hbs', 'mustache', 'doT', 'dot',
                                  'dust', 'Mustache'})

        for call in find_nodes(self.root, 'call_expression'):
            callee = get_child_by_field(call, 'function')
            args = get_call_args(call)
            if not callee or not args:
                continue

            if callee.type != 'member_expression':
                continue

            method_node = get_child_by_field(callee, 'property')
            obj_node = get_child_by_field(callee, 'object')
            if not method_node or not obj_node:
                continue

            method = node_text(method_node)
            obj_str = node_text(obj_node)

            # Check if this is a known SSTI sink
            if method not in SSTI_SINKS:
                continue

            valid_engines = SSTI_SINKS[method]
            # Check if the object matches a known template engine
            is_template_engine = obj_str in template_objects
            if not is_template_engine:
                # Check if obj matches any of the valid engines for this method
                if not any(eng in obj_str for eng in valid_engines):
                    continue

            # The template string is typically the first argument
            template_arg = args[0]

            # Safe: static template string
            if template_arg.type == 'string':
                continue
            # Safe: template file path (renderFile with static path)
            if method == 'renderFile' and template_arg.type == 'string':
                continue

            taint = self.tracker.is_tainted_node(template_arg)
            if taint:
                self._add_finding(
                    call, f"SSTI via {obj_str}.{method}()",
                    VulnCategory.SSTI, Severity.CRITICAL, 'HIGH',
                    f"Tainted data from '{taint.source_type}' used as template string "
                    f"in {obj_str}.{method}(). This allows server-side template injection.",
                    "CWE-1336",
                    REMEDIATION_MAP.get('ssti',
                        "Never pass user input as the template string. Use it as template data instead."),
                    source=taint.source_code, sink=f"{obj_str}.{method}()"
                )
            elif self._has_dynamic_content(template_arg) and not self._is_sanitized(template_arg):
                self._add_finding(
                    call, f"SSTI via {obj_str}.{method}()",
                    VulnCategory.SSTI, Severity.HIGH, 'MEDIUM',
                    f"Dynamic content used as template string in {obj_str}.{method}(). "
                    f"If user input reaches this, server-side template injection is possible.",
                    "CWE-1336",
                    REMEDIATION_MAP.get('ssti',
                        "Never pass user input as the template string. Use it as template data instead."),
                    source=node_text(template_arg)[:120], sink=f"{obj_str}.{method}()"
                )

    # ------------------------------------------------------------------
    # For-in prototype pollution
    # ------------------------------------------------------------------

    def _check_forin_pollution(self):
        """Detect prototype pollution in for-in loops."""
        for forin in find_nodes(self.root, 'for_in_statement'):
            left = get_child_by_field(forin, 'left')
            right = get_child_by_field(forin, 'right')
            body = get_child_by_field(forin, 'body')
            if not left or not right or not body:
                continue

            # Extract loop variable
            loop_var = None
            if left.type in ('variable_declaration', 'lexical_declaration'):
                decl = get_child_by_type(left, 'variable_declarator')
                if decl:
                    name_node = get_child_by_field(decl, 'name')
                    loop_var = node_text(name_node) if name_node else None
            elif left.type == 'identifier':
                loop_var = node_text(left)

            if not loop_var:
                continue

            # Check if iterated object is unsafe — require evidence of taint
            iterated_obj = node_text(right)
            is_unsafe = self.tracker.is_tainted_node(right) is not None
            if not is_unsafe and right.type == 'identifier':
                var_name = node_text(right)
                # Only flag if the variable is a known function parameter
                # (potential user-controlled input) — NOT all unknown variables
                if var_name in self.tracker.function_params:
                    is_unsafe = True
            elif not is_unsafe and right.type == 'call_expression':
                callee_text = node_text(get_child_by_field(right, 'function') or right)
                if 'JSON.parse' in callee_text:
                    is_unsafe = True

            if not is_unsafe:
                continue

            # Look for target[loopVar] = ... in body
            for assign in find_nodes(body, 'assignment_expression'):
                left_a = get_child_by_field(assign, 'left')
                if left_a and left_a.type == 'subscript_expression':
                    index = get_child_by_field(left_a, 'index')
                    if index and node_text(index) == loop_var:
                        # Check protections
                        body_text = node_text(body)
                        has_protection = False
                        if 'hasOwnProperty' in body_text or 'Object.hasOwn' in body_text:
                            has_protection = True
                        elif 'Object.keys' in body_text:
                            has_protection = True
                        elif ("'__proto__'" in body_text or '"__proto__"' in body_text):
                            if ('continue' in body_text or 'return' in body_text) and '===' in body_text:
                                has_protection = True

                        if not has_protection:
                            self._add_finding(
                                forin, "Prototype Pollution via for-in loop",
                                VulnCategory.PROTOTYPE_POLLUTION, Severity.CRITICAL, 'HIGH',
                                f"Iterating over '{iterated_obj}' with for-in and assigning to target[{loop_var}] without hasOwnProperty check",
                                "CWE-1321", "Add hasOwnProperty check, or use Object.keys() instead of for-in",
                                source=iterated_obj, sink=f"target[{loop_var}]"
                            )
                            break

            # Also check for merge function calls inside for-in
            for call_node in find_nodes(body, 'call_expression'):
                callee = get_child_by_field(call_node, 'function')
                if not callee:
                    continue
                callee_text = node_text(callee)
                method = ''
                if callee.type == 'member_expression':
                    prop = get_child_by_field(callee, 'property')
                    method = node_text(prop) if prop else ''
                elif callee.type == 'identifier':
                    method = node_text(callee)

                if method in DANGEROUS_MERGE_FUNCS:
                    call_text = node_text(call_node)
                    if loop_var in call_text or iterated_obj in call_text:
                        body_text = node_text(body)
                        if 'hasOwnProperty' not in body_text and 'Object.hasOwn' not in body_text:
                            self._add_finding(
                                call_node, f"Prototype Pollution via {method}() in for-in loop",
                                VulnCategory.PROTOTYPE_POLLUTION, Severity.CRITICAL, 'HIGH',
                                f"Calling {method}() inside for-in loop over '{iterated_obj}' without hasOwnProperty check",
                                "CWE-1321", "Add hasOwnProperty check or use Object.keys()",
                                source=iterated_obj, sink=f"{method}()"
                            )
                            break

    # ------------------------------------------------------------------
    # Function parameter pollution
    # ------------------------------------------------------------------

    def _check_function_param_pollution(self):
        """Check if function parameters are used as computed property keys."""
        for func in find_nodes_multi(self.root, {'function_declaration', 'function', 'arrow_function'}):
            params_node = get_child_by_field(func, 'parameters')
            param_names = set()

            if not params_node:
                # Arrow with single param
                param = get_child_by_field(func, 'parameter')
                if param and param.type == 'identifier':
                    param_names.add(node_text(param))
            else:
                for child in params_node.children:
                    if child.type == 'identifier':
                        param_names.add(node_text(child))
                    elif child.type == 'assignment_pattern':
                        left = get_child_by_field(child, 'left')
                        if left and left.type == 'identifier':
                            param_names.add(node_text(left))

            if not param_names:
                continue

            body = get_child_by_field(func, 'body')
            if not body:
                continue

            for assign in find_nodes(body, 'assignment_expression'):
                left_a = get_child_by_field(assign, 'left')
                if left_a and left_a.type == 'subscript_expression':
                    index = get_child_by_field(left_a, 'index')
                    if index and index.type == 'identifier':
                        key_name = node_text(index)
                        if key_name in param_names:
                            obj_node = get_child_by_field(left_a, 'object')
                            target = node_text(obj_node) if obj_node else 'target'
                            self._add_finding(
                                assign, "Prototype Pollution via Function Parameter",
                                VulnCategory.PROTOTYPE_POLLUTION, Severity.HIGH, 'MEDIUM',
                                f"Function parameter '{key_name}' used as computed property key in '{target}[{key_name}]'.",
                                "CWE-1321", "Validate parameter against '__proto__', 'constructor', 'prototype'.",
                                source=f"parameter: {key_name}", sink=f"{target}[{key_name}]"
                            )


# ============================================================================
# RegexScanner - Fallback for HTML and non-parseable JS
# ============================================================================

class RegexScanner:
    """Fallback regex-based scanner for HTML and edge cases."""

    def __init__(self, file_path: str, source_code: str):
        self.file_path = file_path
        self.source_code = source_code
        self.source_lines = source_code.split('\n')
        self.findings: List[Finding] = []

    def get_line_content(self, line_num: int) -> str:
        if 0 < line_num <= len(self.source_lines):
            return self.source_lines[line_num - 1].strip()
        return ""

    def get_line_number(self, pos: int) -> int:
        return self.source_code[:pos].count('\n') + 1

    def _is_comment_or_string(self, line_content: str) -> bool:
        """Check if line is a JS comment or the match is inside a string literal."""
        stripped = line_content.strip()
        if stripped.startswith('//'):
            return True
        if stripped.startswith('/*') or stripped.startswith('*'):
            return True
        # String literal containing sink pattern (e.g. var x = "document.body.innerHTML = ...")
        if stripped.startswith('var ') or stripped.startswith('let ') or stripped.startswith('const '):
            assign_pos = stripped.find('=')
            if assign_pos > 0:
                after_eq = stripped[assign_pos + 1:].strip()
                if after_eq and after_eq[0] in ('"', "'"):
                    return True
        return False

    def scan(self) -> List[Finding]:
        self.scan_dom_xss()
        self.scan_prototype_pollution()
        self.scan_forin_pollution()
        self.scan_express_xss()
        self.scan_template_xss()
        return self.findings

    def scan_dom_xss(self):
        source_patterns = [
            (r'location\.(?:href|search|hash|pathname)', 'url'),
            (r'document\.(?:URL|documentURI|referrer|cookie)', 'document'),
            (r'window\.(?:name|location)', 'window'),
            (r'(?:localStorage|sessionStorage)\.getItem', 'storage'),
            (r'\.value\b', 'input'),
            (r'\b(?:e|evt|event|message)\.data\b', 'postmessage'),
        ]
        dangerous_var_patterns = [
            r'\b(?:response|res|data|result|html|content|body|payload|input|text|msg|message)\b',
            r'\b(?:user|param|query|arg|val|value|href|url|link|uri|path|src)\b',
        ]
        sink_patterns = [
            (r'\.innerHTML\s*=', 'innerHTML', Severity.CRITICAL),
            (r'\.outerHTML\s*=', 'outerHTML', Severity.CRITICAL),
            (r'document\.write(?:ln)?\s*\(', 'document.write', Severity.CRITICAL),
            (r'\beval\s*\(', 'eval', Severity.CRITICAL),
            (r'\bnew\s+Function\s*\(', 'Function', Severity.CRITICAL),
            (r'\.insertAdjacentHTML\s*\(', 'insertAdjacentHTML', Severity.CRITICAL),
            (r'location\.(?:href|assign|replace)\s*=', 'location', Severity.HIGH),
            (r'\$\([^)]*\)\.html\s*\(', 'jQuery.html', Severity.CRITICAL),
            (r'dangerouslySetInnerHTML', 'dangerouslySetInnerHTML', Severity.CRITICAL),
            (r'v-html\s*=', 'v-html', Severity.CRITICAL),
            (r'\bwindow\.open\s*\(', 'window.open', Severity.HIGH),
            (r'\$\s*\([^)]*\+[^)]*location\.', 'jQuery selector (location)', Severity.MEDIUM),
        ]

        for sink_pattern, sink_name, severity in sink_patterns:
            for match in re.finditer(sink_pattern, self.source_code, re.IGNORECASE):
                line_num = self.get_line_number(match.start())
                line_content = self.get_line_content(line_num)

                # Skip matches inside comments or string literals
                if self._is_comment_or_string(line_content):
                    continue

                if sink_name == 'location':
                    after = self.source_code[match.end():match.end()+200]
                    if re.match(r"\s*['\"][^'\"]*['\"]", after):
                        continue

                if sink_name == 'window.open':
                    after = self.source_code[match.end():match.end()+200]
                    if re.match(r"\s*['\"][^'\"]*['\"]", after):
                        continue

                source_found = None
                for src_pattern, src_type in source_patterns:
                    if re.search(src_pattern, line_content, re.IGNORECASE):
                        source_found = src_type
                        break

                if any(safe in line_content.lower() for safe in ['sanitize', 'encode', 'escape', 'dompurify']):
                    continue

                confidence = 'HIGH' if source_found else 'MEDIUM'
                if confidence == 'MEDIUM':
                    rest = line_content[line_content.find(match.group(0)) if match.group(0) in line_content else 0:]
                    for var_pattern in dangerous_var_patterns:
                        if re.search(var_pattern, rest, re.IGNORECASE):
                            confidence = 'HIGH'
                            source_found = 'variable'
                            break
                    if sink_name == 'jQuery.html':
                        if re.search(r'\.html\s*\(\s*["\']["\']', line_content):
                            continue
                        if re.search(r'\.html\s*\(\s*\)\s*(?:==|===|!=|!==|\.|\))', line_content):
                            continue

                if sink_name in ('location', 'window.open'):
                    vuln_cat = VulnCategory.OPEN_REDIRECT
                    vuln_name = f"Open Redirect via {sink_name}"
                    cwe = "CWE-601"
                    rem = "Validate URLs against an allowlist"
                else:
                    vuln_cat = VulnCategory.DOM_XSS
                    vuln_name = f"DOM XSS via {sink_name}"
                    cwe = "CWE-79"
                    rem = "Sanitize user input before use"

                col = match.start() - self.source_code.rfind('\n', 0, match.start())
                self.findings.append(Finding(
                    file_path=self.file_path, line_number=line_num, col_offset=col,
                    line_content=line_content, vulnerability_name=vuln_name,
                    category=vuln_cat, severity=severity, confidence=confidence,
                    description=f"Dangerous sink '{sink_name}' detected" + (f" with {source_found} source" if source_found else ""),
                    source=source_found, sink=sink_name, cwe_id=cwe, remediation=rem
                ))

    def scan_prototype_pollution(self):
        patterns = [
            (r'\[\s*[\'"]__proto__[\'"]\s*\]', '__proto__', Severity.CRITICAL),
            (r'\.__proto__\b', '__proto__', Severity.CRITICAL),
            (r'\[\s*[\'"]constructor[\'"]\s*\]\s*\[\s*[\'"]prototype[\'"]\s*\]', 'constructor.prototype', Severity.CRITICAL),
            (r'\.constructor\.prototype\b', 'constructor.prototype', Severity.CRITICAL),
            (r'_\.(?:merge|mergeWith|defaultsDeep)\s*\(', 'lodash.merge', Severity.HIGH),
            (r'\$\.extend\s*\(\s*true', 'jQuery.extend', Severity.HIGH),
        ]
        for pattern, name, severity in patterns:
            for match in re.finditer(pattern, self.source_code):
                line_num = self.get_line_number(match.start())
                context_start = max(0, match.start() - 200)
                context = self.source_code[context_start:match.end() + 100]
                if 'hasOwnProperty' in context:
                    continue
                col = match.start() - self.source_code.rfind('\n', 0, match.start())
                self.findings.append(Finding(
                    file_path=self.file_path, line_number=line_num, col_offset=col,
                    line_content=self.get_line_content(line_num),
                    vulnerability_name=f"Prototype Pollution via {name}",
                    category=VulnCategory.PROTOTYPE_POLLUTION, severity=severity,
                    confidence='HIGH' if '__proto__' in name or 'constructor' in name else 'MEDIUM',
                    description=f"Potential prototype pollution via {name}",
                    sink=name, cwe_id="CWE-1321",
                    remediation="Use Object.create(null) or validate keys"
                ))

    def scan_forin_pollution(self):
        forin_pattern = r'for\s*\(\s*(?:let|var|const)?\s*(\w+)\s+in\s+(\w+)'
        for match in re.finditer(forin_pattern, self.source_code):
            loop_var = match.group(1)
            iterated_obj = match.group(2)
            line_num = self.get_line_number(match.start())
            context = self.source_code[match.start():min(len(self.source_code), match.end() + 500)]
            if 'hasOwnProperty' in context or 'Object.hasOwn' in context or 'Object.keys' in context:
                continue
            if ("'__proto__'" in context or '"__proto__"' in context) and ('continue' in context or 'return' in context):
                continue
            assign_pattern = rf'\w+\s*\[\s*{loop_var}\s*\]\s*='
            if re.search(assign_pattern, context):
                suspicious = ['req.body', 'req.query', 'req.params', 'body', 'query', 'params',
                              'input', 'data', 'payload', 'source', 'options', 'config', 'settings']
                is_suspicious = any(s in iterated_obj.lower() for s in suspicious)
                if not is_suspicious:
                    broader = self.source_code[max(0, match.start()-300):match.end()+500]
                    if any(s in broader for s in ['req.body', 'req.query', 'req.params']):
                        is_suspicious = True
                confidence = 'HIGH' if is_suspicious else 'MEDIUM'
                col = match.start() - self.source_code.rfind('\n', 0, match.start())
                self.findings.append(Finding(
                    file_path=self.file_path, line_number=line_num, col_offset=col,
                    line_content=self.get_line_content(line_num),
                    vulnerability_name="Prototype Pollution via for-in loop",
                    category=VulnCategory.PROTOTYPE_POLLUTION, severity=Severity.CRITICAL,
                    confidence=confidence,
                    description=f"for-in loop over '{iterated_obj}' with target[{loop_var}] without hasOwnProperty",
                    source=iterated_obj, sink=f"target[{loop_var}]",
                    cwe_id="CWE-1321", remediation="Add hasOwnProperty check or use Object.keys()"
                ))

    def scan_express_xss(self):
        express_sources = [r'req\.query\.\w+', r'req\.body\.\w+', r'req\.params\.\w+',
                           r'req\.query\[', r'req\.body\[', r'req\.params\[']
        sink_patterns = [
            (r'res\.send\s*\(\s*[`\'\"].*<', 'res.send (HTML)'),
            (r'res\.send\s*\(\s*`[^`]*\$\{', 'res.send (template literal)'),
            (r'res\.write\s*\(\s*[`\'\"].*<', 'res.write (HTML)'),
            (r'res\.end\s*\(\s*[`\'\"].*<', 'res.end (HTML)'),
        ]
        for sink_pattern, sink_name in sink_patterns:
            for match in re.finditer(sink_pattern, self.source_code):
                line_num = self.get_line_number(match.start())
                context = self.source_code[max(0, match.start()-200):match.end()+100]
                source_found = None
                for src_pattern in express_sources:
                    m = re.search(src_pattern, context)
                    if m:
                        source_found = m.group(0)
                        break
                if any(s in context.lower() for s in ['escape', 'sanitize', 'encode', 'purify']):
                    continue
                if source_found:
                    col = match.start() - self.source_code.rfind('\n', 0, match.start())
                    self.findings.append(Finding(
                        file_path=self.file_path, line_number=line_num, col_offset=col,
                        line_content=self.get_line_content(line_num),
                        vulnerability_name=f"Reflected XSS via {sink_name}",
                        category=VulnCategory.REFLECTED_XSS, severity=Severity.HIGH,
                        confidence='HIGH',
                        description=f"User input from '{source_found}' reflected in HTML response",
                        source=source_found, sink=sink_name,
                        cwe_id="CWE-79", remediation="Escape HTML entities or use res.json()"
                    ))

    def scan_template_xss(self):
        patterns = [
            (r'\{\{\{\s*\w+\s*\}\}\}', 'Handlebars unescaped', Severity.CRITICAL),
            (r'<%-\s*\w+\s*%>', 'EJS unescaped', Severity.CRITICAL),
            (r'href\s*=\s*[\'"]?\s*javascript:', 'javascript: URL', Severity.HIGH),
            (r'on\w+\s*=\s*[\'"][^"\']*\{\{', 'Event handler template', Severity.HIGH),
        ]
        for pattern, name, severity in patterns:
            for match in re.finditer(pattern, self.source_code, re.IGNORECASE):
                line_num = self.get_line_number(match.start())
                col = match.start() - self.source_code.rfind('\n', 0, match.start())
                self.findings.append(Finding(
                    file_path=self.file_path, line_number=line_num, col_offset=col,
                    line_content=self.get_line_content(line_num),
                    vulnerability_name=f"Reflected XSS - {name}",
                    category=VulnCategory.REFLECTED_XSS, severity=severity,
                    confidence='HIGH',
                    description=f"Unescaped output pattern '{name}' may allow XSS",
                    cwe_id="CWE-79", remediation="Use context-appropriate encoding"
                ))


# ============================================================================
# Rich UI Output
# ============================================================================

def _print_banner():
    banner_lines = [
        "     ██╗███████╗██╗  ██╗██╗   ██╗███╗   ██╗████████╗███████╗██████╗",
        "     ██║██╔════╝██║  ██║██║   ██║████╗  ██║╚══██╔══╝██╔════╝██╔══██╗",
        "     ██║███████╗███████║██║   ██║██╔██╗ ██║   ██║   █████╗  ██████╔╝",
        "██   ██║╚════██║██╔══██║██║   ██║██║╚██╗██║   ██║   ██╔══╝  ██╔══██╗",
        "╚█████╔╝███████║██║  ██║╚██████╔╝██║ ╚████║   ██║   ███████╗██║  ██║",
        " ╚════╝ ╚══════╝╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═══╝   ╚═╝   ╚══════╝╚═╝  ╚═╝",
    ]
    title_content = Text()
    title_content.append('\n'.join(banner_lines), style="bold yellow")
    title_content.append("\n\n")
    title_content.append("Tree-sitter AST JavaScript/TypeScript Vulnerability Scanner v2.1\n", style="bold white")
    title_content.append("XSS | SQLi | SSTI | Prototype Pollution | Command Injection | NoSQL Injection", style="dim")

    console.print()
    console.print(Panel(
        Align.center(title_content),
        border_style="yellow",
        box=box.DOUBLE,
        padding=(1, 2),
    ))
    console.print()


def _build_stats_sidebar(findings: List[Finding], file_count: int, elapsed: float) -> Panel:
    stats = Table(show_header=False, box=None, padding=(0, 1), expand=True)
    stats.add_column("key", style="bold cyan", no_wrap=True, ratio=3)
    stats.add_column("value", style="white", ratio=1)
    stats.add_row("Files Scanned", str(file_count))
    stats.add_row("Total Findings", str(len(findings)))
    stats.add_row("Scan Time", f"{elapsed:.2f}s")
    stats.add_row("Engine", "tree-sitter AST")
    stats.add_row("", "")

    sev_counts = defaultdict(int)
    for f in findings:
        sev_counts[f.severity.value] += 1
    sev_styles = {'CRITICAL': 'bold red', 'HIGH': 'red', 'MEDIUM': 'yellow', 'LOW': 'green'}
    for sev in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']:
        count = sev_counts.get(sev, 0)
        if count > 0:
            stats.add_row(Text(sev, style=sev_styles.get(sev, "white")), str(count))

    stats.add_row("", "")
    cat_counts = defaultdict(int)
    for f in findings:
        cat_counts[f.category.value] += 1
    for cat, count in sorted(cat_counts.items(), key=lambda x: -x[1]):
        stats.add_row(Text(cat, style="cyan"), str(count))

    return Panel(stats, title="[bold white]Scan Statistics[/bold white]",
                 border_style="cyan", box=box.ROUNDED, padding=(1, 1))


def _build_finding_panel(f: Finding, source_code: Optional[str] = None) -> Panel:
    sev = f.severity.value
    border_map = {'CRITICAL': 'bold red', 'HIGH': 'red', 'MEDIUM': 'yellow', 'LOW': 'green'}
    sev_style_map = {'CRITICAL': 'bold white on red', 'HIGH': 'bold red',
                     'MEDIUM': 'bold yellow', 'LOW': 'bold green'}

    title = Text()
    title.append(f" {sev} ", style=sev_style_map.get(sev, "white"))
    title.append(f" {f.vulnerability_name} ", style="bold white")
    if f.cwe_id:
        title.append(f" {f.cwe_id} ", style="dim cyan")
    title.append(f" Confidence: {f.confidence} ", style="dim")

    content_parts = []

    loc = Text()
    loc.append("Location: ", style="bold cyan")
    loc.append(f"Line {f.line_number}", style="white")
    if f.col_offset:
        loc.append(f", Col {f.col_offset}", style="dim")
    cat = Text()
    cat.append("Category: ", style="bold magenta")
    cat.append(f.category.value, style="white")
    content_parts.append(Columns([loc, cat], padding=(0, 4)))

    if f.source or f.sink:
        flow = Text()
        if f.source:
            flow.append("Source: ", style="bold green")
            flow.append(str(f.source)[:80], style="white")
        if f.source and f.sink:
            flow.append("  ->  ", style="bold yellow")
        if f.sink:
            flow.append("Sink: ", style="bold red")
            flow.append(str(f.sink), style="white")
        content_parts.append(flow)

    if f.description:
        desc = Text()
        desc.append(f"\n{f.description}", style="italic white")
        content_parts.append(desc)

    if f.taint_chain:
        tree = Tree("[bold cyan]Taint Path[/bold cyan]", guide_style="cyan")
        for i, node in enumerate(f.taint_chain):
            style = "bold red" if i == len(f.taint_chain) - 1 else "white"
            tree.add(Text(node, style=style))
        content_parts.append(Text(""))
        content_parts.append(tree)

    code_line = f.line_content.strip()
    if code_line:
        if source_code:
            src_lines = source_code.split('\n')
            start = max(0, f.line_number - 3)
            end = min(len(src_lines), f.line_number + 2)
            snippet = '\n'.join(src_lines[start:end])
            syntax = Syntax(snippet, "javascript", theme="monokai",
                           line_numbers=True, start_line=start + 1,
                           highlight_lines={f.line_number})
        else:
            syntax = Syntax(code_line, "javascript", theme="monokai",
                           line_numbers=True, start_line=f.line_number)
        content_parts.append(Text(""))
        content_parts.append(syntax)

    if f.remediation:
        rem = Text()
        rem.append("\nRemediation: ", style="bold yellow")
        rem.append(f.remediation, style="dim white")
        content_parts.append(rem)

    return Panel(Group(*content_parts), title=title,
                 border_style=border_map.get(sev, 'white'),
                 box=box.ROUNDED, padding=(1, 2))


def output_rich(findings: List[Finding], target: str, file_count: int,
                elapsed: float, min_confidence: str):
    scan_date = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    header = Text()
    header.append("Target: ", style="bold cyan")
    header.append(f"{target}  ", style="white")
    header.append("Date: ", style="bold cyan")
    header.append(f"{scan_date}  ", style="white")
    header.append("Confidence: ", style="bold cyan")
    header.append(f">= {min_confidence}", style="white")

    console.print(Panel(Align.center(header), title="[bold white]Scan Info[/bold white]",
                        border_style="blue", box=box.ROUNDED))
    console.print()
    console.print(_build_stats_sidebar(findings, file_count, elapsed))
    console.print()

    if findings:
        console.print(Rule("[bold white]Vulnerability Findings[/bold white]", style="red"))
        console.print()

        source_cache: Dict[str, str] = {}
        findings_by_file = defaultdict(list)
        for f in findings:
            findings_by_file[f.file_path].append(f)

        for fp, file_findings in sorted(findings_by_file.items()):
            console.print(Text(f"FILE: {fp}", style="bold underline cyan"))
            console.print()
            if fp not in source_cache:
                try:
                    source_cache[fp] = Path(fp).read_text(encoding='utf-8', errors='ignore')
                except Exception:
                    pass
            src = source_cache.get(fp)
            for f in sorted(file_findings, key=lambda x: x.line_number):
                console.print(_build_finding_panel(f, source_code=src))
                console.print()
    else:
        console.print(Panel(
            Align.center(Text("No vulnerabilities found.", style="bold green")),
            border_style="green", box=box.ROUNDED, padding=(1, 4)))


def output_text_plain(findings: List[Finding], file_path: str):
    with open(file_path, 'w', encoding='utf-8') as out:
        for f in findings:
            out.write(f"\n{'='*70}\n")
            out.write(f"  [{f.severity.value}] [{f.confidence}] {f.vulnerability_name}\n")
            out.write(f"  File: {f.file_path}:{f.line_number}\n")
            out.write(f"  Code: {f.line_content}\n")
            out.write(f"  Category: {f.category.value}\n")
            if f.description:
                out.write(f"  Description: {f.description}\n")
            if f.source:
                out.write(f"  Source: {f.source}\n")
            if f.sink:
                out.write(f"  Sink: {f.sink}\n")
            if f.taint_chain:
                out.write(f"  Taint chain:\n")
                for tc in f.taint_chain:
                    out.write(f"    -> {tc}\n")
            if f.remediation:
                out.write(f"  Remediation: {f.remediation}\n")
        out.write(f"\n{'='*70}\n")
        out.write(f"Total findings: {len(findings)}\n")


def output_json(findings: List[Finding], file_path: str = None):
    data = {
        "scan_date": datetime.now().isoformat(),
        "scanner": "js-treesitter v2.1",
        "total_findings": len(findings),
        "findings": [
            {
                "file": f.file_path, "line": f.line_number, "column": f.col_offset,
                "code": f.line_content, "vulnerability": f.vulnerability_name,
                "category": f.category.value, "severity": f.severity.value,
                "confidence": f.confidence, "description": f.description,
                "source": f.source, "sink": f.sink,
                "taint_chain": f.taint_chain, "cwe": f.cwe_id,
                "remediation": f.remediation
            }
            for f in findings
        ],
        "summary": {
            "by_severity": dict(sorted({
                sev: sum(1 for f in findings if f.severity.value == sev)
                for sev in set(f.severity.value for f in findings)
            }.items())) if findings else {},
            "by_category": dict(sorted({
                cat: sum(1 for f in findings if f.category.value == cat)
                for cat in set(f.category.value for f in findings)
            }.items())) if findings else {},
        }
    }
    json_str = json.dumps(data, indent=2)
    if file_path:
        with open(file_path, 'w', encoding='utf-8') as f:
            f.write(json_str)
    else:
        print(json_str)


# ============================================================================
# Scan Orchestration & File Discovery
# ============================================================================

SUPPORTED_EXTENSIONS = {'.js', '.jsx', '.mjs', '.ts', '.tsx', '.html', '.htm', '.vue', '.svelte'}
SKIP_DIRS = {'node_modules', '.git', 'vendor', 'dist', 'build', '.next', '__pycache__',
             'bower_components', 'jspm_packages', 'third_party', 'third-party',
             'external', 'externals', '.bundle'}
SKIP_PATTERNS = ['node_modules', 'vendor', 'dist/', 'build/',
                 'bundle.js', 'chunk.', '.bundle.', 'polyfill', '.map']

# Vendor library filename patterns — if any pattern appears in the filename, skip it
SKIP_VENDOR_FILES = {
    # Minified files
    '.min.js', '.min.css', '.bundle.js', '.chunk.js',
    '-min.js', '-min.css', '.prod.js', '.production.js',
    # Common vendor libraries
    'jquery', 'bootstrap', 'angular', 'react', 'vue', 'ember',
    'backbone', 'lodash', 'underscore', 'moment', 'axios',
    'popper', 'd3', 'chart', 'highcharts', 'three',
    'socket.io', 'knockout', 'polymer', 'mootools', 'prototype',
    'dojo', 'ext-all', 'sencha', 'kendo', 'telerik',
    'tinymce', 'ckeditor', 'codemirror', 'ace-builds',
    'select2', 'chosen', 'datatables', 'fullcalendar',
    'sweetalert', 'toastr', 'bootbox', 'magnific-popup',
    'slick', 'owl.carousel', 'swiper', 'photoswipe',
    'leaflet', 'mapbox', 'google-maps', 'openlayers',
    'hammer', 'modernizr', 'respond', 'html5shiv',
    'normalize.css', 'reset.css', 'sanitize.css',
    # Font/icon libraries
    'fontawesome', 'font-awesome', 'ionicons', 'material-icons',
    'glyphicons', 'feather', 'bootstrap-icons',
    # Polyfills and shims
    'polyfill', 'core-js', 'babel-polyfill', 'es5-shim', 'es6-shim',
    # Build artifacts
    'webpack-runtime', 'runtime~', 'vendors~', 'vendor.',
}


def should_skip_file(file_path: str) -> bool:
    path_lower = file_path.lower()
    if any(p in path_lower for p in SKIP_PATTERNS):
        return True
    filename_lower = os.path.basename(path_lower)
    return any(p in filename_lower for p in SKIP_VENDOR_FILES)


def detect_minified(content: str, file_path: str) -> bool:
    if not content:
        return False
    lines = content.split('\n')
    if len(lines) < 10 and len(content) > 5000:
        return True
    non_empty = [l for l in lines if l.strip()]
    if non_empty and sum(len(l) for l in non_empty) / len(non_empty) > 500:
        return True
    if any(len(l) > 1000 for l in lines):
        return True
    sample = content[:5000]
    if sample.count(';') > 50 and sample.count('\n') < 20:
        return True
    filename = os.path.basename(file_path).lower()
    if '.min.' in filename or '-min.' in filename:
        return True
    if (re.search(r'\b[a-z]\s*=\s*[a-z]\s*\(', sample) and
        re.search(r'function\s*\([a-z](,[a-z]){3,}', sample)):
        return True
    return False


def read_file(file_path: str) -> Optional[str]:
    for encoding in ['utf-8', 'latin-1', 'cp1252']:
        try:
            with open(file_path, 'r', encoding=encoding) as f:
                return f.read()
        except (UnicodeDecodeError, PermissionError):
            continue
    return None


def scan_js_file(file_path: str, content: str, min_confidence: str) -> List[Finding]:
    """Scan a JS file using tree-sitter AST + regex fallback."""
    findings = []
    try:
        analyzer = JSASTAnalyzer(content, file_path)
        findings = analyzer.analyze()
    except Exception:
        # Fallback to regex
        scanner = RegexScanner(file_path, content)
        findings = scanner.scan()

    conf_levels = {'HIGH': 3, 'MEDIUM': 2, 'LOW': 1}
    threshold = conf_levels.get(min_confidence, 3)
    return [f for f in findings if conf_levels.get(f.confidence, 0) >= threshold]


def scan_html_file(file_path: str, content: str, min_confidence: str) -> List[Finding]:
    """Scan HTML file: inline scripts via AST, HTML patterns via regex."""
    findings = []
    html_lines = content.split('\n')
    script_line_ranges = []  # Track lines covered by AST-scanned inline scripts

    # Extract inline scripts with correct line offset
    for match in re.finditer(r'<script[^>]*>(.*?)</script>', content, re.DOTALL | re.IGNORECASE):
        script_content = match.group(1)
        if not script_content.strip():
            continue
        # Calculate line offset: number of newlines before the script content starts
        script_start_pos = match.start(1)
        script_end_pos = match.end(1)
        line_offset = content[:script_start_pos].count('\n')
        line_start = line_offset + 1
        line_end = content[:script_end_pos].count('\n') + 1
        script_line_ranges.append((line_start, line_end))

        inline_findings = scan_js_file(file_path, script_content, min_confidence)
        # Adjust line numbers to HTML file positions
        for f in inline_findings:
            f.line_number += line_offset
            if 0 < f.line_number <= len(html_lines):
                f.line_content = html_lines[f.line_number - 1].strip()
        findings.extend(inline_findings)

    # Regex for HTML patterns (template XSS + DOM XSS outside inline scripts)
    scanner = RegexScanner(file_path, content)
    scanner.scan_template_xss()
    scanner.scan_dom_xss()

    conf_levels = {'HIGH': 3, 'MEDIUM': 2, 'LOW': 1}
    threshold = conf_levels.get(min_confidence, 3)
    for f in scanner.findings:
        if conf_levels.get(f.confidence, 0) < threshold:
            continue
        # Skip regex DOM XSS findings inside inline scripts (AST scanner handles those)
        if f.category == VulnCategory.DOM_XSS or f.category == VulnCategory.DANGEROUS_EVAL or f.category == VulnCategory.OPEN_REDIRECT:
            in_script = any(start <= f.line_number <= end for start, end in script_line_ranges)
            if in_script:
                continue
        findings.append(f)
    return findings


# ---------------------------------------------------------------------------
# npm audit integration
# ---------------------------------------------------------------------------

_NPM_SEVERITY_MAP = {
    'critical': Severity.CRITICAL,
    'high': Severity.HIGH,
    'moderate': Severity.MEDIUM,
    'low': Severity.LOW,
}


def run_npm_audit(target: str) -> List[Finding]:
    """Run ``npm audit --json`` and return findings for known-vulnerable deps."""
    if shutil.which('npm') is None:
        print("[npm audit] npm is not installed — skipping dependency audit")
        return []

    target_path = Path(target)
    target_dir = target_path if target_path.is_dir() else target_path.parent

    lock_file = target_dir / 'package-lock.json'
    if not lock_file.exists():
        return []

    try:
        result = subprocess.run(
            ['npm', 'audit', '--json'],
            cwd=str(target_dir),
            capture_output=True,
            text=True,
            timeout=60,
        )
    except (subprocess.TimeoutExpired, OSError):
        return []

    try:
        data = json.loads(result.stdout)
    except (json.JSONDecodeError, ValueError):
        return []

    vulns = data.get('vulnerabilities', {})
    findings: List[Finding] = []

    for pkg_name, info in vulns.items():
        npm_severity = info.get('severity', 'low')
        severity = _NPM_SEVERITY_MAP.get(npm_severity, Severity.LOW)
        version = info.get('range', 'unknown')
        fix_available = info.get('fixAvailable', False)
        via = info.get('via', [])

        desc_parts = []
        for entry in via:
            if isinstance(entry, dict):
                title = entry.get('title', '')
                url = entry.get('url', '')
                if title:
                    desc_parts.append(title)
                if url:
                    desc_parts.append(url)
        if fix_available:
            desc_parts.append("Fix available: yes")
        else:
            desc_parts.append("Fix available: no")
        desc_parts.append(f"Affected range: {version}")

        findings.append(Finding(
            file_path="package.json",
            line_number=0,
            col_offset=0,
            line_content="",
            vulnerability_name=f"Vulnerable Dependency - {pkg_name}@{version} ({npm_severity})",
            category=VulnCategory.VULNERABLE_DEPENDENCY,
            severity=severity,
            confidence="HIGH",
            description="; ".join(desc_parts),
        ))

    return findings


def scan_path(target: str, min_confidence: str = 'HIGH',
              show_progress: bool = True, config: VibehunterConfig = None) -> Tuple[List[Finding], int, float]:
    """Scan a file or directory. Returns (findings, file_count, elapsed)."""
    target_path = Path(target)
    start = time.time()
    all_findings: List[Finding] = []
    file_count = 0

    # Collect files
    files = []
    if target_path.is_file():
        fp = str(target_path)
        if not (config and config.should_exclude(fp)):
            files.append(fp)
    elif target_path.is_dir():
        for root, dirs, filenames in os.walk(str(target_path)):
            dirs[:] = [d for d in dirs if d not in SKIP_DIRS]
            for fname in filenames:
                fp = os.path.join(root, fname)
                ext = Path(fp).suffix.lower()
                if ext in SUPPORTED_EXTENSIONS and not should_skip_file(fp):
                    if config and config.should_exclude(fp):
                        continue
                    files.append(fp)
    else:
        console.print(f"[bold red]Error: {target} does not exist[/bold red]", file=sys.stderr)
        sys.exit(1)

    if show_progress and files:
        with Progress(
            SpinnerColumn(), TextColumn("[progress.description]{task.description}"),
            BarColumn(), MofNCompleteColumn(), console=console
        ) as progress:
            task = progress.add_task("[cyan]Scanning files...", total=len(files))
            for fp in files:
                content = read_file(fp)
                if not content:
                    progress.advance(task)
                    continue
                file_count += 1
                ext = Path(fp).suffix.lower()

                if ext in {'.js', '.jsx', '.mjs', '.ts', '.tsx'} and detect_minified(content, fp):
                    console.print(Panel(
                        Text(f"Minified file: {os.path.basename(fp)}\nFindings may have more false positives.", style="yellow"),
                        title="[bold yellow]Warning[/bold yellow]",
                        border_style="yellow", box=box.ROUNDED
                    ))

                if ext in {'.js', '.jsx', '.mjs', '.ts', '.tsx'}:
                    all_findings.extend(scan_js_file(fp, content, min_confidence))
                elif ext in {'.html', '.htm', '.vue', '.svelte'}:
                    all_findings.extend(scan_html_file(fp, content, min_confidence))
                progress.advance(task)
    else:
        for fp in files:
            content = read_file(fp)
            if not content:
                continue
            file_count += 1
            ext = Path(fp).suffix.lower()
            if ext in {'.js', '.jsx', '.mjs', '.ts', '.tsx'}:
                all_findings.extend(scan_js_file(fp, content, min_confidence))
            elif ext in {'.html', '.htm', '.vue', '.svelte'}:
                all_findings.extend(scan_html_file(fp, content, min_confidence))

    elapsed = time.time() - start
    return all_findings, file_count, elapsed


def filter_findings(findings: List[Finding], min_severity: str = None,
                    min_confidence: str = None, suppression_keyword: str = "nosec") -> List[Finding]:
    result = []
    for f in findings:
        # Check inline suppression (// nosec, # nosec, /* nosec, etc.)
        if re.search(rf'(?://|#|/\*|--|%)\s*{re.escape(suppression_keyword)}\b', f.line_content):
            continue
        if 'vibehunter:ignore' in f.line_content:
            continue
        result.append(f)
    if min_severity:
        sev_order = {'CRITICAL': 4, 'HIGH': 3, 'MEDIUM': 2, 'LOW': 1}
        threshold = sev_order.get(min_severity, 0)
        result = [f for f in result if sev_order.get(f.severity.value, 0) >= threshold]
    if min_confidence:
        conf_order = {'HIGH': 3, 'MEDIUM': 2, 'LOW': 1}
        threshold = conf_order.get(min_confidence, 0)
        result = [f for f in result if conf_order.get(f.confidence, 0) >= threshold]
    return result


# ============================================================================
# Main
# ============================================================================

def main():
    parser = argparse.ArgumentParser(
        description='js-treesitter - AST-Based JavaScript/TypeScript Vulnerability Scanner'
    )
    parser.add_argument('target', help='File or directory to scan')
    parser.add_argument('-v', '--verbose', action='store_true', help='Verbose output')
    parser.add_argument('--output', choices=['text', 'json'], default='text', help='Output format')
    parser.add_argument('-o', '--output-file', help='Save report to file')
    parser.add_argument('--min-confidence', choices=['HIGH', 'MEDIUM', 'LOW'],
                        help='Minimum confidence level (default: HIGH)')
    parser.add_argument('--min-severity', choices=['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'],
                        help='Minimum severity to report')
    parser.add_argument('--all', action='store_true', help='Show all findings (no filters)')
    parser.add_argument('--no-banner', action='store_true', help='Suppress banner')
    parser.add_argument('--config', help='Path to .vibehunter.yml config file')

    args = parser.parse_args()

    # Load config
    config = load_config(args.target, args.config)

    min_confidence = args.min_confidence
    min_severity = args.min_severity
    if args.all:
        min_confidence = None
        min_severity = None
    elif not min_severity and not min_confidence:
        min_confidence = config.min_confidence if config else "HIGH"

    is_json = args.output == 'json'

    if not args.no_banner and not is_json:
        _print_banner()

    findings, file_count, elapsed = scan_path(
        args.target,
        min_confidence=min_confidence or 'HIGH',
        show_progress=not is_json,
        config=config
    )

    # npm audit integration
    npm_findings = run_npm_audit(args.target)
    findings.extend(npm_findings)

    suppression_kw = config.suppression_keyword if config else "nosec"
    findings = filter_findings(findings, min_severity, min_confidence, suppression_kw)
    findings.sort(key=lambda f: (f.file_path, f.line_number))

    if is_json:
        output_json(findings, args.output_file)
    else:
        output_rich(findings, args.target, file_count, elapsed, min_confidence or 'HIGH')
        if args.output_file:
            output_text_plain(findings, args.output_file)
            console.print(f"\n[bold green]Report saved to {args.output_file}[/bold green]")

    critical_high = sum(1 for f in findings if f.severity in (Severity.CRITICAL, Severity.HIGH))
    sys.exit(1 if critical_high > 0 else 0)


if __name__ == '__main__':
    main()
