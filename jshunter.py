#!/usr/bin/env python3
"""
JSHunter - AST-Based JavaScript Vulnerability Scanner
======================================================
A structural analysis scanner for JavaScript files using AST parsing.

Features:
- JavaScript AST parsing via esprima (ES6+) or pyjsparser (ES5)
- Source-to-sink taint tracking
- XSS detection (reflected, DOM-based)
- Prototype pollution detection
- Path traversal (LFI/LFW) detection
- Command injection detection
- Inter-procedural taint flow analysis
- Line-precise vulnerability reporting

Requirements:
    pip install esprima  # Recommended (ES6+ support)
    pip install pyjsparser  # Fallback (ES5 only)

Usage:
    python3 jshunter.py target.js
    python3 jshunter.py /path/to/project --verbose
    python3 jshunter.py app.js --output json -o report.json
"""

import os
import sys
import json
import argparse
import re
from pathlib import Path
from dataclasses import dataclass, field
from typing import List, Dict, Set, Optional, Any, Tuple, Union, FrozenSet
from enum import Enum
from datetime import datetime
from collections import defaultdict
import textwrap

# Check for esprima (ES6+ support)
try:
    import esprima
    HAS_ESPRIMA = True
except ImportError:
    HAS_ESPRIMA = False

# Check for pyjsparser (ES5 fallback)
try:
    import pyjsparser
    HAS_PYJSPARSER = True
except ImportError:
    HAS_PYJSPARSER = False

if not HAS_ESPRIMA and not HAS_PYJSPARSER:
    print("[!] Warning: No JS parser installed. Install with: pip install esprima")
    print("[!] Falling back to regex-based detection for JavaScript files.")


class Severity(Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"


class VulnCategory(Enum):
    DOM_XSS = "DOM-based XSS"
    REFLECTED_XSS = "Reflected XSS"
    PROTOTYPE_POLLUTION = "Prototype Pollution"
    DANGEROUS_EVAL = "Dangerous Eval"
    OPEN_REDIRECT = "Open Redirect"
    PATH_TRAVERSAL = "Path Traversal"
    COMMAND_INJECTION = "Command Injection"


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
    column: int
    node_type: str
    vulnerability_name: str
    category: VulnCategory
    severity: Severity
    confidence: str
    description: str
    source: Optional[str] = None
    sink: Optional[str] = None
    code_snippet: str = ""
    cwe_id: str = ""
    remediation: str = ""


# ============================================================================
# XSS Sources - Where attacker-controlled data enters
# ============================================================================

# Member expressions that are sources (object.property)
MEMBER_SOURCES = {
    # Location sources
    ('location', 'href'): ('url', 'HIGH'),
    ('location', 'search'): ('query', 'HIGH'),
    ('location', 'hash'): ('hash', 'HIGH'),
    ('location', 'pathname'): ('url', 'MEDIUM'),
    ('location', 'host'): ('url', 'LOW'),
    ('location', 'hostname'): ('url', 'LOW'),
    ('location', 'origin'): ('url', 'LOW'),
    ('location', 'protocol'): ('url', 'LOW'),

    # Document sources
    ('document', 'URL'): ('url', 'HIGH'),
    ('document', 'documentURI'): ('url', 'HIGH'),
    ('document', 'referrer'): ('referrer', 'HIGH'),
    ('document', 'cookie'): ('cookie', 'HIGH'),
    ('document', 'location'): ('url', 'HIGH'),
    ('document', 'domain'): ('url', 'LOW'),

    # Window sources
    ('window', 'location'): ('url', 'HIGH'),
    ('window', 'name'): ('window_name', 'HIGH'),

    # Storage sources
    ('localStorage', 'getItem'): ('storage', 'MEDIUM'),
    ('sessionStorage', 'getItem'): ('storage', 'MEDIUM'),

    # Express.js/Node.js sources
    ('req', 'query'): ('express_query', 'HIGH'),
    ('req', 'body'): ('express_body', 'HIGH'),
    ('req', 'params'): ('express_params', 'HIGH'),
    ('req', 'headers'): ('express_headers', 'HIGH'),
    ('req', 'cookies'): ('express_cookies', 'HIGH'),
    ('request', 'query'): ('express_query', 'HIGH'),
    ('request', 'body'): ('express_body', 'HIGH'),
    ('request', 'params'): ('express_params', 'HIGH'),
}

# Call expressions that are sources (func())
CALL_SOURCES = {
    # URLSearchParams
    'URLSearchParams': ('query', 'HIGH'),
    'URL': ('url', 'HIGH'),

    # jQuery input
    'val': ('input', 'MEDIUM'),  # .val()

    # Storage
    'getItem': ('storage', 'MEDIUM'),

    # DOM queries (return elements with .value)
    'getElementById': ('dom', 'LOW'),
    'querySelector': ('dom', 'LOW'),
    'querySelectorAll': ('dom', 'LOW'),
    'getElementsByClassName': ('dom', 'LOW'),
    'getElementsByTagName': ('dom', 'LOW'),
}

# Properties that taint when accessed
TAINT_PROPERTIES = {'value', 'innerHTML', 'outerHTML', 'textContent', 'innerText', 'data'}

# PostMessage event data
POSTMESSAGE_SOURCES = {'data'}  # event.data, e.data, etc.

# ============================================================================
# XSS Sinks - Where data execution leads to vulnerabilities
# ============================================================================

# Property assignment sinks (element.property = value)
PROPERTY_SINKS = {
    'innerHTML': (VulnCategory.DOM_XSS, Severity.CRITICAL, 'CWE-79'),
    'outerHTML': (VulnCategory.DOM_XSS, Severity.CRITICAL, 'CWE-79'),
    'srcdoc': (VulnCategory.DOM_XSS, Severity.CRITICAL, 'CWE-79'),
}

# Property assignment sinks that need context (navigation)
NAVIGATION_SINKS = {
    'href': (VulnCategory.OPEN_REDIRECT, Severity.HIGH, 'CWE-601'),
    'src': (VulnCategory.DOM_XSS, Severity.HIGH, 'CWE-79'),
    'action': (VulnCategory.OPEN_REDIRECT, Severity.MEDIUM, 'CWE-601'),
}

# Call expression sinks (func(tainted))
CALL_SINKS = {
    # Direct execution
    'eval': (VulnCategory.DANGEROUS_EVAL, Severity.CRITICAL, 'CWE-95'),
    'Function': (VulnCategory.DANGEROUS_EVAL, Severity.CRITICAL, 'CWE-95'),
    'execScript': (VulnCategory.DANGEROUS_EVAL, Severity.CRITICAL, 'CWE-95'),

    # Timer sinks (dangerous with string argument)
    'setTimeout': (VulnCategory.DANGEROUS_EVAL, Severity.HIGH, 'CWE-95'),
    'setInterval': (VulnCategory.DANGEROUS_EVAL, Severity.HIGH, 'CWE-95'),
    'setImmediate': (VulnCategory.DANGEROUS_EVAL, Severity.HIGH, 'CWE-95'),

    # Document write
    'write': (VulnCategory.DOM_XSS, Severity.CRITICAL, 'CWE-79'),
    'writeln': (VulnCategory.DOM_XSS, Severity.CRITICAL, 'CWE-79'),

    # DOM manipulation
    'insertAdjacentHTML': (VulnCategory.DOM_XSS, Severity.CRITICAL, 'CWE-79'),

    # Navigation
    'assign': (VulnCategory.OPEN_REDIRECT, Severity.HIGH, 'CWE-601'),
    'replace': (VulnCategory.OPEN_REDIRECT, Severity.HIGH, 'CWE-601'),
    'open': (VulnCategory.OPEN_REDIRECT, Severity.MEDIUM, 'CWE-601'),

    # jQuery sinks
    'html': (VulnCategory.DOM_XSS, Severity.CRITICAL, 'CWE-79'),
    'append': (VulnCategory.DOM_XSS, Severity.HIGH, 'CWE-79'),
    'prepend': (VulnCategory.DOM_XSS, Severity.HIGH, 'CWE-79'),
    'after': (VulnCategory.DOM_XSS, Severity.HIGH, 'CWE-79'),
    'before': (VulnCategory.DOM_XSS, Severity.HIGH, 'CWE-79'),
    'replaceWith': (VulnCategory.DOM_XSS, Severity.HIGH, 'CWE-79'),
    'wrapAll': (VulnCategory.DOM_XSS, Severity.HIGH, 'CWE-79'),
    'wrapInner': (VulnCategory.DOM_XSS, Severity.HIGH, 'CWE-79'),
}

# Express.js response sinks (need special handling - only dangerous with HTML)
EXPRESS_SINKS = {
    'send': (VulnCategory.REFLECTED_XSS, Severity.HIGH, 'CWE-79'),
    'end': (VulnCategory.REFLECTED_XSS, Severity.HIGH, 'CWE-79'),
    'render': (VulnCategory.REFLECTED_XSS, Severity.MEDIUM, 'CWE-79'),
}

# Node.js file system sinks (Path Traversal / LFI)
FS_SINKS = {
    'readFile': (VulnCategory.PATH_TRAVERSAL, Severity.CRITICAL, 'CWE-22'),
    'readFileSync': (VulnCategory.PATH_TRAVERSAL, Severity.CRITICAL, 'CWE-22'),
    'readdir': (VulnCategory.PATH_TRAVERSAL, Severity.HIGH, 'CWE-22'),
    'readdirSync': (VulnCategory.PATH_TRAVERSAL, Severity.HIGH, 'CWE-22'),
    'writeFile': (VulnCategory.PATH_TRAVERSAL, Severity.CRITICAL, 'CWE-22'),
    'writeFileSync': (VulnCategory.PATH_TRAVERSAL, Severity.CRITICAL, 'CWE-22'),
    'appendFile': (VulnCategory.PATH_TRAVERSAL, Severity.CRITICAL, 'CWE-22'),
    'appendFileSync': (VulnCategory.PATH_TRAVERSAL, Severity.CRITICAL, 'CWE-22'),
    'unlink': (VulnCategory.PATH_TRAVERSAL, Severity.CRITICAL, 'CWE-22'),
    'unlinkSync': (VulnCategory.PATH_TRAVERSAL, Severity.CRITICAL, 'CWE-22'),
    'rmdir': (VulnCategory.PATH_TRAVERSAL, Severity.CRITICAL, 'CWE-22'),
    'rmdirSync': (VulnCategory.PATH_TRAVERSAL, Severity.CRITICAL, 'CWE-22'),
    'stat': (VulnCategory.PATH_TRAVERSAL, Severity.MEDIUM, 'CWE-22'),
    'statSync': (VulnCategory.PATH_TRAVERSAL, Severity.MEDIUM, 'CWE-22'),
    'access': (VulnCategory.PATH_TRAVERSAL, Severity.MEDIUM, 'CWE-22'),
    'accessSync': (VulnCategory.PATH_TRAVERSAL, Severity.MEDIUM, 'CWE-22'),
    'createReadStream': (VulnCategory.PATH_TRAVERSAL, Severity.CRITICAL, 'CWE-22'),
    'createWriteStream': (VulnCategory.PATH_TRAVERSAL, Severity.CRITICAL, 'CWE-22'),
}

# Node.js command execution sinks
COMMAND_SINKS = {
    'exec': (VulnCategory.COMMAND_INJECTION, Severity.CRITICAL, 'CWE-78'),
    'execSync': (VulnCategory.COMMAND_INJECTION, Severity.CRITICAL, 'CWE-78'),
    'spawn': (VulnCategory.COMMAND_INJECTION, Severity.CRITICAL, 'CWE-78'),
    'spawnSync': (VulnCategory.COMMAND_INJECTION, Severity.CRITICAL, 'CWE-78'),
    'execFile': (VulnCategory.COMMAND_INJECTION, Severity.CRITICAL, 'CWE-78'),
    'execFileSync': (VulnCategory.COMMAND_INJECTION, Severity.CRITICAL, 'CWE-78'),
    'fork': (VulnCategory.COMMAND_INJECTION, Severity.HIGH, 'CWE-78'),
}

# ============================================================================
# Prototype Pollution Patterns
# ============================================================================

PROTO_POLLUTION_PROPS = {'__proto__', 'constructor', 'prototype'}

DANGEROUS_MERGE_FUNCS = {
    'merge', 'mergeWith', 'defaultsDeep', 'set', 'setWith',  # Lodash
    'extend', 'assign',  # jQuery, Object
    'deepMerge', 'deepExtend', 'deepClone',  # Custom
}

# ============================================================================
# Safe Patterns (to reduce false positives)
# ============================================================================

SAFE_FUNCTIONS = {
    'encodeURIComponent', 'encodeURI', 'escape',
    'sanitize', 'sanitizeHtml', 'sanitizeHTML', 'sanitizeUrl',
    'escapeHtml', 'escapeHTML', 'htmlEncode', 'htmlEscape',
    'DOMPurify', 'xss', 'validator',
}

SAFE_SINKS = {'textContent', 'innerText', 'text'}  # Safe ways to set text


# ============================================================================
# AST Visitor for JavaScript Analysis
# ============================================================================

class JSASTVisitor:
    """
    Visits JavaScript AST nodes to detect XSS vulnerabilities.
    Uses source-to-sink taint tracking.
    """

    def __init__(self, file_path: str, source_code: str, verbose: bool = False):
        self.file_path = file_path
        self.source_code = source_code
        self.source_lines = source_code.split('\n')
        self.verbose = verbose

        # Taint tracking
        self.tainted_vars: Dict[str, TaintedVar] = {}
        self.findings: List[Finding] = []

        # Scope tracking (simplified)
        self.current_function: Optional[str] = None

        # Track function parameters (for prototype pollution detection)
        self.function_params: Set[str] = set()

    def log(self, msg: str) -> None:
        if self.verbose:
            print(f"  [DEBUG] {msg}")

    def get_line_content(self, line_num: int) -> str:
        """Get source code line content."""
        if 0 < line_num <= len(self.source_lines):
            return self.source_lines[line_num - 1].strip()
        return ""

    def get_node_location(self, node: dict) -> Tuple[int, int]:
        """Extract line and column from AST node.

        pyjsparser doesn't provide location info in AST, so we search
        for the code pattern in the source to estimate line numbers.
        """
        # First try standard ESTree location format
        loc = node.get('loc', {})
        if loc:
            start = loc.get('start', {})
            line = start.get('line', 0)
            if line > 0:
                return line, start.get('column', 0)

        # Fallback: search for the code in source
        code_str = self.node_to_string(node)
        if code_str and code_str not in ('<Unknown>', ''):
            # Search for this pattern in source
            for i, line in enumerate(self.source_lines, 1):
                # Check if key parts of the code appear on this line
                if len(code_str) > 3 and code_str[:20] in line:
                    return i, line.find(code_str[:20])
                # For assignments like element.innerHTML = x
                if '=' in code_str:
                    left_part = code_str.split('=')[0].strip()
                    if left_part and left_part in line:
                        return i, line.find(left_part)

        return 0, 0

    def find_line_for_pattern(self, pattern: str, skip_comments: bool = True) -> int:
        """Find line number where pattern appears (skipping comments by default)."""
        for i, line in enumerate(self.source_lines, 1):
            stripped = line.strip()
            # Skip comment lines
            if skip_comments and (stripped.startswith('//') or stripped.startswith('*') or stripped.startswith('/*')):
                continue
            if pattern in line:
                return i
        return 0

    def check_proto_in_chain(self, node: dict) -> Optional[str]:
        """
        Recursively check if a member expression chain contains __proto__,
        constructor, or prototype access.
        Returns the dangerous property name if found, None otherwise.
        """
        if not isinstance(node, dict) or node.get('type') != 'MemberExpression':
            return None

        prop = node.get('property', {})

        # Check current property
        if prop.get('type') == 'Identifier':
            prop_name = prop.get('name', '')
            if prop_name in PROTO_POLLUTION_PROPS:
                return prop_name
        elif prop.get('type') == 'Literal':
            prop_val = prop.get('value', '')
            if prop_val in PROTO_POLLUTION_PROPS:
                return prop_val

        # Check the object part of the chain recursively
        obj = node.get('object', {})
        if obj.get('type') == 'MemberExpression':
            return self.check_proto_in_chain(obj)

        return None

    def node_to_string(self, node: dict) -> str:
        """Convert AST node back to approximate source string."""
        if node is None:
            return ""

        node_type = node.get('type', '')

        if node_type == 'Identifier':
            return node.get('name', '')

        elif node_type == 'Literal':
            val = node.get('value', '')
            if isinstance(val, str):
                return f'"{val}"'
            return str(val)

        elif node_type == 'MemberExpression':
            obj = self.node_to_string(node.get('object'))
            prop = self.node_to_string(node.get('property'))
            if node.get('computed'):
                return f"{obj}[{prop}]"
            return f"{obj}.{prop}"

        elif node_type == 'CallExpression':
            callee = self.node_to_string(node.get('callee'))
            args = ', '.join(self.node_to_string(a) for a in node.get('arguments', []))
            return f"{callee}({args})"

        elif node_type == 'BinaryExpression':
            left = self.node_to_string(node.get('left'))
            right = self.node_to_string(node.get('right'))
            op = node.get('operator', '+')
            return f"{left} {op} {right}"

        elif node_type == 'AssignmentExpression':
            left = self.node_to_string(node.get('left'))
            right = self.node_to_string(node.get('right'))
            op = node.get('operator', '=')
            return f"{left} {op} {right}"

        elif node_type == 'NewExpression':
            callee = self.node_to_string(node.get('callee'))
            args = ', '.join(self.node_to_string(a) for a in node.get('arguments', []))
            return f"new {callee}({args})"

        elif node_type == 'ThisExpression':
            return 'this'

        elif node_type == 'ArrayExpression':
            elements = ', '.join(self.node_to_string(e) for e in node.get('elements', []) if e)
            return f"[{elements}]"

        elif node_type == 'ObjectExpression':
            return '{...}'

        elif node_type == 'TemplateLiteral':
            return '`template`'

        elif node_type == 'ConditionalExpression':
            return f"{self.node_to_string(node.get('test'))} ? ... : ..."

        return f"<{node_type}>"

    def is_source(self, node: dict) -> Optional[Tuple[str, str]]:
        """
        Check if node is a taint source.
        Returns (source_type, confidence) or None.
        """
        node_type = node.get('type', '')

        # Check MemberExpression sources (e.g., location.hash)
        if node_type == 'MemberExpression':
            obj = node.get('object', {})
            prop = node.get('property', {})

            obj_name = self.node_to_string(obj)
            prop_name = prop.get('name', '') if prop.get('type') == 'Identifier' else ''

            # Direct member source check
            key = (obj_name, prop_name)
            if key in MEMBER_SOURCES:
                return MEMBER_SOURCES[key]

            # Check for nested: window.location.hash
            if obj.get('type') == 'MemberExpression':
                inner_obj = self.node_to_string(obj.get('object', {}))
                inner_prop = obj.get('property', {}).get('name', '')

                if inner_obj in ('window', 'document', 'self') and inner_prop == 'location':
                    if prop_name in ('href', 'search', 'hash', 'pathname'):
                        return ('url', 'HIGH')

                # Express.js nested: req.query.name, req.body.foo, req.params.id
                if inner_obj in ('req', 'request'):
                    if inner_prop in ('query', 'body', 'params', 'headers', 'cookies'):
                        return (f'express_{inner_prop}', 'HIGH')

            # PostMessage: event.data, e.data
            if prop_name == 'data' and obj_name in ('event', 'e', 'evt', 'message', 'msg'):
                return ('postmessage', 'HIGH')

            # .value property (form inputs)
            if prop_name == 'value':
                return ('input', 'MEDIUM')

            # Computed property with string (potential prototype pollution)
            if node.get('computed'):
                return ('computed', 'LOW')

        # Check CallExpression sources
        elif node_type == 'CallExpression':
            callee = node.get('callee', {})

            # Direct function call
            if callee.get('type') == 'Identifier':
                func_name = callee.get('name', '')
                if func_name in CALL_SOURCES:
                    return CALL_SOURCES[func_name]

            # Method call: obj.method()
            elif callee.get('type') == 'MemberExpression':
                method_name = callee.get('property', {}).get('name', '')
                obj_name = self.node_to_string(callee.get('object', {}))

                # URLSearchParams.get()
                if method_name == 'get' and 'URLSearchParams' in obj_name:
                    return ('query', 'HIGH')
                if method_name == 'get' and 'searchParams' in obj_name:
                    return ('query', 'HIGH')

                # localStorage/sessionStorage.getItem()
                if method_name == 'getItem' and obj_name in ('localStorage', 'sessionStorage'):
                    return ('storage', 'MEDIUM')

                # .json() or .text() from fetch
                if method_name in ('json', 'text'):
                    return ('fetch_response', 'MEDIUM')

                # JSON.parse() - result is potentially tainted if input is tainted
                if obj_name == 'JSON' and method_name == 'parse':
                    return ('json_parse', 'HIGH')

        # NewExpression: new URLSearchParams(), new URL()
        elif node_type == 'NewExpression':
            callee = node.get('callee', {})
            if callee.get('type') == 'Identifier':
                class_name = callee.get('name', '')
                if class_name == 'URLSearchParams':
                    return ('query', 'HIGH')
                if class_name == 'URL':
                    return ('url', 'MEDIUM')

        return None

    def is_tainted(self, node: dict) -> Optional[TaintedVar]:
        """
        Check if node uses tainted data.
        Returns the TaintedVar if tainted, None otherwise.
        """
        node_type = node.get('type', '')

        # Direct identifier reference
        if node_type == 'Identifier':
            var_name = node.get('name', '')
            if var_name in self.tainted_vars:
                return self.tainted_vars[var_name]

        # Member expression - check if base object is tainted
        elif node_type == 'MemberExpression':
            obj = node.get('object', {})
            obj_taint = self.is_tainted(obj)
            if obj_taint:
                return obj_taint

            # Also check the full expression
            full_name = self.node_to_string(node)
            base_name = full_name.split('.')[0].split('[')[0]
            if base_name in self.tainted_vars:
                return self.tainted_vars[base_name]

        # Binary expression (string concatenation)
        elif node_type == 'BinaryExpression':
            left_taint = self.is_tainted(node.get('left', {}))
            if left_taint:
                return left_taint
            right_taint = self.is_tainted(node.get('right', {}))
            if right_taint:
                return right_taint

        # Logical expression (||, &&, ??)
        elif node_type == 'LogicalExpression':
            left_taint = self.is_tainted(node.get('left', {}))
            if left_taint:
                return left_taint
            right_taint = self.is_tainted(node.get('right', {}))
            if right_taint:
                return right_taint

        # Object expression with spread: { ...taintedVar }
        elif node_type == 'ObjectExpression':
            for prop in node.get('properties', []):
                # SpreadElement: { ...x }
                if prop.get('type') == 'SpreadElement':
                    arg_taint = self.is_tainted(prop.get('argument', {}))
                    if arg_taint:
                        return arg_taint
                # Regular property with tainted value
                elif prop.get('type') == 'Property':
                    val_taint = self.is_tainted(prop.get('value', {}))
                    if val_taint:
                        return val_taint

        # Array expression: [taintedVar, "safe", ...]
        elif node_type == 'ArrayExpression':
            for elem in node.get('elements', []):
                if elem:
                    elem_taint = self.is_tainted(elem)
                    if elem_taint:
                        return elem_taint

        # Template literal
        elif node_type == 'TemplateLiteral':
            for expr in node.get('expressions', []):
                taint = self.is_tainted(expr)
                if taint:
                    return taint

        # Call expression - check arguments AND method calls on tainted objects
        elif node_type == 'CallExpression':
            callee = node.get('callee', {})

            # Check for tainted array/string methods: arr.join(), str.split(), etc.
            # These propagate taint from the object to the result
            if callee.get('type') == 'MemberExpression':
                obj = callee.get('object', {})
                method = callee.get('property', {}).get('name', '')

                # Methods that propagate taint from object to result
                taint_propagating_methods = {
                    'join', 'toString', 'valueOf', 'concat', 'slice', 'substring',
                    'substr', 'split', 'replace', 'replaceAll', 'trim', 'trimStart',
                    'trimEnd', 'toLowerCase', 'toUpperCase', 'normalize', 'repeat',
                    'padStart', 'padEnd', 'charAt', 'charCodeAt', 'at',
                    'map', 'filter', 'reduce', 'find', 'flat', 'flatMap',
                }

                if method in taint_propagating_methods:
                    obj_taint = self.is_tainted(obj)
                    if obj_taint:
                        return obj_taint

            # Also check arguments
            for arg in node.get('arguments', []):
                taint = self.is_tainted(arg)
                if taint:
                    return taint

        # Conditional expression
        elif node_type == 'ConditionalExpression':
            cons_taint = self.is_tainted(node.get('consequent', {}))
            if cons_taint:
                return cons_taint
            alt_taint = self.is_tainted(node.get('alternate', {}))
            if alt_taint:
                return alt_taint

        # Also check if the node itself is a source
        source = self.is_source(node)
        if source:
            line, col = self.get_node_location(node)
            return TaintedVar(
                name=self.node_to_string(node),
                line=line,
                source_type=source[0],
                source_code=self.node_to_string(node)
            )

        return None

    def is_sanitized(self, node: dict) -> bool:
        """Check if value appears to be sanitized."""
        node_type = node.get('type', '')

        if node_type == 'CallExpression':
            callee = node.get('callee', {})

            # Direct sanitizer call
            if callee.get('type') == 'Identifier':
                func_name = callee.get('name', '')
                if func_name in SAFE_FUNCTIONS:
                    return True

            # Method call: DOMPurify.sanitize()
            elif callee.get('type') == 'MemberExpression':
                obj_name = self.node_to_string(callee.get('object', {}))
                method_name = callee.get('property', {}).get('name', '')

                if obj_name in SAFE_FUNCTIONS or method_name in ('sanitize', 'escape', 'encode'):
                    return True

                # encodeURIComponent, etc.
                full_call = f"{obj_name}.{method_name}"
                if any(safe in full_call for safe in SAFE_FUNCTIONS):
                    return True

        return False

    def check_sink(self, node: dict, value_node: dict, sink_name: str, sink_info: tuple) -> None:
        """Check if a sink receives tainted data and report finding."""
        category, severity, cwe = sink_info

        # Skip if value is sanitized
        if self.is_sanitized(value_node):
            self.log(f"Skipping sanitized sink: {sink_name}")
            return

        # Check if value is tainted
        taint = self.is_tainted(value_node)

        # Also check if value itself is a direct source
        if not taint:
            source = self.is_source(value_node)
            if source:
                line, col = self.get_node_location(value_node)
                taint = TaintedVar(
                    name=self.node_to_string(value_node),
                    line=line,
                    source_type=source[0],
                    source_code=self.node_to_string(value_node)
                )

        if taint:
            line, col = self.get_node_location(node)

            # If line not found, try searching for the sink pattern
            if line == 0:
                # Search for sink usage with tainted variable
                sink_patterns = [
                    f'.{sink_name}',
                    f'{sink_name}(',
                    f'{sink_name} =',
                ]
                for pattern in sink_patterns:
                    line = self.find_line_for_pattern(pattern)
                    if line > 0:
                        # Make sure this line also references the tainted var or source
                        line_content = self.get_line_content(line)
                        if taint.name in line_content or taint.source_code[:15] in line_content:
                            break
                        # Keep searching
                        for j, src_line in enumerate(self.source_lines[line:], line + 1):
                            if pattern.replace('.', '') in src_line:
                                if taint.name in src_line or taint.source_code[:15] in src_line:
                                    line = j
                                    break

            confidence = 'HIGH' if taint.source_type in ('url', 'query', 'hash', 'postmessage', 'cookie') else 'MEDIUM'

            self.findings.append(Finding(
                file_path=self.file_path,
                line_number=line,
                column=col,
                node_type=node.get('type', 'Unknown'),
                vulnerability_name=f"{category.value} via {sink_name}",
                category=category,
                severity=severity,
                confidence=confidence,
                description=f"Tainted data from '{taint.source_type}' source flows to dangerous sink '{sink_name}'",
                source=taint.source_code,
                sink=sink_name,
                code_snippet=self.get_line_content(line),
                cwe_id=cwe,
                remediation=self.get_remediation(sink_name)
            ))
            self.log(f"Found {category.value}: {sink_name} at line {line}")

    def get_remediation(self, sink_name: str) -> str:
        """Get remediation advice for a sink."""
        remediations = {
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
        }
        return remediations.get(sink_name, "Validate and sanitize user input before use")

    def visit(self, node: dict) -> None:
        """Visit an AST node and its children."""
        if not isinstance(node, dict):
            return

        node_type = node.get('type', '')

        # Dispatch to specific visitor
        visitor = getattr(self, f'visit_{node_type}', None)
        if visitor:
            visitor(node)

        # Visit children
        self.visit_children(node)

    def visit_children(self, node: dict) -> None:
        """Visit all child nodes."""
        for key, value in node.items():
            if key in ('type', 'loc', 'range', 'start', 'end'):
                continue
            if isinstance(value, dict):
                self.visit(value)
            elif isinstance(value, list):
                for item in value:
                    if isinstance(item, dict):
                        self.visit(item)

    def visit_VariableDeclarator(self, node: dict) -> None:
        """Handle variable declarations: var x = source;"""
        var_id = node.get('id', {})
        init = node.get('init')

        if not init:
            return

        # Handle destructuring: const { a, b } = source;
        if var_id.get('type') == 'ObjectPattern':
            # Check if RHS is a tainted source
            source = self.is_source(init)
            taint = self.is_tainted(init) if not source else None

            source_info = source or (taint.source_type if taint else None, 'HIGH' if taint else None)

            if source_info and source_info[0]:
                # All destructured properties are tainted
                for prop in var_id.get('properties', []):
                    prop_key = prop.get('key', {})
                    prop_value = prop.get('value', {})

                    # Get the variable name being assigned
                    if prop_value.get('type') == 'Identifier':
                        var_name = prop_value.get('name', '')
                    elif prop_key.get('type') == 'Identifier':
                        var_name = prop_key.get('name', '')
                    else:
                        continue

                    line, col = self.get_node_location(node)
                    self.tainted_vars[var_name] = TaintedVar(
                        name=var_name,
                        line=line,
                        source_type=source_info[0] if isinstance(source_info[0], str) else source_info[0],
                        source_code=f"{self.node_to_string(init)}.{var_name}"
                    )
                    self.log(f"Destructured taint: {var_name} from {self.node_to_string(init)}")
            return

        # Handle array destructuring: const [a, b] = source;
        if var_id.get('type') == 'ArrayPattern':
            source = self.is_source(init)
            taint = self.is_tainted(init) if not source else None

            if source or taint:
                source_type = source[0] if source else taint.source_type
                for i, elem in enumerate(var_id.get('elements', [])):
                    if elem and elem.get('type') == 'Identifier':
                        var_name = elem.get('name', '')
                        line, col = self.get_node_location(node)
                        self.tainted_vars[var_name] = TaintedVar(
                            name=var_name,
                            line=line,
                            source_type=source_type,
                            source_code=f"{self.node_to_string(init)}[{i}]"
                        )
                        self.log(f"Array destructured taint: {var_name}")
            return

        if var_id.get('type') != 'Identifier':
            return

        var_name = var_id.get('name', '')

        # Check if initializer is a source
        source = self.is_source(init)
        if source:
            line, col = self.get_node_location(node)
            self.tainted_vars[var_name] = TaintedVar(
                name=var_name,
                line=line,
                source_type=source[0],
                source_code=self.node_to_string(init)
            )
            self.log(f"Tainted var: {var_name} = {self.node_to_string(init)} (source: {source[0]})")

        # Check if initializer uses tainted data
        taint = self.is_tainted(init)
        if taint and var_name not in self.tainted_vars:
            line, col = self.get_node_location(node)
            self.tainted_vars[var_name] = TaintedVar(
                name=var_name,
                line=line,
                source_type=taint.source_type,
                source_code=taint.source_code
            )
            self.log(f"Propagated taint: {var_name} from {taint.name}")

        # Check for spread operator prototype pollution: { ...taintedVar }
        if init and init.get('type') == 'ObjectExpression':
            for prop in init.get('properties', []):
                if prop.get('type') == 'SpreadElement':
                    spread_arg = prop.get('argument', {})
                    spread_taint = self.is_tainted(spread_arg)
                    if spread_taint:
                        line, col = self.get_node_location(node)
                        if line == 0:
                            line = self.find_line_for_pattern('...')
                        self.findings.append(Finding(
                            file_path=self.file_path,
                            line_number=line,
                            column=col,
                            node_type='SpreadElement',
                            vulnerability_name="Prototype Pollution via Spread Operator",
                            category=VulnCategory.PROTOTYPE_POLLUTION,
                            severity=Severity.HIGH,
                            confidence='HIGH',
                            description=f"Spreading tainted object '{spread_taint.name}' can cause prototype pollution if it contains __proto__",
                            source=spread_taint.source_code,
                            sink="{ ...obj }",
                            code_snippet=self.get_line_content(line),
                            cwe_id="CWE-1321",
                            remediation="Sanitize object before spreading, or use Object.assign with Object.create(null)"
                        ))

    def visit_AssignmentExpression(self, node: dict) -> None:
        """Handle assignments: x = source; or element.innerHTML = tainted;"""
        left = node.get('left', {})
        right = node.get('right', {})
        left_type = left.get('type', '')

        # Variable assignment: x = value
        if left_type == 'Identifier':
            var_name = left.get('name', '')

            # Check if RHS is a source
            source = self.is_source(right)
            if source:
                line, col = self.get_node_location(node)
                self.tainted_vars[var_name] = TaintedVar(
                    name=var_name,
                    line=line,
                    source_type=source[0],
                    source_code=self.node_to_string(right)
                )
                self.log(f"Assigned taint: {var_name} = {self.node_to_string(right)}")

            # Check if RHS is tainted
            taint = self.is_tainted(right)
            if taint and var_name not in self.tainted_vars:
                line, col = self.get_node_location(node)
                self.tainted_vars[var_name] = TaintedVar(
                    name=var_name,
                    line=line,
                    source_type=taint.source_type,
                    source_code=taint.source_code
                )

        # Property assignment: element.innerHTML = value
        elif left_type == 'MemberExpression':
            prop = left.get('property', {})
            prop_name = prop.get('name', '') if prop.get('type') == 'Identifier' else ''

            # Check dangerous property sinks
            if prop_name in PROPERTY_SINKS:
                self.check_sink(node, right, prop_name, PROPERTY_SINKS[prop_name])

            # Check navigation sinks (href, src)
            elif prop_name in NAVIGATION_SINKS:
                # Only flag if on location or link/script elements
                obj_str = self.node_to_string(left.get('object', {}))
                if 'location' in obj_str or prop_name == 'src':
                    self.check_sink(node, right, prop_name, NAVIGATION_SINKS[prop_name])

            # Check for safe sinks (don't flag)
            elif prop_name in SAFE_SINKS:
                self.log(f"Safe sink: {prop_name}")

            # Check for __proto__ or constructor.prototype anywhere in the chain
            proto_found = self.check_proto_in_chain(left)
            if proto_found:
                line, col = self.get_node_location(node)
                if line == 0:
                    # Search for actual property access patterns, not string comparisons
                    for i, src_line in enumerate(self.source_lines, 1):
                        stripped = src_line.strip()
                        if stripped.startswith('//') or stripped.startswith('*'):
                            continue
                        # Look for property access patterns: .__proto__ or ['__proto__'] or ["__proto__"]
                        if (f'.{proto_found}' in src_line or
                            f"['{proto_found}']" in src_line or
                            f'["{proto_found}"]' in src_line):
                            # Make sure it's not a string comparison (=== or !==)
                            if '===' not in src_line and '!==' not in src_line:
                                line = i
                                break
                # Only report if we found actual property access (not just string comparison)
                if line > 0:
                    self.findings.append(Finding(
                        file_path=self.file_path,
                        line_number=line,
                        column=col,
                        node_type='AssignmentExpression',
                        vulnerability_name="Prototype Pollution",
                        category=VulnCategory.PROTOTYPE_POLLUTION,
                        severity=Severity.CRITICAL,
                        confidence='HIGH',
                        description=f"Access to '{proto_found}' in property chain allows prototype pollution",
                        sink=proto_found,
                        code_snippet=self.get_line_content(line),
                        cwe_id="CWE-1321",
                        remediation="Never allow __proto__ or constructor.prototype access from user input"
                    ))

            # Check computed property for prototype pollution: obj[key] = value
            if left.get('computed'):
                key_node = left.get('property', {})
                key_taint = self.is_tainted(key_node)

                if key_taint:
                    line, col = self.get_node_location(node)
                    self.findings.append(Finding(
                        file_path=self.file_path,
                        line_number=line,
                        column=col,
                        node_type='AssignmentExpression',
                        vulnerability_name="Potential Prototype Pollution",
                        category=VulnCategory.PROTOTYPE_POLLUTION,
                        severity=Severity.HIGH,
                        confidence='MEDIUM',
                        description=f"Dynamic property assignment with tainted key. If key is '__proto__', prototype pollution occurs.",
                        source=key_taint.source_code,
                        sink="computed property assignment",
                        code_snippet=self.get_line_content(line),
                        cwe_id="CWE-1321",
                        remediation="Validate keys against '__proto__', 'constructor', 'prototype'. Use Object.create(null) or Map."
                    ))

                # Check for literal __proto__ access
                if key_node.get('type') == 'Literal' and key_node.get('value') in PROTO_POLLUTION_PROPS:
                    line, col = self.get_node_location(node)
                    prop_name = key_node.get('value')
                    # Fallback: search for __proto__ or constructor in source
                    if line == 0:
                        line = self.find_line_for_pattern(f"'{prop_name}'") or self.find_line_for_pattern(f'"{prop_name}"')
                    self.findings.append(Finding(
                        file_path=self.file_path,
                        line_number=line,
                        column=col,
                        node_type='AssignmentExpression',
                        vulnerability_name="Prototype Pollution",
                        category=VulnCategory.PROTOTYPE_POLLUTION,
                        severity=Severity.CRITICAL,
                        confidence='HIGH',
                        description=f"Direct access to '{prop_name}' allows prototype pollution",
                        sink=prop_name,
                        code_snippet=self.get_line_content(line),
                        cwe_id="CWE-1321",
                        remediation="Never allow direct __proto__ or constructor.prototype access"
                    ))

    def visit_CallExpression(self, node: dict) -> None:
        """Handle function calls: eval(tainted), element.innerHTML(tainted)"""
        callee = node.get('callee', {})
        args = node.get('arguments', [])

        callee_type = callee.get('type', '')

        # Check for dynamic property call: obj[taintedKey]() - user controls which method is called
        if callee_type == 'MemberExpression' and callee.get('computed'):
            key_node = callee.get('property', {})
            key_taint = self.is_tainted(key_node)

            if key_taint:
                line, col = self.get_node_location(node)
                if line == 0:
                    # Try to find the pattern in source
                    key_str = self.node_to_string(key_node)
                    line = self.find_line_for_pattern(f'[{key_str}](')

                self.findings.append(Finding(
                    file_path=self.file_path,
                    line_number=line,
                    column=col,
                    node_type='CallExpression',
                    vulnerability_name="Dynamic Method Invocation",
                    category=VulnCategory.PROTOTYPE_POLLUTION,
                    severity=Severity.CRITICAL,
                    confidence='HIGH',
                    description=f"User-controlled method name '{key_taint.name}' allows invoking arbitrary methods. Can lead to prototype pollution or RCE via constructor access.",
                    source=key_taint.source_code,
                    sink="obj[userInput]()",
                    code_snippet=self.get_line_content(line),
                    cwe_id="CWE-94",
                    remediation="Validate method names against an allowlist. Never use user input directly as method/property names."
                ))

        # Direct function call: eval(), setTimeout()
        if callee_type == 'Identifier':
            func_name = callee.get('name', '')

            if func_name in CALL_SINKS and args:
                # For setTimeout/setInterval, only flag if first arg is string-like or tainted
                if func_name in ('setTimeout', 'setInterval', 'setImmediate'):
                    first_arg = args[0]
                    # Only dangerous if first arg is a string or tainted variable
                    if first_arg.get('type') == 'Literal' and isinstance(first_arg.get('value'), str):
                        self.check_sink(node, first_arg, func_name, CALL_SINKS[func_name])
                    elif self.is_tainted(first_arg):
                        self.check_sink(node, first_arg, func_name, CALL_SINKS[func_name])
                else:
                    # For eval, Function, etc. - check first argument
                    self.check_sink(node, args[0], func_name, CALL_SINKS[func_name])

            # Check Function constructor: new Function(tainted)
            if func_name == 'Function' and args:
                self.check_sink(node, args[-1], 'Function', CALL_SINKS['Function'])

        # Method call: document.write(), element.insertAdjacentHTML()
        elif callee_type == 'MemberExpression':
            method_name = callee.get('property', {}).get('name', '')
            obj = callee.get('object', {})
            obj_str = self.node_to_string(obj)

            # Object.defineProperty prototype pollution: Object.defineProperty(obj.__proto__, key, desc)
            if obj_str == 'Object' and method_name == 'defineProperty' and len(args) >= 2:
                target_arg = args[0]
                key_arg = args[1] if len(args) > 1 else {}

                # Check if target is __proto__ access
                target_proto = self.check_proto_in_chain(target_arg)
                # Check if key is tainted (user-controlled property name)
                key_taint = self.is_tainted(key_arg)

                if target_proto or key_taint:
                    line, col = self.get_node_location(node)
                    if line == 0:
                        line = self.find_line_for_pattern('defineProperty')

                    desc = f"Using {target_proto} as defineProperty target" if target_proto else f"User-controlled property name '{key_taint.name}'"

                    self.findings.append(Finding(
                        file_path=self.file_path,
                        line_number=line,
                        column=col,
                        node_type='CallExpression',
                        vulnerability_name="Prototype Pollution via Object.defineProperty()",
                        category=VulnCategory.PROTOTYPE_POLLUTION,
                        severity=Severity.CRITICAL,
                        confidence='HIGH',
                        description=f"{desc} allows prototype pollution via Object.defineProperty().",
                        source=key_taint.source_code if key_taint else target_proto,
                        sink="Object.defineProperty()",
                        code_snippet=self.get_line_content(line),
                        cwe_id="CWE-1321",
                        remediation="Never use __proto__ with Object.defineProperty(). Validate property names against dangerous values."
                    ))

            # Object.assign prototype pollution: Object.assign({}, taintedSource) or Object.assign(__proto__, data)
            # Must check FIRST before other 'assign' patterns
            elif obj_str == 'Object' and method_name == 'assign' and len(args) >= 2:
                # First check: is the target (args[0]) using __proto__?
                target_arg = args[0]
                target_proto = self.check_proto_in_chain(target_arg)
                if target_proto:
                    # Check if any source arg is tainted
                    for arg in args[1:]:
                        taint = self.is_tainted(arg)
                        if taint:
                            line, col = self.get_node_location(node)
                            if line == 0:
                                line = self.find_line_for_pattern('Object.assign')

                            self.findings.append(Finding(
                                file_path=self.file_path,
                                line_number=line,
                                column=col,
                                node_type='CallExpression',
                                vulnerability_name="Prototype Pollution via Object.assign() to __proto__",
                                category=VulnCategory.PROTOTYPE_POLLUTION,
                                severity=Severity.CRITICAL,
                                confidence='HIGH',
                                description=f"Object.assign() directly modifying {target_proto} with tainted data from '{taint.source_type}' causes prototype pollution.",
                                source=taint.source_code,
                                sink=f"Object.assign({target_proto}, ...)",
                                code_snippet=self.get_line_content(line),
                                cwe_id="CWE-1321",
                                remediation="Never use __proto__ as Object.assign target. Use a regular object instead."
                            ))
                            break

                # Second check: is any source argument tainted or from JSON.parse?
                for i, arg in enumerate(args[1:], 1):
                    is_json_parse = False
                    taint = None

                    # Check for JSON.parse directly
                    if arg.get('type') == 'CallExpression':
                        arg_callee = arg.get('callee', {})
                        if arg_callee.get('type') == 'MemberExpression':
                            arg_obj = self.node_to_string(arg_callee.get('object', {}))
                            arg_method = arg_callee.get('property', {}).get('name', '')
                            if arg_obj == 'JSON' and arg_method == 'parse':
                                is_json_parse = True

                    # Check if argument is tainted (including from JSON.parse result stored in variable)
                    taint = self.is_tainted(arg)

                    if is_json_parse or taint:
                        line, col = self.get_node_location(node)
                        if line == 0:
                            line = self.find_line_for_pattern('Object.assign')

                        source_desc = "JSON.parse()" if is_json_parse else (taint.source_code if taint else "unknown")
                        confidence = 'HIGH' if (is_json_parse or (taint and taint.source_type == 'json_parse')) else 'MEDIUM'

                        self.findings.append(Finding(
                            file_path=self.file_path,
                            line_number=line,
                            column=col,
                            node_type='CallExpression',
                            vulnerability_name="Prototype Pollution via Object.assign()",
                            category=VulnCategory.PROTOTYPE_POLLUTION,
                            severity=Severity.HIGH,
                            confidence=confidence,
                            description=f"Object.assign() with potentially tainted source from {source_desc}. If source contains __proto__, prototype pollution occurs.",
                            source=source_desc,
                            sink="Object.assign()",
                            code_snippet=self.get_line_content(line),
                            cwe_id="CWE-1321",
                            remediation="Use Object.create(null) as target, or filter __proto__/constructor from source before assigning."
                        ))
                        break

            # document.write(), document.writeln()
            elif method_name in ('write', 'writeln') and 'document' in obj_str:
                if args:
                    self.check_sink(node, args[0], method_name, CALL_SINKS[method_name])

            # insertAdjacentHTML
            elif method_name == 'insertAdjacentHTML' and len(args) >= 2:
                self.check_sink(node, args[1], method_name, CALL_SINKS[method_name])

            # jQuery methods: .html(), .append(), etc. (but not Object.assign)
            elif method_name in CALL_SINKS and args and not (obj_str == 'Object' and method_name == 'assign'):
                self.check_sink(node, args[0], method_name, CALL_SINKS[method_name])

            # location.assign(), location.replace()
            elif method_name in ('assign', 'replace') and 'location' in obj_str:
                if args:
                    self.check_sink(node, args[0], method_name, CALL_SINKS[method_name])

            # window.open()
            elif method_name == 'open' and obj_str in ('window', 'self'):
                if args:
                    self.check_sink(node, args[0], 'open', CALL_SINKS['open'])

            # Dangerous merge functions: _.merge(), $.extend(true, ...) (but not Object.assign - handled above)
            elif method_name in DANGEROUS_MERGE_FUNCS:
                line, col = self.get_node_location(node)
                # Fallback: search for method call in source
                if line == 0:
                    line = self.find_line_for_pattern(f'.{method_name}(')
                # Check if deep merge ($.extend(true, ...))
                is_deep = False
                if method_name == 'extend' and args and args[0].get('value') is True:
                    is_deep = True

                confidence = 'HIGH' if is_deep or method_name in ('merge', 'mergeWith', 'defaultsDeep') else 'MEDIUM'

                # Check if any argument is tainted
                for arg in args:
                    if self.is_tainted(arg):
                        self.findings.append(Finding(
                            file_path=self.file_path,
                            line_number=line,
                            column=col,
                            node_type='CallExpression',
                            vulnerability_name=f"Prototype Pollution via {method_name}()",
                            category=VulnCategory.PROTOTYPE_POLLUTION,
                            severity=Severity.HIGH,
                            confidence=confidence,
                            description=f"Tainted data passed to {method_name}() can cause prototype pollution",
                            sink=method_name,
                            code_snippet=self.get_line_content(line),
                            cwe_id="CWE-1321",
                            remediation=f"Validate input before passing to {method_name}(). Use Object.create(null) for target objects."
                        ))
                        break

            # Express.js response sinks: res.send(), res.write(), res.end()
            elif method_name in EXPRESS_SINKS and obj_str in ('res', 'response'):
                if args:
                    # Check if the argument contains tainted data or is a template literal with tainted vars
                    arg = args[0]
                    taint = self.is_tainted(arg)

                    # Also check if argument is template literal containing HTML
                    if not taint and arg.get('type') == 'TemplateLiteral':
                        # Template literal - check if any expression in it is tainted
                        for expr in arg.get('expressions', []):
                            taint = self.is_tainted(expr)
                            if taint:
                                break

                    if taint:
                        line, col = self.get_node_location(node)
                        if line == 0:
                            line = self.find_line_for_pattern(f'.{method_name}(')
                        category, severity, cwe = EXPRESS_SINKS[method_name]
                        self.findings.append(Finding(
                            file_path=self.file_path,
                            line_number=line,
                            column=col,
                            node_type='CallExpression',
                            vulnerability_name=f"Reflected XSS via {method_name}()",
                            category=category,
                            severity=severity,
                            confidence='HIGH',
                            description=f"Tainted data from '{taint.source_type}' reflected in HTTP response via {method_name}()",
                            source=taint.source_code,
                            sink=f"res.{method_name}()",
                            code_snippet=self.get_line_content(line),
                            cwe_id=cwe,
                            remediation="Escape HTML entities before including in response, or use res.json() for JSON data"
                        ))

            # Node.js fs sinks: fs.readFile(), fs.readFileSync(), etc.
            elif method_name in FS_SINKS and obj_str in ('fs', 'require("fs")', "require('fs')"):
                if args:
                    arg = args[0]
                    taint = self.is_tainted(arg)
                    if taint:
                        line, col = self.get_node_location(node)
                        if line == 0:
                            line = self.find_line_for_pattern(f'.{method_name}(')
                        category, severity, cwe = FS_SINKS[method_name]
                        self.findings.append(Finding(
                            file_path=self.file_path,
                            line_number=line,
                            column=col,
                            node_type='CallExpression',
                            vulnerability_name=f"Path Traversal via fs.{method_name}()",
                            category=category,
                            severity=severity,
                            confidence='HIGH',
                            description=f"Tainted data from '{taint.source_type}' used as file path in fs.{method_name}(). Attacker can read/write arbitrary files.",
                            source=taint.source_code,
                            sink=f"fs.{method_name}()",
                            code_snippet=self.get_line_content(line),
                            cwe_id=cwe,
                            remediation="Validate and sanitize file paths. Use path.basename() or a whitelist of allowed paths."
                        ))

            # Node.js child_process sinks: exec(), spawn(), etc.
            elif method_name in COMMAND_SINKS:
                if args:
                    arg = args[0]
                    taint = self.is_tainted(arg)
                    if taint:
                        line, col = self.get_node_location(node)
                        if line == 0:
                            line = self.find_line_for_pattern(f'.{method_name}(')
                        category, severity, cwe = COMMAND_SINKS[method_name]
                        self.findings.append(Finding(
                            file_path=self.file_path,
                            line_number=line,
                            column=col,
                            node_type='CallExpression',
                            vulnerability_name=f"Command Injection via {method_name}()",
                            category=category,
                            severity=severity,
                            confidence='HIGH',
                            description=f"Tainted data from '{taint.source_type}' used in command execution via {method_name}(). Attacker can execute arbitrary commands.",
                            source=taint.source_code,
                            sink=f"{method_name}()",
                            code_snippet=self.get_line_content(line),
                            cwe_id=cwe,
                            remediation="Never pass user input directly to command execution. Use parameterized APIs or strict input validation."
                        ))

        # Inter-procedural: Check if calling a user-defined function with tainted args
        # that eventually passes to a sink (runs for ALL calls, not just unmatched ones)
        self._check_interprocedural_call(node, callee, args)

    def _check_interprocedural_call(self, node: dict, callee: dict, args: list) -> None:
        """
        Check for inter-procedural taint flow:
        When a function is called with tainted arguments, check if those args
        flow to sinks inside the function.
        """
        # Get function name
        func_name = None
        if callee.get('type') == 'Identifier':
            func_name = callee.get('name', '')
        elif callee.get('type') == 'MemberExpression':
            func_name = callee.get('property', {}).get('name', '')

        if not func_name or not args:
            return

        # Check if any argument is tainted
        tainted_arg_indices = []
        for i, arg in enumerate(args):
            taint = self.is_tainted(arg)
            if taint:
                tainted_arg_indices.append((i, taint))

        if not tainted_arg_indices:
            return

        # Check if this function is known to pass its arg to a sink
        # This is a simplified check - in practice would need full call graph analysis
        dangerous_wrapper_patterns = {
            'respond': [1],  # respond(res, data, ...) - data at index 1
            'sendResponse': [0, 1],
            'sendError': [0, 1],
            'writeResponse': [0, 1],
            'output': [0],
            'render': [0, 1],
            'sendData': [0, 1],
        }

        if func_name.lower() in [p.lower() for p in dangerous_wrapper_patterns.keys()]:
            for idx, taint in tainted_arg_indices:
                # Check if this arg index is potentially dangerous
                line, col = self.get_node_location(node)
                if line == 0:
                    line = self.find_line_for_pattern(f'{func_name}(')

                self.findings.append(Finding(
                    file_path=self.file_path,
                    line_number=line,
                    column=col,
                    node_type='CallExpression',
                    vulnerability_name=f"Potential XSS via {func_name}()",
                    category=VulnCategory.REFLECTED_XSS,
                    severity=Severity.MEDIUM,
                    confidence='MEDIUM',
                    description=f"Tainted data from '{taint.source_type}' passed to function '{func_name}()' which may output to response. Review function implementation.",
                    source=taint.source_code,
                    sink=f"{func_name}()",
                    code_snippet=self.get_line_content(line),
                    cwe_id="CWE-79",
                    remediation="Ensure the function properly escapes data before outputting to HTTP response."
                ))
                break  # Only report once per call

    def visit_NewExpression(self, node: dict) -> None:
        """Handle new expressions: new Function(tainted)"""
        callee = node.get('callee', {})
        args = node.get('arguments', [])

        if callee.get('type') == 'Identifier':
            class_name = callee.get('name', '')

            # new Function(code)
            if class_name == 'Function' and args:
                self.check_sink(node, args[-1], 'Function', CALL_SINKS['Function'])

    def visit_ForInStatement(self, node: dict) -> None:
        """
        Detect prototype pollution in for-in loops:
        for (let key in taintedObj) { target[key] = taintedObj[key]; }
        """
        left = node.get('left', {})
        right = node.get('right', {})
        body = node.get('body', {})

        # Get the loop variable name
        loop_var = None
        if left.get('type') == 'VariableDeclaration':
            decls = left.get('declarations', [])
            if decls and decls[0].get('id', {}).get('type') == 'Identifier':
                loop_var = decls[0]['id'].get('name')
        elif left.get('type') == 'Identifier':
            loop_var = left.get('name')

        if not loop_var:
            return

        # Check if iterating over tainted object
        iterated_obj = self.node_to_string(right)
        is_tainted_iteration = self.is_tainted(right) is not None

        # Check if the iterated object could be user-controlled:
        # 1. It's tainted from a known source
        # 2. It's a function parameter (potentially user input)
        # 3. It's from JSON.parse
        # 4. It's from any external/unknown source
        is_potentially_unsafe = is_tainted_iteration

        if right.get('type') == 'Identifier':
            var_name = right.get('name', '')
            # Treat function parameters and unknown variables as potentially tainted
            # Names like userConfig, userInput, data, input, params, etc. are suspicious
            suspicious_names = ['user', 'input', 'data', 'config', 'params', 'options',
                               'settings', 'body', 'payload', 'request', 'req', 'args', 'source', 'obj']
            if any(sus in var_name.lower() for sus in suspicious_names):
                is_potentially_unsafe = True
            # Also flag if variable is not in our tainted tracking (could be parameter)
            elif var_name not in self.tainted_vars:
                is_potentially_unsafe = True

        elif right.get('type') == 'CallExpression':
            callee = right.get('callee', {})
            if callee.get('type') == 'MemberExpression':
                obj_name = self.node_to_string(callee.get('object', {}))
                method = callee.get('property', {}).get('name', '')
                if obj_name == 'JSON' and method == 'parse':
                    is_potentially_unsafe = True

        if not is_potentially_unsafe:
            return

        # Look for assignment patterns in the loop body: target[key] = source[key]
        self._check_forin_body_for_pollution(body, loop_var, iterated_obj, node)

    def _check_forin_body_for_pollution(self, body: dict, loop_var: str, iterated_obj: str, forin_node: dict) -> None:
        """Check for-in loop body for prototype pollution patterns."""
        if not isinstance(body, dict):
            return

        body_type = body.get('type', '')

        # Handle block statement
        if body_type == 'BlockStatement':
            for stmt in body.get('body', []):
                self._check_forin_body_for_pollution(stmt, loop_var, iterated_obj, forin_node)
            return

        # Handle if statement (may contain the assignment)
        if body_type == 'IfStatement':
            self._check_forin_body_for_pollution(body.get('consequent', {}), loop_var, iterated_obj, forin_node)
            if body.get('alternate'):
                self._check_forin_body_for_pollution(body.get('alternate', {}), loop_var, iterated_obj, forin_node)
            return

        # Check expression statements
        if body_type == 'ExpressionStatement':
            expr = body.get('expression', {})
            if expr.get('type') == 'AssignmentExpression':
                self._check_pollution_assignment(expr, loop_var, iterated_obj, forin_node)
            elif expr.get('type') == 'CallExpression':
                # Check for Object.assign or other merge functions inside for-in
                self._check_pollution_call(expr, loop_var, iterated_obj, forin_node)
            return

    def _check_pollution_assignment(self, expr: dict, loop_var: str, iterated_obj: str, forin_node: dict) -> None:
        """Check if an assignment in a for-in loop causes prototype pollution."""
        left = expr.get('left', {})

        # Look for pattern: target[key] = ... where key is the loop variable
        if left.get('type') == 'MemberExpression' and left.get('computed'):
            prop = left.get('property', {})
            if prop.get('type') == 'Identifier' and prop.get('name') == loop_var:
                # Found: target[loopVar] = value
                # This is vulnerable if there's no hasOwnProperty check

                line = self.find_line_for_pattern(f'[{loop_var}]')
                if line == 0:
                    line = self.find_line_for_pattern('for')

                # Check if there's a protection mechanism in the surrounding context
                has_protection = False
                # Get context: lines around the for-in loop (CODE only, not comments)
                context_start = max(0, line - 10) if line > 0 else 0
                context_end = min(len(self.source_lines), line + 10 if line > 0 else 20)
                context_lines = []
                for ctx_line in self.source_lines[context_start:context_end]:
                    stripped = ctx_line.strip()
                    # Skip comment lines for protection detection
                    if not (stripped.startswith('//') or stripped.startswith('*') or stripped.startswith('/*')):
                        context_lines.append(ctx_line)
                context = '\n'.join(context_lines)

                # Check for hasOwnProperty
                if 'hasOwnProperty' in context:
                    has_protection = True
                # Check for Object.hasOwn
                elif 'Object.hasOwn' in context:
                    has_protection = True
                # Check for explicit __proto__ filtering in CODE (not comments)
                elif ("'__proto__'" in context or '"__proto__"' in context):
                    # Must be in a conditional check, not just mentioned
                    if ('continue' in context or 'return' in context) and '===' in context:
                        has_protection = True
                # Check for Object.keys usage instead
                elif 'Object.keys' in context:
                    has_protection = True

                if not has_protection:
                    self.findings.append(Finding(
                        file_path=self.file_path,
                        line_number=line,
                        column=0,
                        node_type='ForInStatement',
                        vulnerability_name="Prototype Pollution via for-in loop",
                        category=VulnCategory.PROTOTYPE_POLLUTION,
                        severity=Severity.CRITICAL,
                        confidence='HIGH',
                        description=f"Iterating over '{iterated_obj}' with for-in and assigning to target[{loop_var}] without hasOwnProperty check allows prototype pollution",
                        source=iterated_obj,
                        sink=f"target[{loop_var}]",
                        code_snippet=self.get_line_content(line),
                        cwe_id="CWE-1321",
                        remediation="Add hasOwnProperty check, or filter out '__proto__', 'constructor', 'prototype' keys, or use Object.keys() instead of for-in"
                    ))

    def _check_pollution_call(self, expr: dict, loop_var: str, iterated_obj: str, forin_node: dict) -> None:
        """Check if a function call in a for-in loop causes prototype pollution (e.g., Object.assign)."""
        callee = expr.get('callee', {})
        args = expr.get('arguments', [])

        # Check for Object.assign pattern
        is_dangerous_merge = False
        method_name = ""

        if callee.get('type') == 'MemberExpression':
            obj = callee.get('object', {})
            prop = callee.get('property', {})
            obj_name = self.node_to_string(obj)
            method_name = prop.get('name', '') if prop.get('type') == 'Identifier' else ''

            # Object.assign(target[loopVar], source[loopVar])
            if obj_name == 'Object' and method_name == 'assign':
                is_dangerous_merge = True
            # _.merge, _.extend, $.extend, etc.
            elif method_name in DANGEROUS_MERGE_FUNCS:
                is_dangerous_merge = True

        elif callee.get('type') == 'Identifier':
            method_name = callee.get('name', '')
            # Direct call to merge functions like deepMerge()
            if method_name in DANGEROUS_MERGE_FUNCS:
                is_dangerous_merge = True

        if not is_dangerous_merge:
            return

        # Check if arguments involve the loop variable (e.g., source[property])
        involves_loop_var = False
        for arg in args:
            arg_str = self.node_to_string(arg)
            if loop_var in arg_str or iterated_obj in arg_str:
                involves_loop_var = True
                break
            # Check for computed property access with loop var
            if arg.get('type') == 'MemberExpression' and arg.get('computed'):
                prop = arg.get('property', {})
                if prop.get('type') == 'Identifier' and prop.get('name') == loop_var:
                    involves_loop_var = True
                    break

        if not involves_loop_var:
            return

        # Find line number
        line = self.find_line_for_pattern(f'{method_name}(')
        if line == 0:
            line = self.find_line_for_pattern(f'for')

        # Check for protection mechanisms
        has_protection = False
        context_start = max(0, line - 10) if line > 0 else 0
        context_end = min(len(self.source_lines), line + 10 if line > 0 else 20)
        context_lines = []
        for ctx_line in self.source_lines[context_start:context_end]:
            stripped = ctx_line.strip()
            if not (stripped.startswith('//') or stripped.startswith('*') or stripped.startswith('/*')):
                context_lines.append(ctx_line)
        context = '\n'.join(context_lines)

        if 'hasOwnProperty' in context or 'Object.hasOwn' in context:
            has_protection = True
        elif 'Object.keys' in context:
            has_protection = True
        elif ("'__proto__'" in context or '"__proto__"' in context):
            if ('continue' in context or 'return' in context) and '===' in context:
                has_protection = True

        if not has_protection:
            self.findings.append(Finding(
                file_path=self.file_path,
                line_number=line,
                column=0,
                node_type='ForInStatement',
                vulnerability_name=f"Prototype Pollution via {method_name}() in for-in loop",
                category=VulnCategory.PROTOTYPE_POLLUTION,
                severity=Severity.CRITICAL,
                confidence='HIGH',
                description=f"Calling {method_name}() inside for-in loop over '{iterated_obj}' without hasOwnProperty check allows prototype pollution",
                source=iterated_obj,
                sink=f"{method_name}()",
                code_snippet=self.get_line_content(line),
                cwe_id="CWE-1321",
                remediation="Add hasOwnProperty check, filter dangerous keys, or use Object.keys() instead of for-in"
            ))

    def visit_FunctionDeclaration(self, node: dict) -> None:
        """Track function context and parameters."""
        func_id = node.get('id', {})
        if func_id:
            self.current_function = func_id.get('name', '')

        # Track function parameters
        self._track_function_params(node)
        self._check_function_body_for_param_pollution(node)

    def visit_FunctionExpression(self, node: dict) -> None:
        """Track function context and parameters."""
        func_id = node.get('id', {})
        if func_id:
            self.current_function = func_id.get('name', '')

        # Track function parameters
        self._track_function_params(node)
        self._check_function_body_for_param_pollution(node)

    def visit_ArrowFunctionExpression(self, node: dict) -> None:
        """Track arrow function parameters."""
        self._track_function_params(node)
        self._check_function_body_for_param_pollution(node)

    def _track_function_params(self, node: dict) -> None:
        """Extract and track function parameter names."""
        params = node.get('params', [])
        for param in params:
            if param.get('type') == 'Identifier':
                self.function_params.add(param.get('name', ''))
            elif param.get('type') == 'AssignmentPattern':
                # Default parameter: (key = 'default')
                left = param.get('left', {})
                if left.get('type') == 'Identifier':
                    self.function_params.add(left.get('name', ''))

    def _check_function_body_for_param_pollution(self, node: dict) -> None:
        """Check if function parameters are used as computed property keys."""
        params = node.get('params', [])
        param_names = set()
        for param in params:
            if param.get('type') == 'Identifier':
                param_names.add(param.get('name', ''))
            elif param.get('type') == 'AssignmentPattern':
                left = param.get('left', {})
                if left.get('type') == 'Identifier':
                    param_names.add(left.get('name', ''))

        if not param_names:
            return

        # Get function body
        body = node.get('body', {})
        if body.get('type') == 'BlockStatement':
            self._scan_body_for_param_assignment(body, param_names)
        elif body.get('type') == 'AssignmentExpression':
            # Arrow function with expression body: (k, v) => obj[k] = v
            self._check_assignment_for_param_key(body, param_names)

    def _scan_body_for_param_assignment(self, body: dict, param_names: set) -> None:
        """Recursively scan function body for param-based computed property assignments."""
        if not isinstance(body, dict):
            return

        body_type = body.get('type', '')

        if body_type == 'BlockStatement':
            for stmt in body.get('body', []):
                self._scan_body_for_param_assignment(stmt, param_names)

        elif body_type == 'ExpressionStatement':
            expr = body.get('expression', {})
            if expr.get('type') == 'AssignmentExpression':
                self._check_assignment_for_param_key(expr, param_names)

        elif body_type == 'IfStatement':
            self._scan_body_for_param_assignment(body.get('consequent', {}), param_names)
            if body.get('alternate'):
                self._scan_body_for_param_assignment(body.get('alternate', {}), param_names)

        elif body_type == 'ForStatement' or body_type == 'WhileStatement':
            self._scan_body_for_param_assignment(body.get('body', {}), param_names)

    def _check_assignment_for_param_key(self, expr: dict, param_names: set) -> None:
        """Check if assignment uses a function parameter as computed property key."""
        left = expr.get('left', {})

        # Pattern: target[key] = value where key is a parameter
        if left.get('type') == 'MemberExpression' and left.get('computed'):
            key_node = left.get('property', {})
            if key_node.get('type') == 'Identifier':
                key_name = key_node.get('name', '')
                if key_name in param_names:
                    line, col = self.get_node_location(expr)
                    if line == 0:
                        line = self.find_line_for_pattern(f'[{key_name}]')

                    target_name = self.node_to_string(left.get('object', {}))

                    self.findings.append(Finding(
                        file_path=self.file_path,
                        line_number=line,
                        column=col,
                        node_type='AssignmentExpression',
                        vulnerability_name="Prototype Pollution via Function Parameter",
                        category=VulnCategory.PROTOTYPE_POLLUTION,
                        severity=Severity.HIGH,
                        confidence='MEDIUM',
                        description=f"Function parameter '{key_name}' used as computed property key in '{target_name}[{key_name}]'. If caller passes '__proto__', prototype pollution occurs.",
                        source=f"parameter: {key_name}",
                        sink=f"{target_name}[{key_name}]",
                        code_snippet=self.get_line_content(line),
                        cwe_id="CWE-1321",
                        remediation="Validate parameter against '__proto__', 'constructor', 'prototype' before use as property key."
                    ))

    def visit_TaggedTemplateExpression(self, node: dict) -> None:
        """
        Detect XSS via tagged template literals.
        Pattern: dangerousFunction`...${taintedValue}`
        """
        tag = node.get('tag', {})
        quasi = node.get('quasi', {})

        # Check if any expression in the template is tainted
        expressions = quasi.get('expressions', [])
        taint = None
        for expr in expressions:
            taint = self.is_tainted(expr)
            if taint:
                break

        if not taint:
            return

        # Get tag function name
        tag_name = self.node_to_string(tag)

        # Any tagged template with tainted input is potentially dangerous
        # The tag function processes the template and could use it unsafely
        line, col = self.get_node_location(node)
        if line == 0:
            line = self.find_line_for_pattern('`')

        self.findings.append(Finding(
            file_path=self.file_path,
            line_number=line,
            column=col,
            node_type='TaggedTemplateExpression',
            vulnerability_name="XSS via Tagged Template Literal",
            category=VulnCategory.DOM_XSS,
            severity=Severity.HIGH,
            confidence='MEDIUM',
            description=f"Tainted data from '{taint.source_type}' passed to tagged template function '{tag_name}'. If the tag function outputs to DOM, XSS may occur.",
            source=taint.source_code,
            sink=f"{tag_name}`...`",
            code_snippet=self.get_line_content(line),
            cwe_id="CWE-79",
            remediation="Ensure the tag function properly sanitizes interpolated values before DOM insertion."
        ))

    def analyze(self, ast: dict) -> List[Finding]:
        """Analyze the AST and return findings."""
        self.visit(ast)
        return self.findings


# ============================================================================
# Regex Fallback for HTML and non-parseable JS
# ============================================================================

class RegexScanner:
    """Fallback regex-based scanner for HTML and when pyjsparser is unavailable."""

    def __init__(self, file_path: str, source_code: str, verbose: bool = False):
        self.file_path = file_path
        self.source_code = source_code
        self.source_lines = source_code.split('\n')
        self.verbose = verbose
        self.findings: List[Finding] = []

    def log(self, msg: str) -> None:
        if self.verbose:
            print(f"  [DEBUG] {msg}")

    def get_line_content(self, line_num: int) -> str:
        if 0 < line_num <= len(self.source_lines):
            return self.source_lines[line_num - 1].strip()
        return ""

    def get_line_number(self, pos: int) -> int:
        return self.source_code[:pos].count('\n') + 1

    def scan(self) -> List[Finding]:
        """Run regex-based scanning."""
        self.scan_dom_xss()
        self.scan_prototype_pollution()
        self.scan_forin_pollution()
        self.scan_express_xss()
        self.scan_template_xss()
        return self.findings

    def scan_dom_xss(self) -> None:
        """Scan for DOM XSS patterns."""
        # Source patterns
        source_patterns = [
            (r'location\.(?:href|search|hash|pathname)', 'url'),
            (r'document\.(?:URL|documentURI|referrer|cookie)', 'document'),
            (r'window\.(?:name|location)', 'window'),
            (r'(?:localStorage|sessionStorage)\.getItem', 'storage'),
            (r'\.value\b', 'input'),
            (r'\b(?:e|evt|event|message)\.data\b', 'postmessage'),
        ]

        # Variable names that typically contain user-controlled/external data
        # These indicate HIGH confidence when used as sink arguments
        dangerous_var_patterns = [
            r'\b(?:response|res|data|result|html|content|body|payload|input|text|msg|message)\b',
            r'\b(?:user|param|query|arg|val|value|href|url|link|uri|path|src)\b',
        ]

        # Sink patterns with severity
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
            # jQuery selector injection: $('...' + userInput + '...')
            (r'\$\s*\([^)]*\+[^)]*location\.', 'jQuery selector (location)', Severity.MEDIUM),
        ]

        for sink_pattern, sink_name, severity in sink_patterns:
            for match in re.finditer(sink_pattern, self.source_code, re.IGNORECASE):
                line_num = self.get_line_number(match.start())
                line_content = self.get_line_content(line_num)

                # FALSE POSITIVE FIX: Skip location.href = 'static string' patterns
                # These are safe because the destination is hardcoded, not user-controlled
                if sink_name == 'location':
                    # Check if assignment value is a string literal (safe)
                    after_match = self.source_code[match.end():match.end()+200]
                    # Pattern: = followed by optional whitespace then quote (string literal)
                    if re.match(r"\s*['\"][^'\"]*['\"]", after_match):
                        continue

                # FALSE POSITIVE FIX: Skip window.open('static string') patterns
                if sink_name == 'window.open':
                    after_match = self.source_code[match.end():match.end()+200]
                    # Pattern: ( followed by optional whitespace then quote (string literal as first arg)
                    if re.match(r"\s*['\"][^'\"]*['\"]", after_match):
                        continue

                # Check if any source is on the same line or nearby
                source_found = None
                for src_pattern, src_type in source_patterns:
                    if re.search(src_pattern, line_content, re.IGNORECASE):
                        source_found = src_type
                        break

                # Check for sanitization
                if any(safe in line_content.lower() for safe in ['sanitize', 'encode', 'escape', 'dompurify']):
                    continue

                confidence = 'HIGH' if source_found else 'MEDIUM'

                # FALSE NEGATIVE FIX: Increase confidence for dangerous variable patterns
                # Variables like 'response', 'data', 'input' etc. typically contain user data
                if confidence == 'MEDIUM':
                    # Get the argument/value being passed to the sink
                    # For innerHTML = X, check X
                    # For .html(X), check X
                    rest_of_line = line_content[line_content.find(match.group(0)) if match.group(0) in line_content else 0:]

                    for var_pattern in dangerous_var_patterns:
                        if re.search(var_pattern, rest_of_line, re.IGNORECASE):
                            confidence = 'HIGH'
                            source_found = 'variable'
                            break

                    # Also check for empty string patterns like .html("") which are safe
                    if sink_name == 'jQuery.html':
                        # Pattern: .html("") or .html('') - safe clearing
                        if re.search(r'\.html\s*\(\s*["\']["\']', line_content):
                            continue
                        # Pattern: .html() used as getter (no arguments, followed by comparison/property access)
                        # e.g., .html() == "" or .html().length - these read HTML, not write it
                        if re.search(r'\.html\s*\(\s*\)\s*(?:==|===|!=|!==|\.|\))', line_content):
                            continue

                # Determine category and CWE based on sink type
                if sink_name in ('location', 'window.open'):
                    vuln_category = VulnCategory.OPEN_REDIRECT
                    vuln_name = f"Open Redirect via {sink_name}"
                    cwe = "CWE-601"
                    remediation = "Validate URLs against an allowlist of trusted domains before navigation"
                else:
                    vuln_category = VulnCategory.DOM_XSS
                    vuln_name = f"DOM XSS via {sink_name}"
                    cwe = "CWE-79"
                    remediation = "Sanitize user input before use in this context"

                self.findings.append(Finding(
                    file_path=self.file_path,
                    line_number=line_num,
                    column=match.start() - self.source_code.rfind('\n', 0, match.start()),
                    node_type='RegexMatch',
                    vulnerability_name=vuln_name,
                    category=vuln_category,
                    severity=severity,
                    confidence=confidence,
                    description=f"Dangerous sink '{sink_name}' detected" + (f" with {source_found} source" if source_found else ""),
                    source=source_found,
                    sink=sink_name,
                    code_snippet=line_content,
                    cwe_id=cwe,
                    remediation=remediation
                ))

    def scan_prototype_pollution(self) -> None:
        """Scan for prototype pollution patterns."""
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
                line_content = self.get_line_content(line_num)

                # Skip if hasOwnProperty check nearby
                context_start = max(0, match.start() - 200)
                context = self.source_code[context_start:match.end() + 100]
                if 'hasOwnProperty' in context:
                    continue

                self.findings.append(Finding(
                    file_path=self.file_path,
                    line_number=line_num,
                    column=match.start() - self.source_code.rfind('\n', 0, match.start()),
                    node_type='RegexMatch',
                    vulnerability_name=f"Prototype Pollution via {name}",
                    category=VulnCategory.PROTOTYPE_POLLUTION,
                    severity=severity,
                    confidence='HIGH' if '__proto__' in name or 'constructor' in name else 'MEDIUM',
                    description=f"Potential prototype pollution via {name}",
                    sink=name,
                    code_snippet=line_content,
                    cwe_id="CWE-1321",
                    remediation="Use Object.create(null) or validate keys against __proto__/constructor/prototype"
                ))

    def scan_forin_pollution(self) -> None:
        """Scan for prototype pollution via for-in loops without hasOwnProperty."""
        # Pattern: for (let/var/const key in obj) { ... target[key] = ... }
        forin_pattern = r'for\s*\(\s*(?:let|var|const)?\s*(\w+)\s+in\s+(\w+)'

        for match in re.finditer(forin_pattern, self.source_code):
            loop_var = match.group(1)
            iterated_obj = match.group(2)
            line_num = self.get_line_number(match.start())

            # Get context: the for-in loop and its body (next ~20 lines or until closing brace balance)
            context_start = match.start()
            context_end = min(len(self.source_code), match.end() + 500)
            context = self.source_code[context_start:context_end]

            # Check for hasOwnProperty protection
            if 'hasOwnProperty' in context or 'Object.hasOwn' in context:
                continue

            # Check for Object.keys (safe pattern)
            if 'Object.keys' in context:
                continue

            # Check for explicit __proto__ filtering
            if ("'__proto__'" in context or '"__proto__"' in context) and ('continue' in context or 'return' in context):
                continue

            # Look for assignment pattern: target[loopVar] = ...
            assign_pattern = rf'\w+\s*\[\s*{loop_var}\s*\]\s*='
            if re.search(assign_pattern, context):
                # Check if iterating over suspicious sources
                suspicious_sources = ['req.body', 'req.query', 'req.params', 'request.body',
                                     'request.query', 'body', 'query', 'params', 'input',
                                     'data', 'payload', 'source', 'options', 'config', 'settings']

                is_suspicious = any(src in iterated_obj.lower() or src.replace('.', '') == iterated_obj.lower()
                                   for src in suspicious_sources)

                # Also check the broader context for req.body etc being passed to the function
                broader_context_start = max(0, match.start() - 300)
                broader_context = self.source_code[broader_context_start:context_end]
                if any(src in broader_context for src in ['req.body', 'req.query', 'req.params']):
                    is_suspicious = True

                confidence = 'HIGH' if is_suspicious else 'MEDIUM'

                self.findings.append(Finding(
                    file_path=self.file_path,
                    line_number=line_num,
                    column=match.start() - self.source_code.rfind('\n', 0, match.start()),
                    node_type='RegexMatch',
                    vulnerability_name="Prototype Pollution via for-in loop",
                    category=VulnCategory.PROTOTYPE_POLLUTION,
                    severity=Severity.CRITICAL,
                    confidence=confidence,
                    description=f"for-in loop over '{iterated_obj}' with assignment target[{loop_var}] without hasOwnProperty check",
                    source=iterated_obj,
                    sink=f"target[{loop_var}]",
                    code_snippet=self.get_line_content(line_num),
                    cwe_id="CWE-1321",
                    remediation="Add hasOwnProperty check or use Object.keys() instead of for-in"
                ))

    def scan_express_xss(self) -> None:
        """Scan for Express.js XSS patterns (res.send with user input)."""
        # Express sources
        express_sources = [
            r'req\.query\.\w+',
            r'req\.body\.\w+',
            r'req\.params\.\w+',
            r'req\.query\[',
            r'req\.body\[',
            r'req\.params\[',
        ]

        # Express sinks that output HTML
        sink_patterns = [
            (r'res\.send\s*\(\s*[`\'\"].*<', 'res.send (HTML)'),  # res.send with HTML tags
            (r'res\.send\s*\(\s*`[^`]*\$\{', 'res.send (template literal)'),  # res.send with template literal interpolation
            (r'res\.write\s*\(\s*[`\'\"].*<', 'res.write (HTML)'),
            (r'res\.end\s*\(\s*[`\'\"].*<', 'res.end (HTML)'),
        ]

        for sink_pattern, sink_name in sink_patterns:
            for match in re.finditer(sink_pattern, self.source_code):
                line_num = self.get_line_number(match.start())
                line_content = self.get_line_content(line_num)

                # Check if any Express source is on the same line or nearby
                context_start = max(0, match.start() - 200)
                context_end = min(len(self.source_code), match.end() + 100)
                context = self.source_code[context_start:context_end]

                source_found = None
                for src_pattern in express_sources:
                    if re.search(src_pattern, context):
                        source_match = re.search(src_pattern, context)
                        if source_match:
                            source_found = source_match.group(0)
                            break

                # Check for sanitization
                if any(safe in context.lower() for safe in ['escape', 'sanitize', 'encode', 'purify']):
                    continue

                if source_found:
                    self.findings.append(Finding(
                        file_path=self.file_path,
                        line_number=line_num,
                        column=match.start() - self.source_code.rfind('\n', 0, match.start()),
                        node_type='RegexMatch',
                        vulnerability_name=f"Reflected XSS via {sink_name}",
                        category=VulnCategory.REFLECTED_XSS,
                        severity=Severity.HIGH,
                        confidence='HIGH',
                        description=f"User input from '{source_found}' reflected in HTML response without sanitization",
                        source=source_found,
                        sink=sink_name,
                        code_snippet=line_content,
                        cwe_id="CWE-79",
                        remediation="Escape HTML entities before including in response, or use res.json() for JSON data"
                    ))

    def scan_template_xss(self) -> None:
        """Scan for template-based XSS in HTML."""
        patterns = [
            (r'\{\{\{\s*\w+\s*\}\}\}', 'Handlebars unescaped', Severity.CRITICAL),
            (r'<%-\s*\w+\s*%>', 'EJS unescaped', Severity.CRITICAL),
            (r'href\s*=\s*[\'"]?\s*javascript:', 'javascript: URL', Severity.HIGH),
            (r'on\w+\s*=\s*[\'"][^"\']*\{\{', 'Event handler template', Severity.HIGH),
        ]

        for pattern, name, severity in patterns:
            for match in re.finditer(pattern, self.source_code, re.IGNORECASE):
                line_num = self.get_line_number(match.start())
                line_content = self.get_line_content(line_num)

                self.findings.append(Finding(
                    file_path=self.file_path,
                    line_number=line_num,
                    column=match.start() - self.source_code.rfind('\n', 0, match.start()),
                    node_type='RegexMatch',
                    vulnerability_name=f"Reflected XSS - {name}",
                    category=VulnCategory.REFLECTED_XSS,
                    severity=severity,
                    confidence='HIGH',
                    description=f"Unescaped output pattern '{name}' may allow XSS",
                    code_snippet=line_content,
                    cwe_id="CWE-79",
                    remediation="Use context-appropriate encoding for output"
                ))


# ============================================================================
# Main Scanner Class
# ============================================================================

class JSHunter:
    """Main scanner orchestrating AST and regex analysis."""

    def __init__(self, verbose: bool = False, min_confidence: str = "HIGH"):
        self.verbose = verbose
        self.min_confidence = min_confidence
        self.findings: List[Finding] = []
        self.files_scanned = 0
        self.parse_errors = 0
        self.supported_extensions = {'.js', '.jsx', '.mjs', '.html', '.htm', '.vue', '.svelte'}

    def log(self, msg: str) -> None:
        if self.verbose:
            print(f"[*] {msg}")

    def should_skip_file(self, file_path: str) -> bool:
        """Skip minified, vendor, and build files."""
        skip_patterns = [
            'node_modules', 'vendor', 'dist/', 'build/',
            'bundle.js', 'chunk.', '.bundle.', 'polyfill', '.map'
        ]
        path_lower = file_path.lower()
        return any(p in path_lower for p in skip_patterns)

    def _detect_minified_file(self, content: str, file_path: str) -> bool:
        """
        Detect if file is minified/obfuscated using multiple heuristics.
        Returns True if file appears to be minified.
        """
        if not content:
            return False

        lines = content.split('\n')
        total_lines = len(lines)

        # Heuristic 1: Very few lines with large file size
        if total_lines < 10 and len(content) > 5000:
            return True

        # Heuristic 2: Average line length > 500 characters
        non_empty_lines = [l for l in lines if l.strip()]
        if non_empty_lines:
            avg_line_length = sum(len(l) for l in non_empty_lines) / len(non_empty_lines)
            if avg_line_length > 500:
                return True

        # Heuristic 3: Any single line > 1000 characters (common in minified)
        if any(len(line) > 1000 for line in lines):
            return True

        # Heuristic 4: High density of semicolons with minimal newlines
        sample = content[:5000]
        semicolons = sample.count(';')
        newlines = sample.count('\n')
        if semicolons > 50 and newlines < 20:
            return True

        # Heuristic 5: Filename patterns suggesting minified
        filename = os.path.basename(file_path).lower()
        if '.min.' in filename or '-min.' in filename or filename.endswith('.min.js'):
            return True

        # Heuristic 6: Contains typical minified patterns (obfuscated variable names)
        # Look for high frequency of single-letter variables like: a,b,c,d,e,f,g
        if re.search(r'\b[a-z]\s*=\s*[a-z]\s*\(', sample) and re.search(r'\b[a-z]\s*,\s*[a-z]\s*,\s*[a-z]\b', sample):
            # Multiple single-letter params and assignments
            if re.search(r'function\s*\([a-z](,[a-z]){3,}', sample):
                return True

        return False

    def _display_minified_warning(self, file_path: str) -> None:
        """Display warning banner for minified/obfuscated files."""
        filename = os.path.basename(file_path)
        print("")
        print("  ╔══════════════════════════════════════════════════════════════════════════════╗")
        print("  ║  ⚠️  MINIFIED/OBFUSCATED FILE DETECTED                                        ║")
        print(f"  ║  File: {filename:<69} ║")
        print("  ║                                                                              ║")
        print("  ║  WARNING: Minified files may produce MORE FALSE POSITIVES.                  ║")
        print("  ║  Findings from this file should be reviewed carefully.                      ║")
        print("  ║  Consider scanning the original source files instead.                       ║")
        print("  ╚══════════════════════════════════════════════════════════════════════════════╝")
        print("")

    def read_file(self, file_path: str) -> Optional[str]:
        """Read file with encoding handling."""
        for encoding in ['utf-8', 'latin-1', 'cp1252']:
            try:
                with open(file_path, 'r', encoding=encoding) as f:
                    return f.read()
            except (UnicodeDecodeError, PermissionError):
                continue
        return None

    def confidence_meets_threshold(self, confidence: str) -> bool:
        """Check if finding meets minimum confidence."""
        levels = {'HIGH': 3, 'MEDIUM': 2, 'LOW': 1}
        return levels.get(confidence, 0) >= levels.get(self.min_confidence, 0)

    def esprima_to_dict(self, node) -> dict:
        """Convert esprima's object-based AST to dict format for compatibility."""
        if node is None:
            return None
        if isinstance(node, list):
            return [self.esprima_to_dict(item) for item in node]
        if not hasattr(node, '__dict__'):
            return node

        result = {}
        for key, value in node.__dict__.items():
            if key.startswith('_'):
                continue
            if hasattr(value, '__dict__'):
                result[key] = self.esprima_to_dict(value)
            elif isinstance(value, list):
                result[key] = [self.esprima_to_dict(item) for item in value]
            else:
                result[key] = value
        return result

    def scan_js_file(self, file_path: str, content: str) -> None:
        """Scan a JavaScript file using AST analysis."""
        ast = None
        parser_used = None

        # Try esprima first (ES6+ support)
        if HAS_ESPRIMA:
            try:
                esprima_ast = esprima.parseScript(content, {'loc': True, 'tolerant': True})
                ast = self.esprima_to_dict(esprima_ast)
                parser_used = 'esprima'
                self.log(f"Parsed with esprima (ES6+)")
            except Exception as e:
                self.log(f"Esprima parse error: {e}")

        # Try pyjsparser as fallback (ES5)
        if ast is None and HAS_PYJSPARSER:
            try:
                ast = pyjsparser.parse(content)
                parser_used = 'pyjsparser'
                self.log(f"Parsed with pyjsparser (ES5)")
            except Exception as e:
                self.log(f"Pyjsparser parse error: {e}")

        # Run AST analysis if parsing succeeded
        if ast is not None:
            try:
                visitor = JSASTVisitor(file_path, content, self.verbose)
                findings = visitor.analyze(ast)

                for f in findings:
                    if self.confidence_meets_threshold(f.confidence):
                        self.findings.append(f)

                self.log(f"AST analysis complete ({parser_used}): {len(findings)} findings")
                return

            except Exception as e:
                self.log(f"AST visitor error, falling back to regex: {e}")
                self.parse_errors += 1
        else:
            self.parse_errors += 1

        # Fallback to regex
        self.log(f"Using regex fallback for {file_path}")
        scanner = RegexScanner(file_path, content, self.verbose)
        findings = scanner.scan()

        for f in findings:
            if self.confidence_meets_threshold(f.confidence):
                self.findings.append(f)

    def scan_html_file(self, file_path: str, content: str) -> None:
        """Scan HTML file using regex (and inline scripts with AST if possible)."""
        # Extract inline scripts for AST analysis
        script_pattern = r'<script[^>]*>(.*?)</script>'
        for match in re.finditer(script_pattern, content, re.DOTALL | re.IGNORECASE):
            script_content = match.group(1).strip()
            if script_content and not script_content.startswith('//'):
                # Calculate line offset
                script_start = match.start(1)
                line_offset = content[:script_start].count('\n')

                self.scan_js_file(f"{file_path} (inline script)", script_content)

        # Scan HTML patterns with regex
        scanner = RegexScanner(file_path, content, self.verbose)
        scanner.scan_template_xss()
        scanner.scan_dom_xss()

        for f in scanner.findings:
            if self.confidence_meets_threshold(f.confidence):
                self.findings.append(f)

    def scan_file(self, file_path: str) -> None:
        """Scan a single file."""
        if self.should_skip_file(file_path):
            self.log(f"Skipping: {file_path}")
            return

        content = self.read_file(file_path)
        if not content:
            return

        self.files_scanned += 1
        self.log(f"Scanning: {file_path}")

        # Check for minified/obfuscated file and display warning
        ext = Path(file_path).suffix.lower()
        if ext in {'.js', '.jsx', '.mjs'}:
            if self._detect_minified_file(content, file_path):
                self._display_minified_warning(file_path)

        if ext in {'.js', '.jsx', '.mjs'}:
            self.scan_js_file(file_path, content)
        elif ext in {'.html', '.htm', '.vue', '.svelte'}:
            self.scan_html_file(file_path, content)

    def scan_directory(self, directory: str) -> None:
        """Recursively scan directory."""
        skip_dirs = {'node_modules', '.git', 'vendor', 'dist', 'build', '.next', '__pycache__'}

        for root, dirs, files in os.walk(directory):
            dirs[:] = [d for d in dirs if d not in skip_dirs]

            for file in files:
                file_path = os.path.join(root, file)
                ext = Path(file_path).suffix.lower()

                if ext in self.supported_extensions:
                    self.scan_file(file_path)

    def scan(self, target: str) -> List[Finding]:
        """Main scan entry point."""
        target_path = Path(target)

        if target_path.is_file():
            self.scan_file(str(target_path))
        elif target_path.is_dir():
            self.scan_directory(str(target_path))
        else:
            print(f"Error: {target} does not exist", file=sys.stderr)
            sys.exit(1)

        return self.findings

    def generate_report(self, output_format: str = 'text') -> str:
        """Generate scan report."""
        if output_format == 'json':
            return self.generate_json_report()
        return self.generate_text_report()

    def generate_text_report(self) -> str:
        """Generate human-readable report."""
        lines = []
        lines.append("=" * 70)
        lines.append("JSHunter Scan Report (AST-Based Analysis)")
        lines.append("=" * 70)
        lines.append(f"Scan Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        lines.append(f"Files Scanned: {self.files_scanned}")
        lines.append(f"Parse Errors (regex fallback): {self.parse_errors}")
        lines.append(f"Vulnerabilities Found: {len(self.findings)}")
        lines.append("")

        if not self.findings:
            lines.append("No vulnerabilities found.")
            return '\n'.join(lines)

        # Summary by category
        by_category = defaultdict(list)
        for f in self.findings:
            by_category[f.category.value].append(f)

        lines.append("Summary by Category:")
        lines.append("-" * 40)
        for cat, findings in sorted(by_category.items()):
            lines.append(f"  {cat}: {len(findings)}")
        lines.append("")

        # Summary by severity
        by_severity = defaultdict(int)
        for f in self.findings:
            by_severity[f.severity.value] += 1

        lines.append("Summary by Severity:")
        lines.append("-" * 40)
        for sev in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']:
            if by_severity[sev]:
                lines.append(f"  {sev}: {by_severity[sev]}")
        lines.append("")

        # Detailed findings
        lines.append("=" * 70)
        lines.append("Detailed Findings")
        lines.append("=" * 70)

        for i, f in enumerate(self.findings, 1):
            lines.append("")
            lines.append(f"[{i}] {f.vulnerability_name}")
            lines.append("-" * 50)
            lines.append(f"    File: {f.file_path}:{f.line_number}:{f.column}")
            lines.append(f"    Node Type: {f.node_type}")
            lines.append(f"    Severity: {f.severity.value}")
            lines.append(f"    Confidence: {f.confidence}")
            lines.append(f"    Category: {f.category.value}")
            lines.append(f"    CWE: {f.cwe_id}")
            lines.append(f"    Description: {f.description}")
            if f.source:
                lines.append(f"    Source: {f.source}")
            if f.sink:
                lines.append(f"    Sink: {f.sink}")
            lines.append(f"    Code: {f.code_snippet[:100]}")
            lines.append(f"    Remediation: {f.remediation}")

        return '\n'.join(lines)

    def generate_json_report(self) -> str:
        """Generate JSON report."""
        report = {
            "scan_time": datetime.now().isoformat(),
            "files_scanned": self.files_scanned,
            "parse_errors": self.parse_errors,
            "total_findings": len(self.findings),
            "findings": [
                {
                    "file": f.file_path,
                    "line": f.line_number,
                    "column": f.column,
                    "node_type": f.node_type,
                    "vulnerability": f.vulnerability_name,
                    "category": f.category.value,
                    "severity": f.severity.value,
                    "confidence": f.confidence,
                    "description": f.description,
                    "source": f.source,
                    "sink": f.sink,
                    "code": f.code_snippet,
                    "cwe": f.cwe_id,
                    "remediation": f.remediation
                }
                for f in self.findings
            ]
        }
        return json.dumps(report, indent=2)


def main():
    parser = argparse.ArgumentParser(
        description='JSHunter - AST-Based JavaScript Vulnerability Scanner',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=textwrap.dedent('''
            Examples:
              python3 jshunter.py target.js
              python3 jshunter.py /path/to/project --verbose
              python3 jshunter.py app.js --output json -o report.json
              python3 jshunter.py src/ --min-confidence MEDIUM

            Requirements:
              pip install esprima  # ES6+ support
        ''')
    )

    parser.add_argument('target', help='File or directory to scan')
    parser.add_argument('-v', '--verbose', action='store_true', help='Verbose output')
    parser.add_argument('--output', choices=['text', 'json'], default='text', help='Output format')
    parser.add_argument('-o', '--output-file', help='Save report to file')
    parser.add_argument('--min-confidence', choices=['HIGH', 'MEDIUM', 'LOW'], default='HIGH',
                        help='Minimum confidence level (default: HIGH)')

    args = parser.parse_args()

    print(f"\n[*] JSHunter - AST-Based JavaScript Vulnerability Scanner")
    parser_info = 'esprima (ES6+)' if HAS_ESPRIMA else ('pyjsparser (ES5)' if HAS_PYJSPARSER else 'Regex (fallback)')
    print(f"[*] Parser: {parser_info}")
    print(f"[*] Target: {args.target}")
    print(f"[*] Min Confidence: {args.min_confidence}")
    print()

    scanner = JSHunter(verbose=args.verbose, min_confidence=args.min_confidence)
    scanner.scan(args.target)

    report = scanner.generate_report(args.output)

    if args.output_file:
        with open(args.output_file, 'w') as f:
            f.write(report)
        print(f"[+] Report saved to {args.output_file}")
    else:
        print(report)

    sys.exit(1 if scanner.findings else 0)


if __name__ == '__main__':
    main()
