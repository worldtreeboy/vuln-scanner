#!/usr/bin/env python3
"""
AST-Based Vulnerability Scanner v2.0
=====================================
A multi-language static analysis scanner using taint tracking to reduce false positives.
Provides deeper code analysis through:
- Taint tracking (tracing user input through variables)
- Data flow analysis (following data from sources to sinks)
- Context-aware detection (understands function calls and code structure)
- Confidence scoring (HIGH/MEDIUM/LOW ratings)

Supported Languages:
- Python (.py) - Full AST analysis with taint tracking
- JavaScript/TypeScript (.js, .ts, .jsx, .tsx) - Regex-enhanced with taint tracking
- Java/Kotlin/Scala (.java, .kt, .scala) - Regex-enhanced with taint tracking
- PHP (.php, .phtml) - Regex-enhanced with taint tracking
- C# (.cs) - Regex-enhanced with taint tracking
- Ruby (.rb, .erb) - Regex-enhanced with taint tracking

Vulnerability Categories:
- SQL Injection - String concatenation, dynamic queries, ORM misuse
- NoSQL Injection - MongoDB, Redis injection patterns
- Command Injection - system(), exec(), Runtime.exec(), Process.Start()
- Code Injection - eval(), reflection, dynamic code execution
- Insecure Deserialization - pickle, unserialize(), Marshal, BinaryFormatter
- SSTI - Jinja2, Twig, ERB, Freemarker template injection
- SSRF - Server-side request forgery via HTTP clients
- Path Traversal - File operations with user-controlled paths
- LFI/RFI - Local/Remote file inclusion (PHP)
- XXE - XML External Entity injection
- Authentication Bypass - Hardcoded credentials, weak comparisons
"""

import os
import sys
import ast
import json
import argparse
import re
import warnings
import time
import shutil
import subprocess
from pathlib import Path
from dataclasses import dataclass, field
from typing import List, Dict, Set, Optional, Tuple, Any, Union
from enum import Enum
from datetime import datetime
from collections import defaultdict
import textwrap
import javalang
from vibehunter_config import load_config, VibehunterConfig

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.tree import Tree
from rich.syntax import Syntax
from rich.columns import Columns
from rich.text import Text
from rich.layout import Layout
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, MofNCompleteColumn
from rich.align import Align
from rich.rule import Rule
from rich import box

console = Console()

# Suppress deprecation warnings for ast.Str, ast.Num, etc. (removed in Python 3.14)
warnings.filterwarnings('ignore', category=DeprecationWarning, message='.*ast\\.Str.*')
warnings.filterwarnings('ignore', category=DeprecationWarning, message='.*ast\\.Num.*')
warnings.filterwarnings('ignore', category=DeprecationWarning, message='.*ast\\.Bytes.*')
warnings.filterwarnings('ignore', category=DeprecationWarning, message='.*ast\\.NameConstant.*')
warnings.filterwarnings('ignore', category=DeprecationWarning, message='.*ast\\.Ellipsis.*')


class Severity(Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


class VulnCategory(Enum):
    SQL_INJECTION = "SQL Injection"
    NOSQL_INJECTION = "NoSQL Injection"
    CODE_INJECTION = "Code Injection"
    COMMAND_INJECTION = "Command Injection"
    DESERIALIZATION = "Insecure Deserialization"
    SSTI = "Server-Side Template Injection"
    AUTH_BYPASS = "Authentication Bypass"
    XPATH_INJECTION = "XPath Injection"
    XXE = "XML External Entity"
    LDAP_INJECTION = "LDAP Injection"
    INFO_DISCLOSURE = "Information Disclosure"
    VULNERABLE_DEPENDENCY = "Vulnerable Dependency"


@dataclass
class TaintSource:
    """Represents a source of tainted (user-controlled) data."""
    name: str
    line: int
    col: int
    source_type: str  # 'request', 'input', 'argv', 'env', 'file', etc.


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
    confidence: str  # 'HIGH', 'MEDIUM', 'LOW'
    taint_chain: List[str] = field(default_factory=list)
    description: str = ""

    def to_dict(self) -> dict:
        return {
            "file": self.file_path,
            "line": self.line_number,
            "column": self.col_offset,
            "code": self.line_content.strip(),
            "vulnerability": self.vulnerability_name,
            "category": self.category.value,
            "severity": self.severity.value,
            "confidence": self.confidence,
            "taint_chain": self.taint_chain,
            "description": self.description,
        }


# ============================================================================
# TAINT SOURCES - Variables/patterns that introduce user-controlled data
# ============================================================================

PYTHON_TAINT_SOURCES = {
    # Flask
    'request.args', 'request.form', 'request.json', 'request.data',
    'request.values', 'request.files', 'request.cookies', 'request.headers',
    'request.get_json', 'request.get_data',
    # Django
    'request.GET', 'request.POST', 'request.body', 'request.COOKIES',
    'request.META', 'request.FILES', 'request.data',
    # FastAPI
    'Query', 'Body', 'Form', 'File', 'Header', 'Cookie', 'Path',
    # General
    'input', 'sys.argv', 'os.environ', 'raw_input',
    # Environment - os.environ.get() is a major taint source
    'os.environ.get', 'os.getenv', 'environ.get',
}

# Dangerous modules where dynamic attribute access is suspicious
DANGEROUS_MODULES = {
    'subprocess': {'Popen', 'call', 'run', 'check_output', 'check_call',
                   'getoutput', 'getstatusoutput'},
    'os': {'system', 'popen', 'popen2', 'popen3', 'popen4', 'spawn', 'spawnl',
           'spawnle', 'spawnlp', 'spawnlpe', 'spawnv', 'spawnve', 'spawnvp',
           'spawnvpe', 'exec', 'execl', 'execle', 'execlp', 'execlpe',
           'execv', 'execve', 'execvp', 'execvpe'},
    'builtins': {'eval', 'exec', 'compile', '__import__'},
    'pickle': {'loads', 'load'},
    'marshal': {'loads', 'load'},
    'yaml': {'load', 'unsafe_load', 'full_load'},
}

# Shell execution patterns that indicate command injection
SHELL_PATTERNS = [
    # Unix shells
    '/bin/sh', '/bin/bash', '/bin/zsh', '/bin/ksh', '/bin/csh', '/bin/tcsh',
    '/usr/bin/sh', '/usr/bin/bash', '/usr/bin/zsh', '/usr/bin/env',
    'sh', 'bash', 'zsh', 'ksh',
    # Windows shells
    'cmd.exe', 'cmd', 'powershell.exe', 'powershell', 'pwsh',
]

SHELL_FLAGS = ['-c', '/c', '/k', '-Command', '-EncodedCommand']

PYTHON_TAINT_FUNCTIONS = {
    'input': 'user_input',
    'raw_input': 'user_input',
}

# Dangerous sinks by category
PYTHON_SINKS = {
    VulnCategory.SQL_INJECTION: {
        'execute': ['cursor.execute', 'connection.execute', 'db.execute',
                    'session.execute', 'engine.execute', 'raw', 'executemany',
                    'executescript'],
        'raw_query': ['RawSQL', 'raw', 'extra', 'cursor.executemany'],
    },
    VulnCategory.CODE_INJECTION: {
        'eval': ['eval', 'exec', 'compile', 'execfile'],
        'import': ['__import__', 'importlib.import_module'],
        'getattr': ['getattr', 'setattr', 'delattr'],
    },
    VulnCategory.COMMAND_INJECTION: {
        'os': ['os.system', 'os.popen', 'os.popen2', 'os.popen3', 'os.popen4',
               'os.spawn', 'os.spawnl', 'os.spawnle', 'os.spawnlp', 'os.spawnlpe',
               'os.spawnv', 'os.spawnve', 'os.spawnvp', 'os.spawnvpe',
               'os.exec', 'os.execl', 'os.execle', 'os.execlp', 'os.execlpe',
               'os.execv', 'os.execve', 'os.execvp', 'os.execvpe'],
        'subprocess': ['subprocess.call', 'subprocess.run', 'subprocess.Popen',
                       'subprocess.check_output', 'subprocess.check_call',
                       'subprocess.getoutput', 'subprocess.getstatusoutput'],
        'commands': ['commands.getoutput', 'commands.getstatusoutput'],
    },
    VulnCategory.DESERIALIZATION: {
        'pickle': ['pickle.loads', 'pickle.load', 'cPickle.loads', 'cPickle.load',
                   '_pickle.loads', '_pickle.load'],
        'yaml': ['yaml.load', 'yaml.unsafe_load', 'yaml.full_load',
                 'yaml.load_all', 'yaml.unsafe_load_all'],
        'marshal': ['marshal.loads', 'marshal.load'],
        'shelve': ['shelve.open'],
    },
    VulnCategory.SSTI: {
        'jinja2': ['Template', 'Environment.from_string', 'from_string'],
        'mako': ['Template', 'mako.template.Template'],
        'django': ['Template'],
    },
    VulnCategory.XPATH_INJECTION: {
        'xpath': ['xpath', 'find', 'findall', 'findtext', 'iterfind'],
        'lxml': ['lxml.etree.XPath', 'etree.xpath'],
    },
    VulnCategory.XXE: {
        'xml': ['xml.etree.ElementTree.parse', 'xml.etree.ElementTree.fromstring',
                'xml.dom.minidom.parse', 'xml.dom.minidom.parseString',
                'xml.sax.parse', 'xml.sax.parseString',
                'lxml.etree.parse', 'lxml.etree.fromstring'],
    },
}


class PythonTaintTracker(ast.NodeVisitor):
    """
    AST visitor that tracks taint propagation through Python code.
    Implements basic dataflow analysis to trace user input to dangerous sinks.
    """

    def __init__(self, source_code: str, file_path: str):
        self.source_code = source_code
        self.source_lines = source_code.splitlines()
        self.file_path = file_path
        self.findings: List[Finding] = []

        # Taint tracking
        self.tainted_vars: Dict[str, TaintSource] = {}
        self.taint_propagation: Dict[str, List[str]] = defaultdict(list)

        # Import tracking
        self.imports: Dict[str, str] = {}  # alias -> full module name
        self.from_imports: Dict[str, str] = {}  # name -> module

        # Function definitions for interprocedural analysis
        self.function_params: Dict[str, List[str]] = {}
        self.function_returns_tainted: Set[str] = set()

        # Context tracking
        self.current_function: Optional[str] = None
        self.in_try_block = False
        self.shell_param_seen = False

        # Track variables containing shell execution patterns
        # Maps var_name -> (shell_name, has_tainted_cmd, taint_source, line)
        self.shell_pattern_vars: Dict[str, Tuple[str, bool, Optional[TaintSource], int]] = {}

        # CONSTANT FOLDING: Resolve obfuscated strings at analysis time
        # Maps var_name -> resolved string value (e.g., 'self.trigger' -> 'system')
        self.resolved_constants: Dict[str, str] = {}

        # VIRTUAL SINKS: Track variables that resolve to dangerous functions
        # Maps var_name -> (module, func_name, line) e.g., 'executor' -> ('os', 'system', 16)
        self.virtual_sinks: Dict[str, Tuple[str, str, int]] = {}

        # Dangerous functions that can be loaded via getattr
        self.dangerous_funcs = {
            'os': {'system', 'popen', 'popen2', 'popen3', 'popen4', 'spawn', 'spawnl',
                   'spawnle', 'spawnlp', 'spawnlpe', 'spawnv', 'spawnve', 'spawnvp',
                   'spawnvpe', 'exec', 'execl', 'execle', 'execlp', 'execlpe',
                   'execv', 'execve', 'execvp', 'execvpe', 'startfile'},
            'subprocess': {'call', 'run', 'Popen', 'check_output', 'check_call',
                          'getoutput', 'getstatusoutput'},
            'builtins': {'eval', 'exec', 'compile', '__import__'},
            'commands': {'getoutput', 'getstatusoutput'},
        }

        # Track dynamically imported modules: var_name -> True (indicates dynamic import)
        self.dynamic_imports: Dict[str, int] = {}  # var -> line number

        # Track variables that hold decoded strings (potential function names)
        self.decoded_vars: Dict[str, int] = {}  # var -> line number

        # Track functions that return virtual sinks
        self.virtual_sink_factories: Dict[str, Tuple[str, int]] = {}  # func_name -> (pattern, line)

        # 2nd-order detection: Track DB-sourced variables (SQLAlchemy/Django ORM)
        self.db_sourced_vars: Dict[str, Tuple[int, str]] = {}  # var -> (line, source description)

    def get_line_content(self, lineno: int) -> str:
        """Get the source line content."""
        if 1 <= lineno <= len(self.source_lines):
            return self.source_lines[lineno - 1]
        return ""

    def get_full_attr_name(self, node: ast.AST) -> Optional[str]:
        """Get the full dotted name from an attribute node."""
        parts = []
        current = node
        while isinstance(current, ast.Attribute):
            parts.append(current.attr)
            current = current.value
        if isinstance(current, ast.Name):
            parts.append(current.id)
            parts.reverse()
            return '.'.join(parts)
        return None

    def try_resolve_constant(self, node: ast.AST) -> Optional[str]:
        """
        CONSTANT FOLDING: Try to resolve an AST node to a constant string value.
        Handles obfuscation patterns like:
        - bytes.fromhex('...').decode()
        - base64.b64decode('...').decode()
        - codecs.decode('...', 'rot13')
        - chr(n) + chr(n) + ...
        - ''.join([chr(x) for x in [...]])
        """
        # Direct string constant
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            return node.value
        if isinstance(node, ast.Str):  # Python < 3.8
            return node.s

        # Variable reference - check resolved_constants
        if isinstance(node, ast.Name):
            if node.id in self.resolved_constants:
                return self.resolved_constants[node.id]

        # Attribute reference (self.xxx) - check resolved_constants
        if isinstance(node, ast.Attribute):
            full_name = self.get_full_attr_name(node)
            if full_name and full_name in self.resolved_constants:
                return self.resolved_constants[full_name]

        # Method call patterns
        if isinstance(node, ast.Call):
            # Pattern: bytes.fromhex('...').decode()
            if isinstance(node.func, ast.Attribute) and node.func.attr == 'decode':
                inner = node.func.value
                if isinstance(inner, ast.Call) and isinstance(inner.func, ast.Attribute):
                    if inner.func.attr == 'fromhex':
                        # bytes.fromhex('hex_string')
                        if inner.args and isinstance(inner.args[0], (ast.Constant, ast.Str)):
                            hex_str = inner.args[0].value if isinstance(inner.args[0], ast.Constant) else inner.args[0].s
                            try:
                                return bytes.fromhex(hex_str).decode()
                            except:
                                pass

            # Pattern: base64.b64decode('...').decode() or just base64.b64decode('...')
            if isinstance(node.func, ast.Attribute):
                func_name = self.get_full_attr_name(node.func)
                if func_name and 'b64decode' in func_name:
                    # Check for chained .decode()
                    if node.func.attr == 'decode':
                        inner = node.func.value
                        if isinstance(inner, ast.Call):
                            inner_func = self.get_full_attr_name(inner.func) if isinstance(inner.func, ast.Attribute) else None
                            if inner_func and 'b64decode' in inner_func and inner.args:
                                b64_arg = inner.args[0]
                                if isinstance(b64_arg, (ast.Constant, ast.Str)):
                                    b64_str = b64_arg.value if isinstance(b64_arg, ast.Constant) else b64_arg.s
                                    try:
                                        import base64
                                        return base64.b64decode(b64_str).decode()
                                    except:
                                        pass
                    # Direct b64decode
                    elif node.func.attr == 'b64decode' and node.args:
                        b64_arg = node.args[0]
                        if isinstance(b64_arg, (ast.Constant, ast.Str)):
                            b64_str = b64_arg.value if isinstance(b64_arg, ast.Constant) else b64_arg.s
                            try:
                                import base64
                                return base64.b64decode(b64_str).decode()
                            except:
                                pass

            # Pattern: codecs.decode('...', 'rot13')
            if isinstance(node.func, ast.Attribute) and node.func.attr == 'decode':
                func_name = self.get_full_attr_name(node.func)
                if func_name == 'codecs.decode' and len(node.args) >= 2:
                    str_arg = node.args[0]
                    enc_arg = node.args[1]
                    if isinstance(str_arg, (ast.Constant, ast.Str)) and isinstance(enc_arg, (ast.Constant, ast.Str)):
                        s = str_arg.value if isinstance(str_arg, ast.Constant) else str_arg.s
                        enc = enc_arg.value if isinstance(enc_arg, ast.Constant) else enc_arg.s
                        if 'rot' in enc.lower():
                            try:
                                import codecs
                                return codecs.decode(s, enc)
                            except:
                                pass

            # Pattern: chr(n) - single character
            if isinstance(node.func, ast.Name) and node.func.id == 'chr':
                if node.args and isinstance(node.args[0], (ast.Constant, ast.Num)):
                    num = node.args[0].value if isinstance(node.args[0], ast.Constant) else node.args[0].n
                    if isinstance(num, int):
                        try:
                            return chr(num)
                        except:
                            pass

        # Binary operation (string concatenation)
        if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
            left = self.try_resolve_constant(node.left)
            right = self.try_resolve_constant(node.right)
            if left is not None and right is not None:
                return left + right

        # List/tuple of characters joined
        if isinstance(node, ast.Call):
            if isinstance(node.func, ast.Attribute) and node.func.attr == 'join':
                # ''.join([...])
                if isinstance(node.func.value, (ast.Constant, ast.Str)):
                    joiner = node.func.value.value if isinstance(node.func.value, ast.Constant) else node.func.value.s
                    if node.args and isinstance(node.args[0], (ast.List, ast.Tuple)):
                        chars = []
                        for elt in node.args[0].elts:
                            resolved = self.try_resolve_constant(elt)
                            if resolved is not None:
                                chars.append(resolved)
                            else:
                                return None
                        return joiner.join(chars)

        return None

    def is_tainted(self, node: ast.AST) -> Tuple[bool, Optional[TaintSource]]:
        """Check if an AST node represents tainted data."""
        if isinstance(node, ast.Name):
            if node.id in self.tainted_vars:
                return True, self.tainted_vars[node.id]
            # Check if it's a known taint source function result
            if node.id in PYTHON_TAINT_FUNCTIONS:
                return True, TaintSource(node.id, node.lineno, node.col_offset, 'function')

        elif isinstance(node, ast.Attribute):
            full_name = self.get_full_attr_name(node)
            if full_name:
                # Check direct taint sources
                for source in PYTHON_TAINT_SOURCES:
                    if full_name == source or full_name.endswith('.' + source):
                        return True, TaintSource(full_name, node.lineno, node.col_offset, 'request')
                # Check if base is tainted
                if isinstance(node.value, ast.Name) and node.value.id in self.tainted_vars:
                    return True, self.tainted_vars[node.value.id]

        elif isinstance(node, ast.Call):
            # Check if calling a taint source function
            if isinstance(node.func, ast.Name):
                if node.func.id in PYTHON_TAINT_FUNCTIONS:
                    return True, TaintSource(node.func.id, node.lineno, node.col_offset, 'function')
                if node.func.id == 'input':
                    return True, TaintSource('input()', node.lineno, node.col_offset, 'user_input')
                # os.getenv() as direct call
                if node.func.id == 'getenv':
                    return True, TaintSource('os.getenv()', node.lineno, node.col_offset, 'env')

            # Check for os.environ.get(), os.getenv(), request.args.get(), etc.
            if isinstance(node.func, ast.Attribute):
                full_name = self.get_full_attr_name(node.func)
                if full_name:
                    # os.environ.get() or os.getenv()
                    if full_name in ('os.environ.get', 'environ.get', 'os.getenv'):
                        return True, TaintSource(full_name + '()', node.lineno, node.col_offset, 'env')

                # request.args.get(), request.form.get(), etc.
                if node.func.attr == 'get':
                    base_name = self.get_full_attr_name(node.func.value)
                    if base_name:
                        for source in PYTHON_TAINT_SOURCES:
                            if source in base_name:
                                return True, TaintSource(base_name, node.lineno, node.col_offset, 'request')

            # TAINT PROPAGATION: If any argument is tainted, result is tainted
            # This handles cases like: base64.b64decode(tainted_var), json.loads(data), etc.
            for arg in node.args:
                tainted, source = self.is_tainted(arg)
                if tainted:
                    return True, source
            # Also check keyword arguments
            for kw in node.keywords:
                tainted, source = self.is_tainted(kw.value)
                if tainted:
                    return True, source
            # Check method calls on tainted objects: tainted_obj.method()
            # e.g., base64.b64decode(tainted).decode() - the .decode() call is on tainted data
            if isinstance(node.func, ast.Attribute):
                tainted, source = self.is_tainted(node.func.value)
                if tainted:
                    return True, source

        elif isinstance(node, ast.Subscript):
            # Check request['key'] style access
            if isinstance(node.value, ast.Attribute):
                full_name = self.get_full_attr_name(node.value)
                if full_name:
                    for source in PYTHON_TAINT_SOURCES:
                        if source in full_name:
                            return True, TaintSource(full_name, node.lineno, node.col_offset, 'request')
            # Check if base is tainted
            if isinstance(node.value, ast.Name) and node.value.id in self.tainted_vars:
                return True, self.tainted_vars[node.value.id]

        elif isinstance(node, ast.BinOp):
            # String concatenation or formatting can propagate taint
            left_tainted, left_source = self.is_tainted(node.left)
            right_tainted, right_source = self.is_tainted(node.right)
            if left_tainted:
                return True, left_source
            if right_tainted:
                return True, right_source

        elif isinstance(node, ast.JoinedStr):
            # f-strings
            for value in node.values:
                if isinstance(value, ast.FormattedValue):
                    tainted, source = self.is_tainted(value.value)
                    if tainted:
                        return True, source

        elif isinstance(node, ast.List) or isinstance(node, ast.Tuple):
            for elt in node.elts:
                tainted, source = self.is_tainted(elt)
                if tainted:
                    return True, source

        return False, None

    def add_finding(self, node: ast.AST, vuln_name: str, category: VulnCategory,
                    severity: Severity, confidence: str, taint_source: Optional[TaintSource] = None,
                    description: str = ""):
        """Add a vulnerability finding."""
        line_content = self.get_line_content(node.lineno)
        taint_chain = []
        if taint_source:
            taint_chain = [f"{taint_source.source_type}: {taint_source.name} (line {taint_source.line})"]

        finding = Finding(
            file_path=self.file_path,
            line_number=node.lineno,
            col_offset=getattr(node, 'col_offset', 0),
            line_content=line_content,
            vulnerability_name=vuln_name,
            category=category,
            severity=severity,
            confidence=confidence,
            taint_chain=taint_chain,
            description=description,
        )
        self.findings.append(finding)

    def visit_Import(self, node: ast.Import):
        """Track imports."""
        for alias in node.names:
            name = alias.asname if alias.asname else alias.name
            self.imports[name] = alias.name
        self.generic_visit(node)

    def visit_ImportFrom(self, node: ast.ImportFrom):
        """Track from imports."""
        module = node.module or ''
        for alias in node.names:
            name = alias.asname if alias.asname else alias.name
            self.from_imports[name] = f"{module}.{alias.name}"
        self.generic_visit(node)

    def visit_Assign(self, node: ast.Assign):
        """Track variable assignments for taint propagation, shell patterns, and constant folding."""
        # CONSTANT FOLDING: Try to resolve the value to a constant string
        resolved_value = self.try_resolve_constant(node.value)
        if resolved_value is not None:
            for target in node.targets:
                if isinstance(target, ast.Name):
                    self.resolved_constants[target.id] = resolved_value
                elif isinstance(target, ast.Attribute):
                    full_name = self.get_full_attr_name(target)
                    if full_name:
                        self.resolved_constants[full_name] = resolved_value

        # VIRTUAL SINK DETECTION: Check for getattr(module, func_name) patterns
        self._check_virtual_sink_creation(node)

        # Check if right side is tainted
        tainted, source = self.is_tainted(node.value)

        if tainted and source:
            # Propagate taint to all assigned targets
            for target in node.targets:
                if isinstance(target, ast.Name):
                    self.tainted_vars[target.id] = source
                    self.taint_propagation[target.id].append(source.name)
                elif isinstance(target, ast.Tuple) or isinstance(target, ast.List):
                    # Handle tuple unpacking
                    for elt in target.elts:
                        if isinstance(elt, ast.Name):
                            self.tainted_vars[elt.id] = source

        # Track shell execution patterns: args = ["/bin/sh", "-c", cmd]
        if isinstance(node.value, (ast.List, ast.Tuple)):
            shell_detected, shell_name, cmd_tainted, taint_source = self._check_shell_execution_pattern(node.value)
            if shell_detected:
                for target in node.targets:
                    if isinstance(target, ast.Name):
                        self.shell_pattern_vars[target.id] = (shell_name, cmd_tainted, taint_source, node.lineno)

        self.generic_visit(node)

    def _check_virtual_sink_creation(self, node: ast.Assign):
        """
        Detect when a variable is assigned a dangerous function via getattr.
        e.g., executor = getattr(os, 'system') -> executor becomes a virtual sink
        Also tracks __import__() and decode() patterns for interprocedural analysis.
        """
        if not isinstance(node.value, ast.Call):
            return

        call = node.value

        # Check if calling a virtual sink factory: sink_ptr = bridge_factory(...)
        if isinstance(call.func, ast.Name) and call.func.id in self.virtual_sink_factories:
            factory_name = call.func.id
            pattern, line = self.virtual_sink_factories[factory_name]
            for target in node.targets:
                if isinstance(target, ast.Name):
                    self.virtual_sinks[target.id] = ("<factory>", factory_name, node.lineno)
                    self.add_finding(
                        node,
                        f"Virtual Sink Created - Call to sink factory '{factory_name}'",
                        VulnCategory.CODE_INJECTION, Severity.HIGH, "HIGH",
                        description=f"Variable '{target.id}' receives result from virtual sink factory "
                                   f"'{factory_name}()'. This variable is now a potential RCE vector."
                    )

        # Track __import__() assignments: mod = __import__(module_name)
        if isinstance(call.func, ast.Name) and call.func.id == '__import__':
            for target in node.targets:
                if isinstance(target, ast.Name):
                    self.dynamic_imports[target.id] = node.lineno

        # Track decode() assignments from hex/base64: func_name = bytes.fromhex(...).decode()
        if isinstance(call.func, ast.Attribute) and call.func.attr == 'decode':
            inner = call.func.value
            if isinstance(inner, ast.Call) and isinstance(inner.func, ast.Attribute):
                if inner.func.attr in ('fromhex', 'b64decode'):
                    for target in node.targets:
                        if isinstance(target, ast.Name):
                            self.decoded_vars[target.id] = node.lineno

        # Check for getattr(module, func_name)
        if isinstance(call.func, ast.Name) and call.func.id == 'getattr':
            if len(call.args) >= 2:
                module_arg = call.args[0]
                func_arg = call.args[1]

                # Get module name - check if it's a dynamic import
                module_name = None
                is_dynamic_module = False
                if isinstance(module_arg, ast.Name):
                    if module_arg.id in self.dynamic_imports:
                        is_dynamic_module = True
                        module_name = f"<dynamic:{module_arg.id}>"
                    else:
                        module_name = module_arg.id
                elif isinstance(module_arg, ast.Attribute):
                    module_name = self.get_full_attr_name(module_arg)

                # Try to resolve the function name
                func_name = self.try_resolve_constant(func_arg)

                # Check if func_arg is a decoded variable (potential sink name)
                func_is_decoded = False
                if isinstance(func_arg, ast.Name) and func_arg.id in self.decoded_vars:
                    func_is_decoded = True

                # Case 1: Both module and func are known - precise detection
                if module_name and func_name:
                    is_dangerous = False
                    for mod, funcs in self.dangerous_funcs.items():
                        if mod in module_name or module_name == mod:
                            if func_name in funcs:
                                is_dangerous = True
                                break

                    if is_dangerous:
                        for target in node.targets:
                            if isinstance(target, ast.Name):
                                self.virtual_sinks[target.id] = (module_name, func_name, node.lineno)
                                self.add_finding(
                                    node,
                                    f"Code Evasion - Dynamic function resolution: {module_name}.{func_name}",
                                    VulnCategory.CODE_INJECTION, Severity.HIGH, "HIGH",
                                    description=f"getattr() resolves to dangerous function {module_name}.{func_name}(). "
                                               f"Variable '{target.id}' is now a virtual sink."
                                )

                # Case 2: Dynamic module + decoded function name - high suspicion
                elif is_dynamic_module and func_is_decoded:
                    for target in node.targets:
                        if isinstance(target, ast.Name):
                            # Mark as virtual sink with unknown function
                            self.virtual_sinks[target.id] = ("<dynamic>", "<decoded>", node.lineno)
                            self.add_finding(
                                node,
                                "Critical Evasion - Dynamic module + decoded function name",
                                VulnCategory.CODE_INJECTION, Severity.CRITICAL, "HIGH",
                                description=f"getattr() on dynamically imported module with decoded function name. "
                                           f"Variable '{target.id}' is a potential RCE sink. "
                                           f"Pattern: __import__() + bytes.fromhex/b64decode + getattr()"
                            )

                # Case 3: Known dangerous module + decoded function name
                elif module_name and func_is_decoded:
                    for mod in self.dangerous_funcs.keys():
                        if mod in module_name or module_name == mod:
                            for target in node.targets:
                                if isinstance(target, ast.Name):
                                    self.virtual_sinks[target.id] = (module_name, "<decoded>", node.lineno)
                                    self.add_finding(
                                        node,
                                        f"Code Evasion - getattr({module_name}, <decoded>) potential RCE",
                                        VulnCategory.CODE_INJECTION, Severity.HIGH, "HIGH",
                                        description=f"getattr() on {module_name} with decoded function name. "
                                                   f"Variable '{target.id}' may be a dangerous function."
                                    )
                            break

    def visit_FunctionDef(self, node: ast.FunctionDef):
        """Track function definitions."""
        old_function = self.current_function
        self.current_function = node.name

        # === CRITICAL: Detect Flask/FastAPI route decorators ===
        # Parameters of route-decorated functions come from URL and are tainted
        # EXCEPT: integer-typed parameters (<int:id>) can't contain path traversal
        is_route_handler = False
        route_string = ""
        for decorator in node.decorator_list:
            decorator_str = ast.dump(decorator)
            # Flask: @app.route(), @blueprint.route()
            # FastAPI: @app.get(), @app.post(), @router.get()
            if any(pattern in decorator_str for pattern in [
                '.route', '.get', '.post', '.put', '.delete', '.patch',
                'route(', 'api_view', 'endpoint'
            ]):
                is_route_handler = True
                # Try to extract the route string to check for type converters
                route_match = re.search(r"['\"]([^'\"]+)['\"]", decorator_str)
                if route_match:
                    route_string = route_match.group(1)
                break

        # Track parameters and mark potentially tainted ones
        params = []
        taint_param_keywords = {'input', 'data', 'user', 'request', 'query', 'cmd', 'command',
                                'param', 'arg', 'payload', 'body', 'content', 'raw', 'untrusted',
                                # Add more web-related keywords
                                'file', 'path', 'name', 'url', 'uri', 'key', 'token',
                                'filename', 'filepath', 'dirname', 'logfile', 'svr', 'server',
                                'host', 'endpoint', 'target', 'dest',
                                'source', 'src', 'callback', 'redirect', 'next', 'return_url'}
        for arg in node.args.args:
            params.append(arg.arg)
            arg_lower = arg.arg.lower()

            # If this is a route handler, check if parameter is type-constrained
            if is_route_handler and arg.arg not in ('self', 'cls'):
                # Check if this parameter has an integer type converter in the route
                # Flask: <int:id>, <int:port>, etc. - these CANNOT contain path traversal
                int_pattern = rf'<int:{re.escape(arg.arg)}>'
                float_pattern = rf'<float:{re.escape(arg.arg)}>'
                if re.search(int_pattern, route_string) or re.search(float_pattern, route_string):
                    # Integer/float parameters are safe - skip tainting
                    pass
                else:
                    # String parameters from URL are tainted
                    self.tainted_vars[arg.arg] = TaintSource(
                        arg.arg, node.lineno, node.col_offset, 'flask_route_parameter'
                    )
            # Otherwise, mark parameters with suspicious names as tainted
            elif any(kw in arg_lower for kw in taint_param_keywords):
                self.tainted_vars[arg.arg] = TaintSource(
                    arg.arg, node.lineno, node.col_offset, 'parameter'
                )
        self.function_params[node.name] = params

        self.generic_visit(node)
        self.current_function = old_function

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef):
        """Track async function definitions."""
        self.visit_FunctionDef(node)  # Same handling

    def visit_Return(self, node: ast.Return):
        """Track return statements for virtual sink factories."""
        if node.value and isinstance(node.value, ast.Call):
            call = node.value
            # Check for: return getattr(dynamic_module, decoded_func)
            if isinstance(call.func, ast.Name) and call.func.id == 'getattr':
                if len(call.args) >= 2:
                    module_arg = call.args[0]
                    func_arg = call.args[1]

                    # Check if module is dynamically imported
                    is_dynamic_module = False
                    module_name = None
                    if isinstance(module_arg, ast.Name):
                        if module_arg.id in self.dynamic_imports:
                            is_dynamic_module = True
                        module_name = module_arg.id

                    # Check if func is from decode
                    func_is_decoded = False
                    if isinstance(func_arg, ast.Name) and func_arg.id in self.decoded_vars:
                        func_is_decoded = True

                    # Detect the dangerous pattern
                    if is_dynamic_module and func_is_decoded:
                        # Mark the current function as a virtual sink factory
                        if self.current_function:
                            self.virtual_sink_factories[self.current_function] = ("dynamic_getattr", node.lineno)
                        self.add_finding(
                            node,
                            "Critical Evasion - Function returns dynamic getattr()",
                            VulnCategory.CODE_INJECTION, Severity.CRITICAL, "HIGH",
                            description=f"Function '{self.current_function}' returns getattr() on dynamically "
                                       f"imported module with decoded function name. "
                                       f"Any call to this function returns a potential RCE sink."
                        )

        self.generic_visit(node)

    def visit_Call(self, node: ast.Call):
        """Analyze function calls for dangerous sinks."""
        func_name = None
        full_func_name = None

        # Get function name
        if isinstance(node.func, ast.Name):
            func_name = node.func.id
            # Resolve imports
            if func_name in self.from_imports:
                full_func_name = self.from_imports[func_name]
            else:
                full_func_name = func_name
        elif isinstance(node.func, ast.Attribute):
            full_func_name = self.get_full_attr_name(node.func)
            if full_func_name:
                func_name = full_func_name.split('.')[-1]

        # VIRTUAL SINK DETECTION: Check if calling a virtual sink with tainted data
        if isinstance(node.func, ast.Name) and node.func.id in self.virtual_sinks:
            module_name, resolved_func, def_line = self.virtual_sinks[node.func.id]
            if node.args:
                tainted, source = self.is_tainted(node.args[0])
                if tainted:
                    self.add_finding(
                        node,
                        f"Remote Code Execution - Resolved dynamic sink {module_name}.{resolved_func}()",
                        VulnCategory.COMMAND_INJECTION, Severity.CRITICAL, "HIGH", source,
                        f"Virtual sink '{node.func.id}' (resolved to {module_name}.{resolved_func} at line {def_line}) "
                        f"called with tainted data. This is equivalent to calling {module_name}.{resolved_func}() directly."
                    )
                else:
                    # Even without taint, flag the call to a virtual sink
                    self.add_finding(
                        node,
                        f"Potential RCE - Virtual sink {module_name}.{resolved_func}() called",
                        VulnCategory.COMMAND_INJECTION, Severity.HIGH, "MEDIUM",
                        description=f"Variable '{node.func.id}' was resolved to {module_name}.{resolved_func}(). "
                                   f"Verify the argument is not user-controlled."
                    )

        if full_func_name:
            self._check_dangerous_call(node, func_name, full_func_name)

        # Check ANY call for shell execution patterns in arguments
        # This catches cases like: runner(["/bin/sh", "-c", cmd]) where runner is a variable
        self._check_generic_shell_pattern(node, func_name)

        self.generic_visit(node)

    def _check_generic_shell_pattern(self, node: ast.Call, func_name: Optional[str]):
        """Check any function call for shell execution patterns in arguments."""
        if not node.args:
            return

        first_arg = node.args[0]

        # First check if the argument is a literal list/tuple with shell pattern
        shell_pattern_detected, shell_name, cmd_tainted, cmd_source = self._check_shell_execution_pattern(first_arg)

        # If not found, check if it's a variable that holds a shell pattern
        if not shell_pattern_detected and isinstance(first_arg, ast.Name):
            var_name = first_arg.id
            if var_name in self.shell_pattern_vars:
                shell_name, cmd_tainted, cmd_source, _ = self.shell_pattern_vars[var_name]
                shell_pattern_detected = True

        if shell_pattern_detected:
            # Avoid duplicate if already caught by subprocess detection
            if func_name and func_name in ('Popen', 'call', 'run', 'check_output', 'check_call'):
                return

            if cmd_tainted:
                self.add_finding(
                    node, f"Command Injection - Shell execution via dynamic call",
                    VulnCategory.COMMAND_INJECTION, Severity.CRITICAL, "HIGH", cmd_source,
                    f"Dynamic call with [{shell_name}, '-c', <tainted>] executes user-controlled commands."
                )
            else:
                self.add_finding(
                    node, f"Command Injection - Shell execution pattern in call",
                    VulnCategory.COMMAND_INJECTION, Severity.HIGH, "HIGH",
                    description=f"Call with [{shell_name}, '-c', cmd] pattern detected - potential command execution."
                )

    def _check_dangerous_call(self, node: ast.Call, func_name: str, full_func_name: str):
        """Check if a function call is a dangerous sink with tainted input."""

        # ===== DYNAMIC ATTRIBUTE ACCESS ON DANGEROUS MODULES =====
        # Detects: getattr(subprocess, "Popen"), getattr(os, "system"), etc.
        if func_name == 'getattr' and len(node.args) >= 2:
            module_arg = node.args[0]
            attr_arg = node.args[1]

            # Get the module name
            module_name = None
            if isinstance(module_arg, ast.Name):
                module_name = module_arg.id
            elif isinstance(module_arg, ast.Attribute):
                module_name = self.get_full_attr_name(module_arg)

            # Get the attribute name (could be string literal or variable)
            attr_name = None
            attr_is_tainted = False
            if isinstance(attr_arg, ast.Constant) and isinstance(attr_arg.value, str):
                attr_name = attr_arg.value
            elif isinstance(attr_arg, ast.Str):  # Python < 3.8
                attr_name = attr_arg.s
            else:
                # Attribute name is dynamic/variable - check if tainted
                attr_is_tainted, taint_source = self.is_tainted(attr_arg)

            # Check if this is accessing a dangerous function on a dangerous module
            if module_name in DANGEROUS_MODULES:
                dangerous_funcs = DANGEROUS_MODULES[module_name]
                if attr_name and attr_name in dangerous_funcs:
                    self.add_finding(
                        node, f"Command/Code Injection - getattr({module_name}, '{attr_name}')",
                        VulnCategory.COMMAND_INJECTION if module_name in ('subprocess', 'os') else VulnCategory.CODE_INJECTION,
                        Severity.HIGH, "HIGH",
                        description=f"Dynamic access to dangerous function {module_name}.{attr_name} via getattr() - evasion technique."
                    )
                elif attr_is_tainted:
                    self.add_finding(
                        node, f"Command/Code Injection - getattr({module_name}, <tainted>)",
                        VulnCategory.COMMAND_INJECTION if module_name in ('subprocess', 'os') else VulnCategory.CODE_INJECTION,
                        Severity.CRITICAL, "HIGH", taint_source,
                        description=f"User-controlled attribute name on {module_name} module - can access any function."
                    )
                elif not attr_name:
                    # Dynamic but not confirmed tainted - still suspicious
                    self.add_finding(
                        node, f"Potential Evasion - getattr({module_name}, <dynamic>)",
                        VulnCategory.COMMAND_INJECTION if module_name in ('subprocess', 'os') else VulnCategory.CODE_INJECTION,
                        Severity.MEDIUM, "MEDIUM",
                        description=f"Dynamic attribute access on {module_name} module. Verify attribute name source."
                    )

        # ===== CODE INJECTION =====
        # Exclude re.compile() - it's regex compilation, not code compilation
        if func_name in ('eval', 'exec', 'compile') and full_func_name != 're.compile':
            if node.args:
                tainted, source = self.is_tainted(node.args[0])
                if tainted:
                    self.add_finding(
                        node, f"Code Injection - {func_name}() with user input",
                        VulnCategory.CODE_INJECTION, Severity.CRITICAL, "HIGH", source,
                        f"User-controlled data passed to {func_name}() can lead to arbitrary code execution."
                    )
                else:
                    # Still flag eval/exec usage as it's risky
                    self.add_finding(
                        node, f"Code Injection - {func_name}() usage",
                        VulnCategory.CODE_INJECTION, Severity.MEDIUM, "LOW",
                        description=f"Usage of {func_name}() detected. Verify input is not user-controlled."
                    )

        # ===== COMMAND INJECTION =====
        if func_name == 'system' or full_func_name == 'os.system':
            if node.args:
                tainted, source = self.is_tainted(node.args[0])
                if tainted:
                    # === Check for shlex.quote() sanitization ===
                    # If the argument uses shlex.quote(), it's properly escaped
                    arg = node.args[0]
                    is_sanitized = False
                    if isinstance(arg, ast.JoinedStr):  # f-string
                        # Check each formatted value for shlex.quote
                        for value in arg.values:
                            if isinstance(value, ast.FormattedValue) and isinstance(value.value, ast.Call):
                                call = value.value
                                if isinstance(call.func, ast.Attribute) and call.func.attr == 'quote':
                                    if isinstance(call.func.value, ast.Name) and call.func.value.id == 'shlex':
                                        is_sanitized = True
                                        break
                                elif isinstance(call.func, ast.Name) and call.func.id == 'quote':
                                    is_sanitized = True
                                    break
                    if is_sanitized:
                        pass  # Skip - properly sanitized with shlex.quote
                    else:
                        self.add_finding(
                            node, "Command Injection - os.system() with user input",
                            VulnCategory.COMMAND_INJECTION, Severity.CRITICAL, "HIGH", source,
                            "User-controlled data passed to os.system() can lead to command injection."
                        )

        if func_name in ('popen', 'popen2', 'popen3', 'popen4'):
            if node.args:
                tainted, source = self.is_tainted(node.args[0])
                if tainted:
                    self.add_finding(
                        node, f"Command Injection - os.{func_name}() with user input",
                        VulnCategory.COMMAND_INJECTION, Severity.CRITICAL, "HIGH", source,
                        f"User-controlled data passed to os.{func_name}() can lead to command injection."
                    )

        # subprocess with shell=True or shell execution pattern
        if 'subprocess' in full_func_name or func_name in ('call', 'run', 'Popen', 'check_output', 'check_call'):
            shell_true = False
            for keyword in node.keywords:
                if keyword.arg == 'shell':
                    if isinstance(keyword.value, ast.Constant) and keyword.value.value is True:
                        shell_true = True
                    elif isinstance(keyword.value, ast.NameConstant) and keyword.value.value is True:
                        shell_true = True

            if shell_true and node.args:
                tainted, source = self.is_tainted(node.args[0])
                if tainted:
                    self.add_finding(
                        node, "Command Injection - subprocess with shell=True and user input",
                        VulnCategory.COMMAND_INJECTION, Severity.CRITICAL, "HIGH", source,
                        "subprocess called with shell=True and user-controlled data."
                    )
                else:
                    self.add_finding(
                        node, "Command Injection - subprocess with shell=True",
                        VulnCategory.COMMAND_INJECTION, Severity.MEDIUM, "MEDIUM",
                        description="subprocess called with shell=True. Verify input is sanitized."
                    )

            # Check for shell execution pattern: ["/bin/sh", "-c", cmd] or ["cmd.exe", "/c", cmd]
            # This is equivalent to shell=True but evades simple detection
            if node.args and not shell_true:
                first_arg = node.args[0]
                shell_pattern_detected, shell_name, cmd_tainted, cmd_source = self._check_shell_execution_pattern(first_arg)

                # Also check if it's a variable that holds a shell pattern
                if not shell_pattern_detected and isinstance(first_arg, ast.Name):
                    var_name = first_arg.id
                    if var_name in self.shell_pattern_vars:
                        shell_name, cmd_tainted, cmd_source, _ = self.shell_pattern_vars[var_name]
                        shell_pattern_detected = True

                if shell_pattern_detected:
                    if cmd_tainted:
                        self.add_finding(
                            node, f"Command Injection - Shell execution pattern with tainted input",
                            VulnCategory.COMMAND_INJECTION, Severity.CRITICAL, "HIGH", cmd_source,
                            f"subprocess with [{shell_name}, '-c', <tainted>] executes user-controlled commands."
                        )
                    else:
                        self.add_finding(
                            node, f"Command Injection - Shell execution pattern detected",
                            VulnCategory.COMMAND_INJECTION, Severity.HIGH, "HIGH",
                            description=f"subprocess with [{shell_name}, '-c', cmd] is equivalent to shell=True."
                        )

            # === ARGUMENT INJECTION in subprocess (even without shell=True) ===
            # If user input flows into command arguments via f-string/shlex.split,
            # attacker can inject additional arguments (e.g., SSH -o ProxyCommand=)
            if node.args and not shell_true:
                first_arg = node.args[0]
                # Check if argument is a variable that came from shlex.split()
                if isinstance(first_arg, ast.Name):
                    var_name = first_arg.id
                    # Look back in source for f-string command construction pattern
                    line_num = node.lineno
                    context_start = max(0, line_num - 15)
                    context = '\n'.join(self.source_lines[context_start:line_num])

                    # Pattern: cmd_str = f"..." followed by shlex.split(cmd_str)
                    # then subprocess.check_output(result_of_shlex_split)
                    fstring_cmd_pattern = rf'(\w+)\s*=\s*f["\'].*\{{.*\}}.*["\']'
                    shlex_pattern = rf'{re.escape(var_name)}\s*=\s*shlex\.split\s*\(\s*(\w+)\s*\)'

                    fstring_match = re.search(fstring_cmd_pattern, context)
                    shlex_match = re.search(shlex_pattern, context)

                    if fstring_match and shlex_match:
                        fstring_var = fstring_match.group(1)
                        shlex_input_var = shlex_match.group(1)

                        # Check if the f-string variable is what's passed to shlex.split
                        if fstring_var == shlex_input_var:
                            # Check for dangerous command patterns (ssh, curl, wget, etc.)
                            fstring_line = fstring_match.group(0)

                            # SSH is especially dangerous due to -o ProxyCommand
                            if re.search(r'\bssh\b', fstring_line, re.IGNORECASE):
                                self.add_finding(
                                    node, "Command Injection - SSH argument injection via f-string",
                                    VulnCategory.COMMAND_INJECTION, Severity.CRITICAL, "HIGH",
                                    description="SSH command built with f-string interpolation. "
                                               "Attacker can inject '-o ProxyCommand=cmd' to execute arbitrary commands. "
                                               "Even with shlex.split() and no shell=True, SSH interprets injected options."
                                )
                            else:
                                self.add_finding(
                                    node, "Command Injection - Argument injection via f-string",
                                    VulnCategory.COMMAND_INJECTION, Severity.HIGH, "HIGH",
                                    description="Command built with f-string interpolation and passed to subprocess. "
                                               "User input can inject additional arguments even without shell=True."
                                )

        # ===== SQL INJECTION =====
        if func_name in ('execute', 'executemany', 'executescript'):
            if node.args:
                first_arg = node.args[0]
                tainted, source = self.is_tainted(first_arg)

                # Check for string concatenation/formatting in query
                is_dynamic = self._is_dynamic_string(first_arg)

                # Check if using parameterized query with placeholders
                # SQLAlchemy uses :param style, sqlite3/psycopg2 uses ? or %s
                is_parameterized = False
                has_params = len(node.args) >= 2 or any(kw.arg in ('parameters', 'params') for kw in node.keywords)

                # Check if the query string contains placeholders
                query_line = self.get_line_content(node.lineno)
                # Look in context for the query definition
                context_start = max(0, node.lineno - 10)
                context_lines = self.source_lines[context_start:node.lineno]
                context = '\n'.join(context_lines)

                # Check for :param, ?, or %(name)s style placeholders in context
                if has_params and re.search(r':\w+|(?<![%\w])\?(?!\w)|%\(\w+\)s|%s', context):
                    is_parameterized = True

                if tainted and not is_parameterized:
                    self.add_finding(
                        node, "SQL Injection - execute() with tainted query",
                        VulnCategory.SQL_INJECTION, Severity.CRITICAL, "HIGH", source,
                        "User-controlled data used in SQL query without parameterization."
                    )
                elif is_dynamic and not is_parameterized:
                    # Check if using parameterized query (has second argument)
                    if len(node.args) < 2 or self._is_tainted_in_args(node.args[1:]):
                        self.add_finding(
                            node, "SQL Injection - Dynamic query construction",
                            VulnCategory.SQL_INJECTION, Severity.HIGH, "MEDIUM",
                            description="SQL query appears to use string formatting. Use parameterized queries."
                        )

        # Raw SQL methods
        if func_name in ('raw', 'RawSQL', 'extra'):
            if node.args:
                tainted, source = self.is_tainted(node.args[0])
                if tainted:
                    self.add_finding(
                        node, "SQL Injection - Raw SQL with user input",
                        VulnCategory.SQL_INJECTION, Severity.CRITICAL, "HIGH", source,
                        "User-controlled data used in raw SQL query."
                    )

        # ===== DESERIALIZATION =====
        if 'pickle' in full_func_name and func_name in ('load', 'loads'):
            if node.args:
                tainted, source = self.is_tainted(node.args[0])
                if tainted:
                    self.add_finding(
                        node, "Insecure Deserialization - pickle with user input",
                        VulnCategory.DESERIALIZATION, Severity.CRITICAL, "HIGH", source,
                        "Deserializing user-controlled data with pickle can lead to RCE."
                    )
                else:
                    self.add_finding(
                        node, "Insecure Deserialization - pickle usage",
                        VulnCategory.DESERIALIZATION, Severity.HIGH, "MEDIUM",
                        description="pickle.load/loads detected. Ensure data source is trusted."
                    )

        if 'yaml' in full_func_name and func_name in ('load', 'unsafe_load', 'full_load'):
            # Check for SafeLoader
            uses_safe_loader = False
            for keyword in node.keywords:
                if keyword.arg == 'Loader':
                    if isinstance(keyword.value, ast.Attribute):
                        if 'Safe' in self.get_full_attr_name(keyword.value) or '':
                            uses_safe_loader = True
                    elif isinstance(keyword.value, ast.Name):
                        if 'Safe' in keyword.value.id:
                            uses_safe_loader = True

            if not uses_safe_loader:
                if node.args:
                    tainted, source = self.is_tainted(node.args[0])
                    if tainted:
                        self.add_finding(
                            node, "Insecure Deserialization - yaml.load without SafeLoader",
                            VulnCategory.DESERIALIZATION, Severity.CRITICAL, "HIGH", source,
                            "yaml.load with user data without SafeLoader can lead to RCE."
                        )
                    else:
                        self.add_finding(
                            node, "Insecure Deserialization - yaml.load without SafeLoader",
                            VulnCategory.DESERIALIZATION, Severity.HIGH, "MEDIUM",
                            description="yaml.load without SafeLoader. Use yaml.safe_load() instead."
                        )

        if 'marshal' in full_func_name and func_name in ('load', 'loads'):
            if node.args:
                tainted, source = self.is_tainted(node.args[0])
                if tainted:
                    self.add_finding(
                        node, "Insecure Deserialization - marshal with user input",
                        VulnCategory.DESERIALIZATION, Severity.CRITICAL, "HIGH", source,
                        "marshal.load/loads with user data is dangerous."
                    )

        # ===== SSTI =====
        if func_name == 'Template' or 'Template' in full_func_name:
            if node.args:
                tainted, source = self.is_tainted(node.args[0])
                if tainted:
                    self.add_finding(
                        node, "SSTI - Template() with user input",
                        VulnCategory.SSTI, Severity.CRITICAL, "HIGH", source,
                        "User-controlled template string can lead to Server-Side Template Injection."
                    )

        if func_name == 'from_string' or 'from_string' in full_func_name:
            if node.args:
                tainted, source = self.is_tainted(node.args[0])
                if tainted:
                    self.add_finding(
                        node, "SSTI - Environment.from_string() with user input",
                        VulnCategory.SSTI, Severity.CRITICAL, "HIGH", source,
                        "User-controlled template string in Jinja2 from_string()."
                    )

        if func_name == 'render_template_string':
            if node.args:
                tainted, source = self.is_tainted(node.args[0])
                if tainted:
                    self.add_finding(
                        node, "SSTI - render_template_string() with user input",
                        VulnCategory.SSTI, Severity.CRITICAL, "HIGH", source,
                        "Flask render_template_string() with user input enables SSTI."
                    )

        # ===== XPATH INJECTION =====
        if func_name in ('xpath', 'find', 'findall', 'findtext', 'iterfind'):
            if node.args:
                tainted, source = self.is_tainted(node.args[0])
                if tainted:
                    self.add_finding(
                        node, "XPath Injection - xpath() with user input",
                        VulnCategory.XPATH_INJECTION, Severity.HIGH, "HIGH", source,
                        "User-controlled XPath expression can lead to XPath Injection."
                    )
                elif self._is_dynamic_string(node.args[0]):
                    self.add_finding(
                        node, "XPath Injection - Dynamic XPath expression",
                        VulnCategory.XPATH_INJECTION, Severity.MEDIUM, "MEDIUM",
                        description="XPath expression appears to be dynamically constructed."
                    )

        # ===== XXE =====
        xml_parse_funcs = ['parse', 'fromstring', 'parseString', 'iterparse']
        if func_name in xml_parse_funcs:
            if 'xml' in full_func_name or 'etree' in full_func_name or 'minidom' in full_func_name:
                # Check if defusedxml is used (safe)
                if 'defused' not in full_func_name.lower():
                    self.add_finding(
                        node, "XXE - XML parsing without defusedxml",
                        VulnCategory.XXE, Severity.MEDIUM, "MEDIUM",
                        description="XML parsing without defusedxml. Consider using defusedxml to prevent XXE."
                    )

        # ===== AUTHENTICATION BYPASS =====
        # JWT decode without verification
        if func_name == 'decode' and 'jwt' in full_func_name:
            verify_false = False
            for keyword in node.keywords:
                if keyword.arg == 'verify' or keyword.arg == 'options':
                    if isinstance(keyword.value, ast.Constant) and keyword.value.value is False:
                        verify_false = True
                    elif isinstance(keyword.value, ast.Dict):
                        for k, v in zip(keyword.value.keys, keyword.value.values):
                            if isinstance(k, ast.Constant) and 'verify' in str(k.value).lower():
                                if isinstance(v, ast.Constant) and v.value is False:
                                    verify_false = True
            if verify_false:
                self.add_finding(
                    node, "Auth Bypass - JWT decode without verification",
                    VulnCategory.AUTH_BYPASS, Severity.CRITICAL, "HIGH",
                    description="JWT decoded without signature verification (verify=False)."
                )

    def _is_dynamic_string(self, node: ast.AST) -> bool:
        """Check if a node represents a dynamically constructed string."""
        if isinstance(node, ast.BinOp):
            # String concatenation
            if isinstance(node.op, (ast.Add, ast.Mod)):
                return True
        elif isinstance(node, ast.JoinedStr):
            # f-string
            return True
        elif isinstance(node, ast.Call):
            # String formatting methods
            if isinstance(node.func, ast.Attribute):
                if node.func.attr in ('format', 'join', '%'):
                    return True
        return False

    def _is_tainted_in_args(self, args: list) -> bool:
        """Check if any argument is tainted."""
        for arg in args:
            if isinstance(arg, (ast.List, ast.Tuple)):
                for elt in arg.elts:
                    tainted, _ = self.is_tainted(elt)
                    if tainted:
                        return True
            else:
                tainted, _ = self.is_tainted(arg)
                if tainted:
                    return True
        return False

    def _check_shell_execution_pattern(self, node: ast.AST) -> Tuple[bool, str, bool, Optional[TaintSource]]:
        """
        Check for shell execution pattern: ["/bin/sh", "-c", cmd] or ["cmd.exe", "/c", cmd].

        Returns: (pattern_detected, shell_name, cmd_is_tainted, taint_source)
        """
        if not isinstance(node, (ast.List, ast.Tuple)):
            # Only check if it's a variable that was assigned a shell pattern
            # Do NOT return True just because the argument is tainted!
            return False, "", False, None

        elements = node.elts
        if len(elements) < 2:
            return False, "", False, None

        # Get string values from list elements
        def get_str_value(elt):
            if isinstance(elt, ast.Constant) and isinstance(elt.value, str):
                return elt.value
            elif isinstance(elt, ast.Str):  # Python < 3.8
                return elt.s
            return None

        first_val = get_str_value(elements[0])
        second_val = get_str_value(elements[1]) if len(elements) > 1 else None

        # Check for shell patterns
        shell_detected = False
        shell_name = ""

        if first_val:
            # Check if first element is a shell
            for shell in SHELL_PATTERNS:
                if first_val == shell or first_val.endswith('/' + shell):
                    shell_detected = True
                    shell_name = shell
                    break

        if not shell_detected:
            return False, "", False, None

        # Check if second element is a shell flag (-c, /c, etc.)
        has_shell_flag = False
        if second_val:
            for flag in SHELL_FLAGS:
                if second_val == flag:
                    has_shell_flag = True
                    break

        if not has_shell_flag:
            return False, "", False, None

        # Shell execution pattern detected! Check if the command (3rd+ element) is tainted
        cmd_tainted = False
        taint_source = None

        for i in range(2, len(elements)):
            tainted, source = self.is_tainted(elements[i])
            if tainted:
                cmd_tainted = True
                taint_source = source
                break

        return True, shell_name, cmd_tainted, taint_source

    def _get_string_value(self, node: ast.AST) -> Optional[str]:
        """Extract string value from an AST node if it's a string literal."""
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            return node.value
        elif isinstance(node, ast.Str):  # Python < 3.8
            return node.s
        return None



    def _check_evasion_patterns(self):
        """Check for code evasion patterns that bypass standard detection."""
        # Run these checks after the main AST visit
        for i, line in enumerate(self.source_lines, 1):
            stripped = line.strip()
            if stripped.startswith('#'):
                continue

            # 1. Obfuscated string decoding (rot13, base64, hex)
            if re.search(r'codecs\.decode\s*\([^,]+,\s*["\']rot.?13["\']', line):
                self.findings.append(Finding(
                    file_path=self.file_path, line_number=i, col_offset=0,
                    line_content=line, vulnerability_name="Code Evasion - ROT13 string obfuscation",
                    category=VulnCategory.CODE_INJECTION, severity=Severity.HIGH,
                    confidence="HIGH", description="ROT13 encoding used to hide sensitive strings."
                ))

            if re.search(r'base64\.b64decode\s*\(', line) and not re.search(r'#.*base64', line):
                # Check context for dangerous sinks - only flag if flows to sink
                context = '\n'.join(self.source_lines[max(0, i-3):min(len(self.source_lines), i+10)])
                has_dangerous_sink = re.search(
                    r'subprocess|Popen|system|popen|exec|eval|shell|cmd|command|'
                    r'run_command|execute|Process|spawn|/bin/sh|cmd\.exe',
                    context, re.IGNORECASE
                )

                if has_dangerous_sink:
                    self.findings.append(Finding(
                        file_path=self.file_path, line_number=i, col_offset=0,
                        line_content=line, vulnerability_name="Command/Code Evasion - base64 decode flows to sink",
                        category=VulnCategory.COMMAND_INJECTION, severity=Severity.HIGH,
                        confidence="HIGH", description="base64 decoded data flows to dangerous sink - likely evasion."
                    ))
                # Skip flagging base64 decode without dangerous sink - too many false positives

            if re.search(r'bytes\.fromhex\s*\(|\.fromhex\s*\(', line):
                self.findings.append(Finding(
                    file_path=self.file_path, line_number=i, col_offset=0,
                    line_content=line, vulnerability_name="Potential Evasion - hex string decode",
                    category=VulnCategory.CODE_INJECTION, severity=Severity.MEDIUM,
                    confidence="MEDIUM", description="Hex decoding may hide malicious strings."
                ))

            # 2. Dynamic module/attribute resolution
            # Skip if inside a string literal or regex pattern (avoid self-detection)
            if re.search(r'__import__\s*\(', line) and not re.search(r'["\'].*__import__.*["\']', line):
                self.findings.append(Finding(
                    file_path=self.file_path, line_number=i, col_offset=0,
                    line_content=line, vulnerability_name="Code Evasion - Dynamic __import__",
                    category=VulnCategory.CODE_INJECTION, severity=Severity.HIGH,
                    confidence="HIGH", description="Dynamic import enables module loading to evade detection."
                ))

            if re.search(r'getattr\s*\([^,]+,\s*[^)]*\)', line):
                # Check if the attribute name is obfuscated
                context = '\n'.join(self.source_lines[max(0, i-3):i+1])
                if re.search(r'getattr.*(?:decode|b64|fromhex|r13)', context, re.IGNORECASE):
                    self.findings.append(Finding(
                        file_path=self.file_path, line_number=i, col_offset=0,
                        line_content=line, vulnerability_name="Code Evasion - getattr with obfuscated name",
                        category=VulnCategory.CODE_INJECTION, severity=Severity.HIGH,
                        confidence="HIGH", description="getattr() with decoded/obfuscated attribute name."
                    ))
                # Enhanced: Check if second argument is a tainted/user-controlled variable
                getattr_match = re.search(r'getattr\s*\(\s*(\w+)\s*,\s*(\w+)\s*\)', line)
                if getattr_match:
                    target_obj = getattr_match.group(1)
                    attr_var = getattr_match.group(2)

                    # Check for allowlist patterns BEFORE the getattr call
                    # Look back up to 10 lines for validation like: if attr_var in ['safe', 'list']
                    context = '\n'.join(self.source_lines[max(0, i-10):i])
                    allowlist_patterns = [
                        rf'if\s+{re.escape(attr_var)}\s+in\s+\[',      # if var in [...]
                        rf'if\s+{re.escape(attr_var)}\s+in\s+\{{',     # if var in {...}
                        rf'if\s+{re.escape(attr_var)}\s+in\s+\(',      # if var in (...)
                        rf'if\s+{re.escape(attr_var)}\s+in\s+\w+',     # if var in ALLOWED
                        rf'{re.escape(attr_var)}\s+not\s+in',          # if var not in ...
                    ]
                    has_allowlist = any(re.search(p, context) for p in allowlist_patterns)

                    # Skip if allowlist validation is present
                    if has_allowlist:
                        continue

                    # Check if the target is a safe module (like math, string, json)
                    safe_modules = {'math', 'string', 'json', 'datetime', 'collections', 'itertools', 'functools', 'operator', 're', 'logging', 'logger'}
                    if target_obj in safe_modules:
                        continue

                    # Check if the variable is in tainted_vars
                    if attr_var in self.tainted_vars:
                        self.findings.append(Finding(
                            file_path=self.file_path, line_number=i, col_offset=0,
                            line_content=line, vulnerability_name="Code Evasion - getattr with tainted attribute name",
                            category=VulnCategory.CODE_INJECTION, severity=Severity.CRITICAL,
                            confidence="HIGH", description=f"getattr() with user-controlled attribute name '{attr_var}'. Attacker can access arbitrary attributes/methods."
                        ))
                    else:
                        # Check context for user input flowing to the variable
                        context = '\n'.join(self.source_lines[max(0, i-10):i])
                        user_input_patterns = [
                            rf'{attr_var}\s*=\s*\w+\.get\s*\(',  # var = dict.get("key")
                            rf'{attr_var}\s*=\s*request\.',       # var = request.xxx
                            rf'{attr_var}\s*=\s*input\s*\(',      # var = input()
                            rf'{attr_var}\s*=\s*\w+\[',           # var = dict["key"]
                        ]
                        for pattern in user_input_patterns:
                            if re.search(pattern, context):
                                self.findings.append(Finding(
                                    file_path=self.file_path, line_number=i, col_offset=0,
                                    line_content=line, vulnerability_name="Code Evasion - getattr with user-derived attribute",
                                    category=VulnCategory.CODE_INJECTION, severity=Severity.HIGH,
                                    confidence="HIGH", description=f"getattr() with '{attr_var}' which appears to be user-derived. Dynamic attribute resolution enables arbitrary method access."
                                ))
                                break

            # 3. Metaclass abuse for code execution
            if re.search(r'metaclass\s*=', line) or re.search(r'class\s+\w+Meta\s*\(\s*type\s*\)', line):
                # Check for __call__ or __new__ that might execute code
                context = '\n'.join(self.source_lines[i-1:min(len(self.source_lines), i+20)])
                if re.search(r'def\s+__call__.*eval|exec|__import__|getattr', context, re.DOTALL):
                    self.findings.append(Finding(
                        file_path=self.file_path, line_number=i, col_offset=0,
                        line_content=line, vulnerability_name="Code Injection - Metaclass __call__ execution",
                        category=VulnCategory.CODE_INJECTION, severity=Severity.CRITICAL,
                        confidence="HIGH", description="Metaclass __call__ may execute arbitrary code."
                    ))

            # 4. Descriptor protocol abuse
            if re.search(r'def\s+__get__\s*\(', line):
                context = '\n'.join(self.source_lines[i-1:min(len(self.source_lines), i+15)])
                if re.search(r'eval|exec|compile|__import__', context):
                    self.findings.append(Finding(
                        file_path=self.file_path, line_number=i, col_offset=0,
                        line_content=line, vulnerability_name="Code Injection - Descriptor __get__ execution",
                        category=VulnCategory.CODE_INJECTION, severity=Severity.CRITICAL,
                        confidence="HIGH", description="Descriptor __get__ contains code execution."
                    ))

            # 5. functools.reduce for SQL building
            if re.search(r'functools\.reduce\s*\(|reduce\s*\(', line):
                context = '\n'.join(self.source_lines[max(0, i-5):i+3])
                if re.search(r'SELECT|INSERT|UPDATE|DELETE|FROM|WHERE', context, re.IGNORECASE):
                    self.findings.append(Finding(
                        file_path=self.file_path, line_number=i, col_offset=0,
                        line_content=line, vulnerability_name="SQL Injection - functools.reduce query builder",
                        category=VulnCategory.SQL_INJECTION, severity=Severity.HIGH,
                        confidence="HIGH", description="SQL query built via reduce() - evasion technique."
                    ))

            # 6. Generator/yield for SQL building
            if re.search(r'yield\s+query|yield\s+sql', line, re.IGNORECASE):
                self.findings.append(Finding(
                    file_path=self.file_path, line_number=i, col_offset=0,
                    line_content=line, vulnerability_name="SQL Injection - Generator-based query builder",
                    category=VulnCategory.SQL_INJECTION, severity=Severity.HIGH,
                    confidence="MEDIUM", description="SQL query built via generator - evasion technique."
                ))

            # 7. Context manager hiding subprocess
            # Skip if this is a regex pattern definition (avoid self-detection)
            if re.search(r'@contextmanager', line) and not re.search(r're\.(search|match|compile|findall)', line):
                context = '\n'.join(self.source_lines[i-1:min(len(self.source_lines), i+15)])
                if re.search(r'subprocess|Popen|os\.system|shell', context, re.IGNORECASE):
                    self.findings.append(Finding(
                        file_path=self.file_path, line_number=i, col_offset=0,
                        line_content=line, vulnerability_name="Command Injection - Hidden in context manager",
                        category=VulnCategory.COMMAND_INJECTION, severity=Severity.HIGH,
                        confidence="HIGH", description="Command execution hidden in context manager."
                    ))

            # 8. __getattr__ proxy for command building
            if re.search(r'def\s+__getattr__\s*\(', line):
                context = '\n'.join(self.source_lines[i-1:min(len(self.source_lines), i+15)])
                if re.search(r'subprocess|system|popen|shell|command|cmd', context, re.IGNORECASE):
                    self.findings.append(Finding(
                        file_path=self.file_path, line_number=i, col_offset=0,
                        line_content=line, vulnerability_name="Command Injection - __getattr__ shell proxy",
                        category=VulnCategory.COMMAND_INJECTION, severity=Severity.HIGH,
                        confidence="HIGH", description="__getattr__ proxy pattern for shell command building."
                    ))

            # 9. lxml XMLParser with dangerous options
            if re.search(r'XMLParser\s*\(', line):
                context = '\n'.join(self.source_lines[i-1:min(len(self.source_lines), i+3)])
                if re.search(r'resolve_entities\s*=\s*True|load_dtd\s*=\s*True|no_network\s*=\s*False', context):
                    self.findings.append(Finding(
                        file_path=self.file_path, line_number=i, col_offset=0,
                        line_content=line, vulnerability_name="XXE - lxml XMLParser with dangerous options",
                        category=VulnCategory.XXE, severity=Severity.CRITICAL,
                        confidence="HIGH", description="lxml XMLParser with resolve_entities/load_dtd enabled."
                    ))

            # 10. format_map SSTI
            if re.search(r'\.format_map\s*\(', line):
                self.findings.append(Finding(
                    file_path=self.file_path, line_number=i, col_offset=0,
                    line_content=line, vulnerability_name="SSTI - format_map with potential user input",
                    category=VulnCategory.SSTI, severity=Severity.HIGH,
                    confidence="MEDIUM", description="format_map() can lead to SSTI if template is user-controlled."
                ))

            # 11. ChainMap for dict injection
            if re.search(r'ChainMap\s*\(', line):
                context = '\n'.join(self.source_lines[max(0, i-3):min(len(self.source_lines), i+5)])
                if re.search(r'__class__|__globals__|__builtins__', context):
                    self.findings.append(Finding(
                        file_path=self.file_path, line_number=i, col_offset=0,
                        line_content=line, vulnerability_name="Dict Injection - ChainMap with dunder access",
                        category=VulnCategory.CODE_INJECTION, severity=Severity.HIGH,
                        confidence="HIGH", description="ChainMap may allow __class__ injection."
                    ))

            # 12. LDAP injection via f-string
            if re.search(r'ldap|LDAP', line):
                if re.search(r'f["\'].*\{.*\}|%\s*\(|\.format\s*\(', line):
                    self.findings.append(Finding(
                        file_path=self.file_path, line_number=i, col_offset=0,
                        line_content=line, vulnerability_name="LDAP Injection - Dynamic LDAP filter",
                        category=VulnCategory.LDAP_INJECTION, severity=Severity.HIGH,
                        confidence="HIGH", description="LDAP filter with string interpolation."
                    ))

            # 13. Pickle loads with obfuscated module reference
            if re.search(r'\.loads\s*\(', line):
                context = '\n'.join(self.source_lines[max(0, i-5):i+1])
                if re.search(r'pickle|cvpxyr|7069636b6c65', context):  # cvpxyr = pickle in rot13
                    self.findings.append(Finding(
                        file_path=self.file_path, line_number=i, col_offset=0,
                        line_content=line, vulnerability_name="Insecure Deserialization - Obfuscated pickle",
                        category=VulnCategory.DESERIALIZATION, severity=Severity.CRITICAL,
                        confidence="HIGH", description="pickle.loads with potentially obfuscated reference."
                    ))

            # 15. f-string in lambda with SQL keywords
            if re.search(r'lambda.*f["\'].*(?:SELECT|INSERT|UPDATE|DELETE|FROM|WHERE)', line, re.IGNORECASE):
                self.findings.append(Finding(
                    file_path=self.file_path, line_number=i, col_offset=0,
                    line_content=line, vulnerability_name="SQL Injection - f-string in lambda",
                    category=VulnCategory.SQL_INJECTION, severity=Severity.HIGH,
                    confidence="HIGH", description="SQL query with f-string interpolation in lambda."
                ))

            # 16. Dynamic SQL in f-string
            # Pattern must look like actual SQL, not just contain SQL keywords in messages
            if re.search(r'f["\'].*(?:SELECT|INSERT|UPDATE|DELETE)\s+.*\{', line, re.IGNORECASE):
                # === CRITICAL: Exclude non-SQL patterns (error messages, API responses) ===
                non_sql_patterns = [
                    r'jsonify\s*\(',               # Flask JSON response
                    r'return\s+.*message',          # Error message returns
                    r'raise\s+',                    # Exception raising
                    r'logging\.',                   # Logging calls
                    r'logger\.',                    # Logger calls
                    r'print\s*\(',                  # Print statements
                    r'\.error\s*\(',                # Error logging
                    r'\.warning\s*\(',              # Warning logging
                    r'\.info\s*\(',                 # Info logging
                    r'\.debug\s*\(',                # Debug logging
                    r'Exception\s*\(',              # Exception creation
                    r'Error\s*\(',                  # Error creation
                    r'"message"',                   # JSON message field
                    r"'message'",                   # JSON message field
                    r'Unable to',                   # Error message text
                    r'Failed to',                   # Error message text
                    r'Could not',                   # Error message text
                    r'Cannot ',                     # Error message text
                    r'Error:',                      # Error message text
                ]

                # Require actual SQL syntax context
                sql_syntax_patterns = [
                    r'SELECT\s+.*\s+FROM\s+',        # SELECT ... FROM
                    r'INSERT\s+INTO\s+',             # INSERT INTO
                    r'UPDATE\s+\w+\s+SET\s+',        # UPDATE table SET
                    r'DELETE\s+FROM\s+',             # DELETE FROM
                    r'WHERE\s+',                     # WHERE clause
                    r'execute\s*\(',                 # SQL execute call
                    r'cursor\.',                     # Cursor operations
                    r'\.query\s*\(',                 # Query method (after excluding ORM)
                    r'\.raw\s*\(',                   # Raw SQL
                    r'text\s*\(\s*f["\']',           # SQLAlchemy text()
                ]

                is_non_sql = any(re.search(pat, line, re.IGNORECASE) for pat in non_sql_patterns)
                has_sql_syntax = any(re.search(pat, line, re.IGNORECASE) for pat in sql_syntax_patterns)

                if not is_non_sql and has_sql_syntax:
                    self.findings.append(Finding(
                        file_path=self.file_path, line_number=i, col_offset=0,
                        line_content=line, vulnerability_name="SQL Injection - f-string query",
                        category=VulnCategory.SQL_INJECTION, severity=Severity.HIGH,
                        confidence="HIGH", description="SQL query built with f-string interpolation."
                    ))

            # 17. NoSQL injection via dict comprehension from user input
            if re.search(r'\{.*for.*in.*user|query|request|input', line, re.IGNORECASE):
                if re.search(r'\.find\s*\(|\.find_one\s*\(|\.aggregate\s*\(', '\n'.join(self.source_lines[i:min(len(self.source_lines), i+5)])):
                    self.findings.append(Finding(
                        file_path=self.file_path, line_number=i, col_offset=0,
                        line_content=line, vulnerability_name="NoSQL Injection - Dict from user input",
                        category=VulnCategory.NOSQL_INJECTION, severity=Severity.HIGH,
                        confidence="MEDIUM", description="MongoDB query built from user-controlled dict."
                    ))

            # 19. __builtins__ direct access for sandbox escape
            if re.search(r'__builtins__\s*\[|__builtins__\s*\.\s*__dict__\s*\[|__builtins__\s*\.get\s*\(', line):
                self.findings.append(Finding(
                    file_path=self.file_path, line_number=i, col_offset=0,
                    line_content=line, vulnerability_name="Code Injection - __builtins__ access",
                    category=VulnCategory.CODE_INJECTION, severity=Severity.CRITICAL,
                    confidence="HIGH", description="Direct __builtins__ access enables sandbox escape and arbitrary code execution."
                ))

            # 20. globals()/locals() for dynamic function access
            if re.search(r'(?:globals|locals)\s*\(\s*\)\s*\[', line):
                self.findings.append(Finding(
                    file_path=self.file_path, line_number=i, col_offset=0,
                    line_content=line, vulnerability_name="Code Injection - globals()/locals() dynamic access",
                    category=VulnCategory.CODE_INJECTION, severity=Severity.HIGH,
                    confidence="HIGH", description="Dynamic function access via globals()/locals() enables code execution evasion."
                ))

            # 21. Format string attribute chain for sandbox escape (Jinja2/SSTI style)
            if re.search(r'\{[^}]*\.__class__|__mro__|__subclasses__|__globals__|__getattribute__', line):
                self.findings.append(Finding(
                    file_path=self.file_path, line_number=i, col_offset=0,
                    line_content=line, vulnerability_name="SSTI/Sandbox Escape - Dunder attribute chain in format string",
                    category=VulnCategory.SSTI, severity=Severity.CRITICAL,
                    confidence="HIGH", description="Format string with __class__/__mro__/__subclasses__ chain enables sandbox escape."
                ))

            # 22. __subclasses__() for type enumeration and sandbox escape
            if re.search(r'__subclasses__\s*\(\s*\)', line):
                self.findings.append(Finding(
                    file_path=self.file_path, line_number=i, col_offset=0,
                    line_content=line, vulnerability_name="Sandbox Escape - __subclasses__() enumeration",
                    category=VulnCategory.CODE_INJECTION, severity=Severity.CRITICAL,
                    confidence="HIGH", description="__subclasses__() allows finding dangerous classes like subprocess.Popen for sandbox escape."
                ))

            # 23. vars() for dynamic attribute access
            if re.search(r'vars\s*\([^)]*\)\s*\[', line):
                context = '\n'.join(self.source_lines[max(0, i-3):i+1])
                if any(taint in context for taint in self.tainted_vars):
                    self.findings.append(Finding(
                        file_path=self.file_path, line_number=i, col_offset=0,
                        line_content=line, vulnerability_name="Code Injection - vars() with tainted key",
                        category=VulnCategory.CODE_INJECTION, severity=Severity.HIGH,
                        confidence="HIGH", description="vars() dynamic access with user-controlled key enables arbitrary attribute access."
                    ))

            # 24. importlib dynamic import
            if re.search(r'importlib\.import_module\s*\(', line):
                is_tainted = any(var in line for var in self.tainted_vars)
                if is_tainted:
                    self.findings.append(Finding(
                        file_path=self.file_path, line_number=i, col_offset=0,
                        line_content=line, vulnerability_name="Code Injection - importlib with tainted module name",
                        category=VulnCategory.CODE_INJECTION, severity=Severity.CRITICAL,
                        confidence="HIGH", description="Dynamic import with user-controlled module name enables arbitrary code loading."
                    ))

            # 25. exec/eval with compile() - multi-stage code execution
            if re.search(r'(?:exec|eval)\s*\(\s*compile\s*\(', line):
                self.findings.append(Finding(
                    file_path=self.file_path, line_number=i, col_offset=0,
                    line_content=line, vulnerability_name="Code Injection - exec/eval with compile()",
                    category=VulnCategory.CODE_INJECTION, severity=Severity.CRITICAL,
                    confidence="HIGH", description="Multi-stage code execution via compile() may indicate evasion attempt."
                ))

            # 26. type() constructor for dynamic class creation
            if re.search(r'type\s*\(\s*[^,]+,\s*\([^)]*\)\s*,\s*\{', line):
                self.findings.append(Finding(
                    file_path=self.file_path, line_number=i, col_offset=0,
                    line_content=line, vulnerability_name="Code Injection - Dynamic class creation via type()",
                    category=VulnCategory.CODE_INJECTION, severity=Severity.HIGH,
                    confidence="MEDIUM", description="type() with 3 args creates dynamic class - verify dict contents aren't user-controlled."
                ))

            # 27. String join to build dangerous commands
            if re.search(r'["\'][\s]*\.join\s*\(', line):
                context = '\n'.join(self.source_lines[max(0, i-2):min(len(self.source_lines), i+3)])
                if re.search(r'subprocess|system|popen|eval|exec|shell', context, re.IGNORECASE):
                    self.findings.append(Finding(
                        file_path=self.file_path, line_number=i, col_offset=0,
                        line_content=line, vulnerability_name="Evasion - String join near dangerous sink",
                        category=VulnCategory.COMMAND_INJECTION, severity=Severity.HIGH,
                        confidence="MEDIUM", description="String joining near command execution - potential evasion technique."
                    ))

    def _track_database_sources(self):
        """Track variables that receive values from database/ORM queries.

        Patterns detected:
        - SQLAlchemy: session.query(), session.execute(), Model.query.filter(), etc.
        - Django ORM: Model.objects.get(), Model.objects.filter(), etc.
        - Raw DB: cursor.fetchone(), cursor.fetchall(), cursor.fetchmany()
        """
        for i, line in enumerate(self.source_lines, 1):
            if line.strip().startswith('#'):
                continue

            # SQLAlchemy patterns: result = session.query(Model).first()
            match = re.search(r'(\w+)\s*=\s*\w+\.query\s*\(.*\)\.(?:first|one|all|scalar|one_or_none)\s*\(', line)
            if match:
                var_name = match.group(1)
                self.db_sourced_vars[var_name] = (i, "SQLAlchemy query result")
                continue

            # SQLAlchemy session.execute pattern
            match = re.search(r'(\w+)\s*=\s*\w+\.execute\s*\(.*\)\.(?:fetchone|fetchall|scalar|scalars|first)\s*\(', line)
            if match:
                var_name = match.group(1)
                self.db_sourced_vars[var_name] = (i, "SQLAlchemy execute result")
                continue

            # Django ORM: obj = Model.objects.get() / filter().first()
            match = re.search(r'(\w+)\s*=\s*\w+\.objects\.(?:get|filter|exclude|all)\s*\(.*\)(?:\.(?:first|last))?\s*\(?\)?', line)
            if match:
                var_name = match.group(1)
                self.db_sourced_vars[var_name] = (i, "Django ORM query")
                continue

            # Raw cursor fetch: row = cursor.fetchone()
            match = re.search(r'(\w+)\s*=\s*\w+\.(?:fetchone|fetchall|fetchmany)\s*\(', line)
            if match:
                var_name = match.group(1)
                self.db_sourced_vars[var_name] = (i, "Database cursor fetch")
                continue

            # Pandas read_sql: df = pd.read_sql()
            match = re.search(r'(\w+)\s*=\s*(?:pd|pandas)\.read_sql(?:_query|_table)?\s*\(', line)
            if match:
                var_name = match.group(1)
                self.db_sourced_vars[var_name] = (i, "pandas.read_sql (DB-sourced DataFrame)")
                continue

            # Track attribute access on DB-sourced objects
            for db_var in list(self.db_sourced_vars.keys()):
                # Pattern: value = obj.field or value = obj['field']
                match = re.search(rf'(\w+)\s*=\s*{re.escape(db_var)}\.(\w+)', line)
                if match:
                    new_var = match.group(1)
                    field_name = match.group(2)
                    orig_line, orig_source = self.db_sourced_vars[db_var]
                    self.db_sourced_vars[new_var] = (i, f"{orig_source}.{field_name}")

                # Dict access: value = obj['field']
                match = re.search(rf"(\w+)\s*=\s*{re.escape(db_var)}\s*\[\s*['\"](\w+)['\"]\s*\]", line)
                if match:
                    new_var = match.group(1)
                    field_name = match.group(2)
                    orig_line, orig_source = self.db_sourced_vars[db_var]
                    self.db_sourced_vars[new_var] = (i, f"{orig_source}['{field_name}']")

    def _is_db_sourced(self, line: str) -> Tuple[bool, Optional[str], Optional[str]]:
        """Check if a line contains DB-sourced variable usage."""
        for var, (src_line, source) in self.db_sourced_vars.items():
            # Check for variable in the line (not in comments)
            if re.search(rf'\b{re.escape(var)}\b', line):
                return True, var, source
        return False, None, None

    def _check_pandas_query_injection(self):
        """Detect code injection via pandas df.query() with DB-sourced values.

        Pattern: df.query(db_value) executes the string as a query expression,
        which can include Python code via @ references or backticks.

        NOTE: This specifically targets pandas DataFrame.query(), NOT SQLAlchemy session.query()
        which is a completely different and safe ORM pattern.
        """
        for i, line in enumerate(self.source_lines, 1):
            if line.strip().startswith('#'):
                continue

            # pandas DataFrame.query() pattern
            if re.search(r'\.query\s*\(', line):
                # === CRITICAL: Exclude SQLAlchemy ORM patterns (NOT pandas) ===
                # SQLAlchemy: session.query(Model), db.query(Model), Base.query.filter()
                # These are ORM query builders, NOT pandas string evaluation
                sqlalchemy_patterns = [
                    r'session\.query\s*\(',           # session.query(Model)
                    r'db\.query\s*\(',                # db.query(Model)
                    r'\.query\s*\([A-Z]\w*',          # .query(ModelName) - starts with capital = class
                    r'\.query\s*\(\s*\w+\s*,\s*\w+',  # .query(Model1, Model2) - multiple models
                    r'\.query\s*\([^)]*\)\s*\.',      # .query(...).filter() - chained ORM methods
                    r'with\s+Session\s*\(',           # SQLAlchemy session context
                    r'from\s+sqlalchemy',             # SQLAlchemy import context
                ]

                is_sqlalchemy = any(re.search(pat, line) for pat in sqlalchemy_patterns)

                # Also check surrounding context for SQLAlchemy indicators
                context_start = max(0, i - 10)
                context = '\n'.join(self.source_lines[context_start:i])
                sqlalchemy_context_patterns = [
                    r'from\s+sqlalchemy',
                    r'import.*Session',
                    r'import.*declarative',
                    r'session\s*=',
                    r'Session\s*\(\)',
                    r'\.filter\s*\(',
                    r'\.join\s*\(',
                    r'\.all\s*\(\)',
                    r'\.first\s*\(\)',
                    r'\.scalar\s*\(',
                ]
                is_sqlalchemy_context = any(re.search(pat, context) for pat in sqlalchemy_context_patterns)

                if is_sqlalchemy or is_sqlalchemy_context:
                    continue  # Skip SQLAlchemy - it's safe ORM, not pandas eval

                # Skip safe SQL patterns (parameterized)
                if re.search(r'\.query\s*\(\s*["\']', line) and not re.search(r'\.query\s*\(\s*f["\']', line):
                    # Literal string query - likely safe unless f-string
                    continue

                is_db, db_var, source = self._is_db_sourced(line)
                if is_db:
                    self.findings.append(Finding(
                        file_path=self.file_path, line_number=i, col_offset=0,
                        line_content=self.source_lines[i-1],
                        vulnerability_name="2nd-Order Code Injection - pandas df.query() with DB-sourced value",
                        category=VulnCategory.CODE_INJECTION, severity=Severity.CRITICAL,
                        confidence="HIGH",
                        description=f"DB value from {source} passed to df.query(). "
                                   f"Pandas query() evaluates strings as expressions with @var and `code` syntax."
                    ))

            # pandas DataFrame.eval() pattern - similar risk
            if re.search(r'\.eval\s*\(', line):
                if re.search(r'\.eval\s*\(\s*["\']', line) and not re.search(r'\.eval\s*\(\s*f["\']', line):
                    continue

                is_db, db_var, source = self._is_db_sourced(line)
                if is_db:
                    self.findings.append(Finding(
                        file_path=self.file_path, line_number=i, col_offset=0,
                        line_content=self.source_lines[i-1],
                        vulnerability_name="2nd-Order Code Injection - pandas df.eval() with DB-sourced value",
                        category=VulnCategory.CODE_INJECTION, severity=Severity.CRITICAL,
                        confidence="HIGH",
                        description=f"DB value from {source} passed to df.eval(). "
                                   f"Pandas eval() evaluates strings as code expressions."
                    ))

            # pd.eval() global function
            if re.search(r'(?:pd|pandas)\.eval\s*\(', line):
                is_db, db_var, source = self._is_db_sourced(line)
                if is_db:
                    self.findings.append(Finding(
                        file_path=self.file_path, line_number=i, col_offset=0,
                        line_content=self.source_lines[i-1],
                        vulnerability_name="2nd-Order Code Injection - pd.eval() with DB-sourced value",
                        category=VulnCategory.CODE_INJECTION, severity=Severity.CRITICAL,
                        confidence="HIGH",
                        description=f"DB value from {source} passed to pandas.eval(). "
                                   f"This function evaluates strings as Python expressions."
                    ))

    def _add_finding_simple(self, line_num: int, vuln_name: str, category: VulnCategory,
                            severity: Severity, confidence: str, description: str = ""):
        """Add a finding (simplified version for regex-based post-AST checks)."""
        self.findings.append(Finding(
            file_path=self.file_path,
            line_number=line_num,
            col_offset=0,
            line_content=self.get_line_content(line_num),
            vulnerability_name=vuln_name,
            category=category,
            severity=severity,
            confidence=confidence,
            description=description,
        ))


class JavaScriptAnalyzer:
    """
    Basic JavaScript/TypeScript analyzer using regex-enhanced pattern matching.
    For production use, consider integrating with esprima or typescript parser.
    Includes 2nd-order NoSQL detection for:
    - MongoDB $where operator with DB-sourced JavaScript
    - $accumulator/$function with DB-sourced code
    - Command injection via DB-stored usernames/values
    """

    def __init__(self, source_code: str, file_path: str):
        self.source_code = source_code
        self.source_lines = source_code.splitlines()
        self.file_path = file_path
        self.findings: List[Finding] = []

        # Track variable assignments for basic taint tracking
        self.tainted_vars: Set[str] = set()
        # 2nd-order tracking: variables from DB queries
        self.db_sourced_vars: Dict[str, Tuple[int, str]] = {}  # var -> (line, source)

        self._identify_taint_sources()
        self._track_database_sources()

    def _identify_taint_sources(self):
        """Identify variables that hold user input."""
        taint_patterns = [
            # Express.js patterns - with property access (req.query.id, req.body.name, etc.)
            r'(?:const|let|var)\s+(\w+)\s*=\s*req\.(body|query|params|cookies|headers)(?:\.\w+|\[[\'"][^\]]+[\'"]\])?',
            r'(\w+)\s*=\s*req\.(body|query|params|cookies|headers)(?:\.\w+|\[[\'"][^\]]+[\'"]\])?',
            # Direct req property access
            r'(\w+)\s*=\s*request\.(body|query|params)(?:\.\w+|\[[\'"][^\]]+[\'"]\])?',
            # Destructuring
            r'const\s+\{([^}]+)\}\s*=\s*req\.(body|query|params)',
            r'let\s+\{([^}]+)\}\s*=\s*req\.(body|query|params)',
            # Process argv
            r'(\w+)\s*=\s*process\.argv',
            # Browser DOM sources
            r'(\w+)\s*=\s*document\.(location|URL|referrer|cookie)',
            r'(\w+)\s*=\s*window\.location',
            r'(\w+)\s*=\s*location\.(href|search|hash|pathname)',
            # URL/URLSearchParams
            r'(\w+)\s*=\s*(?:new\s+)?URL(?:SearchParams)?\s*\(',
            r'(\w+)\s*=\s*\w+\.(?:get|getAll)\s*\(',
        ]

        for pattern in taint_patterns:
            for match in re.finditer(pattern, self.source_code):
                var_name = match.group(1)
                if '{' in var_name:
                    # Destructuring
                    vars_list = [v.strip().split(':')[0].strip() for v in var_name.split(',')]
                    self.tainted_vars.update(vars_list)
                else:
                    self.tainted_vars.add(var_name)

        # Second pass: Track taint propagation through assignments
        self._track_taint_propagation()

    def _track_taint_propagation(self):
        """Track taint propagation through variable assignments."""
        # Multiple passes to handle chained assignments
        for _ in range(3):
            for i, line in enumerate(self.source_lines, 1):
                stripped = line.strip()
                if stripped.startswith('//') or stripped.startswith('/*'):
                    continue

                # Match variable assignments: const/let/var x = ... or x = ...
                assign_match = re.search(r'(?:const|let|var)\s+(\w+)\s*=\s*(.+?)(?:;|$)', line)
                if not assign_match:
                    assign_match = re.search(r'^(\w+)\s*=\s*(.+?)(?:;|$)', stripped)

                if assign_match:
                    var_name = assign_match.group(1)
                    rhs = assign_match.group(2)

                    # Check if RHS is wrapped in a sanitizer call — skip taint propagation
                    if re.search(
                        r'(?:escape(?:Html|Shell|Regex)|sanitize\w*|DOMPurify\.sanitize|'
                        r'validator\.\w+|parseInt|parseFloat|Number|'
                        r'encodeURI(?:Component)?|xss|clean|purify)\s*\(',
                        rhs, re.IGNORECASE
                    ):
                        continue

                    # Check if RHS contains any tainted variable
                    for tainted_var in list(self.tainted_vars):
                        # Check for direct use or template literal interpolation
                        if re.search(rf'\b{re.escape(tainted_var)}\b', rhs):
                            self.tainted_vars.add(var_name)
                            break
                        # Check template literal: `...${taintedVar}...`
                        if re.search(rf'\$\{{\s*{re.escape(tainted_var)}\s*\}}', rhs):
                            self.tainted_vars.add(var_name)
                            break

    def _track_database_sources(self):
        """Track variables that receive values from database queries (Mongoose, MongoDB, Sequelize)."""
        # Mongoose/MongoDB query patterns
        db_patterns = [
            (r'(?:const|let|var)\s+(\w+)\s*=\s*await\s+(\w+)\.findOne\s*\(', 'findOne'),
            (r'(?:const|let|var)\s+(\w+)\s*=\s*await\s+(\w+)\.findById\s*\(', 'findById'),
            (r'(?:const|let|var)\s+(\w+)\s*=\s*await\s+(\w+)\.find\s*\(', 'find'),
            (r'(?:const|let|var)\s+(\w+)\s*=\s*await\s+db\.(\w+)\.findOne\s*\(', 'db.findOne'),
            (r'(?:const|let|var)\s+(\w+)\s*=\s*await\s+db\.collection\([\'"](\w+)[\'"]\)\.findOne\s*\(', 'collection.findOne'),
            # Sequelize patterns
            (r'(?:const|let|var)\s+(\w+)\s*=\s*await\s+(\w+)\.findOne\s*\(', 'Sequelize.findOne'),
            (r'(?:const|let|var)\s+(\w+)\s*=\s*await\s+(\w+)\.findByPk\s*\(', 'Sequelize.findByPk'),
        ]

        for i, line in enumerate(self.source_lines, 1):
            stripped = line.strip()
            if stripped.startswith('//') or stripped.startswith('/*'):
                continue

            for pattern, source_type in db_patterns:
                match = re.search(pattern, line)
                if match:
                    var_name = match.group(1)
                    model_name = match.group(2)
                    self.db_sourced_vars[var_name] = (i, f"{model_name}.{source_type}")

        # Track property access on DB-sourced objects
        for i, line in enumerate(self.source_lines, 1):
            stripped = line.strip()
            if stripped.startswith('//') or stripped.startswith('/*'):
                continue

            for entity_var in list(self.db_sourced_vars.keys()):
                # Pattern: entity.property or entity['property']
                prop_patterns = [
                    rf'(?:const|let|var)\s+(\w+)\s*=\s*{re.escape(entity_var)}\.(\w+)',
                    rf'(\w+)\s*=\s*{re.escape(entity_var)}\.(\w+)',
                    rf'{re.escape(entity_var)}\[[\'""](\w+)[\'""]\]',
                ]
                for prop_pattern in prop_patterns[:2]:
                    match = re.search(prop_pattern, line)
                    if match:
                        new_var = match.group(1)
                        prop_name = match.group(2)
                        orig_line, orig_source = self.db_sourced_vars[entity_var]
                        self.db_sourced_vars[new_var] = (i, f"{orig_source}.{prop_name}")

    def _is_db_sourced(self, line: str) -> Tuple[bool, Optional[str], Optional[str]]:
        """Check if line uses a database-sourced variable."""
        for var, (src_line, source) in self.db_sourced_vars.items():
            if re.search(rf'\b{re.escape(var)}\b', line):
                return True, var, source
        return False, None, None

    def get_line_content(self, lineno: int) -> str:
        """Get the source line content."""
        if 1 <= lineno <= len(self.source_lines):
            return self.source_lines[lineno - 1]
        return ""

    def analyze(self):
        """Run the analysis."""
        # Skip minified library files - they generate too many false positives
        # and are third-party code outside developer control
        # Third-party library patterns to skip (both minified and non-minified)
        # These are external dependencies, not application code
        minified_library_patterns = [
            # jQuery (all versions, minified and non-minified)
            r'jquery[.-][\d.]+\.min\.js$',
            r'jquery[.-][\d.]+\.slim\.min\.js$',
            r'jquery[.-][\d.]+\.slim\.js$',
            r'jquery[.-][\d.]+\.js$',
            r'jquery\.min\.js$',
            # Bootstrap
            r'bootstrap[.-][\d.]*\.min\.js$',
            r'bootstrap[.-][\d.]*\.js$',
            r'bootstrap\.bundle\.min\.js$',
            r'bootstrap\.bundle\.js$',
            r'bootstrap\.esm\.min\.js$',
            r'bootstrap\.esm\.js$',
            # Other frameworks
            r'angular[.-][\d.]*\.min\.js$',
            r'angular[.-][\d.]*\.js$',
            r'react[.-][\d.]*\.min\.js$',
            r'react[.-][\d.]*\.js$',
            r'vue[.-][\d.]*\.min\.js$',
            r'vue[.-][\d.]*\.js$',
            # Utilities
            r'lodash[.-][\d.]*\.min\.js$',
            r'lodash[.-][\d.]*\.js$',
            r'moment[.-][\d.]*\.min\.js$',
            r'moment[.-][\d.]*\.js$',
            r'axios[.-][\d.]*\.min\.js$',
            r'axios[.-][\d.]*\.js$',
            r'popper[.-][\d.]*\.min\.js$',
            r'popper[.-][\d.]*\.js$',
            r'modernizr[.-][\d.]*\.js$',
            # Validation plugins
            r'jquery\.validate[.-]?[\w.]*\.js$',
            r'jquery\.validate\.unobtrusive[.-]?[\w.]*\.js$',
            # IntelliSense files (VS tooling, not runtime code)
            r'\.intellisense\.js$',
            r'-vsdoc\.js$',
            # Google API
            r'jsapi\.js$',
            r'google-loader\.js$',
        ]

        import os
        filename = os.path.basename(self.file_path)
        for pattern in minified_library_patterns:
            if re.search(pattern, filename, re.IGNORECASE):
                # Skip this file entirely - it's a third-party library
                return self.findings

        # Detect minified files and warn user
        self._is_minified = self._detect_minified_file()
        if self._is_minified:
            filename = os.path.basename(self.file_path)
            warn_text = Text()
            warn_text.append("MINIFIED FILE DETECTED\n\n", style="bold yellow")
            warn_text.append(f"File: {filename}\n\n", style="white")
            warn_text.append("Minified files may produce MORE FALSE POSITIVES.\n", style="yellow")
            warn_text.append("Findings from this file should be reviewed carefully.", style="dim")
            console.print(Panel(
                warn_text,
                title="[bold yellow]Warning[/bold yellow]",
                border_style="yellow",
                box=box.ROUNDED,
                padding=(1, 2),
            ))

        self._check_eval_injection()
        self._check_command_injection()
        self._check_sql_injection()
        self._check_deserialization()
        self._check_ssti()
        self._check_nosql_injection()
        self._check_dangerous_functions()
        self._check_callback_sinks()
        self._check_xxe()
        self._check_xpath_injection()
        self._check_auth_bypass()
        self._check_react_security()
        # 2nd-order detection
        self._check_second_order_nosql()
        self._check_second_order_cmdi()
        return self.findings

    def _add_finding(self, line_num: int, vuln_name: str, category: VulnCategory,
                     severity: Severity, confidence: str, description: str = ""):
        """Add a finding."""
        finding = Finding(
            file_path=self.file_path,
            line_number=line_num,
            col_offset=0,
            line_content=self.get_line_content(line_num),
            vulnerability_name=vuln_name,
            category=category,
            severity=severity,
            confidence=confidence,
            description=description,
        )
        self.findings.append(finding)

    def _detect_minified_file(self) -> bool:
        """
        Detect if file is minified using multiple heuristics.
        Returns True if file appears to be minified.
        """
        if not self.source_lines:
            return False

        # Heuristic 1: Very few lines but large file size
        if len(self.source_lines) <= 10 and len(self.source_code) > 5000:
            return True

        # Heuristic 2: Average line length > 500 characters
        total_length = sum(len(line) for line in self.source_lines)
        avg_line_length = total_length / len(self.source_lines) if self.source_lines else 0
        if avg_line_length > 500:
            return True

        # Heuristic 3: Any single line > 1000 characters (common in minified)
        if any(len(line) > 1000 for line in self.source_lines):
            return True

        # Heuristic 4: High density of semicolons with minimal whitespace
        # Minified code often has patterns like: };var a=1;function b(){};
        sample = self.source_code[:5000]  # Check first 5KB
        semicolons = sample.count(';')
        newlines = sample.count('\n')
        if semicolons > 50 and newlines < 20:
            return True

        # Heuristic 5: Filename patterns suggesting minified
        import os
        filename = os.path.basename(self.file_path).lower()
        if '.min.' in filename or '-min.' in filename or filename.endswith('.min.js'):
            return True

        # Heuristic 6: Contains typical minified patterns (obfuscated variable names)
        # Look for high frequency of single-letter variables like: a,b,c,d,e,f,g
        if re.search(r'\b[a-z]\s*=\s*[a-z]\s*\(', sample) and re.search(r'\b[a-z]\s*,\s*[a-z]\s*,\s*[a-z]\b', sample):
            # Multiple single-letter params and assignments
            single_letter_vars = len(re.findall(r'\b[a-zA-Z]\s*[=,\(]', sample))
            if single_letter_vars > 100:
                return True

        return False

    def _check_eval_injection(self):
        """Check for eval/Function constructor injection - including evasion techniques."""
        # Direct patterns
        direct_patterns = [
            (r'\beval\s*\(', "Code Injection - eval()"),
            (r'\bnew\s+Function\s*\(', "Code Injection - Function constructor"),
        ]

        # Evasion technique patterns
        evasion_patterns = [
            # [].constructor.constructor or Array.constructor.constructor
            (r'\[\s*\]\s*\.\s*constructor\s*\.\s*constructor', "Code Injection - Indirect Function via [].constructor.constructor"),
            # Function.prototype.constructor
            (r'Function\s*\.\s*prototype\s*\.\s*constructor', "Code Injection - Function.prototype.constructor"),
            # .constructor.constructor on any object
            (r'\.\s*constructor\s*\.\s*constructor\s*\(', "Code Injection - Indirect Function constructor chain"),
            # .bind on Function constructor
            (r'Function.*\.bind\s*\(', "Code Injection - Function constructor via bind"),
            (r'constructor\s*\.\s*bind\s*\(', "Code Injection - Constructor bind evasion"),
            # setTimeout/setInterval with string argument (not function)
            (r'setTimeout\s*\(\s*[^,\)]+,', "Code Injection - setTimeout with potential string"),
            (r'setInterval\s*\(\s*[^,\)]+,', "Code Injection - setInterval with potential string"),
            # Dynamic property access to constructor
            (r'\[\s*["\']constructor["\']\s*\]', "Code Injection - Dynamic constructor access"),
            # Reflect.construct
            (r'Reflect\s*\.\s*construct\s*\(', "Code Injection - Reflect.construct"),
        ]

        # vm module patterns (RCE)
        vm_patterns = [
            (r'vm\s*\.\s*runInContext\s*\(', "Code Injection - vm.runInContext"),
            (r'vm\s*\.\s*runInNewContext\s*\(', "Code Injection - vm.runInNewContext"),
            (r'vm\s*\.\s*runInThisContext\s*\(', "Code Injection - vm.runInThisContext"),
            (r'vm\s*\.\s*compileFunction\s*\(', "Code Injection - vm.compileFunction"),
            (r'vm\s*\.\s*createContext\s*\(', "Code Injection - vm.createContext"),
            (r'new\s+vm\s*\.\s*Script\s*\(', "Code Injection - vm.Script constructor"),
        ]

        for i, line in enumerate(self.source_lines, 1):
            stripped = line.strip()
            if stripped.startswith('//') or stripped.startswith('/*'):
                continue

            # Check direct patterns
            for pattern, vuln_name in direct_patterns:
                if re.search(pattern, line):
                    has_taint = any(var in line for var in self.tainted_vars)
                    if has_taint:
                        self._add_finding(i, f"{vuln_name} with user input",
                                          VulnCategory.CODE_INJECTION, Severity.CRITICAL, "HIGH",
                                          "User-controlled data in code execution context.")
                    else:
                        self._add_finding(i, vuln_name,
                                          VulnCategory.CODE_INJECTION, Severity.HIGH, "MEDIUM",
                                          "Potential code injection. Verify input source.")

            # Check evasion patterns - these are always suspicious
            for pattern, vuln_name in evasion_patterns:
                if re.search(pattern, line):
                    # Check for setTimeout/setInterval specifically - verify it's string arg
                    if 'setTimeout' in line or 'setInterval' in line:
                        # Safe patterns - function references, arrow functions, function expressions
                        # Function reference: setTimeout(funcName, ms) or setTimeout(obj.method, ms)
                        # Arrow function: setTimeout(() => ..., ms) or setTimeout((...) => ..., ms)
                        # Function expression: setTimeout(function() {...}, ms)
                        safe_timer_pattern = (
                            r'(?:setTimeout|setInterval)\s*\(\s*'
                            r'(?:'
                            r'function\s*[\(\w]|'                    # function keyword
                            r'\([^)]*\)\s*=>|'                       # arrow with parens: () =>
                            r'\w+\s*=>|'                             # arrow without parens: x =>
                            r'[a-zA-Z_$][\w$]*(?:\.[a-zA-Z_$][\w$]*)*\s*,'  # function reference: name, or obj.method,
                            r')'
                        )
                        if re.search(safe_timer_pattern, line):
                            continue
                        # Only flag if first arg looks like a string or template with interpolation
                        string_arg_pattern = r'(?:setTimeout|setInterval)\s*\(\s*(?:["\']|`[^`]*\$\{)'
                        if not re.search(string_arg_pattern, line):
                            continue
                    self._add_finding(i, vuln_name,
                                      VulnCategory.CODE_INJECTION, Severity.HIGH, "HIGH",
                                      "Code execution via evasion technique detected.")

            # Check vm module patterns - always critical
            for pattern, vuln_name in vm_patterns:
                if re.search(pattern, line):
                    self._add_finding(i, vuln_name,
                                      VulnCategory.CODE_INJECTION, Severity.CRITICAL, "HIGH",
                                      "VM module allows arbitrary code execution.")

        # Second pass: Check for "Shadow Eval" patterns (string manipulation to hide eval/Function)
        self._check_shadow_eval()

    def _check_shadow_eval(self):
        """
        Detect obfuscated eval/Function access via string manipulation.

        Patterns like:
          const s = "lave";
          const checker = global[s.split("").reverse().join("")];
          checker("malicious code");

        This resolves "lave" reversed to "eval" and flags the dynamic global access.
        """
        # Track potential shadow variables (variables that might hold dangerous functions)
        shadow_vars = {}

        # Known dangerous function names (and their reverses for detection)
        dangerous_funcs = {
            'eval': 'lave',
            'Function': 'noitcnuF',
            'exec': 'cexe',
            'execSync': 'cnySexe',
        }
        reversed_dangerous = {v: k for k, v in dangerous_funcs.items()}

        for i, line in enumerate(self.source_lines, 1):
            stripped = line.strip()
            if stripped.startswith('//') or stripped.startswith('/*'):
                continue

            # Pattern 1: String containing reversed dangerous function name
            # const s = "lave"; or const s = 'noitcnuF';
            for rev_name, orig_name in reversed_dangerous.items():
                if re.search(rf'["\']({re.escape(rev_name)})["\']', line):
                    self._add_finding(i, f"Code Injection - Obfuscated '{orig_name}' string detected",
                                      VulnCategory.CODE_INJECTION, Severity.HIGH, "HIGH",
                                      f"String '{rev_name}' reverses to '{orig_name}'. Likely evasion technique.")

            # Pattern 2: Dynamic global access with string manipulation
            # global[...], window[...], globalThis[...], this[...]
            global_access = re.search(
                r'(global|window|globalThis|this)\s*\[\s*(\w+)\.(?:split|reverse|join|charAt|substring|slice)',
                line
            )
            if global_access:
                self._add_finding(i, "Code Injection - Dynamic global access with string manipulation",
                                  VulnCategory.CODE_INJECTION, Severity.CRITICAL, "HIGH",
                                  f"Dynamic property access on {global_access.group(1)} with string manipulation. "
                                  "Likely obfuscated eval/Function access.")

            # Pattern 3: .split("").reverse().join("") pattern
            if re.search(r'\.split\s*\(\s*["\']["\']?\s*\)\s*\.reverse\s*\(\s*\)\s*\.join\s*\(\s*["\']["\']?\s*\)', line):
                self._add_finding(i, "Code Injection - String reversal pattern",
                                  VulnCategory.CODE_INJECTION, Severity.HIGH, "HIGH",
                                  "String reversal pattern detected. Often used to obfuscate dangerous function names.")

            # Pattern 4: Variable assigned from global[...] then called
            # const checker = global[...]; then checker(...)
            var_from_global = re.search(
                r'(?:const|let|var)\s+(\w+)\s*=\s*(?:global|window|globalThis)\s*\[',
                line
            )
            if var_from_global:
                shadow_vars[var_from_global.group(1)] = i

            # Pattern 5: Check if a shadow variable is being called as a function
            for var_name, def_line in shadow_vars.items():
                if re.search(rf'\b{re.escape(var_name)}\s*\(', line) and i != def_line:
                    self._add_finding(i, "Code Injection - Shadow function invocation",
                                      VulnCategory.CODE_INJECTION, Severity.CRITICAL, "HIGH",
                                      f"Variable '{var_name}' (assigned from global object at line {def_line}) "
                                      "is being called as a function. Likely obfuscated eval/Function.")

            # Pattern 6: Indirect eval via (0, eval) or (1, eval)
            if re.search(r'\(\s*\d+\s*,\s*eval\s*\)', line):
                self._add_finding(i, "Code Injection - Indirect eval invocation",
                                  VulnCategory.CODE_INJECTION, Severity.HIGH, "HIGH",
                                  "Indirect eval pattern (0, eval) used to change execution context.")

            # Pattern 7: eval accessed via globalThis/window/global bracket notation
            if re.search(r'(?:global|window|globalThis)\s*\[\s*["\']eval["\']\s*\]', line):
                self._add_finding(i, "Code Injection - eval via bracket notation",
                                  VulnCategory.CODE_INJECTION, Severity.HIGH, "HIGH",
                                  "eval accessed via bracket notation on global object.")

            # Pattern 8: Dynamic import() with tainted module path
            # Note: Must exclude method calls like sdk.product.import() - only match import() keyword
            if re.search(r'(?<![.\w])\bimport\s*\(', line):  # Negative lookbehind for . or word char
                has_taint = any(var in line for var in self.tainted_vars)
                if has_taint:
                    self._add_finding(i, "Code Injection - Dynamic import() with tainted path",
                                      VulnCategory.CODE_INJECTION, Severity.CRITICAL, "HIGH",
                                      "User-controlled module path in import() enables loading arbitrary code.")
                elif re.search(r'(?<![.\w])import\s*\(\s*[^"\'\`]', line):  # Variable, not string literal
                    self._add_finding(i, "Code Injection - Dynamic import() with variable",
                                      VulnCategory.CODE_INJECTION, Severity.HIGH, "MEDIUM",
                                      "Dynamic import() with variable path. Verify source is not user-controlled.")

            # Pattern 9: this[tainted]() or obj[tainted]() - dynamic method invocation
            dynamic_method = re.search(r'(?:this|self)\s*\[\s*(\w+)\s*\]\s*\(', line)
            if dynamic_method:
                method_var = dynamic_method.group(1)
                if method_var in self.tainted_vars:
                    self._add_finding(i, "Code Injection - this[tainted]() dynamic method call",
                                      VulnCategory.CODE_INJECTION, Severity.CRITICAL, "HIGH",
                                      f"User-controlled method name '{method_var}' enables arbitrary method invocation.")

            # Pattern 10: window[tainted] or global[tainted] with tainted variable
            global_tainted = re.search(r'(?:window|global|globalThis)\s*\[\s*(\w+)\s*\]', line)
            if global_tainted:
                prop_var = global_tainted.group(1)
                if prop_var in self.tainted_vars:
                    self._add_finding(i, "Code Injection - global[tainted] dynamic property access",
                                      VulnCategory.CODE_INJECTION, Severity.CRITICAL, "HIGH",
                                      f"User-controlled property '{prop_var}' on global object enables arbitrary function access.")

            # Pattern 11: Reflect.get/Reflect.apply with tainted property
            if re.search(r'Reflect\s*\.\s*(?:get|apply|construct)\s*\(', line):
                has_taint = any(var in line for var in self.tainted_vars)
                if has_taint:
                    self._add_finding(i, "Code Injection - Reflect API with tainted argument",
                                      VulnCategory.CODE_INJECTION, Severity.HIGH, "HIGH",
                                      "Reflect API with user-controlled argument enables dynamic code access.")

            # Pattern 12: Object.getOwnPropertyDescriptor for property access
            if re.search(r'Object\s*\.\s*getOwnPropertyDescriptor\s*\(', line):
                has_taint = any(var in line for var in self.tainted_vars)
                if has_taint:
                    self._add_finding(i, "Code Injection - getOwnPropertyDescriptor with tainted key",
                                      VulnCategory.CODE_INJECTION, Severity.MEDIUM, "MEDIUM",
                                      "Object property introspection with user-controlled key.")

            # Pattern 13: with statement (enables scope pollution)
            if re.search(r'\bwith\s*\(', line):
                self._add_finding(i, "Code Injection - with statement scope pollution",
                                  VulnCategory.CODE_INJECTION, Severity.MEDIUM, "MEDIUM",
                                  "with statement can enable scope pollution and variable shadowing.")

    def _check_command_injection(self):
        """Check for command injection - including evasion techniques."""
        # Direct patterns
        direct_patterns = [
            (r'child_process\s*\.\s*exec\s*\(', "Command Injection - child_process.exec"),
            (r'child_process\s*\.\s*execSync\s*\(', "Command Injection - child_process.execSync"),
            (r'child_process\s*\.\s*execFile\s*\(', "Command Injection - child_process.execFile"),
            (r'child_process\s*\.\s*fork\s*\(', "Command Injection - child_process.fork"),
            (r'child_process\s*\.\s*spawnSync\s*\(', "Command Injection - child_process.spawnSync"),
            (r'\.exec\s*\(\s*[`"\']', "Command Injection - exec call"),
            (r'\.execSync\s*\(\s*[`"\']', "Command Injection - execSync call"),
            (r'shelljs\s*\.\s*exec\s*\(', "Command Injection - shelljs.exec"),
            (r'execa\s*\(', "Command Injection - execa"),
        ]

        # Evasion patterns
        evasion_patterns = [
            # spawn with shell: true
            (r'spawn\s*\([^)]+shell\s*:\s*true', "Command Injection - spawn with shell:true"),
            # Dynamic require of child_process
            (r'require\s*\(\s*["\']child_?\s*[\+\.]', "Command Injection - Dynamic require child_process"),
            (r"require\s*\(\s*['\"]child_['\"]", "Command Injection - Obfuscated child_process require"),
            # Dynamic method invocation on child_process module
            (r'\[\s*["\']exec', "Command Injection - Dynamic exec method access"),
            (r'\[\s*[`"\']exec\w*[`"\']\s*\]', "Command Injection - Bracket notation exec"),
            # proc.execSync or similar
            (r'\w+\s*\.\s*execSync\s*\(', "Command Injection - execSync call"),
            (r'\w+\s*\.\s*exec\s*\([^)]*\+', "Command Injection - exec with concatenation"),
            # Dynamic property access on child_process: cp['exec'], cp[method]
            (r'child_process\s*\[\s*[`"\']?\w+[`"\']?\s*\]', "Command Injection - Dynamic child_process access"),
            (r'\bcp\s*\[\s*[`"\']?\w+[`"\']?\s*\]', "Command Injection - Dynamic cp module access"),
        ]

        # Shell execution patterns (sh -c, cmd /c)
        shell_patterns = [
            # Unix shells with -c flag
            (r'\[\s*[`"\'](?:/bin/sh|/bin/bash|sh|bash)[`"\']\s*,\s*[`"\']-c[`"\']', "Command Injection - Shell execution pattern [sh, -c]"),
            (r'spawn\s*\(\s*[`"\'](?:/bin/sh|/bin/bash|sh|bash)[`"\']\s*,\s*\[\s*[`"\']-c[`"\']', "Command Injection - spawn shell -c"),
            # Windows cmd /c
            (r'\[\s*[`"\']cmd(?:\.exe)?[`"\']\s*,\s*[`"\']/[ck][`"\']', "Command Injection - Shell execution pattern [cmd, /c]"),
            (r'spawn\s*\(\s*[`"\']cmd(?:\.exe)?[`"\']\s*,\s*\[\s*[`"\']/[ck][`"\']', "Command Injection - spawn cmd /c"),
            # PowerShell
            (r'\[\s*[`"\']powershell(?:\.exe)?[`"\']\s*,\s*[`"\']-(?:Command|c)[`"\']', "Command Injection - Shell execution pattern [powershell]"),
        ]

        for i, line in enumerate(self.source_lines, 1):
            stripped = line.strip()
            if stripped.startswith('//') or stripped.startswith('/*'):
                continue

            # Check direct patterns
            for pattern, vuln_name in direct_patterns:
                if re.search(pattern, line):
                    has_taint = any(var in line for var in self.tainted_vars)
                    has_concat = '+' in line or '${' in line

                    if has_taint:
                        self._add_finding(i, f"{vuln_name} with user input",
                                          VulnCategory.COMMAND_INJECTION, Severity.CRITICAL, "HIGH",
                                          "User-controlled data in shell command.")
                    elif has_concat:
                        self._add_finding(i, vuln_name,
                                          VulnCategory.COMMAND_INJECTION, Severity.HIGH, "MEDIUM",
                                          "Shell command with dynamic string construction.")

            # Check evasion patterns
            for pattern, vuln_name in evasion_patterns:
                if re.search(pattern, line):
                    self._add_finding(i, vuln_name,
                                      VulnCategory.COMMAND_INJECTION, Severity.HIGH, "HIGH",
                                      "Command execution via evasion technique detected.")

            # Check shell execution patterns (sh -c, cmd /c)
            for pattern, vuln_name in shell_patterns:
                if re.search(pattern, line):
                    has_taint = any(var in line for var in self.tainted_vars)
                    if has_taint:
                        self._add_finding(i, f"{vuln_name} with user input",
                                          VulnCategory.COMMAND_INJECTION, Severity.CRITICAL, "HIGH",
                                          "Shell execution pattern with user-controlled command.")
                    else:
                        self._add_finding(i, vuln_name,
                                          VulnCategory.COMMAND_INJECTION, Severity.HIGH, "HIGH",
                                          "Shell execution pattern detected - equivalent to shell:true.")

            # Special: Check for spawn with shell option in context
            if re.search(r'\bspawn\s*\(', line):
                context = '\n'.join(self.source_lines[max(0, i-1):min(len(self.source_lines), i+3)])
                if re.search(r'shell\s*:\s*true', context):
                    self._add_finding(i, "Command Injection - spawn with shell:true",
                                      VulnCategory.COMMAND_INJECTION, Severity.HIGH, "HIGH",
                                      "spawn() with shell:true allows command injection.")

            # Check for exec/execSync with tainted variable arguments
            # Pattern: .exec(varName, ...) or .execSync(varName, ...)
            exec_var_match = re.search(r'\.exec(?:Sync)?\s*\(\s*(\w+)', line)
            if exec_var_match:
                arg_var = exec_var_match.group(1)
                # Check if the variable passed to exec is tainted
                if arg_var in self.tainted_vars:
                    self._add_finding(i, "Command Injection - exec with tainted variable",
                                      VulnCategory.COMMAND_INJECTION, Severity.CRITICAL, "HIGH",
                                      f"Tainted variable '{arg_var}' passed to shell execution function.")
                else:
                    # Check if this looks like a child_process usage
                    context = '\n'.join(self.source_lines[max(0, i-10):i+1])
                    if re.search(r'require\s*\(\s*["\']child_process["\']\s*\)', context):
                        # It's a child_process exec - check broader taint context
                        if any(var in context for var in self.tainted_vars):
                            self._add_finding(i, "Command Injection - exec with potentially tainted data",
                                              VulnCategory.COMMAND_INJECTION, Severity.HIGH, "MEDIUM",
                                              f"exec() called in context with tainted variables.")

            # === ADVANCED EVASION: Level 1 - "Lazy Property" Dynamic Method Invocation ===
            # Pattern: cp[method](parts.join(' ')) where method = 'ex' + 'ec'
            # Detects: string concatenation to build method names like 'ex' + 'ec' = 'exec'
            if re.search(r"['\"]ex['\"]?\s*\+\s*['\"]ec['\"]|['\"]exec['\"]\.split|'cexe'|'cnySexe'", line):
                self._add_finding(i, "Command Injection Evasion - Obfuscated 'exec' string construction",
                                  VulnCategory.COMMAND_INJECTION, Severity.CRITICAL, "HIGH",
                                  "String concatenation builds 'exec' method name to evade detection. "
                                  "Pattern: 'ex' + 'ec' = 'exec'")

            # Pattern: variable[method](...) where variable is child_process module
            bracket_method = re.search(r'(\w+)\s*\[\s*(\w+)\s*\]\s*\(', line)
            if bracket_method:
                obj_name = bracket_method.group(1)
                method_var = bracket_method.group(2)
                context = '\n'.join(self.source_lines[max(0, i-15):i+1])
                # Check if obj is child_process (cp, childProcess, proc, etc.)
                is_cp = re.search(rf'{obj_name}\s*=\s*require\s*\(\s*["\']child_process["\']\s*\)', context)
                if is_cp:
                    # Check if method variable was built from string concatenation
                    method_built = re.search(rf'{method_var}\s*=\s*["\'][^"\']*["\']\s*\+', context)
                    if method_built:
                        self._add_finding(i, "Command Injection Evasion - Dynamic method on child_process",
                                          VulnCategory.COMMAND_INJECTION, Severity.CRITICAL, "HIGH",
                                          f"child_process[{method_var}]() where method name is dynamically constructed. "
                                          "Attacker can invoke exec/execSync via string concatenation evasion.")
                    else:
                        self._add_finding(i, "Command Injection - Bracket notation on child_process module",
                                          VulnCategory.COMMAND_INJECTION, Severity.HIGH, "HIGH",
                                          f"Dynamic method invocation {obj_name}[{method_var}]() on child_process. "
                                          "Verify method name is not user-controlled.")

            # Pattern: .join(' ') flowing to exec - command built from array
            if re.search(r'\.join\s*\(\s*["\'][\s]*["\']\s*\)', line):
                context = '\n'.join(self.source_lines[i-1:min(len(self.source_lines), i+5)])
                if re.search(r'exec|spawn|child_process|\bcp\b', context, re.IGNORECASE):
                    self._add_finding(i, "Command Injection Evasion - Array.join() builds command string",
                                      VulnCategory.COMMAND_INJECTION, Severity.HIGH, "HIGH",
                                      "Array parts joined with space flows to command execution. "
                                      "Pattern: [bin, args].join(' ') -> exec()")

            # === ADVANCED EVASION: Level 3 - Worker Thread Escape ===
            # Pattern: new Worker(__filename, { workerData: userInput })
            if re.search(r'new\s+Worker\s*\(', line):
                has_taint = any(var in line for var in self.tainted_vars)
                if re.search(r'workerData\s*:', line) and has_taint:
                    self._add_finding(i, "Command Injection Evasion - Tainted data passed to Worker thread",
                                      VulnCategory.COMMAND_INJECTION, Severity.CRITICAL, "HIGH",
                                      "User-controlled data passed via workerData to Worker thread. "
                                      "If worker uses execSync(workerData), this enables RCE. "
                                      "Cross-thread taint flow detected.")
                elif re.search(r'workerData\s*:', line):
                    self._add_finding(i, "Potential Command Injection - Data passed to Worker thread",
                                      VulnCategory.COMMAND_INJECTION, Severity.MEDIUM, "MEDIUM",
                                      "Data passed to Worker via workerData. Verify worker doesn't execute it as command.")

            # Pattern: execSync(workerData) in worker thread context
            if re.search(r'exec(?:Sync)?\s*\(\s*workerData\s*\)', line):
                self._add_finding(i, "Command Injection - Worker thread executes workerData",
                                  VulnCategory.COMMAND_INJECTION, Severity.CRITICAL, "HIGH",
                                  "Worker thread executes workerData as shell command. "
                                  "If workerData comes from user input in main thread, this is RCE.")

            # === ADVANCED EVASION: Level 4 - toString/valueOf Hijack (Implicit Execution) ===
            # Pattern: toString: function() { return execSync(input) }
            if re.search(r'toString\s*:\s*function\s*\(', line) or re.search(r'toString\s*:\s*\(\s*\)\s*=>', line):
                context = '\n'.join(self.source_lines[i-1:min(len(self.source_lines), i+5)])
                if re.search(r'exec|spawn|child_process|require\s*\(\s*["\']child_process', context):
                    self._add_finding(i, "Command Injection Evasion - Hijacked toString() executes commands",
                                      VulnCategory.COMMAND_INJECTION, Severity.CRITICAL, "HIGH",
                                      "toString() method contains command execution. "
                                      "Any string coercion (concatenation, template literal, console.log) triggers RCE. "
                                      "Pattern: 'Status: ' + obj triggers obj.toString() -> execSync()")

            # Pattern: valueOf hijack
            if re.search(r'valueOf\s*:\s*function\s*\(', line) or re.search(r'valueOf\s*:\s*\(\s*\)\s*=>', line):
                context = '\n'.join(self.source_lines[i-1:min(len(self.source_lines), i+5)])
                if re.search(r'exec|spawn|child_process|require\s*\(\s*["\']child_process', context):
                    self._add_finding(i, "Command Injection Evasion - Hijacked valueOf() executes commands",
                                      VulnCategory.COMMAND_INJECTION, Severity.CRITICAL, "HIGH",
                                      "valueOf() method contains command execution. "
                                      "Numeric coercion triggers command execution.")

            # Pattern: [Symbol.toPrimitive] hijack
            if re.search(r'\[Symbol\.toPrimitive\]', line):
                context = '\n'.join(self.source_lines[i-1:min(len(self.source_lines), i+5)])
                if re.search(r'exec|spawn|child_process', context):
                    self._add_finding(i, "Command Injection Evasion - Hijacked Symbol.toPrimitive executes commands",
                                      VulnCategory.COMMAND_INJECTION, Severity.CRITICAL, "HIGH",
                                      "Symbol.toPrimitive hijacked with command execution. "
                                      "Type coercion triggers shell command.")

    def _check_sql_injection(self):
        """Check for SQL injection patterns - including evasion techniques."""
        # SQL keywords must be word-bounded to avoid matching 'select-text-' or 'update-btn'
        sql_keywords = r'(?:\bSELECT\b|\bINSERT\b|\bUPDATE\b|\bDELETE\b|\bDROP\b|\bCREATE\b|\bALTER\b|\bTRUNCATE\b|\bUNION\b|\bORDER\s+BY\b|\bGROUP\s+BY\b)'

        # Patterns that indicate UI/DOM strings, not SQL
        ui_false_positive_patterns = [
            r'aria-',           # ARIA attributes
            r'data-',           # Data attributes
            r'class[=:]',       # CSS classes
            r'id[=:]',          # Element IDs
            r'-text-',          # UI text identifiers
            r'-btn-',           # Button identifiers
            r'-icon-',          # Icon identifiers
            r'locale',          # i18n/locale messages
            r'moment\.',        # Moment.js
            r'\.css\(',         # CSS manipulation
            r'\.addClass\(',    # jQuery class manipulation
            r'\.attr\(',        # Attribute manipulation
        ]

        # === CRITICAL: Browser/Frontend patterns that are NOT SQL (false positives) ===
        browser_false_positive_patterns = [
            r'\balert\s*\(',               # JavaScript alert() dialog
            r'\bconfirm\s*\(',             # JavaScript confirm() dialog
            r'\bprompt\s*\(',              # JavaScript prompt() dialog
            r'\bconsole\.\w+\s*\(',        # console.log/warn/error
            r'\bfetch\s*\(',               # fetch() API calls
            r'\baxios\.',                  # Axios HTTP client
            r'API_URL',                    # API URL constants
            r'BASE_URL',                   # Base URL constants
            r'/api/',                      # API route patterns
            r'/music/',                    # REST API routes
            r'/user/',                     # REST API routes
            r'/album/',                    # REST API routes
            r'deleteWithCsrfToken',        # CSRF token functions
            r'postWithCsrfToken',          # CSRF token functions
            r'putWithCsrfToken',           # CSRF token functions
            r'window\.location',           # Browser location
            r'window\.open',               # Browser open
            r'href\s*=',                   # HTML href attributes
            r'src\s*=',                    # HTML src attributes
            r'<Link',                      # React Link components
            r'<a\s',                       # HTML anchor tags
            r'router\.',                   # Router navigation
            r'navigate\s*\(',              # Navigation calls
            r'redirect\s*\(',              # Redirect calls
            r'\.push\s*\(\s*[`"\'/]',      # Router push with path
            r'\.replace\s*\(\s*[`"\'/]',   # Router replace with path
            r'Error:',                     # Error messages
            r'error:',                     # Error messages
            r'\.toString\s*\(',            # String conversion
            r'JSON\.stringify',            # JSON serialization
            # === Additional patterns for error messages and UI ===
            r'toast\.',                    # Toast notifications (toast.error, toast.success)
            r'toast\s*\(',                 # Toast function calls
            r'\.error\s*\(',               # Error method calls
            r'\.warning\s*\(',             # Warning method calls
            r'\.success\s*\(',             # Success notifications
            r'\.info\s*\(',                # Info notifications
            r'className\s*=',              # React/JSX className (CSS classes)
            r'class\s*=',                  # HTML class attribute
            r'Failed to',                  # Error message text
            r'Cannot ',                    # Error message text
            r'Unable to',                  # Error message text
            r'Error\s*\(',                 # Error constructor
            r'new\s+Error\s*\(',           # new Error()
            r'throw\s+',                   # throw statement
            r'AppError\s*\(',              # Custom error classes
            r'\.message\s*=',              # Setting error message
            r'response\.status',           # HTTP response status
            r'status\s*:',                 # Status property
            r'<h[1-6]',                    # HTML headings (not SQL)
            r'<p\s',                       # HTML paragraph (not SQL)
            r'<div',                       # HTML div (not SQL)
            r'<span',                      # HTML span (not SQL)
            r'truncate',                   # CSS class (often misdetected as SQL TRUNCATE)
        ]

        for i, line in enumerate(self.source_lines, 1):
            stripped = line.strip()
            if stripped.startswith('//') or stripped.startswith('/*'):
                continue

            # Direct string concatenation with SQL
            if re.search(rf'["\'][^"\']*{sql_keywords}[^"\']*["\']\s*\+', line, re.IGNORECASE):
                # Skip if line contains UI/DOM patterns (false positives)
                is_ui_pattern = any(re.search(pat, line, re.IGNORECASE) for pat in ui_false_positive_patterns)
                # Skip browser/frontend patterns
                is_browser_pattern = any(re.search(pat, line, re.IGNORECASE) for pat in browser_false_positive_patterns)

                # === CRITICAL: Skip static-only string concatenation ===
                # 'GROUP_CONCAT' + '(' + 'path.name'... = ALL string literals, no variables
                # Pattern: only has '+' between quoted strings (no variables)
                static_concat_pattern = re.compile(r"^[^=]*=\s*(?:['\"][^'\"]*['\"]\s*\+\s*)+['\"][^'\"]*['\"]")
                is_static_only = static_concat_pattern.search(line)

                # Also check if concatenation only involves quoted strings and no variables
                # Count string literals vs potential variables
                parts = re.split(r'\s*\+\s*', line)
                non_string_parts = [p for p in parts if not re.match(r"^\s*['\"].*['\"]\s*$", p.strip())]
                # If most parts are strings and the non-string parts are just the assignment, it's static
                is_mostly_static = len([p for p in parts if re.match(r"^\s*['\"]", p.strip())]) >= len(parts) - 1

                if not is_ui_pattern and not is_browser_pattern and not is_static_only and not is_mostly_static:
                    self._add_finding(i, "SQL Injection - String concatenation",
                                      VulnCategory.SQL_INJECTION, Severity.HIGH, "HIGH",
                                      "SQL query uses string concatenation.")

            # Template literals with SQL
            if re.search(rf'`[^`]*{sql_keywords}[^`]*\$\{{', line, re.IGNORECASE):
                # Exclude false positives: crypto operations, logging, string formatting
                false_positive_patterns = [
                    r'cipher\.|decipher\.|crypto\.',     # Crypto operations
                    r'\.update\s*\([^)]*,\s*["\'](?:utf8|hex|base64)["\']',  # Cipher update
                    r'\.final\s*\(["\'](?:hex|base64|utf8)["\']',  # Cipher final
                    r'console\.|logger\.|log\.',         # Logging
                    r'\.toString\s*\(',                  # Type conversion
                ]
                is_false_positive = any(re.search(pat, line, re.IGNORECASE) for pat in false_positive_patterns)
                # Also check browser/frontend patterns
                is_browser_pattern = any(re.search(pat, line, re.IGNORECASE) for pat in browser_false_positive_patterns)
                # Also check UI patterns
                is_ui_pattern = any(re.search(pat, line, re.IGNORECASE) for pat in ui_false_positive_patterns)

                # === CRITICAL: Skip numeric literal interpolation ===
                # ${1} or ${0} - hardcoded numbers, not user input
                numeric_interp_pattern = re.compile(r'\$\{\s*\d+\s*\}')
                has_only_numeric = numeric_interp_pattern.search(line)
                # Check if ALL interpolations are numeric
                all_interps = re.findall(r'\$\{([^}]+)\}', line)
                all_numeric = all(re.match(r'^\s*\d+\s*$', interp) for interp in all_interps) if all_interps else False

                # === CRITICAL: Skip migration files with hardcoded values ===
                is_migration = 'migration' in self.file_path.lower()
                context = '\n'.join(self.source_lines[max(0, i-3):i])
                is_hardcoded_migration = is_migration and re.search(r'queryRunner\.query', context)

                # === CRITICAL: Skip test files with test fixture data ===
                # Test files often have SQL with ${user.email} etc from test fixtures
                is_test_file = any(p in self.file_path.lower() for p in [
                    '/test/', '/__tests__/', '.spec.', '.test.', '/tests/',
                    'integration-tests', 'unit-tests', 'e2e-tests'
                ])
                # Check if interpolations are from test fixtures (user, admin, customer, etc)
                test_fixture_pattern = re.compile(r'\$\{(?:user|admin|customer|order|product|test|mock|fixture)\w*\.', re.IGNORECASE)
                is_test_fixture_data = is_test_file and test_fixture_pattern.search(line)

                # Check if this is a tagged template literal (sql`...`, gql`...`, etc.)
                # Tagged templates are handled separately below with appropriate confidence levels
                tagged_match = re.search(r'(\w+)\s*`', line)
                is_tagged = tagged_match and tagged_match.group(1).lower() not in ['const', 'let', 'var', 'return', 'function', 'if', 'else', 'for', 'while']

                if not is_false_positive and not is_browser_pattern and not is_ui_pattern and not all_numeric and not is_hardcoded_migration and not is_test_fixture_data and not is_tagged:
                    self._add_finding(i, "SQL Injection - Template literal",
                                      VulnCategory.SQL_INJECTION, Severity.HIGH, "HIGH",
                                      "SQL query uses template literal interpolation.")

            # Tagged template literals (sql`...`, SQL`...`, gql`...`, etc.)
            # These are generally safer than regular template literals because the tag function
            # typically handles parameterization (e.g., sql-template-strings, slonik, postgres.js)
            # Also includes non-SQL tags like gql, graphql, html, css that shouldn't flag as SQL
            tagged_template_match = re.search(rf'(\w+)\s*`[^`]*{sql_keywords}', line, re.IGNORECASE)
            if tagged_template_match:
                tag_name = tagged_template_match.group(1).lower()
                # Safe tagged template libraries/tags that handle parameterization
                safe_sql_tags = ['sql', 'prisma', 'knex', 'slonik', 'pg', 'postgres', 'mysql', 'sequelize', 'raw']
                # Non-SQL tags that should be skipped entirely (false positives)
                # gql/graphql may have SELECT-like keywords but aren't SQL
                # html/css may have keywords that look like SQL but aren't
                non_sql_tags = ['gql', 'graphql', 'html', 'css', 'styled', 'jsx', 'tsx', 'markdown', 'md']
                if tag_name in non_sql_tags:
                    continue  # Skip - not SQL, these are other template literal types
                elif tag_name in safe_sql_tags:
                    # Lower confidence - tagged templates usually handle escaping
                    self._add_finding(i, "SQL Injection - Tagged template literal (likely safe)",
                                      VulnCategory.SQL_INJECTION, Severity.MEDIUM, "LOW",
                                      f"SQL via tagged template '{tag_name}`...`. Tagged templates often handle "
                                      "parameterization safely. Verify the tag function escapes properly.")
                else:
                    self._add_finding(i, "SQL Injection - Tagged template literal",
                                      VulnCategory.SQL_INJECTION, Severity.MEDIUM, "MEDIUM",
                                      "SQL via tagged template. Verify the tag function handles escaping.")

            # Array.join() to build SQL (evasion technique)
            # Only flag if there's actual SQL execution context, not just DOM selectors
            if re.search(r'\.join\s*\(', line):
                context = '\n'.join(self.source_lines[max(0, i-5):i+1])
                # Must have SQL execution sink (execute, query, prepare) not just keywords
                sql_exec_pattern = r'\.(?:execute|query|prepare|raw|sql)\s*\('
                # Exclude DOM/CSS selector patterns
                dom_selector_pattern = r'\.(find|closest|querySelector|querySelectorAll|filter|children)\s*\('
                if re.search(sql_exec_pattern, context, re.IGNORECASE) and \
                   not re.search(dom_selector_pattern, context, re.IGNORECASE):
                    self._add_finding(i, "SQL Injection - Array.join() query construction",
                                      VulnCategory.SQL_INJECTION, Severity.HIGH, "HIGH",
                                      "SQL query built via Array.join() - evasion technique.")

            # String.concat() for SQL (evasion technique)
            # Only flag if there's actual SQL execution context
            if re.search(r'\.concat\s*\(', line):
                context = '\n'.join(self.source_lines[max(0, i-3):i+1])
                sql_exec_pattern = r'\.(?:execute|query|prepare|raw|sql)\s*\('
                # Exclude array/DOM manipulation patterns
                array_pattern = r'\[\s*\]\.concat|\.toArray\(\)|\.push\(|\.slice\('
                if (re.search(sql_exec_pattern, context, re.IGNORECASE) or re.search(r'\bsql\b', context, re.IGNORECASE)) and \
                   not re.search(array_pattern, context, re.IGNORECASE):
                    self._add_finding(i, "SQL Injection - String.concat() query construction",
                                      VulnCategory.SQL_INJECTION, Severity.HIGH, "HIGH",
                                      "SQL query built via String.concat() - evasion technique.")

            # Query method with tainted variable
            if re.search(r'\.query\s*\(\s*(?!["\'])', line):
                for var in self.tainted_vars:
                    if var in line:
                        self._add_finding(i, "SQL Injection - query() with variable",
                                          VulnCategory.SQL_INJECTION, Severity.HIGH, "MEDIUM",
                                          "Query method called with variable. Use parameterized queries.")
                        break

            # String reduction building SQL
            if re.search(r'\.reduce\s*\(', line):
                context = '\n'.join(self.source_lines[max(0, i-3):min(len(self.source_lines), i+3)])
                # Only flag if reduce is building SQL strings (not just data grouping)
                is_sql_building = (
                    re.search(sql_keywords, context, re.IGNORECASE) and
                    re.search(r'(?:query|sql|statement)\s*[\+\+=]|\+\s*["\']', context, re.IGNORECASE)
                )
                # Skip common data manipulation patterns
                safe_reduce_patterns = [
                    r'objectsByKeyValue',             # Data grouping
                    r'groupBy|keyBy',                 # Lodash grouping
                    r'\.concat\(',                    # Array concat
                    r'acc\s*\[\s*\w+\s*\]',           # Object building with keys
                    r'order|sort',                    # Sort/order operations
                ]
                is_safe_reduce = any(re.search(pat, context, re.IGNORECASE) for pat in safe_reduce_patterns)

                if is_sql_building and not is_safe_reduce:
                    self._add_finding(i, "SQL Injection - reduce() query construction",
                                      VulnCategory.SQL_INJECTION, Severity.MEDIUM, "MEDIUM",
                                      "SQL query potentially built via reduce().")

    def _check_deserialization(self):
        """Check for deserialization vulnerabilities - including evasion techniques."""
        critical_patterns = [
            # node-serialize (known RCE)
            (r'serialize\.unserialize\s*\(', "Insecure Deserialization - node-serialize.unserialize"),
            (r'require\s*\(\s*["\']node-serialize["\']', "Insecure Deserialization - node-serialize import"),
            (r'\.unserialize\s*\(', "Insecure Deserialization - unserialize call"),
        ]

        high_patterns = [
            # js-yaml unsafe load
            (r'yaml\s*\.\s*load\s*\(', "Insecure Deserialization - yaml.load (use safeLoad)"),
            (r'yaml\s*\.\s*loadAll\s*\(', "Insecure Deserialization - yaml.loadAll"),
            (r'DEFAULT_FULL_SCHEMA|DEFAULT_SCHEMA', "Insecure Deserialization - yaml unsafe schema"),
            (r'js-yaml.*(?:load|loadAll)\s*\(', "Insecure Deserialization - js-yaml load"),
            # Other deserializers
            (r'jsonwebtoken.*\.decode\s*\(', "Insecure Deserialization - JWT decode without verify"),
            (r'flatted\s*\.\s*parse\s*\(', "Insecure Deserialization - flatted.parse"),
            (r'v8\s*\.\s*deserialize\s*\(', "Insecure Deserialization - v8.deserialize"),
            (r'BSON\s*\.\s*deserialize\s*\(', "Insecure Deserialization - BSON.deserialize"),
        ]

        for i, line in enumerate(self.source_lines, 1):
            stripped = line.strip()
            if stripped.startswith('//') or stripped.startswith('/*'):
                continue

            for pattern, vuln_name in critical_patterns:
                if re.search(pattern, line):
                    self._add_finding(i, vuln_name,
                                      VulnCategory.DESERIALIZATION, Severity.CRITICAL, "HIGH",
                                      "Known vulnerable deserialization - RCE possible.")

            for pattern, vuln_name in high_patterns:
                if re.search(pattern, line):
                    # Skip yaml.load with SAFE_SCHEMA - this is safe usage
                    if 'yaml' in vuln_name.lower() and 'load' in vuln_name.lower():
                        # Check for safe schema patterns: yaml.load(data, { schema: yaml.SAFE_SCHEMA })
                        # or yaml.load(data, { schema: SAFE_SCHEMA })
                        # or yaml.load(data, options) where options contains SAFE_SCHEMA
                        safe_yaml_patterns = [
                            r'SAFE_SCHEMA',          # yaml.SAFE_SCHEMA or SAFE_SCHEMA constant
                            r'JSON_SCHEMA',          # JSON_SCHEMA is also safe
                            r'FAILSAFE_SCHEMA',      # FAILSAFE_SCHEMA is safe
                            r'safeLoad',             # Using safeLoad function instead
                            r'schema\s*:\s*[\'"]?safe',  # schema: 'safe' or similar
                        ]
                        if any(re.search(safe_pat, line, re.IGNORECASE) for safe_pat in safe_yaml_patterns):
                            continue  # Skip - this is safe
                    self._add_finding(i, vuln_name,
                                      VulnCategory.DESERIALIZATION, Severity.HIGH, "HIGH",
                                      "Unsafe deserialization detected.")

    def _check_ssti(self):
        """Check for SSTI patterns - including evasion techniques."""
        # Patterns where template source is user-controlled
        critical_patterns = [
            # EJS
            (r'ejs\s*\.\s*render\s*\(\s*(?!.*["\'])', "SSTI - EJS render with variable template"),
            (r'ejs\s*\.\s*compile\s*\(\s*(?!.*["\'])', "SSTI - EJS compile with variable"),
            # Pug/Jade
            (r'pug\s*\.\s*render\s*\(\s*(?!.*["\'])', "SSTI - Pug render with variable"),
            (r'pug\s*\.\s*compile\s*\(\s*(?!.*["\'])', "SSTI - Pug compile with variable"),
            (r'jade\s*\.\s*render\s*\(', "SSTI - Jade render"),
            # Handlebars - only flag if first arg is NOT a string literal
            (r'handlebars\s*\.\s*compile\s*\(\s*(?!["\'])', "SSTI - Handlebars compile with variable"),
            (r'Handlebars\s*\.\s*compile\s*\(\s*(?!["\'])', "SSTI - Handlebars.compile with variable"),
            # Nunjucks
            (r'nunjucks\s*\.\s*renderString\s*\(', "SSTI - Nunjucks renderString"),
            (r'nunjucks\s*\.\s*compile\s*\(', "SSTI - Nunjucks compile"),
            # Mustache
            (r'Mustache\s*\.\s*render\s*\(\s*(?!.*["\'])', "SSTI - Mustache render with variable"),
            # doT
            (r'doT\s*\.\s*template\s*\(', "SSTI - doT.template"),
            # Generic
            (r'\.render\s*\(\s*(?:req\.|user|input|template)', "SSTI - render with user input"),
            (r'\.compile\s*\(\s*(?:req\.|user|input|template)', "SSTI - compile with user input"),
        ]

        for i, line in enumerate(self.source_lines, 1):
            stripped = line.strip()
            if stripped.startswith('//') or stripped.startswith('/*'):
                continue

            for pattern, vuln_name in critical_patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    # Check if this is with user-controlled template
                    has_param = bool(self.tainted_vars & set(line.split()))
                    has_req = 'req.' in line or 'request.' in line
                    has_user_input = re.search(r'(?:user|input|body|query|params)\.', line, re.IGNORECASE)

                    # Safe patterns - app-defined templates (not user controlled)
                    safe_template_patterns = [
                        r'(?:this|self)\.\w*[Tt]emplate',    # this.template, self.tableTemplate
                        r'[Tt]emplate[A-Z]\w*',              # templateHtml, TemplateString (camelCase named templates)
                        r'\w+[Tt]emplate\s*[,\)]',           # fooTemplate, barTemplate (as variable)
                        r'["\'][^"\']+\.(?:html|hbs|mustache)["\']',  # file path strings
                    ]
                    is_safe_template = any(re.search(pat, line) for pat in safe_template_patterns)

                    if has_param or has_req or has_user_input:
                        self._add_finding(i, f"{vuln_name} with user input",
                                          VulnCategory.SSTI, Severity.CRITICAL, "HIGH",
                                          "Template engine rendering user-controlled template - RCE possible.")
                    elif not is_safe_template:
                        # Only flag if it doesn't look like an app-defined template
                        # and there's some indication of dynamic content
                        context = '\n'.join(self.source_lines[max(0, i-5):i])
                        # Check if template comes from user/dynamic source in context
                        dynamic_source = re.search(
                            r'(?:=\s*(?:req|request|user|input|body|query|params)\.|'
                            r'function\s*\([^)]*template[^)]*\)|'
                            r'template\s*=\s*\w+\s*\|\||'  # template = x || y (dynamic fallback)
                            r'getTemplate\s*\()',  # dynamic template getter
                            context, re.IGNORECASE
                        )
                        if dynamic_source:
                            self._add_finding(i, vuln_name,
                                              VulnCategory.SSTI, Severity.HIGH, "MEDIUM",
                                              "Template compilation/rendering with variable. Verify source.")

    def _check_nosql_injection(self):
        """Check for NoSQL injection patterns - including evasion techniques."""
        # High confidence patterns - direct user input in query
        high_confidence_patterns = [
            (r'\.find\s*\(\s*\{[^}]*:\s*req\.(?:body|query|params|cookies)', "NoSQL Injection - MongoDB find with request"),
            (r'\.findOne\s*\(\s*\{[^}]*:\s*req\.(?:body|query|params|cookies)', "NoSQL Injection - MongoDB findOne with request"),
            (r'\$where\s*:\s*(?:req\.|user|input|\w+\s*\+)', "NoSQL Injection - $where with user input"),
            (r'\$regex\s*:\s*req\.', "NoSQL Injection - $regex with request data"),
            # Evasion: Dynamic object key from user input
            (r'query\s*\[\s*\w+\s*\]\s*=', "NoSQL Injection - Dynamic query key assignment"),
            (r'\[\s*field\s*\]\s*=|\[\s*operator\s*\]\s*=', "NoSQL Injection - Dynamic field/operator"),
        ]

        # MongoDB operators - only flag if value is NOT a hardcoded literal
        # Pattern: $ne: <something> where <something> is not true/false/null/number/string literal
        operator_with_taint_patterns = [
            # $operator: variable (not literal)
            (r'\$(?:gt|gte|lt|lte|ne|in|nin)\s*:\s*(?:req\.|user\.|input\.|body\.|query\.|params\.)', "NoSQL Injection - MongoDB operator with user input"),
            # $operator: variable name (check if tainted)
            (r'\$(?:gt|gte|lt|lte|ne|in|nin)\s*:\s*([a-zA-Z_]\w*)\s*[,}\]]', "NoSQL Injection - MongoDB operator with variable"),
        ]

        # Evasion patterns that use template literals or computed keys
        evasion_patterns = [
            # Template literal to construct operator: [`${op}`] or `$${name}`
            (r'\[\s*`\$\{[^}]+\}`\s*\]', "NoSQL Injection - Template literal operator construction"),
            (r'`\$\$\{[^}]+\}`', "NoSQL Injection - Template literal MongoDB operator"),
            (r'\[\s*`[^`]*\$[^`]*`\s*\]', "NoSQL Injection - Template literal with $ in computed key"),
            # Computed key with variable that could be operator: [key]: { ... }
            (r'\[\s*\w+\s*\]\s*:\s*\{', "NoSQL Injection - Computed property in query object"),
            # Variable assignment of MongoDB operators
            (r'(?:const|let|var)\s+\w+\s*=\s*["\']?\$(?:ne|gt|gte|lt|lte|in|nin|or|and|not|regex)', "NoSQL Injection - MongoDB operator in variable"),
        ]

        # Safe literal patterns - these are NOT injection
        safe_value_pattern = re.compile(r'\$(?:gt|gte|lt|lte|ne|in|nin|or|and|not|nor|exists|type)\s*:\s*(?:true|false|null|undefined|\d+|["\'][^"\']*["\']|\[[\s\d,"\'-]*\])\s*[,}\]]')

        for i, line in enumerate(self.source_lines, 1):
            stripped = line.strip()
            if stripped.startswith('//') or stripped.startswith('/*'):
                continue

            # High confidence patterns - always flag
            for pattern, vuln_name in high_confidence_patterns:
                if re.search(pattern, line):
                    self._add_finding(i, vuln_name,
                                      VulnCategory.NOSQL_INJECTION, Severity.HIGH, "HIGH",
                                      "Potential NoSQL injection vulnerability.")

            # Operator patterns - check if value is tainted, not hardcoded
            for pattern, vuln_name in operator_with_taint_patterns:
                match = re.search(pattern, line)
                if match:
                    # Skip if value is a safe literal
                    if safe_value_pattern.search(line):
                        continue
                    # Check if the variable (if captured) is tainted
                    if match.lastindex and match.lastindex >= 1:
                        var_name = match.group(1)
                        if var_name in self.tainted_vars:
                            self._add_finding(i, vuln_name,
                                              VulnCategory.NOSQL_INJECTION, Severity.HIGH, "HIGH",
                                              f"MongoDB operator with tainted variable '{var_name}'.")
                    else:
                        self._add_finding(i, vuln_name,
                                          VulnCategory.NOSQL_INJECTION, Severity.HIGH, "HIGH",
                                          "Potential NoSQL injection vulnerability.")

            # Check evasion patterns
            for pattern, vuln_name in evasion_patterns:
                if re.search(pattern, line):
                    context = '\n'.join(self.source_lines[max(0, i-5):min(len(self.source_lines), i+5)])
                    # Must be near a database operation
                    has_db_context = re.search(
                        r'\.find\s*\(|\.findOne\s*\(|\.aggregate\s*\(|\.updateOne\s*\(|'
                        r'\.updateMany\s*\(|\.deleteOne\s*\(|\.deleteMany\s*\(|'
                        r'collection\s*\(|\.db\.|query\s*=|Query\s*\(',
                        context, re.IGNORECASE
                    )
                    if has_db_context:
                        self._add_finding(i, vuln_name,
                                          VulnCategory.NOSQL_INJECTION, Severity.HIGH, "HIGH",
                                          "NoSQL injection via operator evasion technique.")

    def _check_dangerous_functions(self):
        """Check for dangerous functions that could lead to RCE."""
        # RCE vectors
        rce_patterns = [
            # vm module
            (r'vm\.runInContext\s*\(', "RCE - vm.runInContext", Severity.CRITICAL),
            (r'vm\.runInNewContext\s*\(', "RCE - vm.runInNewContext", Severity.CRITICAL),
            (r'vm\.runInThisContext\s*\(', "RCE - vm.runInThisContext", Severity.CRITICAL),
            (r'vm\.compileFunction\s*\(', "RCE - vm.compileFunction", Severity.HIGH),
            (r'new\s+vm\.Script\s*\(', "RCE - vm.Script constructor", Severity.HIGH),
            # Process spawn variants
            (r'child_process\.fork\s*\(', "RCE - child_process.fork", Severity.HIGH),
            (r'child_process\.execFile\s*\(', "RCE - child_process.execFile", Severity.HIGH),
            (r'child_process\.spawnSync\s*\(', "RCE - child_process.spawnSync", Severity.HIGH),
            # Worker threads
            (r'new\s+Worker\s*\(', "RCE - Worker thread", Severity.MEDIUM),
            # Shell execution
            (r'shelljs\.exec\s*\(', "RCE - shelljs.exec", Severity.HIGH),
            (r'execa\s*\(', "RCE - execa", Severity.MEDIUM),
            # Require with variable
            (r'require\s*\(\s*[^"\'\s]', "RCE - Dynamic require", Severity.HIGH),
            # Import with variable
            (r'import\s*\(\s*[^"\'\s]', "RCE - Dynamic import", Severity.HIGH),
            # Prototype access for gadget chains
            (r'Function\s*\(\s*["\']return\s+this', "RCE - Function constructor sandbox escape", Severity.CRITICAL),
        ]

        for i, line in enumerate(self.source_lines, 1):
            stripped = line.strip()
            if stripped.startswith('//') or stripped.startswith('/*'):
                continue

            for pattern, vuln_name, severity in rce_patterns:
                if re.search(pattern, line):
                    has_taint = any(var in line for var in self.tainted_vars)
                    has_req = 'req.' in line or 'request.' in line
                    has_dynamic = '${' in line or '+' in line

                    if has_taint or has_req:
                        self._add_finding(i, f"{vuln_name} with user input",
                                          VulnCategory.CODE_INJECTION, Severity.CRITICAL, "HIGH",
                                          "User-controlled data in code execution context.")
                    elif has_dynamic:
                        self._add_finding(i, vuln_name,
                                          VulnCategory.CODE_INJECTION, severity, "MEDIUM",
                                          "Dynamic code execution detected. Verify input source.")

    def _check_callback_sinks(self):
        """Check for vulnerabilities in callback/arrow function patterns."""
        # Track arrow functions and callbacks that contain sinks
        callback_sink_patterns = [
            # Arrow functions with dangerous operations
            (r'=>\s*\{[^}]*(?:exec|eval|Function)\s*\(', "Callback with code execution"),
            (r'=>\s*\{[^}]*fs\.\w+\s*\(', "Callback with file operation"),
            (r'=>\s*\{[^}]*child_process', "Callback with child_process"),
            # forEach/map/filter with dangerous operations
            (r'\.forEach\s*\([^)]*=>\s*\{[^}]*(?:exec|eval)', "forEach callback with code execution"),
            (r'\.map\s*\([^)]*=>\s*\{[^}]*(?:exec|eval)', "map callback with code execution"),
            # Promise handlers with sinks
            (r'\.then\s*\([^)]*=>\s*\{[^}]*(?:exec|eval|unserialize)', "Promise handler with dangerous operation"),
            (r'\.catch\s*\([^)]*=>\s*\{[^}]*(?:exec|eval)', "Error handler with code execution"),
        ]

        for i, line in enumerate(self.source_lines, 1):
            stripped = line.strip()
            if stripped.startswith('//') or stripped.startswith('/*'):
                continue

            for pattern, vuln_name in callback_sink_patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    # Check broader context for taint flow
                    context_start = max(0, i - 5)
                    context = '\n'.join(self.source_lines[context_start:i + 3])

                    has_taint = any(var in context for var in self.tainted_vars)
                    has_req = re.search(r'req\.(body|query|params)', context)

                    if has_taint or has_req:
                        self._add_finding(i, f"Tainted {vuln_name}",
                                          VulnCategory.CODE_INJECTION, Severity.HIGH, "MEDIUM",
                                          "User input may flow into callback containing dangerous operation.")

    def _check_xxe(self):
        """Check for XXE vulnerabilities in JavaScript XML parsing - including evasion techniques."""
        # Critical: Known vulnerable configurations
        critical_patterns = [
            # libxmljs with dangerous options explicitly enabled
            (r'libxml.*\{[^}]*noent\s*:\s*true', "XXE - libxmljs with noent:true"),
            (r'libxml.*\{[^}]*dtdload\s*:\s*true', "XXE - libxmljs with dtdload:true"),
            # xmldom with external resolution
            (r'DOMParser\s*\(\s*\{[^}]*resolveExternals\s*:\s*true', "XXE - xmldom resolveExternals enabled"),
            (r'DOMParser\s*\(\s*\{[^}]*loadExternalSubset\s*:\s*true', "XXE - xmldom loadExternalSubset enabled"),
            # fast-xml-parser with DTD
            (r'XMLParser\s*\(\s*\{[^}]*allowDtd\s*:\s*true', "XXE - XMLParser allowDtd enabled"),
            (r'XMLParser\s*\(\s*\{[^}]*processEntities\s*:\s*true', "XXE - XMLParser processEntities enabled"),
        ]

        # High: Potentially vulnerable parsers
        high_patterns = [
            # libxmljs (needs secure config)
            (r'libxml(?:js)?\s*\.\s*parseXml(?:String)?\s*\(', "XXE - libxmljs.parseXml"),
            # xmldom (specific xmldom module, not browser DOMParser)
            (r'new\s+xmldom\s*\.\s*DOMParser\s*\(', "XXE - xmldom DOMParser"),
            (r'require\s*\(["\']xmldom["\']\)', "XXE - xmldom import"),
            # xml2js
            (r'xml2js\s*\.\s*parseString\s*\(', "XXE - xml2js.parseString"),
            (r'new\s+xml2js\s*\.\s*Parser\s*\(', "XXE - xml2js.Parser"),
            # sax parser
            (r'sax\s*\.\s*parser\s*\(', "XXE - sax parser"),
            # parseFromString with XML MIME type only (not text/html)
            (r'\.parseFromString\s*\([^,]+,\s*["\'](?:text|application)/xml', "XXE - parseFromString with XML"),
            # NOTE: Removed generic DOMParser pattern - browser DOMParser with text/html is safe
            # XXE is only a risk when parsing XML, not HTML
        ]

        for i, line in enumerate(self.source_lines, 1):
            stripped = line.strip()
            if stripped.startswith('//') or stripped.startswith('/*'):
                continue

            # Check critical patterns - explicit dangerous config
            for pattern, vuln_name in critical_patterns:
                if re.search(pattern, line):
                    self._add_finding(i, vuln_name,
                                      VulnCategory.XXE, Severity.CRITICAL, "HIGH",
                                      "XML parser explicitly configured with dangerous options - XXE likely.")

            # Check high patterns
            for pattern, vuln_name in high_patterns:
                if re.search(pattern, line):
                    # Check context for dangerous options
                    context = '\n'.join(self.source_lines[max(0, i-2):min(len(self.source_lines), i+5)])

                    # Look for dangerous options
                    has_dangerous = re.search(
                        r'noent\s*:\s*true|dtdload\s*:\s*true|dtdvalid\s*:\s*true|'
                        r'resolveExternals\s*:\s*true|loadExternalSubset\s*:\s*true|'
                        r'allowDtd\s*:\s*true|processEntities\s*:\s*true',
                        context
                    )

                    # Look for secure options
                    has_secure = re.search(
                        r'noent\s*:\s*false|dtdload\s*:\s*false|'
                        r'resolveExternals\s*:\s*false|allowDtd\s*:\s*false',
                        context
                    )

                    if has_dangerous:
                        self._add_finding(i, f"{vuln_name} with dangerous options",
                                          VulnCategory.XXE, Severity.HIGH, "HIGH",
                                          "XML parser with external entity processing enabled.")
                    elif not has_secure:
                        self._add_finding(i, vuln_name,
                                          VulnCategory.XXE, Severity.MEDIUM, "MEDIUM",
                                          "XML parser without explicit secure configuration.")

    def _check_xpath_injection(self):
        """Check for XPath injection vulnerabilities."""
        xpath_patterns = [
            # xpath package
            (r'xpath\.select\s*\(', "XPath Injection - xpath.select"),
            (r'xpath\.evaluate\s*\(', "XPath Injection - xpath.evaluate"),
            # xmldom with xpath
            (r'\.evaluate\s*\(\s*[`"\'][^`"\']*\$\{', "XPath Injection - evaluate with template"),
            (r'\.selectNodes\s*\(', "XPath Injection - selectNodes"),
            (r'\.selectSingleNode\s*\(', "XPath Injection - selectSingleNode"),
            # libxmljs .find() method for XPath
            (r'\.find\s*\(\s*xpath', "XPath Injection - libxmljs find"),
            (r'xmlDoc\.find\s*\(', "XPath Injection - xmlDoc.find"),
            # NOTE: Generic XPath concatenation pattern removed - handled separately below
            # with context-aware filtering to avoid URL protocol false positives
        ]

        for i, line in enumerate(self.source_lines, 1):
            stripped = line.strip()
            if stripped.startswith('//') or stripped.startswith('/*'):
                continue

            for pattern, vuln_name in xpath_patterns:
                if re.search(pattern, line):
                    has_taint = any(var in line for var in self.tainted_vars)
                    has_req = 'req.' in line

                    if has_taint or has_req:
                        self._add_finding(i, f"{vuln_name} with user input",
                                          VulnCategory.XPATH_INJECTION, Severity.HIGH, "HIGH",
                                          "User input in XPath query may allow injection.")
                    elif '${' in line or '+' in line:
                        self._add_finding(i, vuln_name,
                                          VulnCategory.XPATH_INJECTION, Severity.MEDIUM, "MEDIUM",
                                          "Dynamic XPath construction detected.")

            # Detect XPath string construction with concatenation (common evasion)
            # Must look like actual XPath, not URL protocols or generic strings
            # XPath indicators: //, @, [], ancestor::, descendant::, etc.
            xpath_indicators = r'(?:\[@|ancestor::|descendant::|following::|preceding::|child::|parent::|\]\s*/)'
            # Exclude URL protocol patterns and generic error/log messages
            url_protocol_pattern = r'(?:\.substring|\.slice|\.substr|\.startsWith|\.indexOf|\.match)\s*\([^)]*["\'][/]{2}'
            log_error_pattern = r'(?:log|error|warn|info|debug|console\.)'

            has_xpath_concat = re.search(r'=\s*["\'][^"\']*//[^"\']*["\'].*\+', line) or \
                               re.search(r'\+\s*["\'][^"\']*//[^"\']*["\']', line)

            if has_xpath_concat:
                # Only flag if it looks like XPath (has XPath-specific syntax)
                # or is near XPath-related function calls
                context = '\n'.join(self.source_lines[max(0, i-3):min(len(self.source_lines), i+3)])
                is_xpath_context = re.search(xpath_indicators, line) or \
                                   re.search(r'xpath|selectNodes|selectSingleNode|evaluate', context, re.IGNORECASE)
                is_url_check = re.search(url_protocol_pattern, line) or \
                               re.search(r'["\']//["\']|protocol|href|location\.', line, re.IGNORECASE)
                is_log_message = re.search(log_error_pattern, line, re.IGNORECASE)

                if is_xpath_context and not is_url_check and not is_log_message:
                    self._add_finding(i, "XPath Injection - XPath string concatenation",
                                      VulnCategory.XPATH_INJECTION, Severity.HIGH, "HIGH",
                                      "XPath query constructed via string concatenation.")

    def _check_auth_bypass(self):
        """Check for authentication bypass vulnerabilities - including evasion techniques."""
        critical_patterns = [
            # JWT issues
            (r'jwt\.verify\s*\([^)]*\{\s*algorithms\s*:\s*\[.*none', "Auth Bypass - JWT none algorithm"),
            (r'algorithms\s*:\s*\[\s*["\'](?:HS|RS|ES)\d+["\'].*["\']none["\']', "Auth Bypass - JWT allows none"),
            # Direct bypass
            (r'isAdmin\s*=\s*true\b', "Auth Bypass - Direct admin assignment"),
            (r'\.isAuthenticated\s*=\s*true', "Auth Bypass - Direct authentication bypass"),
            (r'authenticated\s*=\s*true\b', "Auth Bypass - Direct auth flag set"),
        ]

        high_patterns = [
            # JWT decode without verify (evasion: extract payload manually)
            (r'jwt\.decode\s*\(', "Auth Bypass - jwt.decode without verify"),
            (r'\.split\s*\(\s*["\']\.["\']\s*\).*\[\s*1\s*\]', "Auth Bypass - Manual JWT payload extraction"),
            (r'atob\s*\(.*\.split', "Auth Bypass - Base64 decode JWT segment"),
            (r'Buffer\.from\s*\([^,]+,\s*["\']base64', "Auth Bypass - Buffer JWT decode"),
            # Loose comparison (== instead of ===)
            # Note: Use negative lookbehind to exclude !== and ===
            (r'(?:password|token|secret|apiKey|api_key)\s*(?<![!=])==[^=]', "Auth Bypass - Loose comparison (use ===)"),
            (r'provided\s*(?<![!=])==[^=]\s*expected', "Auth Bypass - Loose comparison"),
            (r'(?<![!=])==[^=]\s*(?:password|token|secret)', "Auth Bypass - Loose comparison"),
            # Hardcoded credentials
            (r'password\s*===?\s*["\'][^"\']+["\']', "Auth Bypass - Hardcoded password"),
            (r'===?\s*["\'](?:admin|root|administrator)["\']', "Auth Bypass - Hardcoded role check"),
            # Session manipulation
            (r'req\.session\s*=\s*\{', "Auth Bypass - Direct session assignment"),
            (r'session\s*\[\s*["\'](?:admin|role|user)', "Auth Bypass - Session role manipulation"),
            # Insecure cookie settings
            (r'httpOnly\s*:\s*false', "Auth Bypass - Cookie without httpOnly"),
            (r'secure\s*:\s*false', "Auth Bypass - Cookie without secure flag"),
            (r'sameSite\s*:\s*["\']none["\']', "Auth Bypass - Cookie SameSite none"),
        ]

        medium_patterns = [
            # Timing-vulnerable comparisons
            (r'===\s*(?:password|secret|token|key|apiKey)\b', "Auth Bypass - Potential timing attack"),
            # Bypassable validation
            (r'\.endsWith\s*\(\s*["\']\.internal', "Auth Bypass - Bypassable domain validation"),
            (r'\.includes\s*\(\s*["\'](?:admin|internal)', "Auth Bypass - Weak authorization check"),
        ]

        # === CRITICAL: UI/Frontend patterns that are NOT auth bypass ===
        # These are client-side UI state checks, not authorization logic
        ui_false_positive_patterns = [
            r'<\w+',                          # JSX element (UI rendering context)
            r'\bpage\s*===?\s*["\']',         # UI page state comparison (page == 'admin')
            r'\broute\s*===?\s*["\']',        # UI route state
            r'\bpath\s*===?\s*["\']',         # UI path comparison
            r'\btab\s*===?\s*["\']',          # UI tab state
            r'\bview\s*===?\s*["\']',         # UI view state
            r'\bmode\s*===?\s*["\']',         # UI mode state
            r'\bactive\s*===?\s*["\']',       # UI active state
            r'\bselected\s*===?\s*["\']',     # UI selected state
            r'name\s*=\s*["\']',              # JSX name attribute
            r'className\s*=',                 # React className
            r'class\s*=',                     # HTML class attribute
            r'SidebarItem',                   # UI component names
            r'MenuItem',                      # UI component names
            r'NavItem',                       # UI component names
            r'TabItem',                       # UI component names
            r'Link\s',                        # Link components
            r'href\s*=',                      # href attributes (navigation, not auth)
            r'onClick\s*=',                   # onClick handlers (UI, not auth)
            r'icon\s*=',                      # icon props
            r'\.admin\s*&&',                  # React conditional rendering (user.admin && <Component>)
            r'&&\s*<',                        # JSX conditional rendering
            r'\?\s*<',                        # Ternary JSX rendering
            # === LEGITIMATE AUTHORIZATION CHECK patterns ===
            r'token\?*\.role\s*[!=]==?',      # token.role === "admin" (auth check)
            r'\.role\s*[!=]==?\s*["\']',      # .role === "admin" or .role !== "admin" (authorization)
            r'nextauth\.token',               # NextAuth token checks
            r'return\s+!!',                   # return !!token && ... (auth middleware)
            r'authorized\s*:',                # NextAuth authorized callback
            r'withAuth\s*\(',                 # Next.js withAuth HOC
            r'middleware',                    # Middleware authorization context
            r'confirmPassword\s*[!=]==?',     # Password confirmation check
            r'[!=]==?\s*confirmPassword',     # Password confirmation check (reverse)
            r'password\s*!==\s*.*[Cc]onfirm', # password !== confirmPassword
            r'if\s*\(\s*.*\.role\s*[!=]==?',  # if (user.role === "admin") - authorization check
            r'req\.user\.role',               # Express req.user.role check
            r'session\.user\.role',           # Session role check
            r'user\.role\s*[!=]==?',          # user.role check
        ]

        for i, line in enumerate(self.source_lines, 1):
            stripped = line.strip()
            if stripped.startswith('//') or stripped.startswith('/*'):
                continue

            # Check if this is a UI/frontend pattern (not auth bypass)
            is_ui_pattern = any(re.search(pat, line, re.IGNORECASE) for pat in ui_false_positive_patterns)

            for pattern, vuln_name in critical_patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    self._add_finding(i, vuln_name,
                                      VulnCategory.AUTH_BYPASS, Severity.CRITICAL, "HIGH",
                                      "Critical authentication bypass vulnerability.")

            for pattern, vuln_name in high_patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    # Skip UI patterns for "Hardcoded role check"
                    if "Hardcoded role check" in vuln_name and is_ui_pattern:
                        continue

                    # === CRITICAL: Skip file extension extraction (NOT JWT) ===
                    # .split('.')[1] for getting file extension like .jpg, .pdf, .xlsx
                    if "Manual JWT payload extraction" in vuln_name:
                        context = '\n'.join(self.source_lines[max(0, i-5):min(len(self.source_lines), i+5)])
                        file_ext_patterns = [
                            r'file|name|ext|type|image|photo|video|audio|document',
                            r'\.jpg|\.jpeg|\.png|\.gif|\.pdf|\.xlsx|\.csv|\.zip',
                            r'originalname|filename|mimetype',
                            r'AcceptedFiles|allowedExt|fileType',
                            r'upload|download',
                        ]
                        is_file_context = any(re.search(pat, context, re.IGNORECASE) for pat in file_ext_patterns)
                        if is_file_context:
                            continue  # File extension extraction, not JWT

                    # === CRITICAL: Skip image/PDF base64 decoding (NOT JWT) ===
                    # Buffer.from(imageData, 'base64') for image processing
                    if "Buffer JWT decode" in vuln_name:
                        context = '\n'.join(self.source_lines[max(0, i-5):min(len(self.source_lines), i+5)])
                        image_patterns = [
                            r'image|photo|picture|avatar|logo|icon|thumbnail',
                            r'pdf|document|file|upload',
                            r'data:image|data:application',
                            r'\.split\s*\(\s*["\'],["\']\s*\)',  # data URL split
                            r'mimeType|contentType',
                            r'imageUpload|writeFile|createFile',
                            r's3Service|imageService|storageService',
                            r'pdfBuffer|imageBuffer|fileBuffer',
                        ]
                        is_image_context = any(re.search(pat, context, re.IGNORECASE) for pat in image_patterns)
                        if is_image_context:
                            continue  # Image/file processing, not JWT

                    # === CRITICAL: Skip legitimate role authorization checks ===
                    if "Hardcoded role check" in vuln_name:
                        # Check if it's a legitimate auth check (not bypass)
                        legit_auth_patterns = [
                            r'\.slug\s*[!=]==?\s*["\']admin["\']',  # role.slug !== 'admin'
                            r'if\s*\(\s*\w+\.(?:role|slug|type)',   # if (user.role === ...) condition
                            r'role\s*!==',                          # Checking role is NOT something
                            r'\w+\s*!==?\s*["\'](?:admin|store)["\']',  # Input validation: area !== "admin"
                            r'!==?\s*["\'](?:admin|store)["\'].*&&.*!==?\s*["\']', # area !== "admin" && area !== "store"
                        ]
                        is_legit_auth = any(re.search(pat, line) for pat in legit_auth_patterns)
                        if is_legit_auth:
                            continue  # Legitimate authorization check or input validation

                    # === CRITICAL: Skip jwt.decode in test files ===
                    # Tests use jwt.decode to inspect token contents for assertions, not for auth
                    if "jwt.decode without verify" in vuln_name:
                        is_test_file = any(p in self.file_path.lower() for p in [
                            '/test/', '/__tests__/', '.spec.', '.test.', '/tests/',
                            'integration-tests', 'unit-tests', 'e2e-tests'
                        ])
                        # Check if used in test assertion context
                        context = '\n'.join(self.source_lines[max(0, i-3):min(len(self.source_lines), i+3)])
                        test_assertion_patterns = [
                            r'expect\s*\(',           # Jest/Vitest expect()
                            r'assert\.',              # Node assert
                            r'\.toMatch',             # Jest matcher
                            r'\.toEqual',             # Jest matcher
                            r'\.toBe',                # Jest matcher
                            r'\.toHaveProperty',      # Jest matcher
                            r'\.toMatchObject',       # Jest matcher
                            r'it\s*\(',               # Test block
                            r'describe\s*\(',         # Describe block
                            r'test\s*\(',             # Test block
                        ]
                        is_test_assertion = any(re.search(pat, context) for pat in test_assertion_patterns)
                        if is_test_file or is_test_assertion:
                            continue  # Test file inspecting token, not auth bypass

                    self._add_finding(i, vuln_name,
                                      VulnCategory.AUTH_BYPASS, Severity.HIGH, "HIGH",
                                      "Authentication or authorization bypass detected.")

            for pattern, vuln_name in medium_patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    self._add_finding(i, vuln_name,
                                      VulnCategory.AUTH_BYPASS, Severity.MEDIUM, "MEDIUM",
                                      "Potential authentication weakness.")

    def _check_react_security(self):
        """
        Comprehensive React/JSX security analysis - Levels 1-5 plus enterprise requirements.

        Level 1: dangerouslySetInnerHTML - The Classic XSS
        Level 2: href/src with tainted variables (javascript: protocol injection)
        Level 3: setTimeout/setInterval with string argument (eval in disguise)
        Level 4: Prop spreading - Mass assignment attack {...untrustedProps}
        Level 5: useRef DOM manipulation (ref.current.innerHTML bypass)

        Additional checks:
        - Secret in Props (sensitive data in data-* attributes)
        - SSR Hydration (Next.js getServerSideProps taint)
        """
        # Track component props that might be tainted
        component_props = set()  # Props from function signature
        tainted_refs = {}  # ref_name -> line where created
        json_parsed_vars = {}  # var_name -> line

        # First pass: identify props, refs, and JSON.parse results
        for i, line in enumerate(self.source_lines, 1):
            stripped = line.strip()
            if stripped.startswith('//') or stripped.startswith('/*'):
                continue

            # Detect React component props: const Component = ({ prop1, prop2 }) =>
            # or function Component({ prop1, prop2 })
            props_match = re.search(r'(?:const\s+\w+\s*=\s*\(\s*\{|function\s+\w+\s*\(\s*\{)\s*([^}]+)\s*\}', line)
            if props_match:
                props_str = props_match.group(1)
                props = [p.strip().split('=')[0].strip() for p in props_str.split(',')]
                component_props.update(p for p in props if p and not p.startswith('...'))

            # Detect useRef: const myRef = React.useRef() or useRef()
            ref_match = re.search(r'(?:const|let|var)\s+(\w+)\s*=\s*(?:React\.)?useRef\s*\(', line)
            if ref_match:
                tainted_refs[ref_match.group(1)] = i

            # Detect JSON.parse results
            json_match = re.search(r'(?:const|let|var)\s+(\w+)\s*=\s*JSON\.parse\s*\(', line)
            if json_match:
                json_parsed_vars[json_match.group(1)] = i

        # Second pass: detect vulnerabilities
        for i, line in enumerate(self.source_lines, 1):
            stripped = line.strip()
            if stripped.startswith('//') or stripped.startswith('/*'):
                continue

            # === LEVEL 3: setTimeout/setInterval with string (eval in disguise) ===
            # setTimeout(userInput, 1000) where userInput is a string acts like eval
            timeout_match = re.search(r'(setTimeout|setInterval)\s*\(\s*(\w+)\s*,', line)
            if timeout_match:
                func_name = timeout_match.group(1)
                first_arg = timeout_match.group(2)
                # Check if first arg is a prop or tainted (likely a string, not function)
                if first_arg in component_props or first_arg in self.tainted_vars:
                    self._add_finding(i, f"React RCE Level 3 - {func_name} with tainted string argument",
                                      VulnCategory.CODE_INJECTION, Severity.CRITICAL, "HIGH",
                                      f"{func_name}({first_arg}, delay) - if '{first_arg}' is a string, "
                                      f"it's evaluated as code (equivalent to eval). "
                                      f"User-controlled code execution vulnerability.")

            # Also catch direct prop usage: setTimeout(props.code, ...)
            if re.search(r'(setTimeout|setInterval)\s*\(\s*(?:props|this\.props)\.\w+\s*,', line):
                self._add_finding(i, "React RCE Level 3 - setTimeout/setInterval with props",
                                  VulnCategory.CODE_INJECTION, Severity.CRITICAL, "HIGH",
                                  "setTimeout/setInterval with props value as first argument. "
                                  "If prop is a string (not function), it executes as code.")

            # === SECRET LEAK: Sensitive data in data-* attributes ===
            # Detect: data-token={userAuthToken} or data-*={secret}
            data_attr_match = re.search(r'data-[\w-]+\s*=\s*\{\s*(\w+)\s*\}', line)
            if data_attr_match:
                var_name = data_attr_match.group(1)
                sensitive_patterns = ['token', 'auth', 'secret', 'key', 'password', 'credential', 'session', 'jwt', 'api']
                if any(p in var_name.lower() for p in sensitive_patterns):
                    self._add_finding(i, "Secret Leak - Sensitive data in data-* attribute",
                                      VulnCategory.INFO_DISCLOSURE, Severity.HIGH, "HIGH",
                                      f"Sensitive variable '{var_name}' exposed in data-* attribute. "
                                      f"This is visible in client-side HTML and can be extracted by attackers.")

            # Also check for isAdmin, role, permission type props in attributes
            if re.search(r'data-[\w-]*(?:admin|role|permission|privilege)[\w-]*\s*=', line, re.IGNORECASE):
                self._add_finding(i, "Secret Leak - Authorization data in data-* attribute",
                                  VulnCategory.INFO_DISCLOSURE, Severity.HIGH, "HIGH",
                                  "Authorization/role information exposed in client-side HTML attribute. "
                                  "This can be used for privilege enumeration attacks.")

    def _check_second_order_nosql(self):
        """Detect 2nd-order NoSQL injection with DB-sourced values in MongoDB operators."""
        for i, line in enumerate(self.source_lines, 1):
            stripped = line.strip()
            if stripped.startswith('//') or stripped.startswith('/*'):
                continue

            # $where operator with DB-sourced JavaScript (the most dangerous)
            if re.search(r'\$where\s*:', line):
                is_db, db_var, source = self._is_db_sourced(line)
                if is_db:
                    self._add_finding(i, "2nd-Order NoSQL Injection - $where with DB-sourced JavaScript",
                                      VulnCategory.NOSQL_INJECTION, Severity.CRITICAL, "HIGH",
                                      f"MongoDB $where executes JavaScript from {source}. "
                                      "Stored payload: 'function() {{ return this.password.length > 0; }}' "
                                      "enables data exfiltration via side-channels.")

            # $accumulator / $function operators (MongoDB 4.4+)
            if re.search(r'\$(?:accumulator|function)\s*:', line):
                is_db, db_var, source = self._is_db_sourced(line)
                if is_db:
                    self._add_finding(i, "2nd-Order NoSQL Injection - $function with DB-sourced code",
                                      VulnCategory.NOSQL_INJECTION, Severity.CRITICAL, "HIGH",
                                      f"MongoDB aggregation operator executes code from {source}. "
                                      "Stored JavaScript payload can access/modify any data.")

            # eval-like patterns in MongoDB context
            if re.search(r'\.find\s*\(\s*\{', line):
                is_db, db_var, source = self._is_db_sourced(line)
                if is_db and re.search(r'\$where|\$function|\$accumulator', line):
                    self._add_finding(i, "2nd-Order NoSQL Injection - Query with DB-sourced operator value",
                                      VulnCategory.NOSQL_INJECTION, Severity.CRITICAL, "HIGH",
                                      f"MongoDB query uses DB-sourced value from {source} in dangerous operator.")

    def _check_second_order_cmdi(self):
        """Detect 2nd-order command injection with DB-sourced values."""
        cmd_patterns = [
            (r'exec\s*\(', 'exec'),
            (r'execSync\s*\(', 'execSync'),
            (r'spawn\s*\(', 'spawn'),
            (r'spawnSync\s*\(', 'spawnSync'),
            (r'execFile\s*\(', 'execFile'),
            (r'fork\s*\(', 'fork'),
        ]

        for i, line in enumerate(self.source_lines, 1):
            stripped = line.strip()
            if stripped.startswith('//') or stripped.startswith('/*'):
                continue

            for pattern, func_name in cmd_patterns:
                if re.search(pattern, line):
                    is_db, db_var, source = self._is_db_sourced(line)
                    if is_db:
                        self._add_finding(i, f"2nd-Order Command Injection - {func_name}() with DB-sourced value",
                                          VulnCategory.COMMAND_INJECTION, Severity.CRITICAL, "HIGH",
                                          f"Shell command uses value from {source}. "
                                          "Stored payload: 'worldtree; rm -rf /' can wipe the system.")

            # Template literal in shell command
            if re.search(r'exec\s*\(\s*`', line) or re.search(r'spawn\s*\(\s*`', line):
                is_db, db_var, source = self._is_db_sourced(line)
                if is_db:
                    self._add_finding(i, "2nd-Order Command Injection - Template literal with DB-sourced value",
                                      VulnCategory.COMMAND_INJECTION, Severity.CRITICAL, "HIGH",
                                      f"Shell command template uses value from {source}.")


class JavaAnalyzer:
    """
    Java analyzer using regex-enhanced pattern matching with taint tracking.
    Tracks variable assignments and method parameters to detect tainted data flow.
    Includes 2nd-order SQLi detection for:
    - JPA/Hibernate entity getters (entityManager.find().getX())
    - Hibernate Criteria API (root.get(storedProperty))
    - HQL/JPQL function injection (createQuery with string concat)
    - Table name injection (native queries with entity-sourced tables)
    """

    def __init__(self, source_code: str, file_path: str):
        self.source_code = source_code
        self.source_lines = source_code.splitlines()
        self.file_path = file_path
        self.findings: List[Finding] = []

        # Track tainted variables by line scope
        self.tainted_vars: Dict[str, int] = {}  # var_name -> line where tainted
        self.method_params: Dict[str, Set[str]] = {}  # method_name -> set of param names

        # Lambda tracking for functional interface taint flow
        self.lambda_definitions: Dict[str, dict] = {}  # var_name -> {params, body_lines, sinks}

        # 2nd-order SQLi tracking
        self.db_sourced_vars: Dict[str, Tuple[int, str]] = {}  # var -> (line, entity source)

        # Pre-analyze to identify taint sources
        self._identify_method_params()
        self._identify_lambda_definitions()
        self._track_variable_assignments()
        self._track_lambda_taint_flow()
        self._track_database_sources()

    # Spring/Servlet annotations that mark parameters as user-controlled
    TAINT_ANNOTATIONS = re.compile(
        r'@(?:RequestParam|PathVariable|RequestBody|RequestHeader|'
        r'CookieValue|MatrixVariable|RequestPart|ModelAttribute)\b'
    )
    # Servlet/HTTP types that are inherently tainted
    TAINT_PARAM_TYPES = {
        'HttpServletRequest', 'ServletRequest', 'MultipartFile',
        'MultipartHttpServletRequest', 'WebRequest', 'NativeWebRequest',
    }
    # Servlet entry-point methods where ALL params are tainted
    SERVLET_METHODS = {'doGet', 'doPost', 'doPut', 'doDelete', 'doRequest', 'service'}

    def _identify_method_params(self):
        """Identify method parameters as potential taint sources.

        Only taint params that are:
        - Annotated with Spring web annotations (@RequestParam, etc.)
        - Typed as HttpServletRequest or similar servlet types
        - Parameters of servlet entry-point methods (doGet, doPost, etc.)
        """
        method_pattern = r'(?:public|private|protected|static|\s)+\s+[\w<>,?\s\[\]]+\s+(\w+)\s*\(([^)]*)\)'

        for i, line in enumerate(self.source_lines, 1):
            match = re.search(method_pattern, line)
            if match:
                method_name = match.group(1)
                params_str = match.group(2)
                if params_str.strip():
                    params = set()
                    is_servlet_method = method_name in self.SERVLET_METHODS
                    for param in params_str.split(','):
                        param_text = param.strip()
                        parts = param_text.split()
                        if len(parts) >= 2:
                            param_name = parts[-1].strip()
                            param_name = re.sub(r'\[\]', '', param_name)
                            params.add(param_name)

                            # Determine if this param should be tainted
                            should_taint = is_servlet_method
                            if not should_taint:
                                # Check for Spring web annotations
                                should_taint = bool(self.TAINT_ANNOTATIONS.search(param_text))
                            if not should_taint:
                                # Check for servlet/HTTP types
                                for ptype in self.TAINT_PARAM_TYPES:
                                    if ptype in param_text:
                                        should_taint = True
                                        break

                            if should_taint:
                                self.tainted_vars[param_name] = i
                    self.method_params[method_name] = params

    def _track_variable_assignments(self):
        """Track variable assignments to propagate taint."""
        # Pattern: Type varName = taintedVar; or varName = taintedVar;
        assign_pattern = r'(?:(?:String|Object|byte\[\]|InputStream|List|Map|Set|Queue|Optional)\s+)?(\w+)\s*=\s*([^;]+);'

        for i, line in enumerate(self.source_lines, 1):
            # Skip comments
            stripped = line.strip()
            if stripped.startswith('//') or stripped.startswith('/*') or stripped.startswith('*'):
                continue

            for match in re.finditer(assign_pattern, line):
                var_name = match.group(1)
                rhs = match.group(2)

                # Check if RHS contains any tainted variable
                for tainted_var in list(self.tainted_vars.keys()):
                    # Match whole word
                    if re.search(rf'\b{re.escape(tainted_var)}\b', rhs):
                        self.tainted_vars[var_name] = i
                        break

                # Also check for method calls that return tainted data
                taint_methods = [
                    r'\.get\s*\(', r'\.poll\s*\(', r'\.next\s*\(',
                    r'\.getMessage\s*\(', r'\.getCause\s*\(',
                    r'\.unwrap\s*\(', r'\.getCommand\s*\(',
                    r'\.trim\s*\(', r'\.substring\s*\(',
                    r'\.toString\s*\(', r'\.apply\s*\(',
                    r'getParameter\s*\(', r'getHeader\s*\(',
                ]
                for pattern in taint_methods:
                    if re.search(pattern, rhs):
                        for tainted_var in list(self.tainted_vars.keys()):
                            if re.search(rf'\b{re.escape(tainted_var)}\b', rhs):
                                self.tainted_vars[var_name] = i
                                break

    def _identify_lambda_definitions(self):
        """
        Identify lambda/closure definitions and extract their parameters.
        Tracks: Consumer<T> action = (param) -> { ... }
        """
        # Pattern for lambda assignment: varName = (params) -> { body } or (params) -> expr
        lambda_assign = re.compile(
            r'(\w+)\s*=\s*\(([^)]*)\)\s*->\s*(\{?)',
            re.MULTILINE
        )

        for i, line in enumerate(self.source_lines, 1):
            if '->' not in line:
                continue

            match = lambda_assign.search(line)
            if not match:
                continue

            var_name = match.group(1)
            params_str = match.group(2).strip()
            has_brace = match.group(3) == '{'

            # Parse lambda parameters (may have type annotations)
            params = []
            if params_str:
                for param in params_str.split(','):
                    parts = param.strip().split()
                    param_name = parts[-1] if parts else None
                    if param_name:
                        params.append(param_name)

            # Find lambda body extent
            body_start = i
            body_end = i

            if has_brace:
                # Multi-line lambda - find closing brace
                brace_count = line.count('{') - line.count('}')
                for j in range(i, min(len(self.source_lines), i + 50)):
                    if j > i:
                        brace_count += self.source_lines[j - 1].count('{')
                        brace_count -= self.source_lines[j - 1].count('}')
                    if brace_count <= 0:
                        body_end = j
                        break

            # Extract body lines and check for sinks
            body_lines = self.source_lines[body_start - 1:body_end]
            body_text = '\n'.join(body_lines)

            # Identify sinks within the lambda that use lambda parameters
            sinks = []
            sink_patterns = [
                (r'new\s+File\s*\(', 'File'),
                (r'Files\s*\.\s*(?:read|write|delete|copy|move)', 'Files'),
                (r'Runtime\s*\..*exec\s*\(', 'exec'),
                (r'ProcessBuilder', 'ProcessBuilder'),
                (r'\.executeQuery\s*\(', 'SQL'),
                (r'\.execute\s*\(', 'SQL'),
            ]

            for pattern, sink_type in sink_patterns:
                if re.search(pattern, body_text):
                    # Check if any lambda param is used in the sink context
                    for param in params:
                        if re.search(rf'\b{re.escape(param)}\b', body_text):
                            sinks.append({
                                'type': sink_type,
                                'param': param,
                                'line': body_start
                            })

            self.lambda_definitions[var_name] = {
                'params': params,
                'body_start': body_start,
                'body_end': body_end,
                'sinks': sinks
            }

    def _track_lambda_taint_flow(self):
        """
        Track taint propagation through lambda invocations.

        Handles two patterns:
        1. Direct: consumer.accept(taintedVar) - lambda param becomes tainted
        2. Indirect: method(taintedVar, lambdaVar) - lambda may receive tainted data
        """
        # Pattern 1: Functional interface invocation with tainted argument
        # e.g., worker.accept(data), func.apply(input)
        invoke_patterns = [
            (r'(\w+)\s*\.\s*accept\s*\(\s*([^)]+)\s*\)', 'Consumer'),
            (r'(\w+)\s*\.\s*apply\s*\(\s*([^)]+)\s*\)', 'Function'),
            (r'(\w+)\s*\.\s*test\s*\(\s*([^)]+)\s*\)', 'Predicate'),
            (r'(\w+)\s*\.\s*get\s*\(\s*\)', 'Supplier'),
            (r'(\w+)\s*\.\s*run\s*\(\s*\)', 'Runnable'),
        ]

        # Track which variables might hold lambdas (via method params)
        lambda_holders: Dict[str, str] = {}  # holder_var -> potential lambda source

        for i, line in enumerate(self.source_lines, 1):
            # Track method parameters that are functional interfaces
            func_param_pattern = r'(?:Consumer|Function|Supplier|Predicate|Runnable|Callable)\s*(?:<[^>]+>)?\s+(\w+)'
            for match in re.finditer(func_param_pattern, line):
                param_name = match.group(1)
                lambda_holders[param_name] = f"param@{i}"

            # Check for functional interface invocations
            for pattern, iface_type in invoke_patterns:
                match = re.search(pattern, line)
                if not match:
                    continue

                invoker = match.group(1)
                args = match.group(2) if len(match.groups()) > 1 else ""

                # Check if args contain tainted data
                is_tainted, taint_var = self._is_tainted(args)
                if not is_tainted:
                    continue

                # The invoker is a functional interface being called with tainted data
                # Find which lambda this corresponds to and taint its parameters
                if invoker in lambda_holders or invoker in self.lambda_definitions:
                    # Direct lambda invocation - taint the lambda's parameters
                    if invoker in self.lambda_definitions:
                        for param in self.lambda_definitions[invoker]['params']:
                            self.tainted_vars[param] = i

        # Pattern 2: Method calls passing tainted data alongside lambdas
        # e.g., executeAction(input, action) where input is tainted and action is a lambda
        method_call_pattern = r'(\w+)\s*\(\s*([^)]+)\s*\)'

        for i, line in enumerate(self.source_lines, 1):
            for match in re.finditer(method_call_pattern, line):
                args_str = match.group(2)
                args = [a.strip() for a in args_str.split(',')]

                if len(args) < 2:
                    continue

                # Check if any arg is tainted and any other arg is a lambda
                tainted_args = [a for a in args if a in self.tainted_vars]
                lambda_args = [a for a in args if a in self.lambda_definitions]

                if tainted_args and lambda_args:
                    # Tainted data is being passed alongside a lambda
                    # Conservatively assume the lambda may receive the tainted data
                    for lambda_var in lambda_args:
                        lambda_def = self.lambda_definitions[lambda_var]
                        for param in lambda_def['params']:
                            if param not in self.tainted_vars:
                                self.tainted_vars[param] = i

    def _track_database_sources(self):
        """Track variables that receive values from JPA/Hibernate entities (2nd-order sources)."""
        # JPA/Hibernate entity fetch patterns
        entity_patterns = [
            (r'(\w+)\s*=\s*\w+\.find\s*\(\s*\w+\.class', 'EntityManager.find'),
            (r'(\w+)\s*=\s*\w+\.findById\s*\(', 'Repository.findById'),
            (r'(\w+)\s*=\s*\w+\.getOne\s*\(', 'Repository.getOne'),
            (r'(\w+)\s*=\s*\w+\.getReferenceById\s*\(', 'Repository.getReferenceById'),
            (r'(\w+)\s*=\s*\w+Repo(?:sitory)?\.find', 'Repository.find'),
        ]

        for i, line in enumerate(self.source_lines, 1):
            stripped = line.strip()
            if stripped.startswith('//') or stripped.startswith('/*') or stripped.startswith('*'):
                continue

            for pattern, source_type in entity_patterns:
                match = re.search(pattern, line)
                if match:
                    var_name = match.group(1)
                    self.db_sourced_vars[var_name] = (i, source_type)

        # Track getter calls on entities: String val = entity.getSomeField();
        for i, line in enumerate(self.source_lines, 1):
            stripped = line.strip()
            if stripped.startswith('//') or stripped.startswith('/*') or stripped.startswith('*'):
                continue

            for entity_var in list(self.db_sourced_vars.keys()):
                # Pattern: var = entity.getXxx() or entity.xxx
                getter_pattern = rf'(\w+)\s*=\s*{re.escape(entity_var)}\.(?:get)?(\w+)\s*\('
                match = re.search(getter_pattern, line)
                if match:
                    new_var = match.group(1)
                    getter_name = match.group(2)
                    orig_line, orig_source = self.db_sourced_vars[entity_var]
                    self.db_sourced_vars[new_var] = (i, f"{orig_source}.get{getter_name}()")

        # Track getter chains: user.getProfile().getSettings().getDynamicColumn()
        for i, line in enumerate(self.source_lines, 1):
            stripped = line.strip()
            if stripped.startswith('//') or stripped.startswith('/*') or stripped.startswith('*'):
                continue

            # Long getter chain pattern
            chain_pattern = r'(\w+)\s*=\s*(\w+)(?:\.get\w+\(\))+\.get(\w+)\s*\('
            match = re.search(chain_pattern, line)
            if match:
                new_var = match.group(1)
                root_var = match.group(2)
                final_getter = match.group(3)
                if root_var in self.db_sourced_vars:
                    orig_line, orig_source = self.db_sourced_vars[root_var]
                    self.db_sourced_vars[new_var] = (i, f"{orig_source}...get{final_getter}()")

    def _is_db_sourced(self, line: str) -> Tuple[bool, Optional[str], Optional[str]]:
        """Check if line uses a database/entity-sourced variable.

        Only matches variables on the RHS of assignments, not LHS declarations.
        """
        # Split at first = to get RHS only (for assignments)
        if '=' in line and not line.strip().startswith('if') and not line.strip().startswith('while'):
            parts = line.split('=', 1)
            if len(parts) == 2:
                rhs = parts[1]
            else:
                rhs = line
        else:
            rhs = line

        for var, (src_line, source) in self.db_sourced_vars.items():
            if re.search(rf'\b{re.escape(var)}\b', rhs):
                return True, var, source
        return False, None, None

    def _is_tainted(self, line: str) -> Tuple[bool, Optional[str]]:
        """Check if a line contains tainted data.

        Only matches variables on the RHS of assignments, not LHS declarations.
        """
        # Split at first = to get RHS only (for assignments)
        if '=' in line and not line.strip().startswith('if') and not line.strip().startswith('while'):
            parts = line.split('=', 1)
            if len(parts) == 2:
                rhs = parts[1]
            else:
                rhs = line
        else:
            rhs = line

        # Remove string literals to avoid matching variable names inside strings
        rhs_without_strings = re.sub(r'"[^"\\]*(?:\\.[^"\\]*)*"', '""', rhs)

        for var_name in self.tainted_vars:
            if re.search(rf'\b{re.escape(var_name)}\b', rhs_without_strings):
                return True, var_name
        return False, None

    def get_line_content(self, lineno: int) -> str:
        """Get the source line content."""
        if 1 <= lineno <= len(self.source_lines):
            return self.source_lines[lineno - 1]
        return ""

    def analyze(self) -> List[Finding]:
        """Run the analysis."""
        # Run evasive pattern checks FIRST so they take priority over generic checks
        self._check_encoding_passthrough()
        self._check_spring_query_annotation()
        self._check_stringbuilder_chain()
        self._check_lambda_stream_injection()
        self._check_array_varargs_injection()
        # Then run standard checks
        self._check_sql_injection()
        self._check_command_injection()
        self._check_deserialization()
        self._check_xxe()
        self._check_jndi_injection()
        self._check_script_engine()
        self._check_reflection_injection()
        self._check_jni_native()
        # 2nd-order SQL injection detection
        self._check_second_order_sqli()
        self._check_criteria_api_sqli()
        self._check_hql_function_injection()
        self._check_table_name_injection()
        # 2nd-order XPath injection detection
        self._check_xpath_injection()
        return self.findings

    def _add_finding(self, line_num: int, vuln_name: str, category: VulnCategory,
                     severity: Severity, confidence: str, taint_var: Optional[str] = None,
                     description: str = ""):
        """Add a finding."""
        taint_chain = []
        if taint_var and taint_var in self.tainted_vars:
            taint_chain = [f"tainted: {taint_var} (line {self.tainted_vars[taint_var]})"]

        finding = Finding(
            file_path=self.file_path,
            line_number=line_num,
            col_offset=0,
            line_content=self.get_line_content(line_num),
            vulnerability_name=vuln_name,
            category=category,
            severity=severity,
            confidence=confidence,
            taint_chain=taint_chain,
            description=description,
        )
        self.findings.append(finding)

    def _check_sql_injection(self):
        """Check for SQL injection patterns."""
        sql_keywords = r'(?:SELECT|INSERT|UPDATE|DELETE|DROP|CREATE|ALTER|TRUNCATE|EXEC|EXECUTE)'

        # Patterns that are NOT SQL - should be excluded from SQL injection detection
        non_sql_patterns = [
            r'Runtime\..*\.exec\s*\(',     # Runtime.getRuntime().exec() - command execution, not SQL
            r'\.exec\s*\(\s*["\'](?:cat|ls|rm|cp|mv|chmod|chown|grep|awk|sed|find|curl|wget)',  # Shell commands
            r'ProcessBuilder',              # Command execution
            r'Process\s+\w+\s*=',           # Process variable assignment
        ]

        for i, line in enumerate(self.source_lines, 1):
            stripped = line.strip()
            if stripped.startswith('//') or stripped.startswith('/*') or stripped.startswith('*'):
                continue

            # Skip lines that are command execution, not SQL
            is_command_exec = any(re.search(pat, line) for pat in non_sql_patterns)
            if is_command_exec:
                continue

            # Pattern 1: executeQuery/execute with string concatenation
            if re.search(r'\.(?:executeQuery|execute|executeUpdate)\s*\(', line):
                is_tainted, taint_var = self._is_tainted(line)

                # Check for string concatenation with SQL keywords
                has_concat = '+' in line or 'concat' in line.lower() or 'format' in line.lower()
                has_sql = re.search(sql_keywords, line, re.IGNORECASE)

                # === CRITICAL: Skip PreparedStatement with parameterized queries ===
                # PreparedStatement.executeQuery() with no args is SAFE (params already bound)
                # Pattern: pstmt.executeQuery() where pstmt was prepared with ? placeholders
                context = '\n'.join(self.source_lines[max(0, i-10):i])
                is_prepared_statement = (
                    # Check if context shows a prepareStatement with ? or :param placeholders
                    re.search(r'prepareStatement\s*\([^)]*\?\s*', context) or
                    re.search(r'prepareStatement\s*\([^)]*:\w+', context) or
                    # Check for setString/setInt/setParameter calls (parameter binding)
                    re.search(r'\.set(?:String|Int|Long|Float|Double|Boolean|Object|Parameter)\s*\(', context)
                )
                # executeQuery() with empty parens on PreparedStatement is SAFE
                if is_prepared_statement and re.search(r'\.executeQuery\s*\(\s*\)', line):
                    continue  # SAFE - PreparedStatement with no inline query

                if is_tainted:
                    # Additional check: skip if this is a PreparedStatement variable executing a parameterized query
                    if is_prepared_statement:
                        continue  # SAFE - parameterized query
                    self._add_finding(i, "SQL Injection - executeQuery with tainted input",
                                      VulnCategory.SQL_INJECTION, Severity.CRITICAL, "HIGH", taint_var,
                                      "User-controlled data in SQL query execution.")
                elif has_concat and has_sql:
                    self._add_finding(i, "SQL Injection - Dynamic query construction",
                                      VulnCategory.SQL_INJECTION, Severity.HIGH, "MEDIUM",
                                      description="SQL query uses string concatenation. Use PreparedStatement.")

            # Pattern 2: String building with SQL + tainted data
            # Only flag for actual SQL keywords, not EXEC when it's command execution
            if re.search(sql_keywords, line, re.IGNORECASE) and '+' in line:
                # Additional check: ensure it's SQL context, not command execution
                # EXEC alone without other SQL keywords is likely command execution
                has_real_sql = re.search(r'\b(?:SELECT|INSERT|UPDATE|DELETE|FROM|WHERE|TABLE)\b', line, re.IGNORECASE)
                has_only_exec = re.search(r'\bEXEC(?:UTE)?\b', line, re.IGNORECASE) and not has_real_sql

                if has_only_exec:
                    continue  # Skip - likely command execution, not SQL

                is_tainted, taint_var = self._is_tainted(line)
                if is_tainted:
                    self._add_finding(i, "SQL Injection - String concatenation with tainted data",
                                      VulnCategory.SQL_INJECTION, Severity.CRITICAL, "HIGH", taint_var,
                                      "SQL query built with user-controlled data.")

            # Pattern 3: String.format with SQL
            if 'String.format' in line and re.search(sql_keywords, line, re.IGNORECASE):
                is_tainted, taint_var = self._is_tainted(line)
                if is_tainted:
                    # Check if only integer format specifiers are used (%d, %i, %u, %x, %o)
                    # These are much safer as they can't contain SQL injection payloads
                    format_str_match = re.search(r'String\.format\s*\(\s*"([^"]*)"', line)
                    if format_str_match:
                        format_str = format_str_match.group(1)
                        # Find all format specifiers
                        format_specs = re.findall(r'%[^%\s]*[a-zA-Z]', format_str)
                        # Integer-only specifiers (safe for SQL injection)
                        int_only = all(re.match(r'%[-+0\s#]*\d*\.?\d*[dioxXu]', spec) for spec in format_specs if spec)
                        if int_only and format_specs:
                            self._add_finding(i, "SQL Injection - String.format with integer specifiers (lower risk)",
                                              VulnCategory.SQL_INJECTION, Severity.MEDIUM, "LOW", taint_var,
                                              "SQL with String.format using only integer format specifiers (%d/%i/%x). "
                                              "Lower risk since integers can't contain SQL injection payloads.")
                            continue  # Skip the critical finding
                    self._add_finding(i, "SQL Injection - String.format with tainted data",
                                      VulnCategory.SQL_INJECTION, Severity.CRITICAL, "HIGH", taint_var,
                                      "SQL query uses String.format with user data.")

            # Pattern 4: StringBuilder append with SQL
            if re.search(r'\.append\s*\([^)]*\)', line):
                is_tainted, taint_var = self._is_tainted(line)
                # Look back for SQL context
                context = '\n'.join(self.source_lines[max(0, i-5):i])
                if re.search(sql_keywords, context, re.IGNORECASE) and is_tainted:
                    self._add_finding(i, "SQL Injection - StringBuilder with tainted data",
                                      VulnCategory.SQL_INJECTION, Severity.HIGH, "MEDIUM", taint_var,
                                      "SQL query built with StringBuilder and user data.")

    def _check_command_injection(self):
        """Check for command injection patterns."""
        for i, line in enumerate(self.source_lines, 1):
            stripped = line.strip()
            if stripped.startswith('//') or stripped.startswith('/*') or stripped.startswith('*'):
                continue

            # Runtime.getRuntime().exec()
            if re.search(r'Runtime\s*\.\s*getRuntime\s*\(\s*\)\s*\.\s*exec\s*\(', line):
                is_tainted, taint_var = self._is_tainted(line)
                if is_tainted:
                    self._add_finding(i, "Command Injection - Runtime.exec with tainted input",
                                      VulnCategory.COMMAND_INJECTION, Severity.CRITICAL, "HIGH", taint_var,
                                      "User-controlled data passed to Runtime.exec().")
                else:
                    # Check if using a variable (not a literal)
                    exec_arg = re.search(r'\.exec\s*\(\s*(\w+)', line)
                    if exec_arg:
                        var_name = exec_arg.group(1)
                        if var_name in self.tainted_vars:
                            self._add_finding(i, "Command Injection - Runtime.exec with tainted variable",
                                              VulnCategory.COMMAND_INJECTION, Severity.CRITICAL, "HIGH", var_name,
                                              f"Variable '{var_name}' passed to Runtime.exec().")

            # ProcessBuilder
            if re.search(r'new\s+ProcessBuilder\s*\(', line):
                is_tainted, taint_var = self._is_tainted(line)

                # Check for array/List argument pattern (safer - no shell interpretation)
                # Pattern: new ProcessBuilder(Arrays.asList(...)) or new ProcessBuilder(cmd) where cmd is List
                uses_array_list = re.search(
                    r'new\s+ProcessBuilder\s*\(\s*(?:Arrays\.asList\s*\(|List\.of\s*\(|new\s+ArrayList|command[sS]?|args|argList|cmdList)',
                    line
                )

                if is_tainted:
                    if uses_array_list:
                        # Lower confidence - array/List arguments don't go through shell
                        self._add_finding(i, "Command Injection - ProcessBuilder with array/List (lower risk)",
                                          VulnCategory.COMMAND_INJECTION, Severity.HIGH, "MEDIUM", taint_var,
                                          "ProcessBuilder with array/List argument. Lower risk than shell execution "
                                          "since no shell interpretation occurs. Verify arguments are validated.")
                    else:
                        self._add_finding(i, "Command Injection - ProcessBuilder with tainted input",
                                          VulnCategory.COMMAND_INJECTION, Severity.CRITICAL, "HIGH", taint_var,
                                          "User-controlled data passed to ProcessBuilder.")

                # Check for shell execution pattern: ProcessBuilder("/bin/sh", "-c", cmd)
                # or ProcessBuilder("cmd.exe", "/c", cmd)
                shell_pattern = re.search(
                    r'new\s+ProcessBuilder\s*\(\s*["\'](?:/bin/sh|/bin/bash|sh|bash|cmd(?:\.exe)?)["\']',
                    line
                )
                if shell_pattern:
                    context = '\n'.join(self.source_lines[i-1:min(len(self.source_lines), i+3)])
                    if re.search(r'["\'](?:-c|/c|/k)["\']', context):
                        if is_tainted:
                            self._add_finding(i, "Command Injection - ProcessBuilder shell execution with tainted input",
                                              VulnCategory.COMMAND_INJECTION, Severity.CRITICAL, "HIGH", taint_var,
                                              "ProcessBuilder with shell and -c flag executing user-controlled command.")
                        else:
                            self._add_finding(i, "Command Injection - ProcessBuilder shell execution pattern",
                                              VulnCategory.COMMAND_INJECTION, Severity.HIGH, "HIGH",
                                              description="ProcessBuilder with shell and -c flag - equivalent to Runtime.exec(cmd, true).")

            # Reflection-based command execution evasion
            # Method.invoke() on Runtime class
            if re.search(r'\.invoke\s*\(', line):
                context = '\n'.join(self.source_lines[max(0, i-10):i+1])
                # Check if invoking methods on Runtime or ProcessBuilder
                if re.search(r'Runtime|ProcessBuilder|exec|getRuntime', context, re.IGNORECASE):
                    is_tainted, taint_var = self._is_tainted(line)
                    if is_tainted:
                        self._add_finding(i, "Command Injection - Reflection invoke with tainted input",
                                          VulnCategory.COMMAND_INJECTION, Severity.CRITICAL, "HIGH", taint_var,
                                          "Reflection used to invoke command execution with user-controlled data.")
                    else:
                        self._add_finding(i, "Command Injection - Reflection invoke on Runtime/ProcessBuilder",
                                          VulnCategory.COMMAND_INJECTION, Severity.HIGH, "HIGH",
                                          description="Reflection invoke on Runtime/ProcessBuilder - evasion technique.")

            # getMethod/getDeclaredMethod on exec
            if re.search(r'\.(?:getMethod|getDeclaredMethod)\s*\(\s*["\']exec["\']', line):
                self._add_finding(i, "Command Injection - Reflection getMethod('exec')",
                                  VulnCategory.COMMAND_INJECTION, Severity.HIGH, "HIGH",
                                  description="Reflection used to get 'exec' method - evasion technique.")

    def _check_deserialization(self):
        """Check for insecure deserialization patterns."""
        # Track ObjectInputStream-like variables
        ois_vars = set()
        base64_decoded_vars = set()
        stream_vars = set()
        validating_ois_vars = set()  # Track ValidatingObjectInputStream (safe deserialization)

        for i, line in enumerate(self.source_lines, 1):
            stripped = line.strip()
            if stripped.startswith('//') or stripped.startswith('/*') or stripped.startswith('*'):
                continue

            # Track Base64 decoding: byte[] data = Base64.getDecoder().decode(blob)
            if re.search(r'Base64\s*\.\s*getDecoder\s*\(\s*\)\s*\.\s*decode\s*\(', line):
                is_tainted, taint_var = self._is_tainted(line)
                # Extract variable name
                var_match = re.match(r'\s*(?:byte\s*\[\s*\]|var)\s+(\w+)\s*=', line)
                if var_match:
                    base64_decoded_vars.add(var_match.group(1))
                if is_tainted:
                    self._add_finding(i, "Deserialization Risk - Base64 decoding user input",
                                      VulnCategory.DESERIALIZATION, Severity.MEDIUM, "MEDIUM", taint_var,
                                      "Base64 decoded data may contain serialized objects.")

            # Track ByteArrayInputStream creation
            if re.search(r'new\s+ByteArrayInputStream\s*\(', line):
                var_match = re.match(r'\s*(?:\w+(?:<[^>]+>)?)\s+(\w+)\s*=', line)
                if var_match:
                    stream_vars.add(var_match.group(1))

            # Track ObjectInputStream or subclass creation (e.g., CustomFilterStream extends ObjectInputStream)
            if re.search(r'ObjectInputStream|extends\s+ObjectInputStream', line):
                var_match = re.match(r'\s*(?:\w+(?:<[^>]+>)?)\s+(\w+)\s*=', line)
                if var_match:
                    ois_vars.add(var_match.group(1))

            # Track ValidatingObjectInputStream - Apache Commons IO safe deserialization
            # Pattern: ValidatingObjectInputStream vois = new ValidatingObjectInputStream(...)
            # With: vois.accept(AllowedClass.class, AnotherClass.class)
            if re.search(r'ValidatingObjectInputStream', line):
                var_match = re.search(r'(?:ValidatingObjectInputStream)\s+(\w+)\s*=', line)
                if var_match:
                    validating_ois_vars.add(var_match.group(1))

            # Detect .readObject() calls - the critical deserialization sink
            readobj_match = re.search(r'(\w+)\s*\.\s*readObject\s*\(\s*\)', line)
            if readobj_match:
                var_name = readobj_match.group(1)
                is_tainted, taint_var = self._is_tainted(line)

                # Check broader context for deserialization patterns
                context = '\n'.join(self.source_lines[max(0, i-15):i+3])

                # Check for safe deserialization patterns
                # 1. ValidatingObjectInputStream with .accept() whitelist
                uses_validating_ois = (
                    var_name in validating_ois_vars or
                    re.search(r'ValidatingObjectInputStream', context)
                )
                has_accept_whitelist = re.search(r'\.accept\s*\(', context)
                if uses_validating_ois and has_accept_whitelist:
                    continue  # Safe - ValidatingObjectInputStream with accept() whitelist

                # 2. ObjectInputFilter (Java 9+)
                has_object_filter = re.search(r'ObjectInputFilter|setObjectInputFilter|createFilter', context)
                if has_object_filter:
                    continue  # Safe - using ObjectInputFilter

                # Look for dangerous patterns in context
                has_ois = re.search(r'ObjectInputStream|extends\s+ObjectInputStream', context)
                has_base64 = re.search(r'Base64|decode\s*\(', context)
                has_stream = re.search(r'ByteArrayInputStream|InputStream', context)
                has_user_input = re.search(r'request\.|getParameter|getInputStream|blob|data|input|payload', context, re.IGNORECASE)

                if has_ois or var_name in ois_vars:
                    if is_tainted or has_user_input:
                        self._add_finding(i, "Insecure Deserialization - readObject() with untrusted data",
                                          VulnCategory.DESERIALIZATION, Severity.CRITICAL, "HIGH", taint_var,
                                          "ObjectInputStream.readObject() deserializes untrusted data - RCE possible via gadget chains.")
                    elif has_base64:
                        self._add_finding(i, "Insecure Deserialization - readObject() on decoded data",
                                          VulnCategory.DESERIALIZATION, Severity.CRITICAL, "HIGH",
                                          description="readObject() called on Base64-decoded data - likely deserialization attack vector.")
                    else:
                        self._add_finding(i, "Insecure Deserialization - readObject() usage",
                                          VulnCategory.DESERIALIZATION, Severity.HIGH, "MEDIUM",
                                          description="ObjectInputStream.readObject() detected. Verify data source is trusted.")

            # XMLDecoder - always dangerous
            if re.search(r'XMLDecoder', line):
                self._add_finding(i, "Insecure Deserialization - XMLDecoder",
                                  VulnCategory.DESERIALIZATION, Severity.CRITICAL, "HIGH",
                                  description="XMLDecoder is dangerous and can lead to RCE.")

            # Kryo, XStream, SnakeYAML - other dangerous deserializers
            if re.search(r'Kryo\s*\(\s*\)|\.readClassAndObject\s*\(|\.readObject\s*\(.*Kryo', line):
                self._add_finding(i, "Insecure Deserialization - Kryo",
                                  VulnCategory.DESERIALIZATION, Severity.HIGH, "MEDIUM",
                                  description="Kryo deserialization detected. Ensure proper class filtering.")

            if re.search(r'XStream\s*\(\s*\)|\.fromXML\s*\(', line):
                is_tainted, taint_var = self._is_tainted(line)
                severity = Severity.CRITICAL if is_tainted else Severity.HIGH
                self._add_finding(i, "Insecure Deserialization - XStream",
                                  VulnCategory.DESERIALIZATION, severity, "HIGH" if is_tainted else "MEDIUM",
                                  description="XStream.fromXML() can lead to RCE. Use security framework.")

            # SnakeYAML - Critical RCE vector via !!javax.script.ScriptEngineManager gadget
            # Pattern 1: Direct Yaml.load() or yaml.load() calls
            if re.search(r'\.load\s*\(', line) or re.search(r'\.loadAs\s*\(', line) or re.search(r'\.loadAll\s*\(', line):
                context = '\n'.join(self.source_lines[max(0, i-10):i+1])
                # Check if this is a SnakeYAML context (Yaml instance or import)
                is_snakeyaml = re.search(r'import\s+org\.yaml\.snakeyaml|Yaml\s+\w+\s*=|new\s+Yaml\s*\(', context)
                if is_snakeyaml:
                    # Check if SafeConstructor is used - this is SAFE
                    # Patterns: new Yaml(new SafeConstructor()), Yaml yaml = new Yaml(safeConstructor)
                    safe_constructor_patterns = [
                        r'new\s+Yaml\s*\(\s*new\s+SafeConstructor',  # Inline SafeConstructor
                        r'new\s+Yaml\s*\(\s*\w*[sS]afe\w*\s*\)',    # Variable with 'safe' in name
                        r'SafeConstructor',                          # SafeConstructor anywhere in context
                        r'BaseConstructor',                          # BaseConstructor (can be restricted)
                    ]
                    uses_safe_constructor = any(re.search(pat, context) for pat in safe_constructor_patterns)
                    if uses_safe_constructor:
                        continue  # Skip - SafeConstructor is safe

                    is_tainted, taint_var = self._is_tainted(line)
                    if is_tainted:
                        self._add_finding(i, "Insecure Deserialization - SnakeYAML.load() with untrusted data",
                                          VulnCategory.DESERIALIZATION, Severity.CRITICAL, "HIGH", taint_var,
                                          "SnakeYAML.load() with user input enables RCE via gadget chains. "
                                          "Attacker can use !!javax.script.ScriptEngineManager to execute arbitrary code. "
                                          "Use SafeConstructor: new Yaml(new SafeConstructor())")
                    else:
                        # Check if argument looks like it could be from request/user input
                        load_arg_match = re.search(r'\.load(?:As|All)?\s*\(\s*(\w+)', line)
                        if load_arg_match:
                            arg_name = load_arg_match.group(1)
                            # Check if this variable was assigned from request in context
                            if re.search(rf'{arg_name}\s*=.*(?:request\.|getParameter|getInputStream|getReader)', context):
                                self._add_finding(i, "Insecure Deserialization - SnakeYAML.load() with request data",
                                                  VulnCategory.DESERIALIZATION, Severity.CRITICAL, "HIGH",
                                                  description=f"SnakeYAML.load({arg_name}) where {arg_name} comes from HTTP request. "
                                                  "RCE possible via !!javax.script.ScriptEngineManager gadget. "
                                                  "Use SafeConstructor: new Yaml(new SafeConstructor())")
                            else:
                                self._add_finding(i, "Insecure Deserialization - SnakeYAML.load() usage",
                                                  VulnCategory.DESERIALIZATION, Severity.HIGH, "MEDIUM",
                                                  description="SnakeYAML.load() detected. If input is untrusted, this enables RCE. "
                                                  "Use SafeConstructor: new Yaml(new SafeConstructor())")

            # Pattern 2: new Yaml() without SafeConstructor - configuration warning
            if re.search(r'new\s+Yaml\s*\(\s*\)', line):
                # Check if SafeConstructor is used anywhere nearby
                context = '\n'.join(self.source_lines[max(0, i-3):min(len(self.source_lines), i+3)])
                if not re.search(r'SafeConstructor|BaseConstructor', context):
                    self._add_finding(i, "Insecure Deserialization - Yaml without SafeConstructor",
                                      VulnCategory.DESERIALIZATION, Severity.HIGH, "MEDIUM",
                                      description="new Yaml() without SafeConstructor allows arbitrary object instantiation. "
                                      "If used with untrusted input, RCE is possible. "
                                      "Use: new Yaml(new SafeConstructor())")

    def _check_xxe(self):
        """Check for XXE patterns."""
        for i, line in enumerate(self.source_lines, 1):
            stripped = line.strip()
            if stripped.startswith('//') or stripped.startswith('/*') or stripped.startswith('*'):
                continue

            # DocumentBuilderFactory without secure configuration
            if re.search(r'DocumentBuilderFactory\s*\.\s*newInstance\s*\(', line):
                # Look for security features being set
                context = '\n'.join(self.source_lines[i:min(len(self.source_lines), i+10)])
                has_secure_config = re.search(
                    r'setFeature.*(?:disallow-doctype-decl|external-general-entities|external-parameter-entities)',
                    context
                )
                if not has_secure_config:
                    self._add_finding(i, "XXE - DocumentBuilderFactory without secure configuration",
                                      VulnCategory.XXE, Severity.HIGH, "MEDIUM",
                                      description="DocumentBuilderFactory should disable external entities.")

            # SAXParserFactory
            if re.search(r'SAXParserFactory\s*\.\s*newInstance\s*\(', line):
                context = '\n'.join(self.source_lines[i:min(len(self.source_lines), i+10)])
                has_secure_config = re.search(r'setFeature.*external', context)
                if not has_secure_config:
                    self._add_finding(i, "XXE - SAXParserFactory without secure configuration",
                                      VulnCategory.XXE, Severity.HIGH, "MEDIUM",
                                      description="SAXParserFactory should disable external entities.")

            # XMLInputFactory
            if re.search(r'XMLInputFactory\s*\.\s*newInstance\s*\(', line):
                context = '\n'.join(self.source_lines[i:min(len(self.source_lines), i+10)])
                has_secure_config = re.search(r'setProperty.*SUPPORT_DTD|IS_SUPPORTING_EXTERNAL_ENTITIES', context)
                if not has_secure_config:
                    self._add_finding(i, "XXE - XMLInputFactory without secure configuration",
                                      VulnCategory.XXE, Severity.HIGH, "MEDIUM",
                                      description="XMLInputFactory should disable DTD and external entities.")

    def _check_jndi_injection(self):
        """Check for JNDI injection patterns."""
        for i, line in enumerate(self.source_lines, 1):
            stripped = line.strip()
            if stripped.startswith('//') or stripped.startswith('/*') or stripped.startswith('*'):
                continue

            # JNDI lookup with tainted data
            if re.search(r'\.lookup\s*\(', line):
                is_tainted, taint_var = self._is_tainted(line)
                context = '\n'.join(self.source_lines[max(0, i-5):i+1])
                has_jndi_context = re.search(r'(?:InitialContext|Context|JndiTemplate)', context)

                if has_jndi_context and is_tainted:
                    self._add_finding(i, "JNDI Injection - lookup with tainted data",
                                      VulnCategory.CODE_INJECTION, Severity.CRITICAL, "HIGH", taint_var,
                                      "User-controlled JNDI lookup can lead to RCE (Log4Shell-style).")

            # SpEL (Spring Expression Language) injection
            if re.search(r'SpelExpressionParser|ExpressionParser|parseExpression|StandardEvaluationContext', line):
                is_tainted, taint_var = self._is_tainted(line)
                if is_tainted:
                    self._add_finding(i, "SpEL Injection - Expression parser with tainted data",
                                      VulnCategory.CODE_INJECTION, Severity.CRITICAL, "HIGH", taint_var,
                                      "User-controlled SpEL expression enables RCE via T(java.lang.Runtime).exec().")
                elif re.search(r'parseExpression\s*\(', line):
                    context = '\n'.join(self.source_lines[max(0, i-5):i+1])
                    # Check for user input flowing into expression
                    if re.search(r'request\.|@RequestParam|@PathVariable|getParameter', context):
                        self._add_finding(i, "SpEL Injection - parseExpression near user input",
                                          VulnCategory.CODE_INJECTION, Severity.HIGH, "MEDIUM",
                                          description="SpEL parseExpression() near user input handling. Verify expression source.")

            # OGNL (Object-Graph Navigation Language) injection - Struts2 style
            if re.search(r'OgnlContext|Ognl\.getValue|Ognl\.setValue|OgnlUtil|ValueStack', line):
                is_tainted, taint_var = self._is_tainted(line)
                if is_tainted:
                    self._add_finding(i, "OGNL Injection - OGNL evaluation with tainted data",
                                      VulnCategory.CODE_INJECTION, Severity.CRITICAL, "HIGH", taint_var,
                                      "User-controlled OGNL expression enables RCE (Struts2 CVE-style).")
                else:
                    self._add_finding(i, "OGNL Expression - Potential injection point",
                                      VulnCategory.CODE_INJECTION, Severity.HIGH, "MEDIUM",
                                      description="OGNL evaluation detected. Verify expression is not user-controlled.")

            # MVEL (MVFLEX Expression Language) injection
            if re.search(r'MVEL\.eval|MVEL\.compileExpression|MVELInterpretedRuntime', line):
                is_tainted, taint_var = self._is_tainted(line)
                if is_tainted:
                    self._add_finding(i, "MVEL Injection - MVEL evaluation with tainted data",
                                      VulnCategory.CODE_INJECTION, Severity.CRITICAL, "HIGH", taint_var,
                                      "User-controlled MVEL expression enables code execution.")

            # EL (Expression Language) injection in JSP/JSF
            if re.search(r'ELProcessor|ExpressionFactory|ValueExpression|MethodExpression', line):
                is_tainted, taint_var = self._is_tainted(line)
                if is_tainted:
                    self._add_finding(i, "EL Injection - Expression evaluation with tainted data",
                                      VulnCategory.CODE_INJECTION, Severity.CRITICAL, "HIGH", taint_var,
                                      "User-controlled EL expression can lead to code execution in JSP/JSF.")

            # URLClassLoader for remote class loading
            if re.search(r'URLClassLoader|new\s+URL\s*\([^)]*\)\s*.*\.loadClass', line):
                is_tainted, taint_var = self._is_tainted(line)
                if is_tainted:
                    self._add_finding(i, "Remote Code Loading - URLClassLoader with tainted URL",
                                      VulnCategory.CODE_INJECTION, Severity.CRITICAL, "HIGH", taint_var,
                                      "User-controlled URL in class loader enables remote code execution.")
                else:
                    self._add_finding(i, "Remote Code Loading - URLClassLoader usage",
                                      VulnCategory.CODE_INJECTION, Severity.HIGH, "MEDIUM",
                                      description="URLClassLoader can load remote code. Verify URL source.")

    def _check_script_engine(self):
        """Check for script engine code injection, including Base64-decoded payloads."""
        # Track Base64 decoded variables for detecting obfuscated code execution
        base64_decoded_vars = set()

        for i, line in enumerate(self.source_lines, 1):
            stripped = line.strip()
            if stripped.startswith('//') or stripped.startswith('/*') or stripped.startswith('*'):
                continue

            # Track Base64 decoding that might flow to script engine
            # Pattern: String decoded = new String(Base64.getDecoder().decode(input))
            if re.search(r'Base64\s*\.\s*getDecoder\s*\(\s*\)\s*\.\s*decode\s*\(', line):
                is_tainted, taint_var = self._is_tainted(line)
                # Extract the result variable if present
                var_match = re.search(r'(?:String|byte\s*\[\s*\]|var)\s+(\w+)\s*=', line)
                if var_match:
                    base64_decoded_vars.add(var_match.group(1))
                    if is_tainted:
                        # Check if this flows to ScriptEngine in nearby lines
                        context = '\n'.join(self.source_lines[i-1:min(len(self.source_lines), i+10)])
                        if re.search(r'ScriptEngine|\.eval\s*\(', context):
                            self._add_finding(i, "Code Injection - Base64 decoded data flows to ScriptEngine",
                                              VulnCategory.CODE_INJECTION, Severity.CRITICAL, "HIGH", taint_var,
                                              "User input Base64-decoded then executed via ScriptEngine. "
                                              "Attacker can encode malicious script to evade detection.")

            # Track new String(decoded) - propagate base64 tracking
            new_string_match = re.search(r'(?:String)\s+(\w+)\s*=\s*new\s+String\s*\(\s*(\w+)', line)
            if new_string_match:
                result_var = new_string_match.group(1)
                source_var = new_string_match.group(2)
                if source_var in base64_decoded_vars:
                    base64_decoded_vars.add(result_var)

            # ScriptEngine.eval - enhanced detection
            if re.search(r'ScriptEngine|\.eval\s*\(', line):
                is_tainted, taint_var = self._is_tainted(line)
                context = '\n'.join(self.source_lines[max(0, i-5):i+1])
                has_script_engine = re.search(r'ScriptEngine|getEngineByName', context)

                # Check if any Base64 decoded var is used in eval
                uses_decoded = any(re.search(rf'\b{re.escape(var)}\b', line) for var in base64_decoded_vars)

                # Check if eval argument is a hardcoded string literal (lower risk)
                # Pattern: .eval("...") or .eval('...')
                eval_with_literal = re.search(r'\.eval\s*\(\s*["\'][^"\']*["\']\s*\)', line)

                if has_script_engine:
                    if uses_decoded:
                        self._add_finding(i, "Code Injection - ScriptEngine.eval with Base64-decoded payload",
                                          VulnCategory.CODE_INJECTION, Severity.CRITICAL, "HIGH",
                                          description="ScriptEngine.eval() executes Base64-decoded data. "
                                                      "Obfuscation technique to hide malicious scripts.")
                    elif is_tainted:
                        self._add_finding(i, "Code Injection - ScriptEngine.eval with tainted data",
                                          VulnCategory.CODE_INJECTION, Severity.CRITICAL, "HIGH", taint_var,
                                          "User-controlled data in ScriptEngine.eval() enables code execution.")
                    elif re.search(r'\.eval\s*\(', line):
                        if eval_with_literal:
                            # Hardcoded string literal - much lower risk
                            self._add_finding(i, "Code Injection - ScriptEngine.eval with hardcoded script (lower risk)",
                                              VulnCategory.CODE_INJECTION, Severity.LOW, "LOW",
                                              description="ScriptEngine.eval() with hardcoded string literal. "
                                                          "Lower risk since script content is not user-controlled.")
                        else:
                            self._add_finding(i, "Code Injection - ScriptEngine.eval usage",
                                              VulnCategory.CODE_INJECTION, Severity.HIGH, "MEDIUM",
                                              description="ScriptEngine.eval() detected. Verify input is not user-controlled.")

            # Detect ScriptEngineManager chain pattern
            # Pattern: new ScriptEngineManager().getEngineByName("javascript").eval(...)
            if re.search(r'ScriptEngineManager\s*\(\s*\)\s*\.\s*getEngineByName\s*\([^)]+\)\s*\.\s*eval\s*\(', line):
                is_tainted, taint_var = self._is_tainted(line)
                if is_tainted:
                    self._add_finding(i, "Code Injection - Inline ScriptEngine chain with tainted data",
                                      VulnCategory.CODE_INJECTION, Severity.CRITICAL, "HIGH", taint_var,
                                      "Inline ScriptEngineManager().getEngineByName().eval() with user data. "
                                      "Direct code execution path.")
                else:
                    uses_decoded = any(re.search(rf'\b{re.escape(var)}\b', line) for var in base64_decoded_vars)
                    if uses_decoded:
                        self._add_finding(i, "Code Injection - Inline ScriptEngine chain with decoded payload",
                                          VulnCategory.CODE_INJECTION, Severity.CRITICAL, "HIGH",
                                          description="Inline ScriptEngineManager chain executes decoded payload.")

    def _check_reflection_injection(self):
        """Check for reflection-based injection."""
        for i, line in enumerate(self.source_lines, 1):
            stripped = line.strip()
            if stripped.startswith('//') or stripped.startswith('/*') or stripped.startswith('*'):
                continue

            # Class.forName with tainted data
            if re.search(r'Class\s*\.\s*forName\s*\(', line):
                is_tainted, taint_var = self._is_tainted(line)
                if is_tainted:
                    self._add_finding(i, "Code Injection - Class.forName with tainted data",
                                      VulnCategory.CODE_INJECTION, Severity.CRITICAL, "HIGH", taint_var,
                                      "User-controlled class loading can lead to code execution.")

            # Method.invoke with tainted data
            if re.search(r'\.invoke\s*\(', line):
                is_tainted, taint_var = self._is_tainted(line)
                context = '\n'.join(self.source_lines[max(0, i-5):i+1])
                has_reflection = re.search(r'getMethod|getDeclaredMethod|Method\s+\w+', context)

                if has_reflection and is_tainted:
                    self._add_finding(i, "Code Injection - Reflection invoke with tainted data",
                                      VulnCategory.CODE_INJECTION, Severity.HIGH, "MEDIUM", taint_var,
                                      "Reflection-based method invocation with user data.")

            # Constructor.newInstance with tainted data
            if re.search(r'\.newInstance\s*\(', line):
                is_tainted, taint_var = self._is_tainted(line)
                context = '\n'.join(self.source_lines[max(0, i-5):i+1])
                has_reflection = re.search(r'getConstructor|getDeclaredConstructor|Constructor', context)

                if has_reflection and is_tainted:
                    self._add_finding(i, "Code Injection - Reflection newInstance with tainted data",
                                      VulnCategory.CODE_INJECTION, Severity.HIGH, "MEDIUM", taint_var,
                                      "Reflection-based object creation with user data.")

    def _check_jni_native(self):
        """Check for JNI native method patterns - taint can escape to C/C++ code."""
        native_methods = {}  # method_name -> line_number
        loadlibrary_found = False
        loadlibrary_line = 0

        for i, line in enumerate(self.source_lines, 1):
            stripped = line.strip()
            if stripped.startswith('//') or stripped.startswith('/*') or stripped.startswith('*'):
                continue

            # Detect native method declarations: public native void methodName(...)
            native_match = re.search(r'\bnative\b\s+\w+\s+(\w+)\s*\(', line)
            if native_match:
                method_name = native_match.group(1)
                native_methods[method_name] = i
                self._add_finding(i, "Evasion - JNI Native Method Declaration",
                                  VulnCategory.CODE_INJECTION, Severity.MEDIUM, "MEDIUM",
                                  description=f"Native method '{method_name}' declared. "
                                             f"Code execution escapes to C/C++ - static analysis cannot follow.")

            # Detect System.loadLibrary() - loading native code
            if re.search(r'System\s*\.\s*loadLibrary\s*\(', line):
                loadlibrary_found = True
                loadlibrary_line = i
                self._add_finding(i, "Evasion - Native Library Loading",
                                  VulnCategory.CODE_INJECTION, Severity.HIGH, "HIGH",
                                  description="System.loadLibrary() loads native code. "
                                             "Potential for hidden command execution in C/C++ code.")

            # Detect System.load() - loading native code by path
            if re.search(r'System\s*\.\s*load\s*\(', line):
                is_tainted, taint_var = self._is_tainted(line)
                severity = Severity.CRITICAL if is_tainted else Severity.HIGH
                self._add_finding(i, "Evasion - Native Library Path Loading",
                                  VulnCategory.CODE_INJECTION, severity, "HIGH" if is_tainted else "MEDIUM",
                                  description="System.load() loads native library by path. "
                                             "Can load arbitrary native code.")

        # Check for calls to native methods with tainted data
        for i, line in enumerate(self.source_lines, 1):
            stripped = line.strip()
            if stripped.startswith('//') or stripped.startswith('/*') or stripped.startswith('*'):
                continue

            for method_name, decl_line in native_methods.items():
                # Look for calls to the native method
                call_match = re.search(rf'\b{method_name}\s*\(([^)]*)\)', line)
                if call_match and i != decl_line:
                    is_tainted, taint_var = self._is_tainted(line)
                    args = call_match.group(1)

                    if is_tainted:
                        self._add_finding(i, f"Critical Evasion - Tainted data flows to native method '{method_name}'",
                                          VulnCategory.COMMAND_INJECTION, Severity.CRITICAL, "HIGH", taint_var,
                                          f"User-controlled data passes to native method '{method_name}()'. "
                                          f"Native code at line {decl_line} may execute arbitrary commands. "
                                          f"Static analysis cannot verify safety.")
                    elif loadlibrary_found:
                        self._add_finding(i, f"Potential RCE - Native method '{method_name}' called",
                                          VulnCategory.COMMAND_INJECTION, Severity.HIGH, "MEDIUM",
                                          description=f"Native method '{method_name}()' called. "
                                                     f"Verify arguments are not user-controlled. "
                                                     f"Native library loaded at line {loadlibrary_line}.")

    def _check_second_order_sqli(self):
        """Detect 2nd-order SQLi with entity-sourced values in native queries."""
        for i, line in enumerate(self.source_lines, 1):
            stripped = line.strip()
            if stripped.startswith('//') or stripped.startswith('/*') or stripped.startswith('*'):
                continue

            # Check for native queries with entity-sourced values
            if re.search(r'createNativeQuery\s*\(', line):
                is_db, db_var, source = self._is_db_sourced(line)
                if is_db and ('+' in line or 'concat' in line.lower()):
                    self._add_finding(
                        i, "2nd-Order SQLi - Native query with entity value",
                        VulnCategory.SQL_INJECTION, Severity.CRITICAL, "HIGH", db_var,
                        f"Entity value from {source} concatenated into native query. "
                        "Stored payload can execute arbitrary SQL."
                    )

            # Check HQL with entity values (createQuery)
            if re.search(r'createQuery\s*\(', line) and not re.search(r'createNativeQuery', line):
                is_db, db_var, source = self._is_db_sourced(line)
                if is_db and ('+' in line or 'concat' in line.lower()):
                    self._add_finding(
                        i, "2nd-Order SQLi - HQL with entity value",
                        VulnCategory.SQL_INJECTION, Severity.CRITICAL, "HIGH", db_var,
                        f"Entity value from {source} in HQL query. "
                        "Enables HQL injection and potential DB function hijacking."
                    )

            # JdbcTemplate with entity values
            if re.search(r'jdbcTemplate\s*\.\s*(?:query|update|execute)', line):
                is_db, db_var, source = self._is_db_sourced(line)
                if is_db and '+' in line:
                    self._add_finding(
                        i, "2nd-Order SQLi - JdbcTemplate with entity value",
                        VulnCategory.SQL_INJECTION, Severity.CRITICAL, "HIGH", db_var,
                        f"Entity value from {source} in JDBC query."
                    )

    def _check_criteria_api_sqli(self):
        """Detect 2nd-order SQLi in Hibernate Criteria API (root.get, cb.asc/desc)."""
        criteria_sinks = [
            (r'root\s*\.\s*get\s*\(', 'root.get()'),
            (r'cb\s*\.\s*asc\s*\(\s*root\s*\.\s*get\s*\(', 'cb.asc(root.get())'),
            (r'cb\s*\.\s*desc\s*\(\s*root\s*\.\s*get\s*\(', 'cb.desc(root.get())'),
            (r'criteriaBuilder\s*\.\s*asc\s*\(', 'CriteriaBuilder.asc()'),
            (r'criteriaBuilder\s*\.\s*desc\s*\(', 'CriteriaBuilder.desc()'),
        ]

        for i, line in enumerate(self.source_lines, 1):
            stripped = line.strip()
            if stripped.startswith('//') or stripped.startswith('/*') or stripped.startswith('*'):
                continue

            for pattern, sink_name in criteria_sinks:
                if re.search(pattern, line):
                    is_db, db_var, source = self._is_db_sourced(line)
                    if is_db:
                        self._add_finding(
                            i, f"2nd-Order SQLi - Criteria API {sink_name} with entity value",
                            VulnCategory.SQL_INJECTION, Severity.CRITICAL, "HIGH", db_var,
                            f"Entity value from {source} used in {sink_name}. "
                            "Developers assume Criteria API is safe - it's not when column names are dynamic."
                        )

    def _check_hql_function_injection(self):
        """Detect HQL function injection - the 'Final Boss' pattern."""
        for i, line in enumerate(self.source_lines, 1):
            stripped = line.strip()
            if stripped.startswith('//') or stripped.startswith('/*') or stripped.startswith('*'):
                continue

            # Check for HQL string building patterns
            hql_patterns = [
                (r'String\s+\w*[hH][qQ][lL]\w*\s*=', 'HQL string'),
                (r'String\.format\s*\([^)]*FROM\s', 'String.format HQL'),
                (r'MessageFormat\.format\s*\([^)]*FROM\s', 'MessageFormat HQL'),
                (r'StringBuilder.*append.*FROM\s', 'StringBuilder HQL'),
            ]

            for pattern, hql_type in hql_patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    is_db, db_var, source = self._is_db_sourced(line)
                    if is_db:
                        self._add_finding(
                            i, f"2nd-Order SQLi - {hql_type} with entity value (FINAL BOSS)",
                            VulnCategory.SQL_INJECTION, Severity.CRITICAL, "HIGH", db_var,
                            f"Entity value from {source} used in HQL construction. "
                            "Enables DB function hijacking (dbms_pipe.receive_message for Oracle, "
                            "pg_sleep for PostgreSQL) - can exfiltrate data or cause DoS."
                        )

            # Direct createQuery with string concatenation
            if re.search(r'createQuery\s*\(\s*["\']', line):
                # Look at surrounding context for entity-sourced concatenation
                context_start = max(0, i - 5)
                context_lines = self.source_lines[context_start:i]
                context = '\n'.join(context_lines)

                is_db, db_var, source = self._is_db_sourced(context)
                if is_db and re.search(r'createQuery\s*\([^)]*\+', line):
                    self._add_finding(
                        i, "2nd-Order SQLi - HQL concatenation with entity value",
                        VulnCategory.SQL_INJECTION, Severity.CRITICAL, "HIGH", db_var,
                        f"Entity value from {source} concatenated into HQL. "
                        "Enables HQL function injection attacks."
                    )

    def _check_table_name_injection(self):
        """Detect table name injection in native queries (multi-tenant attacks)."""
        table_patterns = [
            r'(?:FROM|INTO|UPDATE|JOIN)\s*"\s*\+',
            r'DELETE\s+FROM\s*"\s*\+',
            r'INSERT\s+INTO\s*"\s*\+',
        ]

        for i, line in enumerate(self.source_lines, 1):
            stripped = line.strip()
            if stripped.startswith('//') or stripped.startswith('/*') or stripped.startswith('*'):
                continue

            for pattern in table_patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    is_db, db_var, source = self._is_db_sourced(line)
                    if is_db:
                        self._add_finding(
                            i, "2nd-Order SQLi - Table name injection",
                            VulnCategory.SQL_INJECTION, Severity.CRITICAL, "HIGH", db_var,
                            f"Table name from {source} in query. "
                            "Multi-tenant 'Bunker Buster' attack - can access any table."
                        )

    def _check_xpath_injection(self):
        """Detect 2nd-order XPath injection with entity-sourced values.

        XPath injection is harder to detect than SQLi because:
        1. No SQL keywords (SELECT, FROM, WHERE) to trigger regex
        2. Structural manipulation - breaking out of XML tree logic
        3. Blind exfiltration - character-by-character data extraction

        Payloads:
        - Breakout: "Engineering' or 1=1 or 'a'='a"
        - Root access: "/*" or "//*"
        - Brute force: "user[password='123']"
        """
        for i, line in enumerate(self.source_lines, 1):
            stripped = line.strip()
            if stripped.startswith('//') or stripped.startswith('/*') or stripped.startswith('*'):
                continue

            # XPath.evaluate() sink with string concatenation
            if re.search(r'\.evaluate\s*\(.*\+', line):
                # Check for integer-only position patterns (safe from injection)
                # Pattern: "//item[" + pos + "]" where pos is an integer variable
                int_position_var_names = r'(?:pos|position|index|idx|i|n|num|count|page|offset|limit)'
                int_position_patterns = [
                    rf'\+\s*{int_position_var_names}\s*\+',  # + pos +
                    rf'\+\s*{int_position_var_names}\s*[,)]',  # + pos, or + pos)
                    r'Integer\.(?:parseInt|valueOf)',  # Integer.parseInt() or valueOf
                    r'\(\s*int\s*\)',  # (int) cast
                    r'\["\s*\+\s*\w+\s*\+\s*"?\]',  # ["+ var +"] bracket position pattern
                ]
                is_int_position = any(re.search(p, line, re.IGNORECASE) for p in int_position_patterns)

                is_db, db_var, source = self._is_db_sourced(line)
                if is_db:
                    self._add_finding(
                        i, "2nd-Order XPath Injection - evaluate() with entity value",
                        VulnCategory.XPATH_INJECTION, Severity.CRITICAL, "HIGH", db_var,
                        f"Entity value from {source} used in XPath.evaluate(). "
                        "Payload can break out of XML tree logic or enumerate nodes."
                    )
                elif re.search(r'\.evaluate\s*\(\s*["\'].*\+', line):
                    # Check for any variable in concat
                    if is_int_position:
                        # Integer-only position - lower risk
                        self._add_finding(
                            i, "XPath Injection - Integer position in evaluate() (lower risk)",
                            VulnCategory.XPATH_INJECTION, Severity.MEDIUM, "LOW",
                            "XPath expression built with integer position variable. "
                            "Lower risk since integers cannot contain XPath injection payloads."
                        )
                    else:
                        self._add_finding(
                            i, "XPath Injection - String concatenation in evaluate()",
                            VulnCategory.XPATH_INJECTION, Severity.HIGH, "MEDIUM",
                            "XPath expression built with string concatenation."
                        )

            # XPath.compile() sink with concatenation
            if re.search(r'\.compile\s*\(.*\+', line):
                is_db, db_var, source = self._is_db_sourced(line)
                if is_db:
                    self._add_finding(
                        i, "2nd-Order XPath Injection - compile() with entity value",
                        VulnCategory.XPATH_INJECTION, Severity.CRITICAL, "HIGH", db_var,
                        f"Entity value from {source} compiled into XPath expression. "
                        "Attacker can control XML node selection."
                    )

            # String.format XPath pattern
            if re.search(r'String\.format\s*\(\s*["\'][^"\']*//[^"\']*%s', line):
                is_db, db_var, source = self._is_db_sourced(line)
                if is_db:
                    self._add_finding(
                        i, "2nd-Order XPath Injection - String.format XPath",
                        VulnCategory.XPATH_INJECTION, Severity.CRITICAL, "HIGH", db_var,
                        f"Entity value from {source} formatted into XPath. "
                        "String.format doesn't escape XPath special characters."
                    )

            # MessageFormat XPath pattern
            if re.search(r'MessageFormat\.format\s*\(.*//.*\{0\}', line):
                is_db, db_var, source = self._is_db_sourced(line)
                if is_db:
                    self._add_finding(
                        i, "2nd-Order XPath Injection - MessageFormat XPath",
                        VulnCategory.XPATH_INJECTION, Severity.CRITICAL, "HIGH", db_var,
                        f"Entity value from {source} in MessageFormat XPath."
                    )

            # StringBuilder with XPath patterns
            if re.search(r'\.append\s*\(.*[@\[\]/].*\+', line):
                is_db, db_var, source = self._is_db_sourced(line)
                if is_db and re.search(r'//|@\w+|/\w+\[', line):
                    self._add_finding(
                        i, "2nd-Order XPath Injection - StringBuilder XPath",
                        VulnCategory.XPATH_INJECTION, Severity.CRITICAL, "HIGH", db_var,
                        f"Entity value from {source} appended to XPath query."
                    )

            # Direct entity getter in XPath context
            if re.search(r'\.evaluate\s*\(.*\.get\w+\s*\(\s*\)', line):
                is_db, db_var, source = self._is_db_sourced(line)
                if is_db:
                    self._add_finding(
                        i, "2nd-Order XPath Injection - Direct getter in evaluate()",
                        VulnCategory.XPATH_INJECTION, Severity.CRITICAL, "HIGH", db_var,
                        f"Entity getter from {source} used directly in XPath.evaluate()."
                    )

    def _check_reflection_injection(self):
        """Detect SQL injection via reflection - the 'Reflection Ghost' pattern.

        Pattern: Method.invoke(statement, taintedQuery)
        Scanners looking for executeQuery() see nothing - it's hidden behind invoke().
        """
        for i, line in enumerate(self.source_lines, 1):
            stripped = line.strip()
            if stripped.startswith('//') or stripped.startswith('/*') or stripped.startswith('*'):
                continue

            # Method.invoke() with tainted argument
            if re.search(r'\.invoke\s*\(', line):
                is_db, db_var, source = self._is_db_sourced(line)
                if is_db:
                    self._add_finding(
                        i, "Evasive SQLi - Reflection Ghost (Method.invoke with entity value)",
                        VulnCategory.SQL_INJECTION, Severity.CRITICAL, "HIGH", db_var,
                        f"Entity value from {source} passed to Method.invoke(). "
                        "Reflection hides the actual SQL execution method."
                    )
                # Check for tainted variables in invoke
                for var in self.tainted_vars:
                    if re.search(rf'\b{re.escape(var)}\b', line):
                        self._add_finding(
                            i, "Evasive SQLi - Reflection Ghost (Method.invoke with tainted data)",
                            VulnCategory.SQL_INJECTION, Severity.CRITICAL, "HIGH", var,
                            "Tainted data passed to Method.invoke(). Reflection bypasses sink detection."
                        )
                        break

            # Class.forName with entity-sourced class name (RCE risk)
            if re.search(r'Class\.forName\s*\(', line):
                is_db, db_var, source = self._is_db_sourced(line)
                if is_db:
                    self._add_finding(
                        i, "Evasive RCE - Class.forName with entity value",
                        VulnCategory.CODE_INJECTION, Severity.CRITICAL, "HIGH", db_var,
                        f"Entity value from {source} in Class.forName(). Can load arbitrary classes."
                    )

            # getDeclaredMethod/getMethod with tainted method name
            if re.search(r'\.get(?:Declared)?Method\s*\(', line):
                is_db, db_var, source = self._is_db_sourced(line)
                if is_db:
                    self._add_finding(
                        i, "Evasive RCE - getDeclaredMethod with entity value",
                        VulnCategory.CODE_INJECTION, Severity.CRITICAL, "HIGH", db_var,
                        f"Entity value from {source} used to get method by name. Enables arbitrary method calls."
                    )

    def _check_spring_query_annotation(self):
        """Detect SQL injection in Spring @Query annotations.

        The vulnerability is in METADATA, not code!
        Most scanners ignore annotations entirely.
        """
        in_annotation = False
        annotation_start = 0

        for i, line in enumerate(self.source_lines, 1):
            stripped = line.strip()

            # Detect @Query annotation with SpEL or concatenation
            if re.search(r'@Query\s*\(', line):
                in_annotation = True
                annotation_start = i

            if in_annotation:
                # SpEL injection: #{#param} in native query
                if re.search(r'#\{#?\w+', line) and re.search(r'nativeQuery\s*=\s*true', line):
                    self._add_finding(
                        i, "Spring @Query SpEL Injection (nativeQuery)",
                        VulnCategory.SQL_INJECTION, Severity.CRITICAL, "HIGH",
                        description="SpEL expression in native query annotation. "
                                   "Parameter values can inject SQL via :#{#param} syntax."
                    )

                # SpEL in ORDER BY clause
                if re.search(r'ORDER\s+BY.*#\{', line, re.IGNORECASE):
                    self._add_finding(
                        i, "Spring @Query ORDER BY Injection",
                        VulnCategory.SQL_INJECTION, Severity.CRITICAL, "HIGH",
                        description="SpEL in ORDER BY clause. Allows structural SQL injection."
                    )

                # Check for closing paren
                if ')' in line and in_annotation:
                    in_annotation = False

            # @NamedNativeQuery with dynamic content
            if re.search(r'@NamedNativeQuery\s*\(', line):
                context = '\n'.join(self.source_lines[i-1:min(len(self.source_lines), i+5)])
                if re.search(r'query\s*=.*:', context):
                    self._add_finding(
                        i, "JPA @NamedNativeQuery with parameter placeholder",
                        VulnCategory.SQL_INJECTION, Severity.HIGH, "MEDIUM",
                        description="Named native query with parameter. Verify parameter is not used in structural position."
                    )

    def _check_stringbuilder_chain(self):
        """Detect taint flow through StringBuilder chains.

        Pattern: StringBuilder built across multiple methods loses taint tracking.
        """
        # Track StringBuilder variables
        builder_vars = {}  # var -> (line, is_tainted)

        for i, line in enumerate(self.source_lines, 1):
            stripped = line.strip()
            if stripped.startswith('//') or stripped.startswith('/*'):
                continue

            # StringBuilder creation
            match = re.search(r'(\w+)\s*=\s*new\s+StringBuilder\s*\(', line)
            if match:
                var_name = match.group(1)
                builder_vars[var_name] = (i, False)

            # Check for append with tainted data
            for builder_var in list(builder_vars.keys()):
                append_match = re.search(rf'{re.escape(builder_var)}\.append\s*\(', line)
                if append_match:
                    is_db, db_var, source = self._is_db_sourced(line)
                    if is_db:
                        builder_vars[builder_var] = (i, True)

                    for taint_var in self.tainted_vars:
                        if re.search(rf'\b{re.escape(taint_var)}\b', line):
                            builder_vars[builder_var] = (i, True)

            # Check for toString() used in SQL sink
            for builder_var, (def_line, is_tainted) in builder_vars.items():
                if is_tainted and re.search(rf'{re.escape(builder_var)}\.toString\s*\(\s*\)', line):
                    # Check if this flows to SQL execution
                    context = '\n'.join(self.source_lines[i-1:min(len(self.source_lines), i+3)])
                    if re.search(r'executeQuery|createQuery|createNativeQuery|execute\s*\(', context):
                        self._add_finding(
                            i, "Evasive SQLi - StringBuilder chain with tainted data",
                            VulnCategory.SQL_INJECTION, Severity.CRITICAL, "HIGH", builder_var,
                            "StringBuilder accumulated tainted data across method calls. "
                            "Taint flows through append() chain to SQL sink."
                        )

    def _check_encoding_passthrough(self):
        """Detect SQL injection through encoding functions.

        unhex(), from_base64(), CONVERT() do NOT sanitize - they're passthroughs!
        """
        encoding_funcs = [
            (r"unhex\s*\(", "unhex()"),
            (r"from_base64\s*\(", "from_base64()"),
            (r"CONVERT\s*\([^)]*USING", "CONVERT...USING"),
            (r"DECODE\s*\(", "DECODE()"),
            (r"HEX\s*\(", "HEX()"),
            (r"TO_BASE64\s*\(", "TO_BASE64()"),
        ]

        sql_keywords = r'(?:SELECT|INSERT|UPDATE|DELETE|FROM|WHERE)'

        for i, line in enumerate(self.source_lines, 1):
            stripped = line.strip()
            if stripped.startswith('//') or stripped.startswith('/*'):
                continue

            for pattern, func_name in encoding_funcs:
                if re.search(pattern, line, re.IGNORECASE):
                    # Check if in SQL context (execution or string construction)
                    is_sql_context = (
                        re.search(r'createNativeQuery|createQuery|executeQuery|execute\s*\(', line) or
                        (re.search(sql_keywords, line, re.IGNORECASE) and '+' in line)
                    )

                    if is_sql_context:
                        is_db, db_var, source = self._is_db_sourced(line)
                        if is_db:
                            self._add_finding(
                                i, f"Evasive SQLi - Encoding bypass via {func_name}",
                                VulnCategory.SQL_INJECTION, Severity.CRITICAL, "HIGH", db_var,
                                f"{func_name} does NOT sanitize input - it's a passthrough! "
                                f"Entity value from {source} flows through encoder to SQL."
                            )
                        else:
                            # Check for tainted variables (use RHS only to avoid matching declarations)
                            rhs = line.split('=', 1)[1] if '=' in line else line
                            for taint_var in self.tainted_vars:
                                if re.search(rf'\b{re.escape(taint_var)}\b', rhs):
                                    self._add_finding(
                                        i, f"Evasive SQLi - Encoding bypass via {func_name}",
                                        VulnCategory.SQL_INJECTION, Severity.CRITICAL, "HIGH", taint_var,
                                        f"{func_name} does NOT sanitize - tainted data passes through to SQL."
                                    )
                                    break

    def _check_lambda_stream_injection(self):
        """Detect taint flow through lambda/stream operations.

        Functional programming can hide taint flow from scanners.
        """
        for i, line in enumerate(self.source_lines, 1):
            stripped = line.strip()
            if stripped.startswith('//') or stripped.startswith('/*'):
                continue

            # Lambda with SQL concatenation
            if re.search(r'->\s*["\'].*(?:SELECT|INSERT|UPDATE|DELETE|FROM|WHERE).*\+', line, re.IGNORECASE):
                is_db, db_var, source = self._is_db_sourced(line)
                if is_db:
                    self._add_finding(
                        i, "Evasive SQLi - Lambda taint tunnel",
                        VulnCategory.SQL_INJECTION, Severity.CRITICAL, "HIGH", db_var,
                        f"Entity value from {source} flows through lambda to SQL construction."
                    )

            # Stream reduce building query
            if re.search(r'\.reduce\s*\(.*(?:SELECT|WHERE|AND|OR)', line, re.IGNORECASE):
                is_db, db_var, source = self._is_db_sourced(line)
                if is_db:
                    self._add_finding(
                        i, "Evasive SQLi - Stream reduce SQL construction",
                        VulnCategory.SQL_INJECTION, Severity.CRITICAL, "HIGH", db_var,
                        f"Entity value from {source} accumulated via Stream.reduce() into SQL."
                    )

            # Supplier/Callable with SQL
            if re.search(r'(?:Supplier|Callable).*(?:executeQuery|createQuery|createNativeQuery)', line):
                context = '\n'.join(self.source_lines[max(0, i-5):i+1])
                is_db, db_var, source = self._is_db_sourced(context)
                if is_db:
                    self._add_finding(
                        i, "Evasive SQLi - Delayed execution wrapper",
                        VulnCategory.SQL_INJECTION, Severity.HIGH, "MEDIUM", db_var,
                        f"SQL execution wrapped in Supplier/Callable with entity value from {source}."
                    )

    def _check_array_varargs_injection(self):
        """Detect taint hidden in array elements."""
        for i, line in enumerate(self.source_lines, 1):
            stripped = line.strip()
            if stripped.startswith('//') or stripped.startswith('/*'):
                continue

            # String.join with array containing entity values
            if re.search(r'String\.join\s*\(', line):
                context = '\n'.join(self.source_lines[max(0, i-10):i+1])
                is_db, db_var, source = self._is_db_sourced(context)
                if is_db and re.search(r'(?:SELECT|INSERT|UPDATE|DELETE|FROM|WHERE)', context, re.IGNORECASE):
                    self._add_finding(
                        i, "Evasive SQLi - String.join array injection",
                        VulnCategory.SQL_INJECTION, Severity.CRITICAL, "HIGH", db_var,
                        f"Entity value from {source} hidden in array, joined into SQL."
                    )

            # MessageFormat.format with entity values
            if re.search(r'MessageFormat\.format\s*\(', line):
                is_db, db_var, source = self._is_db_sourced(line)
                if is_db:
                    context = '\n'.join(self.source_lines[max(0, i-3):i+3])
                    if re.search(r'(?:SELECT|INSERT|UPDATE|DELETE|FROM|WHERE)', context, re.IGNORECASE):
                        self._add_finding(
                            i, "Evasive SQLi - MessageFormat with entity value",
                            VulnCategory.SQL_INJECTION, Severity.CRITICAL, "HIGH", db_var,
                            f"Entity value from {source} formatted into SQL via MessageFormat."
                        )

class PHPAnalyzer:
    """
    PHP analyzer with taint tracking for common web vulnerabilities.
    Tracks $_GET, $_POST, $_REQUEST, $_COOKIE, $_SERVER as taint sources.
    Includes 2nd-order SQLi detection for:
    - Database-sourced values (fetch_assoc, fetch_object, etc.)
    - JSON-decoded values (json_decode loses taint in most scanners)
    - Unserialized objects (the "Double-Unserialize" pattern)
    - Table name injection (multi-tenant attacks)
    - Calculation sinks (SUM, COUNT, AVG, etc.)
    """

    def __init__(self, source_code: str, file_path: str):
        self.source_code = source_code
        self.source_lines = source_code.splitlines()
        self.file_path = file_path
        self.findings: List[Finding] = []
        self.tainted_vars: Dict[str, int] = {}
        # 2nd-order tracking
        self.db_sourced_vars: Dict[str, Tuple[int, str]] = {}  # var -> (line, source)
        self.json_decoded_vars: Dict[str, Tuple[int, str]] = {}  # var -> (line, source)
        self.unserialized_vars: Dict[str, Tuple[int, str]] = {}  # var -> (line, source)
        self.table_name_vars: Dict[str, Tuple[int, str]] = {}  # var -> (line, source)

        self._identify_taint_sources()
        self._check_regex_validation_gates()
        self._track_variable_assignments()
        self._track_database_sources()
        self._track_json_decoded()
        self._track_unserialized()
        self._track_table_names()

    def _check_regex_validation_gates(self):
        """Remove taint from variables validated by anchored regex with exit() gates.

        Pattern: if(!preg_match($pattern, $var)) { ... exit(); ... }
        If the regex is anchored (^...$) and the failure branch exits,
        the variable cannot carry SQL injection characters.
        """
        for i, line in enumerate(self.source_lines, 1):
            # Match if(!preg_match($pattern, $var))
            m = re.search(
                r'if\s*\(\s*!\s*preg_match\s*\(\s*(\$\w+)\s*,\s*\$(\w+)\s*\)',
                line)
            if not m:
                continue
            pattern_var = m.group(1)
            checked_var = m.group(2)

            if checked_var not in self.tainted_vars:
                continue

            # Check if the if-body (next few lines) has exit()/die()
            has_exit = False
            for j in range(i, min(i + 10, len(self.source_lines))):
                body_line = self.source_lines[j]
                if re.search(r'\b(?:exit|die|return)\b', body_line):
                    has_exit = True
                    break
                # Stop at closing brace of the if block
                if body_line.strip() == '}':
                    break
            if not has_exit:
                continue

            # Resolve the regex pattern variable (search all lines before the check)
            pattern_literal = None
            for j in range(0, i):
                pm = re.search(
                    rf'{re.escape(pattern_var)}\s*=\s*["\'](.+?)["\']',
                    self.source_lines[j])
                if pm:
                    pattern_literal = pm.group(1)

            if not pattern_literal:
                continue

            # Check if the regex is anchored (^...$)
            inner = re.sub(r'^/(.+)/[a-z]*$', r'\1', pattern_literal)
            if inner.startswith('^') and inner.endswith('$'):
                del self.tainted_vars[checked_var]

    def _identify_taint_sources(self):
        """Identify PHP superglobals and function parameters as taint sources."""
        superglobals = [
            r'\$_GET', r'\$_POST', r'\$_REQUEST', r'\$_COOKIE',
            r'\$_SERVER', r'\$_FILES', r'\$_ENV', r'\$HTTP_RAW_POST_DATA',
            r'file_get_contents\s*\(\s*["\']php://input',
        ]

        # getenv() keys that are NOT attacker-controlled
        safe_getenv_keys = {'REMOTE_ADDR', 'REMOTE_PORT', 'SERVER_ADDR', 'SERVER_PORT'}

        for i, line in enumerate(self.source_lines, 1):
            # Skip getenv("REMOTE_ADDR") and similar server-derived values
            if re.search(r'getenv\s*\(', line):
                if any(key in line for key in safe_getenv_keys):
                    continue

            for sg in superglobals:
                if re.search(sg, line):
                    # Extract variable being assigned
                    match = re.search(r'\$(\w+)\s*=', line)
                    if match:
                        # Skip if the superglobal is wrapped in a hash/sanitizer
                        # function (e.g. $password = md5($_POST["password"]))
                        # — the output is NOT user-controlled data
                        if re.search(r'=\s*(?:md5|sha1|hash|crypt|password_hash|'
                                     r'mysqli_real_escape_string|intval|floatval|'
                                     r'htmlspecialchars|htmlentities|addslashes|'
                                     r'escapeshellarg|escapeshellcmd)\s*\(', line):
                            continue
                        self.tainted_vars[match.group(1)] = i

        # Function parameters
        func_pattern = r'function\s+\w+\s*\(([^)]*)\)'
        for i, line in enumerate(self.source_lines, 1):
            match = re.search(func_pattern, line)
            if match:
                params = match.group(1)
                for param in re.findall(r'\$(\w+)', params):
                    self.tainted_vars[param] = i

    # Functions whose return value does NOT carry taint (sinks / metadata)
    TAINT_SINK_FUNCTIONS = [
        r'mysqli_query\s*\(', r'mysqli_real_query\s*\(',
        r'mysql_query\s*\(', r'pg_query\s*\(',
        r'sqlite_query\s*\(', r'mysql_db_query\s*\(',
        r'mysql_unbuffered_query\s*\(',
        r'mysqli_num_rows\s*\(', r'mysqli_affected_rows\s*\(',
        r'mysqli_insert_id\s*\(', r'mysqli_error\s*\(',
        r'mysqli_errno\s*\(', r'mysqli_field_count\s*\(',
        r'mysql_num_rows\s*\(', r'mysql_affected_rows\s*\(',
        r'mysql_insert_id\s*\(', r'mysql_error\s*\(',
        r'pg_num_rows\s*\(', r'pg_affected_rows\s*\(',
        r'mysqli_fetch_array\s*\(', r'mysqli_fetch_assoc\s*\(',
        r'mysqli_fetch_row\s*\(', r'mysqli_fetch_object\s*\(',
        r'mysql_fetch_array\s*\(', r'mysql_fetch_assoc\s*\(',
        r'mysql_fetch_row\s*\(', r'mysql_fetch_object\s*\(',
        r'pg_fetch_assoc\s*\(', r'pg_fetch_row\s*\(',
        # Hash functions — output is a fixed-format hex string, not user data
        r'md5\s*\(', r'sha1\s*\(', r'hash\s*\(',
        r'crypt\s*\(', r'password_hash\s*\(',
    ]

    # Universal sanitizers kill taint for ALL categories
    UNIVERSAL_SANITIZERS = [
        r'intval\s*\(',
        r'\(int\)',
        r'\(integer\)',
        r'floatval\s*\(',
        r'\(float\)',
    ]
    # Category-specific sanitizers: only kill taint for the mapped category
    CATEGORY_SANITIZERS = {
        'COMMAND_INJECTION': [
            r'escapeshellarg\s*\(',
            r'escapeshellcmd\s*\(',
        ],
        'SQL_INJECTION': [
            r'addslashes\s*\(',
            r'mysqli_real_escape_string\s*\(',
            r'pg_escape_string\s*\(',
        ],
        'XSS': [
            r'htmlspecialchars\s*\(',
            r'htmlentities\s*\(',
        ],
    }

    def _track_variable_assignments(self):
        """Track variable assignments to propagate taint."""
        # sanitized_for: var_name -> set of category names where taint is killed
        self.sanitized_vars = set()        # backwards-compat: universally sanitized
        self.sanitized_for: Dict[str, set] = {}  # var -> {category, ...}

        for i, line in enumerate(self.source_lines, 1):
            if line.strip().startswith('//') or line.strip().startswith('#'):
                continue
            match = re.search(r'\$(\w+)\s*=\s*(.+?);', line)
            if match:
                var_name = match.group(1)
                rhs = match.group(2)

                # Check for universal sanitizers — kill ALL taint
                if any(re.search(san, rhs) for san in self.UNIVERSAL_SANITIZERS):
                    self.sanitized_vars.add(var_name)
                    continue

                # Check for category-specific sanitizers
                specific_cats = set()
                for cat, patterns in self.CATEGORY_SANITIZERS.items():
                    if any(re.search(p, rhs) for p in patterns):
                        specific_cats.add(cat)
                if specific_cats:
                    # Variable is sanitized for these categories but still tainted for others
                    self.sanitized_for[var_name] = specific_cats
                    # Still propagate taint (don't continue) — variable remains tainted
                    # for categories NOT in specific_cats

                # Check if RHS calls a taint-sink function — return value is NOT tainted
                is_sink = any(re.search(sf, rhs) for sf in self.TAINT_SINK_FUNCTIONS)
                if is_sink:
                    continue

                for tainted in list(self.tainted_vars.keys()):
                    if re.search(rf'\${re.escape(tainted)}\b', rhs):
                        self.tainted_vars[var_name] = i
                        break

    def _track_database_sources(self):
        """Track variables that receive values from database queries (2nd-order sources)."""
        db_patterns = [
            (r'\$(\w+)\s*=\s*.*->fetch_assoc\s*\(', 'fetch_assoc'),
            (r'\$(\w+)\s*=\s*.*->fetch_object\s*\(', 'fetch_object'),
            (r'\$(\w+)\s*=\s*.*->fetch_row\s*\(', 'fetch_row'),
            (r'\$(\w+)\s*=\s*.*->fetch_array\s*\(', 'fetch_array'),
            (r'\$(\w+)\s*=\s*.*->fetch\s*\(', 'PDO::fetch'),
            (r'\$(\w+)\s*=\s*.*->fetchAll\s*\(', 'PDO::fetchAll'),
            (r'\$(\w+)\s*=\s*.*->fetch_column\s*\(', 'fetch_column'),
            (r'\$(\w+)\s*=\s*mysqli_fetch_assoc\s*\(', 'mysqli_fetch_assoc'),
            (r'\$(\w+)\s*=\s*mysqli_fetch_object\s*\(', 'mysqli_fetch_object'),
            (r'\$(\w+)\s*=\s*pg_fetch_assoc\s*\(', 'pg_fetch_assoc'),
        ]

        for i, line in enumerate(self.source_lines, 1):
            if line.strip().startswith('//') or line.strip().startswith('#'):
                continue
            for pattern, source_type in db_patterns:
                match = re.search(pattern, line)
                if match:
                    var_name = match.group(1)
                    self.db_sourced_vars[var_name] = (i, source_type)

        # Track array access on DB-sourced rows: $col = $row['column']
        for i, line in enumerate(self.source_lines, 1):
            if line.strip().startswith('//') or line.strip().startswith('#'):
                continue
            for db_var in list(self.db_sourced_vars.keys()):
                pattern = rf'\$(\w+)\s*=\s*\${re.escape(db_var)}\s*\[\s*[\'"](\w+)[\'"]\s*\]'
                match = re.search(pattern, line)
                if match:
                    new_var = match.group(1)
                    col_name = match.group(2)
                    orig_line, orig_source = self.db_sourced_vars[db_var]
                    self.db_sourced_vars[new_var] = (i, f"{orig_source}['{col_name}']")

                # Object access: $col = $row->column
                obj_pattern = rf'\$(\w+)\s*=\s*\${re.escape(db_var)}->(\w+)'
                match = re.search(obj_pattern, line)
                if match:
                    new_var = match.group(1)
                    prop_name = match.group(2)
                    orig_line, orig_source = self.db_sourced_vars[db_var]
                    self.db_sourced_vars[new_var] = (i, f"{orig_source}->{prop_name}")

    def _track_json_decoded(self):
        """Track variables through json_decode() - most scanners lose taint here."""
        for i, line in enumerate(self.source_lines, 1):
            if line.strip().startswith('//') or line.strip().startswith('#'):
                continue

            # $config = json_decode($row['config'], true)
            match = re.search(r'\$(\w+)\s*=\s*json_decode\s*\(', line)
            if match:
                var_name = match.group(1)
                # Check if the source is from DB
                for db_var in self.db_sourced_vars:
                    if re.search(rf'\${re.escape(db_var)}', line):
                        orig_line, orig_source = self.db_sourced_vars[db_var]
                        self.json_decoded_vars[var_name] = (i, f"json_decode({orig_source})")
                        break
                else:
                    # Generic json_decode from any source
                    self.json_decoded_vars[var_name] = (i, "json_decode")

        # Track array access on JSON-decoded data: $val = $config['key']
        for i, line in enumerate(self.source_lines, 1):
            if line.strip().startswith('//') or line.strip().startswith('#'):
                continue
            for json_var in list(self.json_decoded_vars.keys()):
                # $val = $config['key'] or $val = $config['outer']['inner']
                pattern = rf'\$(\w+)\s*=\s*\${re.escape(json_var)}\s*\[[\'"](\w+)[\'"]\]'
                match = re.search(pattern, line)
                if match:
                    new_var = match.group(1)
                    key_name = match.group(2)
                    orig_line, orig_source = self.json_decoded_vars[json_var]
                    self.json_decoded_vars[new_var] = (i, f"{orig_source}['{key_name}']")

    def _track_unserialized(self):
        """Track variables through unserialize() - the 'Double-Unserialize' pattern."""
        for i, line in enumerate(self.source_lines, 1):
            if line.strip().startswith('//') or line.strip().startswith('#'):
                continue

            # $prefs = unserialize($data) - where $data came from DB
            match = re.search(r'\$(\w+)\s*=\s*unserialize\s*\(', line)
            if match:
                var_name = match.group(1)
                # Check if the source is from DB
                for db_var in self.db_sourced_vars:
                    if re.search(rf'\${re.escape(db_var)}', line):
                        orig_line, orig_source = self.db_sourced_vars[db_var]
                        self.unserialized_vars[var_name] = (i, f"unserialize({orig_source})")
                        break
                else:
                    # Generic unserialize
                    self.unserialized_vars[var_name] = (i, "unserialize")

        # Track property access on unserialized objects: $val = $prefs->theme
        for i, line in enumerate(self.source_lines, 1):
            if line.strip().startswith('//') or line.strip().startswith('#'):
                continue
            for unser_var in list(self.unserialized_vars.keys()):
                # Object property: $prefs->property
                prop_pattern = rf'\$(\w+)\s*=\s*\${re.escape(unser_var)}->(\w+)'
                match = re.search(prop_pattern, line)
                if match:
                    new_var = match.group(1)
                    prop_name = match.group(2)
                    orig_line, orig_source = self.unserialized_vars[unser_var]
                    self.unserialized_vars[new_var] = (i, f"{orig_source}->{prop_name}")

                # Array access: $prefs['key']
                arr_pattern = rf'\$(\w+)\s*=\s*\${re.escape(unser_var)}\s*\[[\'"](\w+)[\'"]\]'
                match = re.search(arr_pattern, line)
                if match:
                    new_var = match.group(1)
                    key_name = match.group(2)
                    orig_line, orig_source = self.unserialized_vars[unser_var]
                    self.unserialized_vars[new_var] = (i, f"{orig_source}['{key_name}']")

    def _track_table_names(self):
        """Track variables that likely contain table names from config/DB."""
        table_patterns = [
            r'\$(\w*table\w*)\s*=',
            r'\$(\w*tbl\w*)\s*=',
            r'\$(\w*entity\w*)\s*=',
        ]

        for i, line in enumerate(self.source_lines, 1):
            if line.strip().startswith('//') or line.strip().startswith('#'):
                continue

            for pattern in table_patterns:
                match = re.search(pattern, line, re.IGNORECASE)
                if match:
                    var_name = match.group(1)
                    # Check if it comes from DB or JSON
                    for db_var in self.db_sourced_vars:
                        if re.search(rf'\${re.escape(db_var)}', line):
                            orig_line, source = self.db_sourced_vars[db_var]
                            self.table_name_vars[var_name] = (i, f"db:{source}")
                            break
                    for json_var in self.json_decoded_vars:
                        if re.search(rf'\${re.escape(json_var)}', line):
                            orig_line, source = self.json_decoded_vars[json_var]
                            self.table_name_vars[var_name] = (i, f"json:{source}")
                            break

    def _is_db_sourced(self, line: str) -> Tuple[bool, Optional[str], Optional[str]]:
        """Check if line uses a database-sourced variable."""
        for var, (src_line, source) in self.db_sourced_vars.items():
            if re.search(rf'\${re.escape(var)}\b', line):
                return True, var, source
        return False, None, None

    def _is_json_poisoned(self, line: str) -> Tuple[bool, Optional[str], Optional[str]]:
        """Check if line uses a JSON-decoded variable (potential poisoning)."""
        for var, (src_line, source) in self.json_decoded_vars.items():
            if re.search(rf'\${re.escape(var)}\b', line):
                return True, var, source
        return False, None, None

    def _is_table_name_var(self, line: str) -> Tuple[bool, Optional[str], Optional[str]]:
        """Check if line uses a tracked table name variable."""
        for var, (src_line, source) in self.table_name_vars.items():
            if re.search(rf'\${re.escape(var)}\b', line):
                return True, var, source
        return False, None, None

    def _is_unserialized(self, line: str) -> Tuple[bool, Optional[str], Optional[str]]:
        """Check if line uses an unserialized variable (Double-Unserialize pattern)."""
        for var, (src_line, source) in self.unserialized_vars.items():
            if re.search(rf'\${re.escape(var)}\b', line):
                return True, var, source
        return False, None, None

    def _is_tainted(self, line: str, category: str = None) -> Tuple[bool, Optional[str]]:
        # Remove string literals (but keep $var interpolation in double-quoted strings)
        # Only strip single-quoted strings which don't interpolate in PHP
        line_clean = re.sub(r"'[^'\\]*(?:\\.[^'\\]*)*'", "''", line)

        for var in self.tainted_vars:
            # Skip if variable has been universally sanitized
            if hasattr(self, 'sanitized_vars') and var in self.sanitized_vars:
                continue
            # Skip if sanitized specifically for this vulnerability category
            if category and hasattr(self, 'sanitized_for'):
                san_cats = self.sanitized_for.get(var, set())
                if category in san_cats:
                    continue
            if re.search(rf'\${re.escape(var)}\b', line_clean):
                # Also check if the variable in this specific use is sanitized
                # e.g., system("cat " . escapeshellarg($var)) - the $var is sanitized inline
                var_pattern = rf'\${re.escape(var)}\b'
                # Check for inline sanitization
                inline_sanitizers = [
                    rf'escapeshellarg\s*\(\s*\${re.escape(var)}\s*\)',
                    rf'escapeshellcmd\s*\(\s*\${re.escape(var)}\s*\)',
                    rf'intval\s*\(\s*\${re.escape(var)}\s*\)',
                    rf'\(int\)\s*\${re.escape(var)}\b',
                ]
                is_inline_sanitized = any(re.search(san, line) for san in inline_sanitizers)
                if is_inline_sanitized:
                    continue
                return True, var
        # Check direct superglobal use
        if re.search(r'\$_(GET|POST|REQUEST|COOKIE|SERVER|FILES)\s*\[', line_clean):
            return True, '$_REQUEST'
        return False, None

    def _is_tainted_rhs_only(self, line: str, line_num: int = 0) -> Tuple[bool, Optional[str]]:
        """Check taint only on the RHS of an assignment (ignoring LHS variable name).

        For SQL string construction lines like ``$sql = "SELECT ... WHERE x='$var'"``,
        the global ``_is_tainted`` would match ``$sql`` on the LHS even when the
        interpolated variables are safe.  This method extracts the RHS and only
        checks whether the interpolated variables there are actually tainted.
        Falls back to ``_is_tainted`` for non-assignment lines.
        """
        assign_match = re.match(r'\s*\$(\w+)\s*=\s*(.+)', line)
        if not assign_match:
            return self._is_tainted(line)

        lhs_var = assign_match.group(1)
        rhs = assign_match.group(2)

        # Don't strip single-quoted substrings here — they may be literal
        # quote characters inside a double-quoted PHP string (e.g.
        # "SELECT ... WHERE x='$var'") and stripping would lose $var.
        rhs_clean = rhs

        # Arithmetic operations force numeric conversion in PHP, preventing
        # string-based injection.  E.g. $start = ($pageno * $limit) - $limit
        # Even if $pageno is tainted, the result is always numeric.
        if re.search(r'[\*/%]', rhs) and not re.search(r'["\']', rhs):
            return False, None

        # Check direct superglobal use in RHS
        if re.search(r'\$_(GET|POST|REQUEST|COOKIE|SERVER|FILES)\s*\[', rhs_clean):
            return True, '$_REQUEST'

        # Check interpolated variables in RHS
        for var in re.findall(r'\$(\w+)', rhs_clean):
            if var == lhs_var:
                continue  # skip self-reference
            if var in ('con', 'conn', 'connection', 'db', 'pdo', 'mysqli', 'this'):
                continue  # skip connection objects
            if var in self.tainted_vars:
                if hasattr(self, 'sanitized_vars') and var in self.sanitized_vars:
                    continue
                # Inline sanitization check
                inline_sanitizers = [
                    rf'escapeshellarg\s*\(\s*\${re.escape(var)}\s*\)',
                    rf'escapeshellcmd\s*\(\s*\${re.escape(var)}\s*\)',
                    rf'intval\s*\(\s*\${re.escape(var)}\s*\)',
                    rf'\(int\)\s*\${re.escape(var)}\b',
                    rf'mysqli_real_escape_string\s*\([^,]*,\s*\${re.escape(var)}\s*\)',
                ]
                if any(re.search(san, rhs) for san in inline_sanitizers):
                    continue
                # Flow-sensitive check: if the variable was reassigned to a
                # safe value (md5, sanitizer, sink) BEFORE this line, it's
                # not tainted at this point even though globally tainted.
                if line_num > 0 and self._var_reassigned_safe(var, line_num):
                    continue
                return True, var

        return False, None

    def _var_reassigned_safe(self, var_name: str, before_line: int) -> bool:
        """Check if the nearest assignment to ``$var_name`` before
        ``before_line`` is a safe (non-tainted) value.

        Scans ALL lines before ``before_line`` (not just from the taint
        source) to handle cases where tainted_vars stores a later line.
        """
        # Scan all lines before usage for assignments to this variable
        nearest_line = 0
        nearest_rhs = None
        pattern = rf'\${re.escape(var_name)}\s*=\s*(.+?);\s*$'
        for i in range(0, min(before_line - 1, len(self.source_lines))):
            line = self.source_lines[i]
            m = re.search(pattern, line)
            if m and (i + 1) > nearest_line:
                nearest_line = i + 1  # 1-indexed
                nearest_rhs = m.group(1)

        if nearest_rhs is None:
            return False  # no reassignment found

        # Check if the nearest reassignment is a safe function
        safe_patterns = [
            r'md5\s*\(', r'sha1\s*\(', r'hash\s*\(', r'crypt\s*\(',
            r'password_hash\s*\(', r'intval\s*\(', r'floatval\s*\(',
            r'\(int\)', r'\(float\)', r'\(integer\)',
            r'htmlspecialchars\s*\(', r'htmlentities\s*\(',
            r'addslashes\s*\(', r'escapeshellarg\s*\(',
            r'escapeshellcmd\s*\(', r'mysqli_real_escape_string\s*\(',
            r'pg_escape_string\s*\(',
        ]
        # Also check TAINT_SINK_FUNCTIONS
        for sf in self.TAINT_SINK_FUNCTIONS:
            if re.search(sf, nearest_rhs):
                return True
        for sp in safe_patterns:
            if re.search(sp, nearest_rhs):
                return True

        # Arithmetic operations force numeric conversion — result is safe
        if re.search(r'[\*/%]', nearest_rhs) and not re.search(r'["\']', nearest_rhs):
            return True

        # If the nearest RHS contains NO tainted variables at all, it's safe
        # (e.g. $start = 0, or $var = "literal")
        rhs_has_taint = False
        for tv in self.tainted_vars:
            if re.search(rf'\${re.escape(tv)}\b', nearest_rhs):
                rhs_has_taint = True
                break
        if not rhs_has_taint and not re.search(r'\$_(GET|POST|REQUEST|COOKIE)\s*\[', nearest_rhs):
            return True

        return False

    def get_line_content(self, lineno: int) -> str:
        if 1 <= lineno <= len(self.source_lines):
            return self.source_lines[lineno - 1]
        return ""

    def analyze(self) -> List[Finding]:
        self._check_sql_injection()
        self._check_command_injection()
        self._check_strrev_evasion()
        self._check_code_injection()
        self._check_deserialization()
        # 2nd-order SQL injection detection
        self._check_second_order_sqli()
        self._check_json_poisoning_sqli()
        self._check_table_name_injection()
        self._check_structural_calc_sqli()
        self._check_unserialize_sqli()
        # 2nd-order XPath injection detection
        self._check_xpath_injection()
        return self.findings

    def _add_finding(self, line_num: int, vuln_name: str, category: VulnCategory,
                     severity: Severity, confidence: str, taint_var: Optional[str] = None,
                     description: str = ""):
        taint_chain = []
        if taint_var and taint_var in self.tainted_vars:
            taint_chain = [f"tainted: ${taint_var} (line {self.tainted_vars[taint_var]})"]
        elif taint_var:
            taint_chain = [f"tainted: {taint_var}"]

        self.findings.append(Finding(
            file_path=self.file_path, line_number=line_num, col_offset=0,
            line_content=self.get_line_content(line_num),
            vulnerability_name=vuln_name, category=category,
            severity=severity, confidence=confidence,
            taint_chain=taint_chain, description=description,
        ))

    def _check_sql_injection(self):
        sql_funcs = r'(?:mysql_query|mysqli_query|pg_query|sqlite_query|mssql_query|odbc_exec|->query|->prepare|->exec)'
        # Use word boundaries and exclude common false positives like variable names $where
        sql_keywords = r'(?<!\$)\b(?:SELECT|INSERT|UPDATE|DELETE|DROP|UNION)\b'
        # For FROM and WHERE, require them to be in a string context or followed by typical SQL patterns
        sql_from_where = r'["\'].*\b(?:FROM|WHERE)\b.*["\']'

        # Laravel/Eloquent ORM safe patterns - these use parameterized queries
        eloquent_safe_patterns = [
            r'\w+::where\s*\(',           # Model::where() - Eloquent
            r'\w+::find\s*\(',            # Model::find() - Eloquent
            r'\w+::findOrFail\s*\(',      # Model::findOrFail() - Eloquent
            r'\w+::first\s*\(',           # Model::first() - Eloquent
            r'\w+::get\s*\(',             # Model::get() - Eloquent
            r'\w+::all\s*\(',             # Model::all() - Eloquent
            r'\w+::create\s*\(',          # Model::create() - Eloquent
            r'\w+::update\s*\(',          # Model::update() - Eloquent
            r'\w+::delete\s*\(',          # Model::delete() - Eloquent
            r'->where\s*\([^)]*,\s*[\'"][=<>!]+[\'"]\s*,', # ->where('col', '=', $val) parameterized
            r'->where\s*\(\s*[\'"][\w_]+[\'"]\s*,\s*\$',   # ->where('col', $val) parameterized
            r'->first\s*\(\s*\)',         # ->first() - safe
            r'->get\s*\(\s*\)',           # ->get() - safe
            r'->update\s*\(\s*\[',        # ->update([...]) - safe array syntax
            r'->save\s*\(\s*\)',          # ->save() - safe
            # Additional Laravel ORM patterns
            r'->update\s*\(\s*\$',        # ->update($data) - safe parameterized
            r'->delete\s*\(\s*\)',        # ->delete() - safe
            r'->flash\s*\(',              # Session flash - not SQL
            r'->session\s*\(\s*\)',       # Session access - not SQL
            r'->session\s*\(\s*\)->',     # Session chain - not SQL
            r'\$this->update\s*\(',       # Repository update - safe
            r'\$this->model->update\s*\(', # Model update - safe
            r'Repo->',                    # Repository pattern
            r'Repository->',              # Repository pattern
            r'public function \w+\s*\(',  # Function signature - not SQL
            r'return redirect\s*\(',      # Laravel redirect - not SQL
            r'->execute\s*\(',            # PayPal/Payment execute - not SQL
            r'\$\w+->images\(\)',         # Relationship accessor - safe
            r'->attach\s*\(',             # Eloquent attach - safe
            r'->detach\s*\(',             # Eloquent detach - safe
            r'->sync\s*\(',               # Eloquent sync - safe
        ]

        # MongoDB $where is dangerous (NoSQL injection)
        nosql_dangerous = [
            r'\[\s*[\'\"]\$where[\'\"]',  # ['$where' => ...] - dangerous
            r'findOne\s*\(\s*\[\s*[\'\"]\$where', # findOne(['$where' => ...])
        ]

        # MongoDB JavaScript string patterns (used in $where)
        # Detects: sprintf("return this.field == '%s'", $var)
        mongo_js_patterns = [
            r'return\s+this\.',           # return this.field
            r'this\.\w+\s*[=!<>]=',       # this.field == or this.field !=
            r'this\.\w+\s*&&',            # this.field &&
            r'this\.\w+\s*\|\|',          # this.field ||
        ]

        for i, line in enumerate(self.source_lines, 1):
            if line.strip().startswith('//') or line.strip().startswith('#'):
                continue

            # Check for MongoDB $where JavaScript string construction
            # Pattern: sprintf("return this.token == '%s'", $var) or "return this." . $var
            for js_pattern in mongo_js_patterns:
                if re.search(js_pattern, line):
                    is_tainted, taint_var = self._is_tainted(line)
                    # Check if it's string building (sprintf, concatenation, etc.)
                    is_string_building = re.search(r'sprintf\s*\(|\..*\$|%s|%d|\$\w+.*\.', line)
                    if is_tainted and is_string_building:
                        self._add_finding(i, "NoSQL Injection - MongoDB $where JavaScript with tainted data",
                                          VulnCategory.NOSQL_INJECTION, Severity.CRITICAL, "HIGH", taint_var,
                                          "Building MongoDB $where JavaScript string with user input. "
                                          "Attacker can inject arbitrary JavaScript code.")
                        break  # Don't duplicate for same line

            # Check for MongoDB NoSQL injection first (higher priority)
            is_nosql = False
            for pattern in nosql_dangerous:
                if re.search(pattern, line):
                    is_tainted, taint_var = self._is_tainted(line)
                    if is_tainted:
                        self._add_finding(i, "NoSQL Injection - MongoDB $where with tainted data",
                                          VulnCategory.NOSQL_INJECTION, Severity.CRITICAL, "HIGH", taint_var,
                                          "MongoDB $where operator allows JavaScript injection.")
                        is_nosql = True
                        break

            # Skip SQL injection check if already flagged as NoSQL or contains MongoDB patterns
            if is_nosql or re.search(r'findOne|find\s*\(|->collection|MongoDB|\$where', line):
                continue

            # Skip Eloquent ORM safe patterns (parameterized queries)
            is_eloquent_safe = any(re.search(p, line) for p in eloquent_safe_patterns)
            if is_eloquent_safe:
                continue

            # Skip PDO prepared statements with ? placeholders or :named placeholders
            # Pattern: $pdo->prepare("SELECT * FROM users WHERE id = ?")
            # Pattern: $pdo->prepare("SELECT * FROM users WHERE id = :id")
            if re.search(r'->\s*prepare\s*\(\s*["\']', line):
                # Check if the SQL string contains ? placeholder or :named placeholder (parameterized query)
                prepare_match = re.search(r'->\s*prepare\s*\(\s*["\']([^"\']*)["\']', line)
                if prepare_match:
                    sql_content = prepare_match.group(1)
                    if '?' in sql_content or re.search(r':\w+', sql_content):
                        continue  # Safe: prepared statement with placeholders

            # Direct query with concatenation
            has_sql_func = re.search(sql_funcs, line)
            has_sql_keyword = re.search(sql_keywords, line, re.IGNORECASE)
            has_sql_from_where = re.search(sql_from_where, line, re.IGNORECASE)

            if has_sql_func or has_sql_keyword or has_sql_from_where:
                # Skip static SQL queries with no variable interpolation
                # Pattern: $query = "SELECT * FROM users WHERE active = 1";
                if re.search(r'=\s*["\'][^"\']*["\'];?\s*$', line):
                    # Check if the string contains any $ variable or concatenation
                    string_match = re.search(r'=\s*["\']([^"\']*)["\']', line)
                    if string_match:
                        sql_content = string_match.group(1)
                        # If no $ variables in the SQL string, it's static and safe
                        if not re.search(r'\$\w+', sql_content):
                            continue  # Safe: static query

                # Skip lines that are DB sink calls (assignment or condition form)
                # e.g. "$run_query = mysqli_query($con,$sql)" or
                #      "if(mysqli_query($con,$sql))" — the tainted var is the
                # argument being consumed, report on the construction line instead
                if re.search(r'(?:^\s*\$\w+\s*=\s*|^\s*if\s*\(|^\s*)(?:mysqli_query|mysql_query|pg_query|'
                             r'sqlite_query|mysqli_real_query)\s*\(', line):
                    continue

                # For assignment lines ($var = "SQL..."), only check RHS for taint
                # to avoid FP from globally-tainted LHS variable names (e.g. $sql
                # reused across independent if-blocks)
                is_assignment = re.match(r'\s*\$\w+\s*=', line)
                if is_assignment:
                    is_tainted, taint_var = self._is_tainted_rhs_only(line, i)
                else:
                    is_tainted, taint_var = self._is_tainted(line, category='SQL_INJECTION')
                has_concat = '.' in line or '+' in line or re.search(r'\$\w+', line)

                # Skip sprintf with only integer format specifiers (%d, %i, %u, %x, %o)
                # These are safe since integers can't contain SQL injection payloads
                if re.search(r'sprintf\s*\(', line):
                    format_str_match = re.search(r'sprintf\s*\(\s*["\']([^"\']*)["\']', line)
                    if format_str_match:
                        format_str = format_str_match.group(1)
                        # Find all format specifiers
                        format_specs = re.findall(r'%[^%\s]*[a-zA-Z]', format_str)
                        # Integer-only specifiers (safe for SQL injection)
                        uses_int_only = format_specs and all(re.match(r'%[-+0\s#\']*\d*\.?\d*[dioxXu]', spec) for spec in format_specs)
                        if uses_int_only and is_tainted:
                            self._add_finding(i, "SQL Injection - sprintf with integer format (lower risk)",
                                              VulnCategory.SQL_INJECTION, Severity.MEDIUM, "LOW", taint_var,
                                              "SQL with sprintf using only integer format specifiers (%d/%i/%x). "
                                              "Lower risk since integers can't contain SQL injection payloads.")
                            continue  # Skip the critical finding

                if is_tainted and (has_sql_func or has_sql_keyword or has_sql_from_where):
                    self._add_finding(i, "SQL Injection - Query with tainted data",
                                      VulnCategory.SQL_INJECTION, Severity.CRITICAL, "HIGH", taint_var,
                                      "User input directly in SQL query.")

    def _check_command_injection(self):
        # Note: eval is handled separately in _check_code_injection
        cmd_funcs = r'\b(system|exec|shell_exec|passthru|popen|proc_open|pcntl_exec)\s*\('

        for i, line in enumerate(self.source_lines, 1):
            if line.strip().startswith('//'):
                continue
            if re.search(cmd_funcs, line):
                # Skip if escapeshellcmd OR escapeshellarg are used (safe patterns)
                # escapeshellarg: escapes a single argument to be passed to shell
                # escapeshellcmd: escapes shell metacharacters in entire command
                has_escapeshellcmd = re.search(r'escapeshellcmd\s*\(', line)
                has_escapeshellarg = re.search(r'escapeshellarg\s*\(', line)
                if has_escapeshellcmd or has_escapeshellarg:
                    continue  # Safe: escape function used

                is_tainted, taint_var = self._is_tainted(line, category='COMMAND_INJECTION')
                if is_tainted:
                    self._add_finding(i, "Command Injection - Shell function with tainted data",
                                      VulnCategory.COMMAND_INJECTION, Severity.CRITICAL, "HIGH", taint_var,
                                      "User input passed to shell execution function.")
                elif re.search(r'\$\w+', line):
                    self._add_finding(i, "Command Injection - Shell function with variable",
                                      VulnCategory.COMMAND_INJECTION, Severity.HIGH, "MEDIUM",
                                      description="Variable passed to shell function. Verify source.")

            # Backtick execution
            if '`' in line and re.search(r'`[^`]*\$', line):
                is_tainted, taint_var = self._is_tainted(line)
                if is_tainted:
                    self._add_finding(i, "Command Injection - Backtick with tainted data",
                                      VulnCategory.COMMAND_INJECTION, Severity.CRITICAL, "HIGH", taint_var,
                                      "User input in backtick command execution.")

            # Variable function call: $func() where $func could be "system", "exec", etc.
            # Pattern: $var() or $var(args)
            var_func_match = re.search(r'\$(\w+)\s*\(', line)
            if var_func_match:
                var_name = var_func_match.group(1)

                # Skip Laravel/framework safe patterns
                laravel_safe_patterns = [
                    r'\$next\s*\(\s*\$request\s*\)',  # Middleware: $next($request)
                    r'\$callback\s*\(',               # Common callback pattern
                    r'\$handler\s*\(',                # Handler pattern
                    r'\$resolver\s*\(',               # Resolver pattern
                    r'\$this\s*\(',                   # $this is not a variable function
                ]
                is_framework_safe = any(re.search(p, line) for p in laravel_safe_patterns)
                if is_framework_safe:
                    continue

                # Check if this variable might contain a dangerous function name
                context = '\n'.join(self.source_lines[max(0, i-10):i])
                if re.search(rf'\${re.escape(var_name)}\s*=\s*["\'](?:system|exec|shell_exec|passthru|popen|eval)', context):
                    is_tainted, taint_var = self._is_tainted(line)
                    if is_tainted:
                        self._add_finding(i, "Command Injection - Variable function with tainted args",
                                          VulnCategory.COMMAND_INJECTION, Severity.CRITICAL, "HIGH", taint_var,
                                          f"Variable function ${var_name}() with user-controlled arguments.")
                    else:
                        self._add_finding(i, "Command Injection - Variable function (dangerous)",
                                          VulnCategory.COMMAND_INJECTION, Severity.HIGH, "HIGH",
                                          description=f"Variable function ${var_name}() may call dangerous functions.")
                elif var_name in self.tainted_vars:
                    # Function name is tainted - can call arbitrary functions
                    self._add_finding(i, "Code Injection - Tainted variable function name",
                                      VulnCategory.CODE_INJECTION, Severity.CRITICAL, "HIGH", var_name,
                                      f"User-controlled function name ${var_name}() can execute arbitrary code.")

            # call_user_func / call_user_func_array with dynamic function
            if re.search(r'call_user_func(?:_array)?\s*\(', line):
                is_tainted, taint_var = self._is_tainted(line)
                if is_tainted:
                    self._add_finding(i, "Code Injection - call_user_func with tainted data",
                                      VulnCategory.CODE_INJECTION, Severity.CRITICAL, "HIGH", taint_var,
                                      "User-controlled function name in call_user_func().")
                elif re.search(r'call_user_func(?:_array)?\s*\(\s*\$', line):
                    self._add_finding(i, "Code Injection - call_user_func with variable",
                                      VulnCategory.CODE_INJECTION, Severity.HIGH, "MEDIUM",
                                      description="Variable function name in call_user_func(). Verify source.")

            # Shell execution patterns: sh -c, cmd /c in proc_open/popen
            if re.search(r'(?:popen|proc_open)\s*\(', line):
                context = '\n'.join(self.source_lines[i-1:min(len(self.source_lines), i+3)])
                if re.search(r'["\'](?:/bin/sh|/bin/bash|sh|bash|cmd(?:\.exe)?)["\'].*["\'](?:-c|/c)["\']', context):
                    is_tainted, taint_var = self._is_tainted(line)
                    if is_tainted:
                        self._add_finding(i, "Command Injection - Shell execution pattern with tainted input",
                                          VulnCategory.COMMAND_INJECTION, Severity.CRITICAL, "HIGH", taint_var,
                                          "Shell with -c flag executing user-controlled command.")
                    else:
                        self._add_finding(i, "Command Injection - Shell execution pattern",
                                          VulnCategory.COMMAND_INJECTION, Severity.HIGH, "HIGH",
                                          description="Shell with -c flag pattern detected.")

    def _check_strrev_evasion(self):
        """
        Detect strrev()-based evasion for hiding dangerous function names.
        Examples: $f = strrev("urhtssap"); $f($input);  // passthru($input)
        """
        # Lookup table: dangerous function names reversed
        dangerous_reversed = {
            'urhtssap': 'passthru',
            'metsys': 'system',
            'cexe': 'exec',
            'cexe_llehs': 'shell_exec',
            'lave': 'eval',
            'nepo_corp': 'proc_open',
            'nepop': 'popen',
            'cexe_lntcp': 'pcntl_exec',
            'edulcni': 'include',
            'eriuqer': 'require',
            'tropssap': 'passthru',  # Common typo variant
        }

        # Track variables assigned via strrev()
        strrev_vars = {}  # var_name -> (line_num, resolved_func)

        for i, line in enumerate(self.source_lines, 1):
            stripped = line.strip()
            if stripped.startswith('//') or stripped.startswith('#'):
                continue

            # Detect: $var = strrev("reversed_string")
            strrev_match = re.search(r'\$(\w+)\s*=\s*strrev\s*\(\s*["\'](\w+)["\']\s*\)', line)
            if strrev_match:
                var_name = strrev_match.group(1)
                reversed_str = strrev_match.group(2)
                # Check if it's a known dangerous function
                if reversed_str in dangerous_reversed:
                    resolved = dangerous_reversed[reversed_str]
                    strrev_vars[var_name] = (i, resolved)
                    self._add_finding(i, f"Code Evasion - strrev() hides '{resolved}'",
                                      VulnCategory.CODE_INJECTION, Severity.HIGH, "HIGH",
                                      description=f"strrev('{reversed_str}') decodes to dangerous function '{resolved}'.")
                else:
                    # Reverse it manually and check
                    manually_reversed = reversed_str[::-1]
                    if manually_reversed.lower() in ['system', 'exec', 'passthru', 'shell_exec', 'eval',
                                                      'popen', 'proc_open', 'pcntl_exec', 'include', 'require']:
                        strrev_vars[var_name] = (i, manually_reversed)
                        self._add_finding(i, f"Code Evasion - strrev() hides '{manually_reversed}'",
                                          VulnCategory.CODE_INJECTION, Severity.HIGH, "HIGH",
                                          description=f"strrev('{reversed_str}') decodes to dangerous function '{manually_reversed}'.")

            # Detect variable function call: $var($args) where $var was set via strrev
            var_func_call = re.search(r'\$(\w+)\s*\(\s*([^)]*)\s*\)', line)
            if var_func_call:
                var_name = var_func_call.group(1)
                args = var_func_call.group(2)
                if var_name in strrev_vars:
                    orig_line, resolved_func = strrev_vars[var_name]
                    is_tainted, taint_var = self._is_tainted(line)
                    if is_tainted:
                        self._add_finding(i, f"Command Injection - strrev-hidden {resolved_func}() with tainted args",
                                          VulnCategory.COMMAND_INJECTION, Severity.CRITICAL, "HIGH", taint_var,
                                          f"Variable function ${var_name}() resolves to {resolved_func}() (via strrev at line {orig_line}). User input passed as argument.")
                    else:
                        self._add_finding(i, f"Command Injection - strrev-hidden {resolved_func}() call",
                                          VulnCategory.COMMAND_INJECTION, Severity.HIGH, "HIGH",
                                          description=f"Variable function ${var_name}() resolves to {resolved_func}() (hidden via strrev at line {orig_line}).")

    def _check_code_injection(self):
        for i, line in enumerate(self.source_lines, 1):
            if line.strip().startswith('//'):
                continue

            # eval()
            if re.search(r'\beval\s*\(', line):
                # Skip static eval with no variable interpolation
                # Pattern: eval('static code'); or eval("static code");
                static_eval_match = re.search(r'eval\s*\(\s*(["\'])([^"\']*)\1\s*\)', line)
                if static_eval_match:
                    eval_content = static_eval_match.group(2)
                    # If no $ variables in the eval string, it's static and safe
                    if not re.search(r'\$\w+', eval_content):
                        continue  # Safe: static eval

                is_tainted, taint_var = self._is_tainted(line)
                if is_tainted:
                    self._add_finding(i, "Code Injection - eval() with tainted data",
                                      VulnCategory.CODE_INJECTION, Severity.CRITICAL, "HIGH", taint_var,
                                      "User input passed to eval().")

            # preg_replace with /e modifier
            if re.search(r'preg_replace\s*\([^,]*["\'][^"\']*\/e["\']', line):
                is_tainted, taint_var = self._is_tainted(line)
                self._add_finding(i, "Code Injection - preg_replace with /e modifier",
                                  VulnCategory.CODE_INJECTION, Severity.CRITICAL, "HIGH", taint_var,
                                  "preg_replace /e modifier allows code execution.")

            # create_function
            if re.search(r'create_function\s*\(', line):
                is_tainted, taint_var = self._is_tainted(line)
                if is_tainted:
                    self._add_finding(i, "Code Injection - create_function with tainted data",
                                      VulnCategory.CODE_INJECTION, Severity.CRITICAL, "HIGH", taint_var,
                                      "User input in create_function().")

            # assert()
            if re.search(r'\bassert\s*\(', line):
                is_tainted, taint_var = self._is_tainted(line)
                if is_tainted:
                    self._add_finding(i, "Code Injection - assert() with tainted data",
                                      VulnCategory.CODE_INJECTION, Severity.CRITICAL, "HIGH", taint_var,
                                      "User input passed to assert().")

            # call_user_func / call_user_func_array with tainted callback
            if re.search(r'call_user_func(?:_array)?\s*\(', line):
                is_tainted, taint_var = self._is_tainted(line)
                if is_tainted:
                    self._add_finding(i, "Code Injection - call_user_func with tainted callback",
                                      VulnCategory.CODE_INJECTION, Severity.CRITICAL, "HIGH", taint_var,
                                      "User-controlled callback in call_user_func enables arbitrary function execution.")
                # Check for array-based callback evasion: call_user_func([$obj, 'method'])
                elif re.search(r'call_user_func\s*\(\s*\[', line):
                    self._add_finding(i, "Code Injection - call_user_func with array callback",
                                      VulnCategory.CODE_INJECTION, Severity.HIGH, "MEDIUM",
                                      description="Array callback in call_user_func - verify callback source.")

            # Variable functions: $func() where $func could be user-controlled
            var_func_match = re.search(r'\$(\w+)\s*\(', line)
            if var_func_match:
                var_name = var_func_match.group(1)
                # Skip common safe patterns like $this->method(), $callback(), $next() (Laravel middleware), etc.
                safe_var_funcs = ['this', 'self', 'parent', 'callback', 'handler', 'closure', 'next', 'pipe']
                if var_name not in safe_var_funcs:
                    is_tainted, taint_var = self._is_tainted(line)
                    if is_tainted or var_name in [v for v in self.tainted_vars]:
                        self._add_finding(i, f"Code Injection - Variable function ${var_name}()",
                                          VulnCategory.CODE_INJECTION, Severity.CRITICAL, "HIGH", var_name,
                                          f"Variable function ${var_name}() with user-controlled name enables arbitrary function execution.")

            # ReflectionFunction / ReflectionMethod invoke
            if re.search(r'(?:ReflectionFunction|ReflectionMethod|ReflectionClass)\s*\(', line):
                is_tainted, taint_var = self._is_tainted(line)
                if is_tainted:
                    self._add_finding(i, "Code Injection - Reflection with tainted input",
                                      VulnCategory.CODE_INJECTION, Severity.CRITICAL, "HIGH", taint_var,
                                      "Reflection API with user input enables arbitrary method/class access.")

            # array_map/array_filter with user callback
            if re.search(r'array_(?:map|filter|walk|reduce)\s*\(', line):
                is_tainted, taint_var = self._is_tainted(line)
                if is_tainted:
                    self._add_finding(i, "Code Injection - array function with tainted callback",
                                      VulnCategory.CODE_INJECTION, Severity.HIGH, "HIGH", taint_var,
                                      "Array function with user-controlled callback enables code execution.")

            # usort/uasort/uksort with user callback
            if re.search(r'u(?:a|k)?sort\s*\(', line):
                is_tainted, taint_var = self._is_tainted(line)
                if is_tainted:
                    self._add_finding(i, "Code Injection - usort with tainted callback",
                                      VulnCategory.CODE_INJECTION, Severity.HIGH, "HIGH", taint_var,
                                      "Sort function with user-controlled callback enables code execution.")

    def _check_deserialization(self):
        for i, line in enumerate(self.source_lines, 1):
            if line.strip().startswith('//'):
                continue
            if re.search(r'\bunserialize\s*\(', line):
                # Check for safe unserialize patterns in PHP 7+
                # unserialize($data, ['allowed_classes' => false])
                # unserialize($data, ['allowed_classes' => []])
                # unserialize($data, ['allowed_classes' => ['SafeClass']])  (restricted classes)
                # unserialize($data, array('allowed_classes' => false))
                safe_unserialize_patterns = [
                    r'unserialize\s*\([^,]+,\s*\[\s*[\'"]allowed_classes[\'"]\s*=>\s*false\s*\]',
                    r'unserialize\s*\([^,]+,\s*\[\s*[\'"]allowed_classes[\'"]\s*=>\s*\[',  # any array (restricted classes)
                    r'unserialize\s*\([^,]+,\s*array\s*\(\s*[\'"]allowed_classes[\'"]\s*=>\s*false\s*\)',
                    r'unserialize\s*\([^,]+,\s*array\s*\(\s*[\'"]allowed_classes[\'"]\s*=>\s*array\s*\(',
                    r'allowed_classes[\'"]?\s*=>\s*false',  # Check if anywhere in the call
                    r'allowed_classes[\'"]?\s*=>\s*\[',     # Check for array of allowed classes
                ]
                is_safe_unserialize = any(re.search(pat, line, re.IGNORECASE) for pat in safe_unserialize_patterns)

                if is_safe_unserialize:
                    # Safe usage - allowed_classes restricts object instantiation
                    continue  # Skip flagging

                is_tainted, taint_var = self._is_tainted(line)
                if is_tainted:
                    self._add_finding(i, "Insecure Deserialization - unserialize with tainted data",
                                      VulnCategory.DESERIALIZATION, Severity.CRITICAL, "HIGH", taint_var,
                                      "User input passed to unserialize() can lead to RCE. "
                                      "Use unserialize($data, ['allowed_classes' => false]) for safety.")
                else:
                    self._add_finding(i, "Insecure Deserialization - unserialize usage",
                                      VulnCategory.DESERIALIZATION, Severity.HIGH, "MEDIUM",
                                      description="unserialize() detected. Verify data source. "
                                      "Consider using ['allowed_classes' => false] option.")

    def _check_second_order_sqli(self):
        """Detect 2nd-order SQLi with database-sourced values in UPDATE/DELETE."""
        for i, line in enumerate(self.source_lines, 1):
            if line.strip().startswith('//') or line.strip().startswith('#'):
                continue

            # Check for UPDATE/DELETE with db-sourced values
            if re.search(r'(?:UPDATE|DELETE)\s+', line, re.IGNORECASE):
                is_db, db_var, source = self._is_db_sourced(line)
                if is_db:
                    self._add_finding(
                        i, "2nd-Order SQLi - UPDATE/DELETE with DB-sourced value",
                        VulnCategory.SQL_INJECTION, Severity.CRITICAL, "HIGH", db_var,
                        f"Value from {source} used in destructive query. "
                        "Stored payload can modify/delete data."
                    )

    def _check_json_poisoning_sqli(self):
        """Detect SQLi through JSON-decoded values (taint lost through json_decode)."""
        calc_patterns = [
            (r'SUM\s*\(\s*\$', 'SUM'),
            (r'COUNT\s*\(\s*\$', 'COUNT'),
            (r'AVG\s*\(\s*\$', 'AVG'),
            (r'MIN\s*\(\s*\$', 'MIN'),
            (r'MAX\s*\(\s*\$', 'MAX'),
        ]

        for i, line in enumerate(self.source_lines, 1):
            if line.strip().startswith('//') or line.strip().startswith('#'):
                continue

            # Check for calculation functions with JSON-poisoned values
            # Only match inside SQL string context (inside quotes), not PHP
            # functions like count($array) which are not SQL
            for pattern, func_name in calc_patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    # Ensure it's in a SQL string context (inside quotes)
                    if not re.search(r'["\'].*' + func_name + r'\s*\(', line, re.IGNORECASE):
                        continue
                    is_json, json_var, source = self._is_json_poisoned(line)
                    if is_json:
                        self._add_finding(
                            i, f"2nd-Order SQLi - {func_name}() with JSON-decoded value",
                            VulnCategory.SQL_INJECTION, Severity.CRITICAL, "HIGH", json_var,
                            f"JSON-decoded value from {source} used in {func_name}(). "
                            "Most scanners miss this - taint lost through json_decode()."
                        )

            # Check ORDER BY / GROUP BY with JSON values
            if re.search(r'ORDER\s+BY\s+\$|GROUP\s+BY\s+\$', line, re.IGNORECASE):
                is_json, json_var, source = self._is_json_poisoned(line)
                if is_json:
                    self._add_finding(
                        i, "2nd-Order SQLi - ORDER/GROUP BY with JSON-decoded value",
                        VulnCategory.SQL_INJECTION, Severity.CRITICAL, "HIGH", json_var,
                        f"JSON-decoded value from {source} used in structural clause. "
                        "Enables boolean-based data exfiltration."
                    )

    def _check_table_name_injection(self):
        """Detect table name injection (multi-tenant attacks)."""
        table_patterns = [
            r'(?:FROM|INTO|UPDATE|JOIN)\s+\$',
            r'DELETE\s+FROM\s+\$',
            r'INSERT\s+INTO\s+\$',
        ]

        for i, line in enumerate(self.source_lines, 1):
            if line.strip().startswith('//') or line.strip().startswith('#'):
                continue

            for pattern in table_patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    # Check if it's a table name variable
                    is_tbl, tbl_var, source = self._is_table_name_var(line)
                    if is_tbl:
                        self._add_finding(
                            i, "2nd-Order SQLi - Table name injection",
                            VulnCategory.SQL_INJECTION, Severity.CRITICAL, "HIGH", tbl_var,
                            f"Table name from {source} used in query. "
                            "Multi-tenant 'Bunker Buster' attack - can access other tenants' data."
                        )
                    else:
                        # Check if it's from DB or JSON
                        is_db, db_var, db_source = self._is_db_sourced(line)
                        is_json, json_var, json_source = self._is_json_poisoned(line)
                        if is_db:
                            self._add_finding(
                                i, "2nd-Order SQLi - Table name from database",
                                VulnCategory.SQL_INJECTION, Severity.CRITICAL, "HIGH", db_var,
                                f"Table name from {db_source}. Stored payload can access/modify any table."
                            )
                        elif is_json:
                            self._add_finding(
                                i, "2nd-Order SQLi - Table name from JSON config",
                                VulnCategory.SQL_INJECTION, Severity.CRITICAL, "HIGH", json_var,
                                f"Table name from {json_source}. JSON poisoning enables table injection."
                            )

    def _check_structural_calc_sqli(self):
        """Detect 2nd-order SQLi in calculation and structural SQL sinks."""
        for i, line in enumerate(self.source_lines, 1):
            if line.strip().startswith('//') or line.strip().startswith('#'):
                continue

            # Check for direct DB-sourced values used AS column names in aggregate
            # functions (e.g. SUM($db_var)), NOT just anywhere on the line
            agg_match = re.search(r'(?:SUM|COUNT|AVG|MIN|MAX)\s*\(\s*\$(\w+)', line, re.IGNORECASE)
            if agg_match:
                agg_var = agg_match.group(1)
                if agg_var in self.db_sourced_vars:
                    source = self.db_sourced_vars[agg_var][1]
                    self._add_finding(
                        i, "2nd-Order SQLi - Calculation with DB-sourced column",
                        VulnCategory.SQL_INJECTION, Severity.CRITICAL, "HIGH", agg_var,
                        f"DB value from {source} used as column in aggregate function."
                    )

            # ORDER BY / GROUP BY with DB values
            if re.search(r'ORDER\s+BY\s+\$|GROUP\s+BY\s+\$', line, re.IGNORECASE):
                is_db, db_var, source = self._is_db_sourced(line)
                if is_db:
                    self._add_finding(
                        i, "2nd-Order SQLi - Structural clause with DB-sourced value",
                        VulnCategory.SQL_INJECTION, Severity.CRITICAL, "HIGH", db_var,
                        f"DB value from {source} in ORDER/GROUP BY. Boolean-based exfiltration possible."
                    )

    def _check_unserialize_sqli(self):
        """Detect 2nd-order SQLi via unserialized object properties (Double-Unserialize pattern).

        Pattern: Serialized payload stored in DB -> unserialize() -> property used in SQL
        Example: $prefs = unserialize($row['data']); $db->query("... " . $prefs->theme);
        """
        for i, line in enumerate(self.source_lines, 1):
            if line.strip().startswith('//') or line.strip().startswith('#'):
                continue

            # Skip safe parameterized queries
            if re.search(r'(?:prepare|bindParam|bindValue|execute\s*\(\s*\[)', line, re.IGNORECASE):
                continue

            # Check for SQL sinks with unserialized values
            sql_patterns = [
                r'(?:mysql_query|mysqli_query|pg_query|sqlite_query)\s*\(',
                r'\$\w+->query\s*\(',
                r'\$\w+->exec\s*\(',
                r'->(?:raw|select|where|whereRaw|selectRaw)\s*\(',
                r'(?:DB|Database)::(?:query|select|raw|statement)\s*\(',
            ]

            for sql_pat in sql_patterns:
                if re.search(sql_pat, line, re.IGNORECASE):
                    is_unser, var_name, source = self._is_unserialized(line)
                    if is_unser:
                        self._add_finding(
                            i, "2nd-Order SQLi - Unserialized object property in SQL (Double-Unserialize)",
                            VulnCategory.SQL_INJECTION, Severity.CRITICAL, "HIGH", var_name,
                            f"Unserialized object from {source} used in SQL. Payload chain: DB -> unserialize -> property -> SQL sink."
                        )
                        break

            # Check string concat into SQL patterns
            if re.search(r'["\'](?:SELECT|INSERT|UPDATE|DELETE|FROM|WHERE).*\.\s*\$', line, re.IGNORECASE):
                is_unser, var_name, source = self._is_unserialized(line)
                if is_unser:
                    self._add_finding(
                        i, "2nd-Order SQLi - Unserialized object in SQL concat (Double-Unserialize)",
                        VulnCategory.SQL_INJECTION, Severity.CRITICAL, "HIGH", var_name,
                        f"Unserialized value from {source} concatenated into SQL string."
                    )

            # sprintf SQL patterns
            if re.search(r'sprintf\s*\(\s*["\'](?:SELECT|INSERT|UPDATE|DELETE)', line, re.IGNORECASE):
                # Check if only integer format specifiers are used (%d, %i, %u, %x, %o)
                # These are much safer as they can't contain SQL injection payloads
                format_str_match = re.search(r'sprintf\s*\(\s*["\']([^"\']*)["\']', line)
                uses_int_only = False
                if format_str_match:
                    format_str = format_str_match.group(1)
                    # Find all format specifiers
                    format_specs = re.findall(r'%[^%\s]*[a-zA-Z]', format_str)
                    # Integer-only specifiers (safe for SQL injection)
                    uses_int_only = format_specs and all(re.match(r'%[-+0\s#\']*\d*\.?\d*[dioxXu]', spec) for spec in format_specs)

                is_unser, var_name, source = self._is_unserialized(line)
                if is_unser:
                    if uses_int_only:
                        self._add_finding(
                            i, "2nd-Order SQLi - sprintf with integer format (lower risk)",
                            VulnCategory.SQL_INJECTION, Severity.MEDIUM, "LOW", var_name,
                            f"Unserialized value from {source} in sprintf SQL with integer specifiers only. "
                            "Lower risk since integers can't contain SQL injection payloads."
                        )
                    else:
                        self._add_finding(
                            i, "2nd-Order SQLi - Unserialized value in sprintf SQL (Double-Unserialize)",
                            VulnCategory.SQL_INJECTION, Severity.CRITICAL, "HIGH", var_name,
                            f"Unserialized value from {source} formatted into SQL via sprintf."
                        )

    def _check_xpath_injection(self):
        """Detect 2nd-order XPath injection in PHP.

        PHP XPath Sinks:
        - DOMXPath->query($expr)
        - DOMXPath->evaluate($expr)
        - SimpleXMLElement->xpath($expr)

        Attack Payloads:
        - Breakout: "' or 1=1 or 'a'='a"
        - Enumerate: "//user" or "/*"
        """
        xpath_sinks = [
            r'\$\w+->query\s*\(',          # DOMXPath->query()
            r'\$\w+->evaluate\s*\(',        # DOMXPath->evaluate()
            r'\$\w+->xpath\s*\(',           # SimpleXMLElement->xpath()
            r'simplexml_load_.*->xpath\s*\(',
        ]

        # SQL functions that should NOT be flagged as XPath injection
        # These use ->query() but are SQL, not XPath
        sql_function_patterns = [
            r'\$pdo\s*->\s*query',           # PDO::query()
            r'\$\w*db\w*\s*->\s*query',      # $db->query(), $mysqli_db->query()
            r'\$\w*conn\w*\s*->\s*query',    # $conn->query(), $dbconn->query()
            r'\$mysqli\w*\s*->\s*query',     # $mysqli->query()
            r'\$\w*sql\w*\s*->\s*query',     # $sql->query()
            r'mysqli_query\s*\(',            # mysqli_query() function
            r'\$\w+\s*->\s*prepare\s*\(',    # Any ->prepare() is SQL, not XPath
        ]

        # Patterns indicating integer-only position variables (safe from XPath injection)
        int_position_patterns = [
            r'\[\s*\"\s*\.\s*\$(?:pos|position|index|idx|i|n|num|count)\s*\.\s*\"\s*\]',  # [" . $pos . "]
            r'\[\s*\$(?:pos|position|index|idx|i|n|num|count)\s*\]',  # [$pos]
            r'\[\s*\(\s*int\s*\)\s*\$',  # [(int)$var]
            r'\[\s*intval\s*\(\s*\$',    # [intval($var)]
            r'\[\s*\(\s*integer\s*\)\s*\$',  # [(integer)$var]
        ]

        for i, line in enumerate(self.source_lines, 1):
            if line.strip().startswith('//') or line.strip().startswith('#'):
                continue

            for sink_pattern in xpath_sinks:
                if re.search(sink_pattern, line, re.IGNORECASE):
                    # Skip SQL functions that have similar syntax to XPath sinks
                    is_sql_function = any(re.search(sql_pat, line, re.IGNORECASE) for sql_pat in sql_function_patterns)
                    if is_sql_function:
                        continue

                    # Check for integer-only position patterns (low risk)
                    # Pattern: xpath("//item[" . $pos . "]") where $pos is numeric
                    is_int_position = any(re.search(pat, line) for pat in int_position_patterns)
                    # Also check context for parseInt/intval/(int) cast on variable
                    context = '\n'.join(self.source_lines[max(0, i-5):i])
                    has_int_cast_context = re.search(r'(?:intval|parseInt|\(\s*int\s*\)|\(\s*integer\s*\))\s*\(\s*\$\w+\s*\)', context)

                    # Check for direct tainted input
                    is_tainted, taint_var = self._is_tainted(line)
                    if is_tainted:
                        if is_int_position or has_int_cast_context:
                            self._add_finding(
                                i, "XPath Injection - Position index with validated integer (lower risk)",
                                VulnCategory.XPATH_INJECTION, Severity.MEDIUM, "LOW", taint_var,
                                "XPath with integer position index. Lower risk since integers can't contain "
                                "XPath injection payloads. Verify the variable is properly cast/validated as integer."
                            )
                        else:
                            self._add_finding(
                                i, "XPath Injection - Query with tainted data",
                                VulnCategory.XPATH_INJECTION, Severity.CRITICAL, "HIGH", taint_var,
                                "User input in XPath query. Payload can enumerate nodes or break out."
                            )
                        break

                    # 2nd-order: DB-sourced values
                    is_db, db_var, source = self._is_db_sourced(line)
                    if is_db:
                        self._add_finding(
                            i, "2nd-Order XPath Injection - DB-sourced value in query",
                            VulnCategory.XPATH_INJECTION, Severity.CRITICAL, "HIGH", db_var,
                            f"DB value from {source} used in XPath. Stored payload can enumerate nodes."
                        )
                        break

                    # 2nd-order: JSON-decoded values
                    is_json, json_var, json_source = self._is_json_poisoned(line)
                    if is_json:
                        self._add_finding(
                            i, "2nd-Order XPath Injection - JSON-decoded value in query",
                            VulnCategory.XPATH_INJECTION, Severity.CRITICAL, "HIGH", json_var,
                            f"JSON value from {json_source} used in XPath. Poisoned JSON payload."
                        )
                        break

                    # 2nd-order: Unserialized values
                    is_unser, unser_var, unser_source = self._is_unserialized(line)
                    if is_unser:
                        self._add_finding(
                            i, "2nd-Order XPath Injection - Unserialized value in query",
                            VulnCategory.XPATH_INJECTION, Severity.CRITICAL, "HIGH", unser_var,
                            f"Unserialized value from {unser_source} used in XPath. Double-unserialize attack."
                        )
                        break

            # Check for string concatenation XPath patterns
            if re.search(r'xpath\s*\(\s*["\']//.*\.\s*\$', line, re.IGNORECASE):
                is_db, db_var, source = self._is_db_sourced(line)
                if is_db:
                    self._add_finding(
                        i, "2nd-Order XPath Injection - Concatenation with DB value",
                        VulnCategory.XPATH_INJECTION, Severity.CRITICAL, "HIGH", db_var,
                        f"DB value from {source} concatenated into XPath expression."
                    )

class CSharpAnalyzer:
    """
    C# analyzer with taint tracking for ASP.NET and general C# vulnerabilities.
    Includes 2nd-order SQLi detection for:
    - Entity Framework FromSqlRaw/ExecuteSqlRaw with entity values
    - Auto-mapper mass assignment patterns
    - Dynamic UPDATE/INSERT with entity property access
    """

    def __init__(self, source_code: str, file_path: str):
        self.source_code = source_code
        self.source_lines = source_code.splitlines()
        self.file_path = file_path
        self.findings: List[Finding] = []
        self.tainted_vars: Dict[str, int] = {}
        self.tainted_fields: Dict[str, int] = {}  # Track tainted class fields
        self.constructor_params: Dict[str, int] = {}  # Track constructor parameters
        # 2nd-order tracking
        self.db_sourced_vars: Dict[str, Tuple[int, str]] = {}  # var -> (line, source)

        self._identify_taint_sources()
        self._track_variable_assignments()
        self._track_field_assignments()
        self._track_database_sources()

    def _identify_taint_sources(self):
        """Identify ASP.NET request objects and method parameters as taint sources."""
        taint_patterns = [
            r'Request\s*\[', r'Request\.QueryString', r'Request\.Form',
            r'Request\.Cookies', r'Request\.Headers', r'Request\.Params',
            r'Request\.RawUrl', r'Request\.Url', r'Request\.Path',
            r'HttpContext\.Current\.Request',
        ]

        for i, line in enumerate(self.source_lines, 1):
            for pattern in taint_patterns:
                if re.search(pattern, line):
                    match = re.search(r'(?:var|string|object)\s+(\w+)\s*=', line)
                    if match:
                        self.tainted_vars[match.group(1)] = i

        # Method parameters (handle async, static, virtual, override, etc.)
        for i, line in enumerate(self.source_lines, 1):
            # Match method declarations with various modifiers: public async void Method(params)
            match = re.search(
                r'(?:public|private|protected|internal)\s+(?:static\s+)?(?:async\s+)?(?:virtual\s+)?(?:override\s+)?'
                r'(?:\w+(?:<[^>]+>)?)\s+(\w+)\s*\(([^)]*)\)',
                line
            )
            if match:
                params = match.group(2)
                for param_match in re.finditer(r'(?:\w+(?:<[^>]+>)?)\s+(\w+)', params):
                    self.tainted_vars[param_match.group(1)] = i

    def _track_variable_assignments(self):
        for i, line in enumerate(self.source_lines, 1):
            if line.strip().startswith('//'):
                continue
            # Match variable declarations: var x = ...; or string x = ...;
            match = re.search(r'(?:var|string|object|int|bool|Uri)\s+(\w+)\s*=\s*(.+?);', line)
            if match:
                var_name = match.group(1)
                rhs = match.group(2)
                for tainted in list(self.tainted_vars.keys()):
                    # Check if tainted var appears in RHS (including through method chains)
                    if re.search(rf'\b{re.escape(tainted)}\b', rhs):
                        self.tainted_vars[var_name] = i
                        break
            # Also track simple assignments without type: x = tainted.Something();
            else:
                match = re.search(r'(\w+)\s*=\s*(.+?);', line)
                if match and '==' not in line and '!=' not in line:
                    var_name = match.group(1)
                    rhs = match.group(2)
                    for tainted in list(self.tainted_vars.keys()):
                        if re.search(rf'\b{re.escape(tainted)}\b', rhs):
                            self.tainted_vars[var_name] = i
                            break

    def _track_field_assignments(self):
        """Track constructor parameter to field assignments for delayed execution patterns."""
        in_constructor = False
        constructor_line = 0
        current_class = None

        for i, line in enumerate(self.source_lines, 1):
            if line.strip().startswith('//'):
                continue

            # Track class declarations
            class_match = re.search(r'(?:public|private|internal)?\s*class\s+(\w+)', line)
            if class_match:
                current_class = class_match.group(1)

            # Detect constructor: ClassName(params) or public ClassName(params)
            if current_class:
                ctor_pattern = rf'(?:public|private|protected|internal)?\s*{re.escape(current_class)}\s*\(([^)]*)\)'
                ctor_match = re.search(ctor_pattern, line)
                if ctor_match and '~' not in line:  # Not a destructor
                    in_constructor = True
                    constructor_line = i
                    # Extract constructor parameters as taint sources
                    params = ctor_match.group(1)
                    for param_match in re.finditer(r'(?:\w+(?:<[^>]+>)?)\s+(\w+)', params):
                        param_name = param_match.group(1)
                        self.constructor_params[param_name] = i
                        self.tainted_vars[param_name] = i

            # Track field assignments inside constructor: this._field = param or _field = param
            if in_constructor:
                # Pattern: this._field = param; or _field = param; or this.Field = param;
                field_assign = re.search(r'(?:this\.)?(_?\w+)\s*=\s*(\w+)\s*;', line)
                if field_assign:
                    field_name = field_assign.group(1)
                    assigned_value = field_assign.group(2)
                    # Check if assigned value is a constructor parameter (tainted)
                    if assigned_value in self.constructor_params:
                        self.tainted_fields[field_name] = i
                        # Also track without underscore prefix and with this. prefix
                        if field_name.startswith('_'):
                            self.tainted_fields[field_name[1:]] = i
                        self.tainted_fields[f'this.{field_name}'] = i

            # End of constructor (simplified: next method or closing brace at same indent)
            if in_constructor and i > constructor_line:
                # Detect end of constructor by finding next method or destructor
                if re.search(r'(?:public|private|protected|internal)\s+(?:void|string|int|bool|async)', line):
                    in_constructor = False
                elif re.search(r'~\w+\s*\(\s*\)', line):
                    in_constructor = False

    def _track_database_sources(self):
        """Track variables that receive values from Entity Framework/DB queries."""
        # EF Core / Entity Framework patterns
        ef_patterns = [
            (r'(\w+)\s*=\s*(?:db|context|_context|_db)\.(\w+)\.Find\s*\(', 'DbContext.Find'),
            (r'(\w+)\s*=\s*(?:db|context|_context|_db)\.(\w+)\.FirstOrDefault\s*\(', 'DbContext.FirstOrDefault'),
            (r'(\w+)\s*=\s*(?:db|context|_context|_db)\.(\w+)\.SingleOrDefault\s*\(', 'DbContext.SingleOrDefault'),
            (r'(\w+)\s*=\s*(?:db|context|_context|_db)\.(\w+)\.First\s*\(', 'DbContext.First'),
            (r'(\w+)\s*=\s*await\s+(?:db|context|_context|_db)\.(\w+)\.FindAsync\s*\(', 'DbContext.FindAsync'),
            (r'(\w+)\s*=\s*await\s+(?:db|context|_context|_db)\.(\w+)\.FirstOrDefaultAsync\s*\(', 'DbContext.FirstOrDefaultAsync'),
        ]

        for i, line in enumerate(self.source_lines, 1):
            if line.strip().startswith('//'):
                continue

            for pattern, source_type in ef_patterns:
                match = re.search(pattern, line)
                if match:
                    var_name = match.group(1)
                    table_name = match.group(2)
                    self.db_sourced_vars[var_name] = (i, f"{source_type}({table_name})")

        # Track property access on entity objects: var prop = entity.PropertyName
        for i, line in enumerate(self.source_lines, 1):
            if line.strip().startswith('//'):
                continue

            for entity_var in list(self.db_sourced_vars.keys()):
                # Pattern: entity.Property (C# property access)
                prop_pattern = rf'{re.escape(entity_var)}\.(\w+)'
                for match in re.finditer(prop_pattern, line):
                    prop_name = match.group(1)
                    # Skip common method calls
                    if prop_name not in ['Find', 'FirstOrDefault', 'Where', 'Select', 'ToString']:
                        orig_line, orig_source = self.db_sourced_vars[entity_var]
                        # Track the property access pattern for inline detection
                        prop_key = f"{entity_var}.{prop_name}"
                        self.db_sourced_vars[prop_key] = (i, f"{orig_source}.{prop_name}")

    def _is_db_sourced(self, line: str) -> Tuple[bool, Optional[str], Optional[str]]:
        """Check if line uses a database/entity-sourced variable or property."""
        for var, (src_line, source) in self.db_sourced_vars.items():
            if re.search(rf'\b{re.escape(var)}\b', line):
                return True, var, source
        return False, None, None

    def _is_tainted(self, line: str) -> Tuple[bool, Optional[str]]:
        # Remove string literals from the line to avoid matching variable names inside strings
        # This prevents matching 'cmd' inside "cmd.exe" or similar
        line_without_strings = re.sub(r'"[^"\\]*(?:\\.[^"\\]*)*"', '""', line)
        line_without_strings = re.sub(r"'[^'\\]*(?:\\.[^'\\]*)*'", "''", line_without_strings)

        for var in self.tainted_vars:
            if re.search(rf'\b{re.escape(var)}\b', line_without_strings):
                return True, var
        # Check tainted fields (from constructor parameter flow)
        for field in self.tainted_fields:
            if re.search(rf'\b{re.escape(field)}\b', line_without_strings):
                return True, field
        if re.search(r'Request\s*[\[.]', line_without_strings):
            return True, 'Request'
        return False, None

    def get_line_content(self, lineno: int) -> str:
        if 1 <= lineno <= len(self.source_lines):
            return self.source_lines[lineno - 1]
        return ""

    def analyze(self) -> List[Finding]:
        self._check_sql_injection()
        self._check_command_injection()
        self._check_linq_taint_tunnel()
        self._check_deserialization()
        self._check_xxe()
        self._check_ldap_injection()
        self._check_xpath_injection()
        self._check_ssti()
        self._check_viewstate_vulnerabilities()
        # 2nd-order SQL injection detection
        self._check_second_order_sqli()
        return self.findings

    def _add_finding(self, line_num: int, vuln_name: str, category: VulnCategory,
                     severity: Severity, confidence: str, taint_var: Optional[str] = None,
                     description: str = ""):
        taint_chain = []
        if taint_var and taint_var in self.tainted_vars:
            taint_chain = [f"tainted: {taint_var} (line {self.tainted_vars[taint_var]})"]
        elif taint_var:
            taint_chain = [f"tainted: {taint_var}"]

        self.findings.append(Finding(
            file_path=self.file_path, line_number=line_num, col_offset=0,
            line_content=self.get_line_content(line_num),
            vulnerability_name=vuln_name, category=category,
            severity=severity, confidence=confidence,
            taint_chain=taint_chain, description=description,
        ))

    def _check_sql_injection(self):
        sql_patterns = [
            r'\.ExecuteReader\s*\(', r'\.ExecuteNonQuery\s*\(', r'\.ExecuteScalar\s*\(',
            r'SqlCommand\s*\(', r'new\s+SqlCommand\s*\(',
            r'\.CommandText\s*=',
        ]
        sql_keywords = r'(?:SELECT|INSERT|UPDATE|DELETE|DROP|EXEC|EXECUTE|FROM|WHERE|INTO)'

        for i, line in enumerate(self.source_lines, 1):
            if line.strip().startswith('//'):
                continue

            for pattern in sql_patterns:
                if re.search(pattern, line):
                    # Check if this uses parameterized query placeholders (@param)
                    has_param_placeholder = bool(re.search(r'@\w+', line))

                    # Look ahead for Parameters.AddWithValue or Parameters.Add (within next 15 lines)
                    context_window = 15
                    end_idx = min(i + context_window, len(self.source_lines))
                    context_lines = self.source_lines[i-1:end_idx]
                    has_param_add = any(re.search(r'\.Parameters\s*\.\s*(Add|AddWithValue)\s*\(', ctx_line)
                                        for ctx_line in context_lines)

                    is_tainted, taint_var = self._is_tainted(line)

                    # Detect unsafe string building patterns
                    # - String concatenation with quotes: "SELECT " + var
                    # - Interpolated strings: $"SELECT {var}"
                    # - String.Format: string.Format("SELECT {0}", var)
                    has_string_concat = bool(re.search(r'["\'].*\+|\+.*["\']', line))
                    has_interpolation = '$"' in line or '$@"' in line
                    has_string_format = bool(re.search(r'[Ss]tring\.Format\s*\(', line))
                    has_unsafe_concat = has_string_concat or has_interpolation or has_string_format

                    # If using @param placeholders AND Parameters.Add, it's safe parameterized query
                    if has_param_placeholder and has_param_add and not has_unsafe_concat:
                        continue  # Safe - skip this line

                    # CRITICAL: Tainted data with unsafe concatenation (definite SQLi)
                    if is_tainted and has_unsafe_concat:
                        self._add_finding(i, "SQL Injection - SqlCommand with tainted data",
                                          VulnCategory.SQL_INJECTION, Severity.CRITICAL, "HIGH", taint_var,
                                          "User input concatenated into SQL command.")
                    # HIGH: Has unsafe concat with SQL keywords but no detected taint
                    elif has_unsafe_concat and re.search(sql_keywords, line, re.IGNORECASE):
                        self._add_finding(i, "SQL Injection - Dynamic query construction",
                                          VulnCategory.SQL_INJECTION, Severity.HIGH, "MEDIUM",
                                          description="SQL uses string concatenation. Use parameterized queries.")

            # Detect string.Format with SQL keywords (intermediate formatting evasion)
            if re.search(r'string\.Format\s*\(', line, re.IGNORECASE):
                is_tainted, taint_var = self._is_tainted(line)
                # Check context for SQL keywords (in format string or nearby lines)
                context = '\n'.join(self.source_lines[max(0, i-3):i+1])
                if is_tainted and re.search(sql_keywords, context, re.IGNORECASE):
                    self._add_finding(i, "SQL Injection - string.Format with tainted data",
                                      VulnCategory.SQL_INJECTION, Severity.CRITICAL, "HIGH", taint_var,
                                      "User input formatted into SQL string. Use parameterized queries.")
                elif re.search(sql_keywords, context, re.IGNORECASE):
                    # Check if any method param is in the Format call
                    for var in self.tainted_vars:
                        if re.search(rf'\b{re.escape(var)}\b', line):
                            self._add_finding(i, "SQL Injection - string.Format with user input",
                                              VulnCategory.SQL_INJECTION, Severity.HIGH, "HIGH", var,
                                              "SQL query built via string.Format with user-controlled value.")

            # EF Core: FromSql / FromSqlRaw with interpolated or concatenated string variable
            if re.search(r'\.FromSql(?:Raw)?\s*\(', line):
                var_match = re.search(r'\.FromSql(?:Raw)?\s*\(\s*(\w+)\s*[,\)]', line)
                if var_match:
                    var_name = var_match.group(1)
                    for back in range(max(0, i - 10), i):
                        back_line = self.source_lines[back]
                        if re.search(rf'\b{re.escape(var_name)}\b\s*=', back_line):
                            if '$"' in back_line or '$@"' in back_line or re.search(r'["\'].*\+|\+.*["\']', back_line) or re.search(r'[Ss]tring\.Format', back_line):
                                if re.search(sql_keywords, back_line, re.IGNORECASE):
                                    self._add_finding(i, "SQL Injection - EF Core FromSql with interpolated string",
                                                      VulnCategory.SQL_INJECTION, Severity.CRITICAL, "HIGH",
                                                      description="String interpolation used to build SQL query passed to FromSql(). "
                                                      "Use parameterized queries or FromSqlInterpolated().")
                                    break

            # EF Core: ExecuteSqlRaw / ExecuteSqlCommand with interpolated string variable
            if re.search(r'\.ExecuteSql(?:Raw|Command)?\s*\(', line):
                var_match = re.search(r'\.ExecuteSql(?:Raw|Command)?\s*\(\s*(\w+)\s*[,\)]', line)
                if var_match:
                    var_name = var_match.group(1)
                    for back in range(max(0, i - 10), i):
                        back_line = self.source_lines[back]
                        if re.search(rf'\b{re.escape(var_name)}\b\s*=', back_line):
                            if '$"' in back_line or '$@"' in back_line or re.search(r'["\'].*\+|\+.*["\']', back_line) or re.search(r'[Ss]tring\.Format', back_line):
                                if re.search(sql_keywords, back_line, re.IGNORECASE):
                                    self._add_finding(i, "SQL Injection - EF Core ExecuteSql with interpolated string",
                                                      VulnCategory.SQL_INJECTION, Severity.CRITICAL, "HIGH",
                                                      description="String interpolation used to build SQL query passed to ExecuteSql(). "
                                                      "Use parameterized queries.")
                                    break

    def _check_command_injection(self):
        # Common system tools used in "helper" wrapper methods
        system_tools = r'(?:ping|ipconfig|ifconfig|nslookup|tracert|traceroute|netstat|whoami|hostname|' \
                       r'git|svn|curl|wget|ssh|scp|ftp|telnet|nmap|dig|arp|route|systeminfo|tasklist|' \
                       r'sc|net|wmic|reg|certutil|bitsadmin|msiexec|mshta|cscript|wscript)'

        # Track ProcessStartInfo blocks for multi-line analysis
        in_psi_block = False
        psi_block_start = 0
        psi_block_lines = []

        for i, line in enumerate(self.source_lines, 1):
            if line.strip().startswith('//'):
                continue

            # Detect ProcessStartInfo object initializer blocks
            if re.search(r'new\s+ProcessStartInfo\s*\{', line) or re.search(r'ProcessStartInfo\s+\w+\s*=\s*new\s+ProcessStartInfo\s*\{', line):
                in_psi_block = True
                psi_block_start = i
                psi_block_lines = [line]
            elif in_psi_block:
                psi_block_lines.append(line)
                if '}' in line and line.count('}') > line.count('{'):
                    # End of PSI block - analyze it
                    block_text = '\n'.join(psi_block_lines)
                    self._analyze_psi_block(psi_block_start, block_text, system_tools)
                    in_psi_block = False
                    psi_block_lines = []

            # Check for Arguments property assignment with concatenation
            if re.search(r'\.Arguments\s*=', line):
                is_tainted, taint_var = self._is_tainted(line)
                has_concat = '+' in line or '$"' in line or 'String.Format' in line or '$@"' in line

                # Check for system tools in Arguments
                has_system_tool = re.search(system_tools, line, re.IGNORECASE)

                if is_tainted and has_concat:
                    self._add_finding(i, "Command Injection - Arguments with concatenated user input",
                                      VulnCategory.COMMAND_INJECTION, Severity.CRITICAL, "HIGH", taint_var,
                                      "User input concatenated into process Arguments property.")
                elif is_tainted:
                    self._add_finding(i, "Command Injection - Arguments with tainted data",
                                      VulnCategory.COMMAND_INJECTION, Severity.HIGH, "HIGH", taint_var,
                                      "User input passed to process Arguments.")
                elif has_concat and has_system_tool:
                    self._add_finding(i, "Command Injection - System tool wrapper with dynamic arguments",
                                      VulnCategory.COMMAND_INJECTION, Severity.HIGH, "MEDIUM",
                                      description=f"Arguments to system tool built via concatenation. Validate/escape input.")

            if re.search(r'Process\.Start\s*\(|ProcessStartInfo', line):
                is_tainted, taint_var = self._is_tainted(line)
                has_concat = '+' in line or '$"' in line or 'String.Format' in line

                if is_tainted:
                    self._add_finding(i, "Command Injection - Process.Start with tainted data",
                                      VulnCategory.COMMAND_INJECTION, Severity.CRITICAL, "HIGH", taint_var,
                                      "User input passed to Process.Start().")

                # Check for shell execution pattern: cmd.exe /c or powershell -c
                context = '\n'.join(self.source_lines[max(0, i-2):min(len(self.source_lines), i+3)])
                shell_pattern = re.search(
                    r'["\'](?:cmd(?:\.exe)?|powershell(?:\.exe)?)["\'].*["\'](?:/c|/k|-c|-Command)["\']',
                    context, re.IGNORECASE
                )
                if shell_pattern:
                    # Check taint in broader context
                    context_tainted, context_taint_var = self._is_tainted(context)
                    if context_tainted:
                        self._add_finding(i, "Command Injection - Shell execution pattern with tainted input",
                                          VulnCategory.COMMAND_INJECTION, Severity.CRITICAL, "HIGH", context_taint_var,
                                          "Process.Start with cmd/powershell -c and user-controlled command.")
                    elif has_concat or '+' in context:
                        self._add_finding(i, "Command Injection - Shell execution with dynamic command",
                                          VulnCategory.COMMAND_INJECTION, Severity.HIGH, "HIGH",
                                          description="Process.Start with cmd/powershell -c and string concatenation.")
                    else:
                        self._add_finding(i, "Command Injection - Shell execution pattern",
                                          VulnCategory.COMMAND_INJECTION, Severity.MEDIUM, "MEDIUM",
                                          description="Process.Start with cmd/powershell -c pattern. Review for injection.")

            # Reflection-based execution: Type.InvokeMember, MethodInfo.Invoke
            if re.search(r'\.InvokeMember\s*\(|MethodInfo.*\.Invoke\s*\(', line):
                context = '\n'.join(self.source_lines[max(0, i-10):i+1])
                if re.search(r'Process|Start|Shell|Command|Execute', context, re.IGNORECASE):
                    is_tainted, taint_var = self._is_tainted(line)
                    if is_tainted:
                        self._add_finding(i, "Command Injection - Reflection Invoke with tainted input",
                                          VulnCategory.COMMAND_INJECTION, Severity.CRITICAL, "HIGH", taint_var,
                                          "Reflection used to invoke command execution with user input.")
                    else:
                        self._add_finding(i, "Command Injection - Reflection Invoke (evasion)",
                                          VulnCategory.COMMAND_INJECTION, Severity.HIGH, "HIGH",
                                          description="Reflection invoke near command execution - evasion technique.")

        # Second pass: Detect destructor/finalizer command injection (delayed execution pattern)
        self._check_destructor_injection(system_tools)

    def _check_destructor_injection(self, system_tools: str):
        """Detect command injection in destructors/finalizers - delayed execution attack pattern."""
        in_destructor = False
        destructor_line = 0
        destructor_class = None

        for i, line in enumerate(self.source_lines, 1):
            if line.strip().startswith('//'):
                continue

            # Detect destructor: ~ClassName()
            dtor_match = re.search(r'~(\w+)\s*\(\s*\)', line)
            if dtor_match:
                in_destructor = True
                destructor_line = i
                destructor_class = dtor_match.group(1)
                continue

            if in_destructor:
                # Check for Process.Start or other dangerous calls in destructor
                if re.search(r'Process\.Start\s*\(', line):
                    is_tainted, taint_var = self._is_tainted(line)
                    has_concat = '+' in line or '$"' in line or 'String.Format' in line

                    if is_tainted:
                        self._add_finding(i, "Command Injection - Destructor/Finalizer with tainted field",
                                          VulnCategory.COMMAND_INJECTION, Severity.CRITICAL, "HIGH", taint_var,
                                          f"Tainted field used in Process.Start inside ~{destructor_class}() finalizer. "
                                          "Command executes automatically during garbage collection.")
                    elif has_concat:
                        # Check if any field is used in the concatenation
                        field_used = None
                        for field in self.tainted_fields:
                            if re.search(rf'\b{re.escape(field)}\b', line):
                                field_used = field
                                break
                        if field_used:
                            self._add_finding(i, "Command Injection - Destructor with tainted field concatenation",
                                              VulnCategory.COMMAND_INJECTION, Severity.CRITICAL, "HIGH", field_used,
                                              f"Field '{field_used}' (tainted via constructor) concatenated in "
                                              f"~{destructor_class}() finalizer. Delayed command execution attack.")

                # Also check for other dangerous patterns in destructors
                if re.search(r'\.Start\s*\(|Runtime.*exec|shell|cmd\.exe|powershell', line, re.IGNORECASE):
                    is_tainted, taint_var = self._is_tainted(line)
                    if is_tainted and 'Process.Start' not in line:  # Avoid duplicate with above
                        self._add_finding(i, "Command Injection - Dangerous call in destructor",
                                          VulnCategory.COMMAND_INJECTION, Severity.HIGH, "HIGH", taint_var,
                                          f"Tainted data used in dangerous call inside ~{destructor_class}() finalizer.")

                # End of destructor (next method or closing brace)
                if re.search(r'(?:public|private|protected|internal)\s+', line) and '~' not in line:
                    in_destructor = False
                elif line.strip() == '}' and i > destructor_line + 1:
                    # Simple heuristic: closing brace likely ends the destructor
                    in_destructor = False

    def _check_linq_taint_tunnel(self):
        """
        Detect LINQ-based taint tunneling where user input flows through LINQ operations
        to command execution sinks.
        Example: userInputList.Select(x => $"/c {x}").ToList() -> Process.Start(Arguments = list[0])
        """
        # Track collections that contain tainted data
        tainted_collections = {}  # var_name -> line_num

        for i, line in enumerate(self.source_lines, 1):
            stripped = line.strip()
            if stripped.startswith('//'):
                continue

            # Detect List/collection initialization with tainted data
            # Pattern: new List<string> { input } or var list = new List<...>()
            list_init_match = re.search(r'(?:var|List<[^>]+>)\s+(\w+)\s*=\s*new\s+List<[^>]+>\s*(?:\{([^}]*)\}|\(\s*\))', line)
            if list_init_match:
                var_name = list_init_match.group(1)
                init_content = list_init_match.group(2) or ''
                is_tainted, taint_var = self._is_tainted(init_content) if init_content else (False, None)
                if is_tainted:
                    tainted_collections[var_name] = i

            # Detect .Add() to collection with tainted data
            add_match = re.search(r'(\w+)\.Add\s*\(\s*([^)]+)\s*\)', line)
            if add_match:
                collection_name = add_match.group(1)
                added_value = add_match.group(2)
                is_tainted, taint_var = self._is_tainted(added_value)
                if is_tainted:
                    tainted_collections[collection_name] = i

            # Detect LINQ Select with lambda that transforms data for command execution
            # Pattern: collection.Select(x => $"/c {x}") or .Select(x => "/c " + x)
            select_match = re.search(r'(\w+)\s*\.\s*Select\s*\(\s*(\w+)\s*=>\s*(.+?)\)', line)
            if select_match:
                source_collection = select_match.group(1)
                lambda_param = select_match.group(2)
                lambda_body = select_match.group(3)

                # Check if source is tainted or has dangerous patterns in lambda
                source_tainted = source_collection in tainted_collections
                has_shell_pattern = re.search(r'/c\s|cmd|powershell|-Command|-c\s', lambda_body, re.IGNORECASE)
                has_interpolation = re.search(rf'\$".*\{{{lambda_param}\}}|"\s*\+\s*{lambda_param}|{lambda_param}\s*\+', lambda_body)

                if source_tainted and has_shell_pattern and has_interpolation:
                    self._add_finding(i, "Command Injection - LINQ Select transforms tainted data for shell",
                                      VulnCategory.COMMAND_INJECTION, Severity.CRITICAL, "HIGH",
                                      description=f"LINQ .Select() transforms tainted data from '{source_collection}' into shell commands. "
                                                  f"Pattern: {lambda_body}")
                elif has_shell_pattern and has_interpolation:
                    is_tainted, taint_var = self._is_tainted(line)
                    if is_tainted:
                        self._add_finding(i, "Command Injection - LINQ Select builds shell commands",
                                          VulnCategory.COMMAND_INJECTION, Severity.HIGH, "HIGH", taint_var,
                                          description="LINQ .Select() lambda builds shell command patterns with variable data.")

            # Detect chained LINQ to Process.Start pattern
            # Pattern: .Select(...).FirstOrDefault() or .First() used in Process.Start
            if re.search(r'\.(FirstOrDefault|First|Single|Last)\s*\(\s*\)', line):
                context = '\n'.join(self.source_lines[max(0, i-5):min(len(self.source_lines), i+5)])
                if re.search(r'\.Select\s*\(', context) and re.search(r'Process\.Start|ProcessStartInfo', context):
                    is_tainted, taint_var = self._is_tainted(context)
                    if is_tainted:
                        self._add_finding(i, "Command Injection - LINQ result flows to Process.Start",
                                          VulnCategory.COMMAND_INJECTION, Severity.CRITICAL, "HIGH", taint_var,
                                          description="LINQ operation result (potentially transformed tainted data) flows to Process.Start.")

            # Detect aggregation patterns that might hide taint: .Aggregate(), .Join(), etc.
            if re.search(r'\.(Aggregate|Join|Concat)\s*\(', line):
                context = '\n'.join(self.source_lines[max(0, i-5):i+1])
                is_tainted, taint_var = self._is_tainted(context)
                if is_tainted:
                    # Check if result flows to dangerous sink
                    forward_context = '\n'.join(self.source_lines[i-1:min(len(self.source_lines), i+10)])
                    if re.search(r'Process\.Start|Arguments\s*=|ProcessStartInfo', forward_context):
                        self._add_finding(i, "Command Injection - LINQ aggregation tunnels tainted data to sink",
                                          VulnCategory.COMMAND_INJECTION, Severity.HIGH, "HIGH", taint_var,
                                          description="LINQ aggregation method may tunnel tainted data to command execution.")

    def _analyze_psi_block(self, start_line: int, block_text: str, system_tools: str):
        """Analyze a ProcessStartInfo object initializer block for command injection."""
        is_tainted, taint_var = self._is_tainted(block_text)
        has_concat = '+' in block_text or '$"' in block_text or 'String.Format' in block_text

        # Check for shell with arguments pattern
        shell_with_args = re.search(
            r'FileName\s*=\s*["\'](?:cmd(?:\.exe)?|powershell(?:\.exe)?|/bin/(?:ba)?sh)["\']',
            block_text, re.IGNORECASE
        )
        has_arguments = re.search(r'Arguments\s*=', block_text)
        has_system_tool = re.search(system_tools, block_text, re.IGNORECASE)

        if shell_with_args and has_arguments:
            if is_tainted and has_concat:
                self._add_finding(start_line, "Command Injection - ProcessStartInfo shell wrapper with tainted arguments",
                                  VulnCategory.COMMAND_INJECTION, Severity.CRITICAL, "HIGH", taint_var,
                                  "Shell invoked with user-controlled arguments via string concatenation.")
            elif is_tainted:
                self._add_finding(start_line, "Command Injection - ProcessStartInfo shell wrapper with user input",
                                  VulnCategory.COMMAND_INJECTION, Severity.CRITICAL, "HIGH", taint_var,
                                  "Shell invoked with user-controlled arguments.")
            elif has_concat:
                self._add_finding(start_line, "Command Injection - ProcessStartInfo shell wrapper with dynamic arguments",
                                  VulnCategory.COMMAND_INJECTION, Severity.HIGH, "HIGH",
                                  description="Shell invoked with dynamically constructed arguments. Validate/escape input.")
        elif has_system_tool and has_arguments:
            if is_tainted and has_concat:
                self._add_finding(start_line, "Command Injection - System tool wrapper with tainted arguments",
                                  VulnCategory.COMMAND_INJECTION, Severity.CRITICAL, "HIGH", taint_var,
                                  f"System tool invoked with user input concatenated into arguments.")
            elif is_tainted:
                self._add_finding(start_line, "Command Injection - System tool wrapper with user input",
                                  VulnCategory.COMMAND_INJECTION, Severity.HIGH, "HIGH", taint_var,
                                  "System tool invoked with user-controlled arguments.")
            elif has_concat:
                self._add_finding(start_line, "Command Injection - System tool with dynamic arguments",
                                  VulnCategory.COMMAND_INJECTION, Severity.MEDIUM, "MEDIUM",
                                  description="System tool arguments built via concatenation. Review for injection.")

    def _check_deserialization(self):
        deser_patterns = [
            r'BinaryFormatter', r'\.Deserialize\s*\(',
            r'JsonConvert\.DeserializeObject', r'XmlSerializer',
            r'DataContractSerializer', r'NetDataContractSerializer',
            r'ObjectStateFormatter', r'LosFormatter',
            r'SoapFormatter', r'JavaScriptSerializer',
        ]

        for i, line in enumerate(self.source_lines, 1):
            if line.strip().startswith('//'):
                continue

            for pattern in deser_patterns:
                if re.search(pattern, line):
                    is_tainted, taint_var = self._is_tainted(line)

                    # Dangerous deserializers that always lead to RCE with untrusted data
                    dangerous_formatters = ['BinaryFormatter', 'NetDataContractSerializer',
                                            'LosFormatter', 'ObjectStateFormatter', 'SoapFormatter']

                    matched_formatter = next((f for f in dangerous_formatters if f in line), None)
                    if matched_formatter:
                        # ViewState-specific formatters get special messaging
                        if matched_formatter in ['LosFormatter', 'ObjectStateFormatter']:
                            self._add_finding(i, f"Insecure Deserialization - {matched_formatter} (ViewState)",
                                              VulnCategory.DESERIALIZATION, Severity.CRITICAL, "HIGH", taint_var,
                                              f"{matched_formatter} deserializes ViewState objects. "
                                              "Without MachineKey validation, attackers can achieve RCE via ysoserial.net payloads.")
                        else:
                            self._add_finding(i, f"Insecure Deserialization - {matched_formatter}",
                                              VulnCategory.DESERIALIZATION, Severity.CRITICAL, "HIGH", taint_var,
                                              "Dangerous deserializer can lead to RCE.")
                    elif 'JsonConvert.DeserializeObject' in line:
                        # Check for dangerous TypeNameHandling in context
                        context = '\n'.join(self.source_lines[max(0, i-10):i+1])
                        has_typenamehandling = re.search(
                            r'TypeNameHandling\s*[=.]\s*(?:TypeNameHandling\.)?(Auto|All|Objects|Arrays)',
                            context
                        )
                        if has_typenamehandling and is_tainted:
                            self._add_finding(i, "Insecure Deserialization - JsonConvert with TypeNameHandling",
                                              VulnCategory.DESERIALIZATION, Severity.CRITICAL, "HIGH", taint_var,
                                              f"TypeNameHandling.{has_typenamehandling.group(1)} enables arbitrary type instantiation. "
                                              "Attacker can achieve RCE via gadget chains.")
                        elif has_typenamehandling:
                            self._add_finding(i, "Insecure Deserialization - TypeNameHandling enabled",
                                              VulnCategory.DESERIALIZATION, Severity.CRITICAL, "HIGH",
                                              description=f"TypeNameHandling.{has_typenamehandling.group(1)} allows arbitrary type "
                                              "instantiation leading to RCE if attacker controls JSON input.")
                        elif is_tainted:
                            self._add_finding(i, "Insecure Deserialization - JsonConvert with tainted data",
                                              VulnCategory.DESERIALIZATION, Severity.HIGH, "MEDIUM", taint_var,
                                              "User data being deserialized. Check for TypeNameHandling settings.")
                    elif is_tainted:
                        self._add_finding(i, "Insecure Deserialization - Deserialize with tainted data",
                                          VulnCategory.DESERIALIZATION, Severity.HIGH, "MEDIUM", taint_var,
                                          "User data being deserialized.")

            # Detect TypeNameHandling configuration (state-based vulnerability)
            if re.search(r'TypeNameHandling\s*=\s*(?:TypeNameHandling\.)?(Auto|All|Objects)', line):
                match = re.search(r'TypeNameHandling\s*=\s*(?:TypeNameHandling\.)?(Auto|All|Objects)', line)
                self._add_finding(i, f"Insecure Deserialization - TypeNameHandling.{match.group(1)} configured",
                                  VulnCategory.DESERIALIZATION, Severity.HIGH, "HIGH",
                                  description=f"TypeNameHandling.{match.group(1)} enables arbitrary type instantiation. "
                                  "If used with untrusted JSON input, this leads to RCE.")

            # PowerShell execution via System.Management.Automation
            if re.search(r'System\.Management\.Automation|PowerShell\.Create|\.AddScript\s*\(|\.AddCommand\s*\(', line):
                is_tainted, taint_var = self._is_tainted(line)
                if is_tainted:
                    self._add_finding(i, "Command Injection - PowerShell execution with tainted input",
                                      VulnCategory.COMMAND_INJECTION, Severity.CRITICAL, "HIGH", taint_var,
                                      "User-controlled data in PowerShell script enables arbitrary command execution.")
                elif re.search(r'\.AddScript\s*\(|\.AddCommand\s*\(', line):
                    self._add_finding(i, "Command Injection - PowerShell script execution",
                                      VulnCategory.COMMAND_INJECTION, Severity.HIGH, "MEDIUM",
                                      description="PowerShell execution detected. Verify script content is not user-controlled.")

            # Dynamic compilation via CSharpCodeProvider/Roslyn
            if re.search(r'CSharpCodeProvider|CompileAssemblyFromSource|CSharpCompilation|SyntaxFactory', line):
                is_tainted, taint_var = self._is_tainted(line)
                if is_tainted:
                    self._add_finding(i, "Code Injection - Dynamic C# compilation with tainted input",
                                      VulnCategory.CODE_INJECTION, Severity.CRITICAL, "HIGH", taint_var,
                                      "User-controlled code in dynamic compilation enables arbitrary code execution.")
                else:
                    self._add_finding(i, "Code Injection - Dynamic C# compilation",
                                      VulnCategory.CODE_INJECTION, Severity.HIGH, "MEDIUM",
                                      description="Dynamic C# compilation detected. Verify source code is not user-controlled.")

            # Assembly.Load with byte array (potentially encoded assembly)
            if re.search(r'Assembly\.Load\s*\(\s*(?:byte|Convert\.FromBase64)', line):
                is_tainted, taint_var = self._is_tainted(line)
                if is_tainted:
                    self._add_finding(i, "Code Injection - Assembly.Load with tainted bytes",
                                      VulnCategory.CODE_INJECTION, Severity.CRITICAL, "HIGH", taint_var,
                                      "Loading assembly from user-controlled bytes enables arbitrary code execution.")
                else:
                    self._add_finding(i, "Code Injection - Assembly.Load from bytes",
                                      VulnCategory.CODE_INJECTION, Severity.HIGH, "MEDIUM",
                                      description="Assembly loaded from byte array - potential for encoded malicious assembly.")

            # Expression trees with user input
            if re.search(r'Expression\.Lambda|Expression\.Compile|DynamicExpression', line):
                is_tainted, taint_var = self._is_tainted(line)
                if is_tainted:
                    self._add_finding(i, "Code Injection - Expression tree with tainted input",
                                      VulnCategory.CODE_INJECTION, Severity.HIGH, "HIGH", taint_var,
                                      "User-controlled data in expression tree compilation enables code injection.")

            # Activator.CreateInstance with tainted type name
            if re.search(r'Activator\.CreateInstance\s*\(', line):
                is_tainted, taint_var = self._is_tainted(line)
                if is_tainted:
                    self._add_finding(i, "Code Injection - Activator.CreateInstance with tainted type",
                                      VulnCategory.CODE_INJECTION, Severity.CRITICAL, "HIGH", taint_var,
                                      "User-controlled type name in Activator.CreateInstance enables arbitrary object instantiation.")

            # Deserialization with user-controlled type: Type.GetType(var) -> XmlSerializer
            if re.search(r'Type\.GetType\s*\(', line):
                # Check if the argument is NOT a string literal (i.e., it's a variable = user-controlled)
                type_arg = re.search(r'Type\.GetType\s*\(\s*(\w+)\s*\)', line)
                if type_arg:
                    arg_name = type_arg.group(1)
                    # Check if arg comes from user input (XML attribute, request param, etc.)
                    back_context = '\n'.join(self.source_lines[max(0, i - 10):i])
                    if re.search(rf'\b{re.escape(arg_name)}\b\s*=\s*.*(?:GetAttribute|Request|params|Query|Body|Form|Headers|Cookies|\.Value)', back_context):
                        fwd_context = '\n'.join(self.source_lines[i - 1:min(len(self.source_lines), i + 5)])
                        if re.search(r'XmlSerializer|Deserialize|Activator\.CreateInstance|JsonConvert', fwd_context):
                            self._add_finding(i, "Deserialization - User-controlled type in Type.GetType",
                                              VulnCategory.DESERIALIZATION, Severity.CRITICAL, "HIGH",
                                              description="Type.GetType() with user-controlled type name enables "
                                              "deserialization of arbitrary types, potentially leading to RCE.")

    def _check_xxe(self):
        for i, line in enumerate(self.source_lines, 1):
            if line.strip().startswith('//'):
                continue

            # Standard XML parser XXE
            if re.search(r'XmlDocument|XmlReader|XmlTextReader', line):
                context = '\n'.join(self.source_lines[i:min(len(self.source_lines), i+10)])
                has_secure = re.search(r'DtdProcessing\s*=\s*DtdProcessing\.Prohibit|XmlResolver\s*=\s*null', context)
                if not has_secure:
                    self._add_finding(i, "XXE - XML parser without secure configuration",
                                      VulnCategory.XXE, Severity.HIGH, "MEDIUM",
                                      description="XML parser should disable DTD processing.")

            # XSLT-based XXE (XslCompiledTransform) - "Stealth" XXE
            if re.search(r'XslCompiledTransform|XsltSettings', line):
                context = '\n'.join(self.source_lines[max(0, i-5):min(len(self.source_lines), i+10)])

                # Check for XsltSettings with enableDocumentFunction=true
                # XsltSettings(true, ...) or XsltSettings.TrustedXslt
                dangerous_settings = re.search(
                    r'XsltSettings\s*\(\s*true|XsltSettings\.TrustedXslt',
                    context
                )

                # Check for XmlUrlResolver passed to Load()
                has_resolver = re.search(
                    r'\.Load\s*\([^)]*(?:new\s+XmlUrlResolver|XmlUrlResolver)',
                    context
                )

                is_tainted, taint_var = self._is_tainted(context)

                if dangerous_settings and has_resolver:
                    self._add_finding(i, "XXE - XslCompiledTransform with document() and XmlUrlResolver",
                                      VulnCategory.XXE, Severity.CRITICAL, "HIGH", taint_var,
                                      "XSLT transformation enables document() function with XmlUrlResolver. "
                                      "Attacker-controlled XSLT can read arbitrary files via XXE.")
                elif dangerous_settings:
                    self._add_finding(i, "XXE - XsltSettings enables document() function",
                                      VulnCategory.XXE, Severity.HIGH, "HIGH",
                                      description="XsltSettings(true, ...) enables document() which can load external resources. "
                                      "If XSLT source is attacker-controlled, this enables XXE.")
                elif has_resolver:
                    self._add_finding(i, "XXE - XslCompiledTransform with XmlUrlResolver",
                                      VulnCategory.XXE, Severity.HIGH, "MEDIUM",
                                      description="XSLT Load() uses XmlUrlResolver which allows external entity resolution.")

            # XmlUrlResolver with explicit DTD enabling
            if re.search(r'XmlUrlResolver', line) and not re.search(r'XslCompiledTransform|XsltSettings', line):
                context = '\n'.join(self.source_lines[max(0, i-5):min(len(self.source_lines), i+5)])
                if re.search(r'XmlDocument|XmlReader|LoadXml|XmlResolver\s*=', context):
                    self._add_finding(i, "XXE - XmlUrlResolver enables external entity resolution",
                                      VulnCategory.XXE, Severity.HIGH, "MEDIUM",
                                      description="XmlUrlResolver allows loading external entities. Use null resolver or restrict.")

    def _check_ldap_injection(self):
        for i, line in enumerate(self.source_lines, 1):
            if line.strip().startswith('//'):
                continue

            if re.search(r'DirectorySearcher|\.Filter\s*=', line):
                # === Skip static LDAP filters (hardcoded strings) ===
                # Safe: new DirectorySearcher("(&(objectClass=user)(active=TRUE))")
                # Safe: searcher.Filter = "(&(objectClass=user)(active=TRUE))"
                is_static_filter = re.search(r'DirectorySearcher\s*\(\s*"[^"$]*"\s*\)', line)
                is_static_assignment = re.search(r'\.Filter\s*=\s*"[^"$]*"\s*;', line)
                if is_static_filter or is_static_assignment:
                    continue  # SAFE - static LDAP filter

                is_tainted, taint_var = self._is_tainted(line)
                # Also check for string concatenation or interpolation
                has_concat = '+' in line or '$"' in line or 'string.Format' in line.lower()

                if is_tainted and has_concat:
                    self._add_finding(i, "LDAP Injection - Filter with tainted data",
                                      VulnCategory.LDAP_INJECTION, Severity.HIGH, "HIGH", taint_var,
                                      "User input in LDAP filter.")

    def _check_xpath_injection(self):
        """Detect XPath injection vulnerabilities."""
        xpath_sinks = [
            r'\.Evaluate\s*\(', r'\.Select\s*\(', r'\.SelectNodes\s*\(',
            r'\.SelectSingleNode\s*\(', r'XPathExpression\.Compile\s*\(',
            r'\.Compile\s*\(',  # XPath compile
        ]

        for i, line in enumerate(self.source_lines, 1):
            if line.strip().startswith('//'):
                continue

            # Check for XPath navigator/document usage
            if re.search(r'XPathNavigator|XPathDocument|XmlDocument', line):
                context = '\n'.join(self.source_lines[i:min(len(self.source_lines), i+10)])
                for sink in xpath_sinks:
                    if re.search(sink, context):
                        # Check if query built with concatenation or tainted data
                        is_tainted, taint_var = self._is_tainted(context)
                        has_concat = '+' in context or '$"' in context or 'string.Format' in context.lower()

                        if is_tainted and has_concat:
                            # Find the actual sink line
                            for j, ctx_line in enumerate(self.source_lines[i-1:min(len(self.source_lines), i+10)], i):
                                if re.search(sink, ctx_line):
                                    self._add_finding(j, "XPath Injection - Query with concatenated user input",
                                                      VulnCategory.XPATH_INJECTION, Severity.CRITICAL, "HIGH", taint_var,
                                                      "User input concatenated into XPath query. Use parameterized XPath.")
                                    break
                            break

            # Direct sink detection
            for sink in xpath_sinks:
                if re.search(sink, line):
                    # === CRITICAL: Skip static XPath queries (string literals) ===
                    # Pattern: .SelectNodes("literal string") - no interpolation
                    # Safe: doc.SelectNodes("//user[@active='true']")
                    # Unsafe: doc.SelectNodes($"//user[@name='{name}']")
                    is_static_string = re.search(sink + r'\s*\(\s*"[^"$]*"\s*\)', line)
                    is_static_verbatim = re.search(sink + r'\s*\(\s*@"[^"]*"\s*\)', line)
                    if is_static_string or is_static_verbatim:
                        continue  # SAFE - static XPath query

                    is_tainted, taint_var = self._is_tainted(line)
                    # Check context for concatenation (only on the current line's argument)
                    has_concat = '+' in line or '$"' in line

                    if is_tainted and has_concat:
                        self._add_finding(i, "XPath Injection - Evaluate with tainted data",
                                          VulnCategory.XPATH_INJECTION, Severity.HIGH, "HIGH", taint_var,
                                          "User input in XPath query.")
                    elif is_tainted:
                        # Tainted but no obvious concatenation on this line - check context
                        context = '\n'.join(self.source_lines[max(0, i-5):i+1])
                        has_context_concat = '+' in context or '$"' in context
                        if has_context_concat:
                            self._add_finding(i, "XPath Injection - Evaluate with tainted data",
                                              VulnCategory.XPATH_INJECTION, Severity.HIGH, "HIGH", taint_var,
                                              "User input in XPath query.")

            # 2nd-Order XPath injection: Entity-sourced values
            for sink in xpath_sinks:
                if re.search(sink, line):
                    is_db, db_var, source = self._is_db_sourced(line)
                    if is_db:
                        self._add_finding(
                            i, "2nd-Order XPath Injection - Entity value in XPath",
                            VulnCategory.XPATH_INJECTION, Severity.CRITICAL, "HIGH", db_var,
                            f"Entity value from {source} used in XPath query. "
                            "Payload can enumerate nodes or break out of XML tree logic."
                        )
                        break

                    # Check context for entity-sourced values
                    context = '\n'.join(self.source_lines[max(0, i-5):i+1])
                    is_db, db_var, source = self._is_db_sourced(context)
                    if is_db and ('+' in context or '$"' in context):
                        self._add_finding(
                            i, "2nd-Order XPath Injection - Entity value concatenated",
                            VulnCategory.XPATH_INJECTION, Severity.CRITICAL, "HIGH", db_var,
                            f"Entity value from {source} concatenated into XPath. "
                            "2nd-order injection via database-sourced value."
                        )
                        break

    def _check_ssti(self):
        """Detect Server-Side Template Injection vulnerabilities."""
        template_sinks = [
            # RazorEngine
            r'Engine\.Razor\.RunCompile\s*\(', r'Engine\.Razor\.Compile\s*\(',
            r'RazorEngine\.Razor\.Parse\s*\(', r'\.Parse\s*\([^)]*template',
            # Scriban
            r'Template\.Parse\s*\(', r'Template\.Render\s*\(',
            # Liquid
            r'Template\.ParseLiquid\s*\(',
            # Generic template patterns
            r'\.RenderTemplate\s*\(', r'\.CompileTemplate\s*\(',
        ]

        for i, line in enumerate(self.source_lines, 1):
            if line.strip().startswith('//'):
                continue

            for sink in template_sinks:
                if re.search(sink, line):
                    is_tainted, taint_var = self._is_tainted(line)

                    if is_tainted:
                        self._add_finding(i, "SSTI - Template compilation with user-controlled input",
                                          VulnCategory.SSTI, Severity.CRITICAL, "HIGH", taint_var,
                                          "User input used as template source. Attacker can execute arbitrary code.")
                    else:
                        # Check if first argument might be user-controlled
                        context = '\n'.join(self.source_lines[max(0, i-5):i+1])
                        for var in self.tainted_vars:
                            if re.search(rf'\b{re.escape(var)}\b', line):
                                self._add_finding(i, "SSTI - Template engine with user input",
                                                  VulnCategory.SSTI, Severity.CRITICAL, "HIGH", var,
                                                  "User-controlled template passed to template engine. RCE possible.")
                                break

    def _check_viewstate_vulnerabilities(self):
        """
        Detect ASP.NET ViewState security misconfigurations.

        ViewState is a mechanism to persist page state across postbacks. When improperly
        configured, it can lead to:
        1. Deserialization attacks (EnableViewStateMac = false)
        2. Information disclosure (ViewStateEncryptionMode = Never)

        These are global configuration risks regardless of where they appear in code.
        """
        for i, line in enumerate(self.source_lines, 1):
            if line.strip().startswith('//'):
                continue

            # Pattern 1: EnableViewStateMac = false (CRITICAL - Deserialization)
            # Can appear as: this.EnableViewStateMac = false; Page.EnableViewStateMac = false;
            # Or in Page directive: <%@ Page EnableViewStateMac="false" %>
            enablemac_match = re.search(
                r'EnableViewStateMac\s*=\s*(?:false|"false"|False|"False")',
                line, re.IGNORECASE
            )
            if enablemac_match:
                # Determine context (code-behind vs directive)
                is_directive = '<%@' in line or '<%@' in '\n'.join(self.source_lines[max(0, i-2):i])
                context_type = "Page directive" if is_directive else "Code assignment"

                self._add_finding(
                    i,
                    "Insecure Deserialization - ViewState MAC Disabled",
                    VulnCategory.DESERIALIZATION,
                    Severity.CRITICAL,
                    "HIGH",
                    description=f"{context_type}: EnableViewStateMac=false allows ViewState tampering. "
                    "Attackers can craft malicious ViewState payloads for RCE via deserialization gadgets "
                    "(e.g., ObjectDataProvider, TypeConfuseDelegate). This is exploitable with ysoserial.net."
                )

            # Pattern 2: ViewStateEncryptionMode = Never (HIGH - Auth/Information Disclosure)
            # Can appear as: ViewStateEncryptionMode = ViewStateEncryptionMode.Never
            # Or: Page.ViewStateEncryptionMode = ViewStateEncryptionMode.Never
            encryption_match = re.search(
                r'ViewStateEncryptionMode\s*=\s*(?:ViewStateEncryptionMode\.)?Never',
                line, re.IGNORECASE
            )
            if encryption_match:
                is_directive = '<%@' in line or '<%@' in '\n'.join(self.source_lines[max(0, i-2):i])
                context_type = "Page directive" if is_directive else "Code assignment"

                self._add_finding(
                    i,
                    "Authentication Bypass - ViewState Encryption Disabled",
                    VulnCategory.AUTH_BYPASS,
                    Severity.HIGH,
                    "HIGH",
                    description=f"{context_type}: ViewStateEncryptionMode=Never exposes ViewState contents. "
                    "Attackers can decode and read sensitive data stored in ViewState, potentially "
                    "bypassing authentication or extracting secrets."
                )

            # Pattern 3: ViewStateUserKey not set (when EnableViewState is used)
            # This enables CSRF attacks via ViewState
            if re.search(r'EnableViewState\s*=\s*(?:true|"true")', line, re.IGNORECASE):
                # Check if ViewStateUserKey is set in the file
                full_source = '\n'.join(self.source_lines)
                if not re.search(r'ViewStateUserKey\s*=', full_source, re.IGNORECASE):
                    self._add_finding(
                        i,
                        "CSRF via ViewState - ViewStateUserKey Not Set",
                        VulnCategory.AUTH_BYPASS,
                        Severity.MEDIUM,
                        "MEDIUM",
                        description="EnableViewState=true without ViewStateUserKey allows CSRF attacks. "
                        "Set ViewStateUserKey to Session.SessionID in Page_Init to prevent ViewState reuse."
                    )

            # Pattern 4: MachineKey validation/decryption in web.config style
            # <machineKey validation="None" /> or validationKey="AutoGenerate"
            if re.search(r'machineKey.*validation\s*=\s*["\']?None', line, re.IGNORECASE):
                self._add_finding(
                    i,
                    "Insecure Deserialization - MachineKey Validation Disabled",
                    VulnCategory.DESERIALIZATION,
                    Severity.CRITICAL,
                    "HIGH",
                    description="MachineKey validation=None disables ViewState integrity checks. "
                    "This allows arbitrary ViewState manipulation and deserialization attacks."
                )

            # Pattern 5: pages enableViewStateMac="false" in config
            if re.search(r'<pages[^>]*enableViewStateMac\s*=\s*["\']false["\']', line, re.IGNORECASE):
                self._add_finding(
                    i,
                    "Insecure Deserialization - Global ViewState MAC Disabled",
                    VulnCategory.DESERIALIZATION,
                    Severity.CRITICAL,
                    "HIGH",
                    description="Web.config disables ViewState MAC globally. All pages are vulnerable "
                    "to ViewState deserialization attacks. This is a server-wide RCE vector."
                )

    def _check_second_order_sqli(self):
        """Detect 2nd-order SQLi with Entity Framework entity-sourced values."""
        for i, line in enumerate(self.source_lines, 1):
            if line.strip().startswith('//'):
                continue

            # FromSqlRaw / FromSqlInterpolated with entity values (The "Auto-Mapper" pattern)
            if re.search(r'FromSqlRaw\s*\(\s*\$', line) or re.search(r'FromSqlInterpolated\s*\(', line):
                is_db, db_var, source = self._is_db_sourced(line)
                if is_db:
                    self._add_finding(
                        i, "2nd-Order SQLi - FromSqlRaw with entity value (Auto-Mapper pattern)",
                        VulnCategory.SQL_INJECTION, Severity.CRITICAL, "HIGH", db_var,
                        f"Entity property from {source} in FromSqlRaw. "
                        "Structural Hijack - payload can break out and set other columns (e.g., IsAdmin = true)."
                    )

            # ExecuteSqlRaw / ExecuteSqlRawAsync with entity values
            if re.search(r'ExecuteSqlRaw(?:Async)?\s*\(', line):
                is_db, db_var, source = self._is_db_sourced(line)
                if is_db:
                    self._add_finding(
                        i, "2nd-Order SQLi - ExecuteSqlRaw with entity value",
                        VulnCategory.SQL_INJECTION, Severity.CRITICAL, "HIGH", db_var,
                        f"Entity property from {source} in ExecuteSqlRaw. Stored payload executes."
                    )

            # Dynamic SQL building with entity properties
            if re.search(r'(?:UPDATE|DELETE|INSERT)\s', line, re.IGNORECASE):
                is_db, db_var, source = self._is_db_sourced(line)
                if is_db and ('$"' in line or '$@"' in line or re.search(r'\+\s*\w+\.', line)):
                    self._add_finding(
                        i, "2nd-Order SQLi - Dynamic SQL with entity property",
                        VulnCategory.SQL_INJECTION, Severity.CRITICAL, "HIGH", db_var,
                        f"Entity property from {source} in dynamic SQL. "
                        "Mass assignment via 2nd-order injection."
                    )

            # SqlCommand / SqlQuery with entity values
            if re.search(r'new\s+SqlCommand\s*\(|\.SqlQuery\s*\(', line):
                is_db, db_var, source = self._is_db_sourced(line)
                if is_db and ('$"' in line or '+' in line):
                    self._add_finding(
                        i, "2nd-Order SQLi - SqlCommand with entity value",
                        VulnCategory.SQL_INJECTION, Severity.CRITICAL, "HIGH", db_var,
                        f"Entity property from {source} in SqlCommand."
                    )

class ASPNetConfigAnalyzer:
    """
    ASP.NET web.config analyzer for security misconfigurations.
    Detects global settings that affect application security.
    """

    def __init__(self, source_code: str, file_path: str):
        self.source_code = source_code
        self.source_lines = source_code.splitlines()
        self.file_path = file_path
        self.findings: List[Finding] = []

    def get_line_content(self, lineno: int) -> str:
        if 1 <= lineno <= len(self.source_lines):
            return self.source_lines[lineno - 1]
        return ""

    def analyze(self) -> List[Finding]:
        self._check_viewstate_settings()
        self._check_authentication_settings()
        self._check_debug_settings()
        self._check_request_validation()
        self._check_session_settings()
        self._check_custom_errors()
        return self.findings

    def _add_finding(self, line_num: int, vuln_name: str, category: VulnCategory,
                     severity: Severity, confidence: str, description: str = ""):
        self.findings.append(Finding(
            file_path=self.file_path, line_number=line_num, col_offset=0,
            line_content=self.get_line_content(line_num),
            vulnerability_name=vuln_name, category=category,
            severity=severity, confidence=confidence,
            taint_chain=[], description=description,
        ))

    def _check_viewstate_settings(self):
        """Check for ViewState security misconfigurations."""
        for i, line in enumerate(self.source_lines, 1):
            # CRITICAL: enableViewStateMac="false"
            if re.search(r'enableViewStateMac\s*=\s*["\']false["\']', line, re.IGNORECASE):
                self._add_finding(
                    i, "Insecure Deserialization - Global ViewState MAC Disabled",
                    VulnCategory.DESERIALIZATION, Severity.CRITICAL, "HIGH",
                    "web.config disables ViewState MAC globally. ALL pages vulnerable to "
                    "deserialization attacks via ysoserial.net gadgets (ObjectDataProvider, TypeConfuseDelegate)."
                )

            # HIGH: viewStateEncryptionMode="Never"
            if re.search(r'viewStateEncryptionMode\s*=\s*["\']Never["\']', line, re.IGNORECASE):
                self._add_finding(
                    i, "Authentication Bypass - Global ViewState Encryption Disabled",
                    VulnCategory.AUTH_BYPASS, Severity.HIGH, "HIGH",
                    "web.config disables ViewState encryption globally. Sensitive data in ViewState is exposed."
                )

            # CRITICAL: machineKey validation="None"
            if re.search(r'<machineKey[^>]*validation\s*=\s*["\']None["\']', line, re.IGNORECASE):
                self._add_finding(
                    i, "Insecure Deserialization - MachineKey Validation Disabled",
                    VulnCategory.DESERIALIZATION, Severity.CRITICAL, "HIGH",
                    "MachineKey validation=None disables ALL cryptographic validation. "
                    "ViewState, Forms Auth tickets, and other tokens can be forged."
                )

            # HIGH: machineKey with weak validation (MD5/SHA1 without HMAC)
            if re.search(r'<machineKey[^>]*validation\s*=\s*["\'](MD5|SHA1)["\']', line, re.IGNORECASE):
                match = re.search(r'validation\s*=\s*["\'](MD5|SHA1)["\']', line, re.IGNORECASE)
                self._add_finding(
                    i, f"Weak Cryptography - MachineKey uses {match.group(1)}",
                    VulnCategory.AUTH_BYPASS, Severity.MEDIUM, "HIGH",
                    f"MachineKey validation={match.group(1)} uses weak algorithm. Use HMACSHA256 or higher."
                )

    def _check_authentication_settings(self):
        """Check for authentication security misconfigurations."""
        for i, line in enumerate(self.source_lines, 1):
            # HIGH: Forms auth protection="None"
            if re.search(r'<forms[^>]*protection\s*=\s*["\']None["\']', line, re.IGNORECASE):
                self._add_finding(
                    i, "Authentication Bypass - Forms Auth Protection Disabled",
                    VulnCategory.AUTH_BYPASS, Severity.CRITICAL, "HIGH",
                    "Forms authentication protection=None disables ticket encryption AND validation. "
                    "Attackers can forge authentication tickets."
                )

            # HIGH: requireSSL="false" on forms auth
            if re.search(r'<forms[^>]*requireSSL\s*=\s*["\']false["\']', line, re.IGNORECASE):
                self._add_finding(
                    i, "Authentication Bypass - Forms Auth Cookies Over HTTP",
                    VulnCategory.AUTH_BYPASS, Severity.HIGH, "HIGH",
                    "Forms authentication cookies sent over HTTP. Vulnerable to session hijacking via MITM."
                )

            # HIGH: cookieless="UseUri" or "true" enables session fixation
            if re.search(r'<forms[^>]*cookieless\s*=\s*["\'](UseUri|true)["\']', line, re.IGNORECASE):
                self._add_finding(
                    i, "Session Fixation - Cookieless Forms Authentication",
                    VulnCategory.AUTH_BYPASS, Severity.HIGH, "HIGH",
                    "Cookieless auth embeds session in URL. Enables session fixation and leakage via Referer."
                )

    def _check_debug_settings(self):
        """Check for debug mode in production."""
        for i, line in enumerate(self.source_lines, 1):
            # HIGH: compilation debug="true"
            if re.search(r'<compilation[^>]*debug\s*=\s*["\']true["\']', line, re.IGNORECASE):
                self._add_finding(
                    i, "Information Disclosure - Debug Mode Enabled",
                    VulnCategory.INFO_DISCLOSURE, Severity.HIGH, "HIGH",
                    "Debug mode exposes detailed error messages, stack traces, and compilation info. "
                    "Disable in production: debug=\"false\""
                )

            # HIGH: trace enabled
            if re.search(r'<trace[^>]*enabled\s*=\s*["\']true["\']', line, re.IGNORECASE):
                self._add_finding(
                    i, "Information Disclosure - Trace Enabled",
                    VulnCategory.INFO_DISCLOSURE, Severity.HIGH, "HIGH",
                    "ASP.NET trace exposes request details, session data, and application variables."
                )

    def _check_session_settings(self):
        """Check for session security misconfigurations."""
        for i, line in enumerate(self.source_lines, 1):
            # HIGH: cookieless sessions
            if re.search(r'<sessionState[^>]*cookieless\s*=\s*["\'](true|UseUri)["\']', line, re.IGNORECASE):
                self._add_finding(
                    i, "Session Fixation - Cookieless Sessions",
                    VulnCategory.AUTH_BYPASS, Severity.HIGH, "HIGH",
                    "Cookieless sessions embed session ID in URL. Vulnerable to session fixation and leakage."
                )

            # MEDIUM: session timeout too long
            timeout_match = re.search(r'<sessionState[^>]*timeout\s*=\s*["\'](\d+)["\']', line, re.IGNORECASE)
            if timeout_match:
                timeout = int(timeout_match.group(1))
                if timeout > 60:
                    self._add_finding(
                        i, "Session Security - Long Session Timeout",
                        VulnCategory.AUTH_BYPASS, Severity.LOW, "MEDIUM",
                        f"Session timeout of {timeout} minutes is excessive. Consider 20-30 minutes for sensitive apps."
                    )

    def _check_custom_errors(self):
        """Check for custom errors configuration."""
        for i, line in enumerate(self.source_lines, 1):
            # HIGH: customErrors mode="Off"
            if re.search(r'<customErrors[^>]*mode\s*=\s*["\']Off["\']', line, re.IGNORECASE):
                self._add_finding(
                    i, "Information Disclosure - Custom Errors Disabled",
                    VulnCategory.INFO_DISCLOSURE, Severity.HIGH, "HIGH",
                    "customErrors=Off exposes detailed error messages and stack traces to users. "
                    "Use mode=\"RemoteOnly\" or \"On\" in production."
                )

            # MEDIUM: directory browsing enabled
            if re.search(r'<directoryBrowse[^>]*enabled\s*=\s*["\']true["\']', line, re.IGNORECASE):
                self._add_finding(
                    i, "Information Disclosure - Directory Browsing Enabled",
                    VulnCategory.INFO_DISCLOSURE, Severity.MEDIUM, "HIGH",
                    "Directory browsing exposes file structure. Attackers can enumerate files and find sensitive data."
                )


class RubyAnalyzer:
    """
    Ruby analyzer with taint tracking for Rails and general Ruby vulnerabilities.
    Includes 2nd-order SQLi detection for:
    - Structural sinks: order(), reorder(), group()
    - Calculation sinks: sum(), count(), average(), minimum(), maximum()
    - Destructive sinks: delete_all(), destroy_all()
    """

    def __init__(self, source_code: str, file_path: str):
        self.source_code = source_code
        self.source_lines = source_code.splitlines()
        self.file_path = file_path
        self.findings: List[Finding] = []
        self.tainted_vars: Dict[str, int] = {}
        self.db_sourced_vars: Dict[str, Tuple[int, str]] = {}  # var -> (line, source_model)

        self._identify_taint_sources()
        self._track_variable_assignments()
        self._track_database_sources()

    def _identify_taint_sources(self):
        """Identify Rails params, request data, and method parameters."""
        taint_patterns = [
            r'\bparams\s*\[', r'\brequest\.', r'\bcookies\s*\[',
            r'\bsession\s*\[', r'\.query_parameters', r'\.request_parameters',
            r'ARGV', r'gets\b', r'STDIN\.',
        ]

        for i, line in enumerate(self.source_lines, 1):
            for pattern in taint_patterns:
                if re.search(pattern, line):
                    match = re.search(r'(\w+)\s*=', line)
                    if match:
                        self.tainted_vars[match.group(1)] = i

        # Method parameters
        for i, line in enumerate(self.source_lines, 1):
            match = re.search(r'def\s+\w+\s*\(([^)]+)\)', line)
            if match:
                params = match.group(1)
                for param in re.findall(r'(\w+)', params):
                    if param not in ['self']:
                        self.tainted_vars[param] = i

    def _track_variable_assignments(self):
        for i, line in enumerate(self.source_lines, 1):
            if line.strip().startswith('#'):
                continue
            match = re.search(r'(\w+)\s*=\s*(.+)', line)
            if match:
                var_name = match.group(1)
                rhs = match.group(2)
                for tainted in list(self.tainted_vars.keys()):
                    if re.search(rf'\b{re.escape(tainted)}\b', rhs):
                        self.tainted_vars[var_name] = i
                        break

    def _track_database_sources(self):
        """Track variables that get values from database (entity-sourced for 2nd-order SQLi)."""
        # ActiveRecord patterns that fetch from DB
        db_patterns = [
            (r'(\w+)\s*=\s*(\w+)\.find\s*\(', 'find'),
            (r'(\w+)\s*=\s*(\w+)\.find_by\s*\(', 'find_by'),
            (r'(\w+)\s*=\s*(\w+)\.first\b', 'first'),
            (r'(\w+)\s*=\s*(\w+)\.last\b', 'last'),
            (r'(\w+)\s*=\s*(\w+)\.where\s*\(.*\)\.first', 'where.first'),
            (r'(\w+)\s*=\s*(\w+)\.find_or_create_by\s*\(', 'find_or_create'),
            (r'(\w+)\s*=\s*(\w+)\.find_or_initialize_by\s*\(', 'find_or_init'),
        ]

        for i, line in enumerate(self.source_lines, 1):
            if line.strip().startswith('#'):
                continue
            for pattern, source_type in db_patterns:
                match = re.search(pattern, line)
                if match:
                    var_name = match.group(1)
                    model_name = match.group(2)
                    self.db_sourced_vars[var_name] = (i, f"{model_name}.{source_type}")

        # Track attribute access on DB-sourced objects
        for i, line in enumerate(self.source_lines, 1):
            if line.strip().startswith('#'):
                continue
            for db_var in list(self.db_sourced_vars.keys()):
                # var = entity.attribute or var = entity[:attr]
                attr_pattern = rf'(\w+)\s*=\s*{re.escape(db_var)}\.(\w+)'
                match = re.search(attr_pattern, line)
                if match:
                    new_var = match.group(1)
                    attr_name = match.group(2)
                    orig_line, orig_source = self.db_sourced_vars[db_var]
                    self.db_sourced_vars[new_var] = (i, f"{orig_source}.{attr_name}")

                # Hash-style access: var = entity[:column]
                hash_pattern = rf'(\w+)\s*=\s*{re.escape(db_var)}\s*\[\s*[:\'\"](\w+)'
                match = re.search(hash_pattern, line)
                if match:
                    new_var = match.group(1)
                    attr_name = match.group(2)
                    orig_line, orig_source = self.db_sourced_vars[db_var]
                    self.db_sourced_vars[new_var] = (i, f"{orig_source}[{attr_name}]")

    def _is_db_sourced(self, line: str) -> Tuple[bool, Optional[str], Optional[str]]:
        """Check if line uses a database-sourced variable."""
        for var, (src_line, source) in self.db_sourced_vars.items():
            if re.search(rf'\b{re.escape(var)}\b', line):
                return True, var, source
        return False, None, None

    def _is_tainted(self, line: str) -> Tuple[bool, Optional[str]]:
        # Remove string literals to avoid matching variable names inside strings
        # Preserve #{...} interpolation inside double-quoted strings
        line_clean = re.sub(r"'[^'\\]*(?:\\.[^'\\]*)*'", "''", line)

        for var in self.tainted_vars:
            if re.search(rf'\b{re.escape(var)}\b', line_clean):
                return True, var
        if re.search(r'\bparams\s*\[', line_clean):
            return True, 'params'
        return False, None

    def get_line_content(self, lineno: int) -> str:
        if 1 <= lineno <= len(self.source_lines):
            return self.source_lines[lineno - 1]
        return ""

    def analyze(self) -> List[Finding]:
        self._check_sql_injection()
        self._check_command_injection()
        self._check_code_injection()
        self._check_deserialization()
        self._check_ssti()
        # 2nd-order SQL injection detection
        self._check_structural_sqli()
        self._check_calculation_sqli()
        self._check_destructive_sqli()
        return self.findings

    def _add_finding(self, line_num: int, vuln_name: str, category: VulnCategory,
                     severity: Severity, confidence: str, taint_var: Optional[str] = None,
                     description: str = ""):
        taint_chain = []
        if taint_var and taint_var in self.tainted_vars:
            taint_chain = [f"tainted: {taint_var} (line {self.tainted_vars[taint_var]})"]
        elif taint_var:
            taint_chain = [f"tainted: {taint_var}"]

        self.findings.append(Finding(
            file_path=self.file_path, line_number=line_num, col_offset=0,
            line_content=self.get_line_content(line_num),
            vulnerability_name=vuln_name, category=category,
            severity=severity, confidence=confidence,
            taint_chain=taint_chain, description=description,
        ))

    def _check_sql_injection(self):
        sql_patterns = [
            r'\.where\s*\(["\']', r'\.find_by_sql\s*\(',
            r'\.execute\s*\(', r'\.select\s*\(["\']',
            r'\.joins\s*\(["\']', r'\.order\s*\(["\']',
        ]

        for i, line in enumerate(self.source_lines, 1):
            if line.strip().startswith('#'):
                continue

            for pattern in sql_patterns:
                if re.search(pattern, line):
                    is_tainted, taint_var = self._is_tainted(line)
                    has_interp = '#{' in line

                    if is_tainted or has_interp:
                        if is_tainted:
                            self._add_finding(i, "SQL Injection - ActiveRecord with tainted data",
                                              VulnCategory.SQL_INJECTION, Severity.CRITICAL, "HIGH", taint_var,
                                              "User input in SQL query.")
                        elif has_interp:
                            self._add_finding(i, "SQL Injection - String interpolation in query",
                                              VulnCategory.SQL_INJECTION, Severity.HIGH, "MEDIUM",
                                              description="String interpolation in SQL. Use parameterized queries.")

            # Arel.sql() - commonly misused for ORDER BY injection
            if re.search(r'Arel\.sql\s*\(', line):
                is_tainted, taint_var = self._is_tainted(line)
                has_interp = '#{' in line

                # Check if only direction is validated (common mistake)
                # Pattern: sort_direction validated but sort_key/sort_column is not
                has_partial_validation = False
                context_start = max(0, i - 5)
                context_lines = self.source_lines[context_start:i]
                context = '\n'.join(context_lines)

                # Check for direction validation without column validation
                if re.search(r'(?:asc|desc|ASC|DESC)["\'\]]', context):
                    if re.search(r'(?:sort_key|sort_column|column|field|order_by)', line):
                        # Direction validated, but column might not be
                        if not re.search(r'(?:ALLOWED|VALID|SAFE|PERMITTED|include\?)', context):
                            has_partial_validation = True

                if has_interp:
                    self._add_finding(i, "SQL Injection - Arel.sql() with string interpolation",
                                      VulnCategory.SQL_INJECTION, Severity.CRITICAL, "HIGH", taint_var,
                                      "Arel.sql() with interpolation allows SQL injection. Whitelist column names.")
                elif is_tainted:
                    self._add_finding(i, "SQL Injection - Arel.sql() with tainted input",
                                      VulnCategory.SQL_INJECTION, Severity.CRITICAL, "HIGH", taint_var,
                                      "User input passed to Arel.sql(). Whitelist allowed values.")
                elif has_partial_validation:
                    self._add_finding(i, "SQL Injection - Arel.sql() partial validation (direction only)",
                                      VulnCategory.SQL_INJECTION, Severity.HIGH, "HIGH",
                                      description="Direction validated but column/key may not be. Whitelist column names.")

    def _check_command_injection(self):
        cmd_patterns = [
            r'\bsystem\s*\(', r'\bexec\s*\(', r'\b`[^`]+`',
            r'%x\{', r'%x\[', r'IO\.popen\s*\(',
            r'Open3\.', r'Kernel\.system', r'Kernel\.exec',
        ]

        for i, line in enumerate(self.source_lines, 1):
            if line.strip().startswith('#'):
                continue

            for pattern in cmd_patterns:
                if re.search(pattern, line):
                    is_tainted, taint_var = self._is_tainted(line)
                    has_interp = '#{' in line

                    if is_tainted or has_interp:
                        self._add_finding(i, "Command Injection - Shell execution with tainted data",
                                          VulnCategory.COMMAND_INJECTION, Severity.CRITICAL, "HIGH", taint_var,
                                          "User input in shell command.")

            # Shell execution pattern with sh -c
            if re.search(r'(?:system|exec|IO\.popen|Open3\.)', line):
                context = '\n'.join(self.source_lines[i-1:min(len(self.source_lines), i+3)])
                if re.search(r'["\'](?:/bin/sh|/bin/bash|sh|bash)["\'].*["\'](?:-c)["\']', context):
                    is_tainted, taint_var = self._is_tainted(line)
                    if is_tainted:
                        self._add_finding(i, "Command Injection - Shell execution pattern with tainted input",
                                          VulnCategory.COMMAND_INJECTION, Severity.CRITICAL, "HIGH", taint_var,
                                          "Shell with -c flag executing user-controlled command.")
                    else:
                        self._add_finding(i, "Command Injection - Shell execution pattern",
                                          VulnCategory.COMMAND_INJECTION, Severity.HIGH, "HIGH",
                                          description="Shell with -c pattern detected.")

            # Dynamic method call via send with dangerous methods
            if re.search(r'\.send\s*\([^)]*(?:system|exec|eval)', line):
                is_tainted, taint_var = self._is_tainted(line)
                self._add_finding(i, "Code Injection - send() with dangerous method",
                                  VulnCategory.CODE_INJECTION, Severity.HIGH, "HIGH", taint_var,
                                  "Dynamic method invocation with dangerous method name.")

    def _check_code_injection(self):
        for i, line in enumerate(self.source_lines, 1):
            if line.strip().startswith('#'):
                continue

            if re.search(r'\beval\s*\(', line):
                is_tainted, taint_var = self._is_tainted(line)
                if is_tainted:
                    self._add_finding(i, "Code Injection - eval with tainted data",
                                      VulnCategory.CODE_INJECTION, Severity.CRITICAL, "HIGH", taint_var,
                                      "User input passed to eval().")

            if re.search(r'\.constantize\b|\.safe_constantize\b', line):
                is_tainted, taint_var = self._is_tainted(line)
                if is_tainted:
                    self._add_finding(i, "Code Injection - constantize with tainted data",
                                      VulnCategory.CODE_INJECTION, Severity.CRITICAL, "HIGH", taint_var,
                                      "User input in constantize can load arbitrary classes.")

            if re.search(r'\.send\s*\(|\.public_send\s*\(', line):
                is_tainted, taint_var = self._is_tainted(line)
                if is_tainted:
                    self._add_finding(i, "Code Injection - send with tainted method name",
                                      VulnCategory.CODE_INJECTION, Severity.HIGH, "MEDIUM", taint_var,
                                      "User-controlled method invocation.")

            # .try(params[:method]) — arbitrary method dispatch
            if re.search(r'\.try\s*\(\s*params\s*\[', line):
                self._add_finding(i, "Code Injection - try() with user-controlled method name",
                                  VulnCategory.CODE_INJECTION, Severity.HIGH, "HIGH",
                                  description="User-controlled method name passed to .try() allows "
                                  "arbitrary method invocation on the receiver.")

    def _check_deserialization(self):
        for i, line in enumerate(self.source_lines, 1):
            if line.strip().startswith('#'):
                continue

            if re.search(r'Marshal\.load\s*\(|YAML\.load\s*\(', line):
                is_tainted, taint_var = self._is_tainted(line)
                if is_tainted:
                    self._add_finding(i, "Insecure Deserialization - Marshal/YAML.load with tainted data",
                                      VulnCategory.DESERIALIZATION, Severity.CRITICAL, "HIGH", taint_var,
                                      "User input in deserialization can lead to RCE.")
                else:
                    self._add_finding(i, "Insecure Deserialization - Marshal/YAML.load usage",
                                      VulnCategory.DESERIALIZATION, Severity.HIGH, "MEDIUM",
                                      description="Marshal/YAML.load detected. Use YAML.safe_load instead.")

    def _check_ssti(self):
        for i, line in enumerate(self.source_lines, 1):
            if line.strip().startswith('#'):
                continue

            if re.search(r'ERB\.new\s*\(|render\s+inline:', line):
                is_tainted, taint_var = self._is_tainted(line)
                if is_tainted:
                    self._add_finding(i, "SSTI - ERB template with tainted data",
                                      VulnCategory.SSTI, Severity.CRITICAL, "HIGH", taint_var,
                                      "User input in ERB template.")

    def _check_structural_sqli(self):
        """Detect 2nd-order SQLi in structural sinks: order(), reorder(), group()."""
        structural_patterns = [
            (r'\.order\s*\(', 'order'),
            (r'\.reorder\s*\(', 'reorder'),
            (r'\.group\s*\(', 'group'),
        ]

        for i, line in enumerate(self.source_lines, 1):
            if line.strip().startswith('#'):
                continue

            for pattern, sink_type in structural_patterns:
                if re.search(pattern, line):
                    is_db, db_var, source = self._is_db_sourced(line)
                    if is_db:
                        self._add_finding(
                            i, f"2nd-Order SQLi - {sink_type}() with DB-sourced value",
                            VulnCategory.SQL_INJECTION, Severity.CRITICAL, "HIGH", db_var,
                            f"Entity value from {source} used in {sink_type}(). "
                            "Enables ORDER BY injection for boolean-based data exfiltration."
                        )

    def _check_calculation_sqli(self):
        """Detect 2nd-order SQLi in calculation sinks: sum(), count(), average(), etc."""
        calc_patterns = [
            (r'\.sum\s*\(', 'sum'),
            (r'\.count\s*\(', 'count'),
            (r'\.average\s*\(', 'average'),
            (r'\.minimum\s*\(', 'minimum'),
            (r'\.maximum\s*\(', 'maximum'),
            (r'\.calculate\s*\(', 'calculate'),
            (r'\.pluck\s*\(', 'pluck'),
        ]

        for i, line in enumerate(self.source_lines, 1):
            if line.strip().startswith('#'):
                continue

            for pattern, sink_type in calc_patterns:
                if re.search(pattern, line):
                    is_db, db_var, source = self._is_db_sourced(line)
                    if is_db:
                        self._add_finding(
                            i, f"2nd-Order SQLi - {sink_type}() with DB-sourced column",
                            VulnCategory.SQL_INJECTION, Severity.CRITICAL, "HIGH", db_var,
                            f"Entity value from {source} used as column in {sink_type}(). "
                            "Allows arbitrary SQL fragment injection via column name."
                        )

    def _check_destructive_sqli(self):
        """Detect 2nd-order SQLi in destructive sinks: delete_all(), destroy_all(), update_all()."""
        destructive_patterns = [
            (r'\.delete_all\s*\(', 'delete_all'),
            (r'\.destroy_all\s*\(', 'destroy_all'),
            (r'\.update_all\s*\(', 'update_all'),
        ]

        for i, line in enumerate(self.source_lines, 1):
            if line.strip().startswith('#'):
                continue

            for pattern, sink_type in destructive_patterns:
                if re.search(pattern, line):
                    is_db, db_var, source = self._is_db_sourced(line)
                    if is_db:
                        self._add_finding(
                            i, f"2nd-Order SQLi - {sink_type}() with DB-sourced condition",
                            VulnCategory.SQL_INJECTION, Severity.CRITICAL, "HIGH", db_var,
                            f"Entity value from {source} used in {sink_type}(). "
                            "Payload like '1 OR 1=1' can wipe entire table."
                        )

                    # Also check for string interpolation with any variable
                    if '#{' in line:
                        self._add_finding(
                            i, f"SQLi - {sink_type}() with string interpolation",
                            VulnCategory.SQL_INJECTION, Severity.HIGH, "MEDIUM",
                            description=f"String interpolation in {sink_type}() condition. "
                            "Use parameterized queries or sanitize input."
                        )

class ASTScanner:
    """Main scanner class that orchestrates AST-based analysis."""

    SUPPORTED_EXTENSIONS = {
        '.py': 'python',
        '.js': 'javascript',
        '.ts': 'typescript',
        '.jsx': 'javascript',
        '.tsx': 'typescript',
        '.mjs': 'javascript',
        '.java': 'java',
        '.kt': 'kotlin',
        '.scala': 'scala',
        '.php': 'php',
        '.php3': 'php',
        '.php4': 'php',
        '.php5': 'php',
        '.phtml': 'php',
        '.cs': 'csharp',
        '.config': 'aspnet_config',
        '.aspx': 'csharp',
        '.ascx': 'csharp',
        '.rb': 'ruby',
        '.erb': 'ruby',
    }

    # Directories to exclude by default
    DEFAULT_EXCLUDES = {
        'node_modules', '.git', '__pycache__', 'venv', 'env', '.venv',
        'vendor', 'dist', 'build', '.tox', '.pytest_cache', 'site-packages',
        '.eggs', '*.egg-info', 'htmlcov', '.mypy_cache', 'bower_components',
        'jspm_packages', '.nuget', 'packages', 'lib', 'libs', 'third_party',
        'third-party', 'external', 'externals', '.bundle', 'Pods',
    }

    # File patterns to exclude (minified, vendor libraries, etc.)
    DEFAULT_FILE_EXCLUDES = {
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

    def __init__(self, verbose: bool = False, scan_all: bool = False, config: VibehunterConfig = None):
        self.verbose = verbose
        self.scan_all = scan_all
        self.config = config
        self.all_findings: List[Finding] = []
        self.files_scanned = 0
        self.parse_errors = 0
        self.scan_start_time = 0.0
        self.scan_elapsed = 0.0

    def log(self, message: str):
        """Print verbose logging."""
        if self.verbose:
            console.print(f"[dim][*] {message}[/dim]")

    def should_scan_file(self, file_path: Path) -> bool:
        """Check if file should be scanned."""
        # Check extension
        if file_path.suffix.lower() not in self.SUPPORTED_EXTENSIONS:
            return False

        # If scan_all is enabled, skip exclusion checks
        if self.scan_all:
            return True

        # Check directory exclusions
        parts = file_path.parts
        for exclude in self.DEFAULT_EXCLUDES:
            if any(exclude.replace('*', '') in part for part in parts):
                return False

        # Check file pattern exclusions (minified, vendor libraries)
        filename_lower = file_path.name.lower()
        for pattern in self.DEFAULT_FILE_EXCLUDES:
            if pattern in filename_lower:
                self.log(f"Skipping vendor/minified file: {file_path.name}")
                return False

        return True

    def scan_file(self, file_path: Path) -> List[Finding]:
        """Scan a single file."""
        findings = []

        if self.config and self.config.should_exclude(str(file_path)):
            return findings

        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                source_code = f.read()
        except (IOError, OSError) as e:
            self.log(f"Error reading {file_path}: {e}")
            return findings

        ext = file_path.suffix.lower()
        lang = self.SUPPORTED_EXTENSIONS.get(ext)

        self.log(f"Scanning {file_path} ({lang})")

        try:
            if lang == 'python':
                findings = self._scan_python(source_code, str(file_path))
            elif lang in ('javascript', 'typescript'):
                findings = self._scan_javascript(source_code, str(file_path))
            elif lang in ('java', 'kotlin', 'scala'):
                findings = self._scan_java(source_code, str(file_path))
            elif lang == 'php':
                findings = self._scan_php(source_code, str(file_path))
            elif lang == 'csharp':
                findings = self._scan_csharp(source_code, str(file_path))
            elif lang == 'aspnet_config':
                findings = self._scan_aspnet_config(source_code, str(file_path))
            elif lang == 'ruby':
                findings = self._scan_ruby(source_code, str(file_path))
        except Exception as e:
            self.log(f"Error scanning {file_path}: {e}")
            self.parse_errors += 1

        self.files_scanned += 1
        return findings

    def _scan_python(self, source_code: str, file_path: str) -> List[Finding]:
        """Scan Python source code."""
        try:
            tree = ast.parse(source_code)
        except SyntaxError as e:
            self.log(f"Syntax error in {file_path}: {e}")
            self.parse_errors += 1
            return []

        tracker = PythonTaintTracker(source_code, file_path)
        tracker.visit(tree)
        tracker._check_evasion_patterns()  # Run evasion detection after AST visit

        # 2nd-order detection for pandas df.query()/eval() with DB-sourced values
        tracker._track_database_sources()
        tracker._check_pandas_query_injection()

        return self._filter_findings(tracker.findings)

    def _scan_javascript(self, source_code: str, file_path: str) -> List[Finding]:
        """Scan JavaScript/TypeScript source code."""
        analyzer = JavaScriptAnalyzer(source_code, file_path)
        findings = analyzer.analyze()
        return self._filter_findings(findings)

    def _scan_java(self, source_code: str, file_path: str) -> List[Finding]:
        """Scan Java/Kotlin/Scala source code."""
        analyzer = JavaAnalyzer(source_code, file_path)
        findings = analyzer.analyze()
        return self._filter_findings(findings)

    def _scan_php(self, source_code: str, file_path: str) -> List[Finding]:
        """Scan PHP source code."""
        analyzer = PHPAnalyzer(source_code, file_path)
        findings = analyzer.analyze()
        return self._filter_findings(findings)

    def _scan_csharp(self, source_code: str, file_path: str) -> List[Finding]:
        """Scan C# source code."""
        analyzer = CSharpAnalyzer(source_code, file_path)
        findings = analyzer.analyze()
        return self._filter_findings(findings)

    def _scan_aspnet_config(self, source_code: str, file_path: str) -> List[Finding]:
        """Scan ASP.NET web.config files."""
        analyzer = ASPNetConfigAnalyzer(source_code, file_path)
        findings = analyzer.analyze()
        return self._filter_findings(findings)

    def _scan_ruby(self, source_code: str, file_path: str) -> List[Finding]:
        """Scan Ruby source code."""
        analyzer = RubyAnalyzer(source_code, file_path)
        findings = analyzer.analyze()
        return self._filter_findings(findings)

    def _filter_findings(self, findings: List[Finding]) -> List[Finding]:
        """Filter findings by category if specified, deduplicate, and apply nosec suppression."""
        severity_order = {Severity.CRITICAL: 4, Severity.HIGH: 3, Severity.MEDIUM: 2, Severity.LOW: 1, Severity.INFO: 0}
        conf_order = {'HIGH': 3, 'MEDIUM': 2, 'LOW': 1}

        best_findings: Dict[Tuple[str, int, VulnCategory], Finding] = {}
        for f in findings:
            # Inline suppression: skip findings where source line contains nosec/vibehunter:ignore
            if re.search(r'(?://|#|/\*|--|%)\s*nosec\b', f.line_content) or \
               re.search(r'vibehunter:ignore', f.line_content):
                continue

            key = (f.file_path, f.line_number, f.category)
            if key not in best_findings:
                best_findings[key] = f
            else:
                existing = best_findings[key]
                existing_score = (severity_order.get(existing.severity, 0), conf_order.get(existing.confidence, 0))
                new_score = (severity_order.get(f.severity, 0), conf_order.get(f.confidence, 0))
                if new_score > existing_score:
                    best_findings[key] = f

        return list(best_findings.values())

    def _collect_scannable_files(self, directory: Path) -> List[Path]:
        """Collect all files that should be scanned from a directory."""
        scannable = []
        for root, dirs, files in os.walk(directory):
            if not self.scan_all:
                dirs[:] = [d for d in dirs if d not in self.DEFAULT_EXCLUDES]
            for file in files:
                file_path = Path(root) / file
                if self.should_scan_file(file_path):
                    scannable.append(file_path)
        return scannable

    def scan_directory(self, directory: Path) -> List[Finding]:
        """Recursively scan a directory with progress display."""
        findings = []
        scannable_files = self._collect_scannable_files(directory)

        if not scannable_files:
            return findings

        with Progress(
            SpinnerColumn("moon"),
            TextColumn("[bold cyan]{task.description}"),
            BarColumn(bar_width=30, style="cyan", complete_style="green"),
            MofNCompleteColumn(),
            TextColumn("[dim]{task.fields[current_file]}[/dim]"),
            console=console,
            transient=True,
        ) as progress:
            task = progress.add_task(
                "Scanning", total=len(scannable_files), current_file=""
            )
            for file_path in scannable_files:
                progress.update(task, current_file=file_path.name)
                file_findings = self.scan_file(file_path)
                findings.extend(file_findings)
                progress.advance(task)

        return findings

    def scan(self, target: str) -> List[Finding]:
        """Scan a file or directory."""
        target_path = Path(target)

        if not target_path.exists():
            console.print(f"[bold red]Error:[/bold red] {target} does not exist")
            return []

        self.scan_start_time = time.time()

        if target_path.is_file():
            with Progress(
                SpinnerColumn("moon"),
                TextColumn("[bold cyan]Parsing AST...[/bold cyan]"),
                TextColumn("[dim]{task.fields[file]}[/dim]"),
                console=console,
                transient=True,
            ) as progress:
                task = progress.add_task("Scanning", total=1, file=target_path.name)
                findings = self.scan_file(target_path)
                progress.advance(task)
        else:
            findings = self.scan_directory(target_path)

        self.scan_elapsed = time.time() - self.scan_start_time
        self.all_findings = findings
        return findings

    def print_report(self, output_format: str = 'text', output_file: Optional[str] = None):
        """Print the scan report."""
        if output_format == 'json':
            report = {
                'scan_date': datetime.now().isoformat(),
                'files_scanned': self.files_scanned,
                'parse_errors': self.parse_errors,
                'total_findings': len(self.all_findings),
                'findings': [f.to_dict() for f in self.all_findings],
                'summary': self._get_summary(),
            }
            output = json.dumps(report, indent=2)
        else:
            output = self._format_text_report()

        if output_file:
            with open(output_file, 'w', encoding='utf-8') as f:
                f.write(output)
            console.print(f"\n[bold green]Report saved to {output_file}[/bold green]")
        else:
            print(output)

    def _get_summary(self) -> dict:
        """Get findings summary."""
        summary = {
            'by_severity': defaultdict(int),
            'by_category': defaultdict(int),
            'by_confidence': defaultdict(int),
        }

        for f in self.all_findings:
            summary['by_severity'][f.severity.value] += 1
            summary['by_category'][f.category.value] += 1
            summary['by_confidence'][f.confidence] += 1

        return dict(summary)

    def _format_text_report(self) -> str:
        """Format findings as text report."""
        lines = []

        lines.append("=" * 80)
        lines.append("AST-BASED VULNERABILITY SCAN REPORT")
        lines.append("=" * 80)
        lines.append(f"Scan Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        lines.append(f"Files Scanned: {self.files_scanned}")
        lines.append(f"Parse Errors: {self.parse_errors}")
        lines.append(f"Total Findings: {len(self.all_findings)}")
        lines.append("")

        # Summary by severity
        summary = self._get_summary()
        lines.append("Summary by Severity:")
        for sev in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO']:
            count = summary['by_severity'].get(sev, 0)
            if count > 0:
                lines.append(f"  {sev:10}: {count}")
        lines.append("")

        # Summary by confidence
        lines.append("Summary by Confidence:")
        for conf in ['HIGH', 'MEDIUM', 'LOW']:
            count = summary['by_confidence'].get(conf, 0)
            if count > 0:
                lines.append(f"  {conf:10}: {count}")
        lines.append("")

        lines.append("=" * 80)
        lines.append("")

        # Group findings by file
        findings_by_file = defaultdict(list)
        for f in self.all_findings:
            findings_by_file[f.file_path].append(f)

        for file_path, file_findings in sorted(findings_by_file.items()):
            lines.append(f"FILE: {file_path}")
            lines.append("-" * 80)

            for f in sorted(file_findings, key=lambda x: x.line_number):
                sev_color = {
                    'CRITICAL': '\033[91m',  # Red
                    'HIGH': '\033[93m',      # Yellow
                    'MEDIUM': '\033[94m',    # Blue
                    'LOW': '\033[92m',       # Green
                    'INFO': '\033[90m',      # Gray
                }
                reset = '\033[0m'

                lines.append(f"[{f.severity.value}] {f.vulnerability_name} (Confidence: {f.confidence})")
                lines.append(f"  Line {f.line_number}: {f.line_content.strip()[:100]}")
                if f.description:
                    lines.append(f"  -> {f.description}")
                if f.taint_chain:
                    lines.append(f"  Taint: {' -> '.join(f.taint_chain)}")
                lines.append("")

            lines.append("")

        if not self.all_findings:
            lines.append("No vulnerabilities found.")
            lines.append("")

        return '\n'.join(lines)


def _print_banner():
    """Print the VibeHunter banner using Rich."""
    banner_lines = [
        " _   _____ __         __  __           __",
        "| | / / (_) /_  ___  / / / /_ _____  / /____ ____",
        "| |/ / / / _  \\/ -_)/ _ / // / _ \\/ __/ -_) __/",
        "|___/_/_/_.___/\\__/_//_/\\_,_/_//_/\\__/\\__/_/",
    ]
    banner_text = '\n'.join(banner_lines)

    title_content = Text()
    title_content.append(banner_text, style="bold red")
    title_content.append("\n\n")
    title_content.append("AST-Based SAST Scanner v2.0\n", style="bold white")
    title_content.append("Taint Tracking | Multi-Language | Deep Analysis", style="dim")

    console.print()
    console.print(Panel(
        Align.center(title_content),
        border_style="red",
        box=box.DOUBLE,
        padding=(1, 2),
    ))
    console.print()


def _build_stats_sidebar(scanner, findings: List[Finding], elapsed: float) -> Panel:
    """Build the sidebar panel with scan statistics."""
    stats = Table(show_header=False, box=None, padding=(0, 1), expand=True)
    stats.add_column("key", style="bold cyan", no_wrap=True, ratio=3)
    stats.add_column("value", style="white", ratio=1)

    stats.add_row("Files Scanned", str(scanner.files_scanned))
    stats.add_row("Parse Errors", str(scanner.parse_errors))
    stats.add_row("Total Findings", str(len(findings)))
    stats.add_row("Scan Time", f"{elapsed:.2f}s")
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
            stats.add_row(
                Text(sev, style=sev_styles.get(sev, "white")),
                str(count)
            )

    stats.add_row("", "")

    # Category breakdown
    cat_counts = defaultdict(int)
    for f in findings:
        cat_counts[f.category.value] += 1
    # Use abbreviated names for long categories
    cat_abbrev = {
        "Insecure Direct Object Reference": "IDOR",
        "Server-Side Template Injection": "SSTI",
        "Insecure Deserialization": "Deserialization",
        "Authentication Bypass": "Auth Bypass",
        "XML External Entity": "XXE",
        "Information Disclosure": "Info Disclosure",
        "Command Injection": "Cmd Injection",
        "Code Injection": "Code Injection",
        "SQL Injection": "SQL Injection",
        "NoSQL Injection": "NoSQL Injection",
        "XPath Injection": "XPath Injection",
        "LDAP Injection": "LDAP Injection",
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

    # Source / Sink columns
    source_text = Text()
    source_text.append("Source: ", style="bold cyan")
    source_text.append(f"Line {f.line_number}", style="white")
    if f.col_offset:
        source_text.append(f", Col {f.col_offset}", style="dim")

    sink_text = Text()
    sink_text.append("Category: ", style="bold magenta")
    sink_text.append(f"{f.category.value}", style="white")

    content_parts.append(Columns([source_text, sink_text], padding=(0, 4)))

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
        ext_map = {
            '.py': 'python', '.js': 'javascript', '.ts': 'typescript',
            '.java': 'java', '.php': 'php', '.cs': 'csharp',
            '.rb': 'ruby', '.kt': 'kotlin',
            '.scala': 'scala', '.jsx': 'javascript', '.tsx': 'typescript',
        }
        ext = os.path.splitext(f.file_path)[1].lower()
        lang = ext_map.get(ext, 'text')

        # Build a small code window around the finding line
        if source_code:
            src_lines = source_code.split('\n')
            start = max(0, f.line_number - 3)
            end = min(len(src_lines), f.line_number + 2)
            snippet = '\n'.join(src_lines[start:end])
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

    # Combine all parts into a renderable group
    from rich.console import Group
    panel_content = Group(*content_parts)

    return Panel(
        panel_content,
        title=title,
        border_style=border_style,
        box=box.ROUNDED,
        padding=(1, 2),
    )


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


def main():
    parser = argparse.ArgumentParser(
        description='VibeHunter - Multi-Language SAST with 2nd-Order Injection Detection',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=textwrap.dedent('''
            Examples:
              python3 vibehunter.py /path/to/project
              python3 vibehunter.py app.py --verbose
              python3 vibehunter.py /path/to/project --output json -o report.json
              python3 vibehunter.py /path/to/project --min-confidence HIGH
        ''')
    )

    parser.add_argument('target', help='File or directory to scan')
    parser.add_argument('-v', '--verbose', action='store_true', help='Enable verbose output')
    parser.add_argument('--output', choices=['text', 'json'], default='text',
                        help='Output format (default: text)')
    parser.add_argument('-o', '--output-file', help='Save report to file')
    parser.add_argument('--min-confidence', choices=['HIGH', 'MEDIUM', 'LOW'], default='HIGH',
                        help='Minimum confidence level to report (default: HIGH)')
    parser.add_argument('--all', '-a', action='store_true',
                        help='Show all findings including LOW/MEDIUM confidence (equivalent to --min-confidence LOW)')
    parser.add_argument('--scan-all', action='store_true',
                        help='Scan all files including vendor libraries and minified files')
    parser.add_argument('--config', help='Path to .vibehunter.yml config file')

    args = parser.parse_args()

    # Load config
    config = load_config(args.target, getattr(args, 'config', None))

    _print_banner()

    scanner = ASTScanner(verbose=args.verbose, scan_all=args.scan_all, config=config)
    findings = scanner.scan(args.target)

    # npm audit integration
    npm_findings = run_npm_audit(args.target)
    findings.extend(npm_findings)

    # Filter by confidence
    conf_levels = {'HIGH': 3, 'MEDIUM': 2, 'LOW': 1}
    default_conf = config.min_confidence if config else 'HIGH'
    min_confidence = 'LOW' if args.all else (args.min_confidence or default_conf)
    min_conf = conf_levels[min_confidence]
    findings = [f for f in findings if conf_levels.get(f.confidence, 0) >= min_conf]
    scanner.all_findings = findings

    # JSON output bypasses Rich dashboard
    if args.output == 'json':
        scanner.print_report(output_format='json', output_file=args.output_file)
    else:
        # Load source code for syntax highlighting
        source_cache: Dict[str, str] = {}
        target_path = Path(args.target)
        if target_path.is_file():
            try:
                source_cache[str(target_path)] = target_path.read_text(encoding='utf-8', errors='ignore')
            except Exception:
                pass

        # --- Header ---
        scan_date = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        header_text = Text()
        header_text.append("Target: ", style="bold cyan")
        header_text.append(f"{args.target}  ", style="white")
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

        # --- Statistics sidebar ---
        sidebar = _build_stats_sidebar(scanner, findings, scanner.scan_elapsed)
        console.print(sidebar)
        console.print()

        # --- Findings feed ---
        if findings:
            console.print(Rule("[bold white]Vulnerability Findings[/bold white]", style="red"))
            console.print()

            findings_by_file = defaultdict(list)
            for f in findings:
                findings_by_file[f.file_path].append(f)

            for file_path, file_findings in sorted(findings_by_file.items()):
                console.print(Text(f"FILE: {file_path}", style="bold underline cyan"))
                console.print()

                # Load source for this file if not cached
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

        # Save to file if requested
        if args.output_file:
            output = scanner._format_text_report()
            with open(args.output_file, 'w', encoding='utf-8') as fh:
                fh.write(output)
            console.print(f"\n[bold green]Report saved to {args.output_file}[/bold green]")

    # Exit with error code if critical/high findings
    critical_high = sum(1 for f in findings if f.severity in (Severity.CRITICAL, Severity.HIGH))
    sys.exit(1 if critical_high > 0 else 0)


if __name__ == '__main__':
    main()
