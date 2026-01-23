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
- Go (.go) - Regex-enhanced with taint tracking
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
- XSS - Cross-site scripting (reflected)
- Authentication Bypass - Hardcoded credentials, weak comparisons
"""

import os
import sys
import ast
import json
import argparse
import re
from pathlib import Path
from dataclasses import dataclass, field
from typing import List, Dict, Set, Optional, Tuple, Any, Union
from enum import Enum
from datetime import datetime
from collections import defaultdict
import textwrap


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
    SSRF = "Server-Side Request Forgery"
    AUTH_BYPASS = "Authentication Bypass"
    PROTOTYPE_POLLUTION = "Prototype Pollution"
    XPATH_INJECTION = "XPath Injection"
    XXE = "XML External Entity"
    PATH_TRAVERSAL = "Path Traversal"
    XSS = "Cross-Site Scripting"
    LFI_RFI = "Local/Remote File Inclusion"
    LDAP_INJECTION = "LDAP Injection"


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
}

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
    VulnCategory.SSRF: {
        'requests': ['requests.get', 'requests.post', 'requests.put',
                     'requests.delete', 'requests.patch', 'requests.head',
                     'requests.options', 'requests.request'],
        'urllib': ['urllib.request.urlopen', 'urllib.request.Request',
                   'urllib.urlopen', 'urllib2.urlopen'],
        'httpx': ['httpx.get', 'httpx.post', 'httpx.put', 'httpx.delete',
                  'httpx.patch', 'httpx.AsyncClient'],
        'aiohttp': ['aiohttp.ClientSession', 'session.get', 'session.post'],
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
    VulnCategory.PATH_TRAVERSAL: {
        'file': ['open', 'file', 'io.open'],
        'path': ['os.path.join', 'pathlib.Path'],
        'shutil': ['shutil.copy', 'shutil.copy2', 'shutil.copytree',
                   'shutil.move', 'shutil.rmtree'],
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

            # Check for request.args.get(), request.form.get(), etc.
            if isinstance(node.func, ast.Attribute) and node.func.attr == 'get':
                full_name = self.get_full_attr_name(node.func.value)
                if full_name:
                    for source in PYTHON_TAINT_SOURCES:
                        if source in full_name:
                            return True, TaintSource(full_name, node.lineno, node.col_offset, 'request')

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
        """Track variable assignments for taint propagation."""
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

        self.generic_visit(node)

    def visit_FunctionDef(self, node: ast.FunctionDef):
        """Track function definitions."""
        old_function = self.current_function
        self.current_function = node.name

        # Track parameters
        params = []
        for arg in node.args.args:
            params.append(arg.arg)
        self.function_params[node.name] = params

        self.generic_visit(node)
        self.current_function = old_function

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef):
        """Track async function definitions."""
        self.visit_FunctionDef(node)  # Same handling

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

        if full_func_name:
            self._check_dangerous_call(node, func_name, full_func_name)

        self.generic_visit(node)

    def _check_dangerous_call(self, node: ast.Call, func_name: str, full_func_name: str):
        """Check if a function call is a dangerous sink with tainted input."""

        # ===== CODE INJECTION =====
        if func_name in ('eval', 'exec', 'compile'):
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

        # subprocess with shell=True
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

        # ===== SQL INJECTION =====
        if func_name in ('execute', 'executemany', 'executescript'):
            if node.args:
                first_arg = node.args[0]
                tainted, source = self.is_tainted(first_arg)

                # Check for string concatenation/formatting in query
                is_dynamic = self._is_dynamic_string(first_arg)

                if tainted:
                    self.add_finding(
                        node, "SQL Injection - execute() with tainted query",
                        VulnCategory.SQL_INJECTION, Severity.CRITICAL, "HIGH", source,
                        "User-controlled data used in SQL query without parameterization."
                    )
                elif is_dynamic:
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

        # ===== SSRF =====
        ssrf_funcs = ['get', 'post', 'put', 'delete', 'patch', 'head', 'options', 'request', 'urlopen']
        if func_name in ssrf_funcs:
            if 'requests' in full_func_name or 'urllib' in full_func_name or 'httpx' in full_func_name:
                if node.args:
                    tainted, source = self.is_tainted(node.args[0])
                    if tainted:
                        self.add_finding(
                            node, f"SSRF - {full_func_name}() with user-controlled URL",
                            VulnCategory.SSRF, Severity.HIGH, "HIGH", source,
                            "User-controlled URL can lead to Server-Side Request Forgery."
                        )
                    # Check for variable URL (non-literal)
                    elif isinstance(node.args[0], ast.Name):
                        var_name = node.args[0].id.lower()
                        if any(hint in var_name for hint in ['url', 'uri', 'target', 'endpoint', 'link', 'href']):
                            self.add_finding(
                                node, f"SSRF - {full_func_name}() with variable URL",
                                VulnCategory.SSRF, Severity.MEDIUM, "MEDIUM",
                                description=f"URL from variable '{node.args[0].id}'. Verify URL is validated."
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

        # ===== PATH TRAVERSAL =====
        if func_name == 'open' or func_name == 'file':
            if node.args:
                tainted, source = self.is_tainted(node.args[0])
                if tainted:
                    self.add_finding(
                        node, "Path Traversal - open() with user input",
                        VulnCategory.PATH_TRAVERSAL, Severity.HIGH, "HIGH", source,
                        "User-controlled file path can lead to path traversal attacks."
                    )

        if func_name == 'join' and 'os.path' in full_func_name:
            for arg in node.args:
                tainted, source = self.is_tainted(arg)
                if tainted:
                    self.add_finding(
                        node, "Path Traversal - os.path.join() with user input",
                        VulnCategory.PATH_TRAVERSAL, Severity.HIGH, "HIGH", source,
                        "User-controlled path component in os.path.join()."
                    )
                    break

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

    def visit_Compare(self, node: ast.Compare):
        """Check for weak password comparisons."""
        # Detect patterns like: password == user_input
        if len(node.ops) == 1 and isinstance(node.ops[0], ast.Eq):
            left_name = self._get_name(node.left)

            if left_name and any(kw in left_name.lower() for kw in ['password', 'passwd', 'pwd', 'secret', 'token']):
                if node.comparators:
                    tainted, source = self.is_tainted(node.comparators[0])
                    # This is actually expected - comparing password to user input
                    # But we should flag == instead of constant-time comparison
                    self.add_finding(
                        node, "Auth Bypass - Timing-unsafe password comparison",
                        VulnCategory.AUTH_BYPASS, Severity.LOW, "LOW",
                        description="Use hmac.compare_digest() for constant-time comparison."
                    )

        self.generic_visit(node)

    def _get_name(self, node: ast.AST) -> Optional[str]:
        """Get a simple name from a node."""
        if isinstance(node, ast.Name):
            return node.id
        elif isinstance(node, ast.Attribute):
            return node.attr
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
                # Check context for suspicious decoded content
                self.findings.append(Finding(
                    file_path=self.file_path, line_number=i, col_offset=0,
                    line_content=line, vulnerability_name="Potential Evasion - base64 decode",
                    category=VulnCategory.CODE_INJECTION, severity=Severity.MEDIUM,
                    confidence="MEDIUM", description="base64 decoding may hide malicious strings."
                ))

            if re.search(r'bytes\.fromhex\s*\(|\.fromhex\s*\(', line):
                self.findings.append(Finding(
                    file_path=self.file_path, line_number=i, col_offset=0,
                    line_content=line, vulnerability_name="Potential Evasion - hex string decode",
                    category=VulnCategory.CODE_INJECTION, severity=Severity.MEDIUM,
                    confidence="MEDIUM", description="Hex decoding may hide malicious strings."
                ))

            # 2. Dynamic module/attribute resolution
            if re.search(r'__import__\s*\(', line):
                self.findings.append(Finding(
                    file_path=self.file_path, line_number=i, col_offset=0,
                    line_content=line, vulnerability_name="Code Evasion - Dynamic __import__",
                    category=VulnCategory.CODE_INJECTION, severity=Severity.HIGH,
                    confidence="HIGH", description="__import__() enables dynamic module loading to evade detection."
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
            if re.search(r'@contextmanager', line):
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

            # 14. urlopen with obfuscated reference
            if re.search(r'\.urlopen\s*\(', line):
                self.findings.append(Finding(
                    file_path=self.file_path, line_number=i, col_offset=0,
                    line_content=line, vulnerability_name="SSRF - urlopen call",
                    category=VulnCategory.SSRF, severity=Severity.HIGH,
                    confidence="MEDIUM", description="urlopen() may allow SSRF if URL is user-controlled."
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
            if re.search(r'f["\'].*(?:SELECT|INSERT|UPDATE|DELETE)\s+.*\{', line, re.IGNORECASE):
                self.findings.append(Finding(
                    file_path=self.file_path, line_number=i, col_offset=0,
                    line_content=line, vulnerability_name="SQL Injection - f-string query",
                    category=VulnCategory.SQL_INJECTION, severity=Severity.HIGH,
                    confidence="HIGH", description="SQL query built with f-string interpolation."
                ))

            # 17. Path with incomplete sanitization
            if re.search(r"\.replace\s*\(\s*['\"]\.\./?['\"]", line):
                self.findings.append(Finding(
                    file_path=self.file_path, line_number=i, col_offset=0,
                    line_content=line, vulnerability_name="Path Traversal - Incomplete ../ sanitization",
                    category=VulnCategory.PATH_TRAVERSAL, severity=Severity.HIGH,
                    confidence="HIGH", description="Only removes literal ../ - can be bypassed with encoding."
                ))

            # 18. NoSQL injection via dict comprehension from user input
            if re.search(r'\{.*for.*in.*user|query|request|input', line, re.IGNORECASE):
                if re.search(r'\.find\s*\(|\.find_one\s*\(|\.aggregate\s*\(', '\n'.join(self.source_lines[i:min(len(self.source_lines), i+5)])):
                    self.findings.append(Finding(
                        file_path=self.file_path, line_number=i, col_offset=0,
                        line_content=line, vulnerability_name="NoSQL Injection - Dict from user input",
                        category=VulnCategory.NOSQL_INJECTION, severity=Severity.HIGH,
                        confidence="MEDIUM", description="MongoDB query built from user-controlled dict."
                    ))


class JavaScriptAnalyzer:
    """
    Basic JavaScript/TypeScript analyzer using regex-enhanced pattern matching.
    For production use, consider integrating with esprima or typescript parser.
    """

    def __init__(self, source_code: str, file_path: str):
        self.source_code = source_code
        self.source_lines = source_code.splitlines()
        self.file_path = file_path
        self.findings: List[Finding] = []

        # Track variable assignments for basic taint tracking
        self.tainted_vars: Set[str] = set()
        self._identify_taint_sources()

    def _identify_taint_sources(self):
        """Identify variables that hold user input."""
        taint_patterns = [
            r'(\w+)\s*=\s*req\.(body|query|params|cookies|headers)',
            r'(\w+)\s*=\s*request\.(body|query|params)',
            r'const\s+\{([^}]+)\}\s*=\s*req\.(body|query|params)',
            r'let\s+\{([^}]+)\}\s*=\s*req\.(body|query|params)',
            r'(\w+)\s*=\s*process\.argv',
            r'(\w+)\s*=\s*document\.(location|URL|referrer|cookie)',
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

    def get_line_content(self, lineno: int) -> str:
        """Get the source line content."""
        if 1 <= lineno <= len(self.source_lines):
            return self.source_lines[lineno - 1]
        return ""

    def analyze(self):
        """Run the analysis."""
        self._check_eval_injection()
        self._check_command_injection()
        self._check_sql_injection()
        self._check_prototype_pollution()
        self._check_ssrf()
        self._check_deserialization()
        self._check_ssti()
        self._check_nosql_injection()
        self._check_path_traversal()
        self._check_dangerous_functions()
        self._check_callback_sinks()
        self._check_xxe()
        self._check_xpath_injection()
        self._check_auth_bypass()
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
                        # Look for function keyword or arrow - if present, likely safe
                        if re.search(r'setTimeout\s*\(\s*(?:function|\()', line) or \
                           re.search(r'setInterval\s*\(\s*(?:function|\()', line):
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

            # Special: Check for spawn with shell option in context
            if re.search(r'\bspawn\s*\(', line):
                context = '\n'.join(self.source_lines[max(0, i-1):min(len(self.source_lines), i+3)])
                if re.search(r'shell\s*:\s*true', context):
                    self._add_finding(i, "Command Injection - spawn with shell:true",
                                      VulnCategory.COMMAND_INJECTION, Severity.HIGH, "HIGH",
                                      "spawn() with shell:true allows command injection.")

    def _check_sql_injection(self):
        """Check for SQL injection patterns - including evasion techniques."""
        sql_keywords = r'(?:SELECT|INSERT|UPDATE|DELETE|DROP|CREATE|ALTER|TRUNCATE|UNION|ORDER\s+BY|GROUP\s+BY)'

        for i, line in enumerate(self.source_lines, 1):
            stripped = line.strip()
            if stripped.startswith('//') or stripped.startswith('/*'):
                continue

            # Direct string concatenation with SQL
            if re.search(rf'["\'][^"\']*{sql_keywords}[^"\']*["\']\s*\+', line, re.IGNORECASE):
                self._add_finding(i, "SQL Injection - String concatenation",
                                  VulnCategory.SQL_INJECTION, Severity.HIGH, "HIGH",
                                  "SQL query uses string concatenation.")

            # Template literals with SQL
            if re.search(rf'`[^`]*{sql_keywords}[^`]*\$\{{', line, re.IGNORECASE):
                self._add_finding(i, "SQL Injection - Template literal",
                                  VulnCategory.SQL_INJECTION, Severity.HIGH, "HIGH",
                                  "SQL query uses template literal interpolation.")

            # Tagged template literals (sql`...`)
            if re.search(rf'\bsql\s*`[^`]*{sql_keywords}', line, re.IGNORECASE):
                self._add_finding(i, "SQL Injection - Tagged template literal",
                                  VulnCategory.SQL_INJECTION, Severity.HIGH, "HIGH",
                                  "SQL via tagged template may allow injection if not properly escaped.")

            # Array.join() to build SQL (evasion technique)
            if re.search(r'\.join\s*\(', line):
                context = '\n'.join(self.source_lines[max(0, i-5):i+1])
                if re.search(sql_keywords, context, re.IGNORECASE):
                    self._add_finding(i, "SQL Injection - Array.join() query construction",
                                      VulnCategory.SQL_INJECTION, Severity.HIGH, "HIGH",
                                      "SQL query built via Array.join() - evasion technique.")

            # String.concat() for SQL (evasion technique)
            if re.search(r'\.concat\s*\(', line):
                context = '\n'.join(self.source_lines[max(0, i-3):i+1])
                if re.search(sql_keywords, context, re.IGNORECASE) or re.search(r'query|sql', context, re.IGNORECASE):
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
                if re.search(sql_keywords, context, re.IGNORECASE):
                    self._add_finding(i, "SQL Injection - reduce() query construction",
                                      VulnCategory.SQL_INJECTION, Severity.MEDIUM, "MEDIUM",
                                      "SQL query potentially built via reduce().")

    def _check_prototype_pollution(self):
        """Check for prototype pollution patterns - comprehensive detection."""

        # === CRITICAL: Direct __proto__ access/assignment ===
        critical_patterns = [
            # Direct __proto__ assignment
            (r'\[[\s]*["\']__proto__["\'][\s]*\]\s*=', "Prototype Pollution - __proto__ Direct Assignment"),
            (r'\.__proto__\s*=(?!=)', "Prototype Pollution - __proto__ Direct Assignment"),
            (r'\.__proto__\.\w+\s*=', "Prototype Pollution - __proto__ Property Assignment"),
            (r'\[[\s]*["\']__proto__["\'][\s]*\]\s*\[', "Prototype Pollution - __proto__ Nested Access"),
            # __proto__ in object literal
            (r'\{\s*["\']?__proto__["\']?\s*:', "Prototype Pollution - __proto__ in Object Literal"),
            (r'__proto__\s*:\s*\{', "Prototype Pollution - __proto__ Object Definition"),
            # JSON.parse with __proto__ in string
            (r'JSON\.parse\s*\([^)]*__proto__', "Prototype Pollution - JSON.parse with __proto__"),
            (r'["\']__proto__["\']\s*:\s*\{', "Prototype Pollution - __proto__ in JSON String"),
            # constructor.prototype
            (r'\[[\s]*["\']constructor["\'][\s]*\]\s*\[[\s]*["\']prototype["\']', "Prototype Pollution - constructor.prototype Access"),
            (r'\.constructor\.prototype', "Prototype Pollution - constructor.prototype Access"),
            (r'\.constructor\s*\[[\s]*["\']prototype["\']', "Prototype Pollution - constructor.prototype Access"),
        ]

        # === HIGH: Unsafe merge/extend operations ===
        high_patterns = [
            # Lodash vulnerable functions
            (r'_\.merge\s*\(', "Prototype Pollution - lodash _.merge (vulnerable < 4.17.12)"),
            (r'_\.mergeWith\s*\(', "Prototype Pollution - lodash _.mergeWith"),
            (r'_\.defaultsDeep\s*\(', "Prototype Pollution - lodash _.defaultsDeep"),
            (r'_\.set\s*\([^,]+,\s*req\.', "Prototype Pollution - lodash _.set with user path"),
            (r'_\.setWith\s*\(', "Prototype Pollution - lodash _.setWith"),
            # jQuery extend
            (r'\$\.extend\s*\(\s*true', "Prototype Pollution - jQuery deep extend"),
            (r'jQuery\.extend\s*\(\s*true', "Prototype Pollution - jQuery deep extend"),
            # Spread with user input
            (r'\.\.\.req\.(body|query|params)', "Prototype Pollution - Spread with user input"),
            (r'\.\.\.\s*JSON\.parse', "Prototype Pollution - Spread with JSON.parse"),
            # Object.assign with user input
            (r'Object\.assign\s*\([^)]*req\.(body|query|params)', "Prototype Pollution - Object.assign with user input"),
            (r'Object\.assign\s*\([^)]*JSON\.parse', "Prototype Pollution - Object.assign with JSON.parse"),
            # Deep merge packages
            (r'deepmerge\s*\(', "Prototype Pollution - deepmerge package"),
            (r'merge\-deep\s*\(', "Prototype Pollution - merge-deep package"),
            (r'deep\-extend\s*\(', "Prototype Pollution - deep-extend package"),
            (r'extend\s*\(\s*true', "Prototype Pollution - extend with deep flag"),
            # Evasion: Reflect.ownKeys with dynamic assignment
            (r'Reflect\s*\.\s*ownKeys\s*\(', "Prototype Pollution - Reflect.ownKeys iteration"),
            # Evasion: Object.getOwnPropertyDescriptor without filtering
            (r'Object\s*\.\s*getOwnPropertyDescriptor\s*\(', "Prototype Pollution - getOwnPropertyDescriptor"),
            # Evasion: Object.defineProperty with user data
            (r'Object\s*\.\s*defineProperty\s*\([^)]+\[\s*\w+\s*\]', "Prototype Pollution - defineProperty with dynamic key"),
            # Evasion: path-based set function
            (r'setByPath\s*\(|set\s*\(\s*\w+\s*,\s*["\'][^"\']*\.[^"\']*["\']', "Prototype Pollution - Path-based property setter"),
            # Evasion: split('.') for path traversal
            (r'\.split\s*\(\s*["\']\.["\']\s*\)', "Prototype Pollution - Path splitting for nested access"),
        ]

        # === MEDIUM: Unsafe custom implementations ===
        # Patterns that indicate custom merge without __proto__ filtering
        medium_patterns = [
            # for...in without hasOwnProperty
            (r'for\s*\(\s*(?:const|let|var)\s+\w+\s+in\s+', "Prototype Pollution - Unsafe Object Manipulation"),
            # Object.keys iteration with dynamic assignment
            (r'Object\.keys\s*\([^)]+\)\.forEach', "Prototype Pollution - Object.keys iteration"),
            (r'Object\.entries\s*\([^)]+\)\.forEach', "Prototype Pollution - Object.entries iteration"),
        ]

        # Track findings to avoid duplicates
        found_lines = set()

        for i, line in enumerate(self.source_lines, 1):
            stripped = line.strip()
            if stripped.startswith('//') or stripped.startswith('/*'):
                continue

            # Check critical patterns
            for pattern, vuln_name in critical_patterns:
                if re.search(pattern, line) and i not in found_lines:
                    self._add_finding(i, vuln_name,
                                      VulnCategory.PROTOTYPE_POLLUTION, Severity.CRITICAL, "HIGH",
                                      "Direct prototype pollution vector detected.")
                    found_lines.add(i)
                    break

            # Check high severity patterns
            for pattern, vuln_name in high_patterns:
                if re.search(pattern, line) and i not in found_lines:
                    self._add_finding(i, vuln_name,
                                      VulnCategory.PROTOTYPE_POLLUTION, Severity.HIGH, "HIGH",
                                      "Unsafe object manipulation that may allow prototype pollution.")
                    found_lines.add(i)
                    break

            # Check medium patterns (require context)
            for pattern, vuln_name in medium_patterns:
                if re.search(pattern, line) and i not in found_lines:
                    # Look for dynamic property assignment in surrounding context
                    context_start = max(0, i - 2)
                    context_end = min(len(self.source_lines), i + 10)
                    context = '\n'.join(self.source_lines[context_start:context_end])

                    # Check if there's dynamic property assignment
                    has_dynamic_assign = re.search(r'\[\s*\w+\s*\]\s*=', context)

                    # Check for proper __proto__ filtering (not just mention in comments)
                    has_proto_filter = re.search(
                        r'(?:hasOwnProperty|===\s*["\']__proto__|!==\s*["\']__proto__|'
                        r'key\s*(?:===|!==)\s*["\']__proto__|'
                        r'if\s*\([^)]*__proto__[^)]*\)\s*continue)',
                        context
                    )

                    if has_dynamic_assign and not has_proto_filter:
                        self._add_finding(i, vuln_name,
                                          VulnCategory.PROTOTYPE_POLLUTION, Severity.HIGH, "MEDIUM",
                                          "Object iteration with dynamic assignment without __proto__ filtering.")
                        found_lines.add(i)

        # Check for unsafe merge/extend function definitions
        self._check_unsafe_merge_functions()

    def _check_unsafe_merge_functions(self):
        """Detect custom merge/extend functions that lack __proto__ protection."""
        # Find function definitions with dangerous names
        merge_func_def_pattern = re.compile(
            r'function\s+(deepMerge|merge|extend|deepExtend|mergeDeep|recursiveMerge|'
            r'deepAssign|clone|deepClone|copy|deepCopy)\s*\(',
            re.IGNORECASE
        )

        # Find function calls with potentially unsafe input
        merge_func_call_pattern = re.compile(
            r'(deepMerge|merge|extend|deepExtend|mergeDeep|recursiveMerge|'
            r'deepAssign|clone|deepClone|copy|deepCopy)\s*\(\s*([^)]+)\)',
            re.IGNORECASE
        )

        for i, line in enumerate(self.source_lines, 1):
            # Check function definitions
            def_match = merge_func_def_pattern.search(line)
            if def_match:
                func_name = def_match.group(1)
                # Find function body by counting braces
                brace_count = line.count('{') - line.count('}')
                body_lines = [line]
                body_end = i

                for j in range(i, min(len(self.source_lines), i + 25)):
                    if j > i - 1:
                        next_line = self.source_lines[j]
                        brace_count += next_line.count('{') - next_line.count('}')
                        body_lines.append(next_line)
                        if brace_count <= 0:
                            body_end = j + 1
                            break

                body = '\n'.join(body_lines)

                # Check if it has for...in and dynamic assignment
                has_for_in = re.search(r'for\s*\(\s*(?:const|let|var)\s+\w+\s+in', body)
                has_dynamic_assign = re.search(r'\[\s*\w+\s*\]\s*=', body)

                # Check for actual __proto__ protection (filtering, not just usage)
                has_proto_filter = re.search(
                    r'hasOwnProperty|'
                    r'(?:key|prop|k)\s*(?:===|!==|==|!=)\s*["\'](?:__proto__|constructor)["\']|'
                    r'if\s*\([^)]*["\']__proto__["\'][^)]*\)\s*(?:continue|return)',
                    body
                )

                if has_for_in and has_dynamic_assign and not has_proto_filter:
                    self._add_finding(i, f"Prototype Pollution - Unsafe {func_name} function",
                                      VulnCategory.PROTOTYPE_POLLUTION, Severity.HIGH, "HIGH",
                                      f"Custom {func_name} function lacks __proto__/constructor filtering.")

            # Check function calls with untrusted input
            call_match = merge_func_call_pattern.search(line)
            if call_match and not def_match:  # Not a definition
                func_name = call_match.group(1)
                args = call_match.group(2)

                # Check if any argument is from untrusted source
                has_json_parse = 'JSON.parse' in line or re.search(r'JSON\.parse', args)
                has_req_input = re.search(r'req\.(body|query|params)', args)
                has_untrusted = re.search(r'untrusted|userInput|user_input|input|data', args, re.IGNORECASE)

                # Also check context for where the args come from
                context = '\n'.join(self.source_lines[max(0, i-5):i])
                args_tainted = any(
                    re.search(rf'\b{re.escape(arg.strip())}\b.*(?:JSON\.parse|req\.|untrusted|input)',
                              context, re.IGNORECASE)
                    for arg in args.split(',')
                )

                if has_json_parse or has_req_input or has_untrusted or args_tainted:
                    self._add_finding(i, f"Prototype Pollution - {func_name} with untrusted input",
                                      VulnCategory.PROTOTYPE_POLLUTION, Severity.HIGH, "HIGH",
                                      f"Merge function called with potentially untrusted data.")

    def _check_ssrf(self):
        """Check for SSRF patterns."""
        fetch_patterns = [
            r'fetch\s*\(\s*(?!["\']https?://)',
            r'axios\.(get|post|put|delete)\s*\(\s*(?!["\'])',
            r'https?\.get\s*\(\s*(?!["\'])',
            r'got\s*\(\s*(?!["\'])',
            r'request\s*\(\s*(?!["\'])',
        ]

        for i, line in enumerate(self.source_lines, 1):
            for pattern in fetch_patterns:
                if re.search(pattern, line):
                    # Check for user input
                    has_taint = any(var in line for var in self.tainted_vars)
                    has_req_input = 'req.' in line or 'request.' in line

                    if has_taint or has_req_input:
                        self._add_finding(i, "SSRF - HTTP request with user-controlled URL",
                                          VulnCategory.SSRF, Severity.HIGH, "HIGH",
                                          "User-controlled URL in HTTP request.")
                    elif '${' in line or '" +' in line:
                        self._add_finding(i, "SSRF - HTTP request with dynamic URL",
                                          VulnCategory.SSRF, Severity.MEDIUM, "MEDIUM",
                                          "HTTP request with dynamic URL construction.")

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
            # Handlebars
            (r'handlebars\s*\.\s*compile\s*\(\s*(?!.*["\'])', "SSTI - Handlebars compile with variable"),
            (r'Handlebars\s*\.\s*compile\s*\(', "SSTI - Handlebars.compile"),
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

                    if has_param or has_req:
                        self._add_finding(i, f"{vuln_name} with user input",
                                          VulnCategory.SSTI, Severity.CRITICAL, "HIGH",
                                          "Template engine rendering user-controlled template - RCE possible.")
                    else:
                        self._add_finding(i, vuln_name,
                                          VulnCategory.SSTI, Severity.HIGH, "MEDIUM",
                                          "Template compilation/rendering with variable. Verify source.")

    def _check_nosql_injection(self):
        """Check for NoSQL injection patterns - including evasion techniques."""
        patterns = [
            (r'\.find\s*\(\s*\{[^}]*:\s*req\.', "NoSQL Injection - MongoDB find with request"),
            (r'\.findOne\s*\(\s*\{[^}]*:\s*req\.', "NoSQL Injection - MongoDB findOne with request"),
            (r'\$where\s*:', "NoSQL Injection - $where operator"),
            (r'\$regex\s*:\s*req\.', "NoSQL Injection - $regex with request data"),
            # Evasion: Dynamic object key from user input
            (r'query\s*\[\s*\w+\s*\]\s*=', "NoSQL Injection - Dynamic query key assignment"),
            (r'\[\s*field\s*\]\s*=|\[\s*operator\s*\]\s*=', "NoSQL Injection - Dynamic field/operator"),
            # MongoDB operators
            (r'\$(?:gt|gte|lt|lte|ne|in|nin|or|and|not|nor|exists|type|regex)\s*:', "NoSQL Injection - MongoDB operator"),
        ]

        for i, line in enumerate(self.source_lines, 1):
            stripped = line.strip()
            if stripped.startswith('//') or stripped.startswith('/*'):
                continue

            for pattern, vuln_name in patterns:
                if re.search(pattern, line):
                    # Check context for query building
                    context = '\n'.join(self.source_lines[max(0, i-3):min(len(self.source_lines), i+2)])
                    has_query_context = re.search(r'query|find|collection|\.db\.|mongo', context, re.IGNORECASE)

                    if has_query_context or 'query' in line.lower():
                        self._add_finding(i, vuln_name,
                                          VulnCategory.NOSQL_INJECTION, Severity.HIGH, "HIGH",
                                          "Potential NoSQL injection vulnerability.")

    def _check_path_traversal(self):
        """Check for path traversal vulnerabilities - including evasion techniques."""
        # File system operations that could be exploited
        fs_patterns = [
            (r'fs\.readFile(?:Sync)?\s*\(', 'readFile'),
            (r'fs\.writeFile(?:Sync)?\s*\(', 'writeFile'),
            (r'fs\.unlink(?:Sync)?\s*\(', 'unlink'),
            (r'fs\.rmdir(?:Sync)?\s*\(', 'rmdir'),
            (r'fs\.rm(?:Sync)?\s*\(', 'rm'),
            (r'fs\.mkdir(?:Sync)?\s*\(', 'mkdir'),
            (r'fs\.readdir(?:Sync)?\s*\(', 'readdir'),
            (r'fs\.stat(?:Sync)?\s*\(', 'stat'),
            (r'fs\.access(?:Sync)?\s*\(', 'access'),
            (r'fs\.createReadStream\s*\(', 'createReadStream'),
            (r'fs\.createWriteStream\s*\(', 'createWriteStream'),
            (r'fs\.copyFile(?:Sync)?\s*\(', 'copyFile'),
            (r'fs\.rename(?:Sync)?\s*\(', 'rename'),
            (r'path\.join\s*\(', 'path.join'),
            (r'path\.resolve\s*\(', 'path.resolve'),
            (r'require\s*\(\s*(?!["\'])', 'require'),
        ]

        for i, line in enumerate(self.source_lines, 1):
            stripped = line.strip()
            if stripped.startswith('//') or stripped.startswith('/*'):
                continue

            for pattern, op_name in fs_patterns:
                if re.search(pattern, line):
                    # Check for user input
                    has_taint = any(var in line for var in self.tainted_vars)
                    has_req_input = re.search(r'req\.(body|query|params|path)', line)
                    has_template = '${' in line or "' +" in line or '" +' in line

                    if has_taint or has_req_input:
                        self._add_finding(i, f"Path Traversal - {op_name} with user input",
                                          VulnCategory.PATH_TRAVERSAL, Severity.HIGH, "HIGH",
                                          "User-controlled path in file system operation.")
                    elif has_template:
                        # Look for path sanitization in context
                        context = '\n'.join(self.source_lines[max(0, i-3):i])
                        has_sanitize = re.search(r'sanitize|normalize|basename|\.replace\s*\([^)]*\.\.', context)
                        if not has_sanitize:
                            self._add_finding(i, f"Path Traversal - {op_name} with dynamic path",
                                              VulnCategory.PATH_TRAVERSAL, Severity.MEDIUM, "MEDIUM",
                                              "Dynamic path construction without apparent sanitization.")

            # Evasion: Incomplete ../ sanitization (only removes literal ../)
            if re.search(r'\.replace\s*\(\s*/\\\.\\\.\\//g', line) or \
               re.search(r'\.replace\s*\(\s*["\']\.\./', line):
                # Check if it's the ONLY sanitization
                context = '\n'.join(self.source_lines[max(0, i-2):min(len(self.source_lines), i+3)])
                has_decode = re.search(r'decodeURI|unescape|%2e|%2f', context, re.IGNORECASE)
                has_normalize = re.search(r'path\.normalize|realpath', context)
                if not has_decode and not has_normalize:
                    self._add_finding(i, "Path Traversal - Incomplete ../ sanitization",
                                      VulnCategory.PATH_TRAVERSAL, Severity.HIGH, "HIGH",
                                      "Sanitization only removes literal ../ - can be bypassed with encoding.")

            # Evasion: path.resolve without containment check
            if re.search(r'path\.resolve\s*\(', line):
                # Check if result is validated to be within base path
                context = '\n'.join(self.source_lines[i-1:min(len(self.source_lines), i+5)])
                has_containment = re.search(r'startsWith|indexOf.*===\s*0|includes\s*\(|\.resolve.*\.resolve', context)
                if not has_containment:
                    self._add_finding(i, "Path Traversal - path.resolve without containment",
                                      VulnCategory.PATH_TRAVERSAL, Severity.MEDIUM, "MEDIUM",
                                      "path.resolve() without validating result stays within base directory.")

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
            # xmldom
            (r'new\s+(?:xmldom\s*\.\s*)?DOMParser\s*\(', "XXE - xmldom DOMParser"),
            # xml2js
            (r'xml2js\s*\.\s*parseString\s*\(', "XXE - xml2js.parseString"),
            (r'new\s+xml2js\s*\.\s*Parser\s*\(', "XXE - xml2js.Parser"),
            # sax parser
            (r'sax\s*\.\s*parser\s*\(', "XXE - sax parser"),
            # Generic DOMParser
            (r'new\s+DOMParser\s*\(\s*\)', "XXE - DOMParser"),
            (r'\.parseFromString\s*\([^,]+,\s*["\'](?:text|application)/xml', "XXE - parseFromString"),
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
            # Generic XPath construction
            (r'["\'][^"\']*//[^"\']*["\']\s*\+', "XPath Injection - XPath concatenation"),
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
            # Pattern: variable = "...//..." + userInput + "..."
            if re.search(r'=\s*["\'][^"\']*//[^"\']*["\'].*\+', line) or \
               re.search(r'\+\s*["\'][^"\']*//[^"\']*["\']', line):
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
            (r'(?:password|token|secret|apiKey|api_key)\s*==\s*[^=]', "Auth Bypass - Loose comparison (use ===)"),
            (r'provided\s*==\s*expected', "Auth Bypass - Loose comparison"),
            (r'==\s*(?:password|token|secret)', "Auth Bypass - Loose comparison"),
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

        for i, line in enumerate(self.source_lines, 1):
            stripped = line.strip()
            if stripped.startswith('//') or stripped.startswith('/*'):
                continue

            for pattern, vuln_name in critical_patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    self._add_finding(i, vuln_name,
                                      VulnCategory.AUTH_BYPASS, Severity.CRITICAL, "HIGH",
                                      "Critical authentication bypass vulnerability.")

            for pattern, vuln_name in high_patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    self._add_finding(i, vuln_name,
                                      VulnCategory.AUTH_BYPASS, Severity.HIGH, "HIGH",
                                      "Authentication or authorization bypass detected.")

            for pattern, vuln_name in medium_patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    self._add_finding(i, vuln_name,
                                      VulnCategory.AUTH_BYPASS, Severity.MEDIUM, "MEDIUM",
                                      "Potential authentication weakness.")


class JavaAnalyzer:
    """
    Java analyzer using regex-enhanced pattern matching with taint tracking.
    Tracks variable assignments and method parameters to detect tainted data flow.
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

        # Pre-analyze to identify taint sources
        self._identify_method_params()
        self._identify_lambda_definitions()
        self._track_variable_assignments()
        self._track_lambda_taint_flow()

    def _identify_method_params(self):
        """Identify method parameters as potential taint sources."""
        # Match method declarations with parameters
        method_pattern = r'(?:public|private|protected|static|\s)+\s+\w+\s+(\w+)\s*\(([^)]*)\)'

        for i, line in enumerate(self.source_lines, 1):
            match = re.search(method_pattern, line)
            if match:
                method_name = match.group(1)
                params_str = match.group(2)
                if params_str.strip():
                    # Parse parameters: "Type name, Type name, ..."
                    params = set()
                    for param in params_str.split(','):
                        parts = param.strip().split()
                        if len(parts) >= 2:
                            param_name = parts[-1].strip()
                            # Remove array brackets if present
                            param_name = re.sub(r'\[\]', '', param_name)
                            params.add(param_name)
                            # Mark as tainted
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

    def _is_tainted(self, line: str) -> Tuple[bool, Optional[str]]:
        """Check if a line contains tainted data."""
        for var_name in self.tainted_vars:
            if re.search(rf'\b{re.escape(var_name)}\b', line):
                return True, var_name
        return False, None

    def get_line_content(self, lineno: int) -> str:
        """Get the source line content."""
        if 1 <= lineno <= len(self.source_lines):
            return self.source_lines[lineno - 1]
        return ""

    def analyze(self) -> List[Finding]:
        """Run the analysis."""
        self._check_sql_injection()
        self._check_command_injection()
        self._check_deserialization()
        self._check_ssrf()
        self._check_path_traversal()
        self._check_xxe()
        self._check_jndi_injection()
        self._check_script_engine()
        self._check_reflection_injection()
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

        for i, line in enumerate(self.source_lines, 1):
            stripped = line.strip()
            if stripped.startswith('//') or stripped.startswith('/*') or stripped.startswith('*'):
                continue

            # Pattern 1: executeQuery/execute with string concatenation
            if re.search(r'\.(?:executeQuery|execute|executeUpdate)\s*\(', line):
                is_tainted, taint_var = self._is_tainted(line)

                # Check for string concatenation with SQL keywords
                has_concat = '+' in line or 'concat' in line.lower() or 'format' in line.lower()
                has_sql = re.search(sql_keywords, line, re.IGNORECASE)

                if is_tainted:
                    self._add_finding(i, "SQL Injection - executeQuery with tainted input",
                                      VulnCategory.SQL_INJECTION, Severity.CRITICAL, "HIGH", taint_var,
                                      "User-controlled data in SQL query execution.")
                elif has_concat and has_sql:
                    self._add_finding(i, "SQL Injection - Dynamic query construction",
                                      VulnCategory.SQL_INJECTION, Severity.HIGH, "MEDIUM",
                                      description="SQL query uses string concatenation. Use PreparedStatement.")

            # Pattern 2: String building with SQL + tainted data
            if re.search(sql_keywords, line, re.IGNORECASE) and '+' in line:
                is_tainted, taint_var = self._is_tainted(line)
                if is_tainted:
                    self._add_finding(i, "SQL Injection - String concatenation with tainted data",
                                      VulnCategory.SQL_INJECTION, Severity.CRITICAL, "HIGH", taint_var,
                                      "SQL query built with user-controlled data.")

            # Pattern 3: String.format with SQL
            if 'String.format' in line and re.search(sql_keywords, line, re.IGNORECASE):
                is_tainted, taint_var = self._is_tainted(line)
                if is_tainted:
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
                if is_tainted:
                    self._add_finding(i, "Command Injection - ProcessBuilder with tainted input",
                                      VulnCategory.COMMAND_INJECTION, Severity.CRITICAL, "HIGH", taint_var,
                                      "User-controlled data passed to ProcessBuilder.")

    def _check_deserialization(self):
        """Check for insecure deserialization patterns."""
        for i, line in enumerate(self.source_lines, 1):
            stripped = line.strip()
            if stripped.startswith('//') or stripped.startswith('/*') or stripped.startswith('*'):
                continue

            # ObjectInputStream.readObject()
            if re.search(r'ObjectInputStream|\.readObject\s*\(', line):
                is_tainted, taint_var = self._is_tainted(line)

                # Look for ObjectInputStream creation with tainted data
                context = '\n'.join(self.source_lines[max(0, i-3):i+1])
                if re.search(r'new\s+ObjectInputStream\s*\(', context):
                    if is_tainted:
                        self._add_finding(i, "Insecure Deserialization - ObjectInputStream with tainted data",
                                          VulnCategory.DESERIALIZATION, Severity.CRITICAL, "HIGH", taint_var,
                                          "Deserializing user-controlled data can lead to RCE.")
                    else:
                        self._add_finding(i, "Insecure Deserialization - ObjectInputStream usage",
                                          VulnCategory.DESERIALIZATION, Severity.HIGH, "MEDIUM",
                                          description="ObjectInputStream.readObject() detected. Verify data source.")

            # XMLDecoder
            if re.search(r'XMLDecoder|\.readObject\s*\(', line) and 'XMLDecoder' in line:
                self._add_finding(i, "Insecure Deserialization - XMLDecoder",
                                  VulnCategory.DESERIALIZATION, Severity.CRITICAL, "HIGH",
                                  description="XMLDecoder is dangerous and can lead to RCE.")

    def _check_ssrf(self):
        """Check for SSRF patterns."""
        for i, line in enumerate(self.source_lines, 1):
            stripped = line.strip()
            if stripped.startswith('//') or stripped.startswith('/*') or stripped.startswith('*'):
                continue

            # URL construction with tainted data
            if re.search(r'new\s+URL\s*\(', line):
                is_tainted, taint_var = self._is_tainted(line)
                if is_tainted:
                    self._add_finding(i, "SSRF - URL constructed with tainted data",
                                      VulnCategory.SSRF, Severity.HIGH, "HIGH", taint_var,
                                      "User-controlled data used in URL construction.")

            # URI construction
            if re.search(r'new\s+URI\s*\(', line):
                is_tainted, taint_var = self._is_tainted(line)
                if is_tainted:
                    self._add_finding(i, "SSRF - URI constructed with tainted data",
                                      VulnCategory.SSRF, Severity.HIGH, "HIGH", taint_var,
                                      "User-controlled data used in URI construction.")

            # openConnection, openStream
            if re.search(r'\.(?:openConnection|openStream)\s*\(', line):
                is_tainted, taint_var = self._is_tainted(line)
                context = '\n'.join(self.source_lines[max(0, i-3):i+1])
                taint_in_context, ctx_var = self._is_tainted(context)
                if is_tainted or taint_in_context:
                    self._add_finding(i, "SSRF - HTTP connection with potentially tainted URL",
                                      VulnCategory.SSRF, Severity.HIGH, "HIGH", taint_var or ctx_var,
                                      "HTTP request made with potentially user-controlled URL.")

            # HttpURLConnection
            if re.search(r'HttpURLConnection', line):
                context = '\n'.join(self.source_lines[max(0, i-5):i+1])
                taint_in_context, ctx_var = self._is_tainted(context)
                if taint_in_context:
                    self._add_finding(i, "SSRF - HttpURLConnection with tainted URL",
                                      VulnCategory.SSRF, Severity.HIGH, "MEDIUM", ctx_var,
                                      "HTTP connection may use user-controlled URL.")

    def _check_path_traversal(self):
        """Check for path traversal patterns."""
        for i, line in enumerate(self.source_lines, 1):
            stripped = line.strip()
            if stripped.startswith('//') or stripped.startswith('/*') or stripped.startswith('*'):
                continue

            # Files.readAllBytes, Files.write, etc.
            if re.search(r'Files\s*\.\s*(?:readAllBytes|write|copy|move|delete|newInputStream|newOutputStream)\s*\(', line):
                is_tainted, taint_var = self._is_tainted(line)
                if is_tainted:
                    self._add_finding(i, "Path Traversal - Files API with tainted path",
                                      VulnCategory.PATH_TRAVERSAL, Severity.HIGH, "HIGH", taint_var,
                                      "User-controlled data used in file path.")

            # Paths.get
            if re.search(r'Paths\s*\.\s*get\s*\(', line):
                is_tainted, taint_var = self._is_tainted(line)
                if is_tainted or '+' in line:
                    context = '\n'.join(self.source_lines[max(0, i-2):i+1])
                    ctx_taint, ctx_var = self._is_tainted(context)
                    if is_tainted or ctx_taint:
                        self._add_finding(i, "Path Traversal - Paths.get with tainted data",
                                          VulnCategory.PATH_TRAVERSAL, Severity.HIGH, "HIGH", taint_var or ctx_var,
                                          "User-controlled data used to construct file path.")

            # new File()
            if re.search(r'new\s+File\s*\(', line):
                is_tainted, taint_var = self._is_tainted(line)
                if is_tainted:
                    self._add_finding(i, "Path Traversal - File constructed with tainted data",
                                      VulnCategory.PATH_TRAVERSAL, Severity.HIGH, "HIGH", taint_var,
                                      "User-controlled data used in File constructor.")

            # FileInputStream, FileOutputStream, FileReader, FileWriter
            if re.search(r'new\s+(?:FileInputStream|FileOutputStream|FileReader|FileWriter)\s*\(', line):
                is_tainted, taint_var = self._is_tainted(line)
                if is_tainted or '+' in line:
                    self._add_finding(i, "Path Traversal - File stream with tainted path",
                                      VulnCategory.PATH_TRAVERSAL, Severity.HIGH, "HIGH", taint_var,
                                      "User-controlled data in file stream path.")

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

    def _check_script_engine(self):
        """Check for script engine code injection."""
        for i, line in enumerate(self.source_lines, 1):
            stripped = line.strip()
            if stripped.startswith('//') or stripped.startswith('/*') or stripped.startswith('*'):
                continue

            # ScriptEngine.eval
            if re.search(r'ScriptEngine|\.eval\s*\(', line):
                is_tainted, taint_var = self._is_tainted(line)
                context = '\n'.join(self.source_lines[max(0, i-5):i+1])
                has_script_engine = re.search(r'ScriptEngine|getEngineByName', context)

                if has_script_engine:
                    if is_tainted:
                        self._add_finding(i, "Code Injection - ScriptEngine.eval with tainted data",
                                          VulnCategory.CODE_INJECTION, Severity.CRITICAL, "HIGH", taint_var,
                                          "User-controlled data in ScriptEngine.eval() enables code execution.")
                    elif re.search(r'\.eval\s*\(', line):
                        self._add_finding(i, "Code Injection - ScriptEngine.eval usage",
                                          VulnCategory.CODE_INJECTION, Severity.HIGH, "MEDIUM",
                                          description="ScriptEngine.eval() detected. Verify input is not user-controlled.")

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


class PHPAnalyzer:
    """
    PHP analyzer with taint tracking for common web vulnerabilities.
    Tracks $_GET, $_POST, $_REQUEST, $_COOKIE, $_SERVER as taint sources.
    """

    def __init__(self, source_code: str, file_path: str):
        self.source_code = source_code
        self.source_lines = source_code.splitlines()
        self.file_path = file_path
        self.findings: List[Finding] = []
        self.tainted_vars: Dict[str, int] = {}

        self._identify_taint_sources()
        self._track_variable_assignments()

    def _identify_taint_sources(self):
        """Identify PHP superglobals and function parameters as taint sources."""
        superglobals = [
            r'\$_GET', r'\$_POST', r'\$_REQUEST', r'\$_COOKIE',
            r'\$_SERVER', r'\$_FILES', r'\$_ENV', r'\$HTTP_RAW_POST_DATA',
            r'file_get_contents\s*\(\s*["\']php://input',
        ]

        for i, line in enumerate(self.source_lines, 1):
            for sg in superglobals:
                if re.search(sg, line):
                    # Extract variable being assigned
                    match = re.search(r'\$(\w+)\s*=', line)
                    if match:
                        self.tainted_vars[match.group(1)] = i

        # Function parameters
        func_pattern = r'function\s+\w+\s*\(([^)]*)\)'
        for i, line in enumerate(self.source_lines, 1):
            match = re.search(func_pattern, line)
            if match:
                params = match.group(1)
                for param in re.findall(r'\$(\w+)', params):
                    self.tainted_vars[param] = i

    def _track_variable_assignments(self):
        """Track variable assignments to propagate taint."""
        for i, line in enumerate(self.source_lines, 1):
            if line.strip().startswith('//') or line.strip().startswith('#'):
                continue
            match = re.search(r'\$(\w+)\s*=\s*(.+?);', line)
            if match:
                var_name = match.group(1)
                rhs = match.group(2)
                for tainted in list(self.tainted_vars.keys()):
                    if re.search(rf'\${re.escape(tainted)}\b', rhs):
                        self.tainted_vars[var_name] = i
                        break

    def _is_tainted(self, line: str) -> Tuple[bool, Optional[str]]:
        for var in self.tainted_vars:
            if re.search(rf'\${re.escape(var)}\b', line):
                return True, var
        # Check direct superglobal use
        if re.search(r'\$_(GET|POST|REQUEST|COOKIE|SERVER|FILES)\s*\[', line):
            return True, '$_REQUEST'
        return False, None

    def get_line_content(self, lineno: int) -> str:
        if 1 <= lineno <= len(self.source_lines):
            return self.source_lines[lineno - 1]
        return ""

    def analyze(self) -> List[Finding]:
        self._check_sql_injection()
        self._check_command_injection()
        self._check_code_injection()
        self._check_file_inclusion()
        self._check_xss()
        self._check_deserialization()
        self._check_ssrf()
        self._check_path_traversal()
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
        sql_keywords = r'(?:SELECT|INSERT|UPDATE|DELETE|DROP|UNION|FROM|WHERE)'

        for i, line in enumerate(self.source_lines, 1):
            if line.strip().startswith('//') or line.strip().startswith('#'):
                continue

            # Direct query with concatenation
            if re.search(sql_funcs, line) or re.search(sql_keywords, line, re.IGNORECASE):
                is_tainted, taint_var = self._is_tainted(line)
                has_concat = '.' in line or '+' in line or re.search(r'\$\w+', line)

                if is_tainted and (re.search(sql_funcs, line) or re.search(sql_keywords, line, re.IGNORECASE)):
                    self._add_finding(i, "SQL Injection - Query with tainted data",
                                      VulnCategory.SQL_INJECTION, Severity.CRITICAL, "HIGH", taint_var,
                                      "User input directly in SQL query.")

    def _check_command_injection(self):
        cmd_funcs = r'\b(system|exec|shell_exec|passthru|popen|proc_open|pcntl_exec|eval)\s*\('

        for i, line in enumerate(self.source_lines, 1):
            if line.strip().startswith('//'):
                continue
            if re.search(cmd_funcs, line):
                is_tainted, taint_var = self._is_tainted(line)
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

    def _check_code_injection(self):
        for i, line in enumerate(self.source_lines, 1):
            if line.strip().startswith('//'):
                continue

            # eval()
            if re.search(r'\beval\s*\(', line):
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

    def _check_file_inclusion(self):
        include_funcs = r'\b(include|include_once|require|require_once)\s*[\(\s]'

        for i, line in enumerate(self.source_lines, 1):
            if line.strip().startswith('//'):
                continue
            if re.search(include_funcs, line):
                is_tainted, taint_var = self._is_tainted(line)
                if is_tainted:
                    self._add_finding(i, "File Inclusion - LFI/RFI with tainted data",
                                      VulnCategory.LFI_RFI, Severity.CRITICAL, "HIGH", taint_var,
                                      "User input in file inclusion allows LFI/RFI.")
                elif re.search(r'\$\w+', line):
                    self._add_finding(i, "File Inclusion - Dynamic include",
                                      VulnCategory.PATH_TRAVERSAL, Severity.HIGH, "MEDIUM",
                                      description="Variable in file inclusion. Verify source.")

    def _check_xss(self):
        output_funcs = r'\b(echo|print|printf|print_r|var_dump)\s*[\(\s]'

        for i, line in enumerate(self.source_lines, 1):
            if line.strip().startswith('//'):
                continue
            if re.search(output_funcs, line):
                is_tainted, taint_var = self._is_tainted(line)
                # Check if escaped
                has_escape = re.search(r'htmlspecialchars|htmlentities|strip_tags|esc_html', line)
                if is_tainted and not has_escape:
                    self._add_finding(i, "XSS - Unescaped output with tainted data",
                                      VulnCategory.XSS, Severity.HIGH, "MEDIUM", taint_var,
                                      "User input output without escaping.")

    def _check_deserialization(self):
        for i, line in enumerate(self.source_lines, 1):
            if line.strip().startswith('//'):
                continue
            if re.search(r'\bunserialize\s*\(', line):
                is_tainted, taint_var = self._is_tainted(line)
                if is_tainted:
                    self._add_finding(i, "Insecure Deserialization - unserialize with tainted data",
                                      VulnCategory.DESERIALIZATION, Severity.CRITICAL, "HIGH", taint_var,
                                      "User input passed to unserialize() can lead to RCE.")
                else:
                    self._add_finding(i, "Insecure Deserialization - unserialize usage",
                                      VulnCategory.DESERIALIZATION, Severity.HIGH, "MEDIUM",
                                      description="unserialize() detected. Verify data source.")

    def _check_ssrf(self):
        url_funcs = r'\b(file_get_contents|curl_init|curl_setopt|fopen|readfile|get_headers)\s*\('

        for i, line in enumerate(self.source_lines, 1):
            if line.strip().startswith('//'):
                continue
            if re.search(url_funcs, line):
                is_tainted, taint_var = self._is_tainted(line)
                if is_tainted:
                    self._add_finding(i, "SSRF - URL function with tainted data",
                                      VulnCategory.SSRF, Severity.HIGH, "HIGH", taint_var,
                                      "User-controlled URL in request function.")

    def _check_path_traversal(self):
        file_funcs = r'\b(fopen|file_get_contents|readfile|file|unlink|rmdir|mkdir|copy|rename|move_uploaded_file)\s*\('

        for i, line in enumerate(self.source_lines, 1):
            if line.strip().startswith('//'):
                continue
            if re.search(file_funcs, line):
                is_tainted, taint_var = self._is_tainted(line)
                if is_tainted:
                    self._add_finding(i, "Path Traversal - File function with tainted path",
                                      VulnCategory.PATH_TRAVERSAL, Severity.HIGH, "HIGH", taint_var,
                                      "User input in file path allows traversal.")


class CSharpAnalyzer:
    """
    C# analyzer with taint tracking for ASP.NET and general C# vulnerabilities.
    """

    def __init__(self, source_code: str, file_path: str):
        self.source_code = source_code
        self.source_lines = source_code.splitlines()
        self.file_path = file_path
        self.findings: List[Finding] = []
        self.tainted_vars: Dict[str, int] = {}

        self._identify_taint_sources()
        self._track_variable_assignments()

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

        # Method parameters
        for i, line in enumerate(self.source_lines, 1):
            match = re.search(r'(?:public|private|protected|internal)\s+\w+\s+\w+\s*\(([^)]+)\)', line)
            if match:
                params = match.group(1)
                for param_match in re.finditer(r'(?:\w+(?:<[^>]+>)?)\s+(\w+)', params):
                    self.tainted_vars[param_match.group(1)] = i

    def _track_variable_assignments(self):
        for i, line in enumerate(self.source_lines, 1):
            if line.strip().startswith('//'):
                continue
            match = re.search(r'(?:var|string|object|int)\s+(\w+)\s*=\s*(.+?);', line)
            if match:
                var_name = match.group(1)
                rhs = match.group(2)
                for tainted in list(self.tainted_vars.keys()):
                    if re.search(rf'\b{re.escape(tainted)}\b', rhs):
                        self.tainted_vars[var_name] = i
                        break

    def _is_tainted(self, line: str) -> Tuple[bool, Optional[str]]:
        for var in self.tainted_vars:
            if re.search(rf'\b{re.escape(var)}\b', line):
                return True, var
        if re.search(r'Request\s*[\[.]', line):
            return True, 'Request'
        return False, None

    def get_line_content(self, lineno: int) -> str:
        if 1 <= lineno <= len(self.source_lines):
            return self.source_lines[lineno - 1]
        return ""

    def analyze(self) -> List[Finding]:
        self._check_sql_injection()
        self._check_command_injection()
        self._check_deserialization()
        self._check_path_traversal()
        self._check_xxe()
        self._check_ldap_injection()
        self._check_xss()
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
        sql_keywords = r'(?:SELECT|INSERT|UPDATE|DELETE|DROP|EXEC|EXECUTE)'

        for i, line in enumerate(self.source_lines, 1):
            if line.strip().startswith('//'):
                continue

            for pattern in sql_patterns:
                if re.search(pattern, line):
                    is_tainted, taint_var = self._is_tainted(line)
                    has_concat = '+' in line or '$"' in line or 'String.Format' in line

                    if is_tainted:
                        self._add_finding(i, "SQL Injection - SqlCommand with tainted data",
                                          VulnCategory.SQL_INJECTION, Severity.CRITICAL, "HIGH", taint_var,
                                          "User input in SQL command.")
                    elif has_concat and re.search(sql_keywords, line, re.IGNORECASE):
                        self._add_finding(i, "SQL Injection - Dynamic query construction",
                                          VulnCategory.SQL_INJECTION, Severity.HIGH, "MEDIUM",
                                          description="SQL uses string concatenation. Use parameterized queries.")

    def _check_command_injection(self):
        for i, line in enumerate(self.source_lines, 1):
            if line.strip().startswith('//'):
                continue

            if re.search(r'Process\.Start\s*\(|ProcessStartInfo', line):
                is_tainted, taint_var = self._is_tainted(line)
                if is_tainted:
                    self._add_finding(i, "Command Injection - Process.Start with tainted data",
                                      VulnCategory.COMMAND_INJECTION, Severity.CRITICAL, "HIGH", taint_var,
                                      "User input passed to Process.Start().")

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
                    if 'BinaryFormatter' in line or 'NetDataContractSerializer' in line:
                        self._add_finding(i, f"Insecure Deserialization - {pattern.split('|')[0]}",
                                          VulnCategory.DESERIALIZATION, Severity.CRITICAL, "HIGH", taint_var,
                                          "Dangerous deserializer can lead to RCE.")
                    elif is_tainted:
                        self._add_finding(i, "Insecure Deserialization - Deserialize with tainted data",
                                          VulnCategory.DESERIALIZATION, Severity.HIGH, "MEDIUM", taint_var,
                                          "User data being deserialized.")

    def _check_path_traversal(self):
        file_patterns = [
            r'File\.ReadAllText\s*\(', r'File\.ReadAllBytes\s*\(',
            r'File\.WriteAllText\s*\(', r'File\.Open\s*\(',
            r'File\.Delete\s*\(', r'Directory\.CreateDirectory\s*\(',
            r'Path\.Combine\s*\(', r'StreamReader\s*\(',
            r'FileStream\s*\(',
        ]

        for i, line in enumerate(self.source_lines, 1):
            if line.strip().startswith('//'):
                continue

            for pattern in file_patterns:
                if re.search(pattern, line):
                    is_tainted, taint_var = self._is_tainted(line)
                    if is_tainted:
                        self._add_finding(i, "Path Traversal - File operation with tainted path",
                                          VulnCategory.PATH_TRAVERSAL, Severity.HIGH, "HIGH", taint_var,
                                          "User input in file path.")

    def _check_xxe(self):
        for i, line in enumerate(self.source_lines, 1):
            if line.strip().startswith('//'):
                continue

            if re.search(r'XmlDocument|XmlReader|XmlTextReader', line):
                context = '\n'.join(self.source_lines[i:min(len(self.source_lines), i+10)])
                has_secure = re.search(r'DtdProcessing\s*=\s*DtdProcessing\.Prohibit|XmlResolver\s*=\s*null', context)
                if not has_secure:
                    self._add_finding(i, "XXE - XML parser without secure configuration",
                                      VulnCategory.XXE, Severity.HIGH, "MEDIUM",
                                      description="XML parser should disable DTD processing.")

    def _check_ldap_injection(self):
        for i, line in enumerate(self.source_lines, 1):
            if line.strip().startswith('//'):
                continue

            if re.search(r'DirectorySearcher|\.Filter\s*=', line):
                is_tainted, taint_var = self._is_tainted(line)
                if is_tainted:
                    self._add_finding(i, "LDAP Injection - Filter with tainted data",
                                      VulnCategory.LDAP_INJECTION, Severity.HIGH, "HIGH", taint_var,
                                      "User input in LDAP filter.")

    def _check_xss(self):
        for i, line in enumerate(self.source_lines, 1):
            if line.strip().startswith('//'):
                continue

            if re.search(r'Response\.Write\s*\(|@Html\.Raw\s*\(', line):
                is_tainted, taint_var = self._is_tainted(line)
                has_encode = re.search(r'HtmlEncode|AntiXss|Encoder\.', line)
                if is_tainted and not has_encode:
                    self._add_finding(i, "XSS - Unencoded output with tainted data",
                                      VulnCategory.XSS, Severity.HIGH, "MEDIUM", taint_var,
                                      "User input output without encoding.")


class GoAnalyzer:
    """
    Go analyzer with taint tracking for common vulnerabilities.
    """

    def __init__(self, source_code: str, file_path: str):
        self.source_code = source_code
        self.source_lines = source_code.splitlines()
        self.file_path = file_path
        self.findings: List[Finding] = []
        self.tainted_vars: Dict[str, int] = {}

        self._identify_taint_sources()
        self._track_variable_assignments()

    def _identify_taint_sources(self):
        """Identify HTTP request data and function parameters as taint sources."""
        taint_patterns = [
            r'r\.URL\.Query\(\)', r'r\.FormValue\s*\(', r'r\.PostFormValue\s*\(',
            r'r\.Header\.Get\s*\(', r'r\.Body', r'c\.Query\s*\(', r'c\.Param\s*\(',
            r'c\.PostForm\s*\(', r'c\.GetHeader\s*\(',
            r'os\.Args', r'flag\.\w+\s*\(',
        ]

        for i, line in enumerate(self.source_lines, 1):
            for pattern in taint_patterns:
                if re.search(pattern, line):
                    match = re.search(r'(\w+)\s*:?=', line)
                    if match:
                        self.tainted_vars[match.group(1)] = i

        # Function parameters
        for i, line in enumerate(self.source_lines, 1):
            match = re.search(r'func\s+(?:\([^)]+\)\s+)?\w+\s*\(([^)]+)\)', line)
            if match:
                params = match.group(1)
                for param in re.findall(r'(\w+)\s+\w+', params):
                    self.tainted_vars[param] = i

    def _track_variable_assignments(self):
        for i, line in enumerate(self.source_lines, 1):
            if line.strip().startswith('//'):
                continue
            match = re.search(r'(\w+)\s*:?=\s*(.+)', line)
            if match:
                var_name = match.group(1)
                rhs = match.group(2)
                for tainted in list(self.tainted_vars.keys()):
                    if re.search(rf'\b{re.escape(tainted)}\b', rhs):
                        self.tainted_vars[var_name] = i
                        break

    def _is_tainted(self, line: str) -> Tuple[bool, Optional[str]]:
        for var in self.tainted_vars:
            if re.search(rf'\b{re.escape(var)}\b', line):
                return True, var
        return False, None

    def get_line_content(self, lineno: int) -> str:
        if 1 <= lineno <= len(self.source_lines):
            return self.source_lines[lineno - 1]
        return ""

    def analyze(self) -> List[Finding]:
        self._check_sql_injection()
        self._check_command_injection()
        self._check_path_traversal()
        self._check_ssrf()
        self._check_ssti()
        return self.findings

    def _add_finding(self, line_num: int, vuln_name: str, category: VulnCategory,
                     severity: Severity, confidence: str, taint_var: Optional[str] = None,
                     description: str = ""):
        taint_chain = []
        if taint_var and taint_var in self.tainted_vars:
            taint_chain = [f"tainted: {taint_var} (line {self.tainted_vars[taint_var]})"]

        self.findings.append(Finding(
            file_path=self.file_path, line_number=line_num, col_offset=0,
            line_content=self.get_line_content(line_num),
            vulnerability_name=vuln_name, category=category,
            severity=severity, confidence=confidence,
            taint_chain=taint_chain, description=description,
        ))

    def _check_sql_injection(self):
        sql_patterns = [
            r'\.Query\s*\(', r'\.QueryRow\s*\(', r'\.Exec\s*\(',
            r'\.QueryContext\s*\(', r'\.ExecContext\s*\(',
        ]
        sql_keywords = r'(?:SELECT|INSERT|UPDATE|DELETE|DROP)'

        for i, line in enumerate(self.source_lines, 1):
            if line.strip().startswith('//'):
                continue

            for pattern in sql_patterns:
                if re.search(pattern, line):
                    is_tainted, taint_var = self._is_tainted(line)
                    # Check for string concatenation or fmt.Sprintf
                    has_concat = '+' in line or 'fmt.Sprintf' in line or 'fmt.Sprint' in line

                    if is_tainted and has_concat:
                        self._add_finding(i, "SQL Injection - Query with tainted data",
                                          VulnCategory.SQL_INJECTION, Severity.CRITICAL, "HIGH", taint_var,
                                          "User input concatenated in SQL query.")

            if 'fmt.Sprintf' in line and re.search(sql_keywords, line, re.IGNORECASE):
                is_tainted, taint_var = self._is_tainted(line)
                if is_tainted:
                    self._add_finding(i, "SQL Injection - fmt.Sprintf with SQL and tainted data",
                                      VulnCategory.SQL_INJECTION, Severity.CRITICAL, "HIGH", taint_var,
                                      "User input in fmt.Sprintf SQL query.")

    def _check_command_injection(self):
        for i, line in enumerate(self.source_lines, 1):
            if line.strip().startswith('//'):
                continue

            if re.search(r'exec\.Command\s*\(', line):
                is_tainted, taint_var = self._is_tainted(line)
                if is_tainted:
                    self._add_finding(i, "Command Injection - exec.Command with tainted data",
                                      VulnCategory.COMMAND_INJECTION, Severity.CRITICAL, "HIGH", taint_var,
                                      "User input passed to exec.Command().")

            if re.search(r'os\.StartProcess\s*\(', line):
                is_tainted, taint_var = self._is_tainted(line)
                if is_tainted:
                    self._add_finding(i, "Command Injection - os.StartProcess with tainted data",
                                      VulnCategory.COMMAND_INJECTION, Severity.CRITICAL, "HIGH", taint_var,
                                      "User input passed to os.StartProcess().")

    def _check_path_traversal(self):
        file_patterns = [
            r'os\.Open\s*\(', r'os\.Create\s*\(', r'os\.ReadFile\s*\(',
            r'ioutil\.ReadFile\s*\(', r'ioutil\.WriteFile\s*\(',
            r'filepath\.Join\s*\(', r'http\.ServeFile\s*\(',
        ]

        for i, line in enumerate(self.source_lines, 1):
            if line.strip().startswith('//'):
                continue

            for pattern in file_patterns:
                if re.search(pattern, line):
                    is_tainted, taint_var = self._is_tainted(line)
                    if is_tainted:
                        self._add_finding(i, "Path Traversal - File operation with tainted path",
                                          VulnCategory.PATH_TRAVERSAL, Severity.HIGH, "HIGH", taint_var,
                                          "User input in file path.")

    def _check_ssrf(self):
        for i, line in enumerate(self.source_lines, 1):
            if line.strip().startswith('//'):
                continue

            if re.search(r'http\.Get\s*\(|http\.Post\s*\(|http\.NewRequest\s*\(', line):
                is_tainted, taint_var = self._is_tainted(line)
                if is_tainted:
                    self._add_finding(i, "SSRF - HTTP request with tainted URL",
                                      VulnCategory.SSRF, Severity.HIGH, "HIGH", taint_var,
                                      "User-controlled URL in HTTP request.")

    def _check_ssti(self):
        for i, line in enumerate(self.source_lines, 1):
            if line.strip().startswith('//'):
                continue

            if re.search(r'template\.New\s*\([^)]*\)\.Parse\s*\(', line):
                is_tainted, taint_var = self._is_tainted(line)
                if is_tainted:
                    self._add_finding(i, "SSTI - Template parsing with tainted data",
                                      VulnCategory.SSTI, Severity.HIGH, "HIGH", taint_var,
                                      "User input parsed as template.")


class RubyAnalyzer:
    """
    Ruby analyzer with taint tracking for Rails and general Ruby vulnerabilities.
    """

    def __init__(self, source_code: str, file_path: str):
        self.source_code = source_code
        self.source_lines = source_code.splitlines()
        self.file_path = file_path
        self.findings: List[Finding] = []
        self.tainted_vars: Dict[str, int] = {}

        self._identify_taint_sources()
        self._track_variable_assignments()

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

    def _is_tainted(self, line: str) -> Tuple[bool, Optional[str]]:
        for var in self.tainted_vars:
            if re.search(rf'\b{re.escape(var)}\b', line):
                return True, var
        if re.search(r'\bparams\s*\[', line):
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
        self._check_path_traversal()
        self._check_ssrf()
        self._check_ssti()
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

    def _check_path_traversal(self):
        file_patterns = [
            r'File\.read\s*\(', r'File\.open\s*\(', r'File\.write\s*\(',
            r'File\.delete\s*\(', r'FileUtils\.', r'IO\.read\s*\(',
            r'send_file\s*\(', r'send_data\s*\(',
        ]

        for i, line in enumerate(self.source_lines, 1):
            if line.strip().startswith('#'):
                continue

            for pattern in file_patterns:
                if re.search(pattern, line):
                    is_tainted, taint_var = self._is_tainted(line)
                    if is_tainted:
                        self._add_finding(i, "Path Traversal - File operation with tainted path",
                                          VulnCategory.PATH_TRAVERSAL, Severity.HIGH, "HIGH", taint_var,
                                          "User input in file path.")

    def _check_ssrf(self):
        for i, line in enumerate(self.source_lines, 1):
            if line.strip().startswith('#'):
                continue

            if re.search(r'Net::HTTP\.|HTTParty\.|RestClient\.|Faraday\.|open-uri|URI\.open', line):
                is_tainted, taint_var = self._is_tainted(line)
                if is_tainted:
                    self._add_finding(i, "SSRF - HTTP request with tainted URL",
                                      VulnCategory.SSRF, Severity.HIGH, "HIGH", taint_var,
                                      "User-controlled URL in HTTP request.")

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
        '.go': 'go',
        '.rb': 'ruby',
        '.erb': 'ruby',
    }

    DEFAULT_EXCLUDES = {
        'node_modules', '.git', '__pycache__', 'venv', 'env', '.venv',
        'vendor', 'dist', 'build', '.tox', '.pytest_cache', 'site-packages',
        '.eggs', '*.egg-info', 'htmlcov', '.mypy_cache',
    }

    def __init__(self, verbose: bool = False, categories: Optional[List[str]] = None):
        self.verbose = verbose
        self.categories = categories
        self.all_findings: List[Finding] = []
        self.files_scanned = 0
        self.parse_errors = 0

    def log(self, message: str):
        """Print verbose logging."""
        if self.verbose:
            print(f"[*] {message}")

    def should_scan_file(self, file_path: Path) -> bool:
        """Check if file should be scanned."""
        # Check extension
        if file_path.suffix.lower() not in self.SUPPORTED_EXTENSIONS:
            return False

        # Check exclusions
        parts = file_path.parts
        for exclude in self.DEFAULT_EXCLUDES:
            if any(exclude.replace('*', '') in part for part in parts):
                return False

        return True

    def scan_file(self, file_path: Path) -> List[Finding]:
        """Scan a single file."""
        findings = []

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
            elif lang == 'go':
                findings = self._scan_go(source_code, str(file_path))
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

    def _scan_go(self, source_code: str, file_path: str) -> List[Finding]:
        """Scan Go source code."""
        analyzer = GoAnalyzer(source_code, file_path)
        findings = analyzer.analyze()
        return self._filter_findings(findings)

    def _scan_ruby(self, source_code: str, file_path: str) -> List[Finding]:
        """Scan Ruby source code."""
        analyzer = RubyAnalyzer(source_code, file_path)
        findings = analyzer.analyze()
        return self._filter_findings(findings)

    def _filter_findings(self, findings: List[Finding]) -> List[Finding]:
        """Filter findings by category if specified."""
        if not self.categories:
            return findings

        category_map = {
            'sql': VulnCategory.SQL_INJECTION,
            'nosql': VulnCategory.NOSQL_INJECTION,
            'code': VulnCategory.CODE_INJECTION,
            'command': VulnCategory.COMMAND_INJECTION,
            'deser': VulnCategory.DESERIALIZATION,
            'deserialization': VulnCategory.DESERIALIZATION,
            'ssti': VulnCategory.SSTI,
            'ssrf': VulnCategory.SSRF,
            'auth': VulnCategory.AUTH_BYPASS,
            'proto': VulnCategory.PROTOTYPE_POLLUTION,
            'xpath': VulnCategory.XPATH_INJECTION,
            'xxe': VulnCategory.XXE,
            'path': VulnCategory.PATH_TRAVERSAL,
            'xss': VulnCategory.XSS,
            'lfi': VulnCategory.LFI_RFI,
            'rfi': VulnCategory.LFI_RFI,
            'ldap': VulnCategory.LDAP_INJECTION,
        }

        allowed = set()
        for cat in self.categories:
            cat_lower = cat.lower()
            if cat_lower in category_map:
                allowed.add(category_map[cat_lower])
            elif cat_lower == 'all':
                return findings

        return [f for f in findings if f.category in allowed]

    def scan_directory(self, directory: Path) -> List[Finding]:
        """Recursively scan a directory."""
        findings = []

        for root, dirs, files in os.walk(directory):
            # Skip excluded directories
            dirs[:] = [d for d in dirs if d not in self.DEFAULT_EXCLUDES]

            for file in files:
                file_path = Path(root) / file
                if self.should_scan_file(file_path):
                    file_findings = self.scan_file(file_path)
                    findings.extend(file_findings)

        return findings

    def scan(self, target: str) -> List[Finding]:
        """Scan a file or directory."""
        target_path = Path(target)

        if not target_path.exists():
            print(f"Error: {target} does not exist")
            return []

        if target_path.is_file():
            findings = self.scan_file(target_path)
        else:
            findings = self.scan_directory(target_path)

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
            with open(output_file, 'w') as f:
                f.write(output)
            print(f"Report saved to {output_file}")
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


def main():
    parser = argparse.ArgumentParser(
        description='AST-Based Vulnerability Scanner - Reduces false positives through code analysis',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=textwrap.dedent('''
            Examples:
              python3 ast-scanner.py /path/to/project
              python3 ast-scanner.py app.py --verbose
              python3 ast-scanner.py /path/to/project --category sql code ssrf
              python3 ast-scanner.py /path/to/project --output json -o report.json

            Categories:
              sql       - SQL Injection
              nosql     - NoSQL Injection
              code      - Code Injection (eval, exec)
              command   - Command Injection (os.system, subprocess)
              deser     - Insecure Deserialization
              ssti      - Server-Side Template Injection
              ssrf      - Server-Side Request Forgery
              auth      - Authentication Bypass
              proto     - Prototype Pollution
              xpath     - XPath Injection
              xxe       - XML External Entity
              path      - Path Traversal
              all       - All categories (default)
        ''')
    )

    parser.add_argument('target', help='File or directory to scan')
    parser.add_argument('-v', '--verbose', action='store_true', help='Enable verbose output')
    parser.add_argument('-c', '--category', nargs='+', default=['all'],
                        help='Categories to scan (default: all)')
    parser.add_argument('--output', choices=['text', 'json'], default='text',
                        help='Output format (default: text)')
    parser.add_argument('-o', '--output-file', help='Save report to file')
    parser.add_argument('--min-confidence', choices=['HIGH', 'MEDIUM', 'LOW'], default='LOW',
                        help='Minimum confidence level to report (default: LOW)')

    args = parser.parse_args()

    # Print banner
    print("""
██╗    ██╗ ██████╗ ██████╗ ██╗     ██████╗ ████████╗██████╗ ███████╗███████╗██████╗  ██████╗ ██╗   ██╗
██║    ██║██╔═══██╗██╔══██╗██║     ██╔══██╗╚══██╔══╝██╔══██╗██╔════╝██╔════╝██╔══██╗██╔═══██╗╚██╗ ██╔╝
██║ █╗ ██║██║   ██║██████╔╝██║     ██║  ██║   ██║   ██████╔╝█████╗  █████╗  ██████╔╝██║   ██║ ╚████╔╝
██║███╗██║██║   ██║██╔══██╗██║     ██║  ██║   ██║   ██╔══██╗██╔══╝  ██╔══╝  ██╔══██╗██║   ██║  ╚██╔╝
╚███╔███╔╝╚██████╔╝██║  ██║███████╗██████╔╝   ██║   ██║  ██║███████╗███████╗██████╔╝╚██████╔╝   ██║
 ╚══╝╚══╝  ╚═════╝ ╚═╝  ╚═╝╚══════╝╚═════╝    ╚═╝   ╚═╝  ╚═╝╚══════╝╚══════╝╚═════╝  ╚═════╝    ╚═╝
                        ╔═╗╔═╗╔╦╗  ╔╗ ┌─┐┌─┐┌─┐┌┬┐  ╔═╗┌─┐┌─┐┌┐┌┌┐┌┌─┐┬─┐
                        ╠═╣╚═╗ ║   ╠╩╗├─┤└─┐├┤  ││  ╚═╗│  ├─┤││││││├┤ ├┬┘
                        ╩ ╩╚═╝ ╩   ╚═╝┴ ┴└─┘└─┘─┴┘  ╚═╝└─┘┴ ┴┘└┘┘└┘└─┘┴└─
                                   Security Scanner v2.0
                      Taint Tracking | Multi-Language | Deep Analysis
    """)

    scanner = ASTScanner(verbose=args.verbose, categories=args.category)
    findings = scanner.scan(args.target)

    # Filter by confidence
    conf_levels = {'HIGH': 3, 'MEDIUM': 2, 'LOW': 1}
    min_conf = conf_levels[args.min_confidence]
    findings = [f for f in findings if conf_levels.get(f.confidence, 0) >= min_conf]
    scanner.all_findings = findings

    scanner.print_report(output_format=args.output, output_file=args.output_file)

    # Exit with error code if critical/high findings
    critical_high = sum(1 for f in findings if f.severity in (Severity.CRITICAL, Severity.HIGH))
    sys.exit(1 if critical_high > 0 else 0)


if __name__ == '__main__':
    main()
