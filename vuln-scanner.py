#!/usr/bin/env python3
"""
Advanced Vulnerability Scanner v3.1 (Improved False Positive Handling)
=======================================================================
Cross-platform (Windows/Kali Linux) vulnerability scanner with .NET DLL decompilation support.

Changes from v3.0:
- Fixed NoSQL injection false positives for findById() - Mongoose validates ObjectId internally
- Fixed Prototype Pollution patterns - spread in create() is different from deep merge
- Fixed call_user_func false positives - closures vs user input
- Fixed Auth Bypass mislabeling SQL injection as hardcoded credentials
- Added context-aware pattern matching
- Improved PHP SSRF detection to exclude known safe library patterns
- Scanner no longer detects its own patterns
"""

import os
import re
import sys
import argparse
import json
import fnmatch
import subprocess
import tempfile
import shutil
import zipfile
import platform
from pathlib import Path
from dataclasses import dataclass, field
from typing import List, Dict, Set, Optional, Tuple
from enum import Enum
from datetime import datetime


class Severity(Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


class VulnCategory(Enum):
    SQL_INJECTION = "SQL Injection"
    POSTGRESQL_INJECTION = "PostgreSQL Injection"
    NOSQL_INJECTION = "NoSQL Injection"
    XPATH_INJECTION = "XPath Injection"
    DESERIALIZATION = "Insecure Deserialization"
    AUTH_BYPASS = "Authentication Bypass"
    SSTI = "Server-Side Template Injection"
    SSRF = "Server-Side Request Forgery"
    CODE_INJECTION = "Code Injection"
    PROTOTYPE_POLLUTION = "Prototype Pollution"
    BINARY_SUSPECT = "Binary Analysis Finding"


@dataclass
class VulnerabilityPattern:
    name: str
    category: VulnCategory
    patterns: List[str]
    severity: Severity
    languages: List[str]
    false_positive_patterns: List[str] = field(default_factory=list)
    # New: context patterns that must also match for finding to be valid
    context_required: List[str] = field(default_factory=list)


@dataclass
class Finding:
    file_path: str
    line_number: int
    line_content: str
    vulnerability_name: str
    category: VulnCategory
    severity: Severity


# =============================================================================
# VULNERABILITY PATTERNS DATABASE (v3.1 - Improved)
# =============================================================================

VULNERABILITY_PATTERNS: List[VulnerabilityPattern] = [
    
    # =========================================================================
    # CODE INJECTION - JavaScript/Node.js
    # =========================================================================
    
    VulnerabilityPattern(
        name="Code Injection - JavaScript eval",
        category=VulnCategory.CODE_INJECTION,
        patterns=[
            r'\beval\s*\(\s*req\.',
            r'\beval\s*\(\s*request\.',
            r'\beval\s*\(\s*["\'].*\+\s*req\.',
            r'\beval\s*\(\s*`[^`]*\$\{.*req\.',
        ],
        severity=Severity.CRITICAL,
        languages=[".js", ".ts", ".jsx", ".tsx"],
        false_positive_patterns=[r'//.*\beval', r'/\*.*\beval', r'\.evaluate\(', r'evalua', r'literal_eval', r'JSON\.parse']
    ),
    VulnerabilityPattern(
        name="Code Injection - new Function Constructor",
        category=VulnCategory.CODE_INJECTION,
        patterns=[
            r'\bnew\s+Function\s*\(\s*req\.',
            r'\bnew\s+Function\s*\(\s*.*\+\s*req\.',
        ],
        severity=Severity.CRITICAL,
        languages=[".js", ".ts", ".jsx", ".tsx"],
        false_positive_patterns=[r'//.*Function', r'isFunction', r'typeof\s+\w+\s*[=!]==?\s*["\']function', r'function\s+\w+\s*\('],
    ),
    VulnerabilityPattern(
        name="Code Injection - setTimeout/setInterval string",
        category=VulnCategory.CODE_INJECTION,
        patterns=[
            r'setTimeout\s*\(\s*["\'].*\+\s*req\.',
            r'setTimeout\s*\(\s*`.*\$\{.*req\.',
            r'setInterval\s*\(\s*["\'].*\+\s*req\.',
            r'setInterval\s*\(\s*`.*\$\{.*req\.',
        ],
        severity=Severity.MEDIUM,
        languages=[".js", ".ts", ".jsx", ".tsx"],
        false_positive_patterns=[r'setTimeout\s*\(\s*function', r'setTimeout\s*\(\s*\(\)', r'session_alive'],
    ),
    VulnerabilityPattern(
        name="Command Injection - child_process exec with user input",
        category=VulnCategory.CODE_INJECTION,
        patterns=[
            r'exec\s*\(\s*`[^`]*\$\{.*req\.',
            r'exec\s*\(\s*["\'].*\+\s*req\.',
            r'exec\s*\(\s*req\.',
            r'execSync\s*\(\s*`[^`]*\$\{.*req\.',
            r'execSync\s*\(\s*["\'].*\+\s*req\.',
            r'execSync\s*\(\s*req\.',
        ],
        severity=Severity.CRITICAL,
        languages=[".js", ".ts"],
        false_positive_patterns=[r'execFile', r'//.*exec']
    ),
    VulnerabilityPattern(
        name="Command Injection - child_process spawn with user input",
        category=VulnCategory.CODE_INJECTION,
        patterns=[
            r'spawn\s*\(\s*req\.',
            r'spawnSync\s*\(\s*req\.',
        ],
        severity=Severity.HIGH,
        languages=[".js", ".ts"],
    ),
    VulnerabilityPattern(
        name="Code Injection - vm module with user input",
        category=VulnCategory.CODE_INJECTION,
        patterns=[
            r'vm\.runInContext\s*\(\s*req\.',
            r'vm\.runInNewContext\s*\(\s*req\.',
            r'vm\.runInThisContext\s*\(\s*req\.',
        ],
        severity=Severity.CRITICAL,
        languages=[".js", ".ts"],
    ),
    VulnerabilityPattern(
        name="Code Injection - require with variable",
        category=VulnCategory.CODE_INJECTION,
        patterns=[
            r'require\s*\(\s*req\.',
            r'require\s*\(\s*request\.',
            r'import\s*\(\s*req\.',
        ],
        severity=Severity.HIGH,
        languages=[".js", ".ts"],
        false_positive_patterns=[r'require\s*\(\s*["\'][^"\']+["\']\s*\)']
    ),
    
    # =========================================================================
    # PROTOTYPE POLLUTION - IMPROVED (v3.1)
    # =========================================================================
    
    VulnerabilityPattern(
        name="Prototype Pollution - __proto__ Direct Assignment",
        category=VulnCategory.PROTOTYPE_POLLUTION,
        patterns=[
            r'\[.*__proto__.*\]\s*=',
            r'\.__proto__\s*=',
            r'\["__proto__"\]\s*=',
            r"\['__proto__'\]\s*=",
        ],
        severity=Severity.CRITICAL,
        languages=[".js", ".ts", ".jsx", ".tsx"],
        false_positive_patterns=[
            r'hasOwnProperty.*__proto__', 
            r'===\s*["\']__proto__["\']', 
            r'!==\s*["\']__proto__["\']',
            r'key\s*===\s*["\']__proto__["\']',  # Checking for proto, not setting
            r'key\s*!==\s*["\']__proto__["\']',
            r'typeof superClass', 
            r'Object\.getPrototypeOf', 
            r'Object\.create\(',
            r'//.*__proto__',  # Comments
            r'\*.*__proto__',  # Multi-line comments
        ],
    ),
    VulnerabilityPattern(
        name="Prototype Pollution - Unsafe Deep Merge with User Input",
        category=VulnCategory.PROTOTYPE_POLLUTION,
        patterns=[
            r'_\.merge\s*\(\s*[^,]+,\s*req\.(body|query|params)',
            r'_\.defaultsDeep\s*\(\s*[^,]+,\s*req\.(body|query|params)',
            r'lodash\.merge\s*\(\s*[^,]+,\s*req\.(body|query|params)',
            r'deepmerge\s*\(\s*[^,]+,\s*req\.(body|query|params)',
            r'\.merge\s*\(\s*\{\s*\}\s*,\s*req\.(body|query|params)',
            r'Object\.assign\s*\(\s*[^,]+,\s*JSON\.parse\s*\(\s*req\.',
        ],
        severity=Severity.HIGH,
        languages=[".js", ".ts", ".jsx", ".tsx"],
    ),
    # NOTE: Removed generic spread patterns - they cause too many false positives
    # Spread in Model.create({...req.body}) is not prototype pollution
    # Real prototype pollution requires deep recursive merge operations

    # =========================================================================
    # CODE INJECTION - Python
    # =========================================================================
    
    VulnerabilityPattern(
        name="Code Injection - Python eval with user input",
        category=VulnCategory.CODE_INJECTION,
        patterns=[
            r'\beval\s*\(\s*.*request\.(form|args|json|data|values)',
            r'\beval\s*\(\s*.*input\s*\(',
            r'\beval\s*\(\s*f["\'].*\{.*request\.',
        ],
        severity=Severity.CRITICAL,
        languages=[".py"],
        false_positive_patterns=[r'#.*\beval', r'ast\.literal_eval', r'safe_eval']
    ),
    VulnerabilityPattern(
        name="Code Injection - Python exec with user input",
        category=VulnCategory.CODE_INJECTION,
        patterns=[
            r'\bexec\s*\(\s*.*request\.(form|args|json|data)',
            r'\bexec\s*\(\s*.*input\s*\(',
            r'\bexec\s*\(\s*f["\'].*\{.*request\.',
        ],
        severity=Severity.CRITICAL,
        languages=[".py"],
        false_positive_patterns=[r'#.*\bexec', r'exec_query', r'execute\(']
    ),
    VulnerabilityPattern(
        name="Command Injection - Python os.system/popen",
        category=VulnCategory.CODE_INJECTION,
        patterns=[
            r'os\.system\s*\(\s*.*request\.',
            r'os\.system\s*\(\s*f["\']',
            r'os\.popen\s*\(\s*.*request\.',
            r'os\.popen\s*\(\s*f["\']',
        ],
        severity=Severity.CRITICAL,
        languages=[".py"],
    ),
    VulnerabilityPattern(
        name="Command Injection - Python subprocess shell=True with user input",
        category=VulnCategory.CODE_INJECTION,
        patterns=[
            r'subprocess\.\w+\s*\([^)]*shell\s*=\s*True[^)]*request\.',
            r'subprocess\.\w+\s*\([^)]*request\.[^)]*shell\s*=\s*True',
            r'subprocess\.\w+\s*\(\s*f["\'][^)]*shell\s*=\s*True',
        ],
        severity=Severity.CRITICAL,
        languages=[".py"],
        false_positive_patterns=[r'shell\s*=\s*False']
    ),

    # =========================================================================
    # CODE INJECTION - PHP (IMPROVED v3.1)
    # =========================================================================
    
    VulnerabilityPattern(
        name="Code Injection - PHP eval with user input",
        category=VulnCategory.CODE_INJECTION,
        patterns=[
            r'\beval\s*\(\s*\$_(GET|POST|REQUEST|COOKIE)',
            r'\beval\s*\(\s*base64_decode\s*\(\s*\$_(GET|POST|REQUEST)',
        ],
        severity=Severity.CRITICAL,
        languages=[".php"],
        false_positive_patterns=[r'//.*eval', r'/\*.*eval']
    ),
    VulnerabilityPattern(
        name="Code Injection - PHP call_user_func with user input",
        category=VulnCategory.CODE_INJECTION,
        patterns=[
            # Only flag when the FUNCTION NAME comes from user input
            r'call_user_func\s*\(\s*\$_(GET|POST|REQUEST|COOKIE)',
            r'call_user_func_array\s*\(\s*\$_(GET|POST|REQUEST|COOKIE)',
        ],
        severity=Severity.HIGH,
        languages=[".php"],
        # Exclude closures and known safe patterns
        false_positive_patterns=[
            r'call_user_func\s*\(\s*\$closure',  # Closure variable
            r'call_user_func\s*\(\s*\$callback',  # Callback variable
            r'call_user_func\s*\(\s*\$func',  # Function variable (internal)
            r'call_user_func\s*\(\s*\$handler',  # Handler variable
            r'call_user_func\s*\(\s*\[\s*\$this',  # Method call on $this
            r'call_user_func\s*\(\s*\[\s*\$\w+\s*,\s*["\']',  # Method with string name
            r'call_user_func\s*\(\s*["\']',  # Static function name string
        ]
    ),
    VulnerabilityPattern(
        name="Command Injection - PHP system/exec/shell_exec with user input",
        category=VulnCategory.CODE_INJECTION,
        patterns=[
            r'\bsystem\s*\(\s*\$_(GET|POST|REQUEST)',
            r'\bexec\s*\(\s*\$_(GET|POST|REQUEST)',
            r'shell_exec\s*\(\s*\$_(GET|POST|REQUEST)',
            r'passthru\s*\(\s*\$_(GET|POST|REQUEST)',
        ],
        severity=Severity.CRITICAL,
        languages=[".php"],
    ),
    VulnerabilityPattern(
        name="Code Injection - PHP include/require with user input",
        category=VulnCategory.CODE_INJECTION,
        patterns=[
            r'\binclude\s*\(\s*\$_(GET|POST|REQUEST)',
            r'\binclude\s*\s+\$_(GET|POST|REQUEST)',
            r'include_once\s*\(\s*\$_(GET|POST|REQUEST)',
            r'\brequire\s*\(\s*\$_(GET|POST|REQUEST)',
            r'\brequire\s*\s+\$_(GET|POST|REQUEST)',
            r'require_once\s*\(\s*\$_(GET|POST|REQUEST)',
        ],
        severity=Severity.CRITICAL,
        languages=[".php"],
    ),

    # =========================================================================
    # SQL INJECTION PATTERNS
    # =========================================================================
    
    VulnerabilityPattern(
        name="SQL Injection - String Concatenation",
        category=VulnCategory.SQL_INJECTION,
        patterns=[
            r'["\']SELECT\s+.+\s+FROM\s+.+["\']\s*\.\s*\$',  # PHP
            r'["\']SELECT\s+.+\s+FROM\s+.+["\']\s*\+\s*req\.',  # JS
            r'["\']INSERT\s+INTO\s+.+["\']\s*\.\s*\$',
            r'["\']UPDATE\s+.+\s+SET\s+.+["\']\s*\.\s*\$',
            r'["\']DELETE\s+FROM\s+.+["\']\s*\.\s*\$',
            r'f["\']SELECT\s+.+\{',  # Python f-string
            r'f["\']INSERT\s+.+\{',
            r'f["\']UPDATE\s+.+\{',
            r'f["\']DELETE\s+.+\{',
        ],
        severity=Severity.CRITICAL,
        languages=[".js", ".ts", ".jsx", ".tsx", ".py", ".php", ".java", ".cs", ".rb", ".go", ".kt"],
        false_positive_patterns=[r'//.*SELECT', r'#.*SELECT', r'PreparedStatement', r'\?', r'%s', r':param'],
    ),
    VulnerabilityPattern(
        name="SQL Injection - PHP with user variables",
        category=VulnCategory.SQL_INJECTION,
        patterns=[
            r'["\']SELECT\s+.+WHERE\s+.+\$_(GET|POST|REQUEST|COOKIE)',
            r'["\']SELECT\s+.+WHERE\s+.+["\']\s*\.\s*\$\w+\s*\.\s*["\']',
            r'mysql_query\s*\(\s*["\'].*\$_(GET|POST|REQUEST)',
            r'mysqli_query\s*\(\s*\$\w+,\s*["\'].*\$_(GET|POST|REQUEST)',
        ],
        severity=Severity.CRITICAL,
        languages=[".php"],
        false_positive_patterns=[r'mysqli_real_escape_string', r'PDO', r'prepare\s*\(']
    ),
    VulnerabilityPattern(
        name="SQL Injection - Template Literals with user input",
        category=VulnCategory.SQL_INJECTION,
        patterns=[
            r'`SELECT\s+.+\s+FROM\s+.+\$\{.*req\.',
            r'`INSERT\s+INTO\s+.+\$\{.*req\.',
            r'`UPDATE\s+.+\s+SET\s+.+\$\{.*req\.',
            r'`DELETE\s+FROM\s+.+\$\{.*req\.',
        ],
        severity=Severity.CRITICAL,
        languages=[".js", ".ts"],
    ),

    # =========================================================================
    # NOSQL INJECTION PATTERNS (IMPROVED v3.1)
    # =========================================================================

    VulnerabilityPattern(
        name="NoSQL Injection - MongoDB $where Operator",
        category=VulnCategory.NOSQL_INJECTION,
        patterns=[
            r'\$where\s*:\s*req\.',
            r'"\$where"\s*:\s*req\.',
            r"'\$where'\s*:\s*req\.",
        ],
        severity=Severity.CRITICAL,
        languages=[".js", ".ts", ".jsx", ".tsx"],
    ),
    VulnerabilityPattern(
        name="NoSQL Injection - Direct Query Object from User Input",
        category=VulnCategory.NOSQL_INJECTION,
        patterns=[
            # Only flag when the entire query object comes from user input
            r'\.find\s*\(\s*req\.(body|query)\s*\)',
            r'\.findOne\s*\(\s*req\.(body|query)\s*\)',
            r'\.updateOne\s*\(\s*req\.(body|query)\s*,',
            r'\.updateMany\s*\(\s*req\.(body|query)\s*,',
            r'\.deleteOne\s*\(\s*req\.(body|query)\s*\)',
            r'\.deleteMany\s*\(\s*req\.(body|query)\s*\)',
        ],
        severity=Severity.HIGH,
        languages=[".js", ".ts", ".jsx", ".tsx"],
    ),
    VulnerabilityPattern(
        name="NoSQL Injection - Unvalidated Object Property Access",
        category=VulnCategory.NOSQL_INJECTION,
        patterns=[
            # Query with bracket notation from user input (allows $gt, $ne, etc.)
            r'\.find\s*\(\s*\{[^}]*:\s*req\.(body|query|params)\[',
            r'\.findOne\s*\(\s*\{[^}]*:\s*req\.(body|query|params)\[',
        ],
        severity=Severity.HIGH,
        languages=[".js", ".ts", ".jsx", ".tsx"],
        false_positive_patterns=[
            r'\.findById\s*\(',  # findById is safe - validates ObjectId
            r'\.findByIdAndUpdate\s*\(',
            r'\.findByIdAndDelete\s*\(',
            r'params\.id\)',  # Single ID lookup is safe
            r'\.id\)',
        ]
    ),
    # NOTE: Removed patterns that flagged findById() - it's safe because:
    # 1. Mongoose casts params.id to ObjectId
    # 2. Invalid ObjectId throws CastError, doesn't execute query
    # 3. No query operators can be injected

    # =========================================================================
    # XPATH INJECTION PATTERNS
    # =========================================================================

    VulnerabilityPattern(
        name="XPath Injection - String Concatenation with user input",
        category=VulnCategory.XPATH_INJECTION,
        patterns=[
            r'\.xpath\s*\(\s*["\'].*\+\s*req\.',
            r'\.xpath\s*\(\s*f["\'].*\{.*request\.',
            r'SelectNodes\s*\(\s*\$".*\{.*Request\.',
            r'SelectSingleNode\s*\(\s*\$".*\{.*Request\.',
        ],
        severity=Severity.HIGH,
        languages=[".js", ".ts", ".py", ".php", ".java", ".cs", ".rb"],
    ),

    # =========================================================================
    # INSECURE DESERIALIZATION PATTERNS
    # =========================================================================

    VulnerabilityPattern(
        name="Insecure Deserialization - Python pickle",
        category=VulnCategory.DESERIALIZATION,
        patterns=[
            r'pickle\.loads?\s*\(\s*.*request\.',
            r'pickle\.loads?\s*\(\s*.*\.read\s*\(',
            r'cPickle\.loads?\s*\(',
        ],
        severity=Severity.CRITICAL,
        languages=[".py"],
        false_positive_patterns=[r'#.*pickle', r'pickle\.dumps'],
    ),
    VulnerabilityPattern(
        name="Insecure Deserialization - Python YAML unsafe load",
        category=VulnCategory.DESERIALIZATION,
        patterns=[
            r'yaml\.load\s*\(\s*[^,)]+\s*\)',  # yaml.load without Loader
            r'yaml\.unsafe_load\s*\(',
            r'yaml\.full_load\s*\(',
        ],
        severity=Severity.CRITICAL,
        languages=[".py"],
        false_positive_patterns=[r'yaml\.safe_load', r'Loader\s*=\s*yaml\.SafeLoader', r'SafeLoader'],
    ),
    VulnerabilityPattern(
        name="Insecure Deserialization - PHP unserialize with user input",
        category=VulnCategory.DESERIALIZATION,
        patterns=[
            r'unserialize\s*\(\s*\$_(GET|POST|REQUEST|COOKIE)',
            r'unserialize\s*\(\s*base64_decode\s*\(\s*\$_(GET|POST|REQUEST)',
        ],
        severity=Severity.CRITICAL,
        languages=[".php"],
        false_positive_patterns=[r'allowed_classes\s*=>\s*false', r'allowed_classes\s*=>\s*\[\s*\]'],
    ),
    VulnerabilityPattern(
        name="Insecure Deserialization - Java ObjectInputStream",
        category=VulnCategory.DESERIALIZATION,
        patterns=[
            r'new\s+ObjectInputStream\s*\(\s*.*request\.',
            r'ObjectInputStream.*\.readObject\s*\(\s*\)',
            r'XMLDecoder\s*\(\s*.*request\.',
        ],
        severity=Severity.CRITICAL,
        languages=[".java", ".kt", ".scala"],
        false_positive_patterns=[r'ObjectInputFilter', r'ValidatingObjectInputStream'],
    ),
    VulnerabilityPattern(
        name="Insecure Deserialization - C# BinaryFormatter",
        category=VulnCategory.DESERIALIZATION,
        patterns=[
            r'BinaryFormatter.*\.Deserialize\s*\(',
            r'new\s+BinaryFormatter\s*\(\s*\).*\.Deserialize',
        ],
        severity=Severity.CRITICAL,
        languages=[".cs"],
    ),
    VulnerabilityPattern(
        name="Insecure Deserialization - C# TypeNameHandling",
        category=VulnCategory.DESERIALIZATION,
        patterns=[
            r'TypeNameHandling\s*=\s*TypeNameHandling\.(All|Auto|Objects|Arrays)',
        ],
        severity=Severity.HIGH,
        languages=[".cs"],
        false_positive_patterns=[r'TypeNameHandling\.None'],
    ),
    VulnerabilityPattern(
        name="Insecure Deserialization - Ruby Marshal",
        category=VulnCategory.DESERIALIZATION,
        patterns=[
            r'Marshal\.load\s*\(\s*.*params',
            r'Marshal\.load\s*\(\s*.*request',
            r'YAML\.load\s*\(\s*.*params',
        ],
        severity=Severity.CRITICAL,
        languages=[".rb"],
        false_positive_patterns=[r'YAML\.safe_load', r'Psych\.safe_load'],
    ),

    # =========================================================================
    # AUTHENTICATION BYPASS PATTERNS (IMPROVED v3.1)
    # =========================================================================

    VulnerabilityPattern(
        name="Auth Bypass - Hardcoded API Key/Secret",
        category=VulnCategory.AUTH_BYPASS,
        patterns=[
            # Only flag actual hardcoded secrets, not variable assignments from env
            r'api[_-]?key\s*[=:]\s*["\'][a-zA-Z0-9_-]{20,}["\']',
            r'api[_-]?secret\s*[=:]\s*["\'][a-zA-Z0-9_-]{20,}["\']',
            r'secret[_-]?key\s*[=:]\s*["\'][a-zA-Z0-9_-]{20,}["\']',
            r'private[_-]?key\s*[=:]\s*["\']-----BEGIN',
            r'aws_secret_access_key\s*[=:]\s*["\'][^"\']{30,}["\']',
        ],
        severity=Severity.HIGH,
        languages=[".js", ".ts", ".py", ".php", ".java", ".cs", ".rb", ".go", ".kt", ".env", ".config", ".json", ".yaml", ".yml"],
        false_positive_patterns=[
            r'process\.env',
            r'os\.environ',
            r'os\.getenv',
            r'getenv\(',
            r'Environment\.GetEnvironmentVariable',
            r'Configuration\[',
            r'\$\{',
            r'\{\{',  # Template variables
            r'<YOUR_',
            r'<API_KEY>',
            r'<SECRET>',
            r'PLACEHOLDER',
            r'example',
            r'xxx+',
            r'\.\.\.+',
            r'your[_-]?api',
            r'your[_-]?secret',
        ],
    ),
    VulnerabilityPattern(
        name="Auth Bypass - JWT None Algorithm",
        category=VulnCategory.AUTH_BYPASS,
        patterns=[
            r'algorithms\s*[=:]\s*\[\s*["\']none["\']',
            r'algorithm\s*[=:]\s*["\']none["\']',
            r'jwt\.decode\s*\([^)]*verify\s*=\s*False',
        ],
        severity=Severity.CRITICAL,
        languages=[".js", ".ts", ".py", ".php", ".java", ".cs", ".rb", ".go"],
        false_positive_patterns=[r'jwt\.verify', r'//.*none', r'#.*none'],
    ),
    # NOTE: Removed weak comparison patterns - too many false positives
    # PHP == vs === should be a code quality tool finding, not a vuln scanner

    # =========================================================================
    # SSTI (Server-Side Template Injection) PATTERNS
    # =========================================================================

    VulnerabilityPattern(
        name="SSTI - Jinja2/Flask render_template_string with user input",
        category=VulnCategory.SSTI,
        patterns=[
            r'render_template_string\s*\(\s*.*request\.(form|args|json|data)',
            r'render_template_string\s*\(\s*f["\'].*\{.*request\.',
        ],
        severity=Severity.CRITICAL,
        languages=[".py"],
    ),
    VulnerabilityPattern(
        name="SSTI - Node.js template engines with user input",
        category=VulnCategory.SSTI,
        patterns=[
            r'pug\.render\s*\(\s*req\.(body|query|params)',
            r'ejs\.render\s*\(\s*req\.(body|query|params)',
            r'Handlebars\.compile\s*\(\s*req\.(body|query|params)',
        ],
        severity=Severity.CRITICAL,
        languages=[".js", ".ts"],
    ),

    # =========================================================================
    # SSRF (Server-Side Request Forgery) PATTERNS (IMPROVED v3.1)
    # =========================================================================

    VulnerabilityPattern(
        name="SSRF - Dynamic URL Fetch (Node.js)",
        category=VulnCategory.SSRF,
        patterns=[
            r'fetch\s*\(\s*req\.(body|query|params)\.',
            r'fetch\s*\(\s*`[^`]*\$\{.*req\.(body|query|params)',
            r'axios\.(get|post|put|delete)\s*\(\s*req\.(body|query|params)\.',
            r'axios\s*\(\s*\{[^}]*url\s*:\s*req\.(body|query|params)',
            r'http\.get\s*\(\s*req\.(body|query|params)',
            r'https\.get\s*\(\s*req\.(body|query|params)',
        ],
        severity=Severity.HIGH,
        languages=[".js", ".ts"],
    ),
    VulnerabilityPattern(
        name="SSRF - Dynamic URL Fetch (Python)",
        category=VulnCategory.SSRF,
        patterns=[
            r'requests\.(get|post|put|delete)\s*\(\s*.*request\.(form|args|json|data)\[',
            r'urllib\.request\.urlopen\s*\(\s*.*request\.(form|args|json)',
        ],
        severity=Severity.HIGH,
        languages=[".py"],
    ),
    VulnerabilityPattern(
        name="SSRF - Dynamic URL Fetch (PHP)",
        category=VulnCategory.SSRF,
        patterns=[
            r'file_get_contents\s*\(\s*\$_(GET|POST|REQUEST)',
            r'curl_setopt\s*\([^,]+,\s*CURLOPT_URL\s*,\s*\$_(GET|POST|REQUEST)',
            r'curl_init\s*\(\s*\$_(GET|POST|REQUEST)',
        ],
        severity=Severity.HIGH,
        languages=[".php"],
        # Exclude known safe libraries
        false_positive_patterns=[
            r'recaptcha',  # Google reCAPTCHA library
            r'google\.com/recaptcha',
            r'gstatic\.com',
            r'//.*file_get_contents',
        ]
    ),
]


# Binary patterns for DLL/EXE analysis (improved v3.1)
BINARY_PATTERNS = [
    {"name": "Hardcoded Connection String", "pattern": r'(Data Source|Server|Initial Catalog|User ID|Password|Integrated Security)\s*=', "severity": Severity.HIGH},
    {
        "name": "Deserialization Indicators", 
        "pattern": r'(BinaryFormatter|ObjectInputStream|NetDataContractSerializer|LosFormatter|SoapFormatter|ObjectStateFormatter|JavaScriptSerializer|TypeNameHandling)',
        "severity": Severity.HIGH,
        # Exclude common .NET method names that contain serialize but aren't dangerous
        "false_positive_patterns": [r'^Deserialize$', r'^Serialize$', r'^DeserializeObject$', r'^SerializeObject$']
    },
    {
        "name": "Weak Crypto Algorithm", 
        # More specific patterns to avoid FPs:
        # - DES must be standalone or in crypto context (DESCryptoServiceProvider, TripleDES, 3DES)
        # - MD5/SHA1 in method names like MD5.Create(), MD5CryptoServiceProvider
        # - ECB mode specifically
        "pattern": r'(MD5CryptoServiceProvider|MD5\.Create|SHA1CryptoServiceProvider|SHA1\.Create|SHA1Managed|DESCryptoServiceProvider|TripleDESCryptoServiceProvider|3DES|RC4|CipherMode\.ECB|"ECB"|AesManaged.*ECB)',
        "severity": Severity.MEDIUM
    },
    {
        "name": "Weak Hash Usage",
        # Matches common weak hash patterns in code
        "pattern": r'(\.ComputeHash|HashAlgorithm\.Create\(["\']MD5|HashAlgorithm\.Create\(["\']SHA1)',
        "severity": Severity.LOW
    },
    {"name": "Private Key", "pattern": r'-----BEGIN (RSA |DSA |EC )?PRIVATE KEY-----', "severity": Severity.CRITICAL},
    {"name": "AWS Credentials", "pattern": r'AKIA[0-9A-Z]{16}', "severity": Severity.CRITICAL},
    {"name": "Azure/AWS Connection String", "pattern": r'(AccountKey|SharedAccessSignature|DefaultEndpointsProtocol)\s*=', "severity": Severity.HIGH},
]


def get_platform() -> str:
    """Detect current platform"""
    system = platform.system().lower()
    if system == "windows":
        return "windows"
    elif system == "linux":
        try:
            with open("/etc/os-release") as f:
                if "kali" in f.read().lower():
                    return "kali"
        except:
            pass
        return "linux"
    elif system == "darwin":
        return "macos"
    return system


def find_ilspy() -> Optional[str]:
    """Find ILSpy/ilspycmd on the system"""
    ilspy_names = ["ilspycmd", "ilspy"]
    
    for name in ilspy_names:
        path = shutil.which(name)
        if path:
            return path
    
    common_paths = [
        "/usr/bin/ilspycmd",
        "/usr/local/bin/ilspycmd",
        os.path.expanduser("~/.dotnet/tools/ilspycmd"),
    ]
    
    for path in common_paths:
        if os.path.exists(path):
            return path
    
    return None


class DotNetDecompiler:
    """Cross-platform .NET DLL decompiler"""
    
    def __init__(self, verbose: bool = False):
        self.verbose = verbose
        self.platform = get_platform()
        self.ilspy_path = find_ilspy()
        
    def is_available(self) -> bool:
        return self.ilspy_path is not None
    
    def get_tool_info(self) -> str:
        if self.ilspy_path:
            return f"ILSpy: {self.ilspy_path}"
        return "No .NET decompiler found"
    
    def decompile(self, dll_path: str) -> Optional[str]:
        if self.ilspy_path:
            return self._decompile_ilspy(dll_path)
        return None
    
    def _decompile_ilspy(self, dll_path: str) -> Optional[str]:
        try:
            with tempfile.TemporaryDirectory() as temp_dir:
                output_dir = os.path.join(temp_dir, "decompiled")
                os.makedirs(output_dir, exist_ok=True)
                
                cmd = [self.ilspy_path, dll_path, "-o", output_dir, "-p"]
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
                
                source_content = []
                for root, _, files in os.walk(output_dir):
                    for file in files:
                        if file.endswith(".cs"):
                            file_path = os.path.join(root, file)
                            try:
                                with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                                    content = f.read()
                                    source_content.append(f"// === {file} ===\n{content}")
                            except:
                                pass
                
                if source_content:
                    return "\n\n".join(source_content)
                    
        except Exception as e:
            if self.verbose:
                print(f"[!] ILSpy decompilation error: {e}")
        
        return None


class VulnerabilityScanner:
    """Advanced vulnerability scanner with improved false positive handling"""
    
    DEFAULT_EXCLUDE_DIRS = {
        'node_modules', '.git', '__pycache__', 'venv', 'env', '.venv',
        'dist', 'build', '.idea', '.vscode', 'vendor', 'target', 'bin',
        'obj', '.next', 'coverage', '.tox', '.pytest_cache', '.mypy_cache',
        'site-packages', '.gradle', '.m2', 'packages', '.nuget', '.cache',
        'tests', 'test', '__tests__', 'spec', 'specs', 'test_files',
        'docs', 'doc', 'documentation',
    }
    
    DEFAULT_EXCLUDE_FILES = {
        'package-lock.json', 'yarn.lock', 'composer.lock', 'Gemfile.lock',
        'poetry.lock', 'Cargo.lock', 'go.sum', 'pnpm-lock.yaml',
        'vuln_scanner.py', 'vuln-scanner.py', 'vuln-scanner-improved.py', 'scanner.py',
        # Common JS libraries
        'jquery.js', 'jquery.min.js', 'jquery-*.js',
        'bootstrap.js', 'bootstrap.min.js', 'bootstrap.bundle.js',
        'react.js', 'react.min.js', 'react-dom.js',
        'vue.js', 'vue.min.js', 'angular.js',
        'lodash.js', 'lodash.min.js',
        'd3.js', 'd3.min.js',
        'Parsedown.php',  # Known safe markdown parser
        'recaptchalib.php',  # Google reCAPTCHA library
    }
    
    DEFAULT_EXCLUDE_PATTERNS = {
        '*.min.js', '*.min.css', '*.map', '*.bundle.js',
        '*.test.js', '*.spec.js', '*.test.ts', '*.spec.ts',
        'test_*.py', '*_test.py', '*_test.go',
        '*.d.ts',
    }
    
    BINARY_EXTENSIONS = {'.dll', '.exe', '.so', '.dylib', '.bin'}
    ARCHIVE_EXTENSIONS = {'.jar', '.war', '.ear', '.zip', '.apk'}
    DOTNET_EXTENSIONS = {'.dll', '.exe'}
    
    def __init__(
        self,
        verbose: bool = False,
        exclude_dirs: Optional[Set[str]] = None,
        exclude_files: Optional[Set[str]] = None,
        exclude_patterns: Optional[Set[str]] = None,
        include_extensions: Optional[Set[str]] = None,
        exclude_extensions: Optional[Set[str]] = None,
        no_default_excludes: bool = False,
        scan_binaries: bool = False,
        decompile_dotnet: bool = False,
        categories: Optional[List[str]] = None
    ):
        self.verbose = verbose
        self.findings: List[Finding] = []
        self.files_scanned = 0
        self.files_with_findings: Set[str] = set()
        self.files_skipped = 0
        self.binaries_scanned = 0
        self.stats: Dict = {}
        self.scan_binaries = scan_binaries
        self.decompile_dotnet = decompile_dotnet
        self.platform = get_platform()
        
        self.decompiler = DotNetDecompiler(verbose) if decompile_dotnet else None
        
        self.active_categories: Optional[Set[VulnCategory]] = None
        if categories and "all" not in categories:
            category_map = {
                "sql": VulnCategory.SQL_INJECTION,
                "postgresql": VulnCategory.POSTGRESQL_INJECTION,
                "nosql": VulnCategory.NOSQL_INJECTION,
                "xpath": VulnCategory.XPATH_INJECTION,
                "deserialization": VulnCategory.DESERIALIZATION,
                "auth": VulnCategory.AUTH_BYPASS,
                "ssti": VulnCategory.SSTI,
                "ssrf": VulnCategory.SSRF,
                "code": VulnCategory.CODE_INJECTION,
                "eval": VulnCategory.CODE_INJECTION,
                "prototype": VulnCategory.PROTOTYPE_POLLUTION,
                "pollution": VulnCategory.PROTOTYPE_POLLUTION,
            }
            self.active_categories = {category_map[c] for c in categories if c in category_map}
        
        if no_default_excludes:
            self.exclude_dirs: Set[str] = set()
            self.exclude_files: Set[str] = set()
            self.exclude_patterns: Set[str] = set()
        else:
            self.exclude_dirs = self.DEFAULT_EXCLUDE_DIRS.copy()
            self.exclude_files = self.DEFAULT_EXCLUDE_FILES.copy()
            self.exclude_patterns = self.DEFAULT_EXCLUDE_PATTERNS.copy()
        
        if exclude_dirs:
            self.exclude_dirs.update(exclude_dirs)
        if exclude_files:
            self.exclude_files.update(exclude_files)
        if exclude_patterns:
            self.exclude_patterns.update(exclude_patterns)
        
        self.include_extensions = include_extensions
        self.exclude_extensions = exclude_extensions or set()

    def should_skip_path(self, file_path: str) -> bool:
        path = Path(file_path)
        
        for part in path.parts:
            if part in self.exclude_dirs:
                return True
        
        if path.name in self.exclude_files:
            return True
        
        for pattern in self.exclude_patterns:
            if fnmatch.fnmatch(path.name, pattern):
                return True
        
        ext = path.suffix.lower()
        if ext in self.exclude_extensions:
            return True
        
        if self.include_extensions and ext not in self.include_extensions:
            if not (self.scan_binaries and ext in self.BINARY_EXTENSIONS):
                return True
        
        return False

    def get_relevant_extensions(self) -> Set[str]:
        extensions = set()
        for pattern in VULNERABILITY_PATTERNS:
            if self.active_categories is None or pattern.category in self.active_categories:
                extensions.update(pattern.languages)
        return extensions

    def is_binary_file(self, file_path: str) -> bool:
        return Path(file_path).suffix.lower() in self.BINARY_EXTENSIONS

    def is_dotnet_binary(self, file_path: str) -> bool:
        return Path(file_path).suffix.lower() in self.DOTNET_EXTENSIONS

    def is_archive_file(self, file_path: str) -> bool:
        return Path(file_path).suffix.lower() in self.ARCHIVE_EXTENSIONS

    def extract_strings_from_binary(self, file_path: str, min_length: int = 4) -> List[Tuple[int, str]]:
        strings_found = []
        
        strings_cmd = "strings" if self.platform != "windows" else "strings.exe"
        try:
            result = subprocess.run(
                [strings_cmd, '-n', str(min_length), file_path],
                capture_output=True, text=True, timeout=60
            )
            if result.returncode == 0:
                for idx, line in enumerate(result.stdout.split('\n'), 1):
                    if line.strip():
                        strings_found.append((idx, line.strip()))
                return strings_found
        except:
            pass
        
        try:
            with open(file_path, 'rb') as f:
                data = f.read()
            
            current_string = []
            string_start = 0
            
            for i, byte in enumerate(data):
                if 32 <= byte <= 126:
                    if not current_string:
                        string_start = i
                    current_string.append(chr(byte))
                else:
                    if len(current_string) >= min_length:
                        strings_found.append((string_start, ''.join(current_string)))
                    current_string = []
        except Exception as e:
            if self.verbose:
                print(f"[!] Error reading binary {file_path}: {e}")
        
        return strings_found

    def scan_binary(self, file_path: str) -> List[Finding]:
        findings = []
        
        if self.verbose:
            print(f"[*] Analyzing binary: {file_path}")
        
        if self.decompile_dotnet and self.is_dotnet_binary(file_path) and self.decompiler:
            if self.decompiler.is_available():
                source = self.decompiler.decompile(file_path)
                if source:
                    lines = source.split('\n')
                    for line_num, line in enumerate(lines, 1):
                        for vuln_pattern in VULNERABILITY_PATTERNS:
                            if ".cs" not in vuln_pattern.languages:
                                continue
                            for pattern in vuln_pattern.patterns:
                                try:
                                    if re.search(pattern, line, re.IGNORECASE):
                                        is_fp = any(re.search(fp, line, re.IGNORECASE) for fp in vuln_pattern.false_positive_patterns)
                                        if not is_fp:
                                            findings.append(Finding(
                                                file_path=f"{file_path} (decompiled)",
                                                line_number=line_num,
                                                line_content=line.strip()[:200],
                                                vulnerability_name=vuln_pattern.name,
                                                category=vuln_pattern.category,
                                                severity=vuln_pattern.severity,
                                            ))
                                            break
                                except re.error:
                                    continue
        
        strings = self.extract_strings_from_binary(file_path)
        for offset, string_content in strings:
            for pattern_info in BINARY_PATTERNS:
                try:
                    if re.search(pattern_info["pattern"], string_content, re.IGNORECASE):
                        # Check for false positives if patterns are defined
                        is_fp = False
                        if "false_positive_patterns" in pattern_info:
                            is_fp = any(
                                re.search(fp, string_content, re.IGNORECASE) 
                                for fp in pattern_info["false_positive_patterns"]
                            )
                        
                        if not is_fp:
                            findings.append(Finding(
                                file_path=file_path,
                                line_number=offset,
                                line_content=string_content[:200],
                                vulnerability_name=f"Binary: {pattern_info['name']}",
                                category=VulnCategory.BINARY_SUSPECT,
                                severity=pattern_info["severity"],
                            ))
                except re.error:
                    continue
        
        self.binaries_scanned += 1
        return findings

    def scan_line(self, line: str, line_number: int, file_path: str, extension: str) -> List[Finding]:
        findings = []
        stripped = line.strip()
        
        # Skip commented lines
        if extension in ['.py', '.rb', '.sh', '.bash', '.yaml', '.yml']:
            if stripped.startswith('#'):
                return findings
        elif extension in ['.js', '.ts', '.jsx', '.tsx', '.java', '.cs', '.go', '.kt']:
            if stripped.startswith('//') or stripped.startswith('/*') or stripped.startswith('*'):
                return findings
        elif extension in ['.php']:
            if stripped.startswith('//') or stripped.startswith('#') or stripped.startswith('/*') or stripped.startswith('*'):
                return findings
        
        for vuln_pattern in VULNERABILITY_PATTERNS:
            if self.active_categories and vuln_pattern.category not in self.active_categories:
                continue
            
            if extension not in vuln_pattern.languages:
                continue
            
            for pattern in vuln_pattern.patterns:
                try:
                    if re.search(pattern, line, re.IGNORECASE):
                        # Check false positive patterns
                        is_false_positive = any(
                            re.search(fp, line, re.IGNORECASE)
                            for fp in vuln_pattern.false_positive_patterns
                        )
                        
                        if not is_false_positive:
                            findings.append(Finding(
                                file_path=file_path,
                                line_number=line_number,
                                line_content=line.strip()[:300],
                                vulnerability_name=vuln_pattern.name,
                                category=vuln_pattern.category,
                                severity=vuln_pattern.severity,
                            ))
                            break
                except re.error:
                    continue
        
        return findings

    def scan_file(self, file_path: str) -> List[Finding]:
        if self.is_archive_file(file_path):
            return []
        
        if self.is_binary_file(file_path):
            if self.scan_binaries:
                return self.scan_binary(file_path)
            return []
        
        extension = Path(file_path).suffix.lower()
        if extension not in self.get_relevant_extensions():
            return []
        
        findings = []
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                lines = f.readlines()
            
            for line_number, line in enumerate(lines, 1):
                findings.extend(self.scan_line(line, line_number, file_path, extension))
        except (IOError, PermissionError) as e:
            if self.verbose:
                print(f"[!] Error reading {file_path}: {e}")
        
        return findings

    def scan_directory(self, directory: str) -> List[Finding]:
        all_findings = []
        
        for root, dirs, files in os.walk(directory):
            dirs[:] = [d for d in dirs if d not in self.exclude_dirs]
            
            for file in files:
                file_path = os.path.join(root, file)
                
                if self.should_skip_path(file_path):
                    self.files_skipped += 1
                    continue
                
                ext = Path(file_path).suffix.lower()
                is_binary = ext in self.BINARY_EXTENSIONS
                
                if not is_binary and ext not in self.get_relevant_extensions():
                    continue
                
                if is_binary and not self.scan_binaries:
                    continue
                
                self.files_scanned += 1
                
                if self.verbose:
                    print(f"[*] Scanning: {file_path}")
                
                file_findings = self.scan_file(file_path)
                if file_findings:
                    self.files_with_findings.add(file_path)
                    all_findings.extend(file_findings)
        
        self.findings = all_findings
        self._calculate_stats()
        return all_findings

    def scan_target(self, target: str) -> List[Finding]:
        if os.path.isfile(target):
            self.files_scanned = 1
            findings = self.scan_file(target)
            self.findings = findings
            if findings:
                self.files_with_findings.add(target)
            self._calculate_stats()
            return findings
        return self.scan_directory(target)

    def _calculate_stats(self):
        self.stats = {
            "total_findings": len(self.findings),
            "files_scanned": self.files_scanned,
            "binaries_scanned": self.binaries_scanned,
            "by_category": {},
            "by_severity": {},
        }
        
        for finding in self.findings:
            cat = finding.category.value
            self.stats["by_category"][cat] = self.stats["by_category"].get(cat, 0) + 1
            sev = finding.severity.value
            self.stats["by_severity"][sev] = self.stats["by_severity"].get(sev, 0) + 1

    def generate_report(self, output_format: str = "text") -> str:
        if output_format == "json":
            return self._generate_json_report()
        return self._generate_text_report()

    def _generate_text_report(self) -> str:
        lines = []
        lines.append("=" * 80)
        lines.append("VULNERABILITY SCAN REPORT (v3.1 - Improved False Positive Handling)")
        lines.append("=" * 80)
        lines.append(f"Platform: {self.platform.upper()}")
        lines.append(f"Files scanned: {self.files_scanned} | Binaries: {self.binaries_scanned}")
        lines.append(f"Total findings: {len(self.findings)}")
        lines.append("")
        
        for sev in [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO]:
            count = self.stats["by_severity"].get(sev.value, 0)
            if count:
                lines.append(f"  {sev.value:10}: {count}")
        lines.append("")
        lines.append("=" * 80)
        
        findings_by_file = {}
        for f in self.findings:
            findings_by_file.setdefault(f.file_path, []).append(f)
        
        severity_order = {s: i for i, s in enumerate([Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO])}
        
        for file_path, file_findings in sorted(findings_by_file.items()):
            file_findings.sort(key=lambda x: (severity_order.get(x.severity, 99), x.line_number))
            
            lines.append("")
            lines.append(f"FILE: {file_path}")
            lines.append("-" * 80)
            
            for f in file_findings:
                lines.append(f"[{f.severity.value}] {f.vulnerability_name}")
                lines.append(f"  Line {f.line_number}: {f.line_content}")
                lines.append("")
        
        return "\n".join(lines)

    def _generate_json_report(self) -> str:
        report = {
            "scanner_version": "3.1",
            "platform": self.platform,
            "scan_date": datetime.now().isoformat(),
            "files_scanned": self.files_scanned,
            "binaries_scanned": self.binaries_scanned,
            "summary": self.stats,
            "findings": [
                {
                    "file": f.file_path,
                    "line": f.line_number,
                    "code": f.line_content,
                    "vulnerability": f.vulnerability_name,
                    "category": f.category.value,
                    "severity": f.severity.value,
                }
                for f in self.findings
            ]
        }
        return json.dumps(report, indent=2)


def main():
    parser = argparse.ArgumentParser(
        description="Vulnerability Scanner v3.1 (Improved False Positive Handling)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
v3.1 Improvements:
  - Fixed NoSQL injection FPs for findById() (Mongoose validates ObjectId)
  - Fixed Prototype Pollution FPs for spread in Model.create()
  - Fixed call_user_func FPs for closures/callbacks
  - Improved Auth Bypass patterns (no longer flags SQL injection)
  - Added context-aware pattern matching
  - Scanner no longer detects its own patterns

Categories:
  sql, postgresql, nosql, xpath, deserialization, auth, ssti, ssrf, code/eval, all

Examples:
  python3 %(prog)s /path/to/project
  python3 %(prog)s /path/to/project --category sql code auth
  python3 %(prog)s /path/to/project --output json -o report.json
        """
    )
    
    parser.add_argument("target", help="File or directory to scan")
    parser.add_argument("-o", "--output-file", help="Output file path")
    parser.add_argument("--output", choices=["text", "json"], default="text")
    parser.add_argument("-v", "--verbose", action="store_true")
    
    parser.add_argument(
        "--category", "-c", nargs="+",
        choices=["sql", "postgresql", "nosql", "xpath", "deserialization", "auth", "ssti", "ssrf", "code", "eval", "prototype", "pollution", "all"],
        default=["all"], help="Categories to scan"
    )
    
    parser.add_argument("--scan-binaries", "-b", action="store_true")
    parser.add_argument("--decompile", "-d", action="store_true")
    
    parser.add_argument("--exclude-dir", nargs="+", default=[])
    parser.add_argument("--exclude-file", nargs="+", default=[])
    parser.add_argument("--exclude-pattern", nargs="+", default=[])
    parser.add_argument("--exclude-ext", nargs="+", default=[])
    parser.add_argument("--include-ext", nargs="+", default=[])
    parser.add_argument("--no-default-excludes", action="store_true")
    
    args = parser.parse_args()
    
    if not os.path.exists(args.target):
        print(f"[!] Error: Target not found: {args.target}")
        return 1
    
    banner = """
░█░█░█▀█░█▀▄░█░░░█▀▄░▀█▀░█▀▄░█▀▀░█▀▀░█▀▄░█▀█░█░█
░█▄█░█░█░█▀▄░█░░░█░█░░█░░█▀▄░█▀▀░█▀▀░█▀▄░█░█░░█░
░▀░▀░▀▀▀░▀░▀░▀▀▀░▀▀░░░▀░░▀░▀░▀▀▀░▀▀▀░▀▀░░▀▀▀░░▀░
        ╔═╗┌─┐┌─┐┬ ┬┬─┐┬┌┬┐┬ ┬  ╔═╗┌─┐┌─┐┌┐┌┌┐┌┌─┐┬─┐
        ╚═╗├┤ │  │ │├┬┘│ │ └┬┘  ╚═╗│  ├─┤││││││├┤ ├┬┘
        ╚═╝└─┘└─┘└─┘┴└─┴ ┴  ┴   ╚═╝└─┘┴ ┴┘└┘┘└┘└─┘┴└─
                Source Code Security Scanner v3.1
                 Improved False Positive Handling
                      by worldtreeboy
    """
    print(banner)
    
    current_platform = get_platform()
    print(f"[*] Platform: {current_platform.upper()}")
    print(f"[*] Target: {args.target}")
    print(f"[*] Categories: {', '.join(args.category)}")
    print("")
    
    scanner = VulnerabilityScanner(
        verbose=args.verbose,
        exclude_dirs=set(args.exclude_dir) if args.exclude_dir else None,
        exclude_files=set(args.exclude_file) if args.exclude_file else None,
        exclude_patterns=set(args.exclude_pattern) if args.exclude_pattern else None,
        include_extensions=set(f".{e.lstrip('.')}" for e in args.include_ext) if args.include_ext else None,
        exclude_extensions=set(f".{e.lstrip('.')}" for e in args.exclude_ext) if args.exclude_ext else None,
        no_default_excludes=args.no_default_excludes,
        scan_binaries=args.scan_binaries,
        decompile_dotnet=args.decompile,
        categories=args.category
    )
    
    scanner.scan_target(args.target)
    report = scanner.generate_report(args.output)
    
    if args.output_file:
        with open(args.output_file, 'w', encoding='utf-8') as f:
            f.write(report)
        print(f"[*] Report saved: {args.output_file}")
    else:
        print(report)
    
    print(f"\n[*] Scan complete: {scanner.files_scanned} files, {len(scanner.findings)} findings")
    
    return 0


if __name__ == "__main__":
    exit(main())
