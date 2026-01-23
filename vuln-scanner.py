#!/usr/bin/env python3
"""
Advanced Vulnerability Scanner v3.1
====================================
Cross-platform (Windows/Kali Linux) vulnerability scanner with .NET DLL decompilation support.

Scans for: SQL Injection, NoSQL Injection, XPath Injection, PostgreSQL Injection,
           Insecure Deserialization, Authentication Bypass, SSTI, SSRF, Code Injection (eval)

Features:
- Cross-platform: Windows and Kali Linux
- DLL decompilation via ILSpy (Linux) or built-in reflection (Windows)
- JAR/APK/WAR archive analysis
- Simplified output: just line of code
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
    XXE = "XML External Entity Injection"
    BINARY_SUSPECT = "Binary Analysis Finding"

@dataclass
class VulnerabilityPattern:
    name: str
    category: VulnCategory
    patterns: List[str]
    severity: Severity
    languages: List[str]
    false_positive_patterns: List[str] = field(default_factory=list)

@dataclass
class Finding:
    file_path: str
    line_number: int
    line_content: str
    vulnerability_name: str
    category: VulnCategory
    severity: Severity

# =============================================================================
# VULNERABILITY PATTERNS DATABASE
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
            r'\beval\s*\(\s*["\'].*\+',
            r'\beval\s*\(\s*`[^`]*\$\{',
            r'\beval\s*\(\s*\w+\s*\)',
            r'\beval\s*\(\s*body\.',
            r'\beval\s*\(\s*query\.',
            r'\beval\s*\(\s*params\.',
            r'\(0,\s*eval\)\s*\(',
            r'window\s*\[\s*["\']eval["\']\s*\]\s*\(',
            r'global\s*\[\s*["\']eval["\']\s*\]\s*\(',
            r'globalThis\.eval\s*\(',
        ],
        severity=Severity.CRITICAL,
        languages=[".js", ".ts", ".jsx", ".tsx"],
        false_positive_patterns=[
            r'//.*\beval',
            r'/\*.*\beval',
            r'\.evaluate\(',
            r'evalua',
            r'literal_eval',
            r'evalSync',
            r'_test\.',
            r'\.test\.',
            r'test_',
            r'\.spec\.',
            r'mock',
            r'fixture',
            r'JSON\.parse',
            r'\.safeEval',
            r'sandboxed',
        ]
    ),
    VulnerabilityPattern(
        name="Code Injection - new Function Constructor",
        category=VulnCategory.CODE_INJECTION,
        patterns=[
            r'\bnew\s+Function\s*\(\s*["\'\`]',
            r'[=:]\s*Function\s*\(\s*["\'\`]',
            r'Function\.prototype\.constructor\s*\(\s*["\'\`]',
        ],
        severity=Severity.CRITICAL,
        languages=[".js", ".ts", ".jsx", ".tsx"],
        false_positive_patterns=[r'//.*Function', r'isFunction', r'typeof\s+\w+\s*[=!]==?\s*["\']function', r'function\s+\w+\s*\('],
    ),
    VulnerabilityPattern(
        name="Code Injection - setTimeout/setInterval string",
        category=VulnCategory.CODE_INJECTION,
        patterns=[
            r'setTimeout\s*\(\s*["\'].*\+',
            r'setTimeout\s*\(\s*`.*\$\{',
            r'setInterval\s*\(\s*["\'].*\+',
            r'setInterval\s*\(\s*`.*\$\{',
        ],
        severity=Severity.MEDIUM,
        languages=[".js", ".ts", ".jsx", ".tsx"],
        false_positive_patterns=[r'setTimeout\s*\(\s*function', r'setTimeout\s*\(\s*\(\)', r'session_alive'],
    ),
    VulnerabilityPattern(
        name="Command Injection - child_process exec",
        category=VulnCategory.CODE_INJECTION,
        patterns=[
            r'exec\s*\(\s*["\'].*\+',
            r'exec\s*\(\s*`',
            r'exec\s*\(\s*req\.',
            r'exec\s*\(\s*request\.',
            r'child_process\.exec\s*\(',
            r'require\s*\(\s*["\']child_process["\']\s*\)\.exec',
        ],
        severity=Severity.CRITICAL,
        languages=[".js", ".ts"],
        false_positive_patterns=[r'execFile', r'//.*exec']
    ),
    VulnerabilityPattern(
        name="Command Injection - child_process execSync",
        category=VulnCategory.CODE_INJECTION,
        patterns=[
            r'execSync\s*\(\s*["\'].*\+',
            r'execSync\s*\(\s*`',
            r'execSync\s*\(\s*req\.',
            r'execSync\s*\(\s*request\.',
            r'child_process\.execSync\s*\(',
            r'require\s*\(\s*["\']child_process["\']\s*\)\.execSync',
        ],
        severity=Severity.CRITICAL,
        languages=[".js", ".ts"],
    ),
    VulnerabilityPattern(
        name="Command Injection - child_process spawn",
        category=VulnCategory.CODE_INJECTION,
        patterns=[
            r'spawn\s*\(\s*["\'].*\+',
            r'spawn\s*\(\s*`',
            r'spawn\s*\(\s*req\.',
            r'spawn\s*\(\s*request\.',
            r'spawnSync\s*\(\s*["\'].*\+',
            r'spawnSync\s*\(\s*`',
            r'spawnSync\s*\(\s*req\.',
            r'child_process\.spawn\s*\(',
            r'child_process\.spawnSync\s*\(',
        ],
        severity=Severity.HIGH,
        languages=[".js", ".ts"],
    ),
    VulnerabilityPattern(
        name="Command Injection - child_process execFile",
        category=VulnCategory.CODE_INJECTION,
        patterns=[
            r'execFile\s*\(\s*req\.',
            r'execFile\s*\(\s*request\.',
            r'execFileSync\s*\(\s*req\.',
            r'child_process\.execFile\s*\(',
            r'child_process\.execFileSync\s*\(',
        ],
        severity=Severity.HIGH,
        languages=[".js", ".ts"],
    ),
    VulnerabilityPattern(
        name="Command Injection - child_process fork",
        category=VulnCategory.CODE_INJECTION,
        patterns=[
            r'fork\s*\(\s*req\.',
            r'fork\s*\(\s*request\.',
            r'child_process\.fork\s*\(',
        ],
        severity=Severity.HIGH,
        languages=[".js", ".ts"],
    ),
    VulnerabilityPattern(
        name="Code Injection - vm module",
        category=VulnCategory.CODE_INJECTION,
        patterns=[
            r'vm\.runInContext\s*\(',
            r'vm\.runInNewContext\s*\(',
            r'vm\.runInThisContext\s*\(',
            r'vm\.compileFunction\s*\(',
            r'vm\.Script\s*\(',
            r'new\s+vm\.Script\s*\(',
            r'vm\.createContext\s*\(',
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
            r'require\s*\(\s*\w+\s*\+',
            r'require\s*\(\s*`',
            r'import\s*\(\s*req\.',
            r'import\s*\(\s*`',
        ],
        severity=Severity.HIGH,
        languages=[".js", ".ts"],
        false_positive_patterns=[r'require\s*\(\s*["\'][^"\']+["\']\s*\)']
    ),
    VulnerabilityPattern(
        name="Code Injection - process.binding",
        category=VulnCategory.CODE_INJECTION,
        patterns=[
            r'process\.binding\s*\(',
            r'process\.dlopen\s*\(',
            r'process\._linkedBinding\s*\(',
        ],
        severity=Severity.HIGH,
        languages=[".js", ".ts"],
    ),
    VulnerabilityPattern(
        name="Prototype Pollution",
        category=VulnCategory.CODE_INJECTION,
        patterns=[
            r'\[\s*["\']__proto__["\']\s*\]',
            r'\[\s*["\']constructor["\']\s*\]\s*\[\s*["\']prototype["\']\s*\]',
            r'Object\.assign\s*\(\s*\{\s*\}\s*,.*req\.(body|query|params)',
            r'Object\.assign\s*\(\s*target.*req\.(body|query|params)',
            r'\.\.\.req\.(body|query|params)',
            r'merge\s*\(.*req\.(body|query|params)',
            r'extend\s*\(.*req\.(body|query|params)',
            r'defaultsDeep\s*\([^)]*req\.(body|query|params)',
            r'deepMerge\s*\([^)]*req\.(body|query|params)',
            r'lodash\.merge\s*\([^)]*req\.',
            r'_\.merge\s*\([^)]*req\.',
            r'_\.defaultsDeep\s*\([^)]*req\.',
            r'hoek\.merge\s*\([^)]*req\.',
            r'deap\.merge\s*\([^)]*req\.',
            r'Object\.defineProperty\s*\([^,]+,\s*req\.',
            r'Reflect\.set\s*\([^,]+,\s*req\.',
        ],
        severity=Severity.HIGH,
        languages=[".js", ".ts", ".jsx", ".tsx"],
        false_positive_patterns=[
            r'_test\.',
            r'\.test\.',
            r'test_',
            r'\.spec\.',
            r'mock',
            r'fixture',
            r'sanitize',
            r'validate',
            r'whitelist',
            r'allowedKeys',
            r'pick\s*\(',
            r'omit\s*\(',
        ],
    ),

    # =========================================================================
    # CODE INJECTION - Python
    # =========================================================================

    VulnerabilityPattern(
        name="Code Injection - Python eval",
        category=VulnCategory.CODE_INJECTION,
        patterns=[
            r'\beval\s*\(\s*.*request\.',
            r'\beval\s*\(\s*.*input\s*\(',
            r'\beval\s*\(\s*.*argv',
            r'\beval\s*\(\s*.*\.get\s*\(',
            r'\beval\s*\(\s*f["\']',
            r'\beval\s*\(\s*["\'].*%',
            r'\beval\s*\(\s*["\'].*\.format',
        ],
        severity=Severity.CRITICAL,
        languages=[".py"],
        false_positive_patterns=[r'#.*\beval', r'ast\.literal_eval']
    ),
    VulnerabilityPattern(
        name="Code Injection - Python exec",
        category=VulnCategory.CODE_INJECTION,
        patterns=[
            r'\bexec\s*\(\s*.*request\.',
            r'\bexec\s*\(\s*.*input\s*\(',
            r'\bexec\s*\(\s*.*argv',
            r'\bexec\s*\(\s*f["\']',
            r'\bexec\s*\(\s*["\'].*%',
            r'\bexec\s*\(\s*open\s*\(',
            r'\bexec\s*\(\s*.*\.read\s*\(',
        ],
        severity=Severity.CRITICAL,
        languages=[".py"],
        false_positive_patterns=[r'#.*\bexec']
    ),
    VulnerabilityPattern(
        name="Code Injection - Python compile",
        category=VulnCategory.CODE_INJECTION,
        patterns=[
            r'\bcompile\s*\(\s*.*request\.',
            r'\bcompile\s*\(\s*.*input\s*\(',
            r'\bcompile\s*\(\s*f["\']',
        ],
        severity=Severity.HIGH,
        languages=[".py"],
    ),
    VulnerabilityPattern(
        name="Command Injection - Python os.system",
        category=VulnCategory.CODE_INJECTION,
        patterns=[
            r'os\.system\s*\(',
            r'os\.popen\s*\(',
            r'os\.popen2\s*\(',
            r'os\.popen3\s*\(',
            r'os\.popen4\s*\(',
            r'os\.spawn',
            r'os\.exec',
        ],
        severity=Severity.CRITICAL,
        languages=[".py"],
    ),
    VulnerabilityPattern(
        name="Command Injection - Python subprocess",
        category=VulnCategory.CODE_INJECTION,
        patterns=[
            r'subprocess\.call\s*\(\s*["\']',
            r'subprocess\.call\s*\(\s*f["\']',
            r'subprocess\.call\s*\(\s*.*shell\s*=\s*True',
            r'subprocess\.run\s*\(\s*["\']',
            r'subprocess\.run\s*\(\s*f["\']',
            r'subprocess\.run\s*\(\s*.*shell\s*=\s*True',
            r'subprocess\.Popen\s*\(\s*["\']',
            r'subprocess\.Popen\s*\(\s*f["\']',
            r'subprocess\.Popen\s*\(\s*.*shell\s*=\s*True',
            r'subprocess\.check_output\s*\(\s*.*shell\s*=\s*True',
            r'subprocess\.check_call\s*\(\s*.*shell\s*=\s*True',
            r'subprocess\.getoutput\s*\(',
            r'subprocess\.getstatusoutput\s*\(',
        ],
        severity=Severity.CRITICAL,
        languages=[".py"],
        false_positive_patterns=[r'shell\s*=\s*False']
    ),
    VulnerabilityPattern(
        name="Command Injection - Python commands module",
        category=VulnCategory.CODE_INJECTION,
        patterns=[
            r'commands\.getoutput\s*\(',
            r'commands\.getstatusoutput\s*\(',
        ],
        severity=Severity.CRITICAL,
        languages=[".py"],
    ),
    VulnerabilityPattern(
        name="Code Injection - Python importlib",
        category=VulnCategory.CODE_INJECTION,
        patterns=[
            r'importlib\.import_module\s*\(\s*.*request',
            r'importlib\.import_module\s*\(\s*.*input',
            r'__import__\s*\(\s*.*request',
            r'__import__\s*\(\s*.*input',
        ],
        severity=Severity.HIGH,
        languages=[".py"],
    ),
    VulnerabilityPattern(
        name="Code Injection - Python builtins",
        category=VulnCategory.CODE_INJECTION,
        patterns=[
            r'__builtins__\s*\[',
            r'__import__\s*\(\s*.*request\.',
            r'__import__\s*\(\s*.*input\s*\(',
            r'getattr\s*\(\s*__builtins__',
            r'setattr\s*\(\s*__builtins__',
        ],
        severity=Severity.MEDIUM,
        languages=[".py"],
        false_positive_patterns=[r'__builtins__\s*=\s*\{\}', r'#.*__builtins__', r'getattr\s*\(\s*frappe\.local'],
    ),

    # =========================================================================
    # CODE INJECTION - PHP
    # =========================================================================

    VulnerabilityPattern(
        name="Code Injection - PHP eval",
        category=VulnCategory.CODE_INJECTION,
        patterns=[
            r'\beval\s*\(\s*\$',
            r'\beval\s*\(\s*\$_(GET|POST|REQUEST|COOKIE)',
            r'\beval\s*\(\s*base64_decode',
            r'\beval\s*\(\s*gzinflate',
            r'\beval\s*\(\s*str_rot13',
        ],
        severity=Severity.CRITICAL,
        languages=[".php"],
    ),
    VulnerabilityPattern(
        name="Code Injection - PHP assert",
        category=VulnCategory.CODE_INJECTION,
        patterns=[
            r'\bassert\s*\(\s*\$',
            r'\bassert\s*\(\s*\$_(GET|POST|REQUEST|COOKIE)',
        ],
        severity=Severity.CRITICAL,
        languages=[".php"],
    ),
    VulnerabilityPattern(
        name="Code Injection - PHP create_function",
        category=VulnCategory.CODE_INJECTION,
        patterns=[
            r'create_function\s*\(',
        ],
        severity=Severity.HIGH,
        languages=[".php"],
    ),
    VulnerabilityPattern(
        name="Code Injection - PHP preg_replace /e",
        category=VulnCategory.CODE_INJECTION,
        patterns=[
            r'preg_replace\s*\(\s*["\']/.*/e',
            r'preg_replace\s*\(\s*\$.*,.*\$',
        ],
        severity=Severity.CRITICAL,
        languages=[".php"],
    ),
    VulnerabilityPattern(
        name="Command Injection - PHP system/exec/shell_exec",
        category=VulnCategory.CODE_INJECTION,
        patterns=[
            r'\bsystem\s*\(\s*\$',
            r'\bsystem\s*\(\s*\$_(GET|POST|REQUEST)',
            r'\bexec\s*\(\s*\$',
            r'\bexec\s*\(\s*\$_(GET|POST|REQUEST)',
            r'shell_exec\s*\(\s*\$',
            r'shell_exec\s*\(\s*\$_(GET|POST|REQUEST)',
            r'\bpassthru\s*\(\s*\$',
            r'\bpassthru\s*\(\s*\$_(GET|POST|REQUEST)',
        ],
        severity=Severity.CRITICAL,
        languages=[".php"],
        false_positive_patterns=[r'fpassthru'],
    ),
    VulnerabilityPattern(
        name="Command Injection - PHP popen/proc_open",
        category=VulnCategory.CODE_INJECTION,
        patterns=[
            r'\bpopen\s*\(\s*\$',
            r'proc_open\s*\(\s*\$',
            r'pcntl_exec\s*\(\s*\$',
        ],
        severity=Severity.CRITICAL,
        languages=[".php"],
    ),
    VulnerabilityPattern(
        name="Command Injection - PHP backticks",
        category=VulnCategory.CODE_INJECTION,
        patterns=[
            r'`\s*\$',
            r'`.*\$_(GET|POST|REQUEST)',
        ],
        severity=Severity.CRITICAL,
        languages=[".php"],
    ),
    VulnerabilityPattern(
        name="Code Injection - PHP include/require",
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
    VulnerabilityPattern(
        name="Code Injection - PHP call_user_func",
        category=VulnCategory.CODE_INJECTION,
        patterns=[
            r'call_user_func\s*\(\s*\$_(GET|POST|REQUEST|COOKIE)',
            r'call_user_func_array\s*\(\s*\$_(GET|POST|REQUEST|COOKIE)',
            r'array_map\s*\(\s*\$_(GET|POST|REQUEST)',
            r'array_filter\s*\(\s*.*,\s*\$_(GET|POST|REQUEST)',
        ],
        severity=Severity.HIGH,
        languages=[".php"],
        false_positive_patterns=[r'\$closure', r'\$callback', r'\$handler', r'\$func'],
    ),

    # =========================================================================
    # CODE INJECTION - Ruby
    # =========================================================================

    VulnerabilityPattern(
        name="Code Injection - Ruby eval",
        category=VulnCategory.CODE_INJECTION,
        patterns=[
            r'\beval\s*\(\s*params',
            r'\beval\s*\(\s*request',
            r'\beval\s*\s+params',
            r'instance_eval\s*\(',
            r'class_eval\s*\(',
            r'module_eval\s*\(',
        ],
        severity=Severity.CRITICAL,
        languages=[".rb"],
    ),
    VulnerabilityPattern(
        name="Command Injection - Ruby system/exec/backticks",
        category=VulnCategory.CODE_INJECTION,
        patterns=[
            r'\bsystem\s*\(\s*.*params',
            r'\bsystem\s*\s+.*params',
            r'\bexec\s*\(\s*.*params',
            r'\bexec\s*\s+.*params',
            r'`.*#\{.*params',
            r'%x\[.*#\{.*params',
            r'%x\{.*#\{.*params',
            r'IO\.popen\s*\(',
            r'Open3\.',
            r'Kernel\.system\s*\(',
            r'Kernel\.exec\s*\(',
            r'Kernel\.`',
        ],
        severity=Severity.CRITICAL,
        languages=[".rb"],
    ),
    VulnerabilityPattern(
        name="Code Injection - Ruby send/public_send",
        category=VulnCategory.CODE_INJECTION,
        patterns=[
            r'\.send\s*\(\s*params',
            r'\.public_send\s*\(\s*params',
            r'__send__\s*\(\s*params',
            r'\.send\s*\(\s*request',
        ],
        severity=Severity.HIGH,
        languages=[".rb"],
    ),
    VulnerabilityPattern(
        name="Code Injection - Ruby constantize",
        category=VulnCategory.CODE_INJECTION,
        patterns=[
            r'\.constantize',
            r'\.safe_constantize',
            r'const_get\s*\(\s*params',
        ],
        severity=Severity.HIGH,
        languages=[".rb"],
    ),

    # =========================================================================
    # CODE INJECTION - Java
    # =========================================================================

    VulnerabilityPattern(
        name="Command Injection - Java Runtime.exec",
        category=VulnCategory.CODE_INJECTION,
        patterns=[
            r'Runtime\.getRuntime\s*\(\s*\)\.exec\s*\(',
            r'\.exec\s*\(\s*.*request\.getParameter',
            r'\.exec\s*\(\s*.*\+',
            r'ProcessBuilder\s*\(\s*.*request',
            r'new\s+ProcessBuilder\s*\(',
        ],
        severity=Severity.CRITICAL,
        languages=[".java", ".kt", ".scala"],
    ),
    VulnerabilityPattern(
        name="Code Injection - Java ScriptEngine",
        category=VulnCategory.CODE_INJECTION,
        patterns=[
            r'ScriptEngine.*eval\s*\(',
            r'\.eval\s*\(\s*.*request\.getParameter',
            r'ScriptEngineManager\s*\(',
            r'getEngineByName\s*\(\s*["\']javascript["\']',
            r'Nashorn',
            r'GraalJS',
        ],
        severity=Severity.CRITICAL,
        languages=[".java", ".kt", ".scala"],
    ),
    VulnerabilityPattern(
        name="Code Injection - Java Reflection",
        category=VulnCategory.CODE_INJECTION,
        patterns=[
            r'Class\.forName\s*\(\s*.*request',
            r'\.newInstance\s*\(\s*\)',
            r'Method\.invoke\s*\(',
            r'\.getMethod\s*\(\s*.*request',
            r'\.getDeclaredMethod\s*\(',
            r'Constructor\.newInstance\s*\(',
        ],
        severity=Severity.HIGH,
        languages=[".java", ".kt", ".scala"],
    ),
    VulnerabilityPattern(
        name="Code Injection - Java JNDI",
        category=VulnCategory.CODE_INJECTION,
        patterns=[
            r'InitialContext\s*\(\s*\)',
            r'\.lookup\s*\(\s*.*request',
            r'\.lookup\s*\(\s*["\'].*\$\{',
            r'javax\.naming',
            r'Context\.lookup\s*\(',
        ],
        severity=Severity.CRITICAL,
        languages=[".java", ".kt", ".scala"],
    ),
    VulnerabilityPattern(
        name="Code Injection - Java Expression Language",
        category=VulnCategory.CODE_INJECTION,
        patterns=[
            r'ExpressionFactory',
            r'\.createValueExpression\s*\(',
            r'ELProcessor',
            r'\.eval\s*\(\s*.*request',
            r'SpelExpressionParser',
            r'\.parseExpression\s*\(',
        ],
        severity=Severity.CRITICAL,
        languages=[".java", ".kt", ".scala"],
    ),

    # =========================================================================
    # CODE INJECTION - C#/.NET
    # =========================================================================

    VulnerabilityPattern(
        name="Command Injection - C# Process.Start",
        category=VulnCategory.CODE_INJECTION,
        patterns=[
            r'Process\.Start\s*\(',
            r'new\s+Process\s*\(',
            r'ProcessStartInfo\s*\(',
            r'\.StartInfo\.FileName\s*=',
            r'\.StartInfo\.Arguments\s*=.*Request',
            r'System\.Diagnostics\.Process',
        ],
        severity=Severity.CRITICAL,
        languages=[".cs"],
    ),
    VulnerabilityPattern(
        name="Code Injection - C# Dynamic Compilation",
        category=VulnCategory.CODE_INJECTION,
        patterns=[
            r'CSharpCodeProvider\s*\(',
            r'CompileAssemblyFromSource\s*\(',
            r'Microsoft\.CSharp\.CSharpCodeProvider',
            r'Roslyn.*CSharpCompilation',
            r'CSharpCompilation\.Create',
            r'CodeDomProvider',
        ],
        severity=Severity.CRITICAL,
        languages=[".cs"],
    ),
    VulnerabilityPattern(
        name="Code Injection - C# Assembly Loading",
        category=VulnCategory.CODE_INJECTION,
        patterns=[
            r'Assembly\.Load\s*\(',
            r'Assembly\.LoadFrom\s*\(',
            r'Assembly\.LoadFile\s*\(',
            r'Assembly\.LoadWithPartialName\s*\(',
            r'Activator\.CreateInstance\s*\(',
            r'AppDomain.*CreateInstance',
        ],
        severity=Severity.HIGH,
        languages=[".cs"],
    ),
    VulnerabilityPattern(
        name="Code Injection - C# Reflection",
        category=VulnCategory.CODE_INJECTION,
        patterns=[
            r'Type\.GetType\s*\(\s*.*Request',
            r'\.InvokeMember\s*\(',
            r'MethodInfo\.Invoke\s*\(',
            r'\.GetMethod\s*\(\s*.*Request',
            r'Delegate\.CreateDelegate\s*\(',
            r'DynamicInvoke\s*\(',
        ],
        severity=Severity.HIGH,
        languages=[".cs"],
    ),
    VulnerabilityPattern(
        name="Code Injection - C# PowerShell",
        category=VulnCategory.CODE_INJECTION,
        patterns=[
            r'PowerShell\.Create\s*\(',
            r'\.AddScript\s*\(',
            r'\.AddCommand\s*\(',
            r'Runspace',
            r'System\.Management\.Automation',
        ],
        severity=Severity.CRITICAL,
        languages=[".cs"],
    ),
    VulnerabilityPattern(
        name="Code Injection - C# Expression Trees",
        category=VulnCategory.CODE_INJECTION,
        patterns=[
            r'Expression\.Lambda',
            r'\.Compile\s*\(\s*\)',
            r'DynamicExpression',
            r'System\.Linq\.Expressions',
        ],
        severity=Severity.MEDIUM,
        languages=[".cs"],
    ),

    # =========================================================================
    # CODE INJECTION - Go
    # =========================================================================

    VulnerabilityPattern(
        name="Command Injection - Go exec.Command",
        category=VulnCategory.CODE_INJECTION,
        patterns=[
            r'exec\.Command\s*\(',
            r'exec\.CommandContext\s*\(',
            r'syscall\.Exec\s*\(',
            r'syscall\.ForkExec\s*\(',
            r'os\.StartProcess\s*\(',
        ],
        severity=Severity.HIGH,
        languages=[".go"],
    ),
    VulnerabilityPattern(
        name="Code Injection - Go plugin",
        category=VulnCategory.CODE_INJECTION,
        patterns=[
            r'plugin\.Open\s*\(',
            r'\.Lookup\s*\(',
        ],
        severity=Severity.HIGH,
        languages=[".go"],
    ),

    # =========================================================================
    # CODE INJECTION - Kotlin
    # =========================================================================

    VulnerabilityPattern(
        name="Command Injection - Kotlin ProcessBuilder",
        category=VulnCategory.CODE_INJECTION,
        patterns=[
            r'ProcessBuilder\s*\(',
            r'Runtime\.getRuntime\s*\(\s*\)\.exec',
            r'\.exec\s*\(\s*.*request',
        ],
        severity=Severity.CRITICAL,
        languages=[".kt"],
    ),

    # =========================================================================
    # CODE INJECTION - Shell/Bash
    # =========================================================================

    VulnerabilityPattern(
        name="Command Injection - Shell eval",
        category=VulnCategory.CODE_INJECTION,
        patterns=[
            r'\beval\s+',
            r'\beval\s*\$',
            r'`.*\$',
            r'\$\(.*\$',
        ],
        severity=Severity.HIGH,
        languages=[".sh", ".bash", ".zsh"],
    ),

    # =========================================================================
    # PROTOTYPE POLLUTION PATTERNS - ENTERPRISE GRADE COMPREHENSIVE DETECTION
    # =========================================================================
    # Version: 2.0
    # Coverage: Direct pollution, library-based, recursive merge, JSON parsing,
    #           object cloning, path traversal, class pollution (Python)
    # Languages: JavaScript, TypeScript, Python (class pollution)
    # =========================================================================

    # =============================================================================
    # DIRECT PROTOTYPE ACCESS - __proto__
    # =============================================================================

    VulnerabilityPattern(
        name="Prototype Pollution - __proto__ Direct Assignment",
        category=VulnCategory.PROTOTYPE_POLLUTION,
        patterns=[
    # =====================================================================
            # DIRECT __proto__ ASSIGNMENT
    # =====================================================================

            # Bracket notation assignment
            r'\[[\s]*["\']__proto__["\'][\s]*\]\s*=',
            r'\[[\s]*`__proto__`[\s]*\]\s*=',
            r'\[.*__proto__.*\]\s*=(?!=)',  # Assignment but not comparison

            # Dot notation assignment
            r'\.__proto__\s*=(?!=)',

            # Nested property assignment
            r'\[[\s]*["\']__proto__["\'][\s]*\]\s*\[',  # obj["__proto__"]["polluted"]
            r'\.__proto__\s*\[',  # obj.__proto__["polluted"]
            r'\.__proto__\.\w+\s*=',  # obj.__proto__.polluted =

            # Object literal with __proto__
            r'\{\s*["\']?__proto__["\']?\s*:',
            r'\{\s*__proto__\s*:',
            r'__proto__\s*:\s*\{',

    # =====================================================================
            # __proto__ IN USER INPUT CONTEXT
    # =====================================================================

            # Direct from request
            r'req\.(body|query|params)\s*\[[\s]*["\']__proto__["\'][\s]*\]',
            r'req\.(body|query|params)\s*\.\s*__proto__',
            r'request\.(args|form|json|data)\s*\[[\s]*["\']__proto__["\'][\s]*\]',

            # Object spread with potential __proto__
            r'\{\s*\.\.\.req\.(body|query|params)\s*\}',
            r'\{\s*\.\.\.request\.(args|form|json|data)\s*\}',
            r'\{\s*\.\.\.(?:userInput|userData|clientData|payload|data|input)\s*\}',

            # Destructuring from user input (can include __proto__)
            r'const\s*\{[^}]*\}\s*=\s*req\.(body|query|params)',
            r'let\s*\{[^}]*\}\s*=\s*req\.(body|query|params)',
            r'var\s*\{[^}]*\}\s*=\s*req\.(body|query|params)',

    # =====================================================================
            # DYNAMIC PROPERTY ACCESS WITH __proto__
    # =====================================================================

            # Variable as key that could be __proto__
            r'\[\s*(?:key|prop|property|name|attr|field|k|p)\s*\]\s*=',
            r'\[\s*(?:key|prop|property|name|attr|field|k|p)\s*\]\s*\[',

            # Object.keys/entries iteration without filtering
            r'Object\.(?:keys|entries|values)\s*\([^)]*\)\s*\.(?:forEach|map|reduce|filter)',
            r'for\s*\(\s*(?:const|let|var)\s+(?:key|prop|k)\s+(?:in|of)',

    # =====================================================================
            # JSON PARSING ATTACKS
    # =====================================================================

            # JSON.parse without sanitization
            r'JSON\.parse\s*\(\s*req\.(body|query|params)',
            r'JSON\.parse\s*\(\s*request\.(args|form|json|data|body)',
            r'JSON\.parse\s*\(\s*(?:userInput|userData|clientData|payload|data|input|str|string|text)\s*\)',

            # JSON with __proto__ in string (detection in data)
            r'["\']__proto__["\']\s*:',
            r'"__proto__"\s*:\s*\{',
            r"'__proto__'\s*:\s*\{",
        ],
        severity=Severity.CRITICAL,
        languages=[".js", ".ts", ".jsx", ".tsx", ".mjs", ".cjs"],
        false_positive_patterns=[
            r'^import\s+',
            r'import\s+javax\.naming',
            r'hasOwnProperty\s*\(\s*["\']__proto__["\']',
            r'===\s*["\']__proto__["\']',
            r'!==\s*["\']__proto__["\']',
            r'==\s*["\']__proto__["\']',
            r'!=\s*["\']__proto__["\']',
            r'typeof\s+superClass',
            r'Object\.getPrototypeOf\s*\(',
            r'Object\.setPrototypeOf\s*\(',
            r'Object\.create\s*\(',
            r'Reflect\.getPrototypeOf\s*\(',
            r'Reflect\.setPrototypeOf\s*\(',
            r'delete\s+[^;]*__proto__',
            r'//.*__proto__',
            r'/\*.*__proto__',
            r'if\s*\([^)]*["\']__proto__["\']',
            r'key\s*(?:===|!==|==|!=)\s*["\']__proto__["\']',
            r'prop\s*(?:===|!==|==|!=)\s*["\']__proto__["\']',
            r'\.filter\s*\([^)]*__proto__',
            r'blacklist.*__proto__',
            r'blocklist.*__proto__',
            r'sanitize.*__proto__',
        ],
    ),

    # =============================================================================
    # CONSTRUCTOR.PROTOTYPE ACCESS
    # =============================================================================

    VulnerabilityPattern(
        name="Prototype Pollution - constructor.prototype Access",
        category=VulnCategory.PROTOTYPE_POLLUTION,
        patterns=[
    # =====================================================================
            # DIRECT constructor.prototype ASSIGNMENT
    # =====================================================================

            # Bracket notation
            r'\[[\s]*["\']constructor["\'][\s]*\]\s*\[[\s]*["\']prototype["\'][\s]*\]',
            r'\[[\s]*`constructor`[\s]*\]\s*\[[\s]*`prototype`[\s]*\]',

            # Dot notation
            r'\.constructor\.prototype\s*[=\[]',
            r'\.constructor\s*\[[\s]*["\']prototype["\'][\s]*\]',

            # Mixed notation
            r'\[[\s]*["\']constructor["\'][\s]*\]\.prototype',

            # Assignment to constructor.prototype property
            r'\.constructor\.prototype\.\w+\s*=',
            r'\[[\s]*["\']constructor["\'][\s]*\]\s*\[[\s]*["\']prototype["\'][\s]*\]\s*\[',

    # =====================================================================
            # CONSTRUCTOR MANIPULATION
    # =====================================================================

            # Accessing constructor dynamically
            r'\[\s*(?:key|prop|property|name)\s*\]\s*\[\s*["\']prototype["\']',
            r'\[\s*["\']constructor["\'][\s]*\]\s*\[\s*(?:key|prop|property|name)\s*\]',

            # Object literal with constructor
            r'\{\s*["\']?constructor["\']?\s*:\s*\{',
            r'constructor\s*:\s*\{\s*["\']?prototype["\']?\s*:',
        ],
        severity=Severity.CRITICAL,
        languages=[".js", ".ts", ".jsx", ".tsx", ".mjs", ".cjs"],
        false_positive_patterns=[
            r'Object\.create\s*\(',
            r'typeof\s+superClass',
            r'_inherits',
            r'__extends',
            r'extends\s+\w+',
            r'class\s+\w+\s+extends',
            r'\.prototype\s*=\s*Object\.create\s*\(',
            r'//.*constructor.*prototype',
            r'/\*.*constructor.*prototype',
            r'super\s*\(',
            r'instanceof\s+',
        ],
    ),

    # =============================================================================
    # UNSAFE DEEP MERGE / EXTEND FUNCTIONS
    # =============================================================================

    VulnerabilityPattern(
        name="Prototype Pollution - Unsafe Deep Merge/Extend",
        category=VulnCategory.PROTOTYPE_POLLUTION,
        patterns=[
    # =====================================================================
            # LODASH / UNDERSCORE (VULNERABLE VERSIONS)
    # =====================================================================

            # _.merge with user input (any position)
            r'_\.merge\s*\([^)]*req\.(body|query|params)',
            r'_\.merge\s*\([^)]*request\.(args|form|json|data)',
            r'_\.merge\s*\(\s*\{\s*\}\s*,\s*req\.(body|query|params)',
            r'_\.merge\s*\(\s*[^,]+,\s*req\.(body|query|params)',
            r'_\.merge\s*\(\s*[^,]+,\s*[^,]+,\s*req\.(body|query|params)',

            # _.defaultsDeep (vulnerable)
            r'_\.defaultsDeep\s*\([^)]*req\.(body|query|params)',
            r'_\.defaultsDeep\s*\([^)]*request\.(args|form|json|data)',
            r'_\.defaultsDeep\s*\(\s*\{\s*\}\s*,',
            r'_\.defaultsDeep\s*\(\s*[^,]+,\s*(?:userInput|userData|clientData|payload|data|input)',

            # _.mergeWith
            r'_\.mergeWith\s*\([^)]*req\.(body|query|params)',

            # _.set with user-controlled path (path traversal to __proto__)
            r'_\.set\s*\(\s*[^,]+,\s*req\.(body|query|params)',
            r'_\.set\s*\(\s*[^,]+,\s*(?:path|key|prop)\s*,',
            r'_\.setWith\s*\(\s*[^,]+,\s*req\.(body|query|params)',

            # lodash full name
            r'lodash\.merge\s*\([^)]*req\.(body|query|params)',
            r'lodash\.defaultsDeep\s*\([^)]*req\.(body|query|params)',
            r'lodash\.set\s*\(\s*[^,]+,\s*req\.(body|query|params)',

    # =====================================================================
            # JQUERY DEEP EXTEND
    # =====================================================================

            # $.extend with deep=true
            r'\$\.extend\s*\(\s*true\s*,\s*[^,]+,\s*req\.(body|query|params)',
            r'\$\.extend\s*\(\s*true\s*,\s*\{\s*\}\s*,',
            r'jQuery\.extend\s*\(\s*true\s*,\s*[^,]+,\s*req\.(body|query|params)',
            r'jQuery\.extend\s*\(\s*true\s*,\s*\{\s*\}\s*,',

    # =====================================================================
            # HOEK (HAPI ECOSYSTEM)
    # =====================================================================

            r'[Hh]oek\.merge\s*\([^)]*req\.(body|query|params)',
            r'[Hh]oek\.applyToDefaults\s*\([^)]*req\.(body|query|params)',
            r'[Hh]oek\.applyToDefaultsWithShallow\s*\([^)]*req\.(body|query|params)',
            r'[Hh]oek\.clone\s*\(\s*req\.(body|query|params)',

    # =====================================================================
            # DEEPMERGE / DEEP-EXTEND PACKAGES
    # =====================================================================

            # deepmerge
            r'deepmerge\s*\(\s*[^,]+,\s*req\.(body|query|params)',
            r'deepmerge\.all\s*\(\s*\[[^\]]*req\.(body|query|params)',
            r'merge\s*\(\s*[^,]+,\s*req\.(body|query|params)\s*\)',  # Generic merge

            # deep-extend
            r'deepExtend\s*\(\s*[^,]+,\s*req\.(body|query|params)',
            r'deep-extend\s*\(\s*[^,]+,\s*req\.(body|query|params)',

            # extend (various packages)
            r'extend\s*\(\s*true\s*,\s*[^,]+,\s*req\.(body|query|params)',
            r'extend\s*\(\s*\{\s*\}\s*,\s*req\.(body|query|params)',

            # defaults-deep
            r'defaultsDeep\s*\([^)]*req\.(body|query|params)',

            # object-path
            r'objectPath\.set\s*\(\s*[^,]+,\s*req\.(body|query|params)',

            # dot-prop
            r'dotProp\.set\s*\(\s*[^,]+,\s*req\.(body|query|params)',

    # =====================================================================
            # MOUT.JS
    # =====================================================================

            r'mout\.object\.deepMixIn\s*\([^)]*req\.(body|query|params)',
            r'mout\.object\.merge\s*\([^)]*req\.(body|query|params)',

    # =====================================================================
            # JS-YAML UNSAFE LOAD
    # =====================================================================

            r'yaml\.load\s*\(\s*req\.(body|query|params)',
            r'jsyaml\.load\s*\(\s*req\.(body|query|params)',
            r'YAML\.parse\s*\(\s*req\.(body|query|params)',

    # =====================================================================
            # GENERIC MERGE PATTERNS WITH USER INPUT
    # =====================================================================

            # Common merge function names with user input
            r'(?:deepMerge|mergeDeep|recursiveMerge|mergeRecursive|deepAssign|'
            r'deepCopy|deepClone|cloneDeep|assignDeep|extendDeep|'
            r'mergeObjects|objectMerge|combineObjects|mixIn|mixin)\s*\([^)]*req\.(body|query|params)',

            # Generic with common variable names
            r'(?:merge|extend|assign|clone|copy)\s*\(\s*[^,]+,\s*(?:userInput|userData|clientData|payload|data|input|body|params|query)\s*[,\)]',
        ],
        severity=Severity.HIGH,
        languages=[".js", ".ts", ".jsx", ".tsx", ".mjs", ".cjs"],
        false_positive_patterns=[
            r'_\.merge\s*\(\s*[^,]+,\s*\{\s*["\'][a-zA-Z]+["\']\s*:',  # Static object
            r'sanitize',
            r'safeMerge',
            r'secureMerge',
            r'protectedMerge',
            r'//.*merge',
            r'/\*.*merge',
            r'\.clone\s*\(\s*\)',  # No arguments
            r'structuredClone\s*\(',  # Safe browser API
        ],
    ),

    # =============================================================================
    # OBJECT.ASSIGN WITH USER INPUT
    # =============================================================================

    VulnerabilityPattern(
        name="Prototype Pollution - Object.assign with User Input",
        category=VulnCategory.PROTOTYPE_POLLUTION,
        patterns=[
    # =====================================================================
            # OBJECT.ASSIGN PATTERNS
    # =====================================================================

            # Object.assign with empty target and user input
            r'Object\.assign\s*\(\s*\{\s*\}\s*,\s*req\.(body|query|params)',
            r'Object\.assign\s*\(\s*\{\s*\}\s*,\s*request\.(args|form|json|data)',
            r'Object\.assign\s*\(\s*\{\s*\}\s*,\s*(?:userInput|userData|clientData|payload|data|input)\s*\)',

            # Object.assign with target and user input source
            r'Object\.assign\s*\(\s*[^,]+,\s*req\.(body|query|params)',
            r'Object\.assign\s*\(\s*[^,]+,\s*request\.(args|form|json|data)',
            r'Object\.assign\s*\(\s*[^,]+,\s*\.\.\.req\.(body|query|params)',

            # Multiple sources including user input
            r'Object\.assign\s*\(\s*[^,]+,\s*[^,]+,\s*req\.(body|query|params)',

    # =====================================================================
            # SPREAD OPERATOR IN OBJECT LITERALS
    # =====================================================================

            # Direct spread of user input
            r'\{\s*\.\.\.req\.(body|query|params)',
            r'\{\s*\.\.\.request\.(args|form|json|data)',
            r'\{\s*\.\.\.(?:userInput|userData|clientData|payload|data|input)\s*[,\}]',

            # Spread in nested object
            r'\{\s*\w+\s*:\s*\{\s*\.\.\.req\.(body|query|params)',

            # Array spread with objects
            r'\[\s*\.\.\.req\.(body|query|params)',

    # =====================================================================
            # OBJECT CREATION WITH USER INPUT
    # =====================================================================

            # Object.fromEntries
            r'Object\.fromEntries\s*\(\s*req\.(body|query|params)',
            r'Object\.fromEntries\s*\([^)]*Object\.entries\s*\(\s*req\.(body|query|params)',

            # Object.defineProperty with user input
            r'Object\.defineProperty\s*\(\s*[^,]+,\s*req\.(body|query|params)',
            r'Object\.defineProperties\s*\(\s*[^,]+,\s*req\.(body|query|params)',
        ],
        severity=Severity.HIGH,
        languages=[".js", ".ts", ".jsx", ".tsx", ".mjs", ".cjs"],
        false_positive_patterns=[
            r'Object\.assign\s*\(\s*\{\s*\}\s*,\s*\{\s*["\'][a-zA-Z]+["\']\s*:',  # Static object
            r'sanitize',
            r'//.*Object\.assign',
            r'/\*.*Object\.assign',
            r'structuredClone\s*\(',
        ],
    ),

    # =============================================================================
    # RECURSIVE/CUSTOM MERGE FUNCTIONS (VULNERABLE PATTERNS)
    # =============================================================================

    VulnerabilityPattern(
        name="Prototype Pollution - Vulnerable Custom Merge Implementation",
        category=VulnCategory.PROTOTYPE_POLLUTION,
        patterns=[
    # =====================================================================
            # DANGEROUS RECURSIVE MERGE PATTERNS
    # =====================================================================

            # for...in loop without hasOwnProperty check
            r'for\s*\(\s*(?:const|let|var)\s+\w+\s+in\s+\w+\s*\)\s*\{[^}]*\[\s*\w+\s*\]\s*=',

            # Recursive function assigning properties without filtering
            r'function\s+(?:merge|extend|deepMerge|assign)\s*\([^)]*\)\s*\{[^}]*for\s*\(\s*(?:const|let|var)\s+\w+\s+in',

            # Object.keys without filtering __proto__
            r'Object\.keys\s*\([^)]+\)\s*\.(?:forEach|map)\s*\([^)]*\{\s*[^}]*\[\s*\w+\s*\]\s*=',

    # =====================================================================
            # PATH-BASED PROPERTY ACCESS (DOT NOTATION PARSING)
    # =====================================================================

            # Setting property via path string (e.g., "a.b.__proto__.c")
            r'\.split\s*\(\s*["\'][.\[\]]["\']',  # Splitting path
            r'path\.split\s*\(',
            r'key\.split\s*\(',

            # reduce() to traverse path
            r'\.reduce\s*\(\s*\([^)]*\)\s*=>\s*[^,]+\[\s*\w+\s*\]',
            r'\.reduce\s*\(\s*function\s*\([^)]*\)\s*\{[^}]*\[\s*\w+\s*\]',

            # Bracket notation with variable from split
            r'\[\s*parts\[\w+\]\s*\]',
            r'\[\s*keys\[\w+\]\s*\]',
            r'\[\s*segments\[\w+\]\s*\]',
            r'\[\s*path\[\w+\]\s*\]',

    # =====================================================================
            # DYNAMIC KEY ASSIGNMENT
    # =====================================================================

            # Direct assignment with dynamic key
            r'target\s*\[\s*key\s*\]\s*=\s*source\s*\[\s*key\s*\]',
            r'obj\s*\[\s*key\s*\]\s*=\s*value',
            r'result\s*\[\s*prop\s*\]\s*=\s*input\s*\[\s*prop\s*\]',

            # Nested assignment
            r'\[\s*key\s*\]\s*\[\s*\w+\s*\]\s*=',
        ],
        severity=Severity.MEDIUM,
        languages=[".js", ".ts", ".jsx", ".tsx", ".mjs", ".cjs"],
        false_positive_patterns=[
            r'hasOwnProperty\s*\(\s*(?:key|prop|k)',
            r'Object\.hasOwn\s*\(',
            r'Object\.prototype\.hasOwnProperty\.call\s*\(',
            r'key\s*(?:===|!==|==|!=)\s*["\'](?:__proto__|constructor|prototype)["\']',
            r'prop\s*(?:===|!==|==|!=)\s*["\'](?:__proto__|constructor|prototype)["\']',
            r'blacklist',
            r'blocklist',
            r'whitelist',
            r'allowlist',
            r'(?:isPrototypePolluted|isUnsafeKey|isSafeKey)',
            r'\.filter\s*\([^)]*(?:__proto__|constructor|prototype)',
        ],
    ),

    # =============================================================================
    # PROTOTYPE POLLUTION VIA QUERY STRING PARSING
    # =============================================================================

    VulnerabilityPattern(
        name="Prototype Pollution - Query String Parsing",
        category=VulnCategory.PROTOTYPE_POLLUTION,
        patterns=[
    # =====================================================================
            # QS LIBRARY (OLDER VULNERABLE VERSIONS)
    # =====================================================================

            r'qs\.parse\s*\(\s*req\.(url|query|originalUrl)',
            r'qs\.parse\s*\(\s*(?:queryString|query|search)',
            r'qs\.parse\s*\([^)]+,\s*\{\s*allowPrototypes\s*:\s*true',

    # =====================================================================
            # QUERYSTRING MODULE
    # =====================================================================

            r'querystring\.parse\s*\(\s*req\.(url|query)',
            r'querystring\.parse\s*\(\s*(?:queryString|query|search)',

    # =====================================================================
            # URL SEARCHPARAMS WITHOUT SANITIZATION
    # =====================================================================

            r'new\s+URLSearchParams\s*\(\s*req\.(url|query)',
            r'Object\.fromEntries\s*\(\s*new\s+URLSearchParams\s*\(',
            r'Object\.fromEntries\s*\(\s*\w+\.entries\s*\(\s*\)\s*\)',  # Generic entries conversion

    # =====================================================================
            # BODY PARSER WITH EXTENDED
    # =====================================================================

            r'bodyParser\.urlencoded\s*\(\s*\{\s*extended\s*:\s*true',
            r'express\.urlencoded\s*\(\s*\{\s*extended\s*:\s*true',
        ],
        severity=Severity.HIGH,
        languages=[".js", ".ts", ".jsx", ".tsx", ".mjs", ".cjs"],
        false_positive_patterns=[
            r'qs\.parse\s*\([^)]+,\s*\{\s*allowPrototypes\s*:\s*false',
            r'qs\.parse\s*\([^)]+,\s*\{\s*plainObjects\s*:\s*true',
            r'sanitize',
            r'//.*qs\.parse',
        ],
    ),

    # =============================================================================
    # PROTOTYPE POLLUTION VIA CLONING
    # =============================================================================

    VulnerabilityPattern(
        name="Prototype Pollution - Unsafe Object Cloning",
        category=VulnCategory.PROTOTYPE_POLLUTION,
        patterns=[
    # =====================================================================
            # JSON CLONE PATTERN (GENERALLY SAFE BUT CHECK CONTEXT)
    # =====================================================================

            # JSON parse/stringify with user input (can be safe but flag for review)
            r'JSON\.parse\s*\(\s*JSON\.stringify\s*\(\s*req\.(body|query|params)',

    # =====================================================================
            # UNSAFE CLONE LIBRARIES/METHODS
    # =====================================================================

            # clone package
            r'clone\s*\(\s*req\.(body|query|params)',
            r'clone\s*\(\s*request\.(args|form|json|data)',

            # rfdc (really fast deep clone)
            r'rfdc\s*\(\s*\)\s*\(\s*req\.(body|query|params)',

            # fast-copy
            r'copy\s*\(\s*req\.(body|query|params)',
            r'fastCopy\s*\(\s*req\.(body|query|params)',

            # class-transformer (can execute constructors)
            r'plainToClass\s*\([^,]+,\s*req\.(body|query|params)',
            r'plainToInstance\s*\([^,]+,\s*req\.(body|query|params)',

    # =====================================================================
            # RECURSIVE CLONE WITH USER INPUT
    # =====================================================================

            r'(?:deepClone|cloneDeep|recursiveClone|cloneRecursive)\s*\(\s*req\.(body|query|params)',
            r'(?:deepClone|cloneDeep|recursiveClone|cloneRecursive)\s*\(\s*(?:userInput|userData|clientData|payload|data|input)',
        ],
        severity=Severity.MEDIUM,
        languages=[".js", ".ts", ".jsx", ".tsx", ".mjs", ".cjs"],
        false_positive_patterns=[
            r'structuredClone\s*\(',  # Safe browser/Node API
            r'JSON\.parse\s*\(\s*JSON\.stringify\s*\(\s*\{\s*["\'][a-zA-Z]+["\']\s*:',  # Static object
            r'sanitize',
            r'//.*clone',
        ],
    ),

    # =============================================================================
    # PROTOTYPE POLLUTION IN LIBRARIES/FRAMEWORKS
    # =============================================================================

    VulnerabilityPattern(
        name="Prototype Pollution - Framework/Library Specific",
        category=VulnCategory.PROTOTYPE_POLLUTION,
        patterns=[
    # =====================================================================
            # EXPRESS.JS MIDDLEWARE
    # =====================================================================

            # body-parser vulnerabilities
            r'app\.use\s*\(\s*bodyParser\.json\s*\(\s*\{\s*(?:type|strict|limit)',  # Flag for review

    # =====================================================================
            # MONGOOSE/MONGODB
    # =====================================================================

            # Setting nested paths from user input
            r'\.set\s*\(\s*req\.(body|query|params)',
            r'Model\.findByIdAndUpdate\s*\([^,]+,\s*\{\s*\$set\s*:\s*req\.(body|query|params)',
            r'\.updateOne\s*\([^,]+,\s*\{\s*\$set\s*:\s*req\.(body|query|params)',

    # =====================================================================
            # SEQUELIZE
    # =====================================================================

            r'\.update\s*\(\s*req\.(body|query|params)\s*,',
            r'\.create\s*\(\s*req\.(body|query|params)\s*[,\)]',

    # =====================================================================
            # GRAPHQL
    # =====================================================================

            # GraphQL input types with spread
            r'\.\.\.args\s*',
            r'\.\.\.input\s*',
            r'\{\s*\.\.\.context\.req\.(body|query)',

    # =====================================================================
            # VUE.JS
    # =====================================================================

            # Vue.set / this.$set
            r'Vue\.set\s*\(\s*[^,]+,\s*(?:key|prop|path)',
            r'this\.\$set\s*\(\s*[^,]+,\s*(?:key|prop|path)',

    # =====================================================================
            # REACT
    # =====================================================================

            # setState with spread of untrusted data
            r'setState\s*\(\s*\{\s*\.\.\.(?:props|data|input|params)',
            r'setState\s*\(\s*(?:prev|state)\s*=>\s*\(\s*\{\s*\.\.\.prev\s*,\s*\.\.\.(?:props|data|input)',

    # =====================================================================
            # ANGULAR
    # =====================================================================

            # Object.assign in components
            r'Object\.assign\s*\(\s*this\.\w+\s*,\s*(?:data|input|params)',
        ],
        severity=Severity.MEDIUM,
        languages=[".js", ".ts", ".jsx", ".tsx", ".mjs", ".cjs", ".vue"],
        false_positive_patterns=[
            r'sanitize',
            r'validate',
            r'//.*set',
            r'structuredClone',
        ],
    ),

    # =============================================================================
    # PYTHON CLASS POLLUTION (SIMILAR CONCEPT)
    # =============================================================================

    VulnerabilityPattern(
        name="Prototype Pollution - Python Class Pollution",
        category=VulnCategory.PROTOTYPE_POLLUTION,
        patterns=[
    # =====================================================================
            # __class__ MANIPULATION
    # =====================================================================

            r'__class__\s*=',
            r'\[[\s]*["\']__class__["\'][\s]*\]',
            r'setattr\s*\([^,]+,\s*["\']__class__["\']',

    # =====================================================================
            # __dict__ MANIPULATION
    # =====================================================================

            r'__dict__\s*\.\s*update\s*\(\s*(?:request|data|input|payload|params|kwargs)',
            r'__dict__\s*\[\s*["\'][^"\']+["\']\s*\]\s*=',
            r'vars\s*\([^)]+\)\s*\.\s*update\s*\(\s*(?:request|data|input)',

    # =====================================================================
            # __bases__ MANIPULATION
    # =====================================================================

            r'__bases__\s*=',
            r'\[[\s]*["\']__bases__["\'][\s]*\]',

    # =====================================================================
            # __globals__ ACCESS (CODE EXECUTION)
    # =====================================================================

            r'__globals__\s*\[',
            r'\[[\s]*["\']__globals__["\'][\s]*\]',
            r'func_globals\s*\[',

    # =====================================================================
            # UNSAFE **kwargs UNPACKING
    # =====================================================================

            r'\*\*\s*request\.(args|form|json|data|values)',
            r'\*\*\s*(?:data|input|payload|params|kwargs)',
            r'setattr\s*\(\s*[^,]+,\s*(?:key|attr|name|k)\s*,',  # Dynamic setattr

    # =====================================================================
            # RECURSIVE UPDATE WITHOUT FILTERING
    # =====================================================================

            r'\.update\s*\(\s*request\.(args|form|json|data)',
            r'dict\.update\s*\(\s*[^,]+,\s*request\.',

    # =====================================================================
            # PYDANTIC/DATACLASS MANIPULATION
    # =====================================================================

            r'\.(?:dict|model_dump)\s*\(\s*\)\s*\.\s*update\s*\(\s*(?:request|data|input)',
            r'\.parse_obj\s*\(\s*request\.(args|form|json|data)',
            r'\.model_validate\s*\(\s*request\.(args|form|json|data)',
        ],
        severity=Severity.HIGH,
        languages=[".py"],
        false_positive_patterns=[
            r'hasattr\s*\([^,]+,\s*["\']__',
            r'getattr\s*\([^,]+,\s*["\']__[^"\']+["\']\s*,\s*None',
            r'isinstance\s*\(',
            r'#.*__class__',
            r'#.*__dict__',
            r'pydantic\.',
            r'@validator',
            r'@field_validator',
            r'Schema\s*\(',
        ],
    ),

    # =============================================================================
    # SERVER-SIDE PROTOTYPE POLLUTION DETECTION
    # =============================================================================

    VulnerabilityPattern(
        name="Prototype Pollution - Server-Side Gadget Indicators",
        category=VulnCategory.PROTOTYPE_POLLUTION,
        patterns=[
    # =====================================================================
            # KNOWN GADGETS FOR RCE VIA PROTOTYPE POLLUTION
    # =====================================================================

            # child_process (Node.js RCE gadget)
            r'require\s*\(\s*["\']child_process["\']\s*\)',
            r'child_process\.\w+\s*\(',
            r'spawn\s*\(\s*(?:cmd|command|shell)',
            r'exec\s*\(\s*(?:cmd|command|shell)',

            # vm module (sandbox escape)
            r'require\s*\(\s*["\']vm["\']\s*\)',
            r'vm\.runInContext\s*\(',
            r'vm\.runInNewContext\s*\(',

            # EJS template gadget
            r'ejs\.render\s*\(',
            r'ejs\.compile\s*\(',
            r'outputFunctionName',  # EJS PP gadget
            r'escapeFunction',  # EJS PP gadget
            r'localsName',  # EJS PP gadget

            # Pug template gadget
            r'pug\.render\s*\(',
            r'pug\.compile\s*\(',

            # Handlebars gadget
            r'handlebars\.compile\s*\(',
            r'Handlebars\.compile\s*\(',

    # =====================================================================
            # PROTOTYPE POLLUTION TO XSS
    # =====================================================================

            # innerHTML assignment
            r'\.innerHTML\s*=',
            r'\.outerHTML\s*=',

            # DOM manipulation
            r'document\.write\s*\(',
            r'document\.writeln\s*\(',

    # =====================================================================
            # CONSTRUCTOR POLLUTION LEADING TO RCE
    # =====================================================================

            r'\.constructor\s*\(\s*["\']return\s+(?:this|process|require)',
            r'Function\s*\(\s*["\']return\s+(?:this|process|require)',
        ],
        severity=Severity.INFO,  # These are indicators, not direct vulns
        languages=[".js", ".ts", ".jsx", ".tsx", ".mjs", ".cjs"],
        false_positive_patterns=[
            r'//.*child_process',
            r'/\*.*child_process',
            r'sanitize',
            r'escape',
        ],
    ),
    VulnerabilityPattern(
    name="Prototype Pollution - Unsafe Object Manipulation",
    category=VulnCategory.PROTOTYPE_POLLUTION,
    patterns=[
        # =====================================================================
        # VULNERABLE LIBRARY FUNCTIONS
        # =====================================================================
        # Lodash/Underscore dangerous methods
        r'_\.merge\s*\(',
        r'_\.mergeWith\s*\(',
        r'_\.defaultsDeep\s*\(',
        r'_\.setWith\s*\(',
        r'_\.set\s*\(',
        r'_\.assignIn\s*\(',
        r'_\.assignInWith\s*\(',
        r'_\.extendWith\s*\(',
        r'lodash\.merge\s*\(',
        r'lodash\.defaultsDeep\s*\(',
        r'lodash\.set\s*\(',
        # jQuery deep extend
        r'\$\.extend\s*\(\s*true\s*,',
        r'jQuery\.extend\s*\(\s*true\s*,',
        # Other vulnerable libraries
        r'hoek\.merge\s*\(',
        r'hoek\.applyToDefaults\s*\(',
        r'deepmerge\s*\(',
        r'deep-extend\s*\(',
        r'merge-deep\s*\(',
        r'mixin-deep\s*\(',
        r'defaults-deep\s*\(',
        r'clone-deep\s*\(',
        r'deap\.merge\s*\(',
        r'deap\.extend\s*\(',
        
        # =====================================================================
        # OBJECT SPREAD WITH USER INPUT
        # =====================================================================
        # Spreading request body/params directly
        r'\{\s*\.\.\.req\.body',
        r'\{\s*\.\.\.req\.query',
        r'\{\s*\.\.\.req\.params',
        r'\{\s*\.\.\.request\.body',
        r'\{\s*\.\.\.ctx\.request\.body',
        r'\{\s*\.\.\.body\s*\}',
        r'\{\s*\.\.\.params\s*\}',
        r'\{\s*\.\.\.data\s*,',
        r'\{\s*\.\.\.input\s*,',
        r'\{\s*\.\.\.payload\s*,',
        r'Object\.assign\s*\(\s*\{\s*\}\s*,\s*req\.',
        r'Object\.assign\s*\(\s*\{\s*\}\s*,\s*request\.',
        r'Object\.assign\s*\(\s*target\s*,\s*req\.',
        r'Object\.assign\s*\(\s*\w+\s*,\s*JSON\.parse',
        
        # =====================================================================
        # JSON PARSING WITHOUT VALIDATION
        # =====================================================================
        # Direct JSON parse to object assignment
        r'JSON\.parse\s*\([^)]+\)\s*;?\s*(?:const|let|var)?\s*\w+\s*=',
        r'\[\s*\w+\s*\]\s*=\s*JSON\.parse\s*\(',
        r'Object\.assign\s*\([^,]+,\s*JSON\.parse\s*\(',
        r'\.\.\.JSON\.parse\s*\(',
        
        # =====================================================================
        # RECURSIVE/DEEP COPY FUNCTIONS
        # =====================================================================
        # Custom deep clone/copy patterns
        r'function\s+(?:deepClone|deepCopy|cloneDeep|clone)\s*\(',
        r'(?:const|let|var)\s+(?:deepClone|deepCopy|cloneDeep)\s*=\s*\(',
        r'typeof\s+\w+\s*===?\s*["\']object["\']\s*\?\s*(?:deepClone|deepCopy|merge)',
        # Recursive calls with object assignment
        r'typeof\s+source\[\w+\]\s*===?\s*["\']object["\']\s*\?\s*\w+\s*\(',
        r'typeof\s+obj\[\w+\]\s*===?\s*["\']object["\']\s*\?\s*\w+\s*\(',
        
        # =====================================================================
        # PROPERTY DESCRIPTOR MANIPULATION
        # =====================================================================
        r'Object\.defineProperty\s*\(\s*\w+\s*,\s*\w+\s*,',
        r'Object\.defineProperties\s*\(\s*\w+\s*,\s*\w+\s*\)',
        r'Object\.setPrototypeOf\s*\(',
        r'Reflect\.set\s*\(\s*\w+\s*,\s*\w+\s*,',
        r'Reflect\.defineProperty\s*\(',
        
        # =====================================================================
        # UNSAFE DESERIALIZATION TO OBJECT
        # =====================================================================
        # Query string parsing
        r'querystring\.parse\s*\(',
        r'qs\.parse\s*\(',
        r'new\s+URLSearchParams\s*\([^)]*\)\s*(?:\.entries\s*\(\s*\)|\.forEach)',
        # Form data to object
        r'formData\.entries\s*\(',
        r'Object\.fromEntries\s*\(\s*(?:formData|urlParams|searchParams)',
        
        # =====================================================================
        # EVAL/FUNCTION CONSTRUCTOR WITH OBJECT ACCESS
        # =====================================================================
        r'eval\s*\(\s*["\']?\s*\w+\s*\[\s*\w+\s*\]',
        r'new\s+Function\s*\([^)]*\[\s*\w+\s*\]',
        r'\[\s*["\']constructor["\']\s*\]\s*\(\s*["\']',
        
        # =====================================================================
        # PROTOTYPE CHAIN ACCESS
        # =====================================================================
        # Direct prototype access
        r'\.prototype\s*\[\s*\w+\s*\]\s*=',
        r'\[\s*["\']prototype["\']\s*\]\s*\[\s*\w+\s*\]\s*=',
        r'Object\.getPrototypeOf\s*\([^)]+\)\s*\[\s*\w+\s*\]\s*=',
        r'Object\.prototype\.\w+\s*=',
        # Constructor access
        r'\[\s*["\']constructor["\']\s*\]\s*\[\s*["\']prototype["\']\s*\]',
        r'\.constructor\s*\[\s*["\']prototype["\']\s*\]',
        r'\.constructor\.prototype\s*\[\s*\w+\s*\]',
        
        # =====================================================================
        # CONFIGURATION/OPTIONS MERGING
        # =====================================================================
        # Common config merge patterns
        r'config\s*=\s*\{\s*\.\.\.defaults?\s*,\s*\.\.\.(?:options?|opts?|params?|args?)',
        r'options?\s*=\s*\{\s*\.\.\.defaults?\s*,\s*\.\.\.(?:config|params?|args?)',
        r'settings?\s*=\s*Object\.assign\s*\(\s*\{\s*\}\s*,\s*defaults?\s*,',
        # Express/Koa middleware body merge
        r'req\.body\s*=\s*\{\s*\.\.\.req\.body',
        r'ctx\.request\.body\s*=\s*\{\s*\.\.\.ctx\.request\.body',
        
        # =====================================================================
        # TEMPLATE/VIEW DATA INJECTION
        # =====================================================================
        # Rendering with merged user data
        r'\.render\s*\(\s*["\'][^"\']+["\']\s*,\s*\{\s*\.\.\.req\.',
        r'\.render\s*\(\s*["\'][^"\']+["\']\s*,\s*Object\.assign\s*\([^,]+,\s*req\.',
        r'res\.locals\s*=\s*\{\s*\.\.\.req\.',
        r'res\.locals\s*=\s*Object\.assign\s*\([^,]+,\s*req\.',
        
        # =====================================================================
        # DATABASE/ORM UNSAFE UPDATES
        # =====================================================================
        # MongoDB-style updates with user input
        r'\.\$set\s*\(\s*req\.body',
        r'\.updateOne\s*\(\s*\{[^}]*\}\s*,\s*req\.body',
        r'\.updateMany\s*\(\s*\{[^}]*\}\s*,\s*req\.body',
        r'\.findOneAndUpdate\s*\(\s*\{[^}]*\}\s*,\s*\{\s*\.\.\.req\.body',
        # Sequelize/ORM updates
        r'\.update\s*\(\s*req\.body\s*[,)]',
        r'\.update\s*\(\s*\{\s*\.\.\.req\.body',
        
        # =====================================================================
        # CLASS INSTANCE POLLUTION
        # =====================================================================
        # Constructor with object spread
        r'constructor\s*\([^)]*\)\s*\{[^}]*Object\.assign\s*\(\s*this\s*,',
        r'constructor\s*\([^)]*\)\s*\{[^}]*for\s*\(\s*(?:const|let|var)\s+\w+\s+in\s+\w+\s*\)',
        # this[key] assignment in loops
        r'this\s*\[\s*\w+\s*\]\s*=\s*\w+\s*\[\s*\w+\s*\]',
        r'this\s*\[\s*key\s*\]\s*=',
        r'this\s*\[\s*prop\s*\]\s*=',
        r'self\s*\[\s*\w+\s*\]\s*=\s*\w+\s*\[\s*\w+\s*\]',
    ],
    severity=Severity.HIGH,
    languages=[".js", ".ts", ".jsx", ".tsx", ".mjs", ".cjs"],
    false_positive_patterns=[
        # Proper prototype checks
        r'hasOwnProperty\s*\(',
        r'Object\.hasOwn\s*\(',
        r'Object\.prototype\.hasOwnProperty\.call\s*\(',
        # Key filtering/validation
        r'(?:key|prop|property|k)\s*(?:===|!==|==|!=)\s*["\'](?:__proto__|constructor|prototype)["\']',
        r'(?:key|prop|property)\s*\.(?:startsWith|includes)\s*\(\s*["\'](?:__|constructor|prototype)',
        r'(?:blacklist|blocklist|denylist|forbidden|unsafe|dangerous)(?:Keys?|Props?|Properties)?',
        r'(?:whitelist|allowlist|safelist|allowed|safe)(?:Keys?|Props?|Properties)?',
        r'(?:isPrototypePolluted|isUnsafeKey|isSafeKey|isPolluted|checkPrototype)',
        r'\.filter\s*\([^)]*(?:__proto__|constructor|prototype)',
        r'(?:sanitize|validate|clean|filter)(?:Key|Prop|Input|Object)',
        # Object.freeze/seal
        r'Object\.freeze\s*\(',
        r'Object\.seal\s*\(',
        r'Object\.preventExtensions\s*\(',
        # Safe JSON parsing
        r'JSON\.parse\s*\([^)]+,\s*(?:reviver|sanitize)',
        # Map/Set usage (immune to PP)
        r'new\s+Map\s*\(',
        r'new\s+Set\s*\(',
        # Null prototype objects
        r'Object\.create\s*\(\s*null\s*\)',
        # Test/mock patterns
        r'(?:describe|it|test|expect|mock|jest|sinon|chai)\s*\(',
        r'\.spec\.',
        r'\.test\.',
    ],
),

    # =========================================================================
    # SQL INJECTION PATTERNS - ENHANCED WITH TAINT TRACKING HEURISTICS
    # =========================================================================
    #
    # These patterns detect SQL injection including evasion techniques like:
    # - Variable indirection (passing query through variables)
    # - StringBuilder/StringBuffer construction
    # - Method return values used in queries
    # - Format methods and string interpolation
    #
    # =========================================================================

    VulnerabilityPattern(
        name="SQL Injection - String Concatenation",
        category=VulnCategory.SQL_INJECTION,
        patterns=[
            # Direct concatenation
            r'["\']SELECT\s+.+\s+FROM\s+.+["\']\s*\+',
            r'["\']INSERT\s+INTO\s+.+["\']\s*\+',
            r'["\']UPDATE\s+.+\s+SET\s+.+["\']\s*\+',
            r'["\']DELETE\s+FROM\s+.+["\']\s*\+',
            r'["\']DROP\s+.+["\']\s*\+',
            r'["\']TRUNCATE\s+.+["\']\s*\+',
            r'["\']ALTER\s+TABLE\s+.+["\']\s*\+',
            r'["\']CREATE\s+.+["\']\s*\+',
            # WHERE clause concatenation
            r'["\'].*WHERE\s+\w+\s*=\s*[\'"]?\s*["\']\s*\+',
            r'["\'].*AND\s+\w+\s*=\s*["\']\s*\+',
            r'["\'].*OR\s+\w+\s*=\s*["\']\s*\+',
            r'["\'].*LIKE\s+[\'"]?\s*["\']\s*\+',
            r'["\'].*IN\s*\(\s*["\']\s*\+',
            r'["\'].*ORDER\s+BY\s+["\']\s*\+',
            r'["\'].*GROUP\s+BY\s+["\']\s*\+',
            r'["\'].*HAVING\s+["\']\s*\+',
            r'["\'].*UNION\s+["\']\s*\+',
            r'["\'].*JOIN\s+["\']\s*\+',
            # Variable assignment with SQL
            r'=\s*["\']SELECT\s+.+["\']\s*\+',
            r'=\s*["\']INSERT\s+.+["\']\s*\+',
            r'=\s*["\']UPDATE\s+.+["\']\s*\+',
            r'=\s*["\']DELETE\s+.+["\']\s*\+',
            # Generic string building with variable
            r'["\']\s*\+\s*[a-zA-Z_]\w*\s*\+\s*["\']',
            # Concatenation with request/user input
            r'["\']\s*\+\s*(?:req|request|params|query|body|input|user)\.',
            r'["\']\s*\+\s*\$_(?:GET|POST|REQUEST|COOKIE)\[',
        ],
        severity=Severity.CRITICAL,
        languages=[".js", ".ts", ".jsx", ".tsx", ".py", ".php", ".java", ".cs", ".rb", ".go", ".kt"],
        false_positive_patterns=[
            r'//.*SELECT',
            r'#.*SELECT',
            r'/\*.*SELECT',
            r'PreparedStatement',
            r'prepareStatement',
            r'\+\s*["\']["\']',
            r'\?\s*[,\)]',
            r'setString\s*\(',
            r'setInt\s*\(',
            r'setParameter\s*\(',
            r'AddWithValue\s*\(',
            r'@\w+\s*[,\)]',
            r':\w+\s*[,\)]',
            r'\$\d+\s*[,\)]',
            r'parameterized',
            r'\.Parameters\.Add',
            r'\.bind\s*\(',
            r'\.placeholder',
            r'QueryBuilder',
            r'query_builder',
            r'whereRaw.*\?',
            r'\.escape\s*\(',
            r'mysql_real_escape_string',
            r'pg_escape_string',
            r'\.quote\s*\(',
        ],
    ),

    VulnerabilityPattern(
        name="SQL Injection - Variable Passed to Execute (Taint Sink)",
        category=VulnCategory.SQL_INJECTION,
        patterns=[
            # Java Statement.execute with variable (not string literal)
            r'\.execute\s*\(\s*[a-zA-Z_]\w*\s*\)',
            r'\.executeQuery\s*\(\s*[a-zA-Z_]\w*\s*\)',
            r'\.executeUpdate\s*\(\s*[a-zA-Z_]\w*\s*\)',
            r'\.executeBatch\s*\(\s*\)',
            r'\.addBatch\s*\(\s*[a-zA-Z_]\w*\s*\)',
            # Java Statement.execute with method call result
            r'\.execute\s*\(\s*\w+\s*\.\s*\w+\s*\([^)]*\)\s*\)',
            r'\.executeQuery\s*\(\s*\w+\s*\.\s*\w+\s*\([^)]*\)\s*\)',
            r'\.executeUpdate\s*\(\s*\w+\s*\.\s*\w+\s*\([^)]*\)\s*\)',
            # Spring JdbcTemplate with variable
            r'jdbcTemplate\.query\s*\(\s*[a-zA-Z_]\w*\s*,',
            r'jdbcTemplate\.queryForList\s*\(\s*[a-zA-Z_]\w*\s*,',
            r'jdbcTemplate\.queryForObject\s*\(\s*[a-zA-Z_]\w*\s*,',
            r'jdbcTemplate\.queryForMap\s*\(\s*[a-zA-Z_]\w*\s*,',
            r'jdbcTemplate\.queryForRowSet\s*\(\s*[a-zA-Z_]\w*\s*,',
            r'jdbcTemplate\.update\s*\(\s*[a-zA-Z_]\w*\s*[,\)]',
            r'jdbcTemplate\.execute\s*\(\s*[a-zA-Z_]\w*\s*\)',
            r'jdbcTemplate\.batchUpdate\s*\(\s*[a-zA-Z_]\w*\s*[,\)]',
            r'namedParameterJdbcTemplate\.query\s*\(\s*[a-zA-Z_]\w*\s*,',
            r'namedParameterJdbcTemplate\.update\s*\(\s*[a-zA-Z_]\w*\s*,',
            # Python cursor.execute with variable
            r'cursor\.execute\s*\(\s*[a-zA-Z_]\w*\s*\)',
            r'cur\.execute\s*\(\s*[a-zA-Z_]\w*\s*\)',
            r'\.execute\s*\(\s*[a-zA-Z_]\w*\s*\)',
            r'cursor\.executemany\s*\(\s*[a-zA-Z_]\w*\s*,',
            r'\.executescript\s*\(\s*[a-zA-Z_]\w*\s*\)',
            # C# SqlCommand with variable
            r'SqlCommand\s*\(\s*[a-zA-Z_]\w*\s*,',
            r'\.CommandText\s*=\s*[a-zA-Z_]\w*\s*;',
            r'OracleCommand\s*\(\s*[a-zA-Z_]\w*\s*,',
            r'MySqlCommand\s*\(\s*[a-zA-Z_]\w*\s*,',
            r'NpgsqlCommand\s*\(\s*[a-zA-Z_]\w*\s*,',
            # Go db.Query with variable
            r'db\.Query\s*\(\s*[a-zA-Z_]\w*\s*\)',
            r'db\.Exec\s*\(\s*[a-zA-Z_]\w*\s*\)',
            r'db\.QueryRow\s*\(\s*[a-zA-Z_]\w*\s*\)',
            r'db\.QueryContext\s*\([^,]+,\s*[a-zA-Z_]\w*\s*\)',
            r'db\.ExecContext\s*\([^,]+,\s*[a-zA-Z_]\w*\s*\)',
            r'tx\.Query\s*\(\s*[a-zA-Z_]\w*\s*\)',
            r'tx\.Exec\s*\(\s*[a-zA-Z_]\w*\s*\)',
            # Ruby ActiveRecord
            r'\.execute\s*\(\s*[a-zA-Z_]\w*\s*\)',
            r'\.select_all\s*\(\s*[a-zA-Z_]\w*\s*\)',
            r'\.exec_query\s*\(\s*[a-zA-Z_]\w*\s*\)',
            r'find_by_sql\s*\(\s*[a-zA-Z_]\w*\s*\)',
        ],
        severity=Severity.HIGH,
        languages=[".java", ".kt", ".scala", ".py", ".cs", ".go", ".rb"],
        false_positive_patterns=[
            r'PreparedStatement',
            r'prepareStatement',
            r'prepare\s*\(',
            r'\?\s*[,\)]',
            r'@\w+',
            r':\w+',
            r'setString',
            r'setInt',
            r'setParameter',
            r'bindParam',
            r'\.prepare\s*\(',
            r'\.Prepare\s*\(',
            r'stmt\.Query',
            r'stmt\.Exec',
            # Constant/static query names
            r'QUERY\s*\)',
            r'SQL\s*\)',
            r'_QUERY\s*\)',
            r'_SQL\s*\)',
            r'CONST_',
            r'const\s+\w+\s*=.*\)',
            r'final\s+.*\s*\)',
            r'static\s+final\s+String',
            # ORM safe methods
            r'\.sanitize',
            r'\.escape',
            r'\.quote',
            r'\.where\s*\(\s*\{',
            r'\.findOne\s*\(',
            r'\.findAll\s*\(',
        ],
    ),

    VulnerabilityPattern(
        name="SQL Injection - StringBuilder/StringBuffer Query Construction",
        category=VulnCategory.SQL_INJECTION,
        patterns=[
            # StringBuilder with SQL keywords
            r'StringBuilder\s*\([^)]*SELECT',
            r'StringBuilder\s*\([^)]*INSERT',
            r'StringBuilder\s*\([^)]*UPDATE',
            r'StringBuilder\s*\([^)]*DELETE',
            r'StringBuilder\s*\([^)]*WHERE',
            # StringBuffer with SQL keywords
            r'StringBuffer\s*\([^)]*SELECT',
            r'StringBuffer\s*\([^)]*INSERT',
            r'StringBuffer\s*\([^)]*UPDATE',
            r'StringBuffer\s*\([^)]*DELETE',
            # Append with SQL keywords
            r'\.append\s*\(\s*["\'].*SELECT',
            r'\.append\s*\(\s*["\'].*INSERT',
            r'\.append\s*\(\s*["\'].*UPDATE',
            r'\.append\s*\(\s*["\'].*DELETE',
            r'\.append\s*\(\s*["\'].*WHERE',
            r'\.append\s*\(\s*["\'].*FROM',
            # Append with variable (potential tainted data)
            r'\.append\s*\(\s*[a-zA-Z_]\w*\s*\).*\.append',
            # StringBuilder.toString() used in execute
            r'\.execute\w*\s*\(\s*\w+\.toString\s*\(\s*\)\s*\)',
            # Python string builder patterns
            r'\+=\s*["\'].*SELECT',
            r'\+=\s*["\'].*WHERE',
            r'\.join\s*\([^)]*SELECT',
        ],
        severity=Severity.HIGH,
        languages=[".java", ".kt", ".scala", ".py", ".cs"],
        false_positive_patterns=[
            r'PreparedStatement',
            r'//.*StringBuilder',
            r'#.*StringBuilder',
            r'log\.',
            r'LOG\.',
            r'logger\.',
        ],
    ),

    VulnerabilityPattern(
        name="SQL Injection - Query Built via Method Return (Indirect Taint)",
        category=VulnCategory.SQL_INJECTION,
        patterns=[
            # Method that returns/builds SQL (common naming patterns) - requires SQL keyword in context
            r'def\s+\w*(query|sql|build_query|build_sql|create_query|create_sql|make_query|format_query|generate_query)\w*\s*\([^)]*\)\s*.*(?:SELECT|INSERT|UPDATE|DELETE)',
            r'function\s+\w*(query|sql|buildQuery|buildSql|createQuery|createSql|makeQuery|formatQuery|generateQuery)\w*\s*\([^)]*\)',
            r'private\s+String\s+\w*(query|sql|buildQuery|buildSql|createQuery|createSql)\w*\s*\(',
            r'public\s+String\s+\w*(query|sql|buildQuery|buildSql|createQuery|createSql)\w*\s*\(',
            r'protected\s+String\s+\w*(query|sql|buildQuery|buildSql|createQuery|createSql)\w*\s*\(',
            # Return statement with SQL
            r'return\s+["\']SELECT\s+',
            r'return\s+["\']INSERT\s+',
            r'return\s+["\']UPDATE\s+',
            r'return\s+["\']DELETE\s+',
            # Variable assignment from method that builds SQL (more specific - must have sql/query in name)
            r'\w+\s*=\s*\w*(buildQuery|buildSql|createQuery|createSql|makeQuery|formatQuery|generateQuery|getSql|getQuery)\w*\s*\([^)]*\)',
        ],
        severity=Severity.MEDIUM,
        languages=[".java", ".kt", ".scala", ".py", ".js", ".ts", ".cs", ".rb", ".go"],
        false_positive_patterns=[
            r'//.*return',
            r'#.*return',
            r'PreparedStatement',
            r'parameterized',
            r'sanitize',
            r'escape',
            r'validate',
            # Python built-ins that are not SQL related
            r'getattr\s*\(',
            r'__import__\s*\(',
            r'hasattr\s*\(',
            r'setattr\s*\(',
            # Common non-SQL modules
            r'yaml\.',
            r'pickle\.',
            r'json\.',
            r'marshal\.',
            r'__builtins__',
        ],
    ),

    VulnerabilityPattern(
        name="SQL Injection - Dangerous SQL Construction Patterns",
        category=VulnCategory.SQL_INJECTION,
        patterns=[
            # String.valueOf or toString on user input going to SQL
            r'String\.valueOf\s*\([^)]+\).*(?:SELECT|INSERT|UPDATE|DELETE|WHERE)',
            r'\.toString\s*\(\s*\).*(?:SELECT|INSERT|UPDATE|DELETE|WHERE)',
            # Character-by-character building (like LogicTrap)
            r'for\s*\([^)]*char[^)]*\).*\.append',
            r'for\s*\([^)]*toCharArray[^)]*\)',
            r'\.toCharArray\s*\(\s*\).*append',
            # Map.get used in SQL context
            r'\.get\s*\([^)]+\).*(?:SELECT|INSERT|UPDATE|DELETE|WHERE)',
            r'(?:SELECT|INSERT|UPDATE|DELETE|WHERE).*\.get\s*\(',
            # Params/args used in SQL
            r'params\.get\s*\([^)]+\)',
            r'args\s*\[\s*\d+\s*\].*(?:SELECT|INSERT|UPDATE|DELETE)',
            r'request\.getParameter.*(?:SELECT|INSERT|UPDATE|DELETE)',
        ],
        severity=Severity.HIGH,
        languages=[".java", ".kt", ".scala", ".py", ".js", ".ts", ".cs"],
        false_positive_patterns=[
            r'PreparedStatement',
            r'//.*String\.valueOf',
            r'log\.',
            r'LOG\.',
        ],
    ),

    VulnerabilityPattern(
        name="SQL Injection - Statement Without Parameterization",
        category=VulnCategory.SQL_INJECTION,
        patterns=[
            # createStatement() followed by execute (should use prepareStatement)
            r'createStatement\s*\(\s*\)',
            # Statement object usage (not PreparedStatement)
            r'Statement\s+\w+\s*=',
            r'Statement\s+\w+\s*;',
            # Python cursor without params
            r'cursor\.execute\s*\(\s*[^,\)]+\s*\)(?!\s*,)',
            # Direct query execution without placeholders
            r'\.query\s*\(\s*[^?@:]+\s*\)(?!\s*,\s*\[)',
        ],
        severity=Severity.MEDIUM,
        languages=[".java", ".kt", ".py"],
        false_positive_patterns=[
            r'PreparedStatement',
            r'prepareStatement',
            r'//.*Statement',
            r'#.*cursor',
            r'\.execute\s*\([^,]+,\s*[\[\(]',
            r'\.execute\s*\([^,]+,\s*\{',
        ],
    ),

    VulnerabilityPattern(
        name="SQL Injection - Template Literals/F-strings",
        category=VulnCategory.SQL_INJECTION,
        patterns=[
            # JavaScript template literals
            r'`SELECT\s+.+\s+FROM\s+.+\$\{',
            r'`INSERT\s+INTO\s+.+\$\{',
            r'`UPDATE\s+.+\s+SET\s+.+\$\{',
            r'`DELETE\s+FROM\s+.+\$\{',
            r'`.*WHERE\s+.+=\s*\$\{',
            # Python f-strings
            r'f["\']SELECT\s+.+\s+FROM\s+.+\{',
            r'f["\']INSERT\s+INTO\s+.+\{',
            r'f["\']UPDATE\s+.+\s+SET\s+.+\{',
            r'f["\']DELETE\s+FROM\s+.+\{',
            r'f["\'].*WHERE\s+.+=\s*.*\{',
            # C# interpolated strings
            r'\$"SELECT\s+.+\s+FROM\s+.+\{',
            r'\$"INSERT\s+INTO\s+.+\{',
            r'\$"UPDATE\s+.+\s+SET\s+.+\{',
            r'\$"DELETE\s+FROM\s+.+\{',
            r'\$".*WHERE\s+.+=\s*\{',
            # Ruby string interpolation
            r'["\']SELECT\s+.+\s+FROM\s+.+#\{',
            r'["\'].*WHERE\s+.+=\s*.*#\{',
        ],
        severity=Severity.CRITICAL,
        languages=[".js", ".ts", ".jsx", ".tsx", ".py", ".cs", ".rb"],
        false_positive_patterns=[
            r'\{[\d:,]+\}',
            r'\{\s*\?\s*\}',
            r'\$\d+',
            r'@\w+',
        ],
    ),

    VulnerabilityPattern(
        name="SQL Injection - Format String",
        category=VulnCategory.SQL_INJECTION,
        patterns=[
            # Python % formatting
            r'["\']SELECT\s+.+\s+FROM\s+.+%s.*["\'].*%\s*[\(\[]',
            r'["\'].*WHERE\s+.+%s.*["\'].*%\s*[\(\[]',
            r'["\']SELECT\s+.+["\']\.format\s*\(',
            r'["\'].*WHERE\s+.+["\']\.format\s*\(',
            # C# String.Format
            r'String\.Format\s*\(\s*["\']SELECT\s+.+\{0',
            r'string\.Format\s*\(\s*["\']SELECT\s+.+\{0',
            # Go fmt.Sprintf
            r'fmt\.Sprintf\s*\(\s*["\']SELECT\s+.+%',
            r'fmt\.Sprintf\s*\(\s*["\'].*WHERE\s+.+%',
            # Java String.format
            r'String\.format\s*\(\s*["\']SELECT\s+.+%',
            r'String\.format\s*\(\s*["\'].*WHERE\s+.+%',
        ],
        severity=Severity.CRITICAL,
        languages=[".py", ".php", ".go", ".cs", ".java", ".c", ".cpp"],
        false_positive_patterns=[
            r'%\(\w+\)s',
            r':\w+',
        ],
    ),

    VulnerabilityPattern(
        name="SQL Injection - PHP MySQL",
        category=VulnCategory.SQL_INJECTION,
        patterns=[
            # Superglobal injection
            r'["\']SELECT\s+.+\$_(GET|POST|REQUEST|COOKIE)',
            r'["\']INSERT\s+INTO\s+.+\$_(GET|POST|REQUEST|COOKIE)',
            r'["\']UPDATE\s+.+\$_(GET|POST|REQUEST|COOKIE)',
            r'["\']DELETE\s+FROM\s+.+\$_(GET|POST|REQUEST|COOKIE)',
            r'["\'].*WHERE\s+.+\$_(GET|POST|REQUEST|COOKIE)',
            # Variable concatenation
            r'["\']SELECT\s+.+["\']\s*\.\s*\$\w+',
            r'["\'].*WHERE\s+.+["\']\s*\.\s*\$\w+',
            # Deprecated mysql_* functions
            r'mysql_query\s*\(\s*["\']',
            r'mysql_db_query\s*\(',
            # mysqli/PDO without prepared statements
            r'mysqli_query\s*\(\s*\$\w+,\s*["\'].*\.\s*\$',
            r'\$pdo->query\s*\(\s*["\'].*\.\s*\$',
        ],
        severity=Severity.CRITICAL,
        languages=[".php"],
        false_positive_patterns=[
            r'->prepare\s*\(',
            r'bindParam',
            r'bindValue',
            r'\$stmt',
        ],
    ),

    VulnerabilityPattern(
        name="SQL Injection - Raw Query Methods",
        category=VulnCategory.SQL_INJECTION,
        patterns=[
            # Node.js ORMs
            r'\.raw\s*\(\s*["\']SELECT.+\+',
            r'\.raw\s*\(\s*`SELECT[^`]*\$\{',
            r'sequelize\.query\s*\(\s*["\']SELECT.+\+',
            r'knex\.raw\s*\(\s*["\']SELECT.+\+',
            # Prisma unsafe
            r'prisma\.\$queryRaw\s*`[^`]*\$\{',
            r'prisma\.\$queryRawUnsafe\s*\(',
            r'prisma\.\$executeRawUnsafe\s*\(',
            # Python SQLAlchemy
            r'text\s*\(\s*f["\']SELECT',
            r'\.execute\s*\(\s*f["\']SELECT',
            r'engine\.execute\s*\(\s*f["\']',
            # Django
            r'\.extra\s*\(\s*where\s*=\s*\[',
            r'RawSQL\s*\(\s*f["\']',
            r'cursor\.execute\s*\(\s*f["\']',
            # Ruby ActiveRecord
            r'\.find_by_sql\s*\(\s*["\'].*#\{',
            r'\.execute\s*\(\s*["\'].*#\{',
            # C# Entity Framework
            r'FromSqlRaw\s*\(\s*\$"SELECT',
            r'ExecuteSqlRaw\s*\(\s*\$"',
        ],
        severity=Severity.CRITICAL,
        languages=[".js", ".ts", ".py", ".cs", ".rb"],
        false_positive_patterns=[
            r'\?\s*[,\)]',
            r'\$\d+',
            r':\w+',
            r'@\w+',
            r'bindparams',
        ],
    ),

    VulnerabilityPattern(
        name="SQL Injection - Stored/Second-Order",
        category=VulnCategory.SQL_INJECTION,
        patterns=[
            # Building queries from database values
            r'\.execute\s*\(\s*row\[',
            r'\.execute\s*\(\s*result\[',
            r'executeQuery\s*\(\s*rs\.getString',
            r'executeQuery\s*\(\s*resultSet\.get',
            # Using session/cookie data
            r'["\']SELECT.*["\']\s*\+\s*session\.',
            r'["\']SELECT.*["\']\s*\+\s*Session\[',
        ],
        severity=Severity.HIGH,
        languages=[".js", ".ts", ".py", ".php", ".java", ".cs", ".rb", ".go"],
        false_positive_patterns=[],
    ),

    VulnerabilityPattern(
        name="SQL Injection - ORM Bypass/Unsafe Methods",
        category=VulnCategory.SQL_INJECTION,
        patterns=[
            # Django
            r'\.extra\s*\(\s*where\s*=\s*\[.*%',
            r'RawSQL\s*\(\s*["\'].*%',
            r'RawSQL\s*\(\s*f["\']',
            # SQLAlchemy
            r'text\s*\(\s*["\'].*%.*["\']',
            r'text\s*\(\s*f["\']',
            r'literal_column\s*\(\s*f["\']',
            # Sequelize
            r'sequelize\.literal\s*\(\s*["\'].*\+',
            r'Sequelize\.literal\s*\(\s*["\'].*\+',
            # ActiveRecord
            r'\.where\s*\(\s*["\'].*#\{',
            r'\.order\s*\(\s*["\'].*#\{',
            # Hibernate HQL
            r'createQuery\s*\(\s*["\'].*\+\s*\w+',
            r'createNativeQuery\s*\(\s*["\'].*\+\s*\w+',
        ],
        severity=Severity.HIGH,
        languages=[".py", ".js", ".ts", ".rb", ".java", ".kt"],
        false_positive_patterns=[
            r':\w+',
            r'\?\s*[,\)]',
            r'@Param',
            r'setParameter',
        ],
    ),

    # =========================================================================
    # NOSQL INJECTION PATTERNS - ENTERPRISE GRADE COMPREHENSIVE DETECTION
    # =========================================================================
    # Version: 2.0
    # Coverage: MongoDB, Redis, CouchDB, Cassandra, DynamoDB, Elasticsearch,
    #           Firebase, Neo4j, ArangoDB, RethinkDB, OrientDB
    # Languages: JavaScript, TypeScript, Python, PHP, Ruby, Java, C#, Go, Kotlin
    # =========================================================================

    # =============================================================================
    # MONGODB INJECTION PATTERNS
    # =============================================================================

    VulnerabilityPattern(
        name="NoSQL Injection - MongoDB Tainted Input (JavaScript/TypeScript)",
        category=VulnCategory.NOSQL_INJECTION,
        patterns=[
    # =====================================================================
            # EXPRESS.JS / NODE.JS - Direct Request Object Usage
    # =====================================================================

            # Basic CRUD with req object - covers all MongoDB methods
            r'\.(find|findOne|findMany|findById|findByIdAndUpdate|findByIdAndDelete|findByIdAndRemove|'
            r'findOneAndUpdate|findOneAndDelete|findOneAndRemove|findOneAndReplace|'
            r'update|updateOne|updateMany|replaceOne|'
            r'delete|deleteOne|deleteMany|remove|'
            r'aggregate|count|countDocuments|estimatedDocumentCount|distinct|'
            r'bulkWrite|insertOne|insertMany|'
            r'watch|changeStream)\s*\(\s*\{[^}]*:\s*req\.(body|query|params|cookies|headers|session|user)',

            # Passing entire req object properties as query
            r'\.(find|findOne|findMany|aggregate|countDocuments|distinct|watch)\s*\(\s*req\.(body|query|params)\s*[,\)]',

            # Object spread/destructuring of user input
            r'\.(find|findOne|findMany|update|updateOne|updateMany|delete|deleteOne|deleteMany|'
            r'aggregate|findOneAnd\w*|replaceOne)\s*\(\s*\{\s*\.\.\.req\.(body|query|params)',

            # Template literals in queries
            r'\.(find|findOne|aggregate)\s*\(\s*\{[^}]*:\s*`[^`]*\$\{[^}]*req\.',

            # Dynamic property access
            r'\.(find|findOne|aggregate)\s*\(\s*\{[^}]*\[\s*req\.(body|query|params)',

    # =====================================================================
            # MONGOOSE SPECIFIC PATTERNS
    # =====================================================================

            # Model methods with user input
            r'Model\.(find|findOne|findById|findOneAndUpdate|findOneAndDelete|'
            r'updateOne|updateMany|deleteOne|deleteMany|countDocuments|'
            r'exists|where|aggregate)\s*\([^)]*req\.(body|query|params)',

            # Mongoose where() chaining with user input
            r'\.where\s*\(\s*req\.(body|query|params)',
            r'\.where\s*\(\s*["\'][^"\']+["\']\s*\)\s*\.(equals|ne|gt|gte|lt|lte|in|nin|regex)\s*\(\s*req\.',

            # Mongoose Query builder with tainted input
            r'\.find\s*\(\s*\)\s*\.(where|equals|or|and|nor|select|sort|limit|skip)\s*\(\s*req\.',

            # Mongoose lean() queries (common pattern)
            r'\.find\s*\([^)]*req\.(body|query|params)[^)]*\)\s*\.lean\s*\(',

            # Mongoose exec() with tainted query
            r'\.find\s*\([^)]*req\.(body|query|params)[^)]*\)\s*\.exec\s*\(',

            # Mongoose populate with user input (can leak data)
            r'\.populate\s*\(\s*req\.(body|query|params)',

    # =====================================================================
            # MONGODB NATIVE DRIVER PATTERNS
    # =====================================================================

            # Collection methods
            r'collection\s*\(\s*[^)]+\s*\)\s*\.(find|findOne|insertOne|insertMany|'
            r'updateOne|updateMany|deleteOne|deleteMany|aggregate|countDocuments|'
            r'distinct|findOneAndUpdate|findOneAndDelete|findOneAndReplace|'
            r'bulkWrite|watch)\s*\(\s*[^)]*req\.(body|query|params)',

            # db.collection pattern
            r'db\s*\.\s*collection\s*\(\s*[^)]+\s*\)\s*\.\w+\s*\(\s*[^)]*req\.',

            # Dynamic collection name from user input (CRITICAL)
            r'db\s*\[\s*req\.(body|query|params)',
            r'db\s*\.\s*collection\s*\(\s*req\.(body|query|params)',
            r'mongoose\s*\.\s*connection\s*\.\s*collection\s*\(\s*req\.',

    # =====================================================================
            # MONGODB OPERATORS FROM USER INPUT
    # =====================================================================

            # Comparison operators
            r'\{\s*\$(?:eq|ne|gt|gte|lt|lte)\s*:\s*req\.(body|query|params)',

            # Array operators
            r'\{\s*\$(?:in|nin|all|elemMatch|size)\s*:\s*req\.(body|query|params)',

            # Logical operators
            r'\{\s*\$(?:or|and|not|nor)\s*:\s*\[?\s*req\.(body|query|params)',

            # Evaluation operators (CRITICAL - can execute code)
            r'\{\s*\$(?:where|expr|regex|text|mod|jsonSchema)\s*:\s*req\.(body|query|params)',

            # Update operators from user input
            r'\{\s*\$(?:set|unset|inc|mul|rename|min|max|currentDate|'
            r'addToSet|pop|pull|push|pullAll|each|position|slice|sort)\s*:\s*[^}]*req\.(body|query|params)',

            # Aggregation pipeline from user input (CRITICAL)
            r'\.aggregate\s*\(\s*\[\s*\{\s*\$\w+\s*:\s*[^}]*req\.(body|query|params)',
            r'\.aggregate\s*\(\s*req\.(body|query|params)',

    # =====================================================================
            # $WHERE OPERATOR (JAVASCRIPT EXECUTION - CRITICAL)
    # =====================================================================

            r'\$where\s*:\s*[^,}]*req\.(body|query|params)',
            r'\$where\s*:\s*["\'][^"\']*\+',
            r'\$where\s*:\s*`[^`]*\$\{',
            r'\$where\s*:\s*function\s*\([^)]*\)\s*\{[^}]*(?:req\.|request\.|params|this\.\w+\s*==\s*[^"\']+)',
            r'"\$where"\s*:\s*[^,}]*(?:req\.|request\.|params|user)',
            r"'\$where'\s*:\s*[^,}]*(?:req\.|request\.|params|user)",

    # =====================================================================
            # DYNAMIC OPERATOR KEYS (OPERATOR INJECTION)
    # =====================================================================

            # User controls the operator name
            r'\{\s*\[\s*req\.(body|query|params)\s*\]\s*:',
            r'\{\s*\[.*\]\s*:\s*req\.(body|query|params)',

            # String concatenation for operator
            r'\{\s*["\']?\s*\$\s*["\']?\s*\+\s*req\.(body|query|params)',
            r'\{\s*`\$\{req\.(body|query|params)',

    # =====================================================================
            # COMMON TAINTED VARIABLE PATTERNS
    # =====================================================================

            r'\.(find|findOne|aggregate|update\w*|delete\w*)\s*\(\s*'
            r'(userInput|queryObj|filterObj|searchQuery|userQuery|clientData|'
            r'requestBody|reqBody|queryParams|userFilter|searchFilter|'
            r'userSearch|clientQuery|inputQuery|rawQuery|unsafeQuery)\s*[,\)]',

    # =====================================================================
            # GRAPHQL + MONGODB PATTERNS
    # =====================================================================

            r'args\s*\.\s*\w+\s*.*\.(find|findOne|aggregate)\s*\(',
            r'context\s*\.\s*req\s*\..*\.(find|findOne|aggregate)\s*\(',
            r'input\s*\.\s*\w+\s*.*\.(find|findOne|aggregate)\s*\(',
        ],
        severity=Severity.CRITICAL,
        languages=[".js", ".ts", ".jsx", ".tsx", ".mjs", ".cjs"],
        false_positive_patterns=[
            r'findById\s*\(\s*req\.params\.id\s*\)',      # Single ID lookup with Mongoose
            r'Types\.ObjectId\s*\(',                       # Explicit ObjectId casting
            r'mongoose\.Types\.ObjectId',                  # Mongoose ObjectId
            r'new\s+ObjectId\s*\(',                        # MongoDB ObjectId
            r'ObjectId\.isValid\s*\(',                     # Validation
            r'ObjectId\.createFromHexString\s*\(',         # Safe creation
            r'sanitize\w*\s*\(',                           # Sanitization
            r'escape\w*\s*\(',                             # Escaping
            r'validator\.\w+',                             # Validator library
            r'Joi\.\w+',                                   # Joi validation
            r'yup\.\w+',                                   # Yup validation
            r'zod\.\w+',                                   # Zod validation
            r'express-validator',                          # Express validator
            r'mongo-sanitize',                             # Mongo sanitize
            r'sanitize-mongo',                             # Another sanitizer
            r'express-mongo-sanitize',                     # Express middleware
            r'\.isMongoId\s*\(',                           # Validator check
            r'isValidObjectId\s*\(',                       # Custom validation
            r'parseInt\s*\(\s*req\.',                      # Parsing to int
            r'Number\s*\(\s*req\.',                        # Casting to number
            r'String\s*\(\s*req\.',                        # Casting to string (partial)
            r'Boolean\s*\(\s*req\.',                       # Casting to boolean
            r'\.trim\s*\(\s*\)\s*$',                       # Just trimming
        ],
    ),

    VulnerabilityPattern(
        name="NoSQL Injection - MongoDB Tainted Input (Python)",
        category=VulnCategory.NOSQL_INJECTION,
        patterns=[
    # =====================================================================
            # PYMONGO PATTERNS
    # =====================================================================

            # Direct request object usage (Flask)
            r'\.(?:find|find_one|find_one_and_update|find_one_and_delete|find_one_and_replace|'
            r'update_one|update_many|delete_one|delete_many|replace_one|'
            r'aggregate|count_documents|estimated_document_count|distinct|'
            r'insert_one|insert_many|bulk_write)\s*\(\s*[^)]*request\.(args|form|json|data|values|get_json|files)',

            # request.args.get(), request.form.get() patterns
            r'\.(?:find|find_one|aggregate|update_one|delete_one)\s*\([^)]*request\.(?:args|form|json|data)\.get\s*\(',
            r'\.(?:find|find_one|aggregate)\s*\(\s*\{[^}]*:\s*request\.(?:args|form|json)\.get\s*\(',

            # Django request patterns
            r'\.(?:find|find_one|update|delete|aggregate)\w*\s*\(\s*[^)]*request\.(GET|POST|data|body|COOKIES|META)',
            r'\.(?:find|find_one|aggregate)\s*\(\s*\{[^}]*:\s*request\.(GET|POST|data)\s*\[',
            r'\.(?:find|find_one|aggregate)\s*\(\s*\{[^}]*:\s*request\.(GET|POST|data)\.get\s*\(',

            # FastAPI patterns
            r'\.(?:find|find_one|aggregate)\s*\([^)]*(?:query|body|form|path)\s*\.\s*\w+',
            r'async\s+def\s+\w+\s*\([^)]*\)\s*:.*\.(?:find|find_one|aggregate)\s*\(',

    # =====================================================================
            # VARIABLE TAINT TRACKING
    # =====================================================================

            # Common tainted variable names
            r'\.(?:find|find_one|aggregate|update_one|delete_one|count_documents)\s*\(\s*'
            r'(?:\{[^}]*:\s*)?(query_val|user_val|input_val|param_val|search_val|'
            r'user_input|user_data|query_data|form_data|request_data|payload|'
            r'filter_dict|query_dict|search_query|user_query|raw_query|'
            r'unsafe_query|client_query|input_data|user_filter|search_filter|'
            r'query_param|filter_param|mongo_query|db_query)\s*[,\)]',

            # Variables ending with common suffixes
            r'\.(?:find|find_one|aggregate)\s*\(\s*\{[^}]*:\s*[a-z_]+(?:_val|_input|_data|_param|_query)\s*[,\}]',

            # Generic variable in find (higher FP but catches more)
            r'(?:db|client|mongo|collection)\.\w+\.(?:find|find_one)\s*\(\s*(?!["\'\{])([a-z_][a-z0-9_]*)\s*[,\)]',

    # =====================================================================
            # STRING INJECTION PATTERNS
    # =====================================================================

            # f-string in query (CRITICAL)
            r'\.(?:find|find_one|aggregate|update_one|delete_one)\s*\(\s*f["\']',
            r'\.(?:find|find_one|aggregate)\s*\(\s*f["\'].*\{.*request',
            r'\.(?:find|find_one|aggregate)\s*\(\s*f["\'].*\{.*(?:query|param|input|data)',

            # .format() in query
            r'\.(?:find|find_one|aggregate)\s*\(\s*["\'][^"\']*\{[^}]*\}[^"\']*["\']\.format\s*\(',
            r'\.(?:find|find_one|aggregate)\s*\(\s*["\'][^"\']*%[sd][^"\']*["\'].*%\s*\(',

            # String concatenation
            r'\.(?:find|find_one|aggregate)\s*\(\s*["\'].*\+.*(?:request|query|param|input)',

    # =====================================================================
            # MOTOR (ASYNC MONGODB) PATTERNS
    # =====================================================================

            r'await\s+\w+\.(?:find|find_one|aggregate|update_one|delete_one|'
            r'find_one_and_update|find_one_and_delete|count_documents)\s*\([^)]*request\.',
            r'await\s+(?:db|client|collection)\.\w+\.(?:find|find_one|aggregate)\s*\([^)]*(?:query|param|input|data)',
            r'async\s+for\s+\w+\s+in\s+\w+\.find\s*\([^)]*request\.',

    # =====================================================================
            # MONGOENGINE / ODM PATTERNS
    # =====================================================================

            # MongoEngine queries
            r'\.objects\s*\(\s*__raw__\s*=\s*[^)]*request\.',
            r'\.objects\s*\(\s*__raw__\s*=\s*[^)]*(?:query|param|input|data)',
            r'\.objects\s*\.\s*filter\s*\(\s*\*\*\s*request\.',
            r'\.objects\s*\(\s*\*\*\s*request\.(args|form|json|data)',

            # Beanie (async ODM)
            r'await\s+\w+\.find\s*\(\s*\{[^}]*:\s*.*request\.',
            r'await\s+\w+\.find_one\s*\(\s*\{[^}]*:\s*.*(?:query|param|input)',

    # =====================================================================
            # DANGEROUS OPERATIONS
    # =====================================================================

            # eval/exec with MongoDB
            r'(?:eval|exec)\s*\([^)]*(?:find|mongo|collection|pymongo)',
            r'(?:eval|exec)\s*\([^)]*(?:request|query|param|input)',

            # json.loads directly in query (common vulnerability)
            r'\.(?:find|find_one|aggregate)\s*\(\s*json\.loads\s*\(\s*request\.',
            r'\.(?:find|find_one|aggregate)\s*\(\s*json\.loads\s*\(',

            # ast.literal_eval (safer but still risky with untrusted input)
            r'\.(?:find|find_one|aggregate)\s*\(\s*ast\.literal_eval\s*\(\s*request\.',

            # Dict unpacking
            r'\.(?:find|find_one|aggregate)\s*\(\s*\{\s*\*\*\s*(?:request|query|param|input)',
            r'\.(?:find|find_one|aggregate)\s*\(\s*\*\*\s*request\.(args|form|json|data)',

    # =====================================================================
            # OPERATOR INJECTION
    # =====================================================================

            # MongoDB operators from variables
            r'\{\s*["\']?\$(?:where|regex|expr|gt|gte|lt|lte|ne|eq|in|nin|or|and|not|nor)["\']?\s*:\s*'
            r'(?:request|query|param|input|data|user)',

            # Dynamic operator key
            r'\{\s*f?["\']?\$\{?(?:request|query|param|op)',
            r'\{\s*\*\*\s*\{\s*["\']?\$',

    # =====================================================================
            # AGGREGATION PIPELINE INJECTION
    # =====================================================================

            r'\.aggregate\s*\(\s*\[?\s*request\.(args|form|json|data)',
            r'\.aggregate\s*\(\s*\[?\s*(?:query|param|input|pipeline)',
            r'pipeline\s*=\s*request\.(args|form|json|data)',
            r'pipeline\s*\.\s*(?:append|extend|insert)\s*\(\s*request\.',
        ],
        severity=Severity.CRITICAL,
        languages=[".py"],
        false_positive_patterns=[
            r'ObjectId\s*\(',
            r'bson\.ObjectId\s*\(',
            r'bson\.objectid\.ObjectId\s*\(',
            r'ObjectId\.is_valid\s*\(',
            r'isinstance\s*\([^,]+,\s*(?:ObjectId|str|int|float|bool|dict|list)\)',
            r'int\s*\(\s*request\.',
            r'float\s*\(\s*request\.',
            r'str\s*\(\s*request\.',
            r'bool\s*\(\s*request\.',
            r'\.get\s*\([^)]+,\s*(?:None|default|""|\'\')?\s*\)',
            r'validate',
            r'schema',
            r'pydantic',
            r'marshmallow',
            r'wtforms',
            r'cerberus',
            r'voluptuous',
            r'@validator',
            r'@field_validator',
            r'Field\s*\(',
            r'Query\s*\(',
            r'Body\s*\(',
            r'Depends\s*\(',
            r'sanitize',
            r'escape',
            r'clean',
            r'#.*(?:safe|sanitized|validated)',
        ],
    ),

    VulnerabilityPattern(
        name="NoSQL Injection - MongoDB Tainted Input (PHP)",
        category=VulnCategory.NOSQL_INJECTION,
        patterns=[
    # =====================================================================
            # PHP MONGODB EXTENSION
    # =====================================================================

            # Superglobal injection
            r'->\s*(?:find|findOne|findOneAndUpdate|findOneAndDelete|findOneAndReplace|'
            r'updateOne|updateMany|deleteOne|deleteMany|replaceOne|'
            r'aggregate|count|countDocuments|distinct|'
            r'insertOne|insertMany|bulkWrite)\s*\(\s*[^)]*\$_(GET|POST|REQUEST|COOKIE|SERVER|SESSION)',

            # Array with superglobals
            r'->\s*(?:find|findOne|aggregate)\s*\(\s*\[[^\]]*=>\s*\$_(GET|POST|REQUEST|COOKIE)',

            # Passing superglobal directly
            r'->\s*(?:find|findOne|aggregate)\s*\(\s*\$_(GET|POST|REQUEST)',

            # Variable from superglobal
            r'->\s*(?:find|findOne|aggregate)\s*\(\s*\$(?:query|filter|search|data|input|params?)',

    # =====================================================================
            # LARAVEL MONGODB PATTERNS
    # =====================================================================

            # Request facade/helper
            r'->\s*(?:where|find|get|first|aggregate)\s*\([^)]*(?:\$request->|request\s*\()',
            r'->\s*(?:where|find)\s*\([^)]*Input::\s*(?:get|all|only)',

            # Raw queries with user input
            r'->\s*whereRaw\s*\([^)]*\$_(GET|POST|REQUEST)',
            r'->\s*raw\s*\([^)]*\$_(GET|POST|REQUEST)',

            # Collection variable injection
            r'DB::collection\s*\(\s*\$_(GET|POST|REQUEST)',
            r'DB::collection\s*\(\s*\$(?:collection|table)',

    # =====================================================================
            # DOCTRINE MONGODB ODM
    # =====================================================================

            r'createQueryBuilder\s*\([^)]*\)\s*->\s*(?:field|where|equals)\s*\([^)]*\$_(GET|POST|REQUEST)',
            r'->\s*findBy\s*\(\s*\[[^\]]*=>\s*\$_(GET|POST|REQUEST)',
            r'->\s*findOneBy\s*\(\s*\[[^\]]*=>\s*\$_(GET|POST|REQUEST)',

    # =====================================================================
            # STRING INJECTION
    # =====================================================================

            # String concatenation in query
            r'->\s*(?:find|findOne|aggregate)\s*\(\s*["\'].*\.\s*\$',
            r'->\s*(?:find|findOne|aggregate)\s*\(\s*"[^"]*\$\{',

            # json_decode from user input
            r'->\s*(?:find|findOne|aggregate)\s*\(\s*json_decode\s*\(\s*\$_(GET|POST|REQUEST)',

            # unserialize (CRITICAL)
            r'->\s*(?:find|findOne|aggregate)\s*\(\s*unserialize\s*\(',

    # =====================================================================
            # OPERATOR INJECTION
    # =====================================================================

            r'\[\s*["\']?\$(?:where|regex|gt|gte|lt|lte|ne|eq|in|nin|or|and)["\']?\s*=>\s*\$_(GET|POST|REQUEST)',
            r'\[\s*\$_(GET|POST|REQUEST).*=>\s*',  # Dynamic key from user input
        ],
        severity=Severity.CRITICAL,
        languages=[".php"],
        false_positive_patterns=[
            r'new\s+MongoDB\\BSON\\ObjectId\s*\(',
            r'ObjectId\s*\(\s*\$',
            r'filter_var\s*\(',
            r'filter_input\s*\(',
            r'htmlspecialchars\s*\(',
            r'htmlentities\s*\(',
            r'preg_match\s*\(',
            r'is_string\s*\(',
            r'is_int\s*\(',
            r'is_numeric\s*\(',
            r'intval\s*\(',
            r'floatval\s*\(',
            r'strval\s*\(',
            r'(?:sanitize|validate|clean|escape)\w*\s*\(',
            r'->validated\s*\(',
            r'->validate\s*\(',
            r'Validator::\s*make\s*\(',
        ],
    ),

    VulnerabilityPattern(
        name="NoSQL Injection - MongoDB Tainted Input (Ruby)",
        category=VulnCategory.NOSQL_INJECTION,
        patterns=[
    # =====================================================================
            # MONGOID PATTERNS
    # =====================================================================

            # Direct params usage
            r'\.(?:where|find|find_by|find_or_create_by|find_or_initialize_by|'
            r'update|update_all|delete|delete_all|destroy|destroy_all|'
            r'first|last|all|count|exists\?|'
            r'create|create!|new|build)\s*\(\s*params\s*\[',

            # Params hash unpacking
            r'\.(?:where|find|find_by)\s*\(\s*params\.(?:permit|require|fetch|slice|to_unsafe_h)',
            r'\.(?:where|find|find_by)\s*\(\s*params\s*\)',
            r'\.(?:where|find|find_by)\s*\(\s*\*\*params',

            # String interpolation in queries
            r'\.(?:where|find)\s*\(\s*["\'].*#\{.*params',
            r'\.(?:where|find)\s*\(\s*"[^"]*#\{[^}]*\}[^"]*"',

    # =====================================================================
            # MONGO RUBY DRIVER
    # =====================================================================

            r'collection\s*\[\s*[^\]]+\s*\]\s*\.(?:find|insert|update|delete|aggregate)\s*\(\s*params',
            r'\.(?:find|find_one|insert_one|insert_many|update_one|update_many|'
            r'delete_one|delete_many|replace_one|aggregate|count_documents|distinct)\s*\(\s*params',

    # =====================================================================
            # RAILS CONTROLLER PATTERNS
    # =====================================================================

            r'@\w+\s*=\s*\w+\.(?:where|find|find_by)\s*\(\s*params',
            r'\.(?:where|find_by)\s*\(\s*(?:user_params|search_params|query_params|filter_params)',

            # Strong parameters bypass
            r'\.(?:where|find)\s*\(\s*params\.to_unsafe_h',
            r'\.(?:where|find)\s*\(\s*request\.parameters',
            r'\.(?:where|find)\s*\(\s*request\.query_parameters',
            r'\.(?:where|find)\s*\(\s*request\.request_parameters',

    # =====================================================================
            # OPERATOR INJECTION
    # =====================================================================

            r'\{\s*["\']?\$(?:where|regex|gt|gte|lt|lte|ne|eq|in|nin|or|and)["\']?\s*=>\s*params\s*\[',
            r'\.(?:where|find)\s*\(\s*\{\s*[^}]*=>\s*params\s*\[',
        ],
        severity=Severity.CRITICAL,
        languages=[".rb", ".erb", ".haml", ".slim"],
        false_positive_patterns=[
            r'BSON::ObjectId\s*\(',
            r'\.to_s\s*$',
            r'\.to_i\s*$',
            r'\.permit\s*\(',
            r'\.require\s*\(\s*:\w+\s*\)\s*\.permit\s*\(',
            r'params\s*\[\s*:id\s*\]',
            r'params\.fetch\s*\(\s*:\w+\s*,\s*[^)]+\)',
            r'sanitize',
            r'escape',
            r'validates?\s*:',
            r'strong_parameters',
        ],
    ),

    VulnerabilityPattern(
        name="NoSQL Injection - MongoDB Tainted Input (Java/Kotlin)",
        category=VulnCategory.NOSQL_INJECTION,
        patterns=[
    # =====================================================================
            # MONGODB JAVA DRIVER
    # =====================================================================

            # Direct request parameter usage
            r'\.(?:find|findOne|updateOne|updateMany|deleteOne|deleteMany|'
            r'replaceOne|aggregate|countDocuments|distinct|'
            r'findOneAndUpdate|findOneAndDelete|findOneAndReplace)\s*\(\s*[^)]*request\.getParameter',

            # Filters with user input
            r'Filters\.(?:eq|ne|gt|gte|lt|lte|in|nin|and|or|not|nor|regex|'
            r'text|where|elemMatch|all|size|exists|type|mod)\s*\([^)]*request\.getParameter',

            # Document/BasicDBObject with user input
            r'new\s+(?:Document|BasicDBObject)\s*\([^)]*request\.getParameter',
            r'new\s+(?:Document|BasicDBObject)\s*\(\s*["\'][^"\']+["\']\s*,\s*\w+\s*\)',  # Variable as value
            r'Document\.parse\s*\(\s*(?:request|param|input|user|body)',
            r'BasicDBObject\.parse\s*\(\s*(?:request|param|input|user|body)',

            # Append with user input
            r'\.append\s*\(\s*["\'][^"\']+["\']\s*,\s*request\.getParameter',
            r'\.append\s*\(\s*request\.getParameter',  # Dynamic key

    # =====================================================================
            # SPRING DATA MONGODB
    # =====================================================================

            # Query with Criteria
            r'Criteria\.where\s*\([^)]*\)\s*\.(?:is|ne|gt|gte|lt|lte|in|nin|regex)\s*\([^)]*request\.getParameter',
            r'Query\.query\s*\(\s*Criteria\.where\s*\([^)]*request\.getParameter',

            # MongoTemplate methods
            r'mongoTemplate\.(?:find|findOne|findAll|findById|count|exists|'
            r'findAndModify|findAndRemove|findAndReplace|'
            r'updateFirst|updateMulti|remove|aggregate)\s*\([^)]*request\.getParameter',

            # @Query annotation with SpEL (CRITICAL)
            r'@Query\s*\(\s*["\'][^"\']*\?\d+[^"\']*["\']\s*\)',  # Positional parameter
            r'@Query\s*\(\s*["\'][^"\']*#\{[^}]+\}[^"\']*["\']\s*\)',  # SpEL expression

            # Repository methods with user input
            r'repository\.(?:findBy\w+|searchBy\w+|queryBy\w+)\s*\(\s*request\.getParameter',

    # =====================================================================
            # AGGREGATION FRAMEWORK
    # =====================================================================

            r'Aggregation\.(?:match|project|group|sort|limit|skip|unwind|lookup|'
            r'graphLookup|bucket|bucketAuto|facet|addFields|replaceRoot|'
            r'count|out|merge)\s*\([^)]*request\.getParameter',

            # TypedAggregation
            r'TypedAggregation\.newAggregation\s*\([^)]*request\.getParameter',

    # =====================================================================
            # MORPHIA (MongoDB ODM)
    # =====================================================================

            r'datastore\.(?:find|get|createQuery|createAggregation)\s*\([^)]*request\.getParameter',
            r'\.field\s*\(\s*["\'][^"\']+["\']\s*\)\s*\.(?:equal|notEqual|greaterThan|'
            r'lessThan|hasThisOne|hasAllOf|hasAnyOf|in|notIn)\s*\([^)]*request\.getParameter',

    # =====================================================================
            # STRING BUILDING
    # =====================================================================

            r'Document\.parse\s*\(\s*["\'].*\+.*request\.getParameter',
            r'Document\.parse\s*\(\s*String\.format\s*\(',
            r'new\s+Document\s*\(\s*["\'].*\+',
            r'StringBuilder.*append.*request\.getParameter.*Document\.parse',
        ],
        severity=Severity.CRITICAL,
        languages=[".java", ".kt", ".scala", ".groovy"],
        false_positive_patterns=[
            r'new\s+ObjectId\s*\(',
            r'ObjectId\.isValid\s*\(',
            r'Filters\.eq\s*\(\s*["\']_id["\']\s*,\s*new\s+ObjectId',
            r'@PathVariable\s+ObjectId',
            r'@RequestParam.*ObjectId',
            r'Integer\.parseInt\s*\(',
            r'Long\.parseLong\s*\(',
            r'Double\.parseDouble\s*\(',
            r'@Valid\s+',
            r'@Validated\s+',
            r'@Pattern\s*\(',
            r'@Size\s*\(',
            r'@NotNull',
            r'@NotEmpty',
            r'@NotBlank',
            r'BindingResult',
            r'Validator\.',
            r'sanitize',
            r'escape',
        ],
    ),

    VulnerabilityPattern(
        name="NoSQL Injection - MongoDB Tainted Input (C#/.NET)",
        category=VulnCategory.NOSQL_INJECTION,
        patterns=[
    # =====================================================================
            # MONGODB .NET DRIVER
    # =====================================================================

            # Direct request usage
            r'\.(?:Find|FindAsync|FindOne|FindOneAsync|'
            r'UpdateOne|UpdateOneAsync|UpdateMany|UpdateManyAsync|'
            r'DeleteOne|DeleteOneAsync|DeleteMany|DeleteManyAsync|'
            r'ReplaceOne|ReplaceOneAsync|'
            r'Aggregate|AggregateAsync|'
            r'CountDocuments|CountDocumentsAsync|'
            r'FindOneAndUpdate|FindOneAndUpdateAsync|'
            r'FindOneAndDelete|FindOneAndDeleteAsync|'
            r'FindOneAndReplace|FindOneAndReplaceAsync)\s*\([^)]*Request\.(Query|Form|Body|Cookies|Headers)',

            # FilterDefinition with user input
            r'Builders<\w+>\.Filter\.(?:Eq|Ne|Gt|Gte|Lt|Lte|In|Nin|And|Or|Not|Nor|'
            r'Regex|Text|Where|ElemMatch|All|Size|Exists|Type|Mod)\s*\([^)]*Request\.',

            # BsonDocument with user input
            r'new\s+BsonDocument\s*\([^)]*Request\.(Query|Form|Body)',
            r'BsonDocument\.Parse\s*\(\s*(?:Request\.|request\.|input|user|param|query|body)',

    # =====================================================================
            # ASP.NET CORE PATTERNS
    # =====================================================================

            # Controller parameters
            r'\[FromQuery\][^]]*\s+\w+.*\.(?:Find|FindAsync)',
            r'\[FromBody\][^]]*\s+\w+.*\.(?:Find|FindAsync)',
            r'\[FromForm\][^]]*\s+\w+.*\.(?:Find|FindAsync)',

            # HttpContext
            r'HttpContext\.Request\.(Query|Form|Body).*\.(?:Find|FindAsync)',

    # =====================================================================
            # LINQ PROVIDER
    # =====================================================================

            # IQueryable with user input
            r'\.AsQueryable\s*\(\s*\)\s*\.Where\s*\([^)]*Request\.',
            r'\.Where\s*\(\s*\w+\s*=>\s*\w+\.\w+\s*==\s*Request\.',

    # =====================================================================
            # STRING BUILDING
    # =====================================================================

            r'BsonDocument\.Parse\s*\(\s*\$"',
            r'BsonDocument\.Parse\s*\(\s*["\'].*\+',
            r'BsonDocument\.Parse\s*\(\s*String\.Format\s*\(',
            r'BsonDocument\.Parse\s*\(\s*string\.Concat\s*\(',

    # =====================================================================
            # OPERATOR INJECTION
    # =====================================================================

            r'\{\s*["\']?\$(?:where|regex|gt|gte|lt|lte|ne|eq|in|nin|or|and)["\']?\s*:\s*Request\.',
            r'FilterDefinition.*\$.*Request\.',
        ],
        severity=Severity.CRITICAL,
        languages=[".cs", ".vb"],
        false_positive_patterns=[
            r'ObjectId\.Parse\s*\(',
            r'ObjectId\.TryParse\s*\(',
            r'new\s+ObjectId\s*\(',
            r'int\.Parse\s*\(',
            r'int\.TryParse\s*\(',
            r'long\.Parse\s*\(',
            r'long\.TryParse\s*\(',
            r'Guid\.Parse\s*\(',
            r'Guid\.TryParse\s*\(',
            r'\[Required\]',
            r'\[StringLength\s*\(',
            r'\[RegularExpression\s*\(',
            r'\[Range\s*\(',
            r'ModelState\.IsValid',
            r'TryValidateModel\s*\(',
            r'Validator\.TryValidateObject\s*\(',
            r'DataAnnotations',
            r'FluentValidation',
            r'\.Sanitize\s*\(',
            r'\.Escape\s*\(',
        ],
    ),

    VulnerabilityPattern(
        name="NoSQL Injection - MongoDB Tainted Input (Go)",
        category=VulnCategory.NOSQL_INJECTION,
        patterns=[
    # =====================================================================
            # OFFICIAL MONGODB GO DRIVER
    # =====================================================================

            # Basic operations with user input
            r'\.(?:Find|FindOne|InsertOne|InsertMany|'
            r'UpdateOne|UpdateMany|UpdateByID|'
            r'DeleteOne|DeleteMany|'
            r'ReplaceOne|FindOneAndUpdate|FindOneAndDelete|FindOneAndReplace|'
            r'Aggregate|CountDocuments|EstimatedDocumentCount|Distinct)\s*\(\s*[^)]*r\.(URL\.Query|Form|PostForm|Body)',

            # bson.M/bson.D with user input
            r'bson\.[MD]\s*\{[^}]*:\s*r\.(URL\.Query|Form|PostForm|FormValue)',
            r'bson\.[MD]\s*\{[^}]*:\s*(?:query|param|input|user|data)',

            # Gin framework
            r'c\.(?:Query|PostForm|Param|GetQuery|DefaultQuery)\s*\([^)]*\).*bson\.[MD]',
            r'bson\.[MD]\s*\{[^}]*:\s*c\.(?:Query|PostForm|Param)',

            # Echo framework
            r'c\.(?:QueryParam|FormValue|Param)\s*\([^)]*\).*bson\.[MD]',
            r'bson\.[MD]\s*\{[^}]*:\s*c\.(?:QueryParam|FormValue|Param)',

            # Fiber framework
            r'c\.(?:Query|FormValue|Params)\s*\([^)]*\).*bson\.[MD]',
            r'bson\.[MD]\s*\{[^}]*:\s*c\.(?:Query|FormValue|Params)',

    # =====================================================================
            # STRING BUILDING
    # =====================================================================

            r'bson\.UnmarshalExtJSON\s*\(\s*\[\]byte\s*\(\s*.*\+',
            r'bson\.UnmarshalExtJSON\s*\(\s*\[\]byte\s*\(\s*fmt\.Sprintf',
            r'bson\.UnmarshalExtJSON\s*\(\s*\[\]byte\s*\(\s*r\.(URL\.Query|Form|Body)',

    # =====================================================================
            # OPERATOR INJECTION
    # =====================================================================

            r'bson\.[MD]\s*\{\s*"\$(?:where|regex|gt|gte|lt|lte|ne|eq|in|nin|or|and)"\s*:\s*(?:query|param|input|r\.)',
            r'\$\w+.*r\.(?:URL\.Query|Form|PostForm|FormValue)',
        ],
        severity=Severity.CRITICAL,
        languages=[".go"],
        false_positive_patterns=[
            r'primitive\.ObjectIDFromHex\s*\(',
            r'primitive\.IsValidObjectID\s*\(',
            r'strconv\.Atoi\s*\(',
            r'strconv\.ParseInt\s*\(',
            r'strconv\.ParseFloat\s*\(',
            r'strconv\.ParseBool\s*\(',
            r'uuid\.Parse\s*\(',
            r'validator\.\w+',
            r'validate\.\w+',
            r'binding:"required',
            r'binding:"',
        ],
    ),

    # =============================================================================
    # REDIS INJECTION PATTERNS
    # =============================================================================

    VulnerabilityPattern(
        name="NoSQL Injection - Redis Command Injection",
        category=VulnCategory.NOSQL_INJECTION,
        patterns=[
    # =====================================================================
            # JAVASCRIPT/NODE.JS - ioredis/redis
    # =====================================================================

            # Direct command execution with user input
            r'redis\.(?:eval|evalsha|script|send_command|sendCommand|call)\s*\(\s*[^)]*req\.(body|query|params)',
            r'client\.(?:eval|evalsha|script|send_command|sendCommand|call)\s*\(\s*[^)]*req\.(body|query|params)',

            # Key operations with user input (key injection)
            r'redis\.(?:get|set|del|exists|expire|ttl|keys|scan|'
            r'hget|hset|hdel|hgetall|hmget|hmset|'
            r'lpush|rpush|lpop|rpop|lrange|lindex|'
            r'sadd|srem|smembers|sismember|'
            r'zadd|zrem|zrange|zrangebyscore|zscore|'
            r'publish|subscribe)\s*\(\s*req\.(body|query|params)',

            # Template literal in key/value
            r'redis\.\w+\s*\(\s*`[^`]*\$\{[^}]*req\.',

            # String concatenation
            r'redis\.\w+\s*\(\s*["\'].*\+.*req\.',

    # =====================================================================
            # PYTHON - redis-py
    # =====================================================================

            r'redis\.(?:eval|evalsha|script_load|execute_command)\s*\(\s*[^)]*request\.',
            r'r\.(?:get|set|delete|exists|expire|keys|scan|'
            r'hget|hset|hdel|hgetall|hmget|hmset|'
            r'lpush|rpush|lpop|rpop|lrange|'
            r'sadd|srem|smembers|'
            r'zadd|zrem|zrange|zscore|'
            r'publish)\s*\(\s*request\.(args|form|json|data)',

            # f-string in Redis command
            r'r\.\w+\s*\(\s*f["\'].*request\.',
            r'redis\.\w+\s*\(\s*f["\']',

    # =====================================================================
            # PHP - Predis/phpredis
    # =====================================================================

            r'\$redis->(?:eval|evalsha|script|rawCommand)\s*\(\s*\$_(GET|POST|REQUEST)',
            r'\$redis->\w+\s*\(\s*\$_(GET|POST|REQUEST)',

    # =====================================================================
            # DANGEROUS COMMANDS
    # =====================================================================

            # EVAL command (Lua execution)
            r'\.eval\s*\(\s*[^)]*(?:req\.|request\.|params|query|input|user)',

            # KEYS command with pattern from user (DoS risk)
            r'\.keys\s*\(\s*(?:req\.|request\.|params|query|input|user)',
            r'\.keys\s*\(\s*[`"\'].*\*.*(?:\+|\$\{)',

            # CONFIG command
            r'\.config\s*\(\s*[^)]*(?:req\.|request\.|params|query|input|user)',

            # DEBUG command
            r'\.debug\s*\(\s*[^)]*(?:req\.|request\.|params|query|input|user)',

            # FLUSHALL/FLUSHDB
            r'\.(?:flushall|flushdb)\s*\(',  # Just flag usage
        ],
        severity=Severity.HIGH,
        languages=[".js", ".ts", ".py", ".php", ".rb", ".java", ".go", ".cs"],
        false_positive_patterns=[
            r'redis\.get\s*\(\s*["\'][a-zA-Z_:]+["\']\s*\)',  # Static key
            r'\.get\s*\(\s*`[a-zA-Z_:]+`\s*\)',  # Static key
            r'parseInt\s*\(',
            r'int\s*\(',
            r'sanitize',
            r'escape',
            r'validate',
        ],
    ),

    # =============================================================================
    # ELASTICSEARCH INJECTION PATTERNS
    # =============================================================================

    VulnerabilityPattern(
        name="NoSQL Injection - Elasticsearch Query Injection",
        category=VulnCategory.NOSQL_INJECTION,
        patterns=[
    # =====================================================================
            # JAVASCRIPT - elasticsearch.js / @elastic/elasticsearch
    # =====================================================================

            r'client\.(?:search|index|update|delete|bulk|scroll|'
            r'msearch|mget|reindex|updateByQuery|deleteByQuery)\s*\(\s*\{[^}]*body\s*:\s*[^}]*req\.(body|query|params)',

            # Query DSL with user input
            r'body\s*:\s*\{[^}]*query\s*:\s*[^}]*req\.(body|query|params)',
            r'query\s*:\s*\{[^}]*(?:match|term|terms|range|bool|must|should|filter)\s*:\s*[^}]*req\.',

            # Script execution with user input (CRITICAL)
            r'script\s*:\s*\{[^}]*source\s*:\s*[^}]*req\.(body|query|params)',
            r'script\s*:\s*["\'].*req\.(body|query|params)',

            # Template literal
            r'client\.search\s*\(\s*\{[^}]*`[^`]*\$\{[^}]*req\.',

    # =====================================================================
            # PYTHON - elasticsearch-py
    # =====================================================================

            r'es\.(?:search|index|update|delete|bulk|scroll|'
            r'msearch|mget|reindex|update_by_query|delete_by_query)\s*\([^)]*body\s*=\s*[^)]*request\.',

            # f-string in query
            r'es\.\w+\s*\(\s*[^)]*f["\'].*request\.',
            r'body\s*=\s*f["\'].*request\.',

            # json.loads from request
            r'es\.\w+\s*\(\s*[^)]*json\.loads\s*\(\s*request\.',

    # =====================================================================
            # JAVA - Elasticsearch High Level REST Client
    # =====================================================================

            r'SearchRequest.*QueryBuilders\.(?:matchQuery|termQuery|termsQuery|rangeQuery|'
            r'boolQuery|wildcardQuery|regexpQuery|prefixQuery|fuzzyQuery)\s*\([^)]*request\.getParameter',

            r'new\s+SearchSourceBuilder\s*\(\s*\)\s*\.query\s*\([^)]*request\.getParameter',

            # Script with user input
            r'new\s+Script\s*\([^)]*request\.getParameter',
            r'Script\.(?:inline|stored)\s*\([^)]*request\.getParameter',

    # =====================================================================
            # DANGEROUS PATTERNS
    # =====================================================================

            # Script execution
            r'script\s*[=:]\s*[^,}]*(?:req\.|request\.|params|query|input|user)',

            # _source filtering with user input
            r'_source\s*[=:]\s*[^,}]*(?:req\.|request\.|params|query|input|user)',

            # Index name from user input (index injection)
            r'index\s*[=:]\s*(?:req\.|request\.|params|query|input|user)',
        ],
        severity=Severity.HIGH,
        languages=[".js", ".ts", ".py", ".java", ".php", ".rb", ".go", ".cs"],
        false_positive_patterns=[
            r'index\s*:\s*["\'][a-zA-Z_-]+["\']',  # Static index
            r'sanitize',
            r'escape',
            r'validate',
            r'parseInt',
            r'int\s*\(',
        ],
    ),

    # =============================================================================
    # COUCHDB INJECTION PATTERNS
    # =============================================================================

    VulnerabilityPattern(
        name="NoSQL Injection - CouchDB Query Injection",
        category=VulnCategory.NOSQL_INJECTION,
        patterns=[
            # Mango queries with user input
            r'\.find\s*\(\s*\{[^}]*selector\s*:\s*[^}]*(?:req\.|request\.|params|query|input)',

            # View queries with user input
            r'\.view\s*\(\s*[^,]+,\s*[^,]+,\s*\{[^}]*(?:key|startkey|endkey)\s*:\s*(?:req\.|request\.|params)',

            # Design document with user input
            r'\.insert\s*\(\s*\{[^}]*views\s*:\s*[^}]*(?:req\.|request\.|params)',

            # String injection
            r'nano\.\w+\s*\(\s*[`"\'].*(?:\+|\$\{).*(?:req\.|request\.|params)',
        ],
        severity=Severity.HIGH,
        languages=[".js", ".ts", ".py", ".php", ".rb", ".java", ".go"],
        false_positive_patterns=[
            r'sanitize',
            r'escape',
            r'validate',
        ],
    ),

    # =============================================================================
    # DYNAMODB INJECTION PATTERNS
    # =============================================================================

    VulnerabilityPattern(
        name="NoSQL Injection - DynamoDB Query Injection",
        category=VulnCategory.NOSQL_INJECTION,
        patterns=[
    # =====================================================================
            # AWS SDK - JavaScript
    # =====================================================================

            r'dynamodb\.(?:query|scan|getItem|putItem|updateItem|deleteItem|batchGetItem|'
            r'batchWriteItem|transactGetItems|transactWriteItems)\s*\(\s*\{[^}]*(?:Key|KeyConditionExpression|'
            r'FilterExpression|ProjectionExpression|ExpressionAttributeValues|ExpressionAttributeNames)\s*:'
            r'[^}]*req\.(body|query|params)',

            # Template literal in expressions
            r'(?:KeyConditionExpression|FilterExpression)\s*:\s*`[^`]*\$\{[^}]*req\.',

            # String concatenation in expressions
            r'(?:KeyConditionExpression|FilterExpression)\s*:\s*["\'].*\+.*req\.',

    # =====================================================================
            # AWS SDK - Python (boto3)
    # =====================================================================

            r'table\.(?:query|scan|get_item|put_item|update_item|delete_item|'
            r'batch_get_item|batch_write_item)\s*\([^)]*(?:Key|KeyConditionExpression|'
            r'FilterExpression|ProjectionExpression|ExpressionAttributeValues)\s*=\s*[^)]*request\.',

            # f-string in expressions
            r'(?:KeyConditionExpression|FilterExpression)\s*=\s*f["\'].*request\.',

    # =====================================================================
            # DANGEROUS PATTERNS
    # =====================================================================

            # Raw expression from user
            r'KeyConditionExpression\s*[=:]\s*(?:req\.|request\.|params|query|input|user)',
            r'FilterExpression\s*[=:]\s*(?:req\.|request\.|params|query|input|user)',

            # ExpressionAttributeValues from user (partial control)
            r'ExpressionAttributeValues\s*[=:]\s*(?:req\.|request\.|params|query|input|user)',
        ],
        severity=Severity.HIGH,
        languages=[".js", ".ts", ".py", ".java", ".go", ".cs"],
        false_positive_patterns=[
            r'ExpressionAttributeValues\s*:\s*\{[^}]*:\s*\{[^}]*[SN]\s*:\s*(?:String|parseInt)',
            r'sanitize',
            r'escape',
            r'validate',
        ],
    ),

    # =============================================================================
    # FIREBASE/FIRESTORE INJECTION PATTERNS
    # =============================================================================

    VulnerabilityPattern(
        name="NoSQL Injection - Firebase/Firestore Query Injection",
        category=VulnCategory.NOSQL_INJECTION,
        patterns=[
    # =====================================================================
            # FIRESTORE - JavaScript
    # =====================================================================

            # Collection/document path from user input
            r'(?:firestore|db)\s*\.\s*collection\s*\(\s*req\.(body|query|params)',
            r'\.doc\s*\(\s*req\.(body|query|params)',

            # Query operators with user input
            r'\.where\s*\(\s*[^,]+,\s*[^,]+,\s*req\.(body|query|params)',
            r'\.where\s*\(\s*req\.(body|query|params)',  # Field from user

            # Order/limit with user input
            r'\.orderBy\s*\(\s*req\.(body|query|params)',
            r'\.limit\s*\(\s*req\.(body|query|params)',

    # =====================================================================
            # REALTIME DATABASE - JavaScript
    # =====================================================================

            # Path injection
            r'(?:database|db)\s*\(\s*\)\s*\.ref\s*\(\s*req\.(body|query|params)',
            r'\.ref\s*\(\s*`[^`]*\$\{[^}]*req\.',
            r'\.ref\s*\(\s*["\'].*\+.*req\.',

            # Query methods with user input
            r'\.(?:orderByChild|orderByKey|orderByValue|startAt|endAt|equalTo|'
            r'limitToFirst|limitToLast)\s*\(\s*req\.(body|query|params)',

    # =====================================================================
            # PYTHON - firebase-admin
    # =====================================================================

            r'db\.collection\s*\(\s*request\.(args|form|json|data)',
            r'\.document\s*\(\s*request\.(args|form|json|data)',
            r'\.where\s*\([^)]*request\.(args|form|json|data)',

            # Realtime Database
            r'db\.reference\s*\(\s*request\.(args|form|json|data)',
            r'db\.reference\s*\(\s*f["\'].*request\.',
        ],
        severity=Severity.HIGH,
        languages=[".js", ".ts", ".py", ".java", ".swift", ".kt"],
        false_positive_patterns=[
            r'\.doc\s*\(\s*["\'][a-zA-Z0-9_-]+["\']\s*\)',  # Static doc ID
            r'\.collection\s*\(\s*["\'][a-zA-Z0-9_-]+["\']\s*\)',  # Static collection
            r'sanitize',
            r'escape',
            r'validate',
        ],
    ),

    # =============================================================================
    # CASSANDRA CQL INJECTION PATTERNS
    # =============================================================================

    VulnerabilityPattern(
        name="NoSQL Injection - Cassandra CQL Injection",
        category=VulnCategory.NOSQL_INJECTION,
        patterns=[
    # =====================================================================
            # STRING CONCATENATION IN CQL
    # =====================================================================

            r'session\.execute\s*\(\s*["\']SELECT\s+.*\+',
            r'session\.execute\s*\(\s*f["\']SELECT\s+',
            r'session\.execute\s*\(\s*["\']SELECT\s+.*%\s*\(',
            r'session\.execute\s*\(\s*["\']INSERT\s+.*\+',
            r'session\.execute\s*\(\s*["\']UPDATE\s+.*\+',
            r'session\.execute\s*\(\s*["\']DELETE\s+.*\+',

            # Template literals (JavaScript)
            r'client\.execute\s*\(\s*`SELECT\s+.*\$\{',

    # =====================================================================
            # USER INPUT IN QUERIES
    # =====================================================================

            r'session\.execute\s*\(\s*[^)]*(?:req\.|request\.|params|query|input)',
            r'client\.execute\s*\(\s*[^)]*(?:req\.|request\.|params|query|input)',

            # Batch statements
            r'BatchStatement.*add\s*\([^)]*(?:req\.|request\.|params|query|input)',
        ],
        severity=Severity.CRITICAL,
        languages=[".py", ".java", ".js", ".ts", ".go", ".cs"],
        false_positive_patterns=[
            r'session\.execute\s*\([^,]+,\s*\[',  # Parameterized query
            r'session\.execute\s*\([^,]+,\s*\(',  # Parameterized query
            r'\.prepare\s*\(',                     # Prepared statement
            r'PreparedStatement',
            r'sanitize',
            r'escape',
            r'validate',
        ],
    ),

    # =============================================================================
    # NEO4J CYPHER INJECTION PATTERNS
    # =============================================================================

    VulnerabilityPattern(
        name="NoSQL Injection - Neo4j Cypher Injection",
        category=VulnCategory.NOSQL_INJECTION,
        patterns=[
    # =====================================================================
            # STRING CONCATENATION IN CYPHER
    # =====================================================================

            r'session\.run\s*\(\s*["\']MATCH\s+.*\+',
            r'session\.run\s*\(\s*f["\']MATCH\s+',
            r'session\.run\s*\(\s*["\']CREATE\s+.*\+',
            r'session\.run\s*\(\s*["\']MERGE\s+.*\+',
            r'session\.run\s*\(\s*["\']DELETE\s+.*\+',
            r'session\.run\s*\(\s*["\']SET\s+.*\+',
            r'session\.run\s*\(\s*["\']RETURN\s+.*\+',

            # Template literals (JavaScript)
            r'session\.run\s*\(\s*`MATCH\s+.*\$\{',
            r'session\.run\s*\(\s*`CREATE\s+.*\$\{',

    # =====================================================================
            # USER INPUT IN CYPHER
    # =====================================================================

            r'session\.run\s*\(\s*[^)]*(?:req\.|request\.|params|query|input)',
            r'tx\.run\s*\(\s*[^)]*(?:req\.|request\.|params|query|input)',

            # Cypher keywords with user input
            r'(?:MATCH|CREATE|MERGE|DELETE|SET|WHERE|RETURN)\s*\([^)]*(?:req\.|request\.|params\.|user_input|user_data)',
        ],
        severity=Severity.CRITICAL,
        languages=[".py", ".java", ".js", ".ts", ".go", ".cs"],
        false_positive_patterns=[
            r'session\.run\s*\([^,]+,\s*\{',      # Parameterized query
            r'tx\.run\s*\([^,]+,\s*\{',           # Parameterized query
            r'\$\w+',                              # Cypher parameter placeholder
            r'sanitize',
            r'escape',
            r'validate',
        ],
    ),

    # =============================================================================
    # GENERIC $WHERE OPERATOR DETECTION (ALL LANGUAGES)
    # =============================================================================

    VulnerabilityPattern(
        name="NoSQL Injection - MongoDB $where Operator (Dangerous)",
        category=VulnCategory.NOSQL_INJECTION,
        patterns=[
            # Basic $where detection (code smell - allows JS execution)
            r'\$where\s*:',
            r'"\$where"\s*:',
            r"'\$where'\s*:",
            r'\[\s*["\']?\$where["\']?\s*\]',

            # $where with user input (CRITICAL)
            r'\$where\s*:\s*[^,}]*(?:req\.|request\.|params|query|user_input|input|data|payload)',

            # $where with string operations (injection vector)
            r'\$where\s*:\s*["\'][^"\']*\s*\+',
            r'\$where\s*:\s*`[^`]*\$\{',
            r'\$where\s*:\s*f["\']',
            r'\$where\s*:\s*["\'].*\.format\s*\(',
            r'\$where\s*:\s*["\'].*%\s*[sd]',

            # $where with function containing external variables
            r'\$where\s*:\s*function\s*\([^)]*\)\s*\{[^}]*(?:req\.|request\.|params|this\.\w+\s*[=!]==?\s*[^"\']+)',
            r'\$where\s*:\s*function\s*\([^)]*\)\s*\{[^}]*(?:eval|exec|Function)\s*\(',

            # $where with arrow function
            r'\$where\s*:\s*\(\s*\)\s*=>\s*[^,}]*(?:req\.|request\.|params)',
        ],
        severity=Severity.HIGH,
        languages=[".js", ".ts", ".jsx", ".tsx", ".py", ".php", ".java", ".rb", ".cs", ".go", ".kt"],
        false_positive_patterns=[
            r'\$where\s*:\s*function\s*\(\)\s*\{\s*return\s+(?:true|false)\s*;?\s*\}',  # Static boolean
            r'\$where\s*:\s*["\']this\.\w+\s*[<>=!]+\s*\d+["\']',  # Hardcoded comparison
            r'\$where\s*:\s*["\']this\.\w+\s*[<>=!]+\s*["\'][^"\']+["\']["\']',  # Hardcoded string comparison
            r'#.*\$where',   # Commented
            r'//.*\$where',  # Commented
            r'/\*.*\$where', # Commented
            r'\*.*\$where',  # Commented
        ],
    ),

    # =============================================================================
    # AGGREGATION PIPELINE INJECTION (ALL LANGUAGES)
    # =============================================================================

    VulnerabilityPattern(
        name="NoSQL Injection - MongoDB Aggregation Pipeline Injection",
        category=VulnCategory.NOSQL_INJECTION,
        patterns=[
            # Pipeline from user input
            r'\.aggregate\s*\(\s*req\.(body|query|params)',
            r'\.aggregate\s*\(\s*request\.(args|form|json|data|GET|POST)',
            r'\.aggregate\s*\(\s*\$_(GET|POST|REQUEST)',
            r'\.aggregate\s*\(\s*params',

            # Pipeline array with user input
            r'\.aggregate\s*\(\s*\[\s*\{?\s*\$\w+\s*:\s*[^}]*(?:req\.|request\.|params|query|input|user)',

            # Dangerous stages with user input
            r'\$(?:lookup|graphLookup|unionWith|merge|out)\s*:\s*\{[^}]*(?:from|into|as)\s*:\s*(?:req\.|request\.|params|query|input)',

            # $function stage (JavaScript execution)
            r'\$function\s*:\s*\{[^}]*body\s*:\s*[^}]*(?:req\.|request\.|params|query|input)',

            # $accumulator stage (JavaScript execution)
            r'\$accumulator\s*:\s*\{[^}]*(?:init|accumulate|merge|finalize)\s*:\s*[^}]*(?:req\.|request\.|params|query|input)',

            # Variable in pipeline
            r'pipeline\s*=\s*(?:req\.|request\.|params|query|input|\$_(GET|POST|REQUEST))',
            r'pipeline\s*\.\s*(?:push|append|extend|concat)\s*\([^)]*(?:req\.|request\.|params|query|input)',
        ],
        severity=Severity.CRITICAL,
        languages=[".js", ".ts", ".py", ".php", ".java", ".rb", ".cs", ".go", ".kt"],
        false_positive_patterns=[
            r'\.aggregate\s*\(\s*\[\s*\{\s*\$match\s*:\s*\{\s*["\'][a-zA-Z_]+["\']\s*:\s*(?:ObjectId|new\s+ObjectId)',
            r'sanitize',
            r'escape',
            r'validate',
        ],
    ),

    # =========================================================================
    # XPATH INJECTION PATTERNS
    # =========================================================================

    VulnerabilityPattern(
        name="XPath Injection - String Concatenation",
        category=VulnCategory.XPATH_INJECTION,
        patterns=[
            r'xpath\s*\(\s*["\'].*\+',
            r'\.xpath\s*\(\s*["\'].*\+',
            r'\.xpath\s*\(\s*f["\']',
            r'\.xpath\s*\(\s*\$"',
            r'SelectNodes\s*\(\s*\$"',
            r'SelectSingleNode\s*\(\s*\$"',
            r'XPathSelectElements\s*\(\s*\$"',
            r'->xpath\s*\(\s*["\'].*\$',
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
            r'pickle\.loads?\s*\(',
            r'cPickle\.loads?\s*\(',
            r'_pickle\.loads?\s*\(',
            r'pickle\.Unpickler\s*\(',
            r'shelve\.open\s*\(',
            r'dill\.loads?\s*\(',
            r'cloudpickle\.loads?\s*\(',
            r'joblib\.load\s*\(',
            r'torch\.load\s*\([^)]*pickle',
            r'numpy\.load\s*\([^)]*allow_pickle\s*=\s*True',
            r'pandas\.read_pickle\s*\(',
        ],
        severity=Severity.CRITICAL,
        languages=[".py"],
        false_positive_patterns=[
            r'#.*pickle',
            r'pickle\.dump',
            r'_test\.',
            r'\.test\.',
            r'test_',
            r'mock',
            r'fixture',
            r'RestrictedUnpickler',
            r'SafeUnpickler',
            r'find_class.*raise',
        ],
    ),
    VulnerabilityPattern(
        name="Insecure Deserialization - Python YAML",
        category=VulnCategory.DESERIALIZATION,
        patterns=[
            # PyYAML unsafe loaders
            r'yaml\.load\s*\(\s*[^,)]+\s*\)',                    # yaml.load() without Loader
            r'yaml\.load\s*\([^)]*Loader\s*=\s*yaml\.Loader',    # yaml.load(Loader=yaml.Loader)
            r'yaml\.load\s*\([^)]*Loader\s*=\s*yaml\.UnsafeLoader',
            r'yaml\.load\s*\([^)]*Loader\s*=\s*yaml\.FullLoader',
            r'yaml\.unsafe_load\s*\(',                           # Explicitly unsafe
            r'yaml\.full_load\s*\(',                             # Full load (unsafe)
            r'yaml\.load_all\s*\(\s*[^,)]+\s*\)',               # load_all without Loader
            r'yaml\.unsafe_load_all\s*\(',
            r'yaml\.full_load_all\s*\(',

            # ruamel.yaml
            r'ruamel\.yaml\.YAML\s*\(\s*typ\s*=\s*["\']unsafe["\']',
            r'ruamel\.yaml\.load\s*\(',

            # PyYAML with user input
            r'yaml\.load\s*\(\s*request\.',
            r'yaml\.load\s*\(\s*f\.read\s*\(\s*\)',
            r'yaml\.load\s*\(\s*open\s*\(',
            r'yaml\.load\s*\(\s*.*\.(body|data|content|text)',

            # Dangerous pattern: yaml.load with file from user
            r'yaml\.load\s*\(\s*.*request\.(form|args|json|data|files)',
        ],
        severity=Severity.CRITICAL,
        languages=[".py"],
        false_positive_patterns=[
            r'yaml\.safe_load',
            r'SafeLoader',
            r'yaml\.CSafeLoader',
            r'Loader\s*=\s*yaml\.SafeLoader',
            r'Loader\s*=\s*SafeLoader',
            r'_test\.',
            r'\.test\.',
            r'test_',
            r'mock',
            r'fixture',
            r'yaml\.dump',
        ],
    ),
    VulnerabilityPattern(
        name="Insecure Deserialization - Node serialize",
        category=VulnCategory.DESERIALIZATION,
        patterns=[
            r'serialize\.unserialize\s*\(',
            r'require\s*\(\s*["\']node-serialize["\']\s*\)',
            r'from\s+["\']node-serialize["\']',
        ],
        severity=Severity.CRITICAL,
        languages=[".js", ".ts"],
    ),
    VulnerabilityPattern(
        name="Insecure Deserialization - PHP unserialize",
        category=VulnCategory.DESERIALIZATION,
        patterns=[
            r'unserialize\s*\(\s*\$',
            r'unserialize\s*\(\s*base64_decode',
            r'unserialize\s*\(\s*\$_(GET|POST|REQUEST|COOKIE)',
            r'phar://',
        ],
        severity=Severity.CRITICAL,
        languages=[".php"],
        false_positive_patterns=[r'allowed_classes\s*=>\s*false'],
    ),
    VulnerabilityPattern(
        name="Insecure Deserialization - Java ObjectInputStream",
        category=VulnCategory.DESERIALIZATION,
        patterns=[
            r'ObjectInputStream\s*\(',
            r'\.readObject\s*\(\s*\)',
            r'\.readUnshared\s*\(\s*\)',
            r'XMLDecoder\s*\(',
            r'XStream\s*\(\s*\)',
            r'xstream\.fromXML\s*\(',
            r'enableDefaultTyping\s*\(',
            r'@JsonTypeInfo.*Id\.CLASS',
        ],
        severity=Severity.CRITICAL,
        languages=[".java", ".kt", ".scala"],
        false_positive_patterns=[r'ObjectInputFilter', r'SafeConstructor'],
    ),
    VulnerabilityPattern(
        name="Insecure Deserialization - C# BinaryFormatter",
        category=VulnCategory.DESERIALIZATION,
        patterns=[
            r'BinaryFormatter\s*\(',
            r'new\s+BinaryFormatter\s*\(',
            r'\.Deserialize\s*\(',
        ],
        severity=Severity.CRITICAL,
        languages=[".cs"],
        false_positive_patterns=[r'JsonSerializer\.Deserialize', r'System\.Text\.Json'],
    ),
    VulnerabilityPattern(
        name="Insecure Deserialization - C# NetDataContractSerializer",
        category=VulnCategory.DESERIALIZATION,
        patterns=[
            r'NetDataContractSerializer\s*\(',
            r'new\s+NetDataContractSerializer\s*\(',
            r'NetDataContractSerializer.*\.ReadObject\s*\(',
        ],
        severity=Severity.CRITICAL,
        languages=[".cs"],
    ),
    VulnerabilityPattern(
        name="Insecure Deserialization - C# ObjectStateFormatter",
        category=VulnCategory.DESERIALIZATION,
        patterns=[
            r'ObjectStateFormatter\s*\(',
            r'new\s+ObjectStateFormatter\s*\(',
            r'ObjectStateFormatter.*\.Deserialize\s*\(',
        ],
        severity=Severity.CRITICAL,
        languages=[".cs"],
    ),
    VulnerabilityPattern(
        name="Insecure Deserialization - C# LosFormatter",
        category=VulnCategory.DESERIALIZATION,
        patterns=[
            r'LosFormatter\s*\(',
            r'new\s+LosFormatter\s*\(',
            r'LosFormatter.*\.Deserialize\s*\(',
        ],
        severity=Severity.CRITICAL,
        languages=[".cs"],
    ),
    VulnerabilityPattern(
        name="Insecure Deserialization - C# SoapFormatter",
        category=VulnCategory.DESERIALIZATION,
        patterns=[
            r'SoapFormatter\s*\(',
            r'new\s+SoapFormatter\s*\(',
            r'SoapFormatter.*\.Deserialize\s*\(',
        ],
        severity=Severity.CRITICAL,
        languages=[".cs"],
    ),
    VulnerabilityPattern(
        name="Insecure Deserialization - C# JavaScriptSerializer",
        category=VulnCategory.DESERIALIZATION,
        patterns=[
            r'JavaScriptSerializer\s*\(',
            r'new\s+JavaScriptSerializer\s*\(',
            r'JavaScriptSerializer.*\.Deserialize\s*\(',
            r'JavaScriptSerializer.*\.DeserializeObject\s*\(',
        ],
        severity=Severity.CRITICAL,
        languages=[".cs"],
    ),
    VulnerabilityPattern(
        name="Insecure Deserialization - C# Json.NET (Newtonsoft)",
        category=VulnCategory.DESERIALIZATION,
        patterns=[
            r'JsonConvert\.DeserializeObject\s*\(',
            r'JsonConvert\.DeserializeObject<',
            r'TypeNameHandling\s*=\s*TypeNameHandling\.(All|Auto|Objects|Arrays)',
            r'JsonSerializerSettings.*TypeNameHandling',
            r'TypeNameHandling\.(All|Auto|Objects|Arrays)',
        ],
        severity=Severity.HIGH,
        languages=[".cs"],
        false_positive_patterns=[r'TypeNameHandling\.None'],
    ),
    VulnerabilityPattern(
        name="Insecure Deserialization - C# fastJSON",
        category=VulnCategory.DESERIALIZATION,
        patterns=[
            r'JSON\.ToObject\s*\(',
            r'JSON\.ToObject<',
            r'fastJSON\.JSON\.ToObject',
        ],
        severity=Severity.CRITICAL,
        languages=[".cs"],
    ),
    VulnerabilityPattern(
        name="Insecure Deserialization - C# XmlSerializer",
        category=VulnCategory.DESERIALIZATION,
        patterns=[
            r'XmlSerializer\s*\(',
            r'new\s+XmlSerializer\s*\(',
            r'XmlSerializer.*\.Deserialize\s*\(',
            r'XmlSerializer\s*\(\s*typeof\s*\(\s*object',
            r'XmlSerializer\s*\(\s*Type\.GetType',
        ],
        severity=Severity.HIGH,
        languages=[".cs"],
    ),
    VulnerabilityPattern(
        name="Insecure Deserialization - C# YamlDotNet",
        category=VulnCategory.DESERIALIZATION,
        patterns=[
            r'Deserializer\s*\(\s*\)',
            r'new\s+Deserializer\s*\(',
            r'new\s+DeserializerBuilder\s*\(',
            r'\.Deserialize<',
            r'YamlDotNet.*Deserialize',
        ],
        severity=Severity.HIGH,
        languages=[".cs"],
        false_positive_patterns=[r'System\.Text\.Json', r'JsonSerializer'],
    ),
    VulnerabilityPattern(
        name="Insecure Deserialization - C# DataContractSerializer",
        category=VulnCategory.DESERIALIZATION,
        patterns=[
            r'DataContractSerializer\s*\(',
            r'new\s+DataContractSerializer\s*\(',
            r'DataContractSerializer.*\.ReadObject\s*\(',
            r'DataContractJsonSerializer\s*\(',
            r'DataContractJsonSerializer.*\.ReadObject\s*\(',
        ],
        severity=Severity.HIGH,
        languages=[".cs"],
    ),
    VulnerabilityPattern(
        name="Insecure Deserialization - C# XAML",
        category=VulnCategory.DESERIALIZATION,
        patterns=[
            r'XamlReader\.Load\s*\(',
            r'XamlReader\.Parse\s*\(',
            r'XamlServices\.Load\s*\(',
            r'XamlServices\.Parse\s*\(',
        ],
        severity=Severity.CRITICAL,
        languages=[".cs"],
    ),
    VulnerabilityPattern(
        name="Insecure Deserialization - C# ResourceReader",
        category=VulnCategory.DESERIALIZATION,
        patterns=[
            r'ResourceReader\s*\(',
            r'new\s+ResourceReader\s*\(',
            r'ResXResourceReader\s*\(',
        ],
        severity=Severity.HIGH,
        languages=[".cs"],
    ),
    VulnerabilityPattern(
        name="Insecure Deserialization - Ruby Marshal/YAML",
        category=VulnCategory.DESERIALIZATION,
        patterns=[
            r'Marshal\.load\s*\(',
            r'Marshal\.restore\s*\(',
            r'YAML\.load\s*\(',
            r'Psych\.load\s*\([^,)]+\)',
            r'Psych\.unsafe_load\s*\(',
        ],
        severity=Severity.CRITICAL,
        languages=[".rb"],
        false_positive_patterns=[r'YAML\.safe_load', r'Psych\.safe_load'],
    ),

    # =========================================================================
    # AUTHENTICATION BYPASS PATTERNS
    # =========================================================================

    VulnerabilityPattern(
        name="Auth Bypass - Hardcoded Credentials",
        category=VulnCategory.AUTH_BYPASS,
        patterns=[
    # -----------------------------------------------------------------
            # Assignment patterns
    # -----------------------------------------------------------------
            r'password\s*[=:]\s*["\'][^"\']{4,}["\']',
            r'passwd\s*[=:]\s*["\'][^"\']{4,}["\']',
            r'pwd\s*[=:]\s*["\'][^"\']{4,}["\']',
            r'secret\s*[=:]\s*["\'][^"\']{8,}["\']',
            r'api[_-]?key\s*[=:]\s*["\'][a-zA-Z0-9]{16,}["\']',
            r'apikey\s*[=:]\s*["\'][a-zA-Z0-9]{16,}["\']',
            r'auth[_-]?token\s*[=:]\s*["\'][a-zA-Z0-9]{16,}["\']',
            r'access[_-]?token\s*[=:]\s*["\'][a-zA-Z0-9]{16,}["\']',
            r'private[_-]?key\s*[=:]\s*["\']',
            r'connectionString\s*[=:]\s*["\'].*Password',
            r'ConnectionString\s*=\s*["\'].*Password',
            r'admin[_-]?password\s*[=:]\s*["\'][^"\']{4,}["\']',
            r'api[_-]?token\s*[=:]\s*["\'][^"\']{16,}["\']',
            r'bearer[_-]?token\s*[=:]\s*["\'][^"\']{16,}["\']',

    # -----------------------------------------------------------------
            # AWS Keys
    # -----------------------------------------------------------------
            r'AKIA[0-9A-Z]{16}',
            r'aws[_-]?secret[_-]?access[_-]?key\s*[=:]\s*["\'][A-Za-z0-9/+=]{40}["\']',
            r'AWS_SECRET_ACCESS_KEY\s*[=:]\s*["\'][A-Za-z0-9/+=]{40}["\']',

    # -----------------------------------------------------------------
            # Database Connection Strings
    # -----------------------------------------------------------------
            r'mongodb(\+srv)?://[^\s"\']+:[^\s"\']+@[^\s"\']+',
            r'postgres(ql)?://[^\s"\']+:[^\s"\']+@[^\s"\']+',
            r'mysql://[^\s"\']+:[^\s"\']+@[^\s"\']+',
            r'redis://[^\s"\']+:[^\s"\']+@[^\s"\']+',

    # -----------------------------------------------------------------
            # Payment & SaaS API Keys
    # -----------------------------------------------------------------
            r'sk_live_[a-zA-Z0-9]{24,}',
            r'sk_test_[a-zA-Z0-9]{24,}',
            r'rk_live_[a-zA-Z0-9]{24,}',
            r'https://hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[a-zA-Z0-9]+',
            r'xox[baprs]-[0-9a-zA-Z-]+',

    # -----------------------------------------------------------------
            # Session/App Secrets
    # -----------------------------------------------------------------
            r'SESSION_SECRET\s*[=:]\s*["\'][^"\']{16,}["\']',
            r'APP_SECRET\s*[=:]\s*["\'][^"\']{16,}["\']',
            r'JWT_SECRET\s*[=:]\s*["\'][^"\']{16,}["\']',

    # -----------------------------------------------------------------
            # SSH/PGP Private Keys
    # -----------------------------------------------------------------
            r'-----BEGIN\s+(RSA|DSA|EC|OPENSSH|PGP)\s+PRIVATE\s+KEY-----',
            r'-----BEGIN\s+PRIVATE\s+KEY-----',

    # -----------------------------------------------------------------
            # Auth Headers
    # -----------------------------------------------------------------
            r'Basic\s+[A-Za-z0-9+/=]{10,}',
            r'Bearer\s+[A-Za-z0-9._-]{20,}',

    # -----------------------------------------------------------------
            # Cloud Providers
    # -----------------------------------------------------------------
            r'AZURE[_-]?(?:CLIENT|TENANT|SUBSCRIPTION)[_-]?(?:ID|SECRET)\s*[=:]\s*["\'][^"\']+["\']',
            r'GOOGLE[_-]?(?:API[_-]?KEY|CLIENT[_-]?SECRET)\s*[=:]\s*["\'][^"\']+["\']',
            r'gh[pousr]_[A-Za-z0-9_]{36,}',

    # -----------------------------------------------------------------
            # JWT Tokens
    # -----------------------------------------------------------------
            r'eyJ[A-Za-z0-9_-]*\.eyJ[A-Za-z0-9_-]*\.[A-Za-z0-9_-]*',

    # -----------------------------------------------------------------
            # Hardcoded credential comparisons (Java)
    # -----------------------------------------------------------------
            r'["\'][^"\']{4,}["\']\s*\.\s*equals\s*\(\s*\w+\s*\)',
            r'["\'][^"\']{4,}["\']\s*\.\s*equalsIgnoreCase\s*\(\s*\w+\s*\)',
            r'\.\s*equals\s*\(\s*["\'][^"\']{4,}["\']\s*\)',
            r'\.\s*equalsIgnoreCase\s*\(\s*["\'][^"\']{4,}["\']\s*\)',

    # -----------------------------------------------------------------
            # Hardcoded credential comparisons (Python/JS/Ruby/Go)
    # -----------------------------------------------------------------
            r'(?:password|passwd|pwd|secret|token|key|api_key|auth)\s*[=!]=\s*["\'][^"\']{4,}["\']',
            r'["\'][^"\']{4,}["\']\s*[=!]=\s*(?:password|passwd|pwd|secret|token|key)',
            r'==\s*["\'][^"\']{4,}["\']\s*\{',

    # -----------------------------------------------------------------
            # Hardcoded credential comparisons (C#)
    # -----------------------------------------------------------------
            r'\.Equals\s*\(\s*["\'][^"\']{4,}["\']\s*\)',
            r'["\'][^"\']{4,}["\']\s*\.Equals\s*\(',

    # -----------------------------------------------------------------
            # Common weak passwords (with auth context)
    # -----------------------------------------------------------------
            r'\.equals\s*\(\s*["\'](?:admin123|password123|123456|root123|passw0rd|welcome1|letmein)["\']',
            r'["\'](?:admin123|password123|123456|root123|passw0rd|welcome1|letmein)["\']\s*\.equals',
            r'[=!]=\s*["\'](?:admin123|password123|123456|root123|passw0rd|welcome1|letmein)["\']',

    # -----------------------------------------------------------------
            # Header-based auth with hardcoded values
    # -----------------------------------------------------------------
            r'X-(?:Admin|Auth|Api)-(?:Key|Token|Secret)["\'].*["\'][^"\']{4,20}["\']',
        ],
        severity=Severity.HIGH,
        languages=[".js", ".ts", ".py", ".php", ".java", ".cs", ".rb", ".go", ".kt", ".env", ".config", ".json", ".yaml", ".yml"],
        false_positive_patterns=[
            r'process\.env',
            r'os\.environ',
            r'getenv',
            r'System\.getenv',
            r'password\s*[=:]\s*["\']["\']',
            r'<PASSWORD>',
            r'\$\{',
            r'%\{',
            r'Environment\.GetEnvironmentVariable',
            r'Configuration\[',
            r'\.getProperty\s*\(',
            r'@Value\s*\(',
            r'test[_-]?password',
            r'mock[_-]?password',
            r'example[_-]?password',
            r'your[_-]?password[_-]?here',
            r'CHANGE[_-]?ME',
            r'TODO',
            r'FIXME',
            r'xxx+',
            r'\*{4,}',
            r'\.put\s*\(\s*["\']admin["\']',
            r'\.get\s*\(\s*["\']admin["\']',
            r'config\s*\[\s*["\']admin["\']\s*\]',
            r'["\']admin["\']\s*[=:]\s*(?:true|false|True|False)',
            # Test/example file indicators
            r'_test\.',
            r'\.test\.',
            r'_spec\.',
            r'\.spec\.',
            r'test_',
            r'mock_',
            r'fake_',
            r'example\.',
            r'sample\.',
            # Documentation/comment patterns
            r'["\']password["\']:\s*["\']<',
            r'["\']password["\']:\s*["\']your',
            r'["\']password["\']:\s*["\']REDACTED',
            r'placeholder',
            r'dummy',
            # Schema/validation patterns (not actual passwords)
            r'required:\s*true',
            r'type:\s*["\']string["\']',
            r'minLength',
            r'maxLength',
            r'pattern:',
            # Kubernetes/Docker secrets reference (not actual values)
            r'secretKeyRef',
            r'valueFrom',
            r'secretName',
            # Environment variable references
            r'\$[A-Z_]+',
            r'\$\([^)]+\)',
            r'%[A-Z_]+%',
        ],
    ),

    VulnerabilityPattern(
        name="Auth Bypass - JWT None Algorithm",
        category=VulnCategory.AUTH_BYPASS,
        patterns=[
            r'algorithms\s*[=:]\s*\[\s*["\']none["\']',
            r'algorithm\s*[=:]\s*["\']none["\']',
            r'jwt\.decode\s*\([^)]*verify\s*=\s*False',
            r'ValidateIssuerSigningKey\s*=\s*false',
            r'RequireSignedTokens\s*=\s*false',
            r'RequireExpirationTime\s*=\s*false',
            r'RequireAudience\s*=\s*false',
            r'verify\s*[=:]\s*false',
            r'ignoreExpiration\s*[=:]\s*true',
            r'ignoreNotBefore\s*[=:]\s*true',
            r'algorithms\s*[=:]\s*\[\s*\]',
            # Additional JWT bypass patterns
            r'clockTolerance\s*[=:]\s*\d{6,}',
            r'\.decode\s*\([^)]*options\s*:\s*\{[^}]*complete\s*:\s*true',
            r'jwt_decode\s*\([^)]+,\s*\{[^}]*verify["\']:\s*[Ff]alse',
            r'LifetimeValidator\s*=\s*null',
            r'ValidateLifetime\s*=\s*false',
            r'SaveSigninToken\s*=\s*false.*ValidateIssuerSigningKey\s*=\s*false',
        ],
        severity=Severity.CRITICAL,
        languages=[".js", ".ts", ".py", ".php", ".java", ".cs", ".rb", ".go"],
        false_positive_patterns=[
            r'jwt\.verify',
            r'^#',
            r'^\s*#',
            r'//.*verify',
            r'FrappeClient.*verify=False',
            r'_test\.',
            r'\.test\.',
            r'test_',
            r'\.spec\.',
            r'mock',
            r'fixture',
        ],
    ),

    VulnerabilityPattern(
        name="Auth Bypass - Weak Comparison",
        category=VulnCategory.AUTH_BYPASS,
        patterns=[
            r'password\s*==\s*',
            r'token\s*==\s*',
            r'secret\s*==\s*',
            r'strcmp\s*\(\s*\$',
            r'strcasecmp\s*\(\s*\$',
            r'\$\w*(?:pass|pwd|token|secret|key)\w*\s*==\s*',
            r'md5\s*\([^)]+\)\s*==',
            r'sha1\s*\([^)]+\)\s*==',
            # Additional weak comparison patterns
            r'hash\s*\([^)]+\)\s*==',
            r'crypt\s*\([^)]+\)\s*==',
            r'password_hash\s*\([^)]+\)\s*==',
            r'\.compare\s*\(\s*password',
            r'password\.localeCompare\s*\(',
        ],
        severity=Severity.MEDIUM,
        languages=[".php", ".js"],
        false_positive_patterns=[
            r'===',
            r'!==',
            r'hash_equals',
            r'secure_compare',
            r'constant_time_compare',
            r'timingSafeEqual',
            r'password_verify',
            r'bcrypt\.compare',
            r'argon2\.verify',
            r'scrypt\.verify',
            r'\.verify\s*\(',
            r'crypto\.subtle',
        ],
    ),

    VulnerabilityPattern(
        name="Auth Bypass - Empty/Null Check Bypass",
        category=VulnCategory.AUTH_BYPASS,
        patterns=[
            # Java empty/null bypasses
            r'\|\|\s*\w+\s*\.\s*isEmpty\s*\(\s*\)',
            r'\|\|\s*\w+\s*\.\s*isBlank\s*\(\s*\)',
            r'\|\|\s*\w+\s*==\s*null',
            r'\|\|\s*null\s*==\s*\w+',
            r'(?:password|token|key|secret|auth)\w*\s*\.\s*isEmpty\s*\(\s*\)',
            r'StringUtils\.isEmpty\s*\(\s*(?:password|token|key|secret|auth)',
            r'StringUtils\.isBlank\s*\(\s*(?:password|token|key|secret|auth)',

            # Python empty/None bypasses
            r'if\s+not\s+(?:password|token|key|secret|auth)\w*\s*:',
            r'(?:password|token|key|secret|auth)\w*\s*(?:==|is)\s*None',
            r'(?:password|token|key|secret|auth)\w*\s*==\s*["\']["\']',

            # JS/TS falsy bypasses
            r'!\s*(?:password|token|key|secret|auth)\w*\s*[&|{)\]]',
            r'(?:password|token|key|secret|auth)\w*\s*===?\s*(?:undefined|null|"")',

            # PHP empty bypasses
            r'empty\s*\(\s*\$(?:password|token|key|secret|auth)',
            r'is_null\s*\(\s*\$(?:password|token|key|secret|auth)',

            # C# empty/null bypasses
            r'string\.IsNullOrEmpty\s*\(\s*(?:password|token|key|secret|auth)',
            r'string\.IsNullOrWhiteSpace\s*\(\s*(?:password|token|key|secret|auth)',
        ],
        severity=Severity.CRITICAL,
        languages=[".js", ".ts", ".py", ".php", ".java", ".cs", ".rb", ".go", ".kt"],
        false_positive_patterns=[
            r'throw',
            r'raise',
            r'return\s+false',
            r'return\s+False',
            r'deny',
            r'reject',
            r'unauthorized',
            r'forbidden',
        ],
    ),

    VulnerabilityPattern(
        name="Auth Bypass - Broken Access Control",
        category=VulnCategory.AUTH_BYPASS,
        patterns=[
            # OR conditions that bypass auth
            r'\|\|\s*\w+\s*\.\s*isEmpty\s*\(\s*\)',
            r'\|\|\s*\w+\s*\.\s*isBlank\s*\(\s*\)',
            r'\|\|\s*\w+\s*[=!]=\s*["\']["\']',
            r'\|\|\s*!\s*\w+',
            r'\|\|\s*\w+\s*==\s*null',

            # Commented out auth checks
            r'//\s*if\s*\(\s*!?\s*(?:auth|isAdmin|checkPermission|verify|isAuthenticated)',
            r'#\s*if\s+not\s+(?:auth|is_admin|check_permission|verify)',

            # Always-true conditions
            r'if\s*\(\s*true\s*\)',
            r'if\s+True\s*:',
            r'if\s*\(\s*1\s*\)',

            # Role checks with hardcoded values
            r'(?:role|isAdmin|is_admin|userRole)\s*[=!]=\s*["\'](?:admin|root|superuser)["\']',

            # Insecure default permissions
            r'(?:isAdmin|is_admin|hasAccess|authorized)\s*[=:]\s*true',
            r'(?:isAdmin|is_admin|hasAccess|authorized)\s*[=:]\s*True',
        ],
        severity=Severity.CRITICAL,
        languages=[".js", ".ts", ".py", ".php", ".java", ".cs", ".rb", ".go", ".kt"],
        false_positive_patterns=[
            r'test',
            r'spec',
            r'mock',
            r'\.test\.',
            r'_test\.',
        ],
    ),

    # =========================================================================
    # SSTI (Server-Side Template Injection) PATTERNS
    # =========================================================================

    VulnerabilityPattern(
        name="SSTI - Jinja2/Flask/Mako (Python)",
        category=VulnCategory.SSTI,
        patterns=[
            # render_template_string with user input
            r'render_template_string\s*\(\s*request\.(form|args|json|data|values|get_json)',
            r'render_template_string\s*\(\s*f["\']',
            r'render_template_string\s*\(\s*["\'].*%\s*\(',
            r'render_template_string\s*\(\s*["\'].*\.format\s*\(',
            r'render_template_string\s*\(\s*["\'].*\+',
            r'render_template_string\s*\(\s*\w+\s*\)',  # Variable input
            r'render_template_string\s*\(\s*str\s*\(',

            # Jinja2 Environment/Template direct
            r'Template\s*\(\s*request\.(form|args|json|data)',
            r'Template\s*\(\s*f["\']',
            r'Template\s*\(\s*["\'].*%\s*\(',
            r'Template\s*\(\s*["\'].*\.format\s*\(',
            r'Template\s*\(\s*["\'].*\+',
            r'jinja2\.Template\s*\(\s*request\.',
            r'jinja2\.Template\s*\(\s*f["\']',

            # Environment.from_string
            r'\.from_string\s*\(\s*request\.',
            r'\.from_string\s*\(\s*f["\']',
            r'\.from_string\s*\(\s*["\'].*%',
            r'\.from_string\s*\(\s*["\'].*\+',
            r'env\.from_string\s*\(\s*.*request\.',
            r'Environment\s*\([^)]*\)\.from_string\s*\(',
            r'get_template_attribute.*from_string',

            # Mako templates
            r'mako\.template\.Template\s*\(\s*request\.',
            r'mako\.template\.Template\s*\(\s*f["\']',
            r'MakoTemplate\s*\(\s*request\.',
            r'Template\s*\(\s*text\s*=\s*request\.',
            r'Template\s*\(\s*text\s*=\s*f["\']',
            r'mako\.lookup\.TemplateLookup.*get_template\s*\(\s*request\.',

            # Tornado templates
            r'tornado\.template\.Template\s*\(\s*request\.',
            r'tornado\.template\.Template\s*\(\s*self\.get_argument',
            r'template\.Template\s*\(\s*self\.get_argument',
            r'\.generate\s*\(\s*\*\*.*request\.',

            # Django (unsafe patterns)
            r'django\.template\.Template\s*\(\s*request\.(GET|POST|body)',
            r'Engine\s*\([^)]*\)\.from_string\s*\(\s*request\.',
            r'engines\[["\']django["\']\]\.from_string\s*\(\s*request\.',
            r'Template\s*\(\s*request\.(GET|POST|body)',

            # Chameleon
            r'chameleon\.PageTemplate\s*\(\s*request\.',
            r'PageTemplate\s*\(\s*request\.',

            # Genshi
            r'genshi\.template\.MarkupTemplate\s*\(\s*request\.',
            r'MarkupTemplate\s*\(\s*request\.',
            r'TextTemplate\s*\(\s*request\.',

            # String formatting passed to render
            r'\.render\s*\(\s*\{[^}]*:\s*request\.(form|args|json)',
            r'\.render\s*\(\s*\*\*request\.(form|json)',
            r'\.render_string\s*\(\s*request\.',
        ],
        severity=Severity.CRITICAL,
        languages=[".py"],
        false_positive_patterns=[
            r'render_template\s*\(\s*["\'][^"\']+\.(html|jinja|j2)',
            r'escape\s*\(',
            r'Markup\s*\(',
            r'markupsafe\.',
            r'autoescape\s*=\s*True',
            r'\.txt["\']',
            r'select_autoescape',
            # Safe rendering with static templates
            r'render_template\s*\(\s*["\']',
            r'get_template\s*\(\s*["\']',
            # Escaped output
            r'\|e\s*\}\}',
            r'\|escape\s*\}\}',
            r'\|safe\s*\}\}',
            # Test/mock context
            r'_test\.',
            r'\.test\.',
            r'test_',
            r'mock',
            r'fixture',
        ],
    ),

    VulnerabilityPattern(
        name="SSTI - EJS/Pug/Jade/Nunjucks/Handlebars (Node.js)",
        category=VulnCategory.SSTI,
        patterns=[
            # EJS
            r'ejs\.render\s*\(\s*req\.(body|query|params)',
            r'ejs\.render\s*\(\s*`[^`]*\$\{',
            r'ejs\.render\s*\(\s*["\'].*\+',
            r'ejs\.render\s*\(\s*\w+\s*,',  # Variable as template
            r'ejs\.compile\s*\(\s*req\.',
            r'ejs\.compile\s*\(\s*`[^`]*\$\{',
            r'ejs\.renderFile\s*\(\s*req\.(body|query|params)',
            r'res\.render\s*\(\s*req\.(body|query|params)',  # Express with user-controlled view

            # Pug/Jade
            r'pug\.compile\s*\(\s*req\.(body|query|params)',
            r'pug\.compile\s*\(\s*`[^`]*\$\{',
            r'pug\.render\s*\(\s*req\.(body|query|params)',
            r'pug\.render\s*\(\s*`[^`]*\$\{',
            r'pug\.render\s*\(\s*["\'].*\+',
            r'pug\.renderFile\s*\(\s*req\.',
            r'jade\.compile\s*\(\s*req\.',
            r'jade\.render\s*\(\s*req\.',
            r'jade\.renderFile\s*\(\s*req\.',

            # Nunjucks
            r'nunjucks\.renderString\s*\(\s*req\.',
            r'nunjucks\.renderString\s*\(\s*`[^`]*\$\{',
            r'nunjucks\.renderString\s*\(\s*["\'].*\+',
            r'nunjucks\.compile\s*\(\s*req\.',
            r'env\.renderString\s*\(\s*req\.',
            r'nunjucks\.Environment.*renderString\s*\(\s*req\.',
            r'\.addGlobal\s*\([^)]*req\.(body|query|params)',

            # Handlebars
            r'Handlebars\.compile\s*\(\s*req\.',
            r'Handlebars\.compile\s*\(\s*`[^`]*\$\{',
            r'Handlebars\.compile\s*\(\s*["\'].*\+',
            r'handlebars\.compile\s*\(\s*req\.',
            r'hbs\.compile\s*\(\s*req\.',
            r'Handlebars\.precompile\s*\(\s*req\.',
            r'Handlebars\.registerHelper.*req\.(body|query|params)',
            r'Handlebars\.SafeString\s*\(\s*req\.',  # Bypasses escaping

            # Mustache
            r'Mustache\.render\s*\(\s*req\.',
            r'Mustache\.render\s*\(\s*`[^`]*\$\{',
            r'mustache\.render\s*\(\s*req\.',
            r'Mustache\.parse\s*\(\s*req\.',

            # Lodash/Underscore template
            r'_\.template\s*\(\s*req\.',
            r'_\.template\s*\(\s*`[^`]*\$\{',
            r'_\.template\s*\(\s*["\'].*\+',
            r'lodash\.template\s*\(\s*req\.',
            r'underscore\.template\s*\(\s*req\.',

            # doT.js
            r'doT\.template\s*\(\s*req\.',
            r'doT\.compile\s*\(\s*req\.',
            r'dot\.template\s*\(\s*req\.',

            # Marko
            r'marko\.load\s*\(\s*req\.',
            r'\.renderToString\s*\(\s*\{[^}]*:\s*req\.',

            # Swig (deprecated but still used)
            r'swig\.render\s*\(\s*req\.',
            r'swig\.compile\s*\(\s*req\.',
            r'swig\.renderFile\s*\(\s*req\.',

            # Dust.js
            r'dust\.render\s*\(\s*req\.',
            r'dust\.compile\s*\(\s*req\.',
            r'dust\.renderSource\s*\(\s*req\.',

            # Eta
            r'eta\.render\s*\(\s*req\.',
            r'eta\.renderString\s*\(\s*req\.',
            r'Eta\s*\(\s*\)\.renderString\s*\(\s*req\.',

            # Squirrelly
            r'Sqrl\.render\s*\(\s*req\.',
            r'squirrelly\.render\s*\(\s*req\.',

            # Generic patterns
            r'\.compile\s*\(\s*req\.(body|query|params)',
            r'\.render\s*\(\s*req\.(body|query|params)\s*[,\)]',
            r'template\s*\(\s*req\.(body|query|params)',
            r'eval\s*\(\s*["\'].*req\.(body|query|params)',  # eval in template context
        ],
        severity=Severity.CRITICAL,
        languages=[".js", ".ts", ".jsx", ".tsx", ".mjs"],
        false_positive_patterns=[
            r'\.render\s*\(\s*["\'][^"\']+\.(html|ejs|pug|hbs|njk)',
            r'escape\s*\(',
            r'escapeHtml\s*\(',
            r'sanitize',
            r'encodeURIComponent',
            r'validator\.',
            r'xss\s*\(',
        ],
    ),

    VulnerabilityPattern(
        name="SSTI - Razor/Scriban/Fluid/DotLiquid (C#)",
        category=VulnCategory.SSTI,
        patterns=[
            # RazorEngine
            r'RazorEngine.*\.Compile\s*\(\s*.*Request\.',
            r'RazorEngine.*\.Compile\s*\(\s*\$"',
            r'RazorEngine.*\.Compile\s*\(\s*["\'].*\+',
            r'Engine\.Razor\.RunCompile\s*\(\s*.*Request\.',
            r'Engine\.Razor\.RunCompile\s*\(\s*\$"',
            r'RazorEngineService.*\.RunCompile\s*\(',
            r'RazorEngineService.*\.Compile\s*\(',
            r'\.CompileRenderString\s*\(\s*.*Request\.',
            r'RazorTemplateEngine.*\.GenerateCode\s*\(',
            r'RazorLightEngine.*\.CompileRenderStringAsync\s*\(',

            # Scriban
            r'Scriban\.Template\.Parse\s*\(\s*.*Request\.',
            r'Scriban\.Template\.Parse\s*\(\s*\$"',
            r'Template\.Parse\s*\(\s*.*Request\.(Query|Form)',
            r'Template\.Parse\s*\(\s*\$"',
            r'Template\.ParseLiquid\s*\(\s*.*Request\.',
            r'\.Render\s*\(\s*.*Request\.(Query|Form)',

            # Fluid (Liquid for .NET)
            r'FluidTemplate\.Parse\s*\(\s*.*Request\.',
            r'FluidParser\s*\(\s*\)\.Parse\s*\(\s*.*Request\.',
            r'_fluidParser\.Parse\s*\(\s*.*Request\.',
            r'IFluidTemplate.*Parse\s*\(\s*.*Request\.',

            # DotLiquid
            r'DotLiquid\.Template\.Parse\s*\(\s*.*Request\.',
            r'DotLiquid\.Template\.Parse\s*\(\s*\$"',
            r'Template\.Parse\s*\(\s*.*Request\.(Query|Form|Body)',
            r'\.RegisterSafeType.*Request\.',  # Registering request as safe

            # Handlebars.NET
            r'Handlebars\.Compile\s*\(\s*.*Request\.',
            r'Handlebars\.Compile\s*\(\s*\$"',
            r'handlebarsInstance\.Compile\s*\(\s*.*Request\.',
            r'HandlebarsTemplate.*Compile\s*\(\s*.*Request\.',

            # Stubble (Mustache for .NET)
            r'StubbleBuilder.*Render\s*\(\s*.*Request\.',
            r'stubble\.Render\s*\(\s*.*Request\.',

            # Nustache
            r'Nustache\.Core\.Render\.StringToString\s*\(\s*.*Request\.',

            # ASPX (code expressions)
            r'<%=\s*Request\.',
            r'<%=\s*Request\[("|\')',
            r'<%:\s*Request\.',
            r'Response\.Write\s*\(\s*Request\.',
        ],
        severity=Severity.CRITICAL,
        languages=[".cs", ".cshtml", ".vb", ".aspx", ".ascx"],
        false_positive_patterns=[
            r'\.Parse\s*\(\s*["\'][^"\']*["\']',  # Static template string
            r'HtmlEncode',
            r'AntiXss',
            r'HttpUtility\.HtmlEncode',
            r'WebUtility\.HtmlEncode',
            r'Server\.HtmlEncode',
        ],
    ),

    VulnerabilityPattern(
        name="SSTI - Twig/Blade/Smarty/Latte (PHP)",
        category=VulnCategory.SSTI,
        patterns=[
            # Twig
            r'->createTemplate\s*\(\s*\$_(GET|POST|REQUEST|COOKIE)',
            r'->createTemplate\s*\(\s*\$[a-zA-Z_]\w*\s*\)',
            r'Twig\\Environment.*->createTemplate\s*\(\s*\$',
            r'Twig_Environment.*->createTemplate\s*\(\s*\$',
            r'\$twig->render\s*\(\s*\$_(GET|POST|REQUEST)',
            r'->render\s*\(\s*\$_(GET|POST|REQUEST)',
            r'Environment\s*\([^)]*\)->render\s*\(\s*\$',
            r'->loadTemplate\s*\(\s*\$_(GET|POST|REQUEST)',
            r'Twig\\Loader\\ArrayLoader\s*\(\s*\[.*\$_(GET|POST)',

            # Blade (Laravel)
            r'Blade::compileString\s*\(\s*\$',
            r'Blade::render\s*\(\s*\$',
            r'\\Illuminate\\View\\Compilers\\BladeCompiler.*compile\s*\(\s*\$',
            r'view\s*\(\s*\$_(GET|POST|REQUEST)',
            r'View::make\s*\(\s*\$_(GET|POST|REQUEST)',
            r'@php.*\$_(GET|POST|REQUEST)',
            r'\{!!\s*\$_(GET|POST|REQUEST)',  # Unescaped Blade output

            # Smarty
            r'\{php\}',  # Dangerous Smarty tag
            r'\{/php\}',
            r'->fetch\s*\(\s*["\']string:.*\$_(GET|POST|REQUEST)',
            r'Smarty.*->fetch\s*\(\s*\$',
            r'->display\s*\(\s*["\']string:.*\$',
            r'->assign\s*\(\s*["\'].*["\']\s*,\s*\$_(GET|POST|REQUEST)',
            r'smarty_modifier_',  # Custom modifiers
            r'\{eval\s+var=',  # Smarty eval
            r'\{include\s+file=.*\$',
            r'->registerPlugin.*eval',
            r'->setTemplateDir\s*\(\s*\$_(GET|POST)',

            # Latte
            r'Latte\\Engine.*render\s*\(\s*\$',
            r'Latte\\Engine.*renderToString\s*\(\s*\$',
            r'->renderToString\s*\(\s*\$_(GET|POST)',
            r'\$latte->render\s*\(\s*\$_(GET|POST)',
            r'createTemplate\s*\(\s*\$_(GET|POST)',

            # Plates
            r'->render\s*\(\s*\$_(GET|POST|REQUEST)',
            r'League\\Plates.*render\s*\(\s*\$',
            r'\$plates->render\s*\(\s*\$',

            # Mustache.php
            r'Mustache_Engine.*render\s*\(\s*\$',
            r'\$mustache->render\s*\(\s*\$_(GET|POST)',
            r'->loadTemplate\s*\(\s*\$_(GET|POST)',

            # Volt (Phalcon)
            r'Volt.*compile\s*\(\s*\$',
            r'->render\s*\(\s*\$_(GET|POST)',

            # Generic PHP patterns
            r'eval\s*\(\s*.*\$_(GET|POST|REQUEST|COOKIE)',
            r'create_function\s*\(\s*.*\$_(GET|POST|REQUEST)',
            r'preg_replace\s*\(\s*["\'].*\/e["\']',  # Deprecated /e modifier
            r'assert\s*\(\s*.*\$_(GET|POST|REQUEST)',
        ],
        severity=Severity.CRITICAL,
        languages=[".php", ".tpl", ".blade.php", ".twig", ".latte", ".phtml"],
        false_positive_patterns=[
            r'->render\s*\(\s*["\'][^"\']+\.twig',
            r'->render\s*\(\s*["\'][^"\']+\.blade\.php',
            r'escape\s*\(',
            r'htmlspecialchars\s*\(',
            r'htmlentities\s*\(',
            r'\|e\s*\}',  # Twig escape filter
            r'\|escape\s*\}',
            r'e\s*\(\s*\$',  # Laravel e() helper
            r'\{\{\s*\$',  # Escaped Blade output
        ],
    ),

    VulnerabilityPattern(
        name="SSTI - Thymeleaf/Freemarker/Velocity/Pebble (Java)",
        category=VulnCategory.SSTI,
        patterns=[
            # Thymeleaf
            r'SpringTemplateEngine.*process\s*\(\s*.*getParameter',
            r'TemplateEngine.*process\s*\(\s*.*request\.get',
            r'TemplateEngine.*process\s*\(\s*.*\+',
            r'ITemplateEngine.*process\s*\(\s*.*getParameter',
            r'th:utext\s*=',  # Unescaped text
            r'th:text\s*=\s*["\'].*\$\{.*getParameter',
            r'\[\[.*\$\{.*request\.getParameter',
            r'\[\(.*\$\{.*getParameter',  # Unescaped inline
            r'data-th-utext',
            r'StandardExpressionParser.*parseExpression\s*\(\s*.*getParameter',

            # Freemarker
            r'Template.*process\s*\(\s*.*getParameter',
            r'Configuration.*getTemplate\s*\(\s*.*getParameter',
            r'Configuration.*getTemplate\s*\(\s*.*request\.get',
            r'new\s+Template\s*\(\s*[^,]*,\s*new\s+StringReader\s*\(\s*.*request\.get',
            r'freemarker\.template\.Template\s*\(\s*.*getParameter',
            r'<#assign\s+.*=.*request\.getParameter',
            r'\$\{.*request\.getParameter',
            r'cfg\.setSharedVariable.*getParameter',
            r'Environment.*setVariable.*getParameter',

            # Velocity
            r'Velocity\.evaluate\s*\(\s*.*getParameter',
            r'Velocity\.evaluate\s*\(\s*.*request\.get',
            r'VelocityEngine.*evaluate\s*\(\s*.*request\.get',
            r'VelocityEngine.*evaluate\s*\(\s*.*getParameter',
            r'template\.merge\s*\(\s*.*getParameter',
            r'\.mergeTemplate\s*\(\s*.*request\.get',
            r'RuntimeInstance.*evaluate\s*\(',
            r'VelocityContext.*put.*getParameter',
            r'#set\s*\(\s*\$.*=.*getParameter',
            r'#evaluate\s*\(',
            r'#parse\s*\(\s*.*getParameter',

            # Pebble
            r'PebbleEngine.*getTemplate\s*\(\s*.*getParameter',
            r'PebbleEngine.*getLiteralTemplate\s*\(\s*.*getParameter',
            r'pebbleEngine\.getLiteralTemplate\s*\(\s*.*request\.get',
            r'\.evaluate\s*\(\s*.*getParameter',

            # Groovy Templates (GSP)
            r'GroovyPagesTemplateEngine.*createTemplate\s*\(\s*.*getParameter',
            r'SimpleTemplateEngine.*createTemplate\s*\(\s*.*getParameter',
            r'GStringTemplateEngine.*createTemplate\s*\(\s*.*getParameter',
            r'MarkupTemplateEngine.*createTemplate\s*\(\s*.*getParameter',

            # OGNL (Struts2) - very dangerous
            r'%\{.*#.*\}',  # OGNL expression
            r'OgnlUtil\.getValue\s*\(\s*.*getParameter',
            r'OgnlUtil\.setValue\s*\(\s*.*getParameter',
            r'Ognl\.getValue\s*\(\s*.*request\.get',
            r'OgnlValueStack.*findValue\s*\(\s*.*getParameter',
            r'ActionContext.*get\s*\(\s*.*getParameter',

            # SpEL (Spring Expression Language)
            r'SpelExpressionParser.*parseExpression\s*\(\s*.*getParameter',
            r'ExpressionParser.*parseExpression\s*\(\s*.*request\.get',
            r'StandardEvaluationContext.*setValue.*getParameter',
            r'SpelExpression.*getValue\s*\(\s*.*getParameter',
            r'new\s+SpelExpressionParser\s*\(\s*\)\.parseExpression\s*\(\s*.*getParameter',
            r'@Value\s*\(\s*["\']#\{.*getParameter',

            # MVEL
            r'MVEL\.eval\s*\(\s*.*getParameter',
            r'MVEL\.compileExpression\s*\(\s*.*getParameter',
            r'MVELRuntime.*eval\s*\(\s*.*getParameter',

            # JEXL
            r'JexlEngine.*createExpression\s*\(\s*.*getParameter',
            r'JexlExpression.*evaluate\s*\(\s*.*getParameter',
            r'jexl\.createScript\s*\(\s*.*getParameter',
        ],
        severity=Severity.CRITICAL,
        languages=[".java", ".kt", ".groovy", ".gsp", ".ftl", ".vm"],
        false_positive_patterns=[
            r'\.process\s*\(\s*["\'][^"\']+\.html',
            r'\.getTemplate\s*\(\s*["\'][^"\']+\.(ftl|vm|html)',
            r'HtmlUtils\.htmlEscape',
            r'StringEscapeUtils\.escapeHtml',
            r'escapeHtml4',
            r'ESAPI\.encoder',
        ],
    ),

    VulnerabilityPattern(
        name="SSTI - ERB/Slim/Haml/Liquid (Ruby)",
        category=VulnCategory.SSTI,
        patterns=[
            # ERB
            r'ERB\.new\s*\(\s*params\[',
            r'ERB\.new\s*\(\s*request\.',
            r'ERB\.new\s*\(\s*.*#\{.*params',
            r'ERB\.new\s*\(\s*.*\+.*params',
            r'Erubis::Eruby\.new\s*\(\s*params\[',
            r'Erubis::Eruby\.new\s*\(\s*request\.',
            r'\.result\s*\(\s*binding\s*\).*params',  # ERB result with binding

            # Slim
            r'Slim::Template\.new\s*\(\s*params\[',
            r'Slim::Template\.new\s*\(\s*request\.',
            r'slim\s*\(\s*params\[',
            r'Slim::Engine\.new\.render\s*\(\s*params\[',

            # Haml
            r'Haml::Engine\.new\s*\(\s*params\[',
            r'Haml::Engine\.new\s*\(\s*request\.',
            r'haml\s*\(\s*params\[',
            r'Haml::Template\.new\s*\(\s*params\[',

            # Liquid
            r'Liquid::Template\.parse\s*\(\s*params\[',
            r'Liquid::Template\.parse\s*\(\s*request\.',
            r'\.parse\s*\(\s*params\[',
            r'\.render\s*\(\s*.*params\[',
            r'Liquid::Environment.*parse\s*\(\s*params\[',

            # Tilt (generic template interface)
            r'Tilt\.new\s*\(\s*params\[',
            r'Tilt\[["\'].*["\']\]\.new\s*\(\s*params\[',

            # ActionView render inline
            r'render\s+inline:\s*params\[',
            r'render\s+inline:\s*.*#\{.*params',
            r'render\s+inline:\s*request\.',
            r'render\s*\(\s*inline:\s*params\[',

            # Mustache
            r'Mustache\.render\s*\(\s*params\[',

            # Generic Ruby interpolation in templates
            r'eval\s*\(\s*params\[',
            r'instance_eval\s*\(\s*params\[',
            r'class_eval\s*\(\s*params\[',
            r'send\s*\(\s*params\[',  # Dynamic method calls
        ],
        severity=Severity.CRITICAL,
        languages=[".rb", ".erb", ".haml", ".slim", ".rhtml"],
        false_positive_patterns=[
            r'ERB\.new\s*\(\s*File\.read',
            r'render\s+template:',
            r'render\s+partial:',
            r'html_escape',
            r'h\s*\(',
            r'sanitize',
            r'CGI\.escapeHTML',
            r'ERB::Util\.html_escape',
        ],
    ),

    VulnerabilityPattern(
        name="SSTI - Go Templates",
        category=VulnCategory.SSTI,
        patterns=[
            # html/template and text/template
            r'template\.New\s*\([^)]*\)\.Parse\s*\(\s*r\.(URL|Form|PostForm|FormValue)',
            r'template\.New\s*\([^)]*\)\.Parse\s*\(\s*.*r\.Form\.Get',
            r'template\.Must\s*\(\s*.*\.Parse\s*\(\s*r\.',
            r'text/template.*\.Parse\s*\(\s*r\.',
            r'html/template.*\.Parse\s*\(\s*r\.',
            r'\.Parse\s*\(\s*r\.FormValue\s*\(',
            r'\.Parse\s*\(\s*r\.URL\.Query',
            r'\.Parse\s*\(\s*fmt\.Sprintf',
            r'\.Parse\s*\(\s*.*\+.*r\.',
            r'template\.ParseGlob\s*\(\s*r\.',

            # Pongo2
            r'pongo2\.FromString\s*\(\s*r\.',
            r'pongo2\.FromString\s*\(\s*.*r\.Form',
            r'pongo2\.Must\s*\(\s*.*FromString\s*\(\s*r\.',
            r'pongo2\.FromBytes\s*\(\s*.*r\.',

            # Jet
            r'jet\.NewSet\s*\([^)]*\)\.Parse\s*\(\s*r\.',
            r'views\.GetTemplate\s*\(\s*r\.',

            # Ace
            r'ace\.Load\s*\(\s*r\.',

            # Amber
            r'amber\.CompileString\s*\(\s*r\.',

            # Quicktemplate
            r'Write.*\(\s*r\.Form',

            # Hero
            r'hero\.Render\s*\(\s*r\.',
        ],
        severity=Severity.CRITICAL,
        languages=[".go"],
        false_positive_patterns=[
            r'\.ParseFiles\s*\(',
            r'\.ParseGlob\s*\(\s*["\']',
            r'template\.HTMLEscapeString',
            r'html\.EscapeString',
            r'url\.QueryEscape',
        ],
    ),

    VulnerabilityPattern(
        name="SSTI - Dangerous Template Payloads/Patterns",
        category=VulnCategory.SSTI,
        patterns=[
            # Jinja2/Twig exploitation patterns
            r'\{\{\s*config\s*\}\}',
            r'\{\{\s*self\._TemplateReference__context',
            r'\{\{.*__class__.*__mro__',
            r'\{\{.*__class__.*__base__',
            r'\{\{.*__class__.*__subclasses__',
            r'\{\{.*__globals__',
            r'\{\{.*__builtins__',
            r'\{\{.*__import__',
            r'\{\{.*lipsum\.__globals__',
            r'\{\{.*cycler\.__init__',
            r'\{\{.*joiner\.__init__',
            r'\{\{.*namespace\.__init__',
            r'\{\{.*request\.application',
            r'\{\{.*request\.__class__',
            r'\{\{.*\[["\']\w+["\']\]\.__',
            r'\{\{.*\|attr\s*\(',
            r'\{\%.*import\s+os',
            r'\{\%.*from\s+os\s+import',

            # Freemarker exploitation
            r'<#assign\s+.*=.*ObjectConstructor',
            r'<#assign\s+.*=.*\.class\.forName',
            r'<#assign\s+.*=.*getRuntime',
            r'freemarker\.template\.utility\.Execute',
            r'freemarker\.template\.utility\.ObjectConstructor',
            r'\?new\s*\(\s*\)',
            r'\.getClassLoader',
            r'\.newInstance\s*\(',

            # Velocity exploitation
            r'#set\s*\(\s*\$.*=.*getClass\s*\(',
            r'#set\s*\(\s*\$.*=.*\.class\.forName',
            r'#set\s*\(\s*\$.*=.*getRuntime',
            r'\$class\.inspect',
            r'\$class\.forName',
            r'#evaluate\s*\(\s*\$',
            r'#include\s*\(\s*\$',
            r'#parse\s*\(\s*\$',

            # OGNL exploitation (Struts2)
            r'%\{\s*#.*=.*@',
            r'%\{.*getRuntime',
            r'%\{.*ProcessBuilder',
            r'\(#.*=.*@java\.lang',
            r'#_memberAccess',
            r'#context',
            r'#application',
            r'#session',
            r'OgnlContext',

            # SpEL exploitation
            r'\$\{T\s*\(\s*java\.lang',
            r'\$\{.*Runtime.*exec',
            r'\$\{.*ProcessBuilder',
            r'\$\{.*getClass\(\)\.forName',
            r'#\{T\s*\(\s*java\.lang',
            r'new\s+java\.lang\.ProcessBuilder',
            r'T\s*\(\s*java\.lang\.Runtime\s*\)',

            # Pebble exploitation
            r'\{\{.*\.getClass\(\)',
            r'\{\{.*beans\.get',
            r'\{\{.*getRuntime',

            # Smarty exploitation
            r'\{php\}.*exec',
            r'\{php\}.*system',
            r'\{php\}.*passthru',
            r'\{php\}.*shell_exec',
            r'\{Smarty_Internal_Write_File',

            # ERB exploitation
            r'<%=.*`.*%>',  # Command substitution
            r'<%=.*system\s*\(',
            r'<%=.*exec\s*\(',
            r'<%=.*IO\.popen',
            r'<%=.*Open3',

            # Generic exploitation patterns
            r'__proto__',
            r'constructor\s*\[',
            r'prototype\s*\.',
            r'globalThis',
            r'Function\s*\(\s*["\']',  # Function constructor
        ],
        severity=Severity.CRITICAL,
        languages=[".py", ".php", ".java", ".js", ".ts", ".rb", ".go", ".tpl", ".html", ".htm", ".ftl", ".vm", ".erb", ".kt", ".groovy"],
    ),

    # =========================================================================
    # SSRF (Server-Side Request Forgery) PATTERNS
    # =========================================================================
    # =========================================================================
    # SSRF PATTERNS - IMPROVED
    # =========================================================================

    VulnerabilityPattern(
        name="SSRF - Dynamic URL Fetch (Node.js)",
        category=VulnCategory.SSRF,
        patterns=[
    # =====================================================================
            # FETCH API
    # =====================================================================
            # Direct request object usage
            r'fetch\s*\(\s*req\.(body|query|params|cookies|headers)',
            r'fetch\s*\(\s*`[^`]*\$\{[^}]*req\.',
            r'fetch\s*\(\s*["\'].*\+.*req\.',

            # Variable-based (common taint variable names)
            r'fetch\s*\(\s*(url|uri|target|endpoint|href|link|dest|destination|path|host|'
            r'userUrl|targetUrl|redirectUrl|callbackUrl|imageUrl|fetchUrl|apiUrl|'
            r'externalUrl|remoteUrl|resourceUrl|fileUrl|downloadUrl)\s*[,\)]',

            # Template literal with any variable interpolation
            r'fetch\s*\(\s*`[^`]*\$\{(?!process\.env)[^}]+\}',

    # =====================================================================
            # AXIOS
    # =====================================================================
            r'axios\.(get|post|put|delete|patch|head|options|request)\s*\(\s*req\.',
            r'axios\.(get|post|put|delete|patch|head|options|request)\s*\(\s*`[^`]*\$\{(?!process\.env)',
            r'axios\.(get|post|put|delete|patch|head|options|request)\s*\(\s*["\'].*\+',
            r'axios\s*\(\s*\{[^}]*url\s*:\s*req\.',
            r'axios\s*\(\s*\{[^}]*url\s*:\s*`[^`]*\$\{',

            # Axios with variable URL
            r'axios\.(get|post|put|delete|patch|head|options|request)\s*\(\s*'
            r'(url|uri|target|endpoint|href|link|dest|userUrl|targetUrl|apiUrl|'
            r'externalUrl|remoteUrl|fetchUrl)\s*[,\)]',
            r'axios\s*\(\s*\{[^}]*url\s*:\s*(?![\'"`))[a-zA-Z_]\w*\s*[,\}]',

    # =====================================================================
            # NATIVE HTTP/HTTPS MODULES
    # =====================================================================
            r'https?\.get\s*\(\s*req\.(body|query|params)',
            r'https?\.get\s*\(\s*`[^`]*\$\{',
            r'https?\.get\s*\(\s*["\'].*\+',
            r'https?\.request\s*\(\s*req\.',
            r'https?\.request\s*\(\s*\{[^}]*hostname?\s*:\s*req\.',
            r'https?\.request\s*\(\s*\{[^}]*host\s*:\s*req\.',
            r'https?\.request\s*\(\s*\{[^}]*path\s*:\s*req\.',

            # Variable-based
            r'https?\.get\s*\(\s*(url|uri|target|endpoint|userUrl|targetUrl)\s*[,\)]',
            r'https?\.request\s*\(\s*\{[^}]*hostname?\s*:\s*(?![\'"localhost])[a-zA-Z_]\w*\s*[,\}]',

    # =====================================================================
            # GOT, NODE-FETCH, SUPERAGENT, NEEDLE, REQUEST
    # =====================================================================
            r'got\s*\(\s*req\.(body|query|params)',
            r'got\s*\(\s*`[^`]*\$\{',
            r'got\.(get|post|put|delete|patch)\s*\(\s*req\.',
            r'got\s*\(\s*(url|uri|target|endpoint|userUrl|targetUrl|fetchUrl)\s*[,\)]',

            r'needle\s*\(\s*["\']get["\'],\s*req\.',
            r'needle\.(get|post|put|delete|patch)\s*\(\s*req\.',
            r'needle\s*\(\s*["\'](?:get|post)["\'],\s*(url|target|endpoint)\s*[,\)]',

            r'superagent\.(get|post|put|delete|patch)\s*\(\s*req\.',
            r'superagent\.(get|post|put|delete|patch)\s*\(\s*(url|target|endpoint)\s*\)',

            r'request\s*\(\s*req\.(body|query|params)',
            r'request\s*\(\s*\{[^}]*url\s*:\s*req\.',
            r'request\s*\(\s*(url|uri|target|endpoint|userUrl)\s*[,\)]',
            r'request\s*\(\s*\{[^}]*url\s*:\s*(?![\'"https?://])[a-zA-Z_]\w*\s*[,\}]',

    # =====================================================================
            # URL CONSTRUCTOR WITH USER INPUT
    # =====================================================================
            r'new\s+URL\s*\(\s*req\.(body|query|params)',
            r'new\s+URL\s*\(\s*`[^`]*\$\{[^}]*req\.',
            r'new\s+URL\s*\(\s*(userUrl|targetUrl|inputUrl|urlParam|urlInput)\s*[,\)]',

    # =====================================================================
            # PUPPETEER/PLAYWRIGHT (HEADLESS BROWSER SSRF)
    # =====================================================================
            r'page\.goto\s*\(\s*req\.',
            r'page\.goto\s*\(\s*`[^`]*\$\{',
            r'page\.goto\s*\(\s*(url|uri|target|userUrl|targetUrl)\s*[,\)]',
            r'page\.navigate\s*\(\s*req\.',
            r'browser\.newPage.*goto\s*\(\s*req\.',

    # =====================================================================
            # GENERIC VARIABLE PATTERNS (catches function params likely from user)
    # =====================================================================
            # Function receiving URL parameter and using it
            r'(?:async\s+)?function\s+\w+\s*\(\s*(?:[^)]*,\s*)?(url|uri|target|endpoint)\s*[,\)]'
            r'[^}]*(?:fetch|axios|got|request|https?\.get)\s*\(\s*\1',
        ],
        severity=Severity.HIGH,
        languages=[".js", ".ts", ".jsx", ".tsx", ".mjs"],
        false_positive_patterns=[
            r'https?://localhost',
            r'https?://127\.0\.0\.1',
            r'https?://0\.0\.0\.0',
            r'https?://\[::1\]',
            r'isValidUrl\s*\(',
            r'validateUrl\s*\(',
            r'isSafeUrl\s*\(',
            r'isAllowedUrl\s*\(',
            r'checkUrl\s*\(',
            r'sanitizeUrl\s*\(',
            r'isSafeUrl\s*\(',
            r'allowedHosts',
            r'allowedDomains',
            r'whitelist',
            r'allowlist',
            r'ALLOWED_HOSTS',
            r'process\.env\.',                    # Environment variables are typically safe
            r'config\.\w+[Uu]rl',                 # Config URLs are typically safe
            r'URL\.canParse\s*\(',                # URL validation
            r'new\s+URL\s*\([^)]+\)\.hostname',   # Extracting hostname for validation
            # Test/mock context
            r'_test\.',
            r'\.test\.',
            r'test_',
            r'\.spec\.',
            r'mock',
            r'fixture',
            r'__tests__',
            # Configuration constants
            r'const\s+\w+URL\s*=',
            r'const\s+API_',
            r'const\s+BASE_URL',
            r'const\s+SERVICE_URL',
            # Safe URL patterns
            r'\.parse\s*\([^)]+\)\.host',
            r'\.hostname\s*===',
            r'\.origin\s*===',
            r'startsWith\s*\(["\']https?://',
            r'\.includes\s*\(["\']allowed',
        ],
    ),

    VulnerabilityPattern(
        name="SSRF - Dynamic URL Fetch (Python)",
        category=VulnCategory.SSRF,
        patterns=[
    # =====================================================================
            # REQUESTS LIBRARY (THIS IS WHAT YOU WERE MISSING!)
    # =====================================================================
            # Direct request object usage (Flask/Django)
            r'requests\.(get|post|put|delete|patch|head|options)\s*\(\s*request\.(form|args|json|data|values|GET|POST)',
            r'requests\.(get|post|put|delete|patch|head|options)\s*\(\s*f["\']',
            r'requests\.(get|post|put|delete|patch|head|options)\s*\(\s*["\'].*\+',
            r'requests\.(get|post|put|delete|patch|head|options)\s*\(\s*["\'].*\.format\s*\(',
            r'requests\.(get|post|put|delete|patch|head|options)\s*\(\s*["\'].*%\s*',

            # CRITICAL: Variable-based patterns (catches `requests.get(target)`)
            r'requests\.(get|post|put|delete|patch|head|options|request)\s*\(\s*'
            r'(url|uri|target|endpoint|href|link|dest|destination|'
            r'user_url|target_url|redirect_url|callback_url|image_url|fetch_url|api_url|'
            r'external_url|remote_url|resource_url|file_url|download_url|'
            r'url_param|url_input|input_url|param_url)\s*[,\)]',

            # Generic variable (non-string literal) - higher FP rate but catches more
            r'requests\.(get|post|put|delete|patch|head|options)\s*\(\s*(?!["\'\(f])([a-z_][a-z0-9_]*)\s*[,\)]',

    # =====================================================================
            # URLLIB
    # =====================================================================
            r'urllib\.request\.urlopen\s*\(\s*request\.',
            r'urllib\.request\.urlopen\s*\(\s*f["\']',
            r'urllib\.request\.urlopen\s*\(\s*["\'].*\+',
            r'urllib\.request\.urlopen\s*\(\s*["\'].*\.format\s*\(',
            r'urlopen\s*\(\s*request\.',
            r'urllib\.request\.Request\s*\(\s*request\.',

            # Variable-based
            r'urllib\.request\.urlopen\s*\(\s*(url|uri|target|endpoint|user_url|target_url)\s*[,\)]',
            r'urlopen\s*\(\s*(url|uri|target|endpoint|user_url|target_url)\s*[,\)]',
            r'urllib\.request\.Request\s*\(\s*(url|uri|target|endpoint)\s*[,\)]',

    # =====================================================================
            # HTTPX (ASYNC)
    # =====================================================================
            r'httpx\.(get|post|put|delete|patch|head|options)\s*\(\s*request\.',
            r'httpx\.AsyncClient\s*\(\s*\)\.get\s*\(\s*request\.',
            r'await\s+httpx\.(get|post|put|delete|patch)\s*\(\s*f["\']',
            r'client\.(get|post|put|delete)\s*\(\s*request\.(form|args|json)',

            # Variable-based
            r'httpx\.(get|post|put|delete|patch|head|options)\s*\(\s*(url|uri|target|endpoint|user_url)\s*[,\)]',
            r'await\s+(?:client|httpx)\.(get|post|put|delete)\s*\(\s*(url|target|endpoint)\s*[,\)]',

    # =====================================================================
            # AIOHTTP (ASYNC)
    # =====================================================================
            r'session\.(get|post|put|delete|patch)\s*\(\s*request\.',
            r'aiohttp\.ClientSession\s*\(\s*\)\.get\s*\(\s*request\.',
            r'await\s+session\.(get|post)\s*\(\s*f["\']',

            # Variable-based
            r'session\.(get|post|put|delete|patch)\s*\(\s*(url|uri|target|endpoint|user_url)\s*[,\)]',
            r'await\s+session\.(get|post|put|delete)\s*\(\s*(url|target|endpoint)\s*[,\)]',

    # =====================================================================
            # HTTP.CLIENT
    # =====================================================================
            r'http\.client\.HTTPConnection\s*\(\s*request\.',
            r'HTTPConnection\s*\(\s*request\.',
            r'HTTPSConnection\s*\(\s*request\.',
            r'HTTPConnection\s*\(\s*(host|target|endpoint|user_host)\s*[,\)]',
            r'HTTPSConnection\s*\(\s*(host|target|endpoint|user_host)\s*[,\)]',

    # =====================================================================
            # PYCURL
    # =====================================================================
            r'pycurl.*CURLOPT_URL.*request\.',
            r'curl\.setopt\s*\(.*URL.*request\.',
            r'curl\.setopt\s*\([^,]+,\s*pycurl\.URL\s*,\s*(url|target|endpoint)\s*\)',

    # =====================================================================
            # SOCKET-LEVEL (low-level SSRF)
    # =====================================================================
            r'socket\.create_connection\s*\(\s*\(\s*(host|target|endpoint|user_host)',
            r'socket\.connect\s*\(\s*\(\s*request\.',

    # =====================================================================
            # GENERIC VARIABLE ASSIGNMENT PATTERNS
    # =====================================================================
            # Catches: url = request.args.get('url'); ... requests.get(url)
            # This is a simplified pattern - full taint tracking needs dataflow analysis
            r'(?:url|target|endpoint)\s*=\s*request\.(args|form|json|data|GET|POST)',
        ],
        severity=Severity.HIGH,
        languages=[".py"],
        false_positive_patterns=[
            r'validate_url\s*\(',
            r'is_safe_url\s*\(',
            r'is_valid_url\s*\(',
            r'check_url\s*\(',
            r'sanitize_url\s*\(',
            r'ALLOWED_HOSTS',
            r'ALLOWED_DOMAINS',
            r'urlparse\s*\([^)]+\)\.netloc\s+in\s+',
            r'urlparse\s*\([^)]+\)\.scheme\s+in\s+\[',
            r'\.netloc\s*==',
            r'\.hostname\s*in\s+',
            r'settings\.\w+URL',                    # Django settings
            r'os\.environ\.get\s*\(["\'].*URL',     # Environment variables
            r'config\.\w+[Uu]rl',                   # Config URLs
            r'localhost',
            r'127\.0\.0\.1',
            r'0\.0\.0\.0',
        ],
    ),

    VulnerabilityPattern(
        name="SSRF - Dynamic URL Fetch (PHP)",
        category=VulnCategory.SSRF,
        patterns=[
    # =====================================================================
            # FILE_GET_CONTENTS
    # =====================================================================
            r'file_get_contents\s*\(\s*\$_(GET|POST|REQUEST|COOKIE)',
            r'file_get_contents\s*\(\s*\$[a-zA-Z_]\w*\s*\)',
            r'file_get_contents\s*\(\s*["\'].*\.\s*\$',
            r'file_get_contents\s*\(\s*".*\$\{',

            # Variable-based
            r'file_get_contents\s*\(\s*\$(url|uri|target|endpoint|href|link|'
            r'userUrl|targetUrl|fetchUrl|remoteUrl|fileUrl)\s*\)',

    # =====================================================================
            # CURL
    # =====================================================================
            r'curl_setopt\s*\([^,]+,\s*CURLOPT_URL\s*,\s*\$_(GET|POST|REQUEST)',
            r'curl_setopt\s*\([^,]+,\s*CURLOPT_URL\s*,\s*\$',
            r'curl_init\s*\(\s*\$_(GET|POST|REQUEST)',
            r'curl_init\s*\(\s*\$[a-zA-Z_]\w*\s*\)',
            r'curl_setopt_array\s*\([^,]+,\s*\[[^\]]*CURLOPT_URL\s*=>\s*\$',

            # Variable-based
            r'curl_init\s*\(\s*\$(url|uri|target|endpoint|href|userUrl|targetUrl)\s*\)',
            r'curl_setopt\s*\([^,]+,\s*CURLOPT_URL\s*,\s*\$(url|target|endpoint)\s*\)',

    # =====================================================================
            # FOPEN WITH URL WRAPPERS
    # =====================================================================
            r'fopen\s*\(\s*\$_(GET|POST|REQUEST)',
            r'fopen\s*\(\s*["\']https?://.*\.\s*\$',
            r'fopen\s*\(\s*\$(url|uri|target|endpoint|href)\s*,',

    # =====================================================================
            # GUZZLE
    # =====================================================================
            r'->request\s*\(\s*["\']GET["\'],\s*\$',
            r'->get\s*\(\s*\$_(GET|POST|REQUEST)',
            r'new\s+Client.*->get\s*\(\s*\$',
            r'->get\s*\(\s*\$(url|uri|target|endpoint|userUrl)\s*[,\)]',
            r'->post\s*\(\s*\$(url|uri|target|endpoint)\s*[,\)]',
            r'->request\s*\(\s*["\'](?:GET|POST)["\'],\s*\$(url|target|endpoint)\s*[,\)]',

    # =====================================================================
            # COPY/READFILE WITH URL
    # =====================================================================
            r'copy\s*\(\s*\$_(GET|POST|REQUEST)',
            r'copy\s*\(\s*["\']https?://.*\.\s*\$',
            r'copy\s*\(\s*\$(url|uri|target|source|remoteUrl)\s*,',

            r'readfile\s*\(\s*\$_(GET|POST|REQUEST)',
            r'readfile\s*\(\s*\$(url|uri|target|fileUrl|remoteUrl)\s*\)',

    # =====================================================================
            # SIMPLEXML / DOM
    # =====================================================================
            r'simplexml_load_file\s*\(\s*\$_(GET|POST|REQUEST)',
            r'simplexml_load_file\s*\(\s*\$(url|uri|target|xmlUrl)\s*\)',
            r'DOMDocument.*->load\s*\(\s*\$',
        ],
        severity=Severity.HIGH,
        languages=[".php"],
        false_positive_patterns=[
            r'filter_var\s*\([^,]+,\s*FILTER_VALIDATE_URL',
            r'parse_url\s*\([^)]+\)\s*\[["\']host["\']\]\s*===',
            r'in_array\s*\(\s*parse_url',
            r'preg_match\s*\([^,]+allowed',
            r'ALLOWED_HOSTS',
            r'whitelist',
            r'allowlist',
        ],
    ),

    VulnerabilityPattern(
        name="SSRF - Dynamic URL Fetch (Java)",
        category=VulnCategory.SSRF,
        patterns=[
    # =====================================================================
            # URL/HTTPURLCONNECTION
    # =====================================================================
            r'new\s+URL\s*\(\s*request\.getParameter',
            r'new\s+URL\s*\(\s*.*\+.*request\.get',
            r'URL\s*\(\s*.*\+.*getParameter',
            r'openConnection\s*\(\s*\).*getParameter',

            # Variable-based
            r'new\s+URL\s*\(\s*(url|uri|target|endpoint|userUrl|targetUrl|inputUrl)\s*\)',
            r'new\s+URL\s*\(\s*[a-zA-Z_]\w*\s*\)\.openConnection',

    # =====================================================================
            # HTTPCLIENT (JAVA 11+)
    # =====================================================================
            r'HttpClient.*send\s*\(.*request\.getParameter',
            r'HttpRequest\.newBuilder\s*\(\s*\)\.uri\s*\(.*request\.get',
            r'HttpRequest\.newBuilder\s*\(\s*\)\.uri\s*\(\s*URI\.create\s*\(\s*(url|target|endpoint)',

    # =====================================================================
            # APACHE HTTPCLIENT
    # =====================================================================
            r'HttpGet\s*\(\s*request\.getParameter',
            r'HttpPost\s*\(\s*request\.getParameter',
            r'new\s+HttpGet\s*\(\s*.*\+',
            r'new\s+HttpPost\s*\(\s*.*\+',

            # Variable-based
            r'new\s+HttpGet\s*\(\s*(url|uri|target|endpoint|userUrl|targetUrl)\s*\)',
            r'new\s+HttpPost\s*\(\s*(url|uri|target|endpoint|userUrl)\s*\)',
            r'new\s+HttpPut\s*\(\s*(url|uri|target|endpoint)\s*\)',
            r'new\s+HttpDelete\s*\(\s*(url|uri|target|endpoint)\s*\)',

    # =====================================================================
            # OKHTTP
    # =====================================================================
            r'Request\.Builder\s*\(\s*\)\.url\s*\(.*request\.get',
            r'new\s+Request\.Builder\s*\(\s*\)\.url\s*\(\s*.*\+',
            r'new\s+Request\.Builder\s*\(\s*\)\.url\s*\(\s*(url|target|endpoint|userUrl)\s*\)',

    # =====================================================================
            # RESTTEMPLATE (SPRING)
    # =====================================================================
            r'restTemplate\.(getForObject|getForEntity|postForObject|postForEntity|exchange)\s*\(\s*.*request\.get',
            r'RestTemplate.*\.(get|post).*\(\s*.*\+',
            r'restTemplate\.(getForObject|getForEntity|postForObject|exchange)\s*\(\s*(url|uri|target|endpoint)\s*,',

    # =====================================================================
            # WEBCLIENT (SPRING WEBFLUX)
    # =====================================================================
            r'webClient\.(get|post|put|delete)\s*\(\s*\)\.uri\s*\(.*request\.get',
            r'webClient\.(get|post|put|delete)\s*\(\s*\)\.uri\s*\(\s*(url|uri|target|endpoint)\s*\)',
            r'WebClient\.create\s*\(\s*(url|target|endpoint|userUrl)\s*\)',

    # =====================================================================
            # JSOUP (HTML PARSING WITH FETCH)
    # =====================================================================
            r'Jsoup\.connect\s*\(\s*request\.getParameter',
            r'Jsoup\.connect\s*\(\s*(url|uri|target|endpoint|userUrl)\s*\)',
            r'Jsoup\.connect\s*\(\s*.*\+',
        ],
        severity=Severity.HIGH,
        languages=[".java", ".kt", ".scala"],
        false_positive_patterns=[
            r'UriComponentsBuilder.*whitelist',
            r'isAllowedHost\s*\(',
            r'validateUrl\s*\(',
            r'isValidUrl\s*\(',
            r'ALLOWED_HOSTS',
            r'allowedHosts\.contains',
            r'\.getHost\s*\(\s*\)\.equals',
        ],
    ),

    VulnerabilityPattern(
        name="SSRF - Dynamic URL Fetch (C#)",
        category=VulnCategory.SSRF,
        patterns=[
    # =====================================================================
            # HTTPCLIENT
    # =====================================================================
            r'HttpClient.*Get\w*Async\s*\(\s*.*Request\.(Query|Form|Body)',
            r'HttpClient.*Get\w*Async\s*\(\s*\$"',
            r'HttpClient.*Get\w*Async\s*\(\s*["\'].*\+',
            r'HttpClient.*Post\w*Async\s*\(\s*.*Request\.',
            r'HttpClient.*Send\w*Async\s*\(\s*.*Request\.',
            r'new\s+HttpClient\s*\(\s*\).*Get.*\(\s*.*\+',

            # Variable-based
            r'HttpClient.*Get\w*Async\s*\(\s*(url|uri|target|endpoint|userUrl|targetUrl)\s*[,\)]',
            r'HttpClient.*Post\w*Async\s*\(\s*(url|uri|target|endpoint)\s*,',
            r'\.GetAsync\s*\(\s*(url|uri|target|endpoint|userUrl)\s*\)',
            r'\.PostAsync\s*\(\s*(url|uri|target|endpoint)\s*,',

    # =====================================================================
            # WEBCLIENT (LEGACY)
    # =====================================================================
            r'WebClient.*Download\w*\s*\(\s*.*Request\.',
            r'WebClient.*Download\w*\s*\(\s*\$"',
            r'WebClient.*Upload\w*\s*\(\s*.*Request\.',
            r'new\s+WebClient\s*\(\s*\)\.Download.*\(\s*.*\+',

            # Variable-based
            r'WebClient.*Download\w*\s*\(\s*(url|uri|target|endpoint|userUrl)\s*[,\)]',
            r'\.DownloadString\s*\(\s*(url|uri|target|endpoint)\s*\)',
            r'\.DownloadData\s*\(\s*(url|uri|target|endpoint)\s*\)',

    # =====================================================================
            # WEBREQUEST
    # =====================================================================
            r'WebRequest\.Create\s*\(\s*.*Request\.',
            r'WebRequest\.Create\s*\(\s*\$"',
            r'HttpWebRequest.*Create\s*\(\s*.*Request\.',

            # Variable-based
            r'WebRequest\.Create\s*\(\s*(url|uri|target|endpoint|userUrl)\s*\)',
            r'HttpWebRequest\.Create\s*\(\s*(url|uri|target|endpoint)\s*\)',

    # =====================================================================
            # URI CONSTRUCTION
    # =====================================================================
            r'new\s+Uri\s*\(\s*.*Request\.(Query|Form)',
            r'new\s+Uri\s*\(\s*\$".*\{.*Request\.',
            r'new\s+Uri\s*\(\s*(url|uri|target|endpoint|userUrl|inputUrl)\s*\)',

    # =====================================================================
            # RESTSHARP
    # =====================================================================
            r'RestClient\s*\(\s*.*Request\.',
            r'new\s+RestClient\s*\(\s*\$"',
            r'new\s+RestRequest\s*\(\s*.*Request\.',
            r'new\s+RestClient\s*\(\s*(url|uri|target|endpoint|baseUrl|userUrl)\s*\)',
            r'new\s+RestRequest\s*\(\s*(url|uri|target|endpoint)\s*[,\)]',

    # =====================================================================
            # FLURL
    # =====================================================================
            r'\.GetAsync\s*\(\s*\$"',
            r'\.PostAsync\s*\(\s*\$"',
            r'Url\s*=\s*\$".*\{.*Request\.',
        ],
        severity=Severity.HIGH,
        languages=[".cs", ".vb"],
        false_positive_patterns=[
            r'IsValidUri\s*\(',
            r'IsWellFormedUri\s*\(',
            r'ValidateUrl\s*\(',
            r'AllowedHosts',
            r'AllowedDomains',
            r'Uri\.IsWellFormedUriString',
            r'\.Host\s*==',
            r'Configuration\[.*Url\]',           # Configuration URLs
            r'Environment\.GetEnvironmentVariable.*[Uu]rl',  # Environment variables
        ],
    ),

    # =========================================================================
    # NEW: Generic SSRF Pattern for Variable-Based Taint (All Languages)
    # =========================================================================
    VulnerabilityPattern(
        name="SSRF - Suspicious URL Variable Usage",
        category=VulnCategory.SSRF,
        patterns=[
            # Generic pattern: function_that_fetches(url_variable)
            # This catches cases where variable names suggest user-controlled URLs

            # Python: any HTTP function with suspicious variable
            r'(?:requests|urllib|httpx|aiohttp|http\.client)\.\w+\s*\(\s*'
            r'(?:user_)?(?:url|uri|target|endpoint|link|href|callback|redirect|fetch|remote|external)(?:_url|_uri|_param|_input)?\s*[,\)]',

            # JavaScript: fetch/axios/got with suspicious variable
            r'(?:fetch|axios|got|request|superagent|needle)\s*(?:\.\w+\s*)?\(\s*'
            r'(?:user)?(?:Url|Uri|Target|Endpoint|Link|Href|Callback|Redirect|Fetch|Remote|External)(?:Url|Uri|Param|Input)?\s*[,\)]',

            # Assignment patterns that indicate taint flow
            r'(?:url|uri|target|endpoint)\s*=\s*(?:req|request)\.',
            r'(?:url|uri|target|endpoint)\s*=\s*(?:params|query|body|form|args|data)\[',
            r'(?:url|uri|target|endpoint)\s*=\s*(?:params|query|body|form|args|data)\.get\s*\(',
        ],
        severity=Severity.MEDIUM,  # Lower severity as this has higher FP rate
        languages=[".py", ".js", ".ts", ".jsx", ".tsx", ".php", ".java", ".cs", ".rb", ".go"],
        false_positive_patterns=[
            r'validate',
            r'sanitize',
            r'check.*url',
            r'allowed',
            r'whitelist',
            r'allowlist',
            r'localhost',
            r'127\.0\.0\.1',
            r'\.env',
            r'config\.',
            r'settings\.',
        ],
    ),

    # =========================================================================
    # INSECURE DESERIALIZATION - SnakeYAML (Java)
    # =========================================================================
    VulnerabilityPattern(
        name="Insecure Deserialization - SnakeYAML (Java)",
        category=VulnCategory.DESERIALIZATION,
        patterns=[
            # Basic SnakeYAML instantiation without SafeConstructor
            r'new\s+Yaml\s*\(\s*\)',
            r'Yaml\s+\w+\s*=\s*new\s+Yaml\s*\(\s*\)',

            # Yaml.load() with untrusted input - CRITICAL
            r'yaml\.load\s*\(\s*\w+\s*\)',
            r'\.load\s*\(\s*request\.get',
            r'\.load\s*\(\s*.*getParameter',
            r'\.load\s*\(\s*.*getInputStream',
            r'\.load\s*\(\s*.*InputStream',
            r'\.load\s*\(\s*new\s+StringReader',
            r'\.load\s*\(\s*new\s+FileReader',
            r'\.load\s*\(\s*new\s+InputStreamReader',

            # Yaml.loadAll() - iterative loading
            r'yaml\.loadAll\s*\(',
            r'\.loadAll\s*\(\s*request\.get',
            r'\.loadAll\s*\(\s*.*getParameter',

            # Yaml.loadAs() - typed loading still vulnerable
            r'yaml\.loadAs\s*\(',
            r'\.loadAs\s*\(\s*request\.get',
            r'\.loadAs\s*\(\s*.*getParameter',

            # SnakeYAML with custom Constructor (potentially unsafe)
            r'new\s+Yaml\s*\(\s*new\s+Constructor\s*\(\s*\)',
            r'new\s+Yaml\s*\(\s*new\s+Constructor\s*\([^S]',  # Not SafeConstructor

            # Yaml with custom Representer (may indicate complex config)
            r'new\s+Yaml\s*\(\s*new\s+Representer',

            # Yaml.parse() - returns events, still processes untrusted YAML
            r'yaml\.parse\s*\(\s*request\.get',
            r'yaml\.parse\s*\(\s*.*getParameter',

            # DumperOptions with unsafe settings
            r'DumperOptions.*setAllowReadOnlyProperties\s*\(\s*true',

            # Yaml compose methods
            r'yaml\.compose\s*\(\s*request\.get',
            r'yaml\.composeAll\s*\(\s*request\.get',

            # org.yaml.snakeyaml imports indicate usage
            r'import\s+org\.yaml\.snakeyaml\.Yaml\s*;',
            r'import\s+org\.yaml\.snakeyaml\.\*\s*;',

            # Spring YAML with user input
            r'YamlPropertiesFactoryBean.*setResources.*getParameter',
            r'YamlMapFactoryBean.*setResources.*getParameter',
        ],
        severity=Severity.CRITICAL,
        languages=[".java", ".kt", ".scala", ".groovy"],
        false_positive_patterns=[
            r'new\s+Yaml\s*\(\s*new\s+SafeConstructor',
            r'SafeConstructor',
            r'new\s+Constructor\s*\(\s*\w+\.class\s*\)',  # Type-restricted constructor
            r'yaml\.dump',  # Serializing, not deserializing
            r'//.*yaml\.load',  # Commented out
            r'/\*.*yaml\.load',  # Block comment
        ],
    ),

    # =========================================================================
    # SSTI - FreeMarker (Java) - Comprehensive
    # =========================================================================
    VulnerabilityPattern(
        name="SSTI - FreeMarker Template Injection (Java)",
        category=VulnCategory.SSTI,
        patterns=[
            # Template creation with user-controlled content - CRITICAL
            r'new\s+Template\s*\(\s*[^,]*,\s*new\s+StringReader\s*\(\s*\w+\s*\)',
            r'new\s+Template\s*\(\s*[^,]*,\s*new\s+StringReader\s*\(\s*.*\+',
            r'new\s+Template\s*\(\s*[^,]*,\s*new\s+StringReader\s*\(\s*.*request',
            r'new\s+Template\s*\(\s*[^,]*,\s*new\s+StringReader\s*\(\s*.*getParameter',
            r'new\s+Template\s*\(\s*"[^"]*"\s*,\s*\w+\s*,',  # Variable as template content

            # Configuration.getTemplate with user input
            r'Configuration.*getTemplate\s*\(\s*.*\+',
            r'Configuration.*getTemplate\s*\(\s*.*request\.get',
            r'Configuration.*getTemplate\s*\(\s*.*getParameter',
            r'cfg\.getTemplate\s*\(\s*.*\+',
            r'cfg\.getTemplate\s*\(\s*.*request\.get',

            # Template.process with tainted context
            r'template\.process\s*\(\s*.*request\.get',
            r'template\.process\s*\(\s*.*getParameter',
            r'\.process\s*\(\s*model\s*,',  # Generic process with model

            # Environment manipulation
            r'Environment\.setVariable.*getParameter',
            r'Environment\.setVariable.*request\.get',
            r'env\.setVariable\s*\(\s*.*request\.get',

            # SharedVariable with user input
            r'setSharedVariable\s*\(\s*.*request\.get',
            r'setSharedVariable\s*\(\s*.*getParameter',
            r'cfg\.setSharedVariable\s*\(\s*[^,]+,\s*.*\+',

            # Freemarker imports
            r'import\s+freemarker\.template\.Template\s*;',
            r'import\s+freemarker\.template\.\*\s*;',

            # FreeMarker dangerous builtins (in template content)
            r'\$\{[^}]*\?new\s*\(',  # ?new() builtin - RCE
            r'\$\{[^}]*\?api\s*[.\(]',  # ?api builtin - access Java API
            r'<#assign\s+\w+\s*=\s*"freemarker\.template\.utility\.Execute"',  # Execute class
            r'<#assign\s+\w+\s*=\s*"freemarker\.template\.utility\.ObjectConstructor"',
            r'\.getClassLoader\s*\(\s*\)',  # ClassLoader access in template
            r'\.getClass\s*\(\s*\)\.forName',  # Reflection in template

            # TemplateLoader with user paths
            r'FileTemplateLoader\s*\(\s*.*request\.get',
            r'FileTemplateLoader\s*\(\s*.*getParameter',
            r'StringTemplateLoader.*putTemplate\s*\(\s*.*request\.get',

            # Unsafe Configuration settings
            r'setNewBuiltinClassResolver\s*\(\s*TemplateClassResolver\.UNRESTRICTED',
            r'setAPIBuiltinEnabled\s*\(\s*true',
            r'Configuration\.UNRESTRICTED_RESOLVER',

            # Spring FreeMarker
            r'FreeMarkerConfigurer.*setTemplateLoaderPath.*getParameter',
            r'FreeMarkerTemplateUtils\.processTemplateIntoString\s*\(\s*.*request',
        ],
        severity=Severity.CRITICAL,
        languages=[".java", ".kt", ".groovy", ".ftl", ".ftlh"],
        false_positive_patterns=[
            r'setNewBuiltinClassResolver\s*\(\s*TemplateClassResolver\.SAFER',
            r'setNewBuiltinClassResolver\s*\(\s*TemplateClassResolver\.ALLOWS_NOTHING',
            r'setAPIBuiltinEnabled\s*\(\s*false',
            r'HtmlUtils\.htmlEscape',
            r'StringEscapeUtils\.escapeHtml',
            r'\.getTemplate\s*\(\s*["\'][^"\']+\.ftl',  # Static template name
            r'//.*Template',  # Commented
        ],
    ),

    # =========================================================================
    # SSTI - Velocity Template Injection (Java) - Comprehensive
    # =========================================================================
    VulnerabilityPattern(
        name="SSTI - Velocity Template Injection (Java)",
        category=VulnCategory.SSTI,
        patterns=[
            # Velocity.evaluate with user input - CRITICAL
            r'Velocity\.evaluate\s*\(\s*[^,]+,\s*[^,]+,\s*[^,]+,\s*\w+\s*\)',
            r'Velocity\.evaluate\s*\(\s*[^,]+,\s*[^,]+,\s*[^,]+,\s*.*\+',
            r'Velocity\.evaluate\s*\(\s*[^,]+,\s*[^,]+,\s*[^,]+,\s*.*request',
            r'Velocity\.evaluate\s*\(\s*[^,]+,\s*[^,]+,\s*[^,]+,\s*.*getParameter',
            r'Velocity\.evaluate\s*\(\s*context\s*,\s*writer\s*,\s*[^,]+,\s*\w+',

            # VelocityEngine.evaluate
            r'VelocityEngine.*\.evaluate\s*\(\s*[^,]+,\s*[^,]+,\s*[^,]+,\s*.*request',
            r'VelocityEngine.*\.evaluate\s*\(\s*[^,]+,\s*[^,]+,\s*[^,]+,\s*.*getParameter',
            r'velocityEngine\.evaluate\s*\(\s*[^,]+,\s*[^,]+,\s*[^,]+,\s*\w+\s*\)',
            r've\.evaluate\s*\(\s*[^,]+,\s*[^,]+,\s*[^,]+,\s*\w+\s*\)',

            # RuntimeInstance.evaluate
            r'RuntimeInstance.*\.evaluate\s*\(',
            r'ri\.evaluate\s*\(\s*.*request',

            # Template.merge with tainted context
            r'template\.merge\s*\(\s*.*getParameter',
            r'template\.merge\s*\(\s*context\s*,',  # Merge with context
            r'\.merge\s*\(\s*velocityContext',

            # VelocityContext.put with user input
            r'VelocityContext.*\.put\s*\(\s*[^,]+,\s*.*request\.get',
            r'VelocityContext.*\.put\s*\(\s*[^,]+,\s*.*getParameter',
            r'context\.put\s*\(\s*[^,]+,\s*.*request\.get',
            r'ctx\.put\s*\(\s*[^,]+,\s*.*getParameter',

            # Velocity getTemplate with user input
            r'Velocity\.getTemplate\s*\(\s*.*\+',
            r'Velocity\.getTemplate\s*\(\s*.*request\.get',
            r'velocityEngine\.getTemplate\s*\(\s*.*getParameter',

            # mergeTemplate with user path
            r'Velocity\.mergeTemplate\s*\(\s*.*request\.get',
            r'\.mergeTemplate\s*\(\s*.*getParameter',

            # Velocity imports
            r'import\s+org\.apache\.velocity\.VelocityContext\s*;',
            r'import\s+org\.apache\.velocity\.\*\s*;',
            r'import\s+org\.apache\.velocity\.app\.Velocity\s*;',

            # Dangerous Velocity directives in templates
            r'#set\s*\(\s*\$\w+\s*=\s*.*\.getClass\s*\(\s*\)',  # Reflection
            r'#set\s*\(\s*\$\w+\s*=\s*.*\.forName\s*\(',  # Class loading
            r'#set\s*\(\s*\$\w+\s*=\s*.*Runtime\.getRuntime',  # Runtime access
            r'#set\s*\(\s*\$\w+\s*=\s*.*\.exec\s*\(',  # Command execution
            r'\$class\.forName\s*\(',  # ClassTool abuse
            r'\$\w+\.getClass\s*\(\s*\)\.forName',  # Reflection chain

            # StringResourceLoader with user content
            r'StringResourceLoader.*putStringResource\s*\(\s*[^,]+,\s*.*request',
            r'StringResourceRepository.*putStringResource\s*\(\s*[^,]+,\s*.*getParameter',

            # ResourceLoader configuration
            r'setProperty\s*\(\s*["\']resource\.loader["\'].*request',
            r'setProperty\s*\(\s*RuntimeConstants\.RESOURCE_LOADER.*getParameter',

            # Spring Velocity
            r'VelocityEngineUtils\.mergeTemplateIntoString\s*\(\s*[^,]+,\s*.*request',
            r'VelocityConfigurer.*setResourceLoaderPath.*getParameter',
        ],
        severity=Severity.CRITICAL,
        languages=[".java", ".kt", ".groovy", ".vm", ".vsl"],
        false_positive_patterns=[
            r'\.getTemplate\s*\(\s*["\'][^"\']+\.vm',  # Static template
            r'uberspect\.introspect',  # Introspection check
            r'SecureUberspector',  # Security uberspector
            r'//.*Velocity\.evaluate',  # Commented
            r'/\*.*Velocity\.evaluate',  # Block comment
        ],
    ),

    # =========================================================================
    # XXE - XML External Entity Injection (Java) - Comprehensive
    # =========================================================================
    VulnerabilityPattern(
        name="XXE - DocumentBuilderFactory (Java)",
        category=VulnCategory.XXE,
        patterns=[
            # DocumentBuilderFactory without secure configuration
            r'DocumentBuilderFactory\.newInstance\s*\(\s*\)',
            r'DocumentBuilderFactory\s+\w+\s*=\s*DocumentBuilderFactory\.newInstance',

            # DocumentBuilder.parse with untrusted input
            r'documentBuilder\.parse\s*\(\s*new\s+InputSource',
            r'documentBuilder\.parse\s*\(\s*.*getInputStream',
            r'documentBuilder\.parse\s*\(\s*.*request\.get',
            r'builder\.parse\s*\(\s*new\s+StringReader',
            r'builder\.parse\s*\(\s*new\s+ByteArrayInputStream',
            r'\.parse\s*\(\s*new\s+InputSource\s*\(\s*new\s+StringReader',

            # factory.newDocumentBuilder without setFeature
            r'factory\.newDocumentBuilder\s*\(\s*\)',
            r'dbf\.newDocumentBuilder\s*\(\s*\)',
        ],
        severity=Severity.HIGH,
        languages=[".java", ".kt", ".scala", ".groovy"],
        false_positive_patterns=[
            r'setFeature\s*\(\s*["\']http://apache\.org/xml/features/disallow-doctype-decl["\']\s*,\s*true',
            r'setFeature\s*\(\s*XMLConstants\.FEATURE_SECURE_PROCESSING\s*,\s*true',
            r'setFeature\s*\(\s*["\']http://xml\.org/sax/features/external-general-entities["\']\s*,\s*false',
            r'setFeature\s*\(\s*["\']http://xml\.org/sax/features/external-parameter-entities["\']\s*,\s*false',
            r'setExpandEntityReferences\s*\(\s*false',
            r'FEATURE_SECURE_PROCESSING',
        ],
    ),
    VulnerabilityPattern(
        name="XXE - SAXParserFactory (Java)",
        category=VulnCategory.XXE,
        patterns=[
            # SAXParserFactory without secure configuration
            r'SAXParserFactory\.newInstance\s*\(\s*\)',
            r'SAXParserFactory\s+\w+\s*=\s*SAXParserFactory\.newInstance',

            # SAXParser.parse with untrusted input
            r'saxParser\.parse\s*\(\s*new\s+InputSource',
            r'saxParser\.parse\s*\(\s*.*getInputStream',
            r'saxParser\.parse\s*\(\s*.*request\.get',
            r'parser\.parse\s*\(\s*new\s+InputSource\s*\(\s*new\s+StringReader',

            # factory.newSAXParser without setFeature
            r'factory\.newSAXParser\s*\(\s*\)',
            r'spf\.newSAXParser\s*\(\s*\)',
        ],
        severity=Severity.HIGH,
        languages=[".java", ".kt", ".scala", ".groovy"],
        false_positive_patterns=[
            r'setFeature\s*\(\s*["\']http://apache\.org/xml/features/disallow-doctype-decl["\']\s*,\s*true',
            r'setFeature\s*\(\s*XMLConstants\.FEATURE_SECURE_PROCESSING\s*,\s*true',
            r'setFeature\s*\(\s*["\']http://xml\.org/sax/features/external-general-entities["\']\s*,\s*false',
            r'FEATURE_SECURE_PROCESSING',
        ],
    ),
    VulnerabilityPattern(
        name="XXE - XMLReader (Java)",
        category=VulnCategory.XXE,
        patterns=[
            # XMLReader creation
            r'XMLReaderFactory\.createXMLReader\s*\(\s*\)',
            r'XMLReader\s+\w+\s*=\s*XMLReaderFactory\.createXMLReader',

            # XMLReader.parse with untrusted input
            r'xmlReader\.parse\s*\(\s*new\s+InputSource',
            r'xmlReader\.parse\s*\(\s*.*getInputStream',
            r'reader\.parse\s*\(\s*new\s+InputSource\s*\(\s*new\s+StringReader',

            # SAXParser.getXMLReader
            r'saxParser\.getXMLReader\s*\(\s*\)',
        ],
        severity=Severity.HIGH,
        languages=[".java", ".kt", ".scala", ".groovy"],
        false_positive_patterns=[
            r'setFeature\s*\(\s*["\']http://apache\.org/xml/features/disallow-doctype-decl["\']\s*,\s*true',
            r'setFeature\s*\(\s*["\']http://xml\.org/sax/features/external-general-entities["\']\s*,\s*false',
        ],
    ),
    VulnerabilityPattern(
        name="XXE - TransformerFactory (Java)",
        category=VulnCategory.XXE,
        patterns=[
            # TransformerFactory without secure configuration
            r'TransformerFactory\.newInstance\s*\(\s*\)',
            r'TransformerFactory\s+\w+\s*=\s*TransformerFactory\.newInstance',

            # Transformer with untrusted XSLT
            r'transformerFactory\.newTransformer\s*\(\s*new\s+StreamSource',
            r'tf\.newTransformer\s*\(\s*new\s+StreamSource\s*\(\s*new\s+StringReader',
            r'\.newTransformer\s*\(\s*.*getInputStream',
            r'\.newTransformer\s*\(\s*.*request\.get',

            # SAXTransformerFactory
            r'SAXTransformerFactory\.newInstance\s*\(\s*\)',
        ],
        severity=Severity.HIGH,
        languages=[".java", ".kt", ".scala", ".groovy"],
        false_positive_patterns=[
            r'setAttribute\s*\(\s*XMLConstants\.ACCESS_EXTERNAL_DTD\s*,\s*""',
            r'setAttribute\s*\(\s*XMLConstants\.ACCESS_EXTERNAL_STYLESHEET\s*,\s*""',
            r'setFeature\s*\(\s*XMLConstants\.FEATURE_SECURE_PROCESSING\s*,\s*true',
        ],
    ),
    VulnerabilityPattern(
        name="XXE - XMLInputFactory/StAX (Java)",
        category=VulnCategory.XXE,
        patterns=[
            # XMLInputFactory without secure configuration
            r'XMLInputFactory\.newInstance\s*\(\s*\)',
            r'XMLInputFactory\.newFactory\s*\(\s*\)',
            r'XMLInputFactory\s+\w+\s*=\s*XMLInputFactory\.newInstance',

            # XMLStreamReader with untrusted input
            r'xmlInputFactory\.createXMLStreamReader\s*\(\s*new\s+StringReader',
            r'xmlInputFactory\.createXMLStreamReader\s*\(\s*.*getInputStream',
            r'\.createXMLStreamReader\s*\(\s*.*request\.get',

            # XMLEventReader
            r'xmlInputFactory\.createXMLEventReader\s*\(\s*new\s+StringReader',
            r'\.createXMLEventReader\s*\(\s*.*getInputStream',
        ],
        severity=Severity.HIGH,
        languages=[".java", ".kt", ".scala", ".groovy"],
        false_positive_patterns=[
            r'setProperty\s*\(\s*XMLInputFactory\.IS_SUPPORTING_EXTERNAL_ENTITIES\s*,\s*false',
            r'setProperty\s*\(\s*XMLInputFactory\.SUPPORT_DTD\s*,\s*false',
            r'IS_SUPPORTING_EXTERNAL_ENTITIES.*false',
            r'SUPPORT_DTD.*false',
        ],
    ),
    VulnerabilityPattern(
        name="XXE - SchemaFactory (Java)",
        category=VulnCategory.XXE,
        patterns=[
            # SchemaFactory without secure configuration
            r'SchemaFactory\.newInstance\s*\(',
            r'SchemaFactory\s+\w+\s*=\s*SchemaFactory\.newInstance',

            # Schema creation with untrusted input
            r'schemaFactory\.newSchema\s*\(\s*new\s+StreamSource\s*\(\s*new\s+StringReader',
            r'\.newSchema\s*\(\s*.*getInputStream',
            r'\.newSchema\s*\(\s*.*request\.get',
        ],
        severity=Severity.HIGH,
        languages=[".java", ".kt", ".scala", ".groovy"],
        false_positive_patterns=[
            r'setProperty\s*\(\s*XMLConstants\.ACCESS_EXTERNAL_DTD\s*,\s*""',
            r'setProperty\s*\(\s*XMLConstants\.ACCESS_EXTERNAL_SCHEMA\s*,\s*""',
        ],
    ),
    VulnerabilityPattern(
        name="XXE - Unmarshaller/JAXB (Java)",
        category=VulnCategory.XXE,
        patterns=[
            # JAXB Unmarshaller with untrusted input
            r'unmarshaller\.unmarshal\s*\(\s*new\s+StringReader',
            r'unmarshaller\.unmarshal\s*\(\s*new\s+StreamSource\s*\(\s*new\s+StringReader',
            r'unmarshaller\.unmarshal\s*\(\s*.*getInputStream',
            r'unmarshaller\.unmarshal\s*\(\s*.*request\.get',
            r'\.unmarshal\s*\(\s*new\s+InputSource\s*\(\s*new\s+StringReader',

            # JAXBContext usage
            r'JAXBContext\.newInstance\s*\(',
            r'jaxbContext\.createUnmarshaller\s*\(\s*\)',
        ],
        severity=Severity.MEDIUM,
        languages=[".java", ".kt", ".scala", ".groovy"],
        false_positive_patterns=[
            r'XMLInputFactory.*setProperty.*SUPPORT_DTD.*false',
            r'setProperty\s*\(\s*XMLInputFactory\.IS_SUPPORTING_EXTERNAL_ENTITIES',
        ],
    ),
    VulnerabilityPattern(
        name="XXE - XPathFactory (Java)",
        category=VulnCategory.XXE,
        patterns=[
            # XPathFactory can be exploited when parsing untrusted XML
            r'XPathFactory\.newInstance\s*\(\s*\)',
            r'xpath\.evaluate\s*\(\s*[^,]+,\s*new\s+InputSource\s*\(\s*new\s+StringReader',
            r'xpath\.evaluate\s*\(\s*[^,]+,\s*.*getInputStream',
        ],
        severity=Severity.MEDIUM,
        languages=[".java", ".kt", ".scala", ".groovy"],
        false_positive_patterns=[
            r'setFeature\s*\(\s*XMLConstants\.FEATURE_SECURE_PROCESSING',
        ],
    ),
    VulnerabilityPattern(
        name="XXE - Digester (Apache Commons)",
        category=VulnCategory.XXE,
        patterns=[
            # Apache Commons Digester
            r'new\s+Digester\s*\(\s*\)',
            r'Digester\s+\w+\s*=\s*new\s+Digester',
            r'digester\.parse\s*\(\s*new\s+InputSource',
            r'digester\.parse\s*\(\s*.*getInputStream',
            r'digester\.parse\s*\(\s*.*request\.get',
        ],
        severity=Severity.HIGH,
        languages=[".java", ".kt", ".scala", ".groovy"],
        false_positive_patterns=[
            r'setFeature\s*\(\s*["\']http://apache\.org/xml/features/disallow-doctype-decl',
        ],
    ),
    VulnerabilityPattern(
        name="XXE - dom4j (Java)",
        category=VulnCategory.XXE,
        patterns=[
            # dom4j SAXReader
            r'new\s+SAXReader\s*\(\s*\)',
            r'SAXReader\s+\w+\s*=\s*new\s+SAXReader',
            r'saxReader\.read\s*\(\s*new\s+StringReader',
            r'saxReader\.read\s*\(\s*.*getInputStream',
            r'reader\.read\s*\(\s*new\s+InputSource\s*\(\s*new\s+StringReader',

            # dom4j DocumentHelper
            r'DocumentHelper\.parseText\s*\(',
        ],
        severity=Severity.HIGH,
        languages=[".java", ".kt", ".scala", ".groovy"],
        false_positive_patterns=[
            r'setFeature\s*\(\s*["\']http://apache\.org/xml/features/disallow-doctype-decl',
            r'saxReader\.setFeature\s*\(',
        ],
    ),
    VulnerabilityPattern(
        name="XXE - JDOM (Java)",
        category=VulnCategory.XXE,
        patterns=[
            # JDOM SAXBuilder
            r'new\s+SAXBuilder\s*\(\s*\)',
            r'SAXBuilder\s+\w+\s*=\s*new\s+SAXBuilder',
            r'saxBuilder\.build\s*\(\s*new\s+StringReader',
            r'saxBuilder\.build\s*\(\s*.*getInputStream',
            r'builder\.build\s*\(\s*new\s+InputSource\s*\(\s*new\s+StringReader',
        ],
        severity=Severity.HIGH,
        languages=[".java", ".kt", ".scala", ".groovy"],
        false_positive_patterns=[
            r'setFeature\s*\(\s*["\']http://apache\.org/xml/features/disallow-doctype-decl',
            r'new\s+SAXBuilder\s*\(\s*XMLReaders\.NONVALIDATING',  # Safer in JDOM2
        ],
    ),

    # =========================================================================
    # REFLECTION-BASED COMMAND/CODE INJECTION - EVASION DETECTION
    # =========================================================================
    VulnerabilityPattern(
        name="Reflection-Based Command Injection (Java)",
        category=VulnCategory.CODE_INJECTION,
        patterns=[
            # Method.invoke on Runtime.exec - the core evasion pattern
            r'\.invoke\s*\(\s*runtime\s*,',
            r'\.invoke\s*\(\s*\w*[Rr]untime\w*\s*,',
            r'exec\.invoke\s*\(',
            r'getMethod\s*\(\s*["\']exec["\']\s*,',
            r'getDeclaredMethod\s*\(\s*["\']exec["\']\s*,',

            # Reflection chain: Class.forName("java.lang.Runtime")
            r'Class\.forName\s*\(\s*["\']java\.lang\.Runtime["\']\s*\)',
            r'forName\s*\(\s*["\']java\.lang\.\s*"\s*\+',
            r'forName\s*\(\s*.*Runtime.*\)',

            # getRuntime via reflection
            r'getMethod\s*\(\s*["\']getRuntime["\']\s*\)',
            r'getDeclaredMethod\s*\(\s*["\']getRuntime["\']\s*\)',

            # ProcessBuilder via reflection
            r'Class\.forName\s*\(\s*["\']java\.lang\.ProcessBuilder["\']\s*\)',
            r'forName\s*\(\s*.*ProcessBuilder.*\)',
            r'Constructor.*ProcessBuilder',

            # Dynamic class + method invocation with variables (taint)
            r'Class\.forName\s*\(\s*[a-zA-Z_]\w*\s*\)',  # Variable class name
            r'\.getMethod\s*\(\s*[a-zA-Z_]\w*\s*,',      # Variable method name
            r'\.invoke\s*\(\s*\w+\s*,\s*\w+\s*\)',       # Generic invoke with variable args
        ],
        severity=Severity.CRITICAL,
        languages=[".java", ".kt", ".scala", ".groovy"],
        false_positive_patterns=[
            r'//.*invoke',
            r'/\*.*invoke',
            r'mock',
            r'test',
            r'\.invoke\s*\(\s*null\s*\)',  # Static method invocation on null
        ],
    ),
    VulnerabilityPattern(
        name="Reflection-Based Deserialization (Java)",
        category=VulnCategory.DESERIALIZATION,
        patterns=[
            # ObjectInputStream via reflection
            r'Class\.forName\s*\(\s*["\']java\.io\.ObjectInputStream["\']\s*\)',
            r'forName\s*\(\s*["\'].*ObjectInputStream["\']\s*\)',
            r'readObject\.invoke\s*\(',
            r'getMethod\s*\(\s*["\']readObject["\']\s*\)',
            r'getDeclaredMethod\s*\(\s*["\']readObject["\']\s*\)',

            # Constructor.newInstance for OIS
            r'constructor\.newInstance\s*\(\s*new\s+ByteArrayInputStream',
            r'clazz\.getConstructor.*InputStream.*newInstance',

            # XMLDecoder via reflection
            r'forName\s*\(\s*["\'].*XMLDecoder["\']\s*\)',
            r'getMethod\s*\(\s*["\']readObject["\']\s*\).*XMLDecoder',
        ],
        severity=Severity.CRITICAL,
        languages=[".java", ".kt", ".scala", ".groovy"],
        false_positive_patterns=[
            r'ObjectInputFilter',
            r'SafeObjectInputStream',
        ],
    ),
    VulnerabilityPattern(
        name="Reflection-Based ScriptEngine Injection (Java)",
        category=VulnCategory.CODE_INJECTION,
        patterns=[
            # ScriptEngine via reflection
            r'Class\.forName\s*\(\s*["\']javax\.script\.ScriptEngineManager["\']\s*\)',
            r'forName\s*\(\s*["\'].*ScriptEngine.*["\']\s*\)',
            r'getMethod\s*\(\s*["\']getEngineByName["\']\s*,',
            r'getMethod\s*\(\s*["\']eval["\']\s*,\s*String\.class',
            r'eval\.invoke\s*\(\s*engine',
            r'eval\.invoke\s*\(',

            # Dynamic engine invocation
            r'\.invoke\s*\(\s*manager\s*,\s*["\']',  # getEngineByName invoke
            r'engine\.getClass\s*\(\s*\)\.getMethod\s*\(\s*["\']eval["\']\s*',
        ],
        severity=Severity.CRITICAL,
        languages=[".java", ".kt", ".scala", ".groovy"],
        false_positive_patterns=[
            r'//.*eval\.invoke',
            r'mock',
            r'test',
        ],
    ),
    VulnerabilityPattern(
        name="Reflection-Based JNDI Lookup (Java)",
        category=VulnCategory.CODE_INJECTION,
        patterns=[
            # InitialContext via reflection (Log4Shell style evasion)
            r'Class\.forName\s*\(\s*["\']javax\.naming\.InitialContext["\']\s*\)',
            r'forName\s*\(\s*["\'].*InitialContext["\']\s*\)',
            r'getMethod\s*\(\s*["\']lookup["\']\s*,\s*String\.class',
            r'lookup\.invoke\s*\(\s*ctx',
            r'lookup\.invoke\s*\(',

            # Context via reflection
            r'forName\s*\(\s*["\']javax\.naming\.Context["\']\s*\)',
            r'forName\s*\(\s*["\'].*Context["\']\s*\).*lookup',
        ],
        severity=Severity.CRITICAL,
        languages=[".java", ".kt", ".scala", ".groovy"],
        false_positive_patterns=[
            r'//.*lookup\.invoke',
            r'mock',
            r'test',
        ],
    ),

    # =========================================================================
    # STRING OBFUSCATION EVASION DETECTION
    # =========================================================================
    VulnerabilityPattern(
        name="Char Array String Obfuscation (Java)",
        category=VulnCategory.CODE_INJECTION,
        patterns=[
            # Building dangerous strings from char arrays
            r"char\s*\[\s*\]\s*\w*\s*=\s*\{\s*'[Rr]'\s*,\s*'[Uu]'\s*,\s*'[Nn]'\s*,\s*'[Tt]'\s*,\s*'[Ii]'\s*,\s*'[Mm]'\s*,\s*'[Ee]'\s*\}",
            r"char\s*\[\s*\]\s*\w*\s*=\s*\{\s*'[Ee]'\s*,\s*'[Xx]'\s*,\s*'[Ee]'\s*,\s*'[Cc]'\s*\}",
            r"char\s*\[\s*\]\s*\w*\s*=\s*\{\s*'[Pp]'\s*,\s*'[Rr]'\s*,\s*'[Oo]'\s*,\s*'[Cc]'\s*,\s*'[Ee]'\s*,\s*'[Ss]'\s*,\s*'[Ss]'\s*\}",

            # new String(char[]) used with Class.forName or getMethod
            r'new\s+String\s*\(\s*\w+\s*\).*Class\.forName',
            r'new\s+String\s*\(\s*\w+\s*\).*getMethod',
            r'Class\.forName\s*\(\s*.*new\s+String\s*\(\s*\w+\s*\)',
            r'getMethod\s*\(\s*new\s+String\s*\(\s*\w+\s*\)',

            # Generic pattern: building string from char array then using in reflection
            r'new\s+String\s*\(\s*\w+\s*\)\s*\).*\.invoke',
        ],
        severity=Severity.HIGH,
        languages=[".java", ".kt", ".scala", ".groovy"],
        false_positive_patterns=[
            r'//.*char\s*\[\s*\]',
            r'test',
            r'mock',
        ],
    ),
    VulnerabilityPattern(
        name="Unicode Escape Obfuscation (Java)",
        category=VulnCategory.CODE_INJECTION,
        patterns=[
            # Unicode escapes for "exec" - \u0065\u0078\u0065\u0063
            r'\\u0065\\u0078\\u0065\\u0063',  # exec
            r'\\u0052\\u0075\\u006e\\u0074\\u0069\\u006d\\u0065',  # Runtime
            r'\\u0050\\u0072\\u006f\\u0063\\u0065\\u0073\\u0073',  # Process
            r'\\u0067\\u0065\\u0074\\u0052\\u0075\\u006e\\u0074\\u0069\\u006d\\u0065',  # getRuntime
            r'\\u0066\\u006f\\u0072\\u004e\\u0061\\u006d\\u0065',  # forName
            r'\\u0065\\u0076\\u0061\\u006c',  # eval
            r'\\u006c\\u006f\\u006f\\u006b\\u0075\\u0070',  # lookup

            # Generic: multiple unicode escapes used in method invocation
            r'getMethod\s*\(\s*["\']\\u00',
            r'forName\s*\(\s*["\'].*\\u00',

            # Unicode in string that gets passed to exec-like methods
            r'["\']\\u00\d{2}[^"\']*["\']\s*\).*\.invoke',
        ],
        severity=Severity.HIGH,
        languages=[".java", ".kt", ".scala", ".groovy"],
        false_positive_patterns=[
            r'//.*\\u00',
            r'test',
            r'mock',
        ],
    ),
    VulnerabilityPattern(
        name="Reverse String Obfuscation (Java)",
        category=VulnCategory.CODE_INJECTION,
        patterns=[
            # StringBuilder.reverse() to build dangerous strings
            r'StringBuilder\s*\(\s*["\']cexe["\']\s*\)\s*\.reverse',  # exec
            r'StringBuilder\s*\(\s*["\']emitnuRteg["\']\s*\)\s*\.reverse',  # getRuntime
            r'StringBuilder\s*\(\s*["\']emaNrof["\']\s*\)\s*\.reverse',  # forName
            r'StringBuilder\s*\(\s*["\']lave["\']\s*\)\s*\.reverse',  # eval
            r'StringBuilder\s*\(\s*["\']pukool["\']\s*\)\s*\.reverse',  # lookup

            # Generic: reverse() followed by toString() used in reflection
            r'\.reverse\s*\(\s*\)\s*\.toString\s*\(\s*\).*getMethod',
            r'\.reverse\s*\(\s*\)\s*\.toString\s*\(\s*\).*forName',
            r'\.reverse\s*\(\s*\)\s*\.toString\s*\(\s*\).*\.invoke',

            # StringBuffer.reverse pattern
            r'StringBuffer.*\.reverse\s*\(\s*\).*exec',
            r'StringBuffer.*\.reverse\s*\(\s*\).*getMethod',
        ],
        severity=Severity.HIGH,
        languages=[".java", ".kt", ".scala", ".groovy"],
        false_positive_patterns=[
            r'//.*reverse',
            r'test',
            r'mock',
        ],
    ),
    VulnerabilityPattern(
        name="Base64 Encoded Command Injection (Java)",
        category=VulnCategory.CODE_INJECTION,
        patterns=[
            # Base64 decode followed by exec
            r'Base64\.getDecoder\s*\(\s*\)\s*\.decode.*Runtime.*exec',
            r'Base64\.getDecoder\s*\(\s*\)\s*\.decode.*\.exec\s*\(',
            r'Base64\.decode.*\.exec\s*\(',
            r'DatatypeConverter\.parseBase64Binary.*exec',

            # Decoded bytes to String then exec
            r'new\s+String\s*\(\s*.*decode.*\).*\.exec\s*\(',
            r'new\s+String\s*\(\s*Base64.*\).*exec',
            r'new\s+String\s*\(\s*.*Base64\.getDecoder.*\).*Runtime',

            # Generic: Base64 -> ProcessBuilder
            r'Base64.*ProcessBuilder',
            r'decode.*ProcessBuilder\s*\(',
        ],
        severity=Severity.CRITICAL,
        languages=[".java", ".kt", ".scala", ".groovy"],
        false_positive_patterns=[
            r'//.*Base64',
            r'test',
            r'mock',
            r'log\.',
        ],
    ),

    # =========================================================================
    # STREAM-BASED SQL INJECTION
    # =========================================================================
    VulnerabilityPattern(
        name="Stream-Based SQL Injection (Java)",
        category=VulnCategory.SQL_INJECTION,
        patterns=[
            # Collectors.joining used to build SQL WHERE IN clauses
            r'Collectors\.joining\s*\(\s*["\'],["\']\s*\).*executeQuery',
            r'Collectors\.joining\s*\(\s*["\'].*["\'].*SELECT',
            r'Collectors\.joining\s*\(\s*["\'].*["\'].*WHERE',
            r'Collectors\.joining\s*\(\s*["\'].*["\'].*IN\s*\(',

            # Stream.collect into SQL query
            r'\.collect\s*\(.*Collectors\.joining.*\).*createStatement',
            r'\.collect\s*\(.*Collectors\.joining.*\).*executeQuery',
            r'\.collect\s*\(.*\).*["\']SELECT',

            # String.join with SQL
            r'String\.join\s*\(.*\).*executeQuery',
            r'String\.join\s*\(.*\).*createStatement',
            r'String\.join\s*\(.*\).*WHERE.*IN',

            # Stream processing feeding SQL
            r'\.stream\s*\(\s*\)\..*\.collect\s*\(.*\).*["\'].*SELECT',
            r'userInputs\.stream\s*\(\s*\)',
        ],
        severity=Severity.HIGH,
        languages=[".java", ".kt", ".scala", ".groovy"],
        false_positive_patterns=[
            r'PreparedStatement',
            r'setString',
            r'//.*Collectors\.joining',
        ],
    ),

    # =========================================================================
    # SPRING FRAMEWORK SQL INJECTION
    # =========================================================================
    VulnerabilityPattern(
        name="Spring JdbcTemplate SQL Injection (Java)",
        category=VulnCategory.SQL_INJECTION,
        patterns=[
            # JdbcTemplate with string concatenation
            r'jdbcTemplate\.queryForList\s*\(\s*["\'].*\+',
            r'jdbcTemplate\.queryForList\s*\(\s*[a-zA-Z_]\w*\s*\)',
            r'jdbcTemplate\.queryForObject\s*\(\s*["\'].*\+',
            r'jdbcTemplate\.queryForObject\s*\(\s*[a-zA-Z_]\w*\s*,',
            r'jdbcTemplate\.queryForMap\s*\(\s*["\'].*\+',
            r'jdbcTemplate\.queryForRowSet\s*\(\s*["\'].*\+',
            r'jdbcTemplate\.query\s*\(\s*["\'].*\+',
            r'jdbcTemplate\.update\s*\(\s*["\'].*\+',
            r'jdbcTemplate\.execute\s*\(\s*["\'].*\+',

            # Variable SQL passed to JdbcTemplate
            r'jdbc\.queryForList\s*\(\s*sql\s*\)',
            r'jdbc\.query\s*\(\s*sql\s*,',
            r'jdbc\.update\s*\(\s*sql\s*\)',

            # NamedParameterJdbcTemplate with concatenation
            r'namedParameterJdbcTemplate\.query\s*\(\s*["\'].*\+',
            r'namedJdbc\.query\s*\(\s*["\'].*\+',

            # Spring Data JPA native query with concatenation
            r'@Query\s*\(\s*value\s*=\s*["\'].*\+',
            r'@Query\s*\(\s*nativeQuery\s*=\s*true.*["\'].*\$\{',
        ],
        severity=Severity.HIGH,
        languages=[".java", ".kt", ".scala", ".groovy"],
        false_positive_patterns=[
            r'//.*jdbcTemplate',
            r'\?\s*[,\)]',
            r':\w+',
        ],
    ),
    VulnerabilityPattern(
        name="MyBatis SQL Injection (Java)",
        category=VulnCategory.SQL_INJECTION,
        patterns=[
            # MyBatis ${} injection (vulnerable) vs #{} (safe)
            r'\$\{[^}]+\}',  # ${} is vulnerable
            r'ORDER\s+BY\s+\$\{',
            r'ORDER\s+BY\s+["\']\s*\+\s*\w+',
            r'GROUP\s+BY\s+\$\{',
            r'LIMIT\s+\$\{',

            # Dynamic SQL building
            r'<if\s+test=[^>]*>.*\$\{',
            r'<where>.*\$\{',
            r'<set>.*\$\{',

            # Annotation-based queries with concatenation
            r'@Select\s*\(\s*["\'].*\+',
            r'@Insert\s*\(\s*["\'].*\+',
            r'@Update\s*\(\s*["\'].*\+',
            r'@Delete\s*\(\s*["\'].*\+',
        ],
        severity=Severity.HIGH,
        languages=[".java", ".kt", ".xml"],
        false_positive_patterns=[
            r'#\{[^}]+\}',  # Safe placeholder
            r'//.*\$\{',
        ],
    ),

    # =========================================================================
    # SECOND-ORDER SQL INJECTION
    # =========================================================================
    VulnerabilityPattern(
        name="Second-Order SQL Injection (Java)",
        category=VulnCategory.SQL_INJECTION,
        patterns=[
            # Store data safely, then use unsafely later
            # Pattern: PreparedStatement INSERT followed by concatenated SELECT
            r'pstmt\.setString.*\n.*\n.*createStatement.*executeQuery\s*\(\s*["\'].*\+',

            # Retrieving stored value and using in query
            r'rs\.getString\s*\([^)]+\).*executeQuery',
            r'resultSet\.getString\s*\([^)]+\).*createStatement',
            r'getString\s*\([^)]+\).*["\'].*WHERE.*\+',

            # Reading from DB and executing
            r'\.getString\s*\(\s*["\'][^"\']+["\']\s*\).*\+.*executeQuery',

            # Same variable used in safe insert then unsafe query
            r'setString\s*\([^)]+,\s*(\w+)\s*\).*createStatement.*executeQuery\s*\([^)]*\1',
        ],
        severity=Severity.MEDIUM,
        languages=[".java", ".kt", ".scala", ".groovy", ".py", ".php"],
        false_positive_patterns=[
            r'//.*second',
            r'test',
            r'mock',
        ],
    ),

    # =========================================================================
    # RACE CONDITIONS AND TOCTOU
    # =========================================================================
    VulnerabilityPattern(
        name="TOCTOU Race Condition (Java)",
        category=VulnCategory.AUTH_BYPASS,
        patterns=[
            # File check followed by sleep/wait followed by read
            r'\.exists\s*\(\s*\).*Thread\.sleep.*Files\.read',
            r'\.canRead\s*\(\s*\).*Thread\.sleep.*Files\.read',
            r'\.isFile\s*\(\s*\).*Thread\.sleep.*Files\.read',
            r'getCanonicalPath.*startsWith.*Thread\.sleep',
            r'getCanonicalPath.*startsWith.*\.read',

            # Check -> wait -> use pattern
            r'if\s*\([^)]*\.exists.*\{[^}]*Thread\.sleep',
            r'if\s*\([^)]*\.canRead.*\{[^}]*Thread\.sleep',
            r'if\s*\([^)]*startsWith.*\{[^}]*Thread\.sleep',

            # Path validation followed by file operations
            r'getCanonicalPath\s*\(\s*\)\.startsWith.*Files\.readAllBytes',
            r'toRealPath\s*\(\s*\).*Files\.read',

            # Symlink vulnerable patterns
            r'\.exists\s*\(\s*\).*\.toPath\s*\(\s*\)',
            r'isDirectory\s*\(\s*\).*Files\.walk',
        ],
        severity=Severity.MEDIUM,
        languages=[".java", ".kt", ".scala", ".groovy", ".py", ".go", ".c", ".cpp"],
        false_positive_patterns=[
            r'//.*TOCTOU',
            r'test',
            r'mock',
            r'synchronized',
            r'lock',
        ],
    ),
    VulnerabilityPattern(
        name="Non-Atomic Authentication Check (Java)",
        category=VulnCategory.AUTH_BYPASS,
        patterns=[
            # HashMap for login attempts (not thread-safe)
            r'HashMap\s*<\s*String\s*,\s*Integer\s*>\s*\w*\s*=.*login',
            r'HashMap.*loginAttempts',
            r'HashMap.*attempts',
            r'new\s+HashMap.*password',
            r'new\s+HashMap.*auth',

            # getOrDefault followed by put without sync
            r'\.getOrDefault\s*\([^)]+\)\s*;[^}]*\.put\s*\(',
            r'\.get\s*\([^)]+\)[^}]*\.put\s*\([^)]+,\s*\w+\s*\+\s*1',

            # Non-atomic increment patterns
            r'attempts\s*=\s*\w+\.get.*attempts\s*\+\s*1',
            r'int\s+attempts.*\.put\s*\([^)]+,\s*attempts\s*\+',

            # Check and act without synchronization
            r'if\s*\(\s*\w+\s*>=\s*\d+\s*\)[^}]*return\s+false.*\.put\s*\(',
        ],
        severity=Severity.MEDIUM,
        languages=[".java", ".kt", ".scala", ".groovy"],
        false_positive_patterns=[
            r'ConcurrentHashMap',
            r'synchronized',
            r'AtomicInteger',
            r'ReentrantLock',
            r'\.lock\s*\(',
        ],
    ),

    # =========================================================================
    # DESERIALIZATION GADGET CHAINS
    # =========================================================================
    VulnerabilityPattern(
        name="Deserialization Gadget - InvokerTransformer (Java)",
        category=VulnCategory.DESERIALIZATION,
        patterns=[
            # Commons Collections InvokerTransformer
            r'InvokerTransformer',
            r'org\.apache\.commons\.collections\.functors\.InvokerTransformer',
            r'org\.apache\.commons\.collections4\.functors\.InvokerTransformer',

            # ChainedTransformer with dangerous transformers
            r'ChainedTransformer',
            r'ConstantTransformer.*InvokerTransformer',
            r'InstantiateTransformer',

            # TransformerMap/LazyMap (triggers)
            r'LazyMap\.decorate',
            r'TransformedMap\.decorate',

            # Creating InvokerTransformer via reflection
            r'forName\s*\(\s*["\'].*InvokerTransformer["\']\s*\)',
            r'getConstructor.*InvokerTransformer',
            r'newInstance.*exec.*String\.class',
        ],
        severity=Severity.CRITICAL,
        languages=[".java", ".kt", ".scala", ".groovy"],
        false_positive_patterns=[
            r'//.*InvokerTransformer',
            r'test',
            r'mock',
        ],
    ),
    VulnerabilityPattern(
        name="Deserialization Gadget - TemplatesImpl (Java)",
        category=VulnCategory.DESERIALIZATION,
        patterns=[
            # TemplatesImpl bytecode injection
            r'TemplatesImpl',
            r'com\.sun\.org\.apache\.xalan\.internal\.xsltc\.trax\.TemplatesImpl',

            # Setting bytecode via reflection
            r'_bytecodes',
            r'setAccessible.*_bytecodes',
            r'getDeclaredField\s*\(\s*["\']_bytecodes["\']\s*\)',

            # Related dangerous fields
            r'_name',
            r'_tfactory',
            r'_class',
            r'getDeclaredField\s*\(\s*["\']_name["\']\s*\)',
            r'getDeclaredField\s*\(\s*["\']_tfactory["\']\s*\)',

            # newTransformer trigger
            r'\.newTransformer\s*\(\s*\)',
            r'getMethod\s*\(\s*["\']newTransformer["\']\s*\)',

            # TransletClassLoader
            r'TransletClassLoader',
            r'AbstractTranslet',
        ],
        severity=Severity.CRITICAL,
        languages=[".java", ".kt", ".scala", ".groovy"],
        false_positive_patterns=[
            r'//.*TemplatesImpl',
            r'test',
            r'mock',
        ],
    ),
    VulnerabilityPattern(
        name="Custom readObject Gadget (Java)",
        category=VulnCategory.DESERIALIZATION,
        patterns=[
            # Dangerous readObject implementations
            r'private\s+void\s+readObject\s*\(\s*ObjectInputStream',
            r'readObject\s*\(\s*\).*Runtime\.getRuntime',
            r'readObject\s*\(\s*\).*\.exec\s*\(',
            r'readObject\s*\(\s*\).*ProcessBuilder',
            r'readObject\s*\(\s*\).*ScriptEngine',
            r'readObject\s*\(\s*\).*\.invoke\s*\(',

            # defaultReadObject followed by dangerous code
            r'defaultReadObject\s*\(\s*\).*exec',
            r'defaultReadObject\s*\(\s*\).*ProcessBuilder',
            r'defaultReadObject\s*\(\s*\).*Runtime',

            # ObjectInputStream.readObject inside readObject
            r'ois\.readObject\s*\(\s*\).*\.exec',
        ],
        severity=Severity.CRITICAL,
        languages=[".java", ".kt", ".scala", ".groovy"],
        false_positive_patterns=[
            r'//.*readObject',
            r'ObjectInputFilter',
            r'test',
        ],
    ),

    # =========================================================================
    # CRYPTOGRAPHIC WEAKNESSES
    # =========================================================================
    VulnerabilityPattern(
        name="Weak Crypto - ECB Mode (Java)",
        category=VulnCategory.AUTH_BYPASS,
        patterns=[
            # ECB mode detection (including evasion via concatenation)
            r'Cipher\.getInstance\s*\(\s*["\']AES/ECB',
            r'Cipher\.getInstance\s*\(\s*["\']DES/ECB',
            r'Cipher\.getInstance\s*\(\s*["\']DESede/ECB',
            r'Cipher\.getInstance\s*\(\s*["\']Blowfish/ECB',

            # ECB via string concatenation (evasion)
            r'["\']AES["\']\s*\+\s*["\']\/["\']\s*\+\s*["\']ECB["\']\s*\+',
            r'["\']AES["\']\s*\+\s*["\']\/ECB',
            r'transformation\s*=\s*["\']AES["\']\s*\+\s*.*ECB',
            r'"AES"\s*\+\s*"/"\s*\+\s*"ECB"',

            # AES without mode (defaults to ECB)
            r'Cipher\.getInstance\s*\(\s*["\']AES["\']\s*\)',
            r'Cipher\.getInstance\s*\(\s*["\']DES["\']\s*\)',

            # Variable mode that might be ECB
            r'Cipher\.getInstance\s*\(\s*[a-zA-Z_]\w*\s*\)',
        ],
        severity=Severity.MEDIUM,
        languages=[".java", ".kt", ".scala", ".groovy"],
        false_positive_patterns=[
            r'//.*ECB',
            r'CBC',
            r'GCM',
            r'CTR',
        ],
    ),
    VulnerabilityPattern(
        name="Weak Key Derivation (Java)",
        category=VulnCategory.AUTH_BYPASS,
        patterns=[
            # Password bytes used directly as key
            r'password\.getBytes.*SecretKeySpec',
            r'new\s+SecretKeySpec\s*\(\s*\w*[Pp]assword\w*\.getBytes',
            r'new\s+SecretKeySpec\s*\(\s*\w+\.getBytes.*AES',

            # Arrays.copyOf on password bytes
            r'Arrays\.copyOf\s*\(\s*\w*[Pp]assword\w*\.getBytes',
            r'Arrays\.copyOf\s*\(\s*keyBytes\s*,\s*16',

            # String to key directly
            r'new\s+SecretKeySpec\s*\(\s*["\'][^"\']+["\']\s*\.getBytes',

            # Padding password to key size
            r'paddedKey\s*=.*copyOf.*getBytes',
        ],
        severity=Severity.HIGH,
        languages=[".java", ".kt", ".scala", ".groovy"],
        false_positive_patterns=[
            r'PBKDF2',
            r'SecretKeyFactory',
            r'PBEKeySpec',
            r'//.*weak',
        ],
    ),
    VulnerabilityPattern(
        name="Predictable IV/Nonce (Java)",
        category=VulnCategory.AUTH_BYPASS,
        patterns=[
            # All-zero IV
            r'new\s+byte\s*\[\s*16\s*\].*IvParameterSpec',
            r'IvParameterSpec\s*\(\s*new\s+byte\s*\[\s*16\s*\]',
            r'IvParameterSpec\s*\(\s*new\s+byte\s*\[\s*12\s*\]',  # GCM nonce
            r'iv\s*=\s*new\s+byte\s*\[\s*16\s*\]',

            # Static/hardcoded IV
            r'static\s+.*byte\s*\[\s*\].*IV',
            r'final\s+byte\s*\[\s*\].*=\s*\{[^}]+\}.*iv',
            r'STATIC.*IV',

            # Reusing IV
            r'IvParameterSpec\s*\(\s*["\'][^"\']+["\']\s*\.getBytes',

            # Zero-filled arrays for IV
            r'Arrays\.fill\s*\(\s*iv\s*,\s*\(byte\)\s*0',
        ],
        severity=Severity.HIGH,
        languages=[".java", ".kt", ".scala", ".groovy"],
        false_positive_patterns=[
            r'SecureRandom',
            r'\.generateSeed',
            r'//.*predictable',
        ],
    ),
    VulnerabilityPattern(
        name="Static/Weak Salt (Java)",
        category=VulnCategory.AUTH_BYPASS,
        patterns=[
            # Static salt
            r'static\s+.*byte\s*\[\s*\].*[Ss]alt',
            r'static\s+final\s+.*SALT',
            r'STATIC_SALT',
            r'final\s+byte\s*\[\s*\].*[Ss]alt\s*=\s*["\']',

            # Hardcoded salt string
            r'salt\s*=\s*["\'][^"\']+["\']\s*\.getBytes',
            r'\.getBytes.*PBEKeySpec',
            r'new\s+PBEKeySpec.*["\'][^"\']+["\']\s*\.getBytes',

            # Same salt for all users
            r'private\s+static\s+final\s+byte\s*\[\s*\]\s+SALT',

            # Empty salt
            r'salt\s*=\s*new\s+byte\s*\[\s*0\s*\]',
            r'salt\s*=\s*["\']["\']',
        ],
        severity=Severity.MEDIUM,
        languages=[".java", ".kt", ".scala", ".groovy"],
        false_positive_patterns=[
            r'SecureRandom',
            r'\.generateSeed',
            r'//.*static.*salt',
        ],
    ),
    VulnerabilityPattern(
        name="Insufficient PBKDF2 Iterations (Java)",
        category=VulnCategory.AUTH_BYPASS,
        patterns=[
            # Low iteration count (less than 10000)
            r'PBEKeySpec\s*\([^)]*,\s*\d{1,3}\s*,',  # 1-999 iterations
            r'PBEKeySpec\s*\([^)]*,\s*1\d{3}\s*,',   # 1000-1999 iterations
            r'iterations\s*=\s*\d{1,3}\s*;',
            r'iterations\s*=\s*100\s*;',
            r'iterations\s*=\s*1000\s*;',

            # Magic numbers in PBKDF2
            r'SecretKeyFactory.*PBEKeySpec.*,\s*100\s*,',
            r'SecretKeyFactory.*PBEKeySpec.*,\s*1000\s*,',

            # Variable with low value
            r'ITERATIONS\s*=\s*\d{1,4}\s*;',
            r'ITERATION_COUNT\s*=\s*\d{1,4}\s*;',
        ],
        severity=Severity.MEDIUM,
        languages=[".java", ".kt", ".scala", ".groovy"],
        false_positive_patterns=[
            r'//.*iterations',
            r'100000',
            r'10000',
            r'310000',  # OWASP recommended
        ],
    ),

    # =========================================================================
    # LAMBDA AND FUNCTIONAL INTERFACE INJECTION
    # =========================================================================
    VulnerabilityPattern(
        name="Lambda-Based Code Injection (Java)",
        category=VulnCategory.CODE_INJECTION,
        patterns=[
            # Supplier with ScriptEngine.eval
            r'Supplier.*engine\.eval\s*\(\s*\w+',
            r'Supplier.*ScriptEngine.*eval',
            r'\(\s*\)\s*->\s*\{[^}]*engine\.eval',
            r'\(\s*\)\s*->\s*\{[^}]*\.eval\s*\(\s*code',

            # Function with Runtime.exec
            r'Function.*Runtime\.getRuntime.*exec',
            r'Function.*\.exec\s*\(\s*\w+',
            r'\w+\s*->\s*\{[^}]*Runtime.*exec',
            r'cmd\s*->\s*\{[^}]*Process\s*p\s*=',

            # Consumer/BiConsumer with exec
            r'Consumer.*\.exec\s*\(',
            r'BiConsumer.*\.exec\s*\(',

            # CompletableFuture with code execution
            r'CompletableFuture\.supplyAsync.*engine\.eval',
            r'CompletableFuture\.supplyAsync.*\.exec\s*\(',
            r'supplyAsync\s*\(\s*\(\s*\)\s*->\s*\{[^}]*eval',
            r'supplyAsync\s*\(\s*\(\s*\)\s*->\s*\{[^}]*exec',

            # runAsync with code execution
            r'CompletableFuture\.runAsync.*engine\.eval',
            r'runAsync.*Runtime\.getRuntime',

            # ForkJoinPool with exec
            r'ForkJoinPool.*exec\s*\(',
            r'ForkJoinTask.*exec\s*\(',

            # Method references to dangerous methods
            r'Runtime::exec',
            r'ProcessBuilder::start',
            r'ScriptEngine::eval',
        ],
        severity=Severity.HIGH,
        languages=[".java", ".kt", ".scala", ".groovy"],
        false_positive_patterns=[
            r'//.*Lambda',
            r'test',
            r'mock',
        ],
    ),
    VulnerabilityPattern(
        name="Async Code Injection (Java)",
        category=VulnCategory.CODE_INJECTION,
        patterns=[
            # ExecutorService with dangerous code
            r'ExecutorService.*submit.*engine\.eval',
            r'ExecutorService.*submit.*\.exec\s*\(',
            r'executor\.submit\s*\(\s*\(\s*\)\s*->\s*\{[^}]*eval',
            r'executor\.submit\s*\(\s*\(\s*\)\s*->\s*\{[^}]*exec',

            # ScheduledExecutorService
            r'ScheduledExecutorService.*exec\s*\(',
            r'scheduler\.schedule.*exec',
            r'scheduler\.schedule.*eval',

            # Parallel streams with dangerous operations
            r'\.parallelStream\s*\(\s*\).*exec\s*\(',
            r'\.parallelStream\s*\(\s*\).*eval\s*\(',

            # Thread pool with code injection
            r'ThreadPoolExecutor.*exec\s*\(',
            r'newFixedThreadPool.*exec',
            r'newCachedThreadPool.*exec',
        ],
        severity=Severity.HIGH,
        languages=[".java", ".kt", ".scala", ".groovy"],
        false_positive_patterns=[
            r'//.*Async',
            r'test',
            r'mock',
        ],
    ),

    # =========================================================================
    # EXPRESSION LANGUAGE INJECTION (OGNL, MVEL, JEXL, SpEL)
    # =========================================================================
    VulnerabilityPattern(
        name="OGNL Injection (Java)",
        category=VulnCategory.CODE_INJECTION,
        patterns=[
            # Direct OGNL usage
            r'Ognl\.getValue\s*\(\s*\w+',
            r'Ognl\.setValue\s*\(\s*\w+',
            r'OgnlUtil\.getValue\s*\(',
            r'OgnlUtil\.setValue\s*\(',

            # OGNL via reflection
            r'forName\s*\(\s*["\']ognl\.Ognl["\']\s*\)',
            r'getMethod\s*\(\s*["\']getValue["\']\s*,\s*String\.class',

            # Struts2 OGNL patterns
            r'OgnlValueStack.*findValue',
            r'ActionContext.*get\s*\(',
            r'%\{.*#.*\}',

            # OGNL Context manipulation
            r'OgnlContext',
            r'_memberAccess',
        ],
        severity=Severity.CRITICAL,
        languages=[".java", ".kt", ".scala", ".groovy"],
        false_positive_patterns=[
            r'//.*OGNL',
            r'test',
            r'mock',
        ],
    ),
    VulnerabilityPattern(
        name="MVEL Injection (Java)",
        category=VulnCategory.CODE_INJECTION,
        patterns=[
            # MVEL.eval with variable
            r'MVEL\.eval\s*\(\s*\w+\s*\)',
            r'MVEL\.eval\s*\(\s*expression',
            r'MVEL\.evalToString\s*\(',
            r'MVEL\.compileExpression\s*\(\s*\w+',
            r'MVEL\.executeExpression\s*\(',

            # MVEL via reflection
            r'forName\s*\(\s*["\']org\.mvel2\.MVEL["\']\s*\)',
            r'getMethod\s*\(\s*["\']eval["\']\s*,\s*String\.class.*MVEL',

            # MVELRuntime
            r'MVELRuntime.*eval',
        ],
        severity=Severity.CRITICAL,
        languages=[".java", ".kt", ".scala", ".groovy"],
        false_positive_patterns=[
            r'//.*MVEL',
            r'test',
            r'mock',
        ],
    ),
    VulnerabilityPattern(
        name="JEXL Injection (Java)",
        category=VulnCategory.CODE_INJECTION,
        patterns=[
            # JEXL3 patterns
            r'JexlBuilder\s*\(\s*\)\.create\s*\(',
            r'jexlEngine\.createExpression\s*\(\s*\w+',
            r'jexlEngine\.createScript\s*\(\s*\w+',
            r'\.evaluate\s*\(\s*.*JexlContext',

            # JEXL via reflection
            r'forName\s*\(\s*["\']org\.apache\.commons\.jexl3["\']\s*\)',
            r'forName\s*\(\s*["\'].*JexlBuilder["\']\s*\)',

            # JEXL2 (legacy)
            r'JexlEngine\s*\(\s*\)',
            r'new\s+JexlEngine\s*\(',
        ],
        severity=Severity.CRITICAL,
        languages=[".java", ".kt", ".scala", ".groovy"],
        false_positive_patterns=[
            r'//.*JEXL',
            r'test',
            r'mock',
            r'JexlBuilder.*sandbox',
        ],
    ),
    VulnerabilityPattern(
        name="EL Injection (JSP/JSF)",
        category=VulnCategory.CODE_INJECTION,
        patterns=[
            # ExpressionFactory usage
            r'ExpressionFactory\.newInstance\s*\(',
            r'expressionFactory\.createValueExpression\s*\(',
            r'expressionFactory\.createMethodExpression\s*\(',

            # EL via reflection
            r'forName\s*\(\s*["\']javax\.el\.ExpressionFactory["\']\s*\)',
            r'forName\s*\(\s*["\']jakarta\.el\.ExpressionFactory["\']\s*\)',

            # ELProcessor
            r'ELProcessor\s*\(\s*\)',
            r'elProcessor\.eval\s*\(',
            r'elProcessor\.getValue\s*\(',
            r'elProcessor\.setValue\s*\(',

            # ValueExpression evaluation
            r'valueExpression\.getValue\s*\(',
            r'methodExpression\.invoke\s*\(',
        ],
        severity=Severity.HIGH,
        languages=[".java", ".kt", ".scala", ".groovy", ".jsp"],
        false_positive_patterns=[
            r'//.*EL',
            r'test',
            r'mock',
        ],
    ),

]
# Binary patterns for DLL/EXE analysis
BINARY_PATTERNS = [
    # =============================================================================
    # CREDENTIALS & SECRETS
    # =============================================================================
    {
        "name": "Hardcoded Connection String",
        "pattern": r'(Data Source|Server|Initial Catalog|User ID|Password|Integrated Security|Provider|Persist Security Info|Trusted_Connection|Database|Uid|Pwd|DSN|Driver)\s*=[^;]*;',
        "severity": Severity.HIGH
    },
    {
        "name": "Hardcoded Credentials",
        "pattern": r'(password|passwd|pwd|secret|api[_-]?key|apikey|token|auth[_-]?token|access[_-]?token|bearer|credential|private[_-]?key|encryption[_-]?key|signing[_-]?key|jwt[_-]?secret|session[_-]?secret|master[_-]?key)\s*[=:]\s*["\'][^"\']{8,}["\']',
        "severity": Severity.HIGH
    },
    {
        "name": "Private Key (PEM)",
        "pattern": r'-----BEGIN\s+(RSA\s+|DSA\s+|EC\s+|OPENSSH\s+|PGP\s+|ENCRYPTED\s+)?PRIVATE\s+KEY(\s+BLOCK)?-----',
        "severity": Severity.CRITICAL
    },
    {
        "name": "Private Key (Putty/XML)",
        "pattern": r'(<RSAKeyValue>|<DSAKeyValue>|PuTTY-User-Key-File)',
        "severity": Severity.CRITICAL
    },
    {
        "name": "Certificate",
        "pattern": r'-----BEGIN\s+CERTIFICATE-----',
        "severity": Severity.MEDIUM
    },

    # =============================================================================
    # CLOUD PROVIDER CREDENTIALS
    # =============================================================================
    {
        "name": "AWS Credentials",
        "pattern": r'(AKIA[0-9A-Z]{16}|ABIA[0-9A-Z]{16}|ACCA[0-9A-Z]{16}|ASIA[0-9A-Z]{16}|aws_secret_access_key\s*[=:]\s*["\'][^"\']+|aws_access_key_id\s*[=:]\s*["\'][^"\']+)',
        "severity": Severity.CRITICAL
    },
    {
        "name": "AWS ARN/Resource",
        "pattern": r'arn:aws:[a-z0-9-]+:[a-z0-9-]*:\d{12}:',
        "severity": Severity.MEDIUM
    },
    {
        "name": "Azure Credentials",
        "pattern": r'(AccountKey\s*=\s*[a-zA-Z0-9+/=]{20,}|SharedAccessSignature\s*=\s*[^\s;]+|DefaultEndpointsProtocol=https;AccountName=[^;]+;AccountKey=)',
        "severity": Severity.CRITICAL
    },
    {
        "name": "GCP Credentials",
        "pattern": r'("type"\s*:\s*"service_account"|"private_key_id"\s*:\s*"[a-f0-9]+"|AIza[0-9A-Za-z_-]{35})',
        "severity": Severity.CRITICAL
    },
    {
        "name": "DigitalOcean Token",
        "pattern": r'(dop_v1_[a-f0-9]{64}|doo_v1_[a-f0-9]{64})',
        "severity": Severity.CRITICAL
    },
    {
        "name": "Heroku API Key",
        "pattern": r'[hH]eroku[_-]?(api[_-]?key|auth[_-]?token)\s*[=:]\s*["\']?[a-f0-9-]{36}',
        "severity": Severity.CRITICAL
    },

    # =============================================================================
    # API KEYS & TOKENS
    # =============================================================================
    {
        "name": "GitHub Token",
        "pattern": r'(ghp_[a-zA-Z0-9]{36}|gho_[a-zA-Z0-9]{36}|ghu_[a-zA-Z0-9]{36}|ghs_[a-zA-Z0-9]{36}|ghr_[a-zA-Z0-9]{36}|github_pat_[a-zA-Z0-9]{22}_[a-zA-Z0-9]{59})',
        "severity": Severity.CRITICAL
    },
    {
        "name": "GitLab Token",
        "pattern": r'(glpat-[a-zA-Z0-9_-]{20,}|gldt-[a-zA-Z0-9_-]{20,}|GR1348941[a-zA-Z0-9_-]{20,})',
        "severity": Severity.CRITICAL
    },
    {
        "name": "Stripe API Key",
        "pattern": r'(sk_live_[a-zA-Z0-9]{24,}|sk_test_[a-zA-Z0-9]{24,}|rk_live_[a-zA-Z0-9]{24,}|rk_test_[a-zA-Z0-9]{24,})',
        "severity": Severity.CRITICAL
    },
    {
        "name": "PayPal/Braintree",
        "pattern": r'(access_token\$production\$[a-z0-9]{16}\$[a-f0-9]{32}|paypal[_-]?(client[_-]?secret)\s*[=:]\s*["\'][^"\']+|braintree[_-]?(private)[_-]?key\s*[=:]\s*["\'][^"\']+)',
        "severity": Severity.CRITICAL
    },
    {
        "name": "Twilio Credentials",
        "pattern": r'(twilio[_-]?(account[_-]?sid|auth[_-]?token)\s*[=:]\s*["\'][^"\']+|SK[a-f0-9]{32}(?=\s|"|\'|$))',
        "severity": Severity.CRITICAL
    },
    {
        "name": "SendGrid API Key",
        "pattern": r'SG\.[a-zA-Z0-9_-]{22}\.[a-zA-Z0-9_-]{43}',
        "severity": Severity.CRITICAL
    },
    {
        "name": "Mailgun API Key",
        "pattern": r'(key-[a-f0-9]{32}|api:[a-f0-9]{32}@api\.mailgun\.net)',
        "severity": Severity.CRITICAL
    },
    {
        "name": "Slack Token",
        "pattern": r'xox[baprs]-[0-9]{10,}-[0-9A-Za-z]{10,}',
        "severity": Severity.CRITICAL
    },
    {
        "name": "Slack Webhook",
        "pattern": r'https://hooks\.slack\.com/services/T[A-Z0-9]{8,}/B[A-Z0-9]{8,}/[a-zA-Z0-9]{24}',
        "severity": Severity.HIGH
    },
    {
        "name": "Discord Token/Webhook",
        "pattern": r'(https://discord(app)?\.com/api/webhooks/\d{17,}/[a-zA-Z0-9_-]{60,}|[MN][a-zA-Z0-9_-]{23,}\.[a-zA-Z0-9_-]{6}\.[a-zA-Z0-9_-]{27,})',
        "severity": Severity.HIGH
    },
    {
        "name": "Telegram Bot Token",
        "pattern": r'\d{9,10}:[a-zA-Z0-9_-]{35}',
        "severity": Severity.HIGH
    },
    {
        "name": "Firebase/Google API",
        "pattern": r'AIza[0-9A-Za-z_-]{35}',
        "severity": Severity.HIGH
    },
    {
        "name": "NPM Token",
        "pattern": r'(npm_[a-zA-Z0-9]{36}|//registry\.npmjs\.org/:_authToken=[a-zA-Z0-9-]+)',
        "severity": Severity.CRITICAL
    },
    {
        "name": "PyPI Token",
        "pattern": r'pypi-AgEIcHlwaS5vcmc[a-zA-Z0-9_-]{50,}',
        "severity": Severity.CRITICAL
    },
    {
        "name": "Docker Registry Auth",
        "pattern": r'(docker[_-]?password\s*[=:]\s*["\'][^"\']+|DOCKER_AUTH_CONFIG\s*=)',
        "severity": Severity.HIGH
    },
    {
        "name": "JWT Token",
        "pattern": r'eyJ[a-zA-Z0-9_-]{10,}\.eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{20,}',
        "severity": Severity.MEDIUM
    },
    {
        "name": "Basic Auth Header",
        "pattern": r'Authorization:\s*Basic\s+[A-Za-z0-9+/=]{20,}',
        "severity": Severity.HIGH
    },
    {
        "name": "Bearer Token Header",
        "pattern": r'Authorization:\s*Bearer\s+[a-zA-Z0-9_-]{20,}',
        "severity": Severity.MEDIUM
    },

    # =============================================================================
    # DATABASE
    # =============================================================================
    {
        "name": "SQL Query Pattern",
        "pattern": r'(SELECT\s+[\w\*,\s]+\s+FROM\s+\w+|INSERT\s+INTO\s+\w+\s*\(|UPDATE\s+\w+\s+SET\s+\w+|DELETE\s+FROM\s+\w+\s+WHERE|DROP\s+(TABLE|DATABASE)\s+\w+|TRUNCATE\s+TABLE\s+\w+)',
        "severity": Severity.MEDIUM
    },
    {
        "name": "Database Connection URI",
        "pattern": r'(mongodb(\+srv)?://[^"\'\s]+@[^"\'\s]+|postgres(ql)?://[^"\'\s]+@[^"\'\s]+|mysql://[^"\'\s]+@[^"\'\s]+|redis://[^"\'\s]+@[^"\'\s]+|mssql://[^"\'\s]+@[^"\'\s]+|jdbc:[a-z]+://[^"\'\s]+)',
        "severity": Severity.HIGH
    },
    {
        "name": "Database Password in URI",
        "pattern": r'(mongodb|postgres|mysql|redis|mssql)(\+srv)?://[^:"\'\s]+:[^@"\'\s]+@[^"\'\s]+',
        "severity": Severity.CRITICAL
    },

    # =============================================================================
    # DESERIALIZATION (RCE VECTORS)
    # =============================================================================
    {
        "name": "Deserialization - .NET Critical (RCE)",
        "pattern": r'(BinaryFormatter|ObjectStateFormatter|NetDataContractSerializer|LosFormatter|SoapFormatter|TypeNameHandling|set_TypeNameHandling|XamlReader|XamlServices|ObjectDataProvider|ActivitySurrogateSelector|WindowsIdentity|ClaimsPrincipal|RolePrincipal|WindowsPrincipal|GenericPrincipal|ysoserial)',
        "severity": Severity.CRITICAL
    },
    {
        "name": "Deserialization - .NET JSON (Review)",
        "pattern": r'(JsonConvert\.DeserializeObject|JsonSerializer\.Deserialize|Newtonsoft\.Json|System\.Text\.Json|JavaScriptSerializer|DataContractJsonSerializer|Json\.Decode|JObject\.Parse|JArray\.Parse|JsonTextReader)',
        "severity": Severity.HIGH
    },
    {
        "name": "Deserialization - .NET XML (Review)",
        "pattern": r'(XmlSerializer|DataContractSerializer|XmlObjectSerializer|XmlMessageFormatter|SoapFormatter|XmlTextReader|XDocument\.Load|XElement\.Load|XmlReader\.Create)',
        "severity": Severity.MEDIUM
    },
    {
        "name": "Deserialization - .NET Resources",
        "pattern": r'(ResourceReader|ResXResourceReader|ResXResourceSet|LooselyLinkedResourceReference)',
        "severity": Severity.MEDIUM
    },
    {
        "name": "Deserialization - .NET ViewState",
        "pattern": r'(LosFormatter|ObjectStateFormatter|ViewState|__VIEWSTATE|EnableViewStateMac\s*=\s*false|ViewStateEncryptionMode)',
        "severity": Severity.CRITICAL
    },
    {
        "name": "Deserialization - .NET Remoting",
        "pattern": r'(BinaryServerFormatterSink|SoapServerFormatterSink|RemotingConfiguration|TcpChannel|HttpChannel|IpcChannel|ChannelServices\.RegisterChannel)',
        "severity": Severity.CRITICAL
    },
    {
        "name": "Deserialization - .NET WCF",
        "pattern": r'(DataContractSerializer|NetDataContractSerializer|XmlSerializer|DataContractJsonSerializer|ServiceHost|ChannelFactory|WcfServiceHost|OperationContract)',
        "severity": Severity.MEDIUM
    },
    {
        "name": "Deserialization - .NET Gadgets",
        "pattern": r'(TypeConfuseDelegate|TextFormattingRunProperties|PSObject|ClaimsIdentity|WindowsClaimsIdentity|SessionSecurityToken|RolePrincipal|AxHost\.State|DataSet|TypedTableBase)',
        "severity": Severity.CRITICAL
    },
    {
        "name": "Deserialization - Java Critical",
        "pattern": r'(ObjectInputStream|XMLDecoder|XStream|readObject|readUnshared|readExternal|ObjectMapper\.enableDefaultTyping|JsonTypeInfo\.Id\.CLASS|JsonTypeInfo\.Id\.MINIMAL_CLASS|SerializationConfig|DefaultTyping)',
        "severity": Severity.CRITICAL
    },
    {
        "name": "Deserialization - Java Libraries",
        "pattern": r'(SnakeYAML|Yaml\.load|yaml\.unsafe_load|Kryo|Hessian2Input|Hessian2Output|BurlapInput|Castor|Marshaller|Unmarshaller|XMLBeanInfo|JBossMarshaller|JBossUnmarshaller)',
        "severity": Severity.HIGH
    },
    {
        "name": "Deserialization - Java Gadgets",
        "pattern": r'(CommonsCollections|CommonsBeanutils|CommonsLogging|Spring\d|Hibernate|JBossInterceptors|JavassistWeld|Jdk7u21|URLDNS|Wicket|FileUpload|Clojure|C3P0|JRMP|JRMPClient|JRMPListener)',
        "severity": Severity.CRITICAL
    },
    {
        "name": "Deserialization - PHP",
        "pattern": r'(unserialize\s*\(|__wakeup|__destruct|__toString|PharData|phar://|Serializable|JsonSerializable)',
        "severity": Severity.HIGH
    },
    {
        "name": "Deserialization - Python",
        "pattern": r'(pickle\.(loads?|dump|Unpickler)|cPickle\.(loads?|dump)|_pickle\.(loads?|dump)|dill\.(loads?|dump)|shelve\.open|marshal\.(loads?|dump)|yaml\.load|yaml\.unsafe_load|yaml\.full_load|jsonpickle\.(decode|encode))',
        "severity": Severity.HIGH
    },
    {
        "name": "Deserialization - Ruby",
        "pattern": r'(Marshal\.(load|dump|restore)|YAML\.(load|unsafe_load)|Psych\.(load|unsafe_load)|Oj\.(load|dump)|Ox\.(load|parse))',
        "severity": Severity.HIGH
    },
    {
        "name": "Deserialization - Node.js",
        "pattern": r'(node-serialize|serialize-javascript|cryo\.(parse|stringify)|funcster|js-yaml\.load|fast-json-stringify)',
        "severity": Severity.HIGH
    },
    {
        "name": "Deserialization - Magic Bytes/Signatures",
        "pattern": r'(aced0005|rO0AB|H4sIA[A-Za-z0-9+/]{20,}|O:[0-9]+:"[a-zA-Z]|a:[0-9]+:\{|YTo[0-9]|Tz[0-9]+:|gANj|gASV|\x89HDF)',
        "severity": Severity.HIGH
    },
    {
        "name": "Deserialization - Dangerous Interfaces",
        "pattern": r'(ISerializable|IDeserializationCallback|IObjectReference|IFormatter|ISurrogateSelector|SerializationBinder|SerializationInfo|StreamingContext)',
        "severity": Severity.MEDIUM
    },
    {
        "name": "Deserialization - Type Resolution",
        "pattern": r'(Type\.GetType|Assembly\.GetType|Activator\.CreateInstance|FormatterServices\.GetUninitializedObject|AppDomain\.CreateInstance|Type\.InvokeMember|BindToType)',
        "severity": Severity.HIGH
    },

    # =============================================================================
    # WEAK CRYPTOGRAPHY
    # =============================================================================
    {
        "name": "Weak Hash - MD5",
        "pattern": r'(MD5CryptoServiceProvider|MD5\.Create\s*\(|hashlib\.md5\s*\(|MessageDigest\.getInstance\s*\(\s*["\']MD5["\'])',
        "severity": Severity.MEDIUM
    },
    {
        "name": "Weak Hash - SHA1",
        "pattern": r'(SHA1CryptoServiceProvider|SHA1\.Create\s*\(|hashlib\.sha1\s*\(|MessageDigest\.getInstance\s*\(\s*["\']SHA-?1["\'])',
        "severity": Severity.MEDIUM
    },
    {
        "name": "Weak Encryption - DES/3DES",
        "pattern": r'(DESCryptoServiceProvider|TripleDESCryptoServiceProvider|DES\.Create\s*\(|Cipher\.getInstance\s*\(\s*["\']DES)',
        "severity": Severity.MEDIUM
    },
    {
        "name": "Weak Encryption - RC4",
        "pattern": r'Cipher\.getInstance\s*\(\s*["\']RC4',
        "severity": Severity.MEDIUM
    },
    {
        "name": "Weak Encryption Mode - ECB",
        "pattern": r'(CipherMode\.ECB|Cipher\.getInstance\s*\(\s*["\'][^"\']+/ECB/)',
        "severity": Severity.MEDIUM
    },
    {
        "name": "Insecure Random for Crypto",
        "pattern": r'(new\s+Random\s*\(\s*\)\.Next|Math\.random\s*\(\s*\)\s*\*|rand\s*\(\s*\)\s*%)',
        "severity": Severity.MEDIUM
    },
    {
        "name": "Hardcoded IV/Nonce",
        "pattern": r'(IV\s*=\s*new\s+byte\s*\[\s*\]\s*\{|IV\s*=\s*["\'][0-9a-fA-F]{16,}["\']|nonce\s*=\s*["\'][^"\']{8,}["\'])',
        "severity": Severity.MEDIUM
    },

    # =============================================================================
    # COMMAND/CODE EXECUTION
    # =============================================================================
    {
        "name": "Process Execution - .NET",
        "pattern": r'(Process\.Start\s*\(|new\s+ProcessStartInfo\s*\(|System\.Diagnostics\.Process\.Start)',
        "severity": Severity.HIGH
    },
    {
        "name": "Process Execution - Java",
        "pattern": r'(Runtime\.getRuntime\s*\(\s*\)\.exec\s*\(|new\s+ProcessBuilder\s*\()',
        "severity": Severity.HIGH
    },
    {
        "name": "Process Execution - Python",
        "pattern": r'(subprocess\.(run|call|Popen|check_output)\s*\(|os\.(system|popen|exec\w*|spawn\w*)\s*\()',
        "severity": Severity.HIGH
    },
    {
        "name": "Process Execution - PHP",
        "pattern": r'(exec\s*\(\s*\$|shell_exec\s*\(\s*\$|system\s*\(\s*\$|passthru\s*\(\s*\$|popen\s*\(\s*\$|proc_open\s*\()',
        "severity": Severity.HIGH
    },
    {
        "name": "Process Execution - Node.js",
        "pattern": r'(child_process\.(exec|execSync|spawn|spawnSync|execFile)\s*\(|require\s*\(\s*["\']child_process["\'])',
        "severity": Severity.HIGH
    },
    {
        "name": "Process Execution - Ruby",
        "pattern": r'(Kernel\.system\s*\(|Kernel\.exec\s*\(|IO\.popen\s*\(|Open3\.(capture|popen))',
        "severity": Severity.HIGH
    },
    {
        "name": "Process Execution - Go",
        "pattern": r'(exec\.Command\s*\(|exec\.CommandContext\s*\()',
        "severity": Severity.HIGH
    },
    {
        "name": "PowerShell Execution",
        "pattern": r'(System\.Management\.Automation|AddScript\s*\(|Invoke-Expression|IEX\s*\(|DownloadString\s*\(|EncodedCommand)',
        "severity": Severity.HIGH
    },
    {
        "name": "Shell References",
        "pattern": r'(cmd\.exe\s+/c|/bin/(sh|bash|zsh)\s+-c|powershell\.exe\s+-)',
        "severity": Severity.MEDIUM
    },

    # =============================================================================
    # DYNAMIC CODE EXECUTION
    # =============================================================================
    {
        "name": "Eval/Dynamic Code - JavaScript",
        "pattern": r'(\beval\s*\(\s*[^)]+\)|new\s+Function\s*\(\s*[^)]+\)|setTimeout\s*\(\s*["\'][^"\']+["\']|setInterval\s*\(\s*["\'][^"\']+["\'])',
        "severity": Severity.HIGH
    },
    {
        "name": "Eval/Dynamic Code - Python",
        "pattern": r'(\beval\s*\(\s*[^)]+\)|\bexec\s*\(\s*[^)]+\)|compile\s*\(\s*[^)]+,\s*[^)]+,\s*["\']exec["\'])',
        "severity": Severity.HIGH
    },
    {
        "name": "Eval/Dynamic Code - PHP",
        "pattern": r'(\beval\s*\(\s*\$|assert\s*\(\s*\$|create_function\s*\(|preg_replace\s*\([^)]*["\']/[^/]*e[imsuxADSUXJ]*["\'])',
        "severity": Severity.HIGH
    },
    {
        "name": "Eval/Dynamic Code - Ruby",
        "pattern": r'(\beval\s*\(\s*[^)]+\)|instance_eval\s*\(|class_eval\s*\(|module_eval\s*\()',
        "severity": Severity.HIGH
    },
    {
        "name": "Script Engine - Java",
        "pattern": r'(ScriptEngineManager\s*\(\s*\)\.getEngineByName|ScriptEngine\.eval\s*\(|javax\.script\.ScriptEngine)',
        "severity": Severity.HIGH
    },
    {
        "name": "Expression Language",
        "pattern": r'(SpelExpressionParser\s*\(\s*\)\.parseExpression|ELProcessor\.eval|ExpressionFactory\.createValueExpression)',
        "severity": Severity.HIGH
    },

    # =============================================================================
    # REFLECTION & DYNAMIC LOADING
    # =============================================================================
    {
        "name": "Reflection - .NET Dynamic Invoke",
        "pattern": r'(\.GetMethod\s*\([^)]+\)\.Invoke|Type\.GetType\s*\([^)]+\)\.GetMethod|Activator\.CreateInstance\s*\(|Assembly\.Load(From|File)?\s*\()',
        "severity": Severity.MEDIUM
    },
    {
        "name": "Reflection - Java",
        "pattern": r'(Class\.forName\s*\([^)]+\)\.getMethod|\.getMethod\s*\([^)]+\)\.invoke|setAccessible\s*\(\s*true\s*\))',
        "severity": Severity.MEDIUM
    },
    {
        "name": "Dynamic Compilation - .NET",
        "pattern": r'(CSharpCodeProvider\s*\(\s*\)|CompileAssemblyFromSource|Microsoft\.CodeAnalysis\.CSharp\.CSharpCompilation)',
        "severity": Severity.HIGH
    },
    {
        "name": "Dynamic Compilation - Java",
        "pattern": r'(ToolProvider\.getSystemJavaCompiler|JavaCompiler\.getTask|javax\.tools\.JavaCompiler)',
        "severity": Severity.HIGH
    },
    {
        "name": "Class Loading - Java",
        "pattern": r'(URLClassLoader\s*\(|defineClass\s*\(|ClassLoader\.loadClass\s*\()',
        "severity": Severity.HIGH
    },

    # =============================================================================
    # INJECTION VECTORS
    # =============================================================================
    {
        "name": "JNDI Lookup (Log4Shell)",
        "pattern": r'(\$\{jndi:(ldap|rmi|dns)://|InitialContext\s*\(\s*\)\.lookup\s*\(|Context\.lookup\s*\([^)]*\$)',
        "severity": Severity.CRITICAL
    },
    {
        "name": "LDAP Query",
        "pattern": r'(DirectorySearcher\s*\([^)]*\$|SearchRequest\s*\([^)]*\$|ldap_search\s*\([^)]*\$)',
        "severity": Severity.MEDIUM
    },
    {
        "name": "XPath Query",
        "pattern": r'(XPathExpression\.compile\s*\([^)]*\$|SelectNodes\s*\([^)]*\$|SelectSingleNode\s*\([^)]*\$)',
        "severity": Severity.MEDIUM
    },
    {
        "name": "XML External Entity (XXE)",
        "pattern": r'(<!ENTITY\s+\w+\s+SYSTEM|XmlReaderSettings\s*\{[^}]*DtdProcessing\s*=\s*DtdProcessing\.Parse|DocumentBuilderFactory[^;]*setFeature\s*\([^)]*false)',
        "severity": Severity.HIGH
    },
    {
        "name": "Prototype Pollution",
        "pattern": r'(__proto__\s*[=\[]|constructor\s*\[\s*["\']prototype|Object\.assign\s*\(\s*\{\s*\}\s*,\s*[^)]*req\.)',
        "severity": Severity.HIGH
    },

    # =============================================================================
    # FILE OPERATIONS
    # =============================================================================
    {
        "name": "File Read Operations",
        "pattern": r'(File\.ReadAll(Text|Bytes|Lines)\s*\(|StreamReader\s*\([^)]*\$|file_get_contents\s*\(\s*\$|fs\.readFile(Sync)?\s*\([^)]*req\.)',
        "severity": Severity.MEDIUM
    },
    {
        "name": "File Write Operations",
        "pattern": r'(File\.Write(All)?(Text|Bytes|Lines)\s*\(|StreamWriter\s*\([^)]*\$|file_put_contents\s*\(\s*\$|fs\.writeFile(Sync)?\s*\([^)]*req\.)',
        "severity": Severity.MEDIUM
    },
    {
        "name": "Path Traversal Indicators",
        "pattern": r'(\.\.[/\\]|\.\./|\.\.%2[fF]|%2e%2e%2f|%252e%252e%252f)',
        "severity": Severity.HIGH
    },
    {
        "name": "Archive Extraction",
        "pattern": r'(ZipFile\.ExtractToDirectory|ZipArchive\.ExtractToDirectory|extractall\s*\(|tar\s+-x)',
        "severity": Severity.MEDIUM
    },

    # =============================================================================
    # NETWORK & SSRF
    # =============================================================================
    {
        "name": "External URL",
        "pattern": r'https?://(?!localhost|127\.0\.0\.1|0\.0\.0\.0)[a-zA-Z0-9][-a-zA-Z0-9]*\.[a-zA-Z]{2,}[^\s"\']*',
        "severity": Severity.INFO
    },
    {
        "name": "Internal Network Access",
        "pattern": r'(192\.168\.\d{1,3}\.\d{1,3}|10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(1[6-9]|2[0-9]|3[01])\.\d{1,3}\.\d{1,3})(?::\d+)?[/\w]*',
        "severity": Severity.MEDIUM
    },
    {
        "name": "Cloud Metadata Endpoints",
        "pattern": r'(169\.254\.169\.254|metadata\.google\.internal|metadata\.azure\.com|100\.100\.100\.200)',
        "severity": Severity.HIGH
    },
    {
        "name": "SSRF Indicators",
        "pattern": r'(HttpClient\.GetAsync\s*\([^)]*\$|WebRequest\.Create\s*\([^)]*\$|requests\.(get|post)\s*\([^)]*request\.|fetch\s*\([^)]*req\.)',
        "severity": Severity.HIGH
    },

    # =============================================================================
    # AUTHENTICATION & SESSION
    # =============================================================================
    {
        "name": "Hardcoded Admin Credentials",
        "pattern": r'(admin|root|administrator)\s*[=:]\s*["\'][^"\']{4,}["\']',
        "severity": Severity.HIGH
    },
    {
        "name": "Session Fixation Risk",
        "pattern": r'(session_id\s*\(\s*\$|Session\.SessionID\s*=|req\.session\.id\s*=)',
        "severity": Severity.MEDIUM
    },
    {
        "name": "Insecure Cookie",
        "pattern": r'(setcookie\s*\([^)]*false\s*\)|Cookie\s*\{[^}]*(Secure|HttpOnly)\s*=\s*false)',
        "severity": Severity.MEDIUM
    },
    {
        "name": "OAuth Secret",
        "pattern": r'(client_secret\s*[=:]\s*["\'][a-zA-Z0-9_-]{10,}["\'])',
        "severity": Severity.HIGH
    },

    # =============================================================================
    # LOGGING & DEBUG
    # =============================================================================
    {
        "name": "Debug Mode Enabled",
        "pattern": r'(DEBUG\s*=\s*[Tt]rue|debug\s*:\s*true|FLASK_DEBUG\s*=\s*1|APP_DEBUG\s*=\s*true|NODE_ENV\s*[=:]\s*["\']development["\'])',
        "severity": Severity.MEDIUM
    },
    {
        "name": "Stack Trace Exposure",
        "pattern": r'(printStackTrace\s*\(|customErrors\s+mode\s*=\s*["\']Off|IncludeExceptionDetailInFaults\s*=\s*true)',
        "severity": Severity.MEDIUM
    },

    # =============================================================================
    # MOBILE SPECIFIC
    # =============================================================================
    {
        "name": "Android Sensitive Permissions",
        "pattern": r'android\.permission\.(READ_SMS|RECEIVE_SMS|READ_CONTACTS|ACCESS_FINE_LOCATION|CAMERA|RECORD_AUDIO|READ_CALL_LOG)',
        "severity": Severity.MEDIUM
    },
    {
        "name": "iOS Keychain",
        "pattern": r'(kSecAttrAccessibleAlways|kSecAttrAccessibleAfterFirstUnlock|SecItemCopyMatching)',
        "severity": Severity.MEDIUM
    },
    {
        "name": "Certificate Pinning Bypass",
        "pattern": r'(ALLOW_ALL_HOSTNAME_VERIFIER|trustAllCerts|setHostnameVerifier\s*\(\s*null|checkServerTrusted\s*\([^)]*\)\s*\{\s*\})',
        "severity": Severity.HIGH
    },

    # =============================================================================
    # DANGEROUS IMPORTS (INFO ONLY)
    # =============================================================================
    {
        "name": "Dangerous .NET Import",
        "pattern": r'using\s+(System\.Reflection\.Emit|System\.Runtime\.InteropServices|System\.Diagnostics\.Process)',
        "severity": Severity.INFO
    },
    {
        "name": "Dangerous Java Import",
        "pattern": r'import\s+(java\.lang\.reflect\.\*|java\.lang\.Runtime|java\.io\.ObjectInputStream|javax\.script\.\*)',
        "severity": Severity.INFO
    },
    {
        "name": "Dangerous Python Import",
        "pattern": r'^import\s+(pickle|subprocess|ctypes|marshal)$|^from\s+(pickle|subprocess|ctypes|marshal)\s+import',
        "severity": Severity.INFO
    },

    # =============================================================================
    # SENSITIVE DATA (Reduced False Positives)
    # =============================================================================
    {
        "name": "Hardcoded IP (Non-Local)",
        "pattern": r'(?<![0-9])(?!0\.0\.0\.0|127\.0\.0\.1|255\.255\.255\.\d|1\.0\.0\.0|Version[=\s])([1-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])(?![0-9]|\.0\.0)',
        "severity": Severity.INFO
    },
    {
        "name": "Email Address",
        "pattern": r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.(com|org|net|io|edu|gov|co|us|uk|de|fr)',
        "severity": Severity.INFO
    },
    {
        "name": "Sensitive File Reference",
        "pattern": r'(/etc/(passwd|shadow|hosts)|\.htpasswd|web\.config|appsettings\.(json|xml)|\.env(?:\.local)?|\.git/config|id_rsa)',
        "severity": Severity.MEDIUM
    },
    {
        "name": "Windows Registry Access",
        "pattern": r'(Registry\.(GetValue|SetValue|LocalMachine|CurrentUser)|RegOpenKey(Ex)?|RegSetValue(Ex)?)',
        "severity": Severity.MEDIUM
    },
    {
        "name": "High Entropy String (Potential Secret)",
        "pattern": r'["\'][a-zA-Z0-9+/]{40,}={0,2}["\']',
        "severity": Severity.INFO
    }

]

def get_platform() -> str:
    """Detect current platform"""
    system = platform.system().lower()
    if system == "windows":
        return "windows"
    elif system == "linux":
        # Check if Kali
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
    # Check for ilspycmd (CLI version)
    ilspy_names = ["ilspycmd", "ilspy"]

    for name in ilspy_names:
        path = shutil.which(name)
        if path:
            return path

    # Common installation paths on Kali/Linux
    common_paths = [
        "/usr/bin/ilspycmd",
        "/usr/local/bin/ilspycmd",
        "/opt/ilspy/ilspycmd",
        os.path.expanduser("~/.dotnet/tools/ilspycmd"),
        "/root/.dotnet/tools/ilspycmd",
    ]

    for path in common_paths:
        if os.path.exists(path):
            return path

    return None

def find_dnspy() -> Optional[str]:
    """Find dnSpy on Windows"""
    if get_platform() != "windows":
        return None

    common_paths = [
        r"C:\Tools\dnSpy\dnSpy.Console.exe",
        r"C:\Program Files\dnSpy\dnSpy.Console.exe",
        r"C:\dnSpy\dnSpy.Console.exe",
        os.path.expandvars(r"%USERPROFILE%\Tools\dnSpy\dnSpy.Console.exe"),
    ]

    for path in common_paths:
        if os.path.exists(path):
            return path

    # Check PATH
    dnspy = shutil.which("dnSpy.Console.exe") or shutil.which("dnSpy.Console")
    return dnspy

class DotNetDecompiler:
    """Cross-platform .NET DLL decompiler"""

    def __init__(self, verbose: bool = False):
        self.verbose = verbose
        self.platform = get_platform()
        self.ilspy_path = find_ilspy()
        self.dnspy_path = find_dnspy()

    def is_available(self) -> bool:
        """Check if decompiler is available"""
        return self.ilspy_path is not None or self.dnspy_path is not None

    def get_tool_info(self) -> str:
        """Get info about available decompiler"""
        if self.ilspy_path:
            return f"ILSpy: {self.ilspy_path}"
        if self.dnspy_path:
            return f"dnSpy: {self.dnspy_path}"
        return "No .NET decompiler found"

    def decompile(self, dll_path: str) -> Optional[str]:
        """Decompile DLL to C# source code"""
        if self.ilspy_path:
            return self._decompile_ilspy(dll_path)
        elif self.dnspy_path:
            return self._decompile_dnspy(dll_path)
        else:
            if self.verbose:
                print("[!] No .NET decompiler available. Install ilspycmd:")
                print("    dotnet tool install -g ilspycmd")
            return None

    def _decompile_ilspy(self, dll_path: str) -> Optional[str]:
        """Decompile using ILSpy"""
        try:
            with tempfile.TemporaryDirectory() as temp_dir:
                output_dir = os.path.join(temp_dir, "decompiled")
                os.makedirs(output_dir, exist_ok=True)

                cmd = [
                    self.ilspy_path,
                    dll_path,
                    "-o", output_dir,
                    "-p"  # Decompile to project
                ]

                result = subprocess.run(
                    cmd,
                    capture_output=True,
                    text=True,
                    timeout=120
                )

                if result.returncode != 0:
                    # Try simpler command
                    cmd = [self.ilspy_path, dll_path, "-o", output_dir]
                    result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)

                # Read all decompiled files
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

                # Fallback: try to get output directly
                if result.stdout:
                    return result.stdout

        except subprocess.TimeoutExpired:
            if self.verbose:
                print(f"[!] Decompilation timeout for {dll_path}")
        except Exception as e:
            if self.verbose:
                print(f"[!] ILSpy decompilation error: {e}")

        return None

    def _decompile_dnspy(self, dll_path: str) -> Optional[str]:
        """Decompile using dnSpy (Windows)"""
        try:
            with tempfile.TemporaryDirectory() as temp_dir:
                output_dir = os.path.join(temp_dir, "decompiled")
                os.makedirs(output_dir, exist_ok=True)

                cmd = [
                    self.dnspy_path,
                    dll_path,
                    "--output", output_dir,
                    "--lang", "csharp"
                ]

                result = subprocess.run(
                    cmd,
                    capture_output=True,
                    text=True,
                    timeout=120
                )

                # Read all decompiled files
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
                print(f"[!] dnSpy decompilation error: {e}")

        return None

class VulnerabilityScanner:
    """Advanced vulnerability scanner with binary analysis support"""

    DEFAULT_EXCLUDE_DIRS = {
        'node_modules', '.git', '__pycache__', 'venv', 'env', '.venv',
        'dist', 'build', '.idea', '.vscode', 'vendor', 'target', 'bin',
        'obj', '.next', 'coverage', '.tox', '.pytest_cache', '.mypy_cache',
        'site-packages', '.gradle', '.m2', 'packages', '.nuget', '.cache',
        # Test directories - often contain intentional "vulnerable" code
        'tests', 'test', '__tests__', 'spec', 'specs', 'test_files',
        # Documentation
        'docs', 'doc', 'documentation',
        # External/third-party libraries
        'external', 'third_party', 'third-party', 'thirdparty', 'lib', 'libs',
        # CI/CD directories
        '.travis', '.github', '.circleci', '.gitlab', 'ci', '.ci',
        # Demo/example code
        'demo', 'demos', 'example', 'examples', 'sample', 'samples',
    }

    DEFAULT_EXCLUDE_FILES = {
        'package-lock.json', 'yarn.lock', 'composer.lock', 'Gemfile.lock',
        'poetry.lock', 'Cargo.lock', 'go.sum', 'pnpm-lock.yaml',
        # Scanner itself
        'vuln_scanner.py', 'vuln-scanner.py', 'scanner.py', 'Parsedown.php', 'recaptchalib.php',
        # Common JS libraries - reduce false positives
        'jquery.js', 'jquery.min.js', 'jquery-3.7.1.js', 'jquery-3.7.1.min.js',
        'jquery-3.7.1.slim.js', 'jquery-3.7.1.slim.min.js',
        'jquery.validate.js', 'jquery.validate.min.js',
        'jquery.validate.unobtrusive.js', 'jquery.validate.unobtrusive.min.js',
        'jquery.validate-vsdoc.js', 'jquery-3.7.1.intellisense.js',
        'bootstrap.js', 'bootstrap.min.js', 'bootstrap.esm.js', 'bootstrap.bundle.js',
        'bootstrap.bundle.min.js',
        'modernizr.js', 'modernizr-2.8.3.js',
        'react.js', 'react.min.js', 'react-dom.js', 'react-dom.min.js',
        'vue.js', 'vue.min.js', 'angular.js', 'angular.min.js',
        # Additional libraries
        'leaflet.js', 'leaflet.min.js',
        'lodash.js', 'lodash.min.js', 'underscore.js', 'underscore.min.js',
        'd3.js', 'd3.min.js',
        'moment.js', 'moment.min.js',
        'axios.js', 'axios.min.js',
        'chart.js', 'chart.min.js',
        'three.js', 'three.min.js',
        'socket.io.js', 'socket.io.min.js',
        'popper.js', 'popper.min.js',
        'summernote.js', 'summernote.min.js',
        'codemirror.js', 'codemirror.min.js',
        'fullcalendar.js', 'fullcalendar.min.js',
        'datatables.js', 'datatables.min.js',
        'select2.js', 'select2.min.js',
        'toastr.js', 'toastr.min.js',
        'sweetalert.js', 'sweetalert.min.js', 'sweetalert2.js', 'sweetalert2.min.js',
        'qunit.js', 'qunit.min.js',
        'mocha.js', 'mocha.min.js',
        'chai.js', 'chai.min.js',
        'jasmine.js', 'jasmine.min.js',
        'sinon.js', 'sinon.min.js',
        'clusterize.js', 'clusterize.min.js',
        'snap.svg.js', 'snap.svg-min.js',
        'photoswipe.js', 'photoswipe.min.js',
        'microtemplate.js',
        'json2.js',
        'jscolor.js',
        'frappe-datatable.js', 'frappe-datatable.min.js',
        # PHP Libraries
        'Parsedown.php', 'parsedown.php',
        'PHPMailer.php', 'phpmailer.php',
        'Smarty.class.php',
        'tcpdf.php', 'TCPDF.php',
        'fpdf.php', 'FPDF.php',
        'dompdf.php',
        'recaptchalib.php',
    }

    DEFAULT_EXCLUDE_PATTERNS = {
        '*.min.js', '*.min.css', '*.map', '*.bundle.js', '*.bundle.min.js',
        '*.test.js', '*.spec.js', '*.test.ts', '*.spec.ts',
        'test_*.py', '*_test.py', '*_test.go', '*_test.rb',
        '*.d.ts',
    }

    BINARY_EXTENSIONS = {'.dll', '.exe', '.so', '.dylib', '.bin', '.o', '.a', '.lib'}
    ARCHIVE_EXTENSIONS = {'.jar', '.war', '.ear', '.zip', '.apk', '.aar', '.nupkg'}
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

        # Initialize decompiler if needed
        self.decompiler = DotNetDecompiler(verbose) if decompile_dotnet else None

        # Category filtering
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
                "xxe": VulnCategory.XXE,
            }
            self.active_categories = {category_map[c] for c in categories if c in category_map}

        # Exclusions
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
        """Check if path should be skipped"""
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
        """Get relevant source code extensions"""
        extensions = set()
        for pattern in VULNERABILITY_PATTERNS:
            if self.active_categories is None or pattern.category in self.active_categories:
                extensions.update(pattern.languages)
        return extensions

    def is_binary_file(self, file_path: str) -> bool:
        """Check if file is a binary"""
        return Path(file_path).suffix.lower() in self.BINARY_EXTENSIONS

    def is_dotnet_binary(self, file_path: str) -> bool:
        """Check if file is a .NET binary"""
        return Path(file_path).suffix.lower() in self.DOTNET_EXTENSIONS

    def is_archive_file(self, file_path: str) -> bool:
        """Check if file is an archive"""
        return Path(file_path).suffix.lower() in self.ARCHIVE_EXTENSIONS

    def extract_strings_from_binary(self, file_path: str, min_length: int = 4) -> List[Tuple[int, str]]:
        """Extract printable strings from binary file"""
        strings_found = []

        # Try using 'strings' command (available on Kali/Linux and Windows with GNU tools)
        strings_cmd = "strings" if self.platform != "windows" else "strings.exe"
        try:
            result = subprocess.run(
                [strings_cmd, '-n', str(min_length), file_path],
                capture_output=True,
                text=True,
                timeout=60
    )
            if result.returncode == 0:
                for idx, line in enumerate(result.stdout.split('\n'), 1):
                    if line.strip():
                        strings_found.append((idx, line.strip()))
                return strings_found
        except (subprocess.SubprocessError, FileNotFoundError):
            pass

        # Fallback: manual extraction
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

            if len(current_string) >= min_length:
                strings_found.append((string_start, ''.join(current_string)))

        except Exception as e:
            if self.verbose:
                print(f"[!] Error reading binary {file_path}: {e}")

        return strings_found

    def scan_decompiled_source(self, source: str, original_file: str) -> List[Finding]:
        """Scan decompiled C# source for vulnerabilities"""
        findings = []
        lines = source.split('\n')

        for line_num, line in enumerate(lines, 1):
            if not line.strip():
                continue

            for vuln_pattern in VULNERABILITY_PATTERNS:
                if self.active_categories and vuln_pattern.category not in self.active_categories:
                    continue

                if ".cs" not in vuln_pattern.languages:
                    continue

                for pattern in vuln_pattern.patterns:
                    try:
                        if re.search(pattern, line, re.IGNORECASE):
                            is_fp = any(
                                re.search(fp, line, re.IGNORECASE)
                                for fp in vuln_pattern.false_positive_patterns
                            )
                            if not is_fp:
                                findings.append(Finding(
                                    file_path=f"{original_file} (decompiled)",
                                    line_number=line_num,
                                    line_content=line.strip()[:200],
                                    vulnerability_name=vuln_pattern.name,
                                    category=vuln_pattern.category,
                                    severity=vuln_pattern.severity,
                                ))
                                break
                    except re.error:
                        continue

        return findings

    def scan_binary(self, file_path: str) -> List[Finding]:
        """Scan a binary file for suspicious patterns"""
        findings = []

        if self.verbose:
            print(f"[*] Analyzing binary: {file_path}")

        # For .NET binaries, try decompilation first
        if self.decompile_dotnet and self.is_dotnet_binary(file_path) and self.decompiler:
            if self.decompiler.is_available():
                if self.verbose:
                    print(f"[*] Decompiling with {self.decompiler.get_tool_info()}")

                source = self.decompiler.decompile(file_path)
                if source:
                    findings.extend(self.scan_decompiled_source(source, file_path))
                    if findings:
                        self.binaries_scanned += 1
                        return findings

        # Fallback to string extraction
        strings = self.extract_strings_from_binary(file_path)

        for offset, string_content in strings:
            for pattern_info in BINARY_PATTERNS:
                try:
                    if re.search(pattern_info["pattern"], string_content, re.IGNORECASE):
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

    def scan_archive(self, archive_path: str) -> List[Finding]:
        """Scan archive for vulnerabilities"""
        findings = []

        if self.verbose:
            print(f"[*] Analyzing archive: {archive_path}")

        try:
            with zipfile.ZipFile(archive_path, 'r') as zf:
                for file_info in zf.filelist:
                    if file_info.file_size > 10 * 1024 * 1024:
                        continue
                    if file_info.filename.endswith('/'):
                        continue

                    try:
                        content = zf.read(file_info.filename)

                        try:
                            text_content = content.decode('utf-8', errors='ignore')
                            lines = text_content.split('\n')

                            inner_ext = Path(file_info.filename).suffix.lower()

                            for line_num, line in enumerate(lines, 1):
                                if not line.strip():
                                    continue

                                # Check binary patterns
                                for pattern_info in BINARY_PATTERNS:
                                    try:
                                        if re.search(pattern_info["pattern"], line, re.IGNORECASE):
                                            findings.append(Finding(
                                                file_path=f"{archive_path}!/{file_info.filename}",
                                                line_number=line_num,
                                                line_content=line.strip()[:200],
                                                vulnerability_name=f"Archive: {pattern_info['name']}",
                                                category=VulnCategory.BINARY_SUSPECT,
                                                severity=pattern_info["severity"],
                                            ))
                                    except re.error:
                                        continue

                                # Check vuln patterns for source files
                                if inner_ext in {'.java', '.kt', '.scala', '.cs', '.xml', '.properties', '.yml', '.yaml', '.json', '.js', '.py'}:
                                    for vuln_pattern in VULNERABILITY_PATTERNS:
                                        if self.active_categories and vuln_pattern.category not in self.active_categories:
                                            continue

                                        for pattern in vuln_pattern.patterns:
                                            try:
                                                if re.search(pattern, line, re.IGNORECASE):
                                                    is_fp = any(
                                                        re.search(fp, line, re.IGNORECASE)
                                                        for fp in vuln_pattern.false_positive_patterns
                                                    )
                                                    if not is_fp:
                                                        findings.append(Finding(
                                                            file_path=f"{archive_path}!/{file_info.filename}",
                                                            line_number=line_num,
                                                            line_content=line.strip()[:200],
                                                            vulnerability_name=vuln_pattern.name,
                                                            category=vuln_pattern.category,
                                                            severity=vuln_pattern.severity,
                                                        ))
                                                        break
                                            except re.error:
                                                continue
                        except:
                            pass
                    except:
                        continue
        except Exception as e:
            if self.verbose:
                print(f"[!] Error processing archive {archive_path}: {e}")

        return findings

    def scan_line(self, line: str, line_number: int, file_path: str,
                  extension: str) -> List[Finding]:
        """Scan a line for vulnerabilities"""
        findings = []
        stripped = line.strip()

        # Skip commented lines based on file type
        if extension in ['.py', '.rb', '.sh', '.bash', '.yaml', '.yml']:
            if stripped.startswith('#'):
                return findings
        elif extension in ['.js', '.ts', '.jsx', '.tsx', '.java', '.cs', '.go', '.kt', '.scala', '.c', '.cpp', '.h']:
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
        """Scan a single file"""
        if self.is_archive_file(file_path):
            if self.scan_binaries:
                return self.scan_archive(file_path)
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
        """Recursively scan directory"""
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
                is_archive = ext in self.ARCHIVE_EXTENSIONS

                if not is_binary and not is_archive and ext not in self.get_relevant_extensions():
                    continue

                if (is_binary or is_archive) and not self.scan_binaries:
                    continue

                self.files_scanned += 1

                if self.verbose:
                    ftype = "archive" if is_archive else ("binary" if is_binary else "source")
                    print(f"[*] Scanning ({ftype}): {file_path}")

                file_findings = self.scan_file(file_path)
                if file_findings:
                    self.files_with_findings.add(file_path)
                    all_findings.extend(file_findings)

        self.findings = all_findings
        self._calculate_stats()
        return all_findings

    def scan_target(self, target: str) -> List[Finding]:
        """Scan file or directory"""
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
        """Calculate statistics"""
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
        """Generate report"""
        if output_format == "json":
            return self._generate_json_report()
        return self._generate_text_report()

    def _generate_text_report(self) -> str:
        """Generate simplified text report - just line of code"""
        lines = []
        lines.append("=" * 80)
        lines.append("VULNERABILITY SCAN REPORT")
        lines.append("=" * 80)
        lines.append(f"Platform: {self.platform.upper()}")
        lines.append(f"Files scanned: {self.files_scanned} | Binaries: {self.binaries_scanned}")
        lines.append(f"Total findings: {len(self.findings)}")
        lines.append("")

        # Severity summary
        for sev in [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO]:
            count = self.stats["by_severity"].get(sev.value, 0)
            if count:
                lines.append(f"  {sev.value:10}: {count}")
        lines.append("")
        lines.append("=" * 80)

        # Group by file
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
        """Generate JSON report"""
        report = {
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
        description="Cross-Platform Vulnerability Scanner v3.0 (Windows/Kali)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Categories:
  sql, postgresql, nosql, xpath, deserialization, auth, ssti, ssrf, code/eval, xxe, all

Examples:
  python3 %(prog)s /path/to/project
  python %(prog)s C:\\Projects\\MyApp --scan-binaries --decompile
  python3 %(prog)s /path/to/project --category sql code auth
  python3 %(prog)s /path/to/app.dll --scan-binaries --decompile
  python3 %(prog)s /path/to/project --output json -o report.json

.NET DLL Analysis (requires ilspycmd):
  Install: dotnet tool install -g ilspycmd
        """
    )

    parser.add_argument("target", help="File or directory to scan")
    parser.add_argument("-o", "--output-file", help="Output file path")
    parser.add_argument("--output", choices=["text", "json"], default="text")
    parser.add_argument("-v", "--verbose", action="store_true")

    parser.add_argument(
        "--category", "-c", nargs="+",
        choices=["sql", "postgresql", "nosql", "xpath", "deserialization", "auth", "ssti", "ssrf", "code", "eval", "prototype", "pollution", "xxe", "all"],
        default=["all"], help="Categories to scan"
    )

    parser.add_argument("--scan-binaries", "-b", action="store_true",
                        help="Enable DLL/EXE/SO/JAR analysis")
    parser.add_argument("--decompile", "-d", action="store_true",
                        help="Decompile .NET DLLs using ILSpy/dnSpy")

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

    # ASCII Banner
    banner = """
██╗    ██╗ ██████╗ ██████╗ ██╗     ██████╗ ████████╗██████╗ ███████╗███████╗██████╗  ██████╗ ██╗   ██╗
██║    ██║██╔═══██╗██╔══██╗██║     ██╔══██╗╚══██╔══╝██╔══██╗██╔════╝██╔════╝██╔══██╗██╔═══██╗╚██╗ ██╔╝
██║ █╗ ██║██║   ██║██████╔╝██║     ██║  ██║   ██║   ██████╔╝█████╗  █████╗  ██████╔╝██║   ██║ ╚████╔╝ 
██║███╗██║██║   ██║██╔══██╗██║     ██║  ██║   ██║   ██╔══██╗██╔══╝  ██╔══╝  ██╔══██╗██║   ██║  ╚██╔╝  
╚███╔███╔╝╚██████╔╝██║  ██║███████╗██████╔╝   ██║   ██║  ██║███████╗███████╗██████╔╝╚██████╔╝   ██║   
 ╚══╝╚══╝  ╚═════╝ ╚═╝  ╚═╝╚══════╝╚═════╝    ╚═╝   ╚═╝  ╚═╝╚══════╝╚══════╝╚═════╝  ╚═════╝    ╚═╝   
                        ╔═╗┌─┐┬ ┬┬─┐┌─┐┌─┐  ╔═╗┌─┐┌┬┐┌─┐  ╔═╗┌─┐┌─┐┌┐┌┌┐┌┌─┐┬─┐
                        ╚═╗│ ││ │├┬┘│  ├┤   ║  │ │ ││├┤   ╚═╗│  ├─┤││││││├┤ ├┬┘
                        ╚═╝└─┘└─┘┴└─└─┘└─┘  ╚═╝└─┘─┴┘└─┘  ╚═╝└─┘┴ ┴┘└┘┘└┘└─┘┴└─
                                    Security Scanner v3.1
    """
    print(banner)

    current_platform = get_platform()
    print(f"[*] Platform: {current_platform.upper()}")
    print(f"[*] Target: {args.target}")
    print(f"[*] Categories: {', '.join(args.category)}")

    if args.scan_binaries:
        print(f"[*] Binary analysis: ENABLED")
    if args.decompile:
        decompiler = DotNetDecompiler(args.verbose)
        if decompiler.is_available():
            print(f"[*] .NET Decompiler: {decompiler.get_tool_info()}")
        else:
            print(f"[!] .NET Decompiler: NOT FOUND")
            print(f"    Install with: dotnet tool install -g ilspycmd")
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

    if scanner.stats["by_severity"].get("CRITICAL", 0):
        return 2
    elif scanner.stats["by_severity"].get("HIGH", 0):
        return 1
    return 0

if __name__ == "__main__":
    exit(main())
