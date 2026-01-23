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
            r'\beval\s*\(',
            r'\beval\s*\(\s*req\.',
            r'\beval\s*\(\s*request\.',
            r'\beval\s*\(\s*["\'].*\+',
            r'\beval\s*\(\s*`',
        ],
        severity=Severity.CRITICAL,
        languages=[".js", ".ts", ".jsx", ".tsx"],
        false_positive_patterns=[r'//.*\beval', r'/\*.*\beval', r'\.evaluate\(', r'evalua', r'literal_eval']
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
            r'__proto__',
            r'constructor\s*\[\s*["\']prototype["\']\s*\]',
            r'\[\s*["\']__proto__["\']\s*\]',
            r'Object\.assign\s*\(\s*\{\s*\}\s*,.*req\.',
            r'\.\.\.req\.(body|query|params)',
            r'merge\s*\(.*req\.(body|query|params)',
            r'extend\s*\(.*req\.(body|query|params)',
            r'defaultsDeep\s*\(',
        ],
        severity=Severity.HIGH,
        languages=[".js", ".ts", ".jsx", ".tsx"],
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
    # PROTOTYPE POLLUTION PATTERNS
    # =========================================================================
    
    VulnerabilityPattern(
        name="Prototype Pollution - __proto__ Access",
        category=VulnCategory.PROTOTYPE_POLLUTION,
        patterns=[
            r'\[.*__proto__.*\]\s*=',
            r'\.__proto__\s*=',
            r'\["__proto__"\]\s*=',
            r"\['__proto__'\]\s*=",
            r'__proto__\s*:\s*\{',
        ],
        severity=Severity.CRITICAL,
        languages=[".js", ".ts", ".jsx", ".tsx"],
        false_positive_patterns=[r'hasOwnProperty.*__proto__', r'===\s*["\']__proto__["\']', r'!==\s*["\']__proto__["\']', r'typeof superClass', r'Object\.getPrototypeOf', r'Object\.create\('],
    ),
    VulnerabilityPattern(
        name="Prototype Pollution - constructor.prototype",
        category=VulnCategory.PROTOTYPE_POLLUTION,
        patterns=[
            r'\[.*constructor.*\]\s*\[.*prototype.*\]\s*=',
            r'\.constructor\.prototype\s*=',
            r'\["constructor"\]\s*\["prototype"\]\s*=',
            r"\['constructor'\]\s*\['prototype'\]\s*=",
        ],
        severity=Severity.CRITICAL,
        languages=[".js", ".ts", ".jsx", ".tsx"],
        false_positive_patterns=[r'Object\.create\(', r'typeof superClass', r'_inherits'],
    ),
    VulnerabilityPattern(
        name="Prototype Pollution - Unsafe Deep Merge",
        category=VulnCategory.PROTOTYPE_POLLUTION,
        patterns=[
            r'_\.merge\s*\(\s*[^,]+,\s*req\.',
            r'_\.defaultsDeep\s*\(\s*[^,]+,\s*req\.',
            r'lodash\.merge\s*\(\s*[^,]+,\s*req\.',
            r'deepmerge\s*\(\s*[^,]+,\s*req\.',
            r'hoek\.merge\s*\(\s*[^,]+,\s*req\.',
            r'hoek\.applyToDefaults\s*\(\s*[^,]+,\s*req\.',
            r'\$\.extend\s*\(\s*true\s*,\s*[^,]+,\s*req\.',
        ],
        severity=Severity.HIGH,
        languages=[".js", ".ts", ".jsx", ".tsx"],
    ),

    # =========================================================================
    # SQL INJECTION PATTERNS
    # =========================================================================
    
    VulnerabilityPattern(
        name="SQL Injection - String Concatenation",
        category=VulnCategory.SQL_INJECTION,
        patterns=[
            r'["\']SELECT\s+.+\s+FROM\s+.+["\']\s*\+',
            r'["\']INSERT\s+INTO\s+.+["\']\s*\+',
            r'["\']UPDATE\s+.+\s+SET\s+.+["\']\s*\+',
            r'["\']DELETE\s+FROM\s+.+["\']\s*\+',
            r'["\']DROP\s+.+["\']\s*\+',
            r'executeQuery\s*\(\s*["\'].*\+',
            r'executeUpdate\s*\(\s*["\'].*\+',
        ],
        severity=Severity.CRITICAL,
        languages=[".js", ".ts", ".jsx", ".tsx", ".py", ".php", ".java", ".cs", ".rb", ".go", ".kt"],
        false_positive_patterns=[r'//.*SELECT', r'#.*SELECT', r'PreparedStatement'],
    ),
    VulnerabilityPattern(
        name="SQL Injection - Template Literals/F-strings",
        category=VulnCategory.SQL_INJECTION,
        patterns=[
            r'`SELECT\s+.+\s+FROM\s+.+\$\{',
            r'`INSERT\s+INTO\s+.+\$\{',
            r'`UPDATE\s+.+\s+SET\s+.+\$\{',
            r'`DELETE\s+FROM\s+.+\$\{',
            r'f["\']SELECT\s+.+\{',
            r'f["\']INSERT\s+.+\{',
            r'f["\']UPDATE\s+.+\{',
            r'f["\']DELETE\s+.+\{',
            r'\$"SELECT\s+.+\{',
            r'\$"INSERT\s+.+\{',
        ],
        severity=Severity.CRITICAL,
        languages=[".js", ".ts", ".jsx", ".tsx", ".py", ".cs"],
    ),
    VulnerabilityPattern(
        name="SQL Injection - Format String",
        category=VulnCategory.SQL_INJECTION,
        patterns=[
            r'["\']SELECT\s+.+["\'].*%\s*\(',
            r'["\']SELECT\s+.+["\']\.format\s*\(',
            r'String\.Format\s*\(\s*["\']SELECT',
            r'string\.Format\s*\(\s*["\']SELECT',
            r'fmt\.Sprintf\s*\(\s*["\']SELECT',
            r'sprintf\s*\(\s*["\']SELECT',
        ],
        severity=Severity.CRITICAL,
        languages=[".py", ".php", ".go", ".cs", ".java"],
    ),
    VulnerabilityPattern(
        name="SQL Injection - Raw Query Methods",
        category=VulnCategory.SQL_INJECTION,
        patterns=[
            r'\.raw\s*\(\s*["\']',
            r'\.raw\s*\(\s*`',
            r'\.raw\s*\(\s*f["\']',
            r'sequelize\.query\s*\(',
            r'knex\.raw\s*\(',
            r'prisma\.\$queryRaw',
            r'prisma\.\$executeRaw',
            r'RawSQL\s*\(',
            r'text\s*\(\s*f["\']',
            r'FromSqlRaw\s*\(\s*\$"',
            r'ExecuteSqlRaw\s*\(\s*\$"',
            r'SqlQuery\s*\(\s*\$"',
            r'ExecuteSqlCommand\s*\(\s*\$"',
        ],
        severity=Severity.HIGH,
        languages=[".js", ".ts", ".py", ".cs"],
        false_positive_patterns=[r'\?\s*\)', r'\$\d+', r'bindparams', r'@\w+'],
    ),
    VulnerabilityPattern(
        name="SQL Injection - PHP MySQL",
        category=VulnCategory.SQL_INJECTION,
        patterns=[
            r'["\']SELECT\s+.+\$_(GET|POST|REQUEST|COOKIE)',
            r'["\']SELECT\s+.+["\']\s*\.\s*\$',
            r'mysql_query\s*\(\s*["\'].*\$',
            r'mysqli_query\s*\(\s*\$\w+,\s*["\'].*\$',
            r'mysql_query\s*\(',
        ],
        severity=Severity.CRITICAL,
        languages=[".php"],
    ),
    
    # =========================================================================
    # C# SPECIFIC SQL INJECTION
    # =========================================================================
    
    VulnerabilityPattern(
        name="SQL Injection - C# String Interpolation",
        category=VulnCategory.SQL_INJECTION,
        patterns=[
            r'\$".*SELECT.*\{',
            r'\$".*INSERT.*\{',
            r'\$".*UPDATE.*\{',
            r'\$".*DELETE.*\{',
            r'\$".*WHERE.*\{',
            r'SqlCommand\s*\(\s*\$"',
            r'new\s+SqlCommand\s*\(\s*["\'].*\+',
            r'CommandText\s*=\s*\$"',
            r'CommandText\s*=\s*["\'].*\+',
        ],
        severity=Severity.CRITICAL,
        languages=[".cs"],
        false_positive_patterns=[r'@\w+', r'Parameters\.Add'],
    ),
    VulnerabilityPattern(
        name="SQL Injection - C# Entity Framework Raw",
        category=VulnCategory.SQL_INJECTION,
        patterns=[
            r'\.FromSqlRaw\s*\(\s*\$"',
            r'\.FromSqlRaw\s*\(\s*["\'].*\+',
            r'\.ExecuteSqlRaw\s*\(\s*\$"',
            r'\.ExecuteSqlRaw\s*\(\s*["\'].*\+',
            r'\.SqlQuery\s*\(\s*\$"',
            r'Database\.ExecuteSqlCommand\s*\(\s*\$"',
        ],
        severity=Severity.CRITICAL,
        languages=[".cs"],
    ),
    VulnerabilityPattern(
        name="SQL Injection - C# Dapper",
        category=VulnCategory.SQL_INJECTION,
        patterns=[
            r'\.Query\s*\(\s*\$".*SELECT',
            r'\.Query<.*>\s*\(\s*\$"',
            r'\.Execute\s*\(\s*\$"',
            r'\.QueryFirst.*\(\s*\$"',
            r'\.QuerySingle.*\(\s*\$"',
        ],
        severity=Severity.HIGH,
        languages=[".cs"],
        false_positive_patterns=[r'@\w+'],
    ),

    # =========================================================================
    # POSTGRESQL SPECIFIC INJECTION
    # =========================================================================

    VulnerabilityPattern(
        name="PostgreSQL Injection - COPY Command",
        category=VulnCategory.POSTGRESQL_INJECTION,
        patterns=[
            r'COPY\s+.+\s+FROM\s+.+\$',
            r'COPY\s+.+\s+TO\s+.+\$',
            r'pg_read_file\s*\(',
            r'pg_read_binary_file\s*\(',
            r'pg_ls_dir\s*\(',
            r'lo_import\s*\(',
            r'lo_export\s*\(',
        ],
        severity=Severity.CRITICAL,
        languages=[".js", ".ts", ".py", ".php", ".java", ".cs", ".rb", ".go"],
    ),

    # =========================================================================
    # NOSQL INJECTION PATTERNS
    # =========================================================================

    VulnerabilityPattern(
        name="NoSQL Injection - MongoDB Query Operators",
        category=VulnCategory.NOSQL_INJECTION,
        patterns=[
            r'\.find\s*\(\s*\{[^}]*req\.(body|query|params)\[',
            r'\.findOne\s*\(\s*\{[^}]*req\.(body|query|params)\[',
            r'\.findOneAndUpdate\s*\(\s*\{[^}]*req\.(body|query|params)\[',
            r'\.updateOne\s*\(\s*\{[^}]*req\.(body|query|params)\[',
            r'\.deleteOne\s*\(\s*\{[^}]*req\.(body|query|params)\[',
            r'\.aggregate\s*\(\s*\[.*req\.(body|query|params)\[',
            r'\.find\s*\(\s*req\.(body|query)\s*\)',
            r'\.findOne\s*\(\s*req\.(body|query)\s*\)',
        ],
        severity=Severity.HIGH,
        languages=[".js", ".ts", ".jsx", ".tsx"],
        false_positive_patterns=[r'findById', r'\.id\)$', r'params\.id\)'],
    ),
    VulnerabilityPattern(
        name="NoSQL Injection - MongoDB $where Operator",
        category=VulnCategory.NOSQL_INJECTION,
        patterns=[
            r'\$where\s*:',
            r'"\$where"\s*:',
            r"'\$where'\s*:",
        ],
        severity=Severity.CRITICAL,
        languages=[".js", ".ts", ".jsx", ".tsx", ".py", ".php", ".java", ".rb", ".cs"],
    ),
    VulnerabilityPattern(
        name="NoSQL Injection - Direct Object Spread",
        category=VulnCategory.NOSQL_INJECTION,
        patterns=[
            r'\.find\s*\(\s*\{\s*\.\.\.req\.',
            r'\.findOne\s*\(\s*\{\s*\.\.\.req\.',
            r'\.update\w*\s*\(\s*\{\s*\.\.\.req\.',
        ],
        severity=Severity.CRITICAL,
        languages=[".js", ".ts", ".jsx", ".tsx"],
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
        ],
        severity=Severity.CRITICAL,
        languages=[".py"],
        false_positive_patterns=[r'#.*pickle'],
    ),
    VulnerabilityPattern(
        name="Insecure Deserialization - Python YAML",
        category=VulnCategory.DESERIALIZATION,
        patterns=[
            r'yaml\.load\s*\(\s*[^,)]+\s*\)',
            r'yaml\.unsafe_load\s*\(',
            r'yaml\.full_load\s*\(',
        ],
        severity=Severity.CRITICAL,
        languages=[".py"],
        false_positive_patterns=[r'yaml\.safe_load', r'SafeLoader'],
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
        ],
        severity=Severity.HIGH,
        languages=[".js", ".ts", ".py", ".php", ".java", ".cs", ".rb", ".go", ".kt", ".env", ".config", ".json", ".yaml", ".yml"],
        false_positive_patterns=[r'process\.env', r'os\.environ', r'getenv', r'password\s*[=:]\s*["\']["\']', r'<PASSWORD>', r'\$\{', r'Environment\.GetEnvironmentVariable', r'Configuration\['],
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
        ],
        severity=Severity.CRITICAL,
        languages=[".js", ".ts", ".py", ".php", ".java", ".cs", ".rb", ".go"],
        false_positive_patterns=[r'jwt\.verify', r'^#', r'^\s*#', r'//.*verify', r'FrappeClient.*verify=False'],
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
        ],
        severity=Severity.MEDIUM,
        languages=[".php", ".js"],
        false_positive_patterns=[r'===', r'!=='],
    ),

    # =========================================================================
    # SSTI (Server-Side Template Injection) PATTERNS
    # =========================================================================

    VulnerabilityPattern(
        name="SSTI - Jinja2/Flask (Python)",
        category=VulnCategory.SSTI,
        patterns=[
            r'render_template_string\s*\(\s*.*req',
            r'render_template_string\s*\(\s*.*request\.',
            r'render_template_string\s*\(\s*f["\']',
            r'render_template_string\s*\(\s*["\'].*%',
            r'Template\s*\(\s*.*request\.',
            r'from_string\s*\(\s*.*request\.',
        ],
        severity=Severity.CRITICAL,
        languages=[".py"],
    ),
    VulnerabilityPattern(
        name="SSTI - Pug/Jade/EJS (Node.js)",
        category=VulnCategory.SSTI,
        patterns=[
            r'pug\.compile\s*\(\s*.*req\.',
            r'pug\.render\s*\(\s*.*req\.',
            r'ejs\.render\s*\(\s*.*req\.',
            r'ejs\.compile\s*\(\s*.*req\.',
            r'Handlebars\.compile\s*\(\s*.*req\.',
        ],
        severity=Severity.CRITICAL,
        languages=[".js", ".ts"],
    ),
    VulnerabilityPattern(
        name="SSTI - Razor (C#)",
        category=VulnCategory.SSTI,
        patterns=[
            r'RazorEngine.*Compile\s*\(',
            r'Engine\.Razor\.RunCompile\s*\(',
            r'RazorEngineService.*RunCompile\s*\(',
            r'RazorTemplateEngine.*GenerateCode\s*\(',
        ],
        severity=Severity.HIGH,
        languages=[".cs"],
    ),
    VulnerabilityPattern(
        name="SSTI - Twig/Smarty (PHP)",
        category=VulnCategory.SSTI,
        patterns=[
            r'->createTemplate\s*\(\s*\$_(GET|POST|REQUEST)',
            r'->createTemplate\s*\(\s*\$',
            r'\{php\}',
        ],
        severity=Severity.CRITICAL,
        languages=[".php", ".tpl"],
    ),

    # =========================================================================
    # SSRF (Server-Side Request Forgery) PATTERNS
    # =========================================================================

    VulnerabilityPattern(
        name="SSRF - Dynamic URL Fetch (Node.js)",
        category=VulnCategory.SSRF,
        patterns=[
            r'fetch\s*\(\s*req\.(body|query|params)',
            r'fetch\s*\(\s*`.*\$\{.*req\.',
            r'axios\.(get|post|put|delete|patch|request)\s*\(\s*req\.',
            r'axios\s*\(\s*\{[^}]*url\s*:\s*req\.',
            r'http\.get\s*\(\s*req\.',
            r'https\.get\s*\(\s*req\.',
        ],
        severity=Severity.HIGH,
        languages=[".js", ".ts"],
    ),
    VulnerabilityPattern(
        name="SSRF - Dynamic URL Fetch (Python)",
        category=VulnCategory.SSRF,
        patterns=[
            r'requests\.(get|post|put|delete|patch|head|options)\s*\(\s*.*request\.(form|args|json|data)',
            r'urllib\.request\.urlopen\s*\(\s*.*request\.',
            r'urllib\.request\.urlopen\s*\(\s*[^)]*\+',
            r'httpx\.(get|post|put|delete)\s*\(\s*.*request\.',
        ],
        severity=Severity.HIGH,
        languages=[".py"],
    ),
    VulnerabilityPattern(
        name="SSRF - Dynamic URL Fetch (PHP)",
        category=VulnCategory.SSRF,
        patterns=[
            r'file_get_contents\s*\(\s*\$_(GET|POST|REQUEST)',
            r'file_get_contents\s*\(\s*\$',
            r'curl_setopt\s*\([^,]+,\s*CURLOPT_URL\s*,\s*\$',
            r'curl_init\s*\(\s*\$',
        ],
        severity=Severity.HIGH,
        languages=[".php"],
    ),
    VulnerabilityPattern(
        name="SSRF - Dynamic URL Fetch (C#)",
        category=VulnCategory.SSRF,
        patterns=[
            r'HttpClient.*GetAsync\s*\(\s*.*Request\.',
            r'WebClient.*Download.*\s*\(\s*.*Request\.',
            r'WebRequest\.Create\s*\(\s*.*Request\.',
            r'new\s+Uri\s*\(\s*.*Request\.',
            r'HttpClient.*GetStringAsync\s*\(\s*.*Request',
            r'HttpClient.*PostAsync\s*\(\s*.*Request',
        ],
        severity=Severity.HIGH,
        languages=[".cs"],
    ),
    VulnerabilityPattern(
        name="SSRF - Cloud Metadata Access",
        category=VulnCategory.SSRF,
        patterns=[
            r'169\.254\.169\.254',
            r'metadata\.google\.internal',
            r'metadata\.azure\.com',
            r'100\.100\.100\.200',
        ],
        severity=Severity.INFO,
        languages=[".js", ".ts", ".py", ".php", ".java", ".cs", ".rb", ".go", ".kt"],
    ),
]


# Binary patterns for DLL/EXE analysis
BINARY_PATTERNS = [
    {"name": "Hardcoded Connection String", "pattern": r'(Data Source|Server|Initial Catalog|User ID|Password|Integrated Security)\s*=', "severity": Severity.HIGH},
    {"name": "Hardcoded Credentials", "pattern": r'(password|passwd|pwd|secret|api[_-]?key|token)\s*[=:]\s*["\'][^"\']+["\']', "severity": Severity.HIGH},
    {"name": "SQL Query Pattern", "pattern": r'(SELECT|INSERT|UPDATE|DELETE|DROP|TRUNCATE)\s+.*(FROM|INTO|SET|TABLE)', "severity": Severity.MEDIUM},
    {"name": "Deserialization Indicators", "pattern": r'(BinaryFormatter|ObjectInputStream|pickle|unserialize|Marshal\.load|yaml\.load|NetDataContractSerializer|LosFormatter|SoapFormatter|ObjectStateFormatter|JavaScriptSerializer|JsonConvert\.DeserializeObject|TypeNameHandling|XmlSerializer|DataContractSerializer|XamlReader|XamlServices|fastJSON|JSON\.ToObject|YamlDotNet|Deserializer|ResourceReader|ResXResourceReader)', "severity": Severity.HIGH},
    {"name": "Weak Crypto", "pattern": r'(MD5CryptoServiceProvider|MD5.Create|SHA1CryptoServiceProvider|SHA1.Create|DESCryptoServiceProvider|TripleDESCryptoServiceProvider|CipherMode.ECB)', "severity": Severity.MEDIUM},
    {"name": "URL/Endpoint", "pattern": r'https?://[a-zA-Z0-9.-]+(/[a-zA-Z0-9./_-]*)?', "severity": Severity.INFO},
    {"name": "Private Key", "pattern": r'-----BEGIN (RSA |DSA |EC )?PRIVATE KEY-----', "severity": Severity.CRITICAL},
    {"name": "AWS Credentials", "pattern": r'(AKIA[0-9A-Z]{16}|aws_secret_access_key)', "severity": Severity.CRITICAL},
    {"name": "Eval/Dynamic Code", "pattern": r'\beval\s*\(|\bFunction\s*\(|setTimeout\s*\(\s*["\']', "severity": Severity.HIGH},
    # New patterns for command/code injection
    {"name": "Process Execution", "pattern": r'(Process\.Start|ProcessStartInfo|Runtime\.exec|ProcessBuilder|child_process|exec\(|execSync|spawn|popen|system\(|shell_exec|passthru)', "severity": Severity.HIGH},
    {"name": "PowerShell Execution", "pattern": r'(PowerShell|AddScript|AddCommand|Runspace|System\.Management\.Automation)', "severity": Severity.HIGH},
    {"name": "Script Engine", "pattern": r'(ScriptEngine|ScriptEngineManager|Nashorn|GraalJS|eval\(|Function\()', "severity": Severity.HIGH},
    {"name": "Dynamic Assembly", "pattern": r'(Assembly\.Load|Assembly\.LoadFrom|CSharpCodeProvider|CompileAssembly|CodeDomProvider|Activator\.CreateInstance)', "severity": Severity.HIGH},
    {"name": "Reflection", "pattern": r'(GetMethod|InvokeMember|MethodInfo|Type\.GetType|CreateDelegate|DynamicInvoke)', "severity": Severity.MEDIUM},
    {"name": "JNDI Lookup", "pattern": r'(InitialContext|Context\.lookup|javax\.naming|jndi:)', "severity": Severity.CRITICAL},
    {"name": "Expression Language", "pattern": r'(ExpressionFactory|ELProcessor|SpelExpressionParser|parseExpression)', "severity": Severity.HIGH},
    {"name": "Dangerous PHP", "pattern": r'(assert\(|create_function|preg_replace.*\/e)', "severity": Severity.HIGH},
    {"name": "Command Shell", "pattern": r'(cmd\.exe|/bin/sh|/bin/bash|powershell\.exe|command\.com)', "severity": Severity.MEDIUM},
    {"name": "Prototype Pollution", "pattern": r'(__proto__|constructor\[.*prototype)', "severity": Severity.HIGH},
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
  sql, postgresql, nosql, xpath, deserialization, auth, ssti, ssrf, code/eval, all

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
        choices=["sql", "postgresql", "nosql", "xpath", "deserialization", "auth", "ssti", "ssrf", "code", "eval", "prototype", "pollution", "all"],
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
░█░█░█▀█░█▀▄░█░░░█▀▄░▀█▀░█▀▄░█▀▀░█▀▀░█▀▄░█▀█░█░█
░█▄█░█░█░█▀▄░█░░░█░█░░█░░█▀▄░█▀▀░█▀▀░█▀▄░█░█░░█░
░▀░▀░▀▀▀░▀░▀░▀▀▀░▀▀░░░▀░░▀░▀░▀▀▀░▀▀▀░▀▀░░▀▀▀░░▀░
        ╔═╗┌─┐┌─┐┬ ┬┬─┐┬┌┬┐┬ ┬  ╔═╗┌─┐┌─┐┌┐┌┌┐┌┌─┐┬─┐
        ╚═╗├┤ │  │ │├┬┘│ │ └┬┘  ╚═╗│  ├─┤││││││├┤ ├┬┘
        ╚═╝└─┘└─┘└─┘┴└─┴ ┴  ┴   ╚═╝└─┘┴ ┴┘└┘┘└┘└─┘┴└─
                Source Code Security Scanner v3.1
                      by worldtreeboy
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
