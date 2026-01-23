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
        # Basic SQL statement concatenation
        r'["\']SELECT\s+.+\s+FROM\s+.+["\']\s*\+',
        r'["\']INSERT\s+INTO\s+.+["\']\s*\+',
        r'["\']UPDATE\s+.+\s+SET\s+.+["\']\s*\+',
        r'["\']DELETE\s+FROM\s+.+["\']\s*\+',
        r'["\']DROP\s+.+["\']\s*\+',
        
        # WHERE clause concatenation (common injection point)
        r'["\'].*WHERE\s+.+["\']\s*\+\s*(?!["\']\s*AND\s*["\'])',
        r'["\'].*AND\s+.+["\']\s*\+',
        r'["\'].*OR\s+.+["\']\s*\+',
        
        # ORDER BY / GROUP BY injection
        r'["\'].*ORDER\s+BY\s*["\']\s*\+',
        r'["\'].*GROUP\s+BY\s*["\']\s*\+',
        r'["\'].*HAVING\s+.+["\']\s*\+',
        
        # LIMIT/OFFSET injection
        r'["\'].*LIMIT\s*["\']\s*\+',
        r'["\'].*OFFSET\s*["\']\s*\+',
        
        # Table/Column name injection
        r'["\']SELECT\s+["\']\s*\+\s*\w+\s*\+\s*["\']',
        r'["\']FROM\s+["\']\s*\+',
        r'["\']INTO\s+["\']\s*\+',
        
        # Execute methods with concatenation
        r'executeQuery\s*\(\s*["\'].*\+',
        r'executeUpdate\s*\(\s*["\'].*\+',
        r'executeSql\s*\(\s*["\'].*\+',
        r'execute\s*\(\s*["\'].*SELECT.*\+',
    ],
    severity=Severity.CRITICAL,
    languages=[".js", ".ts", ".jsx", ".tsx", ".py", ".php", ".java", ".cs", ".rb", ".go", ".kt"],
    false_positive_patterns=[
        r'//.*SELECT',
        r'#.*SELECT',
        r'PreparedStatement',
        r'\+\s*["\']["\']',           # Empty string concat
        r'\+\s*["\'][\s,)]+["\']',    # Whitespace/punctuation only
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
        r'`.*WHERE\s+.+\$\{',
        r'`.*ORDER\s+BY\s+\$\{',
        r'`.*LIMIT\s+\$\{',
        
        # Python f-strings
        r'f["\']SELECT\s+.+\{',
        r'f["\']INSERT\s+.+\{',
        r'f["\']UPDATE\s+.+\{',
        r'f["\']DELETE\s+.+\{',
        r'f["\'].*WHERE\s+.+\{',
        r'f["\'].*ORDER\s+BY\s+\{',
        
        # C# interpolated strings
        r'\$"SELECT\s+.+\{',
        r'\$"INSERT\s+.+\{',
        r'\$"UPDATE\s+.+\{',
        r'\$"DELETE\s+.+\{',
        r'\$".*WHERE\s+.+\{',
        
        # Ruby string interpolation
        r'["\']SELECT\s+.+#\{',
        r'["\'].*WHERE\s+.+#\{',
    ],
    severity=Severity.CRITICAL,
    languages=[".js", ".ts", ".jsx", ".tsx", ".py", ".cs", ".rb"],
    false_positive_patterns=[
        r'\{[\d:,]+\}',               # Format specifiers like {0}, {:d}
        r'\{\s*\?\s*\}',              # Placeholder pattern
    ],
),

VulnerabilityPattern(
    name="SQL Injection - Format String",
    category=VulnCategory.SQL_INJECTION,
    patterns=[
        # Python % formatting
        r'["\']SELECT\s+.+["\'].*%\s*\(',
        r'["\'].*WHERE\s+.+%s.*["\'].*%\s*\(',
        r'["\']SELECT\s+.+["\']\.format\s*\(',
        r'["\'].*WHERE\s+.+["\']\.format\s*\(',
        
        # C# String.Format
        r'String\.Format\s*\(\s*["\']SELECT',
        r'string\.Format\s*\(\s*["\']SELECT',
        r'String\.Format\s*\(\s*["\'].*WHERE',
        
        # Go fmt.Sprintf
        r'fmt\.Sprintf\s*\(\s*["\']SELECT',
        r'fmt\.Sprintf\s*\(\s*["\'].*WHERE',
        r'fmt\.Sprintf\s*\(\s*`SELECT',
        
        # C sprintf
        r'sprintf\s*\(\s*\w+,\s*["\']SELECT',
        r'snprintf\s*\(\s*\w+,\s*\d+,\s*["\']SELECT',
        
        # Java String.format
        r'String\.format\s*\(\s*["\']SELECT',
    ],
    severity=Severity.CRITICAL,
    languages=[".py", ".php", ".go", ".cs", ".java", ".c", ".cpp"],
    false_positive_patterns=[
        r'%\(\w+\)s',                 # Python named parameters
    ],
),

VulnerabilityPattern(
    name="SQL Injection - Raw Query Methods",
    category=VulnCategory.SQL_INJECTION,
    patterns=[
        # Node.js ORMs
        r'\.raw\s*\(\s*["\'].*\+',
        r'\.raw\s*\(\s*`[^`]*\$\{',
        r'sequelize\.query\s*\(\s*["\'].*\+',
        r'sequelize\.query\s*\(\s*`[^`]*\$\{',
        r'knex\.raw\s*\(\s*["\'].*\+',
        r'knex\.raw\s*\(\s*`[^`]*\$\{',
        
        # Prisma
        r'prisma\.\$queryRaw\s*`[^`]*\$\{',
        r'prisma\.\$executeRaw\s*`[^`]*\$\{',
        r'prisma\.\$queryRawUnsafe\s*\(',
        r'prisma\.\$executeRawUnsafe\s*\(',
        
        # Python SQLAlchemy
        r'text\s*\(\s*f["\']',
        r'\.execute\s*\(\s*f["\']SELECT',
        r'\.execute\s*\(\s*f["\'].*WHERE',
        r'engine\.execute\s*\(\s*f["\']',
        r'session\.execute\s*\(\s*f["\']',
        r'connection\.execute\s*\(\s*f["\']',
        
        # Django
        r'\.extra\s*\(\s*where\s*=',
        r'\.extra\s*\(\s*select\s*=',
        r'RawSQL\s*\(\s*f["\']',
        r'cursor\.execute\s*\(\s*f["\']',
        
        # Ruby ActiveRecord
        r'\.find_by_sql\s*\(\s*["\'].*#\{',
        r'\.execute\s*\(\s*["\'].*#\{',
        r'\.select_all\s*\(\s*["\'].*#\{',
        
        # C# Entity Framework
        r'FromSqlRaw\s*\(\s*\$"',
        r'ExecuteSqlRaw\s*\(\s*\$"',
        r'SqlQuery\s*\(\s*\$"',
        r'ExecuteSqlCommand\s*\(\s*\$"',
    ],
    severity=Severity.CRITICAL,
    languages=[".js", ".ts", ".py", ".cs", ".rb"],
    false_positive_patterns=[
        r'\?\s*[,\)]',                # Positional placeholders
        r'\$\d+',                     # PostgreSQL positional params
        r':\w+',                      # Named parameters
        r'@\w+',                      # SQL Server parameters
        r'bindparams',
        r'\.bind\s*\(',
    ],
),

VulnerabilityPattern(
    name="SQL Injection - PHP MySQL",
    category=VulnCategory.SQL_INJECTION,
    patterns=[
        # Superglobal injection
        r'["\']SELECT\s+.+\$_(GET|POST|REQUEST|COOKIE|SERVER)',
        r'["\']INSERT\s+.+\$_(GET|POST|REQUEST|COOKIE)',
        r'["\']UPDATE\s+.+\$_(GET|POST|REQUEST|COOKIE)',
        r'["\']DELETE\s+.+\$_(GET|POST|REQUEST|COOKIE)',
        r'["\'].*WHERE\s+.+\$_(GET|POST|REQUEST|COOKIE)',
        
        # Variable concatenation
        r'["\']SELECT\s+.+["\']\s*\.\s*\$(?!pdo)',
        r'["\'].*WHERE\s+.+["\']\s*\.\s*\$(?!pdo)',
        
        # Deprecated mysql_* functions (always flag)
        r'mysql_query\s*\(',
        r'mysql_db_query\s*\(',
        r'mysql_unbuffered_query\s*\(',
        
        # mysqli without prepared statements
        r'mysqli_query\s*\(\s*\$\w+,\s*["\'].*\$(?!stmt)',
        r'mysqli_multi_query\s*\(\s*\$\w+,\s*["\'].*\$',
        
        # PDO without prepared statements
        r'\$pdo->query\s*\(\s*["\'].*\$',
        r'\$\w+->query\s*\(\s*["\'].*\.\s*\$',
    ],
    severity=Severity.CRITICAL,
    languages=[".php"],
    false_positive_patterns=[
        r'->prepare\s*\(',
        r'bindParam',
        r'bindValue',
        r'execute\s*\(\s*\[',
    ],
),

VulnerabilityPattern(
    name="SQL Injection - Java JDBC",
    category=VulnCategory.SQL_INJECTION,
    patterns=[
        # Statement (not PreparedStatement)
        r'createStatement\s*\(\s*\).*executeQuery\s*\(\s*["\'].*\+',
        r'createStatement\s*\(\s*\).*executeUpdate\s*\(\s*["\'].*\+',
        r'createStatement\s*\(\s*\).*execute\s*\(\s*["\'].*\+',
        
        # String building with SQL
        r'StringBuilder.*append\s*\(\s*["\']SELECT',
        r'StringBuffer.*append\s*\(\s*["\']SELECT',
        r'String\.join.*SELECT',
        
        # Statement.execute with concatenation
        r'statement\.execute\w*\s*\(\s*["\'].*\+',
        r'stmt\.execute\w*\s*\(\s*["\'].*\+',
        
        # Spring JDBC without parameters
        r'jdbcTemplate\.query\s*\(\s*["\'].*\+',
        r'jdbcTemplate\.update\s*\(\s*["\'].*\+',
        r'jdbcTemplate\.execute\s*\(\s*["\'].*\+',
        r'namedParameterJdbcTemplate\.query\s*\(\s*["\'].*\+',
    ],
    severity=Severity.CRITICAL,
    languages=[".java", ".kt"],
    false_positive_patterns=[
        r'PreparedStatement',
        r'prepareStatement',
        r'\?\s*[,\)]',
        r'setString',
        r'setInt',
        r'setLong',
    ],
),

VulnerabilityPattern(
    name="SQL Injection - Python Database APIs",
    category=VulnCategory.SQL_INJECTION,
    patterns=[
        # Direct cursor execution with f-strings
        r'cursor\.execute\s*\(\s*f["\']',
        r'cur\.execute\s*\(\s*f["\']',
        r'\.execute\s*\(\s*f["\']SELECT',
        r'\.execute\s*\(\s*f["\'].*WHERE',
        
        # String formatting in execute
        r'\.execute\s*\(\s*["\'].*%s.*["\'].*%\s*\(',
        r'\.execute\s*\(\s*["\'].*["\']\.format\s*\(',
        r'\.executemany\s*\(\s*f["\']',
        
        # psycopg2 / mysql-connector specific
        r'cursor\.execute\s*\(\s*["\'].*%\s*\(',
        r'cursor\.execute\s*\(\s*["\'].*["\']\.format',
        
        # asyncpg
        r'connection\.fetch\s*\(\s*f["\']',
        r'connection\.execute\s*\(\s*f["\']',
        r'pool\.fetch\s*\(\s*f["\']',
    ],
    severity=Severity.CRITICAL,
    languages=[".py"],
    false_positive_patterns=[
        r'execute\s*\(\s*["\'][^"\']*["\'],\s*[\[\(]',   # Parameterized query
        r'execute\s*\(\s*["\'][^"\']*["\'],\s*\{',       # Dict params
        r'%\(\w+\)s',                                      # Named params
        r'mogrify',
    ],
),

VulnerabilityPattern(
    name="SQL Injection - Go Database/SQL",
    category=VulnCategory.SQL_INJECTION,
    patterns=[
        # fmt.Sprintf with SQL
        r'db\.Query\s*\(\s*fmt\.Sprintf\s*\(',
        r'db\.QueryRow\s*\(\s*fmt\.Sprintf\s*\(',
        r'db\.Exec\s*\(\s*fmt\.Sprintf\s*\(',
        r'tx\.Query\s*\(\s*fmt\.Sprintf\s*\(',
        r'tx\.Exec\s*\(\s*fmt\.Sprintf\s*\(',
        
        # String concatenation
        r'db\.Query\s*\(\s*["`].*\+',
        r'db\.Exec\s*\(\s*["`].*\+',
        
        # GORM raw queries
        r'\.Raw\s*\(\s*fmt\.Sprintf',
        r'\.Exec\s*\(\s*fmt\.Sprintf',
        
        # sqlx
        r'sqlx\.Get\s*\(.*fmt\.Sprintf',
        r'sqlx\.Select\s*\(.*fmt\.Sprintf',
    ],
    severity=Severity.CRITICAL,
    languages=[".go"],
    false_positive_patterns=[
        r'\$\d+',                      # PostgreSQL params
        r'\?\s*[,\)]',                 # MySQL params
        r'\.Rebind\s*\(',              # sqlx rebind
    ],
),

# =========================================================================
# C# SPECIFIC SQL INJECTION
# =========================================================================

VulnerabilityPattern(
    name="SQL Injection - C# ADO.NET",
    category=VulnCategory.SQL_INJECTION,
    patterns=[
        # SqlCommand with interpolation/concatenation
        r'new\s+SqlCommand\s*\(\s*\$"',
        r'new\s+SqlCommand\s*\(\s*["\'].*\+',
        r'SqlCommand\s*\(\s*\$"',
        r'CommandText\s*=\s*\$"',
        r'CommandText\s*=\s*["\'].*\+',
        
        # OleDb/Odbc
        r'new\s+OleDbCommand\s*\(\s*\$"',
        r'new\s+OdbcCommand\s*\(\s*\$"',
        
        # SqlDataAdapter
        r'new\s+SqlDataAdapter\s*\(\s*\$"',
        r'new\s+SqlDataAdapter\s*\(\s*["\'].*\+',
    ],
    severity=Severity.CRITICAL,
    languages=[".cs"],
    false_positive_patterns=[
        r'@\w+',                       # SQL Server parameters
        r'Parameters\.Add',
        r'Parameters\.AddWithValue',
        r'\.Parameters\[',
    ],
),

VulnerabilityPattern(
    name="SQL Injection - C# Entity Framework",
    category=VulnCategory.SQL_INJECTION,
    patterns=[
        # Raw SQL methods with interpolation
        r'\.FromSqlRaw\s*\(\s*\$"',
        r'\.FromSqlRaw\s*\(\s*["\'].*\+',
        r'\.ExecuteSqlRaw\s*\(\s*\$"',
        r'\.ExecuteSqlRaw\s*\(\s*["\'].*\+',
        r'\.SqlQuery\s*\(\s*\$"',
        r'Database\.ExecuteSqlCommand\s*\(\s*\$"',
        
        # EF Core interpolated (safer but flag for review)
        r'\.FromSqlInterpolated\s*\(\s*\$".*\+',
    ],
    severity=Severity.CRITICAL,
    languages=[".cs"],
    false_positive_patterns=[
        r'FromSqlInterpolated',        # EF Core handles this safely
        r'@\w+',
    ],
),

VulnerabilityPattern(
    name="SQL Injection - C# Dapper",
    category=VulnCategory.SQL_INJECTION,
    patterns=[
        r'\.Query\s*(<.*>)?\s*\(\s*\$"',
        r'\.Query\s*(<.*>)?\s*\(\s*["\'].*\+',
        r'\.Execute\s*\(\s*\$"',
        r'\.Execute\s*\(\s*["\'].*\+',
        r'\.QueryFirst\w*\s*(<.*>)?\s*\(\s*\$"',
        r'\.QuerySingle\w*\s*(<.*>)?\s*\(\s*\$"',
        r'\.QueryMultiple\s*\(\s*\$"',
    ],
    severity=Severity.CRITICAL,
    languages=[".cs"],
    false_positive_patterns=[
        r'@\w+',
        r',\s*new\s*\{',               # Anonymous object params
    ],
),

# =========================================================================
# SECOND-ORDER & STORED SQL INJECTION
# =========================================================================

VulnerabilityPattern(
    name="SQL Injection - Stored/Second-Order",
    category=VulnCategory.SQL_INJECTION,
    patterns=[
        # Building queries from database values
        r'\.execute\s*\(\s*row\[',
        r'\.execute\s*\(\s*result\[',
        r'\.execute\s*\(\s*record\.',
        r'executeQuery\s*\(\s*rs\.getString',
        r'executeQuery\s*\(\s*resultSet\.get',
        
        # Using session/cookie data in queries
        r'["\']SELECT.*session\[',
        r'["\']SELECT.*Session\[',
        r'["\']SELECT.*cookie',
    ],
    severity=Severity.HIGH,
    languages=[".js", ".ts", ".py", ".php", ".java", ".cs", ".rb", ".go"],
),

# =========================================================================
# POSTGRESQL SPECIFIC INJECTION
# =========================================================================

VulnerabilityPattern(
    name="PostgreSQL Injection - Dangerous Functions",
    category=VulnCategory.SQL_INJECTION,
    patterns=[
        # File system access
        r'pg_read_file\s*\(',
        r'pg_read_binary_file\s*\(',
        r'pg_ls_dir\s*\(',
        r'pg_stat_file\s*\(',
        
        # Large object operations
        r'lo_import\s*\(',
        r'lo_export\s*\(',
        
        # COPY command with variables
        r'COPY\s+.+\s+FROM\s+.+[\$\{#]',
        r'COPY\s+.+\s+TO\s+.+[\$\{#]',
        
        # Code execution
        r'CREATE\s+FUNCTION.*LANGUAGE\s+(plpython|plperl|pltcl)',
    ],
    severity=Severity.CRITICAL,
    languages=[".js", ".ts", ".py", ".php", ".java", ".cs", ".rb", ".go"],
),

# =========================================================================
# ORM-SPECIFIC UNSAFE PATTERNS
# =========================================================================

VulnerabilityPattern(
    name="SQL Injection - ORM Bypass/Unsafe Methods",
    category=VulnCategory.SQL_INJECTION,
    patterns=[
        # Django
        r'\.extra\s*\(\s*where\s*=\s*\[.*%',
        r'\.extra\s*\(\s*select\s*=\s*\{.*%',
        r'RawSQL\s*\(',
        
        # SQLAlchemy
        r'text\s*\(\s*["\'].*%',
        r'text\s*\(\s*f["\']',
        r'literal_column\s*\(\s*f["\']',
        
        # Sequelize
        r'sequelize\.literal\s*\(\s*["\'].*\+',
        r'sequelize\.literal\s*\(\s*`.*\$\{',
        r'Sequelize\.literal\s*\(\s*["\'].*\+',
        
        # ActiveRecord
        r'\.where\s*\(\s*["\'].*#\{',
        r'\.order\s*\(\s*["\'].*#\{',
        r'\.pluck\s*\(\s*["\'].*#\{',
        r'\.group\s*\(\s*["\'].*#\{',
        
        # Hibernate HQL
        r'createQuery\s*\(\s*["\'].*\+',
        r'createNativeQuery\s*\(\s*["\'].*\+',
    ],
    severity=Severity.HIGH,
    languages=[".py", ".js", ".ts", ".rb", ".java", ".kt"],
    false_positive_patterns=[
        r':\w+',                       # Named parameters
        r'\?\s*[,\)]',
    ],
),
    # =========================================================================
    # NOSQL INJECTION PATTERNS
    # =========================================================================

    VulnerabilityPattern(
    name="NoSQL Injection - Tainted Input in Query",
    category=VulnCategory.NOSQL_INJECTION,
    patterns=[
        # Catches: .find({ user: req.query.name }), .findOne({ email: req.body.email })
        r'\.(find|findOne|update|delete|aggregate|count|distinct|findOneAnd(?:Update|Delete|Replace))\w*\s*\(\s*\{[^}]*:\s*req\.(body|query|params)',
        
        # Catches: .find(req.body), .findOne(req.query) - passing raw user input as query
        r'\.(find|findOne|countDocuments|aggregate|distinct)\s*\(\s*req\.(body|query)\s*\)',
        
        # Catches: .find({ ...req.body }) - object spread of user input
        r'\.(find|findOne|update|delete|aggregate|findOneAnd)\w*\s*\(\s*\{\s*\.\.\.req\.(body|query|params)',
        
        # Catches: $where with string concatenation or template literals
        r'\$where\s*:\s*[`"\'].*(\+|\$\{|req\.)',
        
        # Catches: collection[method](userInput) dynamic method calls
        r'collection\s*\[\s*req\.(body|query|params)',
        
        # Catches: MongoDB operators from user input: { $gt: req.body.value }
        r'\{\s*\$(?:gt|gte|lt|lte|ne|in|nin|or|and|not|regex|where|expr)\s*:\s*req\.(body|query|params)',
        
        # Catches: eval-like patterns in Mongoose/MongoDB
        r'\.(?:mapReduce|group)\s*\(\s*[^)]*req\.(body|query|params)',
    ],
    severity=Severity.CRITICAL,
    languages=[".js", ".ts", ".jsx", ".tsx"],
    false_positive_patterns=[
        r'findById',                    # Mongoose casts to ObjectId
        r'params\.id\s*\)',             # Single ID lookups are generally safe
        r'Types\.ObjectId\s*\(',        # Explicit ObjectId casting
        r'mongoose\.Types\.ObjectId',   # Explicit ObjectId casting
        r'new\s+ObjectId\s*\(',         # Explicit ObjectId casting
        r'sanitize',                    # Likely using sanitization
        r'escape',                      # Likely using escaping
        r'validator\.',                 # Using validator library
    ],
),
VulnerabilityPattern(
    name="NoSQL Injection - MongoDB $where Operator",
    category=VulnCategory.NOSQL_INJECTION,
    patterns=[
        r'\$where\s*:',
        r'"\$where"\s*:',
        r"'\$where'\s*:",
    ],
    severity=Severity.HIGH,  # Changed from CRITICAL - $where alone is a code smell, not always exploitable
    languages=[".js", ".ts", ".jsx", ".tsx", ".py", ".php", ".java", ".rb", ".cs"],
    false_positive_patterns=[
        r'\$where\s*:\s*function\s*\(\)\s*\{\s*return\s+(true|false)',  # Static $where
        r'\$where\s*:\s*["\'][^"\']*["\']',  # Hardcoded string (still risky but not injection)
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
        patterns = [
    # Original patterns
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
    
    # 1. AWS Keys
    r'AKIA[0-9A-Z]{16}',  # AWS Access Key ID
    r'aws[_-]?secret[_-]?access[_-]?key\s*[=:]\s*["\'][A-Za-z0-9/+=]{40}["\']',
    r'AWS_SECRET_ACCESS_KEY\s*[=:]\s*["\'][A-Za-z0-9/+=]{40}["\']',
    
    # 2. Database Connection Strings
    r'mongodb(\+srv)?://[^\s"\']+:[^\s"\']+@[^\s"\']+',  # MongoDB URI with creds
    r'postgres(ql)?://[^\s"\']+:[^\s"\']+@[^\s"\']+',    # PostgreSQL URI with creds
    r'mysql://[^\s"\']+:[^\s"\']+@[^\s"\']+',            # MySQL URI with creds
    r'redis://[^\s"\']+:[^\s"\']+@[^\s"\']+',            # Redis URI with creds
    
    # 3. Payment & SaaS API Keys
    r'sk_live_[a-zA-Z0-9]{24,}',           # Stripe live secret key
    r'sk_test_[a-zA-Z0-9]{24,}',           # Stripe test secret key
    r'rk_live_[a-zA-Z0-9]{24,}',           # Stripe restricted key
    r'https://hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[a-zA-Z0-9]+',  # Slack webhook
    r'xox[baprs]-[0-9a-zA-Z-]+',           # Slack tokens
    
    # 4. Session/App Secrets (generic high-entropy strings)
    r'SESSION_SECRET\s*[=:]\s*["\'][^"\']{16,}["\']',
    r'APP_SECRET\s*[=:]\s*["\'][^"\']{16,}["\']',
    r'JWT_SECRET\s*[=:]\s*["\'][^"\']{16,}["\']',
    
    # 5. Common variable names with values
    r'admin[_-]?password\s*[=:]\s*["\'][^"\']{4,}["\']',
    r'api[_-]?token\s*[=:]\s*["\'][^"\']{16,}["\']',
    r'bearer[_-]?token\s*[=:]\s*["\'][^"\']{16,}["\']',
    
    # 6. SSH/PGP Private Keys
    r'-----BEGIN\s+(RSA|DSA|EC|OPENSSH|PGP)\s+PRIVATE\s+KEY-----',
    r'-----BEGIN\s+PRIVATE\s+KEY-----',
    
    # 7. Basic Auth Headers
    r'Basic\s+[A-Za-z0-9+/=]{10,}',        # Base64 encoded Basic auth
    r'Bearer\s+[A-Za-z0-9._-]{20,}',       # Bearer tokens
    
    # 8. Additional cloud providers
    r'AZURE[_-]?(?:CLIENT|TENANT|SUBSCRIPTION)[_-]?(?:ID|SECRET)\s*[=:]\s*["\'][^"\']+["\']',
    r'GOOGLE[_-]?(?:API[_-]?KEY|CLIENT[_-]?SECRET)\s*[=:]\s*["\'][^"\']+["\']',
    r'gh[pousr]_[A-Za-z0-9_]{36,}',        # GitHub tokens
    
    # 9. JWT tokens (full format)
    r'eyJ[A-Za-z0-9_-]*\.eyJ[A-Za-z0-9_-]*\.[A-Za-z0-9_-]*',
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

VulnerabilityPattern(
    name="SSRF - Dynamic URL Fetch (Node.js)",
    category=VulnCategory.SSRF,
    patterns=[
        # Fetch API
        r'fetch\s*\(\s*req\.(body|query|params)',
        r'fetch\s*\(\s*`[^`]*\$\{[^}]*req\.',
        r'fetch\s*\(\s*["\'].*\+.*req\.',
        r'fetch\s*\(\s*\w+\s*\)',  # fetch(userVar) - variable from user input
        
        # Axios
        r'axios\.(get|post|put|delete|patch|head|options|request)\s*\(\s*req\.',
        r'axios\.(get|post|put|delete|patch|head|options|request)\s*\(\s*`[^`]*\$\{',
        r'axios\.(get|post|put|delete|patch|head|options|request)\s*\(\s*["\'].*\+',
        r'axios\s*\(\s*\{[^}]*url\s*:\s*req\.',
        r'axios\s*\(\s*\{[^}]*url\s*:\s*`[^`]*\$\{',
        
        # Native http/https modules
        r'https?\.get\s*\(\s*req\.(body|query|params)',
        r'https?\.get\s*\(\s*`[^`]*\$\{',
        r'https?\.get\s*\(\s*["\'].*\+',
        r'https?\.request\s*\(\s*req\.',
        r'https?\.request\s*\(\s*\{[^}]*hostname?\s*:\s*req\.',
        r'https?\.request\s*\(\s*\{[^}]*host\s*:\s*req\.',
        r'https?\.request\s*\(\s*\{[^}]*path\s*:\s*req\.',
        
        # Got, node-fetch, superagent, needle
        r'got\s*\(\s*req\.(body|query|params)',
        r'got\s*\(\s*`[^`]*\$\{',
        r'got\.(get|post|put|delete|patch)\s*\(\s*req\.',
        r'needle\s*\(\s*["\']get["\'],\s*req\.',
        r'needle\.(get|post|put|delete|patch)\s*\(\s*req\.',
        r'superagent\.(get|post|put|delete|patch)\s*\(\s*req\.',
        r'request\s*\(\s*req\.(body|query|params)',
        r'request\s*\(\s*\{[^}]*url\s*:\s*req\.',
        
        # URL constructor with user input
        r'new\s+URL\s*\(\s*req\.(body|query|params)',
        r'new\s+URL\s*\(\s*`[^`]*\$\{[^}]*req\.',
        
        # Puppeteer/Playwright (headless browser SSRF)
        r'page\.goto\s*\(\s*req\.',
        r'page\.goto\s*\(\s*`[^`]*\$\{',
        r'page\.navigate\s*\(\s*req\.',
        r'browser\.newPage.*goto\s*\(\s*req\.',
    ],
    severity=Severity.HIGH,
    languages=[".js", ".ts", ".jsx", ".tsx"],
    false_positive_patterns=[
        r'https?://localhost',
        r'https?://127\.0\.0\.1',
        r'isValidUrl\s*\(',
        r'validateUrl\s*\(',
        r'allowedHosts',
        r'whitelist',
    ],
),

VulnerabilityPattern(
    name="SSRF - Dynamic URL Fetch (Python)",
    category=VulnCategory.SSRF,
    patterns=[
        # requests library
        r'requests\.(get|post|put|delete|patch|head|options)\s*\(\s*request\.(form|args|json|data|values)',
        r'requests\.(get|post|put|delete|patch|head|options)\s*\(\s*f["\']',
        r'requests\.(get|post|put|delete|patch|head|options)\s*\(\s*["\'].*\+',
        r'requests\.(get|post|put|delete|patch|head|options)\s*\(\s*["\'].*\.format\s*\(',
        r'requests\.(get|post|put|delete|patch|head|options)\s*\(\s*url\s*\)',  # variable
        
        # urllib
        r'urllib\.request\.urlopen\s*\(\s*request\.',
        r'urllib\.request\.urlopen\s*\(\s*f["\']',
        r'urllib\.request\.urlopen\s*\(\s*["\'].*\+',
        r'urllib\.request\.urlopen\s*\(\s*["\'].*\.format\s*\(',
        r'urlopen\s*\(\s*request\.',
        r'urllib\.request\.Request\s*\(\s*request\.',
        
        # httpx (async)
        r'httpx\.(get|post|put|delete|patch|head|options)\s*\(\s*request\.',
        r'httpx\.AsyncClient\s*\(\s*\)\.get\s*\(\s*request\.',
        r'await\s+httpx\.(get|post|put|delete|patch)\s*\(\s*f["\']',
        r'client\.(get|post|put|delete)\s*\(\s*request\.(form|args|json)',
        
        # aiohttp (async)
        r'session\.(get|post|put|delete|patch)\s*\(\s*request\.',
        r'aiohttp\.ClientSession\s*\(\s*\)\.get\s*\(\s*request\.',
        r'await\s+session\.(get|post)\s*\(\s*f["\']',
        
        # http.client
        r'http\.client\.HTTPConnection\s*\(\s*request\.',
        r'HTTPConnection\s*\(\s*request\.',
        r'HTTPSConnection\s*\(\s*request\.',
        
        # pycurl
        r'pycurl.*CURLOPT_URL.*request\.',
        r'curl\.setopt\s*\(.*URL.*request\.',
    ],
    severity=Severity.HIGH,
    languages=[".py"],
    false_positive_patterns=[
        r'validate_url',
        r'is_safe_url',
        r'ALLOWED_HOSTS',
        r'urlparse.*netloc.*in\s+',
    ],
),

VulnerabilityPattern(
    name="SSRF - Dynamic URL Fetch (PHP)",
    category=VulnCategory.SSRF,
    patterns=[
        # file_get_contents
        r'file_get_contents\s*\(\s*\$_(GET|POST|REQUEST|COOKIE)',
        r'file_get_contents\s*\(\s*\$[a-zA-Z_]\w*\s*\)',
        r'file_get_contents\s*\(\s*["\'].*\.\s*\$',
        
        # cURL
        r'curl_setopt\s*\([^,]+,\s*CURLOPT_URL\s*,\s*\$_(GET|POST|REQUEST)',
        r'curl_setopt\s*\([^,]+,\s*CURLOPT_URL\s*,\s*\$',
        r'curl_init\s*\(\s*\$_(GET|POST|REQUEST)',
        r'curl_init\s*\(\s*\$[a-zA-Z_]\w*\s*\)',
        r'curl_setopt_array\s*\([^,]+,\s*\[[^\]]*CURLOPT_URL\s*=>\s*\$',
        
        # fopen with URL wrappers
        r'fopen\s*\(\s*\$_(GET|POST|REQUEST)',
        r'fopen\s*\(\s*["\']https?://.*\.\s*\$',
        
        # Guzzle
        r'->request\s*\(\s*["\']GET["\'],\s*\$',
        r'->get\s*\(\s*\$_(GET|POST|REQUEST)',
        r'new\s+Client.*->get\s*\(\s*\$',
        
        # copy() with URL
        r'copy\s*\(\s*\$_(GET|POST|REQUEST)',
        r'copy\s*\(\s*["\']https?://.*\.\s*\$',
        
        # readfile with URL
        r'readfile\s*\(\s*\$_(GET|POST|REQUEST)',
    ],
    severity=Severity.HIGH,
    languages=[".php"],
    false_positive_patterns=[
        r'filter_var.*FILTER_VALIDATE_URL',
        r'parse_url.*\[.host.\].*===',
    ],
),

VulnerabilityPattern(
    name="SSRF - Dynamic URL Fetch (Java)",
    category=VulnCategory.SSRF,
    patterns=[
        # URL/HttpURLConnection
        r'new\s+URL\s*\(\s*request\.getParameter',
        r'new\s+URL\s*\(\s*.*\+.*request\.get',
        r'URL\s*\(\s*.*\+.*getParameter',
        r'openConnection\s*\(\s*\).*getParameter',
        
        # HttpClient (Java 11+)
        r'HttpClient.*send\s*\(.*request\.getParameter',
        r'HttpRequest\.newBuilder\s*\(\s*\)\.uri\s*\(.*request\.get',
        
        # Apache HttpClient
        r'HttpGet\s*\(\s*request\.getParameter',
        r'HttpPost\s*\(\s*request\.getParameter',
        r'new\s+HttpGet\s*\(\s*.*\+',
        r'new\s+HttpPost\s*\(\s*.*\+',
        
        # OkHttp
        r'Request\.Builder\s*\(\s*\)\.url\s*\(.*request\.get',
        r'new\s+Request\.Builder\s*\(\s*\)\.url\s*\(\s*.*\+',
        
        # RestTemplate (Spring)
        r'restTemplate\.(getForObject|getForEntity|postForObject|exchange)\s*\(\s*.*request\.get',
        r'RestTemplate.*\.(get|post).*\(\s*.*\+',
        
        # WebClient (Spring WebFlux)
        r'webClient\.(get|post|put|delete)\s*\(\s*\)\.uri\s*\(.*request\.get',
    ],
    severity=Severity.HIGH,
    languages=[".java", ".kt"],
    false_positive_patterns=[
        r'UriComponentsBuilder.*whitelist',
        r'isAllowedHost',
    ],
),

VulnerabilityPattern(
    name="SSRF - Dynamic URL Fetch (C#)",
    category=VulnCategory.SSRF,
    patterns=[
        # HttpClient
        r'HttpClient.*Get\w*Async\s*\(\s*.*Request\.(Query|Form|Body)',
        r'HttpClient.*Get\w*Async\s*\(\s*\$"',
        r'HttpClient.*Get\w*Async\s*\(\s*["\'].*\+',
        r'HttpClient.*Post\w*Async\s*\(\s*.*Request\.',
        r'HttpClient.*Send\w*Async\s*\(\s*.*Request\.',
        r'new\s+HttpClient\s*\(\s*\).*Get.*\(\s*.*\+',
        
        # WebClient (legacy)
        r'WebClient.*Download\w*\s*\(\s*.*Request\.',
        r'WebClient.*Download\w*\s*\(\s*\$"',
        r'WebClient.*Upload\w*\s*\(\s*.*Request\.',
        r'new\s+WebClient\s*\(\s*\)\.Download.*\(\s*.*\+',
        
        # WebRequest
        r'WebRequest\.Create\s*\(\s*.*Request\.',
        r'WebRequest\.Create\s*\(\s*\$"',
        r'HttpWebRequest.*Create\s*\(\s*.*Request\.',
        
        # Uri construction
        r'new\s+Uri\s*\(\s*.*Request\.(Query|Form)',
        r'new\s+Uri\s*\(\s*\$".*\{.*Request\.',
        
        # RestSharp
        r'RestClient\s*\(\s*.*Request\.',
        r'new\s+RestClient\s*\(\s*\$"',
        r'new\s+RestRequest\s*\(\s*.*Request\.',
    ],
    severity=Severity.HIGH,
    languages=[".cs"],
    false_positive_patterns=[
        r'IsValidUri',
        r'AllowedHosts',
        r'Uri\.IsWellFormedUriString',
    ],
),
]


# Binary patterns for DLL/EXE analysis
BINARY_PATTERNS = [
    # =========================================================================
    # CREDENTIALS & SECRETS
    # =========================================================================
    {
        "name": "Hardcoded Connection String",
        "pattern": r'(Data Source|Server|Initial Catalog|User ID|Password|Integrated Security|Provider|Persist Security Info|Trusted_Connection|Database|Uid|Pwd|DSN|Driver)\s*=',
        "severity": Severity.HIGH
    },
    {
        "name": "Hardcoded Credentials",
        "pattern": r'(password|passwd|pwd|secret|api[_-]?key|apikey|token|auth[_-]?token|access[_-]?token|bearer|credential|private[_-]?key|encryption[_-]?key|signing[_-]?key|jwt[_-]?secret|session[_-]?secret|master[_-]?key)\s*[=:]\s*["\'][^"\']{4,}["\']',
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
    
    # =========================================================================
    # CLOUD PROVIDER CREDENTIALS
    # =========================================================================
    {
        "name": "AWS Credentials",
        "pattern": r'(AKIA[0-9A-Z]{16}|ABIA[0-9A-Z]{16}|ACCA[0-9A-Z]{16}|ASIA[0-9A-Z]{16}|aws_secret_access_key|aws_access_key_id)',
        "severity": Severity.CRITICAL
    },
    {
        "name": "AWS ARN/Resource",
        "pattern": r'arn:aws:[a-z0-9-]+:[a-z0-9-]*:\d{12}:',
        "severity": Severity.MEDIUM
    },
    {
        "name": "Azure Credentials",
        "pattern": r'(AccountKey\s*=|SharedAccessSignature\s*=|DefaultEndpointsProtocol=https;AccountName=|azure[_-]?(client[_-]?id|client[_-]?secret|tenant[_-]?id|subscription[_-]?id))',
        "severity": Severity.CRITICAL
    },
    {
        "name": "GCP Credentials",
        "pattern": r'("type"\s*:\s*"service_account"|"private_key_id"\s*:|AIza[0-9A-Za-z_-]{35}|GOOG[a-zA-Z0-9_-]{10,})',
        "severity": Severity.CRITICAL
    },
    {
        "name": "DigitalOcean Token",
        "pattern": r'(dop_v1_[a-f0-9]{64}|doo_v1_[a-f0-9]{64})',
        "severity": Severity.CRITICAL
    },
    {
        "name": "Heroku API Key",
        "pattern": r'[hH]eroku[a-zA-Z0-9_-]*[=:]\s*["\']?[a-f0-9-]{36}',
        "severity": Severity.CRITICAL
    },
    
    # =========================================================================
    # API KEYS & TOKENS
    # =========================================================================
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
        "pattern": r'(access_token\$production\$[a-z0-9]{16}\$[a-f0-9]{32}|paypal[_-]?(client[_-]?id|secret)|braintree[_-]?(merchant|public|private)[_-]?(id|key))',
        "severity": Severity.CRITICAL
    },
    {
        "name": "Twilio",
        "pattern": r'(SK[a-f0-9]{32}|AC[a-f0-9]{32}|twilio[_-]?(account[_-]?sid|auth[_-]?token))',
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
        "pattern": r'(xox[baprs]-[0-9]{10,}-[0-9]{10,}-[a-zA-Z0-9]{24}|xox[baprs]-[0-9]{10,}-[a-zA-Z0-9]{24})',
        "severity": Severity.CRITICAL
    },
    {
        "name": "Slack Webhook",
        "pattern": r'https://hooks\.slack\.com/services/T[A-Z0-9]{8,}/B[A-Z0-9]{8,}/[a-zA-Z0-9]{24}',
        "severity": Severity.HIGH
    },
    {
        "name": "Discord Token/Webhook",
        "pattern": r'(https://discord(app)?\.com/api/webhooks/\d+/[a-zA-Z0-9_-]+|[MN][a-zA-Z0-9_-]{23,}\.[a-zA-Z0-9_-]{6}\.[a-zA-Z0-9_-]{27,})',
        "severity": Severity.HIGH
    },
    {
        "name": "Telegram Bot Token",
        "pattern": r'\d{8,10}:[a-zA-Z0-9_-]{35}',
        "severity": Severity.HIGH
    },
    {
        "name": "Firebase/Google API",
        "pattern": r'(AIza[0-9A-Za-z_-]{35}|FIREBASE[_-]?(API[_-]?KEY|AUTH[_-]?DOMAIN|PROJECT[_-]?ID))',
        "severity": Severity.HIGH
    },
    {
        "name": "NPM Token",
        "pattern": r'(npm_[a-zA-Z0-9]{36}|//registry\.npmjs\.org/:_authToken=)',
        "severity": Severity.CRITICAL
    },
    {
        "name": "PyPI Token",
        "pattern": r'pypi-AgEIcHlwaS5vcmc[a-zA-Z0-9_-]{50,}',
        "severity": Severity.CRITICAL
    },
    {
        "name": "Docker Registry",
        "pattern": r'(docker[_-]?(password|auth|token)|DOCKER_AUTH_CONFIG)',
        "severity": Severity.HIGH
    },
    {
        "name": "JWT Token",
        "pattern": r'eyJ[a-zA-Z0-9_-]*\.eyJ[a-zA-Z0-9_-]*\.[a-zA-Z0-9_-]*',
        "severity": Severity.MEDIUM
    },
    {
        "name": "Basic Auth Header",
        "pattern": r'(Basic\s+[A-Za-z0-9+/=]{20,}|Authorization:\s*Basic\s+)',
        "severity": Severity.HIGH
    },
    {
        "name": "Bearer Token",
        "pattern": r'(Bearer\s+[a-zA-Z0-9_-]{20,}|Authorization:\s*Bearer\s+)',
        "severity": Severity.MEDIUM
    },
    
    # =========================================================================
    # DATABASE
    # =========================================================================
    {
        "name": "SQL Query Pattern",
        "pattern": r'(SELECT\s+.{1,50}\s+FROM|INSERT\s+INTO\s+\w+|UPDATE\s+\w+\s+SET|DELETE\s+FROM\s+\w+|DROP\s+(TABLE|DATABASE|INDEX)|TRUNCATE\s+TABLE|ALTER\s+TABLE|CREATE\s+(TABLE|DATABASE|INDEX|VIEW|PROCEDURE)|EXEC(UTE)?\s+)',
        "severity": Severity.MEDIUM
    },
    {
        "name": "Database Connection URI",
        "pattern": r'(mongodb(\+srv)?://[^\s"\']+|postgres(ql)?://[^\s"\']+|mysql://[^\s"\']+|redis://[^\s"\']+|mssql://[^\s"\']+|oracle://[^\s"\']+|jdbc:[a-z]+://[^\s"\']+)',
        "severity": Severity.HIGH
    },
    {
        "name": "Database Password in URI",
        "pattern": r'(mongodb|postgres|mysql|redis|mssql)(\+srv)?://[^:]+:[^@]+@',
        "severity": Severity.CRITICAL
    },
    
    # =========================================================================
    # DESERIALIZATION (RCE VECTORS)
    # =========================================================================
    {
        "name": "Deserialization - .NET",
        "pattern": r'(BinaryFormatter|ObjectStateFormatter|NetDataContractSerializer|LosFormatter|SoapFormatter|DataContractSerializer|XmlSerializer|JavaScriptSerializer|JsonConvert\.DeserializeObject|TypeNameHandling|XamlReader|XamlServices|ObjectDataProvider|ResourceReader|ResXResourceReader|ActivitySurrogateSelector)',
        "severity": Severity.HIGH
    },
    {
        "name": "Deserialization - Java",
        "pattern": r'(ObjectInputStream|XMLDecoder|XStream|SnakeYAML|JsonParser|ObjectMapper\.enableDefaultTyping|readObject\(|readUnshared\(|Yaml\.load|yaml\.unsafe_load|Kryo|Hessian2Input|BurlapInput|Castor)',
        "severity": Severity.HIGH
    },
    {
        "name": "Deserialization - PHP",
        "pattern": r'(unserialize\s*\(|__wakeup|__destruct|PharData|phar://)',
        "severity": Severity.HIGH
    },
    {
        "name": "Deserialization - Python",
        "pattern": r'(pickle\.loads?|cPickle\.loads?|_pickle\.loads?|dill\.loads?|shelve\.open|marshal\.loads?|yaml\.load|yaml\.unsafe_load|jsonpickle)',
        "severity": Severity.HIGH
    },
    {
        "name": "Deserialization - Ruby",
        "pattern": r'(Marshal\.load|YAML\.load|Psych\.load|Oj\.load)',
        "severity": Severity.HIGH
    },
    {
        "name": "Deserialization - Node.js",
        "pattern": r'(node-serialize|serialize-javascript|cryo|funcster)',
        "severity": Severity.HIGH
    },
    {
        "name": "Deserialization Magic Bytes",
        "pattern": r'(aced0005|rO0AB|H4sIA|YTo[0-9]|Tz[0-9]+:|O:[0-9]+:")',
        "severity": Severity.HIGH
    },
    
    # =========================================================================
    # WEAK CRYPTOGRAPHY
    # =========================================================================
    {
        "name": "Weak Hash - MD5",
        "pattern": r'(MD5CryptoServiceProvider|MD5\.Create|hashlib\.md5|MessageDigest\.getInstance\s*\(\s*["\']MD5|md5\s*\(|MD5_CTX|CC_MD5)',
        "severity": Severity.MEDIUM
    },
    {
        "name": "Weak Hash - SHA1",
        "pattern": r'(SHA1CryptoServiceProvider|SHA1\.Create|hashlib\.sha1|MessageDigest\.getInstance\s*\(\s*["\']SHA-?1|sha1\s*\(|SHA_CTX|CC_SHA1)',
        "severity": Severity.MEDIUM
    },
    {
        "name": "Weak Encryption - DES/3DES",
        "pattern": r'(DESCryptoServiceProvider|TripleDESCryptoServiceProvider|DES\.Create|TripleDES\.Create|DES/|DESede|Cipher\.getInstance\s*\(\s*["\']DES)',
        "severity": Severity.MEDIUM
    },
    {
        "name": "Weak Encryption - RC4",
        "pattern": r'(RC4|ARCFOUR|Cipher\.getInstance\s*\(\s*["\']RC4)',
        "severity": Severity.MEDIUM
    },
    {
        "name": "Weak Encryption Mode - ECB",
        "pattern": r'(CipherMode\.ECB|/ECB/|AES/ECB|DES/ECB|Cipher\.getInstance\s*\(\s*["\'][^"\']+/ECB)',
        "severity": Severity.MEDIUM
    },
    {
        "name": "Insecure Random",
        "pattern": r'(Math\.random\s*\(|Random\s*\(\s*\)|random\.random\s*\(|rand\s*\(|srand\s*\(|mt_rand|lcg_value)',
        "severity": Severity.MEDIUM
    },
    {
        "name": "Hardcoded IV/Nonce",
        "pattern": r'(IV\s*=\s*["\'][^"\']{16,}["\']|nonce\s*=\s*["\'][^"\']+["\']|InitializationVector)',
        "severity": Severity.MEDIUM
    },
    
    # =========================================================================
    # COMMAND/CODE EXECUTION
    # =========================================================================
    {
        "name": "Process Execution - .NET",
        "pattern": r'(Process\.Start|ProcessStartInfo|System\.Diagnostics\.Process)',
        "severity": Severity.HIGH
    },
    {
        "name": "Process Execution - Java",
        "pattern": r'(Runtime\.getRuntime\(\)\.exec|ProcessBuilder|ProcessImpl)',
        "severity": Severity.HIGH
    },
    {
        "name": "Process Execution - Python",
        "pattern": r'(subprocess\.(run|call|Popen|check_output)|os\.(system|popen|exec|spawn)|commands\.getoutput)',
        "severity": Severity.HIGH
    },
    {
        "name": "Process Execution - PHP",
        "pattern": r'(exec\s*\(|shell_exec|system\s*\(|passthru|popen\s*\(|proc_open|pcntl_exec|backtick operator)',
        "severity": Severity.HIGH
    },
    {
        "name": "Process Execution - Node.js",
        "pattern": r'(child_process|exec\s*\(|execSync|execFile|spawn|spawnSync|fork\s*\()',
        "severity": Severity.HIGH
    },
    {
        "name": "Process Execution - Ruby",
        "pattern": r'(Kernel\.system|Kernel\.exec|Kernel\.\`|%x\{|IO\.popen|Open3|Shellwords)',
        "severity": Severity.HIGH
    },
    {
        "name": "Process Execution - Go",
        "pattern": r'(exec\.Command|os/exec|syscall\.Exec)',
        "severity": Severity.HIGH
    },
    {
        "name": "PowerShell Execution",
        "pattern": r'(PowerShell|AddScript|AddCommand|Runspace|System\.Management\.Automation|Invoke-Expression|IEX\s|New-Object\s+.*Net\.WebClient|DownloadString|EncodedCommand|-enc\s+-)',
        "severity": Severity.HIGH
    },
    {
        "name": "Shell References",
        "pattern": r'(cmd\.exe|/bin/sh|/bin/bash|/bin/zsh|/bin/ksh|powershell\.exe|pwsh|command\.com|sh\s+-c|bash\s+-c)',
        "severity": Severity.MEDIUM
    },
    
    # =========================================================================
    # DYNAMIC CODE EXECUTION
    # =========================================================================
    {
        "name": "Eval/Dynamic Code - JavaScript",
        "pattern": r'(\beval\s*\(|\bFunction\s*\(|setTimeout\s*\(\s*["\']|setInterval\s*\(\s*["\']|new\s+Function\s*\()',
        "severity": Severity.HIGH
    },
    {
        "name": "Eval/Dynamic Code - Python",
        "pattern": r'(\beval\s*\(|\bexec\s*\(|compile\s*\(|__import__\s*\()',
        "severity": Severity.HIGH
    },
    {
        "name": "Eval/Dynamic Code - PHP",
        "pattern": r'(\beval\s*\(|assert\s*\(|create_function|preg_replace\s*\([^,]*["\']/[^/]*e[^/]*["\']|call_user_func|call_user_func_array)',
        "severity": Severity.HIGH
    },
    {
        "name": "Eval/Dynamic Code - Ruby",
        "pattern": r'(\beval\s*\(|instance_eval|class_eval|module_eval|Kernel\.eval|binding\.eval)',
        "severity": Severity.HIGH
    },
    {
        "name": "Script Engine - Java",
        "pattern": r'(ScriptEngine|ScriptEngineManager|Nashorn|GraalJS|javax\.script|Bindings\.put)',
        "severity": Severity.HIGH
    },
    {
        "name": "Expression Language",
        "pattern": r'(ExpressionFactory|ELProcessor|SpelExpressionParser|parseExpression|StandardEvaluationContext|ValueExpression|MethodExpression)',
        "severity": Severity.HIGH
    },
    
    # =========================================================================
    # REFLECTION & DYNAMIC LOADING
    # =========================================================================
    {
        "name": "Reflection - .NET",
        "pattern": r'(GetMethod|InvokeMember|MethodInfo|Type\.GetType|CreateDelegate|DynamicInvoke|Activator\.CreateInstance|Assembly\.Load|Assembly\.LoadFrom|Assembly\.LoadFile|Assembly\.LoadWithPartialName)',
        "severity": Severity.MEDIUM
    },
    {
        "name": "Reflection - Java",
        "pattern": r'(Class\.forName|getMethod|getDeclaredMethod|invoke\s*\(|getConstructor|newInstance|setAccessible|java\.lang\.reflect)',
        "severity": Severity.MEDIUM
    },
    {
        "name": "Dynamic Compilation - .NET",
        "pattern": r'(CSharpCodeProvider|VBCodeProvider|CompileAssemblyFromSource|CodeDomProvider|Roslyn\.Compil|Microsoft\.CodeAnalysis)',
        "severity": Severity.HIGH
    },
    {
        "name": "Dynamic Compilation - Java",
        "pattern": r'(JavaCompiler|ToolProvider\.getSystemJavaCompiler|javax\.tools|Janino|BeanShell|Groovy)',
        "severity": Severity.HIGH
    },
    {
        "name": "Class Loading - Java",
        "pattern": r'(URLClassLoader|defineClass|ClassLoader\.loadClass|Thread\.currentThread\(\)\.getContextClassLoader)',
        "severity": Severity.HIGH
    },
    
    # =========================================================================
    # INJECTION VECTORS
    # =========================================================================
    {
        "name": "JNDI Lookup (Log4Shell)",
        "pattern": r'(InitialContext|Context\.lookup|javax\.naming|jndi:|ldap://|rmi://|\$\{jndi:)',
        "severity": Severity.CRITICAL
    },
    {
        "name": "LDAP Injection",
        "pattern": r'(DirectorySearcher|SearchRequest|LdapConnection|ldap_search|ldap_bind|ou=|cn=|dc=)',
        "severity": Severity.MEDIUM
    },
    {
        "name": "XPath Injection",
        "pattern": r'(XPathExpression|XPathNavigator|SelectNodes|SelectSingleNode|XPath\.compile|xpath\.evaluate)',
        "severity": Severity.MEDIUM
    },
    {
        "name": "XML External Entity (XXE)",
        "pattern": r'(<!ENTITY|SYSTEM\s+["\']file:|PUBLIC\s+["\']|DTDConfiguration|DocumentBuilderFactory|SAXParserFactory|XMLReader|XmlTextReader|XmlReader\.Create|XmlDocument\.Load)',
        "severity": Severity.HIGH
    },
    {
        "name": "Template Injection Indicators",
        "pattern": r'(\{\{.*\}\}|\{%.*%\}|<%.*%>|\$\{.*\}|#\{.*\})',
        "severity": Severity.MEDIUM
    },
    {
        "name": "Prototype Pollution",
        "pattern": r'(__proto__|constructor\s*\[|Object\.assign\s*\(\s*\{\}|\.prototype\s*=|prototype\s*\[)',
        "severity": Severity.HIGH
    },
    
    # =========================================================================
    # FILE OPERATIONS
    # =========================================================================
    {
        "name": "File Operations",
        "pattern": r'(FileStream|StreamReader|StreamWriter|File\.Open|File\.Read|File\.Write|File\.Delete|Directory\.Delete|fopen|fread|fwrite|file_get_contents|file_put_contents|readfile|include\s*\(|require\s*\(|include_once|require_once)',
        "severity": Severity.MEDIUM
    },
    {
        "name": "Path Traversal Indicators",
        "pattern": r'(\.\./|\.\.\x5c|%2e%2e%2f|%2e%2e/|\.\.%2f|%2e%2e%5c|path\.join|Path\.Combine)',
        "severity": Severity.HIGH
    },
    {
        "name": "Archive/Zip Operations",
        "pattern": r'(ZipFile|ZipArchive|TarArchive|GzipStream|ZipInputStream|ZipEntry|extractall|unzip|tar\s+-)',
        "severity": Severity.MEDIUM
    },
    
    # =========================================================================
    # NETWORK & SSRF
    # =========================================================================
    {
        "name": "URL/Endpoint",
        "pattern": r'https?://[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}(/[a-zA-Z0-9./_?&=-]*)?',
        "severity": Severity.INFO
    },
    {
        "name": "Internal Network",
        "pattern": r'(192\.168\.\d+\.\d+|10\.\d+\.\d+\.\d+|172\.(1[6-9]|2[0-9]|3[01])\.\d+\.\d+|127\.0\.0\.1|localhost|0\.0\.0\.0)',
        "severity": Severity.MEDIUM
    },
    {
        "name": "Cloud Metadata Endpoints",
        "pattern": r'(169\.254\.169\.254|metadata\.google\.internal|metadata\.azure\.com|100\.100\.100\.200)',
        "severity": Severity.HIGH
    },
    {
        "name": "HTTP Client",
        "pattern": r'(HttpClient|WebClient|WebRequest|HttpWebRequest|RestSharp|Flurl|HttpURLConnection|OkHttp|Retrofit|axios|fetch\s*\(|requests\.(get|post)|urllib|aiohttp|httpx)',
        "severity": Severity.INFO
    },
    {
        "name": "Socket Operations",
        "pattern": r'(Socket|TcpClient|UdpClient|ServerSocket|DatagramSocket|socket\.socket|socket\.connect|bind\s*\(|listen\s*\(|accept\s*\()',
        "severity": Severity.MEDIUM
    },
    
    # =========================================================================
    # AUTHENTICATION & SESSION
    # =========================================================================
    {
        "name": "Hardcoded User/Admin",
        "pattern": r'(admin|root|superuser|administrator)\s*[=:]\s*["\'][^"\']+["\']',
        "severity": Severity.MEDIUM
    },
    {
        "name": "Session Handling",
        "pattern": r'(SessionState|HttpSession|session\[|Session\[|\$_SESSION|session_start|session_id)',
        "severity": Severity.INFO
    },
    {
        "name": "Cookie Manipulation",
        "pattern": r'(Response\.Cookies|Request\.Cookies|document\.cookie|HttpCookie|setcookie|set_cookie|Cookie\s*=)',
        "severity": Severity.INFO
    },
    {
        "name": "OAuth/OIDC",
        "pattern": r'(client_secret|client_id|redirect_uri|authorization_code|refresh_token|id_token|access_token)',
        "severity": Severity.MEDIUM
    },
    
    # =========================================================================
    # LOGGING & DEBUG
    # =========================================================================
    {
        "name": "Debug Mode",
        "pattern": r'(DEBUG\s*=\s*[Tt]rue|debug\s*:\s*true|IsDebugMode|EnableDebug|FLASK_DEBUG|APP_DEBUG|NODE_ENV\s*[=:]\s*["\']development)',
        "severity": Severity.MEDIUM
    },
    {
        "name": "Verbose Error",
        "pattern": r'(printStackTrace|traceback\.print|ShowStackTrace|IncludeExceptionDetailInFaults|customErrors\s+mode\s*=\s*["\']Off)',
        "severity": Severity.MEDIUM
    },
    {
        "name": "Console/Log Output",
        "pattern": r'(console\.log|System\.out\.print|print\s*\(|Debug\.Log|Log\.d\s*\(|logger\.(debug|info|warn|error))',
        "severity": Severity.INFO
    },
    
    # =========================================================================
    # MOBILE SPECIFIC
    # =========================================================================
    {
        "name": "Android Sensitive",
        "pattern": r'(android\.permission\.(READ_SMS|RECEIVE_SMS|READ_CONTACTS|ACCESS_FINE_LOCATION|CAMERA|RECORD_AUDIO)|getDeviceId|getSubscriberId|getSimSerialNumber)',
        "severity": Severity.MEDIUM
    },
    {
        "name": "iOS Sensitive",
        "pattern": r'(kSecAttrAccessible|SecItemCopyMatching|SecItemAdd|NSUserDefaults|UIDevice\.current\.identifierForVendor)',
        "severity": Severity.MEDIUM
    },
    {
        "name": "Certificate Pinning Bypass",
        "pattern": r'(setHostnameVerifier|TrustManager|X509TrustManager|checkClientTrusted|checkServerTrusted|SSLSocketFactory|ALLOW_ALL_HOSTNAME_VERIFIER|trustAllCerts)',
        "severity": Severity.HIGH
    },
    
    # =========================================================================
    # DANGEROUS IMPORTS/USING
    # =========================================================================
    {
        "name": "Dangerous .NET Namespace",
        "pattern": r'using\s+(System\.Reflection|System\.Runtime\.InteropServices|System\.Diagnostics|System\.Management|Microsoft\.Win32)',
        "severity": Severity.INFO
    },
    {
        "name": "Dangerous Java Import",
        "pattern": r'import\s+(java\.lang\.reflect|java\.lang\.Runtime|java\.io\.ObjectInputStream|javax\.script|org\.apache\.commons\.collections)',
        "severity": Severity.INFO
    },
    {
        "name": "Dangerous Python Import",
        "pattern": r'import\s+(pickle|subprocess|os|ctypes|marshal|builtins|code|codeop)',
        "severity": Severity.INFO
    },
]: "Prototype Pollution", "pattern": r'(__proto__|constructor\[.*prototype)', "severity": Severity.HIGH},
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
