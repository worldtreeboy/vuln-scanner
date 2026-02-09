#!/usr/bin/env python3
"""
Go AST Vulnerability Scanner (Tree-sitter)
===========================================
A standalone Go security scanner using tree-sitter for AST-based analysis.
Performs per-function taint tracking with ~85%+ AST-based detection.

Detection Categories:
- SQL Injection (string concat in queries, fmt.Sprintf, GORM, sqlx, pgx)
- NoSQL Injection (MongoDB driver: Find, FindOne, UpdateOne, etc.)
- Command Injection (exec.Command with shell, os.StartProcess, syscall.Exec)
- Code Injection (reflect.MethodByName, plugin.Open)
- SSTI (template.New("").Parse(tainted), template.HTML)
- Open Redirect (http.Redirect, c.Redirect)
- XSS (fmt.Fprintf(w,...), io.WriteString, template.HTML, Gin/Echo response)
- LDAP Injection (ldap.NewSearchRequest with tainted filter)
- Insecure Deserialization (gob.Decode, yaml.Unmarshal, xml.Unmarshal)
- XXE (xml.NewDecoder without entity restriction)
- Second-order SQLi (DB-fetched data in SQL concat)
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

import tree_sitter_go as tsgo
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

from vibehunter_config import load_config, VibehunterConfig

console = Console()

GO_LANG = Language(tsgo.language())

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
    OPEN_REDIRECT = "Open Redirect"
    XSS = "Cross-Site Scripting"
    LDAP_INJECTION = "LDAP Injection"
    XXE = "XML External Entity"


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


# ============================================================================
# TaintTracker — Per-Function Taint Analysis
# ============================================================================

class TaintTracker:
    """
    Tracks tainted variables within a single Go function scope.
    Sources: http.Request methods, Gin/Echo/Fiber context methods,
             os.Args, os.Getenv(), io.ReadAll(r.Body), mux.Vars, etc.
    Propagation: assignments, fmt.Sprintf, string operations, type conversions
    """

    # Methods on *http.Request that produce tainted data
    TAINT_METHODS = {
        "FormValue", "PostFormValue",
        "URL", "Header", "Body", "Cookie", "Cookies",
        "Referer", "UserAgent", "PathValue",
        "MultipartReader", "ParseForm", "ParseMultipartForm",
    }

    # Gin context methods that produce tainted data
    GIN_TAINT_METHODS = {
        "Query", "DefaultQuery", "Param", "PostForm", "DefaultPostForm",
        "GetHeader", "Cookie", "ShouldBindJSON", "ShouldBind",
        "BindJSON", "Bind", "GetRawData", "GetPostForm",
    }

    # Echo context methods that produce tainted data
    ECHO_TAINT_METHODS = {
        "QueryParam", "QueryParams", "Param", "ParamValues",
        "FormValue", "FormParams", "Bind",
    }

    # Fiber context methods that produce tainted data
    FIBER_TAINT_METHODS = {
        "Query", "Params", "FormValue", "Body", "BodyParser",
        "Get", "Cookies",
    }

    # Functions that kill taint by converting to a safe type
    TAINT_KILLERS = {
        "strconv.Atoi", "strconv.ParseInt", "strconv.ParseFloat",
        "strconv.ParseBool", "strconv.ParseUint", "strconv.ParseComplex",
        "strconv.FormatInt", "strconv.FormatFloat",
        "net.ParseIP", "uuid.Parse", "uuid.MustParse",
        "filepath.Base", "filepath.Clean",
        "html.EscapeString", "template.HTMLEscapeString",
        "ldap.EscapeFilter",
    }

    # Functions that propagate taint (output is tainted if input is tainted)
    TAINT_PROPAGATORS = {
        "fmt.Sprintf", "fmt.Sprint", "fmt.Sprintln",
        "strings.TrimSpace", "strings.ToLower", "strings.ToUpper",
        "strings.Replace", "strings.ReplaceAll", "strings.Join",
        "strings.Trim", "strings.TrimLeft", "strings.TrimRight",
        "strings.TrimPrefix", "strings.TrimSuffix",
        "strings.Map", "strings.NewReader",
        "strings.Split", "strings.SplitN",
        "bytes.NewBuffer", "bytes.NewBufferString",
        "url.QueryEscape", "url.PathEscape",
        "base64.StdEncoding.DecodeString", "base64.StdEncoding.EncodeToString",
        "hex.DecodeString", "hex.EncodeToString",
    }

    # Taint-killing sanitizers specific to categories
    CATEGORY_SANITIZERS = {
        "html.EscapeString": {"XSS"},
        "template.HTMLEscapeString": {"XSS"},
        "url.QueryEscape": {"XSS"},
        "ldap.EscapeFilter": {"LDAP_INJECTION"},
    }

    # Functions that read user input indirectly
    INPUT_FUNCTIONS = {
        "io.ReadAll", "ioutil.ReadAll",
        "io.Copy", "io.ReadFull",
        "bufio.NewReader", "bufio.NewScanner",
    }

    def __init__(self, func_node: Node, source_lines: List[str],
                 param_names: List[str] = None, is_handler: bool = False):
        self.func_node = func_node
        self.source_lines = source_lines
        # var_name -> (line_number, source_description)
        self.tainted: Dict[str, Tuple[int, str]] = {}
        # var_name -> (line_number, entity_source)
        self.db_sourced: Dict[str, Tuple[int, str]] = {}

        self._init_taint(param_names or [], is_handler)
        self._propagate_taint()

    def _init_taint(self, param_names: List[str], is_handler: bool):
        """Mark function parameters as tainted based on type analysis."""
        func_text = node_text(self.func_node)
        line = get_node_line(self.func_node)

        # Get parameter list
        params_node = get_child_by_type(self.func_node, "parameter_list")
        if not params_node:
            return

        param_decls = get_children_by_type(params_node, "parameter_declaration")

        for param in param_decls:
            # Get param name(s) and type
            names = []
            param_type = ""
            for child in param.children:
                if child.type == "identifier":
                    names.append(node_text(child))
                elif child.type in ("pointer_type", "type_identifier", "qualified_type",
                                    "slice_type", "array_type", "map_type", "interface_type",
                                    "struct_type", "selector_expression"):
                    param_type = node_text(child)

            param_type_lower = param_type.lower()

            for name in names:
                # http.Request or *http.Request
                if "http.Request" in param_type or "Request" == param_type:
                    self.tainted[name] = (line, f"*http.Request parameter")
                # http.ResponseWriter — mark as available (not tainted itself)
                elif "http.ResponseWriter" in param_type or "ResponseWriter" == param_type:
                    # ResponseWriter is a sink, not a source
                    pass
                # Gin context: *gin.Context
                elif "gin.Context" in param_type:
                    self.tainted[name] = (line, f"*gin.Context parameter")
                # Echo context: echo.Context
                elif "echo.Context" in param_type:
                    self.tainted[name] = (line, f"echo.Context parameter")
                # Fiber context: *fiber.Ctx
                elif "fiber.Ctx" in param_type:
                    self.tainted[name] = (line, f"*fiber.Ctx parameter")

    def _propagate_taint(self):
        """Walk function body and propagate taint through assignments."""
        body = get_child_by_type(self.func_node, "block")
        if not body:
            return

        # Multi-pass to handle forward references
        for _ in range(3):
            self._propagate_pass(body)

    def _propagate_pass(self, body: Node):
        """Single pass of taint propagation through the function body."""
        # Short variable declarations (:=)
        short_decls = find_nodes(body, "short_var_declaration")
        for decl in short_decls:
            self._handle_var_decl(decl, body)

        # Regular assignments (=)
        assigns = find_nodes(body, "assignment_statement")
        for assign in assigns:
            self._handle_assignment(assign, body)

        # Var declarations (var x = ...)
        var_decls = find_nodes(body, "var_declaration")
        for vd in var_decls:
            specs = find_nodes(vd, "var_spec")
            for spec in specs:
                self._handle_var_spec(spec, body)

        # Range loops: for _, v := range tainted
        for_stmts = find_nodes(body, "for_statement")
        for fs in for_stmts:
            self._handle_range_loop(fs, body)

        # Track builder patterns: sb.WriteString(tainted), buf.Write(tainted)
        call_exprs = find_nodes(body, "call_expression")
        for ce in call_exprs:
            self._handle_builder_call(ce, body)

    def _handle_var_decl(self, decl: Node, body: Node):
        """Handle short_var_declaration (x := expr)."""
        children = decl.children
        # Find := separator
        lhs_nodes = []
        rhs_nodes = []
        found_assign = False
        for child in children:
            if node_text(child) == ":=":
                found_assign = True
            elif found_assign:
                if child.type not in (",",):
                    rhs_nodes.append(child)
            else:
                if child.type == "identifier":
                    lhs_nodes.append(child)
                elif child.type == "expression_list":
                    for sub in child.children:
                        if sub.type == "identifier":
                            lhs_nodes.append(sub)

        if not lhs_nodes or not rhs_nodes:
            return

        line = get_node_line(decl)
        rhs_text = " ".join(node_text(n) for n in rhs_nodes)

        # Check for taint killers
        if self._is_taint_killer(rhs_text):
            return

        # Check for tainted data in RHS
        if self._rhs_is_tainted(rhs_text, rhs_nodes):
            # For multi-return (val, err := ...), taint the first var
            if lhs_nodes:
                var_name = node_text(lhs_nodes[0])
                if var_name != "_":
                    self.tainted[var_name] = (line, "assigned from tainted data")
            return

        # Check for direct source calls
        source_desc = self._rhs_is_source_call(rhs_text, rhs_nodes)
        if source_desc:
            if lhs_nodes:
                var_name = node_text(lhs_nodes[0])
                if var_name != "_":
                    self.tainted[var_name] = (line, source_desc)
            return

        # Check for taint propagators
        if self._rhs_is_propagator(rhs_text, rhs_nodes):
            if lhs_nodes:
                var_name = node_text(lhs_nodes[0])
                if var_name != "_":
                    self.tainted[var_name] = (line, "propagated from tainted data")
            return

        # Check DB-sourced
        if self._rhs_is_db_source(rhs_text, rhs_nodes):
            if lhs_nodes:
                var_name = node_text(lhs_nodes[0])
                if var_name != "_":
                    self.db_sourced[var_name] = (line, rhs_text.strip())

        # Type conversions: string(b), []byte(s)
        if self._rhs_is_type_conv_tainted(rhs_text, rhs_nodes):
            if lhs_nodes:
                var_name = node_text(lhs_nodes[0])
                if var_name != "_":
                    self.tainted[var_name] = (line, "type conversion of tainted data")

    def _handle_assignment(self, assign: Node, body: Node):
        """Handle assignment_statement (x = expr)."""
        children = assign.children
        # Find = separator (but not :=, ==, !=)
        lhs_nodes = []
        rhs_nodes = []
        found_assign = False
        for child in children:
            txt = node_text(child)
            if txt in ("=", "+=") and not found_assign:
                found_assign = True
            elif found_assign:
                if child.type not in (",",):
                    rhs_nodes.append(child)
            else:
                if child.type not in (",",):
                    lhs_nodes.append(child)

        if not lhs_nodes or not rhs_nodes:
            return

        line = get_node_line(assign)
        rhs_text = " ".join(node_text(n) for n in rhs_nodes)
        var_name = node_text(lhs_nodes[0])

        if self._is_taint_killer(rhs_text):
            return

        if self._rhs_is_tainted(rhs_text, rhs_nodes):
            self.tainted[var_name] = (line, "reassigned from tainted data")
        elif self._rhs_is_propagator(rhs_text, rhs_nodes):
            self.tainted[var_name] = (line, "propagated from tainted data")
        elif self._rhs_is_type_conv_tainted(rhs_text, rhs_nodes):
            self.tainted[var_name] = (line, "type conversion of tainted data")
        else:
            source_desc = self._rhs_is_source_call(rhs_text, rhs_nodes)
            if source_desc:
                self.tainted[var_name] = (line, source_desc)
            elif self._rhs_is_db_source(rhs_text, rhs_nodes):
                self.db_sourced[var_name] = (line, rhs_text.strip())

    def _handle_var_spec(self, spec: Node, body: Node):
        """Handle var_spec (var x type = expr)."""
        names = []
        rhs_text = ""
        rhs_nodes = []
        found_eq = False
        for child in spec.children:
            if node_text(child) == "=":
                found_eq = True
            elif found_eq:
                rhs_nodes.append(child)
            elif child.type == "identifier":
                names.append(node_text(child))

        if not names or not rhs_nodes:
            return

        line = get_node_line(spec)
        rhs_text = " ".join(node_text(n) for n in rhs_nodes)

        if self._is_taint_killer(rhs_text):
            return

        if self._rhs_is_tainted(rhs_text, rhs_nodes):
            for name in names:
                if name != "_":
                    self.tainted[name] = (line, "assigned from tainted data")
        elif self._rhs_is_propagator(rhs_text, rhs_nodes):
            for name in names:
                if name != "_":
                    self.tainted[name] = (line, "propagated from tainted data")
        else:
            source_desc = self._rhs_is_source_call(rhs_text, rhs_nodes)
            if source_desc:
                for name in names:
                    if name != "_":
                        self.tainted[name] = (line, source_desc)

    def _handle_range_loop(self, for_stmt: Node, body: Node):
        """Handle range loops: for _, v := range collection."""
        range_clause = get_child_by_type(for_stmt, "range_clause")
        if not range_clause:
            return

        # Extract loop variables and iterable
        rc_text = node_text(range_clause)
        line = get_node_line(for_stmt)

        # Find identifiers before "range" and expression after "range"
        loop_vars = []
        range_expr = None
        found_range = False
        for child in range_clause.children:
            txt = node_text(child)
            if txt == "range":
                found_range = True
            elif found_range:
                range_expr = child
                break
            elif child.type == "identifier":
                loop_vars.append(node_text(child))
            elif child.type == "expression_list":
                for sub in child.children:
                    if sub.type == "identifier":
                        loop_vars.append(node_text(sub))

        if range_expr and loop_vars:
            range_text = node_text(range_expr)
            if self._rhs_is_tainted(range_text, [range_expr]):
                # For range, the second variable (value) gets taint, or first if only one
                for v in loop_vars:
                    if v != "_":
                        self.tainted[v] = (line, "range over tainted collection")

    def _handle_builder_call(self, ce: Node, body: Node):
        """Handle builder patterns like sb.WriteString(tainted)."""
        ce_text = node_text(ce)
        line = get_node_line(ce)

        # strings.Builder.WriteString / bytes.Buffer.WriteString / Write
        builder_match = re.match(r'(\w+)\s*\.\s*(WriteString|Write|WriteByte)\s*\(', ce_text)
        if builder_match:
            builder_var = builder_match.group(1)
            args_node = get_child_by_type(ce, "argument_list")
            if args_node:
                arg_text = node_text(args_node)
                for tv in self.tainted:
                    if re.search(rf'\b{re.escape(tv)}\b', arg_text):
                        self.tainted[builder_var] = (line, f"Builder.Write({tv})")
                        break

        # append() for slices
        if re.match(r'append\s*\(', ce_text):
            args_node = get_child_by_type(ce, "argument_list")
            if args_node:
                args = self._get_all_args(args_node)
                if len(args) >= 2:
                    slice_name = node_text(args[0])
                    for i in range(1, len(args)):
                        arg_text = node_text(args[i])
                        if self.is_tainted(arg_text):
                            self.tainted[slice_name] = (line, f"append({arg_text})")
                            break

    def _is_taint_killer(self, rhs_text: str) -> bool:
        """Check if the RHS is a taint-killing function call."""
        for killer in self.TAINT_KILLERS:
            if killer in rhs_text:
                return True
        return False

    def _rhs_is_tainted(self, rhs_text: str, rhs_nodes: List[Node]) -> bool:
        """Check if right-hand side references any tainted variable."""
        if self._is_taint_killer(rhs_text):
            return False

        # Remove string literals to avoid matching variable names inside strings
        cleaned = re.sub(r'"[^"]*"', '', rhs_text)
        cleaned = re.sub(r'`[^`]*`', '', cleaned)
        for tainted_var in self.tainted:
            if re.search(rf'\b{re.escape(tainted_var)}\b', cleaned):
                return True
        return False

    def _rhs_is_source_call(self, rhs_text: str, rhs_nodes: List[Node]) -> Optional[str]:
        """Check if RHS is a source call that produces tainted data.
        Returns source description if it is, None otherwise."""
        # r.FormValue("key"), r.URL.Query().Get("key"), etc.
        for method in self.TAINT_METHODS:
            pattern = rf'\.{re.escape(method)}\s*\('
            if re.search(pattern, rhs_text):
                # Check if receiver is a tainted request object
                for tv in self.tainted:
                    if re.search(rf'\b{re.escape(tv)}\b', rhs_text):
                        return f"from {tv}.{method}()"
                # Also catch r.URL.Path, r.URL.Query()
                if re.search(r'\b[rR](?:eq|equest)?\b', rhs_text):
                    return f"from request.{method}()"

        # r.URL.Path, r.URL.RawQuery, r.URL.RawPath
        for tv in self.tainted:
            if re.search(rf'\b{re.escape(tv)}\.URL\.(?:Path|RawQuery|RawPath|Host|Fragment)\b', rhs_text):
                return f"from {tv}.URL property"
            if re.search(rf'\b{re.escape(tv)}\.URL\.Query\s*\(\s*\)', rhs_text):
                return f"from {tv}.URL.Query()"
            if re.search(rf'\b{re.escape(tv)}\.Header\.Get\s*\(', rhs_text):
                return f"from {tv}.Header.Get()"
            if re.search(rf'\b{re.escape(tv)}\.Header\[', rhs_text):
                return f"from {tv}.Header[]"

        # Gin context methods
        for method in self.GIN_TAINT_METHODS:
            if f".{method}(" in rhs_text:
                for tv in self.tainted:
                    if re.search(rf'\b{re.escape(tv)}\b', rhs_text):
                        return f"from gin.Context.{method}()"

        # Echo context methods
        for method in self.ECHO_TAINT_METHODS:
            if f".{method}(" in rhs_text:
                for tv in self.tainted:
                    if re.search(rf'\b{re.escape(tv)}\b', rhs_text):
                        return f"from echo.Context.{method}()"

        # Fiber context methods
        for method in self.FIBER_TAINT_METHODS:
            if f".{method}(" in rhs_text:
                for tv in self.tainted:
                    if re.search(rf'\b{re.escape(tv)}\b', rhs_text):
                        return f"from fiber.Ctx.{method}()"

        # mux.Vars(r) — Gorilla mux
        if "mux.Vars(" in rhs_text:
            for tv in self.tainted:
                if re.search(rf'\b{re.escape(tv)}\b', rhs_text):
                    return "from mux.Vars()"

        # chi.URLParam(r, "key")
        if "chi.URLParam(" in rhs_text:
            for tv in self.tainted:
                if re.search(rf'\b{re.escape(tv)}\b', rhs_text):
                    return "from chi.URLParam()"

        # os.Args, os.Getenv()
        if "os.Args" in rhs_text:
            return "from os.Args"
        if "os.Getenv(" in rhs_text:
            return "from os.Getenv()"

        # io.ReadAll(r.Body), ioutil.ReadAll(r.Body)
        for fn in self.INPUT_FUNCTIONS:
            if fn + "(" in rhs_text:
                for tv in self.tainted:
                    if re.search(rf'\b{re.escape(tv)}\b', rhs_text):
                        return f"from {fn}()"

        # json.Unmarshal — if source is tainted body, result is tainted
        # json.NewDecoder(r.Body).Decode(&target)
        if "json.Unmarshal(" in rhs_text or "json.NewDecoder(" in rhs_text:
            for tv in self.tainted:
                if re.search(rf'\b{re.escape(tv)}\b', rhs_text):
                    return "from JSON decode of tainted data"

        return None

    def _rhs_is_propagator(self, rhs_text: str, rhs_nodes: List[Node]) -> bool:
        """Check if RHS is a taint propagator with tainted args."""
        for prop in self.TAINT_PROPAGATORS:
            if prop + "(" in rhs_text or prop.split(".")[-1] + "(" in rhs_text:
                # Check if any arg is tainted
                cleaned = re.sub(r'"[^"]*"', '', rhs_text)
                cleaned = re.sub(r'`[^`]*`', '', cleaned)
                for tv in self.tainted:
                    if re.search(rf'\b{re.escape(tv)}\b', cleaned):
                        return True
        # String concatenation via +
        if "+" in rhs_text:
            cleaned = re.sub(r'"[^"]*"', '', rhs_text)
            cleaned = re.sub(r'`[^`]*`', '', cleaned)
            for tv in self.tainted:
                if re.search(rf'\b{re.escape(tv)}\b', cleaned):
                    return True
        return False

    def _rhs_is_type_conv_tainted(self, rhs_text: str, rhs_nodes: List[Node]) -> bool:
        """Check if RHS is a type conversion (string(x), []byte(x)) of tainted data."""
        # string(tainted) or []byte(tainted)
        conv_match = re.match(r'(?:string|\[\]byte)\s*\((.+)\)', rhs_text, re.DOTALL)
        if conv_match:
            inner = conv_match.group(1)
            for tv in self.tainted:
                if re.search(rf'\b{re.escape(tv)}\b', inner):
                    return True
        return False

    def _rhs_is_db_source(self, rhs_text: str, rhs_nodes: List[Node]) -> bool:
        """Check if RHS is a database fetch that produces db-sourced data."""
        db_patterns = [
            r'\.QueryRow\s*\(', r'\.Query\s*\(', r'\.QueryContext\s*\(',
            r'\.QueryRowContext\s*\(',
            r'\.Get\s*\(', r'\.Select\s*\(',  # sqlx
            r'\.Find\s*\(', r'\.First\s*\(', r'\.Last\s*\(',  # GORM
            r'\.Scan\s*\(',  # rows.Scan
            r'\.Row\s*\(',
        ]
        for pattern in db_patterns:
            if re.search(pattern, rhs_text):
                return True
        return False

    def is_tainted(self, text: str) -> bool:
        """Check if a text string references any tainted variable."""
        cleaned = re.sub(r'"[^"]*"', '', text)
        cleaned = re.sub(r'`[^`]*`', '', cleaned)
        for tv in self.tainted:
            if re.search(rf'\b{re.escape(tv)}\b', cleaned):
                return True
        return False

    def is_tainted_node(self, node: Node) -> bool:
        """Check if a node's text references any tainted variable."""
        return self.is_tainted(node_text(node))

    def is_db_sourced(self, text: str) -> bool:
        """Check if text references any DB-sourced variable."""
        cleaned = re.sub(r'"[^"]*"', '', text)
        cleaned = re.sub(r'`[^`]*`', '', cleaned)
        for dv in self.db_sourced:
            if re.search(rf'\b{re.escape(dv)}\b', cleaned):
                return True
        return False

    def get_taint_chain(self, text: str) -> List[str]:
        """Get the taint chain for variables referenced in text."""
        chain = []
        cleaned = re.sub(r'"[^"]*"', '', text)
        cleaned = re.sub(r'`[^`]*`', '', cleaned)
        for tv, (line, source) in self.tainted.items():
            if re.search(rf'\b{re.escape(tv)}\b', cleaned):
                chain.append(f"{tv} <- {source} (line {line})")
        return chain

    def _get_all_args(self, args_node: Node) -> List[Node]:
        """Get all arguments from an argument_list node."""
        return [c for c in args_node.children
                if c.type not in ("(", ")", ",", "comment")]


# ============================================================================
# Inter-procedural Analysis — Function Summaries
# ============================================================================

@dataclass
class FunctionSummary:
    """Summary of a function's taint behavior for inter-procedural analysis."""
    name: str
    receiver_type: Optional[str]
    params: List[str]
    # Does any param flow to the return value?
    param_to_return: Set[int] = field(default_factory=set)  # param indices
    # Does the function return tainted data (from any source)?
    tainted_return: bool = False


# ============================================================================
# GoASTAnalyzer — Main Scanner
# ============================================================================

class GoASTAnalyzer:
    """
    AST-based Go vulnerability scanner using tree-sitter.
    Parses Go source, finds functions, runs per-function
    taint analysis, and detects vulnerabilities.
    """

    def __init__(self, source_code: str, file_path: str):
        self.source_code = source_code
        self.source_lines = source_code.splitlines()
        self.file_path = file_path
        self.findings: List[Finding] = []

        # Parse with tree-sitter
        parser = Parser(GO_LANG)
        self.tree = parser.parse(source_code.encode('utf-8'))
        self.root = self.tree.root_node

        # Build structure — functions and methods
        self.functions: List[Node] = []
        self._build_function_list()

    def _build_function_list(self):
        """Find all function and method declarations."""
        # Function declarations: func name(...)
        for func in find_nodes(self.root, "function_declaration"):
            self.functions.append(func)
        # Method declarations: func (r *Type) name(...)
        for method in find_nodes(self.root, "method_declaration"):
            self.functions.append(method)

    def _get_func_name(self, func_node: Node) -> str:
        """Get function/method name."""
        name_node = func_node.child_by_field_name("name")
        if name_node:
            return node_text(name_node)
        # Fallback
        name = get_child_by_type(func_node, "field_identifier")
        if name:
            return node_text(name)
        name = get_child_by_type(func_node, "identifier")
        if name:
            return node_text(name)
        return ""

    def _get_func_params(self, func_node: Node) -> List[str]:
        """Extract parameter names from function signature."""
        params = []
        # For methods, parameters is the second parameter_list
        param_lists = get_children_by_type(func_node, "parameter_list")
        # For function_declaration: first param_list is the parameters
        # For method_declaration: first is receiver, second is parameters
        param_list = None
        if func_node.type == "method_declaration" and len(param_lists) >= 2:
            param_list = param_lists[1]
        elif param_lists:
            param_list = param_lists[0]

        if param_list:
            for param_decl in get_children_by_type(param_list, "parameter_declaration"):
                for child in param_decl.children:
                    if child.type == "identifier":
                        params.append(node_text(child))
        return params

    def _get_receiver_type(self, func_node: Node) -> Optional[str]:
        """Get receiver type for method declarations."""
        if func_node.type != "method_declaration":
            return None
        param_lists = get_children_by_type(func_node, "parameter_list")
        if param_lists:
            receiver_list = param_lists[0]
            for param in get_children_by_type(receiver_list, "parameter_declaration"):
                for child in param.children:
                    if child.type in ("pointer_type", "type_identifier"):
                        return node_text(child)
        return None

    def _is_http_handler(self, func_node: Node) -> bool:
        """Check if function signature matches an HTTP handler pattern."""
        param_lists = get_children_by_type(func_node, "parameter_list")
        param_list = None
        if func_node.type == "method_declaration" and len(param_lists) >= 2:
            param_list = param_lists[1]
        elif param_lists:
            param_list = param_lists[0]

        if not param_list:
            return False

        text = node_text(param_list)
        # Standard http handler: (w http.ResponseWriter, r *http.Request)
        if "http.ResponseWriter" in text or "http.Request" in text:
            return True
        # Gin: (c *gin.Context)
        if "gin.Context" in text:
            return True
        # Echo: (c echo.Context)
        if "echo.Context" in text:
            return True
        # Fiber: (c *fiber.Ctx)
        if "fiber.Ctx" in text:
            return True
        return False

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
        Pass 2: Re-analyze with summaries — user-defined calls propagate taint.
        """
        # Pass 1: Build summaries
        self.function_summaries: Dict[str, FunctionSummary] = {}
        for func in self.functions:
            param_names = self._get_func_params(func)
            tracker = TaintTracker(func, self.source_lines, param_names, is_handler=False)
            summary = self._build_summary(func, tracker)
            if summary:
                self.function_summaries[summary.name] = summary

        # Pass 2: Full analysis with inter-procedural taint
        for func in self.functions:
            param_names = self._get_func_params(func)
            is_handler = self._is_http_handler(func)
            tracker = TaintTracker(func, self.source_lines, param_names, is_handler)
            # Apply inter-procedural taint from function summaries
            self._apply_interprocedural_taint(func, tracker)

            self._check_sql_injection(func, tracker)
            self._check_command_injection(func, tracker)
            self._check_ssti(func, tracker)
            self._check_nosql_injection(func, tracker)
            self._check_xss(func, tracker)
            self._check_open_redirect(func, tracker)
            self._check_ldap_injection(func, tracker)
            self._check_deserialization(func, tracker)
            self._check_code_injection(func, tracker)
            self._check_second_order_sqli(func, tracker)

        return self.findings

    def _build_summary(self, func: Node, tracker: TaintTracker) -> Optional[FunctionSummary]:
        """Build a FunctionSummary from a function's taint tracker state."""
        func_name = self._get_func_name(func)
        if not func_name:
            return None

        receiver_type = self._get_receiver_type(func)
        params = self._get_func_params(func)

        # Check which params flow to return values
        param_to_return: Set[int] = set()
        tainted_return = False
        body = get_child_by_type(func, "block")
        if body:
            return_stmts = find_nodes(body, "return_statement")
            for ret in return_stmts:
                ret_text = node_text(ret)
                for i, pname in enumerate(params):
                    if re.search(rf'\b{re.escape(pname)}\b', ret_text):
                        param_to_return.add(i)
                # Check if return references any tainted variable
                for tv in tracker.tainted:
                    if re.search(rf'\b{re.escape(tv)}\b', ret_text):
                        tainted_return = True
                        # If tainted var was derived from a param, mark it
                        for i, pname in enumerate(params):
                            if pname in tracker.tainted:
                                param_to_return.add(i)

        return FunctionSummary(
            name=func_name,
            receiver_type=receiver_type,
            params=params,
            param_to_return=param_to_return,
            tainted_return=tainted_return,
        )

    def _apply_interprocedural_taint(self, func: Node, tracker: TaintTracker):
        """Apply inter-procedural taint from function summaries to call sites."""
        body = get_child_by_type(func, "block")
        if not body:
            return

        # Find short_var_declarations and assignments with call expressions
        short_decls = find_nodes(body, "short_var_declaration")
        assigns = find_nodes(body, "assignment_statement")

        for decl in short_decls:
            # Get LHS variable name(s)
            lhs_nodes = []
            for child in decl.children:
                if node_text(child) == ":=":
                    break
                if child.type == "identifier":
                    lhs_nodes.append(node_text(child))
                elif child.type == "expression_list":
                    for sub in child.children:
                        if sub.type == "identifier":
                            lhs_nodes.append(node_text(sub))

            if not lhs_nodes:
                continue
            var_name = lhs_nodes[0] if lhs_nodes[0] != "_" else (lhs_nodes[1] if len(lhs_nodes) > 1 else None)
            if not var_name:
                continue

            # Find call expressions in RHS
            calls = find_nodes(decl, "call_expression")
            for call in calls:
                self._check_call_taint(call, var_name, tracker)

        for assign in assigns:
            children = assign.children
            lhs_nodes = []
            found_assign = False
            for child in children:
                if node_text(child) in ("=", "+="):
                    found_assign = True
                elif not found_assign and child.type not in (",",):
                    lhs_nodes.append(child)

            if not lhs_nodes:
                continue
            var_name = node_text(lhs_nodes[0])

            calls = find_nodes(assign, "call_expression")
            for call in calls:
                self._check_call_taint(call, var_name, tracker)

    def _check_call_taint(self, call: Node, target_var: str, tracker: TaintTracker):
        """Check if a call expression should taint the target variable."""
        call_text = node_text(call)

        # Get called function name
        func_node = get_child_by_type(call, "identifier")
        if not func_node:
            # Could be selector_expression: pkg.Func or obj.Method
            sel = get_child_by_type(call, "selector_expression")
            if sel:
                field_node = get_child_by_type(sel, "field_identifier")
                if field_node:
                    call_name = node_text(field_node)
                else:
                    return
            else:
                return
        else:
            call_name = node_text(func_node)

        summary = self.function_summaries.get(call_name)
        if not summary or not summary.param_to_return:
            return

        # Get arguments
        args_node = get_child_by_type(call, "argument_list")
        if not args_node:
            return

        args = [child for child in args_node.children
                if child.type not in ("(", ")", ",")]

        # Check if any argument at a param_to_return index is tainted
        line = get_node_line(call)
        for idx in summary.param_to_return:
            if idx < len(args):
                arg_text = node_text(args[idx])
                for tv in tracker.tainted:
                    if re.search(rf'\b{re.escape(tv)}\b', arg_text):
                        tracker.tainted[target_var] = (
                            line,
                            f"from {call_name}({tv}) [inter-procedural]"
                        )
                        return

    # ========================================================================
    # Helper Methods
    # ========================================================================

    def _get_called_func_name(self, ce: Node) -> str:
        """Get the function/method name from a call_expression node."""
        func_child = ce.child_by_field_name("function")
        if not func_child:
            # Fallback: first child
            for child in ce.children:
                if child.type == "identifier":
                    return node_text(child)
                elif child.type == "selector_expression":
                    field_node = get_child_by_type(child, "field_identifier")
                    return node_text(field_node) if field_node else ""
            return ""

        if func_child.type == "identifier":
            return node_text(func_child)
        elif func_child.type == "selector_expression":
            field_node = get_child_by_type(func_child, "field_identifier")
            return node_text(field_node) if field_node else ""
        return ""

    def _get_receiver_text(self, ce: Node) -> str:
        """Get the receiver/object text of a call expression."""
        func_child = ce.child_by_field_name("function")
        if func_child and func_child.type == "selector_expression":
            # The receiver is everything before the field
            operand = func_child.child_by_field_name("operand")
            if operand:
                return node_text(operand)
            # Fallback: first child of selector
            for child in func_child.children:
                if child.type != "field_identifier" and node_text(child) != ".":
                    return node_text(child)
        return ""

    def _get_first_arg(self, args_node: Node) -> Optional[Node]:
        """Get the first argument from an argument_list node."""
        for child in args_node.children:
            if child.type not in ("(", ")", ",", "comment"):
                return child
        return None

    def _get_all_args(self, args_node: Node) -> List[Node]:
        """Get all arguments from an argument_list node."""
        return [c for c in args_node.children
                if c.type not in ("(", ")", ",", "comment")]

    def _get_full_call_name(self, ce: Node) -> str:
        """Get the full call name (e.g., 'db.Query', 'exec.Command', 'fmt.Sprintf')."""
        func_child = ce.child_by_field_name("function")
        if func_child:
            return node_text(func_child)
        # Fallback
        for child in ce.children:
            if child.type in ("identifier", "selector_expression"):
                return node_text(child)
        return ""

    def _has_tainted_concat(self, node: Node, tracker: TaintTracker) -> bool:
        """Check if a node contains string concatenation with tainted data."""
        # Go uses + for string concat
        binaries = find_nodes(node, "binary_expression")
        for binary in binaries:
            op = None
            for child in binary.children:
                if node_text(child) == "+":
                    op = "+"
                    break
            if op == "+":
                binary_text = node_text(binary)
                if tracker.is_tainted(binary_text):
                    return True

        # Check for fmt.Sprintf
        text = node_text(node)
        if "fmt.Sprintf" in text and tracker.is_tainted(text):
            return True

        return False

    def _has_concat(self, node: Node) -> bool:
        """Check if a node contains any string concatenation."""
        binaries = find_nodes(node, "binary_expression")
        for binary in binaries:
            for child in binary.children:
                if node_text(child) == "+":
                    return True
        text = node_text(node)
        if "fmt.Sprintf" in text:
            return True
        return False

    def _has_parameterized_args(self, ce: Node) -> bool:
        """Check if a SQL call uses parameterized arguments (extra args after query string).
        e.g., db.Query("SELECT ... WHERE id = ?", input) — the extra arg means parameterized."""
        args_node = get_child_by_type(ce, "argument_list")
        if not args_node:
            return False
        args = self._get_all_args(args_node)
        # If there are more than 1 arg, the extra args are query parameters
        if len(args) > 1:
            first_arg_text = node_text(args[0])
            # Check the first arg (query string) for placeholders
            if "?" in first_arg_text or "$" in first_arg_text:
                return True
            # Check for raw string with placeholders
            strings = re.findall(r'["`]([^"`]*)["`]', first_arg_text)
            for s in strings:
                if "?" in s or re.search(r'\$\d+', s):
                    return True
        return False

    # ========================================================================
    # SQL Injection Detection
    # ========================================================================

    def _check_sql_injection(self, func: Node, tracker: TaintTracker):
        """Detect SQL injection via string concatenation in query calls."""
        body = get_child_by_type(func, "block")
        if not body:
            return

        call_exprs = find_nodes(body, "call_expression")

        # SQL execution methods
        sql_methods = {
            "Query", "QueryContext", "QueryRow", "QueryRowContext",
            "Exec", "ExecContext", "Prepare", "PrepareContext",
        }
        # GORM methods that accept raw SQL
        gorm_raw_methods = {"Raw", "Exec"}
        # GORM methods where string concat is dangerous
        gorm_concat_methods = {"Where", "Having", "Joins", "Order", "Group", "Select"}
        # sqlx methods
        sqlx_methods = {"Queryx", "QueryRowx", "Get", "Select", "NamedQuery", "NamedExec"}
        # pgx methods
        pgx_methods = {"Query", "QueryRow", "Exec"}

        for ce in call_exprs:
            ce_text = node_text(ce)
            call_name = self._get_called_func_name(ce)
            full_call = self._get_full_call_name(ce)
            receiver = self._get_receiver_text(ce)
            line = get_node_line(ce)

            args_node = get_child_by_type(ce, "argument_list")
            if not args_node:
                continue

            args = self._get_all_args(args_node)

            # Standard database/sql methods
            if call_name in sql_methods:
                if not args:
                    continue

                # Skip prepared statement execution: stmt.Query(params...)
                # When the receiver is a prepared statement, args are parameters, not SQL
                if receiver and re.search(r'(?i)\bstmt\b|preparedStmt|prepared', receiver):
                    continue

                # Find the query argument (skip context.Context args)
                query_arg = None
                query_arg_idx = 0
                for i, arg in enumerate(args):
                    arg_text = node_text(arg)
                    # Skip context args
                    if re.match(r'(?:ctx|context\.\w+|r\.Context\(\))', arg_text):
                        continue
                    query_arg = arg
                    query_arg_idx = i
                    break

                if not query_arg:
                    continue

                query_text = node_text(query_arg)

                # Check for parameterized query (extra args = params)
                remaining_args = args[query_arg_idx + 1:]
                if remaining_args and ("?" in query_text or re.search(r'\$\d+', query_text)):
                    continue  # Parameterized — safe

                # Check for string concat with tainted data
                if self._has_tainted_concat(query_arg, tracker):
                    self._add_finding(
                        line, 0,
                        f"SQL Injection - String concatenation in {call_name}",
                        VulnCategory.SQL_INJECTION, Severity.CRITICAL, "HIGH",
                        tracker.get_taint_chain(query_text),
                        f"Tainted data concatenated into SQL query passed to {call_name}()."
                    )
                    continue

                # Check if query arg is a tainted variable directly
                if query_arg.type != "interpreted_string_literal" and \
                   query_arg.type != "raw_string_literal" and \
                   tracker.is_tainted(query_text):
                    self._add_finding(
                        line, 0,
                        f"SQL Injection - Tainted variable in {call_name}",
                        VulnCategory.SQL_INJECTION, Severity.CRITICAL, "HIGH",
                        tracker.get_taint_chain(query_text),
                        f"Tainted variable used as query in {call_name}()."
                    )
                    continue

            # GORM Raw/Exec
            if call_name in gorm_raw_methods and receiver:
                if not args:
                    continue
                first_arg = args[0]
                first_arg_text = node_text(first_arg)

                # GORM parameterized: db.Raw("SELECT ? ...", input) — extra args
                if len(args) > 1 and "?" in first_arg_text:
                    continue

                if self._has_tainted_concat(first_arg, tracker):
                    self._add_finding(
                        line, 0,
                        f"SQL Injection - GORM {call_name} with string concatenation",
                        VulnCategory.SQL_INJECTION, Severity.CRITICAL, "HIGH",
                        tracker.get_taint_chain(first_arg_text),
                        f"Tainted data concatenated into GORM {call_name}() query."
                    )
                elif first_arg.type not in ("interpreted_string_literal", "raw_string_literal") and \
                     tracker.is_tainted(first_arg_text):
                    self._add_finding(
                        line, 0,
                        f"SQL Injection - GORM {call_name} with tainted variable",
                        VulnCategory.SQL_INJECTION, Severity.CRITICAL, "HIGH",
                        tracker.get_taint_chain(first_arg_text),
                        f"Tainted variable in GORM {call_name}()."
                    )

            # GORM Where/Having/Joins with string concat
            if call_name in gorm_concat_methods and receiver:
                if not args:
                    continue
                first_arg = args[0]
                first_arg_text = node_text(first_arg)
                # Safe: db.Where(&User{Name: input}) — struct literal
                if first_arg.type in ("unary_expression", "composite_literal"):
                    continue
                # Safe: db.Where("id = ?", input) — parameterized
                if len(args) > 1 and "?" in first_arg_text:
                    continue
                if self._has_tainted_concat(first_arg, tracker):
                    self._add_finding(
                        line, 0,
                        f"SQL Injection - GORM {call_name} with string concatenation",
                        VulnCategory.SQL_INJECTION, Severity.HIGH, "HIGH",
                        tracker.get_taint_chain(first_arg_text),
                        f"Tainted data concatenated into GORM {call_name}() clause."
                    )

            # sqlx methods
            if call_name in sqlx_methods and receiver:
                # Exclude false positives: http.Get is NOT sqlx
                if receiver in ("http", "net/http") or full_call.startswith("http."):
                    continue
                if not args:
                    continue
                # Find query arg (skip ctx)
                query_arg = None
                query_arg_idx = 0
                for i, arg in enumerate(args):
                    arg_text = node_text(arg)
                    if re.match(r'(?:ctx|context\.)', arg_text):
                        continue
                    # For Get/Select, skip the destination arg (pointer)
                    if call_name in ("Get", "Select") and arg_text.startswith("&"):
                        continue
                    query_arg = arg
                    query_arg_idx = i
                    break

                if not query_arg:
                    continue

                query_text = node_text(query_arg)
                remaining_args = args[query_arg_idx + 1:]
                if remaining_args and ("?" in query_text or re.search(r'\$\d+', query_text)):
                    continue  # Parameterized

                if self._has_tainted_concat(query_arg, tracker):
                    self._add_finding(
                        line, 0,
                        f"SQL Injection - sqlx {call_name} with string concatenation",
                        VulnCategory.SQL_INJECTION, Severity.CRITICAL, "HIGH",
                        tracker.get_taint_chain(query_text),
                        f"Tainted data concatenated into sqlx {call_name}() query."
                    )
                elif query_arg.type not in ("interpreted_string_literal", "raw_string_literal") and \
                     tracker.is_tainted(query_text):
                    self._add_finding(
                        line, 0,
                        f"SQL Injection - sqlx {call_name} with tainted variable",
                        VulnCategory.SQL_INJECTION, Severity.CRITICAL, "HIGH",
                        tracker.get_taint_chain(query_text),
                        f"Tainted variable in sqlx {call_name}()."
                    )

    # ========================================================================
    # Command Injection Detection
    # ========================================================================

    def _check_command_injection(self, func: Node, tracker: TaintTracker):
        """Detect command injection via exec.Command, os.StartProcess, syscall.Exec."""
        body = get_child_by_type(func, "block")
        if not body:
            return

        call_exprs = find_nodes(body, "call_expression")

        for ce in call_exprs:
            ce_text = node_text(ce)
            full_call = self._get_full_call_name(ce)
            line = get_node_line(ce)

            args_node = get_child_by_type(ce, "argument_list")
            if not args_node:
                continue
            args = self._get_all_args(args_node)

            # exec.Command("bash", "-c", tainted) — shell invocation
            if full_call == "exec.Command" and len(args) >= 3:
                first_arg = node_text(args[0]).strip('"').strip("'")
                if first_arg in ("bash", "sh", "/bin/bash", "/bin/sh", "cmd", "cmd.exe"):
                    # Check if second arg is "-c" or "/c"
                    second_arg = node_text(args[1]).strip('"').strip("'")
                    if second_arg in ("-c", "/c", "/C"):
                        # Third arg is the command — check taint
                        third_text = node_text(args[2])
                        if tracker.is_tainted(third_text):
                            self._add_finding(
                                line, 0,
                                "Command Injection - exec.Command with shell invocation",
                                VulnCategory.COMMAND_INJECTION, Severity.CRITICAL, "HIGH",
                                tracker.get_taint_chain(third_text),
                                f"Tainted data passed to exec.Command(\"{first_arg}\", \"-c\", ...) allowing shell injection."
                            )
                            continue

            # exec.Command(tainted, ...) — tainted command name
            if full_call == "exec.Command" and args:
                first_text = node_text(args[0])
                if tracker.is_tainted(first_text):
                    self._add_finding(
                        line, 0,
                        "Command Injection - exec.Command with tainted command",
                        VulnCategory.COMMAND_INJECTION, Severity.CRITICAL, "HIGH",
                        tracker.get_taint_chain(first_text),
                        "Tainted data used as command name in exec.Command()."
                    )
                    continue
                # exec.Command("safe", args...) with separate args — safe
                # Only flag if shell invocation detected above

            # exec.CommandContext
            if full_call == "exec.CommandContext" and len(args) >= 4:
                # Skip ctx, check command args
                cmd_arg = node_text(args[1]).strip('"').strip("'")
                if cmd_arg in ("bash", "sh", "/bin/bash", "/bin/sh"):
                    flag_arg = node_text(args[2]).strip('"').strip("'")
                    if flag_arg in ("-c", "/c"):
                        cmd_text = node_text(args[3])
                        if tracker.is_tainted(cmd_text):
                            self._add_finding(
                                line, 0,
                                "Command Injection - exec.CommandContext with shell",
                                VulnCategory.COMMAND_INJECTION, Severity.CRITICAL, "HIGH",
                                tracker.get_taint_chain(cmd_text),
                                "Tainted data in shell command via exec.CommandContext()."
                            )

            # os.StartProcess
            if full_call == "os.StartProcess" and args:
                first_text = node_text(args[0])
                if tracker.is_tainted(first_text):
                    self._add_finding(
                        line, 0,
                        "Command Injection - os.StartProcess with tainted path",
                        VulnCategory.COMMAND_INJECTION, Severity.CRITICAL, "HIGH",
                        tracker.get_taint_chain(first_text),
                        "Tainted data used as process path in os.StartProcess()."
                    )

            # syscall.Exec
            if full_call == "syscall.Exec" and args:
                first_text = node_text(args[0])
                if tracker.is_tainted(first_text):
                    self._add_finding(
                        line, 0,
                        "Command Injection - syscall.Exec with tainted path",
                        VulnCategory.COMMAND_INJECTION, Severity.CRITICAL, "HIGH",
                        tracker.get_taint_chain(first_text),
                        "Tainted data in syscall.Exec()."
                    )

    # ========================================================================
    # SSTI Detection
    # ========================================================================

    def _check_ssti(self, func: Node, tracker: TaintTracker):
        """Detect Server-Side Template Injection."""
        body = get_child_by_type(func, "block")
        if not body:
            return

        call_exprs = find_nodes(body, "call_expression")

        for ce in call_exprs:
            ce_text = node_text(ce)
            call_name = self._get_called_func_name(ce)
            full_call = self._get_full_call_name(ce)
            line = get_node_line(ce)

            args_node = get_child_by_type(ce, "argument_list")
            if not args_node:
                continue
            args = self._get_all_args(args_node)

            # template.New("").Parse(tainted) — chained call
            if call_name == "Parse" and args:
                arg_text = node_text(args[0])
                if tracker.is_tainted(arg_text):
                    # Verify this is a template parse, not something else
                    receiver = self._get_receiver_text(ce)
                    if "template" in ce_text.lower() or "tmpl" in receiver.lower() or \
                       "New(" in receiver or "template.New" in ce_text:
                        self._add_finding(
                            line, 0,
                            "SSTI - template.Parse with tainted input",
                            VulnCategory.SSTI, Severity.HIGH, "HIGH",
                            tracker.get_taint_chain(arg_text),
                            "Tainted data passed to template.Parse() allows template injection."
                        )

            # template.HTML(tainted) — marks string as safe HTML, bypasses auto-escaping
            if full_call == "template.HTML" and args:
                arg_text = node_text(args[0])
                if tracker.is_tainted(arg_text):
                    self._add_finding(
                        line, 0,
                        "XSS - template.HTML bypasses auto-escaping",
                        VulnCategory.XSS, Severity.HIGH, "HIGH",
                        tracker.get_taint_chain(arg_text),
                        "template.HTML() marks tainted data as safe, bypassing html/template auto-escaping."
                    )

            # template.JS(tainted)
            if full_call == "template.JS" and args:
                arg_text = node_text(args[0])
                if tracker.is_tainted(arg_text):
                    self._add_finding(
                        line, 0,
                        "XSS - template.JS bypasses auto-escaping",
                        VulnCategory.XSS, Severity.HIGH, "HIGH",
                        tracker.get_taint_chain(arg_text),
                        "template.JS() marks tainted data as safe JavaScript."
                    )

    # ========================================================================
    # NoSQL Injection Detection
    # ========================================================================

    def _check_nosql_injection(self, func: Node, tracker: TaintTracker):
        """Detect NoSQL injection in MongoDB operations."""
        body = get_child_by_type(func, "block")
        if not body:
            return

        call_exprs = find_nodes(body, "call_expression")

        mongo_methods = {
            "Find", "FindOne", "FindOneAndUpdate", "FindOneAndDelete",
            "FindOneAndReplace", "UpdateOne", "UpdateMany",
            "DeleteOne", "DeleteMany", "ReplaceOne",
            "Aggregate", "CountDocuments", "Distinct",
            "InsertOne", "InsertMany",
        }

        for ce in call_exprs:
            call_name = self._get_called_func_name(ce)
            receiver = self._get_receiver_text(ce)
            line = get_node_line(ce)

            if call_name not in mongo_methods:
                continue

            # Check if receiver looks like a MongoDB collection
            if not re.search(r'(?i)collection|coll|col\b|mongo', receiver):
                continue

            args_node = get_child_by_type(ce, "argument_list")
            if not args_node:
                continue
            args = self._get_all_args(args_node)

            found = False
            for arg in args:
                arg_text = node_text(arg)
                # Skip context args and nil
                if re.match(r'(?:ctx|context\.|nil)', arg_text):
                    continue
                # Skip safe patterns: bson.M{"key": "literal"}, bson.D{...}
                if arg.type in ("composite_literal",):
                    if tracker.is_tainted(arg_text):
                        self._add_finding(
                            line, 0,
                            f"NoSQL Injection - MongoDB {call_name} with tainted filter",
                            VulnCategory.NOSQL_INJECTION, Severity.CRITICAL, "HIGH",
                            tracker.get_taint_chain(arg_text),
                            f"Tainted data in MongoDB {call_name}() filter."
                        )
                        found = True
                    continue
                # Direct tainted variable as filter
                if tracker.is_tainted(arg_text):
                    self._add_finding(
                        line, 0,
                        f"NoSQL Injection - MongoDB {call_name} with tainted filter",
                        VulnCategory.NOSQL_INJECTION, Severity.CRITICAL, "HIGH",
                        tracker.get_taint_chain(arg_text),
                        f"Tainted data used directly as MongoDB {call_name}() filter."
                    )
                    found = True
                    break
            if found:
                continue

    # ========================================================================
    # XSS Detection
    # ========================================================================

    def _check_xss(self, func: Node, tracker: TaintTracker):
        """Detect Cross-Site Scripting via response writing."""
        body = get_child_by_type(func, "block")
        if not body:
            return

        call_exprs = find_nodes(body, "call_expression")

        for ce in call_exprs:
            full_call = self._get_full_call_name(ce)
            call_name = self._get_called_func_name(ce)
            receiver = self._get_receiver_text(ce)
            line = get_node_line(ce)

            args_node = get_child_by_type(ce, "argument_list")
            if not args_node:
                continue
            args = self._get_all_args(args_node)

            # fmt.Fprintf(w, tainted, ...) — writing to ResponseWriter
            if full_call == "fmt.Fprintf" and len(args) >= 2:
                writer_text = node_text(args[0])
                # Check if writer is a ResponseWriter
                if re.search(r'\b[wW]\b|[rR]esponse[wW]riter', writer_text):
                    format_text = node_text(args[1])
                    if tracker.is_tainted(format_text):
                        if not self._is_xss_sanitized(format_text):
                            self._add_finding(
                                line, 0,
                                "XSS - fmt.Fprintf with tainted data to ResponseWriter",
                                VulnCategory.XSS, Severity.HIGH, "HIGH",
                                tracker.get_taint_chain(format_text),
                                "Tainted data written to HTTP response via fmt.Fprintf()."
                            )
                    # Also check remaining format args
                    elif len(args) > 2:
                        for arg in args[2:]:
                            arg_text = node_text(arg)
                            if tracker.is_tainted(arg_text):
                                if not self._is_xss_sanitized(arg_text):
                                    self._add_finding(
                                        line, 0,
                                        "XSS - fmt.Fprintf with tainted format arg",
                                        VulnCategory.XSS, Severity.HIGH, "MEDIUM",
                                        tracker.get_taint_chain(arg_text),
                                        "Tainted data in fmt.Fprintf() format argument."
                                    )
                                break

            # io.WriteString(w, tainted)
            if full_call == "io.WriteString" and len(args) >= 2:
                writer_text = node_text(args[0])
                if re.search(r'\b[wW]\b|[rR]esponse[wW]riter', writer_text):
                    data_text = node_text(args[1])
                    if tracker.is_tainted(data_text):
                        if not self._is_xss_sanitized(data_text):
                            self._add_finding(
                                line, 0,
                                "XSS - io.WriteString with tainted data",
                                VulnCategory.XSS, Severity.HIGH, "HIGH",
                                tracker.get_taint_chain(data_text),
                                "Tainted data written to HTTP response via io.WriteString()."
                            )

            # w.Write(tainted)
            if call_name == "Write" and receiver:
                if re.search(r'\b[wW]\b|[rR]esponse[wW]riter', receiver):
                    if args:
                        data_text = node_text(args[0])
                        if tracker.is_tainted(data_text):
                            if not self._is_xss_sanitized(data_text):
                                self._add_finding(
                                    line, 0,
                                    "XSS - ResponseWriter.Write with tainted data",
                                    VulnCategory.XSS, Severity.HIGH, "HIGH",
                                    tracker.get_taint_chain(data_text),
                                    "Tainted data written to HTTP response via Write()."
                                )

            # Gin: c.String(200, tainted), c.Data(200, contentType, tainted)
            if call_name == "String" and receiver and len(args) >= 2:
                data_text = node_text(args[1])
                if tracker.is_tainted(data_text):
                    self._add_finding(
                        line, 0,
                        "XSS - Gin c.String with tainted data",
                        VulnCategory.XSS, Severity.HIGH, "HIGH",
                        tracker.get_taint_chain(data_text),
                        "Tainted data in Gin c.String() response."
                    )
                # Also check format args
                elif len(args) > 2:
                    for arg in args[2:]:
                        arg_text = node_text(arg)
                        if tracker.is_tainted(arg_text):
                            self._add_finding(
                                line, 0,
                                "XSS - Gin c.String with tainted format arg",
                                VulnCategory.XSS, Severity.HIGH, "MEDIUM",
                                tracker.get_taint_chain(arg_text),
                                "Tainted data in Gin c.String() format argument."
                            )
                            break

            # Echo: c.HTML(200, tainted)
            if call_name == "HTML" and receiver and len(args) >= 2:
                data_text = node_text(args[1])
                if tracker.is_tainted(data_text):
                    self._add_finding(
                        line, 0,
                        "XSS - Echo c.HTML with tainted data",
                        VulnCategory.XSS, Severity.HIGH, "HIGH",
                        tracker.get_taint_chain(data_text),
                        "Tainted data in Echo c.HTML() response."
                    )

    def _is_xss_sanitized(self, text: str) -> bool:
        """Check if XSS data is sanitized."""
        return "html.EscapeString(" in text or \
               "template.HTMLEscapeString(" in text or \
               "url.QueryEscape(" in text

    # ========================================================================
    # Open Redirect Detection
    # ========================================================================

    def _check_open_redirect(self, func: Node, tracker: TaintTracker):
        """Detect open redirect via http.Redirect."""
        body = get_child_by_type(func, "block")
        if not body:
            return

        call_exprs = find_nodes(body, "call_expression")

        for ce in call_exprs:
            full_call = self._get_full_call_name(ce)
            call_name = self._get_called_func_name(ce)
            receiver = self._get_receiver_text(ce)
            line = get_node_line(ce)

            args_node = get_child_by_type(ce, "argument_list")
            if not args_node:
                continue
            args = self._get_all_args(args_node)

            # http.Redirect(w, r, tainted, statusCode)
            if full_call == "http.Redirect" and len(args) >= 3:
                url_text = node_text(args[2])
                if tracker.is_tainted(url_text):
                    self._add_finding(
                        line, 0,
                        "Open Redirect - http.Redirect with tainted URL",
                        VulnCategory.OPEN_REDIRECT, Severity.MEDIUM, "HIGH",
                        tracker.get_taint_chain(url_text),
                        "Tainted data used as redirect URL in http.Redirect()."
                    )

            # Gin/Echo: c.Redirect(302, tainted)
            if call_name == "Redirect" and receiver and len(args) >= 2:
                # Skip http.Redirect (handled above)
                if full_call == "http.Redirect":
                    continue
                url_text = node_text(args[1])
                if tracker.is_tainted(url_text):
                    self._add_finding(
                        line, 0,
                        "Open Redirect - Redirect with tainted URL",
                        VulnCategory.OPEN_REDIRECT, Severity.MEDIUM, "HIGH",
                        tracker.get_taint_chain(url_text),
                        "Tainted data used as redirect URL."
                    )

    # ========================================================================
    # LDAP Injection Detection
    # ========================================================================

    def _check_ldap_injection(self, func: Node, tracker: TaintTracker):
        """Detect LDAP injection via unescaped filter strings."""
        body = get_child_by_type(func, "block")
        if not body:
            return

        call_exprs = find_nodes(body, "call_expression")

        for ce in call_exprs:
            full_call = self._get_full_call_name(ce)
            call_name = self._get_called_func_name(ce)
            line = get_node_line(ce)

            args_node = get_child_by_type(ce, "argument_list")
            if not args_node:
                continue
            args = self._get_all_args(args_node)

            # ldap.NewSearchRequest — filter is typically the 7th arg
            if full_call == "ldap.NewSearchRequest" and len(args) >= 7:
                filter_text = node_text(args[6])
                if tracker.is_tainted(filter_text):
                    self._add_finding(
                        line, 0,
                        "LDAP Injection - NewSearchRequest with tainted filter",
                        VulnCategory.LDAP_INJECTION, Severity.HIGH, "HIGH",
                        tracker.get_taint_chain(filter_text),
                        "Tainted data in LDAP search filter without ldap.EscapeFilter()."
                    )

            # fmt.Sprintf("(uid=%s)", tainted) in LDAP context
            if full_call == "fmt.Sprintf" and args:
                format_str = node_text(args[0])
                if re.search(r'(?:uid|cn|sn|mail|dn|sAMAccountName|objectClass)\s*=\s*%', format_str):
                    for arg in args[1:]:
                        arg_text = node_text(arg)
                        if tracker.is_tainted(arg_text):
                            # Check that the tainted data isn't wrapped in ldap.EscapeFilter
                            if "ldap.EscapeFilter(" not in arg_text:
                                self._add_finding(
                                    line, 0,
                                    "LDAP Injection - Tainted data in LDAP filter string",
                                    VulnCategory.LDAP_INJECTION, Severity.HIGH, "MEDIUM",
                                    tracker.get_taint_chain(arg_text),
                                    "Tainted data in LDAP filter via fmt.Sprintf without EscapeFilter()."
                                )
                            break

    # ========================================================================
    # Insecure Deserialization Detection
    # ========================================================================

    def _check_deserialization(self, func: Node, tracker: TaintTracker):
        """Detect insecure deserialization via gob, yaml, xml."""
        body = get_child_by_type(func, "block")
        if not body:
            return

        call_exprs = find_nodes(body, "call_expression")

        for ce in call_exprs:
            full_call = self._get_full_call_name(ce)
            call_name = self._get_called_func_name(ce)
            receiver = self._get_receiver_text(ce)
            line = get_node_line(ce)

            args_node = get_child_by_type(ce, "argument_list")
            if not args_node:
                continue
            args = self._get_all_args(args_node)
            ce_text = node_text(ce)

            # gob.NewDecoder(r.Body).Decode(&target) — check the decoder source
            # Also handles: decoder := gob.NewDecoder(r.Body); decoder.Decode(&data)
            if call_name == "Decode" and receiver:
                is_gob = "gob.NewDecoder" in receiver or "gob" in receiver.lower()
                # Also check if receiver variable was assigned from gob.NewDecoder
                if not is_gob and receiver in tracker.tainted:
                    # Check taint source description
                    _, source_desc = tracker.tainted[receiver]
                    if "gob" in source_desc.lower() or "NewDecoder" in source_desc:
                        is_gob = True
                # Heuristic: if receiver was assigned from gob.NewDecoder, it's tainted
                if not is_gob:
                    body_text = node_text(body)
                    if re.search(rf'{re.escape(receiver)}\s*:?=\s*gob\.NewDecoder\s*\(', body_text):
                        is_gob = True
                if is_gob:
                    # Check if decoder source is tainted
                    if tracker.is_tainted(receiver) or tracker.is_tainted(ce_text):
                        self._add_finding(
                            line, 0,
                            "Insecure Deserialization - gob.Decode from untrusted source",
                            VulnCategory.DESERIALIZATION, Severity.HIGH, "HIGH",
                            tracker.get_taint_chain(ce_text),
                            "gob.Decode() on data from untrusted source allows arbitrary object creation."
                        )

            # yaml.Unmarshal(tainted, &target)
            if full_call == "yaml.Unmarshal" and args:
                data_text = node_text(args[0])
                if tracker.is_tainted(data_text):
                    self._add_finding(
                        line, 0,
                        "Insecure Deserialization - yaml.Unmarshal with untrusted data",
                        VulnCategory.DESERIALIZATION, Severity.HIGH, "HIGH",
                        tracker.get_taint_chain(data_text),
                        "yaml.Unmarshal() with untrusted data can lead to arbitrary code execution."
                    )

            # xml.Unmarshal(tainted, &target)
            if full_call == "xml.Unmarshal" and args:
                data_text = node_text(args[0])
                if tracker.is_tainted(data_text):
                    self._add_finding(
                        line, 0,
                        "Insecure Deserialization - xml.Unmarshal with untrusted data",
                        VulnCategory.DESERIALIZATION, Severity.MEDIUM, "MEDIUM",
                        tracker.get_taint_chain(data_text),
                        "xml.Unmarshal() with untrusted data."
                    )

    # ========================================================================
    # Code Injection Detection
    # ========================================================================

    def _check_code_injection(self, func: Node, tracker: TaintTracker):
        """Detect code injection via reflect.MethodByName, plugin.Open."""
        body = get_child_by_type(func, "block")
        if not body:
            return

        call_exprs = find_nodes(body, "call_expression")

        for ce in call_exprs:
            full_call = self._get_full_call_name(ce)
            call_name = self._get_called_func_name(ce)
            line = get_node_line(ce)

            args_node = get_child_by_type(ce, "argument_list")
            if not args_node:
                continue
            args = self._get_all_args(args_node)

            # reflect.ValueOf(x).MethodByName(tainted).Call(...)
            if call_name == "MethodByName" and args:
                method_name_text = node_text(args[0])
                if tracker.is_tainted(method_name_text):
                    self._add_finding(
                        line, 0,
                        "Code Injection - reflect.MethodByName with tainted input",
                        VulnCategory.CODE_INJECTION, Severity.HIGH, "HIGH",
                        tracker.get_taint_chain(method_name_text),
                        "Tainted data used to look up method via reflection."
                    )

            # plugin.Open(tainted)
            if full_call == "plugin.Open" and args:
                path_text = node_text(args[0])
                if tracker.is_tainted(path_text):
                    self._add_finding(
                        line, 0,
                        "Code Injection - plugin.Open with tainted path",
                        VulnCategory.CODE_INJECTION, Severity.CRITICAL, "HIGH",
                        tracker.get_taint_chain(path_text),
                        "Tainted data used as plugin path in plugin.Open()."
                    )

    # ========================================================================
    # Second-order SQL Injection Detection
    # ========================================================================

    def _check_second_order_sqli(self, func: Node, tracker: TaintTracker):
        """Detect second-order SQL injection (DB-fetched data in SQL concat)."""
        body = get_child_by_type(func, "block")
        if not body:
            return

        # First, find rows.Scan(&var1, &var2, ...) to mark variables as DB-sourced
        call_exprs = find_nodes(body, "call_expression")
        for ce in call_exprs:
            call_name = self._get_called_func_name(ce)
            if call_name == "Scan":
                args_node = get_child_by_type(ce, "argument_list")
                if not args_node:
                    continue
                args = self._get_all_args(args_node)
                for arg in args:
                    arg_text = node_text(arg)
                    # &var → var is DB-sourced
                    if arg_text.startswith("&"):
                        var_name = arg_text[1:]
                        tracker.db_sourced[var_name] = (get_node_line(ce), "rows.Scan()")

        # Now check for DB-sourced data used in SQL
        sql_methods = {
            "Query", "QueryContext", "QueryRow", "QueryRowContext",
            "Exec", "ExecContext", "Prepare",
        }

        # Also scan assignments/declarations to find variables built from DB-sourced data
        short_decls = find_nodes(body, "short_var_declaration")
        assigns = find_nodes(body, "assignment_statement")
        for decl in short_decls + assigns:
            decl_text = node_text(decl)
            # Check if RHS contains DB-sourced variable in a concat
            for dv in list(tracker.db_sourced.keys()):
                if re.search(rf'\b{re.escape(dv)}\b', decl_text):
                    # Find the LHS variable name
                    for child in decl.children:
                        if child.type == "identifier":
                            var_name = node_text(child)
                            if var_name != dv and var_name != "_":
                                tracker.db_sourced[var_name] = (get_node_line(decl), f"derived from {dv}")
                            break
                        elif child.type == "expression_list":
                            for sub in child.children:
                                if sub.type == "identifier":
                                    var_name = node_text(sub)
                                    if var_name != dv and var_name != "_":
                                        tracker.db_sourced[var_name] = (get_node_line(decl), f"derived from {dv}")
                                    break
                            break
                        elif node_text(child) in (":=", "="):
                            break

        for ce in call_exprs:
            call_name = self._get_called_func_name(ce)
            if call_name not in sql_methods:
                continue

            args_node = get_child_by_type(ce, "argument_list")
            if not args_node:
                continue
            args = self._get_all_args(args_node)
            line = get_node_line(ce)

            for arg in args:
                arg_text = node_text(arg)
                if re.match(r'(?:ctx|context\.)', arg_text):
                    continue
                if tracker.is_db_sourced(arg_text):
                    self._add_finding(
                        line, 0,
                        f"Second-order SQLi - DB-sourced data in {call_name}",
                        VulnCategory.SQL_INJECTION, Severity.HIGH, "MEDIUM",
                        description="Data fetched from database used in string concatenation for SQL query."
                    )
                break


# ============================================================================
# Scanner — File Processing & Output
# ============================================================================

def scan_file(file_path: str, config: VibehunterConfig = None) -> List[Finding]:
    """Scan a single Go file and return findings."""
    if config and config.should_exclude(file_path):
        return []
    try:
        with open(file_path, 'r', encoding='utf-8', errors='replace') as f:
            source = f.read()
    except (IOError, OSError) as e:
        print(f"Error reading {file_path}: {e}", file=sys.stderr)
        return []

    analyzer = GoASTAnalyzer(source, file_path)
    return analyzer.analyze()


def scan_path(target: str, show_progress: bool = True, config: VibehunterConfig = None) -> Tuple[List[Finding], int, float]:
    """Scan a file or directory for Go files. Returns (findings, file_count, elapsed)."""
    all_findings = []
    target_path = Path(target)
    file_count = 0
    start = time.time()

    if target_path.is_file():
        if target_path.suffix == ".go":
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
            console.print(f"[bold yellow]Warning:[/bold yellow] {target} is not a .go file")
    elif target_path.is_dir():
        go_files = sorted(target_path.rglob("*.go"))
        file_count = len(go_files)
        if show_progress and go_files:
            with Progress(
                SpinnerColumn("moon"),
                TextColumn("[bold cyan]{task.description}[/bold cyan]"),
                BarColumn(bar_width=30, style="cyan", complete_style="green"),
                MofNCompleteColumn(),
                TextColumn("[dim]{task.fields[current_file]}[/dim]"),
                console=console, transient=True,
            ) as progress:
                task = progress.add_task("Scanning", total=len(go_files), current_file="")
                for gf in go_files:
                    progress.update(task, current_file=gf.name)
                    all_findings.extend(scan_file(str(gf), config))
                    progress.advance(task)
        else:
            for gf in go_files:
                all_findings.extend(scan_file(str(gf), config))
    else:
        console.print(f"[bold red]Error:[/bold red] {target} does not exist")

    elapsed = time.time() - start
    return all_findings, file_count, elapsed


def filter_findings(findings: List[Finding], min_severity: str = None,
                    min_confidence: str = None, suppression_keyword: str = "nosec") -> List[Finding]:
    """Filter findings by severity, confidence, and inline suppression."""
    result = []
    for f in findings:
        # Check inline suppression (// nosec, // vibehunter:ignore)
        if re.search(rf'(?://|/\*)\s*{re.escape(suppression_keyword)}\b', f.line_content):
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
    """Print the scanner banner using Rich."""
    banner_lines = [
        "  ██████╗  ██████╗ ",
        " ██╔════╝ ██╔═══██╗",
        " ██║  ███╗██║   ██║",
        " ██║   ██║██║   ██║",
        " ╚██████╔╝╚██████╔╝",
        "  ╚═════╝  ╚═════╝ ",
    ]
    banner_text = '\n'.join(banner_lines)

    title_content = Text()
    title_content.append(banner_text, style="bold cyan")
    title_content.append("\n\n")
    title_content.append("Tree-sitter AST Vulnerability Scanner v1.0\n", style="bold white")
    title_content.append("Per-Function Taint Tracking | AST-Based Analysis | Go Security", style="dim")

    console.print()
    console.print(Panel(
        Align.center(title_content),
        border_style="cyan",
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
        "Open Redirect": "Open Redirect",
        "Cross-Site Scripting": "XSS",
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
                snippet, "go", theme="monokai",
                line_numbers=True, start_line=start + 1,
                highlight_lines={f.line_number},
            )
        else:
            syntax = Syntax(
                code_line, "go", theme="monokai",
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
        "scanner": "go-treesitter v1.0",
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
        description="Go AST Vulnerability Scanner using Tree-sitter"
    )
    parser.add_argument("target", help="Go file or directory to scan")
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

        if args.output_file:
            output_text_plain(findings, args.output_file)
            console.print(f"\n[bold green]Report saved to {args.output_file}[/bold green]")

    # Exit with error code if critical/high findings
    critical_high = sum(1 for f in findings if f.severity in (Severity.CRITICAL, Severity.HIGH))
    if critical_high > 0:
        sys.exit(1)


if __name__ == "__main__":
    main()
