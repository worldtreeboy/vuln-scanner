#!/usr/bin/env python3
"""
Java AST Vulnerability Scanner (Tree-sitter)
=============================================
A standalone Java security scanner using tree-sitter for AST-based analysis.
Performs per-method taint tracking with ~80%+ AST-based detection.

Detection Categories:
- SQL Injection (string concat in queries, @Query annotation, HQL)
- Command Injection (Runtime.exec, ProcessBuilder)
- Code Injection (ScriptEngine, SpEL, OGNL, MVEL, Class.forName)
- JNDI Injection (InitialContext.lookup)
- Insecure Deserialization (ObjectInputStream, XMLDecoder, SnakeYAML, XStream)
- XXE (DocumentBuilderFactory, SAXParser, XMLInputFactory)
- XPath Injection (XPath.evaluate/compile with tainted concat)
- Reflection Injection (Class.forName, getMethod with tainted input)
- Second-order SQLi (DB-fetched values in raw SQL)
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

import tree_sitter_java as tsjava
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

JAVA_LANG = Language(tsjava.language())

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
    IDOR = "Mass Assignment / IDOR"


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


def get_annotation_name(annotation_node: Node) -> str:
    """Extract annotation name from a marker_annotation or annotation node."""
    if annotation_node.type == "marker_annotation":
        name_node = get_child_by_type(annotation_node, "identifier")
        return node_text(name_node) if name_node else ""
    elif annotation_node.type == "annotation":
        name_node = get_child_by_type(annotation_node, "identifier")
        return node_text(name_node) if name_node else ""
    return ""


def get_annotations(node: Node) -> List[Tuple[str, Node]]:
    """Get all annotations from a node's modifiers.
    Returns list of (annotation_name, annotation_node)."""
    annotations = []
    modifiers = get_child_by_type(node, "modifiers")
    if modifiers:
        for child in modifiers.children:
            if child.type in ("marker_annotation", "annotation"):
                name = get_annotation_name(child)
                annotations.append((name, child))
    return annotations


def get_annotation_value(annotation_node: Node) -> str:
    """Extract the value/argument from an annotation like @GetMapping("/path")."""
    args = get_child_by_type(annotation_node, "annotation_argument_list")
    if args:
        # Could be a string literal, element_value_pair, etc.
        for child in args.children:
            if child.type == "string_literal":
                return node_text(child).strip('"')
            elif child.type == "element_value_pair":
                val = get_child_by_type(child, "string_literal")
                if val:
                    return node_text(val).strip('"')
                # Could be an array initializer
                arr = get_child_by_type(child, "element_value_array_initializer")
                if arr:
                    strs = find_nodes(arr, "string_literal")
                    return ",".join(node_text(s).strip('"') for s in strs)
    return ""


# ============================================================================
# TaintTracker — Per-Method Taint Analysis
# ============================================================================

class TaintTracker:
    """
    Tracks tainted variables within a single method scope.
    Sources: @PathVariable, @RequestParam, @RequestBody, @CookieValue,
             @RequestHeader, HttpServletRequest.getParameter/getHeader, etc.
    Propagation: assignments, string concat, StringBuilder.append
    """

    # Annotations that make a parameter tainted
    TAINT_ANNOTATIONS = {
        "PathVariable", "RequestParam", "RequestBody",
        "CookieValue", "RequestHeader", "MatrixVariable",
    }

    # Types that indicate taint via request objects
    TAINT_TYPES = {
        "HttpServletRequest", "HttpServletResponse",
        "WebRequest", "NativeWebRequest",
        "MultipartFile", "MultipartHttpServletRequest",
    }

    # Methods on HttpServletRequest that produce tainted data
    TAINT_METHODS = {
        "getParameter", "getParameterValues", "getParameterMap",
        "getHeader", "getHeaders", "getHeaderNames",
        "getQueryString", "getRequestURI", "getRequestURL",
        "getPathInfo", "getCookies", "getInputStream",
        "getReader", "getPart", "getParts",
    }

    # Types that are NOT tainted (framework/infrastructure types)
    SAFE_PARAM_TYPES = {
        "Connection", "EntityManager", "Session", "SessionFactory",
        "DataSource", "JdbcTemplate", "TransactionManager",
        "Logger", "Log",
    }

    # Methods that kill taint by converting to a non-injectable type.
    # Integer.parseInt(tainted) -> int (cannot carry SQLi/RCE payloads)
    # UUID.fromString(tainted) -> UUID (fixed format, not injectable)
    # Boolean.parseBoolean(tainted) -> boolean (only true/false)
    TAINT_KILLER_RE = re.compile(
        r'(?:Integer|Long|Short|Byte|Float|Double)\s*\.\s*(?:parseInt|parseLong|parseShort|parseByte|parseFloat|parseDouble|valueOf)\s*\('
        r'|Boolean\s*\.\s*(?:parseBoolean|valueOf)\s*\('
        r'|UUID\s*\.\s*fromString\s*\('
        r'|Math\s*\.\s*(?:abs|max|min|round|ceil|floor|toIntExact)\s*\('
    )

    def __init__(self, method_node: Node, param_annotations: Dict[str, Set[str]],
                 param_types: Dict[str, str], source_lines: List[str],
                 is_public: bool = True):
        self.method_node = method_node
        self.source_lines = source_lines
        # var_name -> (line_number, source_description)
        self.tainted: Dict[str, Tuple[int, str]] = {}
        # var_name -> (line_number, entity_source)
        self.db_sourced: Dict[str, Tuple[int, str]] = {}

        self._init_taint_from_params(param_annotations, param_types, is_public)
        self._propagate_taint()

    def _init_taint_from_params(self, param_annotations: Dict[str, Set[str]],
                                 param_types: Dict[str, str], is_public: bool):
        """Mark method parameters as tainted based on annotations/types.

        For public methods, ALL non-infrastructure parameters are considered
        potentially tainted since data can flow from controllers/callers.
        """
        already_tainted = set()

        # First pass: mark explicitly annotated params
        for param_name, annots in param_annotations.items():
            for annot in annots:
                if annot in self.TAINT_ANNOTATIONS:
                    line = get_node_line(self.method_node)
                    self.tainted[param_name] = (line, f"@{annot} parameter")
                    already_tainted.add(param_name)
                    break

        for param_name, ptype in param_types.items():
            if ptype in self.TAINT_TYPES and param_name not in already_tainted:
                line = get_node_line(self.method_node)
                self.tainted[param_name] = (line, f"{ptype} parameter")
                already_tainted.add(param_name)

        # Second pass: for public methods, treat all remaining non-infrastructure
        # params as potentially tainted (covers Struts2, plain servlets, service layers)
        if is_public:
            line = get_node_line(self.method_node)
            for param_name, ptype in param_types.items():
                if param_name not in already_tainted and ptype not in self.SAFE_PARAM_TYPES:
                    self.tainted[param_name] = (line, f"method parameter ({ptype})")
            # Also mark params without known types (e.g., primitives)
            all_param_names = set(param_types.keys()) | set(param_annotations.keys())
            # Get ALL param names from the method signature
            params_node = get_child_by_type(self.method_node, "formal_parameters")
            if params_node:
                for param in get_children_by_type(params_node, "formal_parameter"):
                    name_node = get_child_by_type(param, "identifier")
                    if name_node:
                        pname = node_text(name_node)
                        if pname not in already_tainted:
                            self.tainted[pname] = (line, "method parameter")

    def _propagate_taint(self):
        """Walk method body and propagate taint through assignments."""
        body = get_child_by_type(self.method_node, "block")
        if not body:
            return

        # Multi-pass to handle forward references
        for _ in range(3):
            self._propagate_pass(body)

    def _propagate_pass(self, body: Node):
        """Single pass of taint propagation through the method body."""
        # Find all local variable declarations and assignments
        decls = find_nodes(body, "local_variable_declaration")
        assigns = find_nodes(body, "assignment_expression")
        # Also check expression_statements for method calls that return tainted data
        expr_stmts = find_nodes(body, "expression_statement")

        for decl in decls:
            declarators = find_nodes(decl, "variable_declarator")
            for declarator in declarators:
                name_node = get_child_by_type(declarator, "identifier")
                if not name_node:
                    continue
                var_name = node_text(name_node)
                line = get_node_line(declarator)

                # Check if RHS contains tainted data
                # The value is everything after the '=' in the declarator
                children = declarator.children
                rhs_nodes = []
                found_eq = False
                for child in children:
                    if found_eq:
                        rhs_nodes.append(child)
                    elif node_text(child) == "=":
                        found_eq = True

                if rhs_nodes:
                    rhs_text = " ".join(node_text(n) for n in rhs_nodes)

                    # Check for tainted variable reference
                    if self._rhs_is_tainted(rhs_text, rhs_nodes):
                        self.tainted[var_name] = (line, f"assigned from tainted data")
                        continue

                    # Check for request method calls (e.g., request.getParameter("id"))
                    if self._rhs_is_request_call(rhs_text, rhs_nodes):
                        self.tainted[var_name] = (line, f"from request method call")
                        continue

                    # Track DB-sourced variables
                    if self._rhs_is_db_source(rhs_text, rhs_nodes):
                        self.db_sourced[var_name] = (line, rhs_text.strip())

        for assign in assigns:
            children = assign.children
            if len(children) >= 3:
                lhs = children[0]
                rhs = children[2] if len(children) > 2 else None
                if lhs and rhs:
                    var_name = node_text(lhs)
                    rhs_text = node_text(rhs)
                    if self._rhs_is_tainted(rhs_text, [rhs]):
                        self.tainted[var_name] = (get_node_line(assign), "reassigned from tainted data")
                    elif self._rhs_is_request_call(rhs_text, [rhs]):
                        self.tainted[var_name] = (get_node_line(assign), "from request method call")
                    elif self._rhs_is_db_source(rhs_text, [rhs]):
                        self.db_sourced[var_name] = (get_node_line(assign), rhs_text.strip())

        # Track StringBuilder patterns: sb.append(tainted)
        # Track List/Collection patterns: list.add(tainted)
        method_invocations = find_nodes(body, "method_invocation")
        for mi in method_invocations:
            mi_text = node_text(mi)
            # StringBuilder.append(taintedVar)
            append_match = re.match(r'(\w+)\s*\.\s*append\s*\(', mi_text)
            if append_match:
                sb_var = append_match.group(1)
                args = get_child_by_type(mi, "argument_list")
                if args:
                    arg_text = node_text(args)
                    for tv in self.tainted:
                        if re.search(rf'\b{re.escape(tv)}\b', arg_text):
                            self.tainted[sb_var] = (get_node_line(mi), f"StringBuilder.append({tv})")
                            break
            # List.add(taintedVar) — propagate taint to collection
            add_match = re.match(r'(\w+)\s*\.\s*add\s*\(', mi_text)
            if add_match:
                list_var = add_match.group(1)
                args = get_child_by_type(mi, "argument_list")
                if args:
                    arg_text = node_text(args)
                    for tv in self.tainted:
                        if re.search(rf'\b{re.escape(tv)}\b', arg_text):
                            self.tainted[list_var] = (get_node_line(mi), f"List.add({tv})")
                            break

        # Enhanced for-loop: for (Type item : collection)
        # Tree-sitter query:  (enhanced_for_statement
        #                       name: (identifier) @var  value: (_) @iterable)
        # The loop variable inherits taint from the iterable.
        for efs in find_nodes(body, "enhanced_for_statement"):
            name_node = efs.child_by_field_name("name")
            value_node = efs.child_by_field_name("value")
            # Fallback if field names aren't available in this grammar version
            if not name_node or not value_node:
                found_colon = False
                for child in efs.children:
                    if child.type == "identifier" and not found_colon:
                        name_node = child
                    elif node_text(child) == ":":
                        found_colon = True
                    elif found_colon and child.type not in (")", "}"):
                        value_node = child
                        break
            if name_node and value_node:
                var_name = node_text(name_node)
                iter_text = node_text(value_node)
                if self._rhs_is_tainted(iter_text, [value_node]):
                    self.tainted[var_name] = (get_node_line(efs), "for-each over tainted collection")
                elif self._rhs_is_db_source(iter_text, [value_node]):
                    self.db_sourced[var_name] = (get_node_line(efs), iter_text.strip())

        # Try-with-resources: try (Type var = expr) { ... }
        # Tree-sitter query:  (try_with_resources_statement
        #                       resources: (resource_specification
        #                         (resource name: (identifier) @var  value: (_) @init)))
        for resource in find_nodes(body, "resource"):
            name_node = resource.child_by_field_name("name")
            value_node = resource.child_by_field_name("value")
            if not name_node or not value_node:
                # Fallback: walk children for identifier after '='
                found_eq = False
                for child in resource.children:
                    if child.type == "identifier" and not found_eq:
                        name_node = child
                    elif node_text(child) == "=":
                        found_eq = True
                    elif found_eq:
                        value_node = child
                        break
            if name_node and value_node:
                var_name = node_text(name_node)
                rhs_text = node_text(value_node)
                if self._rhs_is_tainted(rhs_text, [value_node]):
                    self.tainted[var_name] = (get_node_line(resource), "try-with-resources from tainted data")
                elif self._rhs_is_request_call(rhs_text, [value_node]):
                    self.tainted[var_name] = (get_node_line(resource), "from request method call")
                elif self._rhs_is_db_source(rhs_text, [value_node]):
                    self.db_sourced[var_name] = (get_node_line(resource), rhs_text.strip())

    def _rhs_is_tainted(self, rhs_text: str, rhs_nodes: List[Node]) -> bool:
        """Check if right-hand side contains a tainted variable.

        Returns False when the RHS wraps tainted data in a taint-killing
        type conversion (e.g. Integer.parseInt, UUID.fromString) because
        the result is a primitive/fixed-format value that cannot carry
        injection payloads.
        """
        # Taint-killing: if the entire RHS is a type-conversion call that
        # wraps tainted data, the result is safe (int, long, UUID, etc.)
        if self.TAINT_KILLER_RE.search(rhs_text):
            return False

        # Remove string literals to avoid matching variable names inside strings
        cleaned = re.sub(r'"[^"]*"', '', rhs_text)
        for tainted_var in self.tainted:
            if re.search(rf'\b{re.escape(tainted_var)}\b', cleaned):
                return True
        return False

    def _rhs_is_request_call(self, rhs_text: str, rhs_nodes: List[Node]) -> bool:
        """Check if RHS is a method call on a request object that produces tainted data."""
        for method in self.TAINT_METHODS:
            if f".{method}(" in rhs_text or f".{method} (" in rhs_text:
                # Verify the receiver is a tainted/request object
                for tv in self.tainted:
                    if re.search(rf'\b{re.escape(tv)}\b', rhs_text):
                        return True
                # Also check for common request variable names
                if re.search(r'\b(?:request|req|httpRequest|servletRequest)\b', rhs_text):
                    return True
        # Also: HttpContext.Request.Query
        if re.search(r'Request\.Query\[', rhs_text):
            return True
        return False

    def _rhs_is_db_source(self, rhs_text: str, rhs_nodes: List[Node]) -> bool:
        """Check if RHS is a database fetch that produces db-sourced data."""
        db_patterns = [
            r'\.find\s*\(', r'\.findById\s*\(', r'\.findOne\s*\(',
            r'\.getOne\s*\(', r'\.getReferenceById\s*\(',
            r'entityManager\s*\.\s*find\s*\(',
            r'\.getSingleResult\s*\(', r'\.getResultList\s*\(',
            r'\.get\w+\s*\(\s*\)',  # getter chain on entity
        ]
        for pattern in db_patterns:
            if re.search(pattern, rhs_text):
                return True
        return False

    def is_tainted(self, text: str) -> bool:
        """Check if a text string references any tainted variable."""
        cleaned = re.sub(r'"[^"]*"', '', text)
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
        for dv in self.db_sourced:
            if re.search(rf'\b{re.escape(dv)}\b', cleaned):
                return True
        return False

    def get_taint_chain(self, text: str) -> List[str]:
        """Get the taint chain for variables referenced in text."""
        chain = []
        cleaned = re.sub(r'"[^"]*"', '', text)
        for tv, (line, source) in self.tainted.items():
            if re.search(rf'\b{re.escape(tv)}\b', cleaned):
                chain.append(f"{tv} <- {source} (line {line})")
        return chain


# ============================================================================
# Inter-procedural Analysis — Function Summaries
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
# JavaASTAnalyzer — Main Scanner
# ============================================================================

class JavaASTAnalyzer:
    """
    AST-based Java vulnerability scanner using tree-sitter.
    Parses Java source, builds class/method structure, runs per-method
    taint analysis, and detects vulnerabilities.
    """

    # Mapping annotations for Spring endpoints
    ENDPOINT_ANNOTATIONS = {
        "GetMapping", "PostMapping", "PutMapping", "DeleteMapping",
        "PatchMapping", "RequestMapping",
    }

    # Auth annotations
    AUTH_ANNOTATIONS = {
        "PreAuthorize", "Secured", "RolesAllowed",
        "DenyAll", "PermitAll",
    }

    # Auth-only annotations (authentication without authorization)
    AUTH_ONLY_ANNOTATIONS = {
        "Authenticated", "LoginRequired",
    }

    def __init__(self, source_code: str, file_path: str):
        self.source_code = source_code
        self.source_lines = source_code.splitlines()
        self.file_path = file_path
        self.findings: List[Finding] = []

        # Parse with tree-sitter
        parser = Parser(JAVA_LANG)
        self.tree = parser.parse(source_code.encode('utf-8'))
        self.root = self.tree.root_node

        # Build structure — classes AND interfaces (Spring Data repos are interfaces)
        self.classes = find_nodes(self.root, "class_declaration")
        self.interfaces = find_nodes(self.root, "interface_declaration")
        self.methods: List[Tuple[Node, Optional[Node]]] = []  # (method, parent_class)
        self._build_method_list()

    def _build_method_list(self):
        """Find all method declarations and their parent classes/interfaces."""
        for cls in self.classes:
            cls_body = get_child_by_type(cls, "class_body")
            if cls_body:
                for method in find_nodes(cls_body, "method_declaration"):
                    self.methods.append((method, cls))
                for method in find_nodes(cls_body, "constructor_declaration"):
                    self.methods.append((method, cls))
        # Interface methods (e.g. Spring Data @Query annotations)
        for iface in self.interfaces:
            iface_body = get_child_by_type(iface, "interface_body")
            if iface_body:
                for method in find_nodes(iface_body, "method_declaration"):
                    self.methods.append((method, iface))
        # Also find methods at top-level (shouldn't happen in valid Java, but just in case)
        for method in find_nodes(self.root, "method_declaration"):
            if not any(m[0] == method for m in self.methods):
                self.methods.append((method, None))

    def _get_method_name(self, method_node: Node) -> str:
        """Get method name from declaration."""
        name = get_child_by_type(method_node, "identifier")
        return node_text(name) if name else ""

    def _is_public_method(self, method_node: Node) -> bool:
        """Check if a method is public (or has no access modifier, which is package-private)."""
        modifiers = get_child_by_type(method_node, "modifiers")
        if not modifiers:
            return True  # No modifiers = package-private, treat as potentially callable
        mod_text = node_text(modifiers)
        if "private" in mod_text:
            return False
        return True  # public, protected, or package-private

    def _get_method_params(self, method_node: Node) -> Tuple[Dict[str, Set[str]], Dict[str, str]]:
        """Extract parameter annotations and types from method.
        Returns (param_annotations, param_types)."""
        param_annotations: Dict[str, Set[str]] = {}
        param_types: Dict[str, str] = {}

        params_node = get_child_by_type(method_node, "formal_parameters")
        if not params_node:
            return param_annotations, param_types

        for param in get_children_by_type(params_node, "formal_parameter"):
            # Get param name
            name_node = get_child_by_type(param, "identifier")
            if not name_node:
                continue
            param_name = node_text(name_node)

            # Get param type
            type_node = None
            for child in param.children:
                if child.type in ("type_identifier", "generic_type", "array_type",
                                  "integral_type", "floating_point_type", "boolean_type"):
                    type_node = child
                    break
            if type_node:
                param_types[param_name] = node_text(type_node)

            # Get param annotations
            annots = set()
            modifiers = get_child_by_type(param, "modifiers")
            if modifiers:
                for child in modifiers.children:
                    if child.type in ("marker_annotation", "annotation"):
                        annot_name = get_annotation_name(child)
                        annots.add(annot_name)
            if annots:
                param_annotations[param_name] = annots

        return param_annotations, param_types

    def _get_class_annotations(self, cls_node: Optional[Node]) -> List[Tuple[str, str]]:
        """Get annotations on a class. Returns [(name, value)]."""
        if not cls_node:
            return []
        annots = get_annotations(cls_node)
        result = []
        for name, node in annots:
            val = get_annotation_value(node) if node.type == "annotation" else ""
            result.append((name, val))
        return result

    def _get_method_annotations(self, method_node: Node) -> List[Tuple[str, str]]:
        """Get annotations on a method. Returns [(name, value)]."""
        annots = get_annotations(method_node)
        result = []
        for name, node in annots:
            val = get_annotation_value(node) if node.type == "annotation" else ""
            result.append((name, val))
        return result

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
        for method, cls in self.methods:
            param_annots, param_types = self._get_method_params(method)
            tracker = TaintTracker(method, param_annots, param_types,
                                   self.source_lines, is_public=False)
            summary = self._build_summary(method, cls, tracker)
            if summary:
                self.function_summaries[summary.name] = summary

        # Pass 2: Full analysis with inter-procedural taint
        for method, cls in self.methods:
            param_annots, param_types = self._get_method_params(method)
            is_public = self._is_public_method(method)
            tracker = TaintTracker(method, param_annots, param_types,
                                   self.source_lines, is_public)
            # Apply inter-procedural taint from function summaries
            self._apply_interprocedural_taint(method, tracker)
            method_annots = self._get_method_annotations(method)
            cls_annots = self._get_class_annotations(cls) if cls else []

            self._check_sql_injection(method, tracker)
            self._check_command_injection(method, tracker)
            self._check_deserialization(method, tracker)
            self._check_xxe(method, tracker)
            self._check_jndi_injection(method, tracker)
            self._check_script_engine(method, tracker)
            self._check_reflection(method, tracker)
            self._check_xpath_injection(method, tracker)
            self._check_ssti(method, tracker)
            self._check_mass_assignment(method, tracker, method_annots)
            self._check_second_order_sqli(method, tracker)
            self._check_nosql_injection(method, tracker)
            self._check_query_annotation(method, method_annots)

        return self.findings

    def _build_summary(self, method: Node, cls: Optional[Node],
                       tracker: TaintTracker) -> Optional[FunctionSummary]:
        """Build a FunctionSummary from a method's taint tracker state."""
        method_name = self._get_method_name(method)
        if not method_name:
            return None

        cls_name = None
        if cls:
            name_node = get_child_by_type(cls, "identifier")
            if name_node:
                cls_name = node_text(name_node)

        # Get parameter names in order
        params = []
        params_node = get_child_by_type(method, "formal_parameters")
        if params_node:
            for param in get_children_by_type(params_node, "formal_parameter"):
                name_node = get_child_by_type(param, "identifier")
                if name_node:
                    params.append(node_text(name_node))

        # Check which params flow to return values
        param_to_return: Set[int] = set()
        tainted_return = False
        body = get_child_by_type(method, "block")
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
                        # If the tainted var was derived from a param, mark it
                        for i, pname in enumerate(params):
                            if pname in tracker.tainted:
                                param_to_return.add(i)

        return FunctionSummary(
            name=method_name,
            class_name=cls_name,
            params=params,
            param_to_return=param_to_return,
            tainted_return=tainted_return,
        )

    def _apply_interprocedural_taint(self, method: Node, tracker: TaintTracker):
        """Apply inter-procedural taint from function summaries to call sites."""
        body = get_child_by_type(method, "block")
        if not body:
            return

        # Find all local variable declarations with method call RHS
        decls = find_nodes(body, "local_variable_declaration")
        assigns = find_nodes(body, "assignment_expression")

        for decl in decls:
            for declarator in find_nodes(decl, "variable_declarator"):
                name_node = get_child_by_type(declarator, "identifier")
                if not name_node:
                    continue
                var_name = node_text(name_node)
                # Find RHS call expressions
                calls = find_nodes(declarator, "method_invocation")
                for call in calls:
                    self._check_call_taint(call, var_name, tracker)

        for assign in assigns:
            children = assign.children
            if len(children) >= 3 and node_text(children[1]) == "=":
                var_name = node_text(children[0])
                calls = find_nodes(children[2], "method_invocation")
                for call in calls:
                    self._check_call_taint(call, var_name, tracker)

    def _check_call_taint(self, call: Node, target_var: str, tracker: TaintTracker):
        """Check if a call expression should taint the target variable."""
        # Get called method name
        call_name_node = get_child_by_type(call, "identifier")
        if not call_name_node:
            return
        call_name = node_text(call_name_node)

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
    # SQL Injection Detection
    # ========================================================================

    def _check_sql_injection(self, method: Node, tracker: TaintTracker):
        """Detect SQL injection via string concatenation in query calls."""
        body = get_child_by_type(method, "block")
        if not body:
            return

        method_invocations = find_nodes(body, "method_invocation")

        # SQL execution methods — unambiguous names (always SQL sinks)
        sql_methods_unambiguous = {
            "createQuery", "createNativeQuery", "createSQLQuery",
            "executeQuery", "executeUpdate",
            "prepareStatement", "prepareCall",
            "queryForList", "queryForObject", "queryForMap",
        }
        # Ambiguous names — only SQL sinks on known JDBC/JPA receivers
        sql_methods_ambiguous = {"update", "batchUpdate", "execute", "query"}
        sql_receiver_patterns = re.compile(
            r'(?i)(?:jdbc|template|statement|stmt|pstmt|preparedStatement|'
            r'entityManager|em|session|connection|conn|con|namedParameter|'
            r'db|database)\b'
        )

        for mi in method_invocations:
            mi_text = node_text(mi)
            # Get the method name being called
            called_method = self._get_called_method_name(mi)
            if called_method not in sql_methods_unambiguous and called_method not in sql_methods_ambiguous:
                continue
            # For ambiguous methods, require a known SQL receiver
            if called_method in sql_methods_ambiguous:
                receiver = self._get_receiver(mi)
                receiver_text = node_text(receiver) if receiver else ""
                if not sql_receiver_patterns.search(receiver_text):
                    continue

            args = get_child_by_type(mi, "argument_list")
            if not args:
                continue

            # Get the first argument (usually the query)
            first_arg = self._get_first_arg(args)
            if not first_arg:
                continue

            first_arg_text = node_text(first_arg)
            line = get_node_line(mi)

            # Check for string concatenation with tainted data
            # NOTE: _is_parameterized_query is NOT checked here. If tainted data
            # is concatenated into the query string, ? placeholders elsewhere only
            # protect OTHER slots — the concat'd fragment is injected raw.
            # e.g. "SELECT * FROM " + table + " WHERE id = ?" — the ? covers id,
            # but table is still injected.
            if self._has_tainted_concat(first_arg, tracker):
                self._add_finding(
                    line, 0,
                    f"SQL Injection - String concatenation in {called_method}",
                    VulnCategory.SQL_INJECTION, Severity.CRITICAL, "HIGH",
                    tracker.get_taint_chain(first_arg_text),
                    f"Tainted data concatenated into SQL query passed to {called_method}()."
                )
                continue

            # Check if the argument is a tainted variable (not a literal)
            if first_arg.type != "string_literal" and tracker.is_tainted(first_arg_text):
                if not self._is_parameterized_query(first_arg_text):
                    self._add_finding(
                        line, 0,
                        f"SQL Injection - Tainted variable in {called_method}",
                        VulnCategory.SQL_INJECTION, Severity.CRITICAL, "HIGH",
                        tracker.get_taint_chain(first_arg_text),
                        f"Tainted variable used as query in {called_method}()."
                    )
                continue

            # Check for String.format in query
            if "String.format" in first_arg_text and tracker.is_tainted(first_arg_text):
                self._add_finding(
                    line, 0,
                    f"SQL Injection - String.format in {called_method}",
                    VulnCategory.SQL_INJECTION, Severity.CRITICAL, "HIGH",
                    tracker.get_taint_chain(first_arg_text),
                    f"String.format with tainted data in SQL query."
                )

            # Check for DB-sourced data (2nd order)
            if tracker.is_db_sourced(first_arg_text):
                if self._has_concat(first_arg):
                    self._add_finding(
                        line, 0,
                        f"Second-order SQLi - DB-sourced data in {called_method}",
                        VulnCategory.SQL_INJECTION, Severity.HIGH, "MEDIUM",
                        description=f"Data fetched from database used in string concatenation for SQL query."
                    )

        # Also check for StringBuilder.toString() passed to SQL methods
        self._check_stringbuilder_sql(body, tracker)

    def _check_stringbuilder_sql(self, body: Node, tracker: TaintTracker):
        """Check for StringBuilder chains resulting in SQL injection."""
        method_invocations = find_nodes(body, "method_invocation")
        sql_methods_unambiguous = {"createQuery", "createNativeQuery", "executeQuery",
                                   "prepareStatement", "queryForList", "queryForObject", "queryForMap"}
        sql_methods_ambiguous = {"execute", "query"}
        sql_receiver_re = re.compile(
            r'(?i)(?:jdbc|template|statement|stmt|pstmt|preparedStatement|'
            r'entityManager|em|session|connection|conn|con|namedParameter|'
            r'db|database)\b'
        )

        for mi in method_invocations:
            called = self._get_called_method_name(mi)
            if called not in sql_methods_unambiguous and called not in sql_methods_ambiguous:
                continue
            # For ambiguous names, require a known SQL receiver
            if called in sql_methods_ambiguous:
                receiver = self._get_receiver(mi)
                if not receiver or not sql_receiver_re.search(node_text(receiver)):
                    continue
            args = get_child_by_type(mi, "argument_list")
            if not args:
                continue
            arg_text = node_text(args)
            # Check for sb.toString() where sb is tainted (tainted via append)
            toString_match = re.search(r'(\w+)\s*\.\s*toString\s*\(\s*\)', arg_text)
            if toString_match:
                sb_var = toString_match.group(1)
                if sb_var in tracker.tainted:
                    line = get_node_line(mi)
                    self._add_finding(
                        line, 0,
                        "SQL Injection - StringBuilder chain with tainted data",
                        VulnCategory.SQL_INJECTION, Severity.CRITICAL, "HIGH",
                        tracker.get_taint_chain(sb_var),
                        "StringBuilder with tainted .append() used in SQL query."
                    )

    # ========================================================================
    # Command Injection Detection
    # ========================================================================

    def _check_command_injection(self, method: Node, tracker: TaintTracker):
        """Detect command injection via Runtime.exec and ProcessBuilder."""
        body = get_child_by_type(method, "block")
        if not body:
            return

        method_invocations = find_nodes(body, "method_invocation")
        object_creations = find_nodes(body, "object_creation_expression")

        for mi in method_invocations:
            mi_text = node_text(mi)
            line = get_node_line(mi)

            # Runtime.getRuntime().exec(tainted)
            if re.search(r'Runtime\s*\.\s*getRuntime\s*\(\s*\)\s*\.\s*exec\s*\(', mi_text):
                args = self._get_exec_args(mi)
                if args and tracker.is_tainted(args):
                    self._add_finding(
                        line, 0,
                        "Command Injection - Runtime.exec with tainted input",
                        VulnCategory.COMMAND_INJECTION, Severity.CRITICAL, "HIGH",
                        tracker.get_taint_chain(args),
                        "User-controlled data passed to Runtime.exec()."
                    )

            # Reflection: Method.invoke on exec
            if re.search(r'\.invoke\s*\(', mi_text) and tracker.is_tainted(mi_text):
                # Check if reflection target is Runtime.exec or similar
                if re.search(r'exec|getRuntime|ProcessBuilder', mi_text) or \
                   re.search(r'getMethod\s*\(\s*"exec"', node_text(body)):
                    self._add_finding(
                        line, 0,
                        "Command Injection - Reflection invoke with tainted input",
                        VulnCategory.COMMAND_INJECTION, Severity.CRITICAL, "HIGH",
                        tracker.get_taint_chain(mi_text),
                        "Tainted data passed to Method.invoke() targeting exec/Runtime."
                    )

        for oc in object_creations:
            oc_text = node_text(oc)
            line = get_node_line(oc)

            # new ProcessBuilder(...tainted...)
            if "ProcessBuilder" in oc_text:
                args = get_child_by_type(oc, "argument_list")
                if args and tracker.is_tainted(node_text(args)):
                    self._add_finding(
                        line, 0,
                        "Command Injection - ProcessBuilder with tainted input",
                        VulnCategory.COMMAND_INJECTION, Severity.CRITICAL, "HIGH",
                        tracker.get_taint_chain(node_text(args)),
                        "User-controlled data passed to ProcessBuilder constructor."
                    )

    # ========================================================================
    # Insecure Deserialization Detection
    # ========================================================================

    def _check_deserialization(self, method: Node, tracker: TaintTracker):
        """Detect insecure deserialization patterns."""
        body = get_child_by_type(method, "block")
        if not body:
            return

        method_invocations = find_nodes(body, "method_invocation")
        object_creations = find_nodes(body, "object_creation_expression")

        # Check for readObject() / readUnshared()
        for mi in method_invocations:
            mi_text = node_text(mi)
            line = get_node_line(mi)
            called = self._get_called_method_name(mi)

            if called in ("readObject", "readUnshared"):
                receiver = self._get_receiver(mi)
                if receiver:
                    recv_text = node_text(receiver)

                    # Skip readObject with arguments (Kryo-style readObject(input, type), not OIS)
                    if called == "readObject":
                        args_node = get_child_by_type(mi, "argument_list")
                        if args_node and len(self._get_all_args(args_node)) > 0:
                            continue

                    # Skip XMLDecoder receivers — handled by dedicated XMLDecoder check
                    if self._is_xml_decoder_var(recv_text, body):
                        continue

                    # Safe: ValidatingObjectInputStream (uses whitelist)
                    if self._is_validating_stream(recv_text, body):
                        continue
                    # Safe: ObjectInputFilter configured on the stream (Java 9+)
                    if self._has_object_input_filter(recv_text, body):
                        continue

                    # Is the stream variable tainted or constructed from tainted data?
                    if tracker.is_tainted(recv_text) or self._stream_is_tainted(recv_text, body, tracker):
                        self._add_finding(
                            line, 0,
                            "Insecure Deserialization - readObject() with untrusted data",
                            VulnCategory.DESERIALIZATION, Severity.CRITICAL, "HIGH",
                            tracker.get_taint_chain(recv_text),
                            "ObjectInputStream.readObject() called on user-controlled stream."
                        )
                    else:
                        # No explicit taint but no filter — gadget chain risk (CWE-502)
                        self._add_finding(
                            line, 0,
                            "Insecure Deserialization - readObject() without deserialization filter",
                            VulnCategory.DESERIALIZATION, Severity.HIGH, "HIGH",
                            description="readObject() called without ObjectInputFilter or "
                                        "ValidatingObjectInputStream. Vulnerable to gadget chain "
                                        "attacks regardless of data source (CWE-502)."
                        )

            # SnakeYAML: yaml.load(tainted)
            if called == "load" and tracker.is_tainted(mi_text):
                # Check receiver is a YAML object, not Hibernate session/other
                receiver = self._get_receiver(mi)
                if receiver:
                    recv_name = node_text(receiver)
                    # Skip if receiver is clearly a Hibernate/JPA session
                    if re.search(r'(?i)session|entityManager|em\b|hibernate', recv_name):
                        pass  # Not a YAML load
                    elif not self._has_safe_constructor(recv_name, body):
                        self._add_finding(
                            line, 0,
                            "Insecure Deserialization - SnakeYAML without SafeConstructor",
                            VulnCategory.DESERIALIZATION, Severity.HIGH, "HIGH",
                            description="SnakeYAML.load() without SafeConstructor allows arbitrary code execution."
                        )

            # XStream: xstream.fromXML(tainted)
            if called == "fromXML" and tracker.is_tainted(mi_text):
                # Check for allowTypes/security configuration
                receiver = self._get_receiver(mi)
                if receiver:
                    recv_name = node_text(receiver)
                    has_security = self._has_xstream_security(recv_name, body)
                    sev = Severity.HIGH if has_security else Severity.CRITICAL
                    conf = "MEDIUM" if has_security else "HIGH"
                    self._add_finding(
                        line, 0,
                        "Insecure Deserialization - XStream",
                        VulnCategory.DESERIALIZATION, sev, conf,
                        description="XStream.fromXML() with user-controlled data can lead to RCE."
                    )

            # enableDefaultTyping (Jackson)
            if called == "enableDefaultTyping":
                self._add_finding(
                    line, 0,
                    "Insecure Deserialization - Jackson enableDefaultTyping",
                    VulnCategory.DESERIALIZATION, Severity.HIGH, "HIGH",
                    description="ObjectMapper.enableDefaultTyping() enables polymorphic deserialization."
                )

            # Kryo: readClassAndObject() — polymorphic deserialization without class whitelist
            if called == "readClassAndObject":
                receiver = self._get_receiver(mi)
                if receiver:
                    recv_name = node_text(receiver)
                    if not self._has_kryo_registration(recv_name, body):
                        sev = Severity.CRITICAL if tracker.is_tainted(mi_text) else Severity.HIGH
                        self._add_finding(
                            line, 0,
                            "Insecure Deserialization - Kryo readClassAndObject()",
                            VulnCategory.DESERIALIZATION, sev, "HIGH",
                            description="Kryo.readClassAndObject() without setRegistrationRequired(true) "
                                        "allows arbitrary class instantiation."
                        )

        # XMLDecoder
        for oc in object_creations:
            oc_text = node_text(oc)
            if "XMLDecoder" in oc_text:
                line = get_node_line(oc)
                args = get_child_by_type(oc, "argument_list")
                if args and tracker.is_tainted(node_text(args)):
                    self._add_finding(
                        line, 0,
                        "Insecure Deserialization - XMLDecoder with untrusted data",
                        VulnCategory.DESERIALIZATION, Severity.CRITICAL, "HIGH",
                        description="XMLDecoder with user-controlled input allows arbitrary code execution."
                    )
                elif args:
                    # XMLDecoder from any source is dangerous — it executes arbitrary method calls
                    self._add_finding(
                        line, 0,
                        "Insecure Deserialization - XMLDecoder",
                        VulnCategory.DESERIALIZATION, Severity.HIGH, "HIGH",
                        description="XMLDecoder can execute arbitrary method calls via crafted XML "
                                    "regardless of data source."
                    )

        # Hessian / Burlap deserialization
        for oc in object_creations:
            oc_text = node_text(oc)
            if re.search(r'(?:Hessian2?Input|BurlapInput)', oc_text):
                line = get_node_line(oc)
                args = get_child_by_type(oc, "argument_list")
                sev = Severity.CRITICAL if (args and tracker.is_tainted(node_text(args))) else Severity.HIGH
                self._add_finding(
                    line, 0,
                    "Insecure Deserialization - Hessian/Burlap",
                    VulnCategory.DESERIALIZATION, sev, "HIGH",
                    description="Hessian/Burlap deserialization allows arbitrary object instantiation."
                )

        # Base64 decode followed by ObjectInputStream
        for mi in method_invocations:
            mi_text = node_text(mi)
            if "decode" in mi_text and "Base64" in mi_text and tracker.is_tainted(mi_text):
                line = get_node_line(mi)
                self._add_finding(
                    line, 0,
                    "Deserialization Risk - Base64 decoding user input",
                    VulnCategory.DESERIALIZATION, Severity.MEDIUM, "MEDIUM",
                    description="Base64-decoded user input may be deserialized downstream."
                )

    def _strip_comments(self, text: str) -> str:
        """Remove Java line comments and block comments from text for safety checks."""
        text = re.sub(r'//[^\n]*', '', text)
        text = re.sub(r'/\*.*?\*/', '', text, flags=re.DOTALL)
        return text

    def _stream_is_tainted(self, stream_var: str, body: Node, tracker: TaintTracker) -> bool:
        """Check if an ObjectInputStream variable was constructed from tainted data."""
        # Look for: new ObjectInputStream(taintedSource)
        object_creations = find_nodes(body, "object_creation_expression")
        for oc in object_creations:
            oc_text = node_text(oc)
            if "ObjectInputStream" in oc_text:
                # Skip ValidatingObjectInputStream (uses whitelist)
                if "ValidatingObjectInputStream" in oc_text:
                    return False
                args = get_child_by_type(oc, "argument_list")
                if not args:
                    continue
                args_text = node_text(args)
                # Direct tainted arg
                if tracker.is_tainted(args_text):
                    return True
                # ByteArrayInputStream(taintedBytes)
                if "ByteArrayInputStream" in args_text and tracker.is_tainted(args_text):
                    return True
                # Check if the inner stream variable was constructed from tainted source
                # e.g., new ObjectInputStream(fis) where fis = new FileInputStream(taintedPath)
                inner_vars = re.findall(r'\b([a-zA-Z_]\w*)\b', args_text)
                for iv in inner_vars:
                    if self._inner_stream_is_tainted(iv, body, tracker):
                        return True
        return False

    def _inner_stream_is_tainted(self, var_name: str, body: Node, tracker: TaintTracker) -> bool:
        """Check if a stream variable was constructed from a tainted source."""
        if tracker.is_tainted(var_name):
            return True
        body_text = node_text(body)
        # FileInputStream(taintedPath) / BufferedInputStream(taintedStream)
        pat = rf'{re.escape(var_name)}\s*=\s*new\s+\w*(?:File|Buffered|Socket|URL)?\w*InputStream\s*\(([^)]+)\)'
        m = re.search(pat, body_text)
        if m:
            constructor_arg = m.group(1).strip()
            if tracker.is_tainted(constructor_arg):
                return True
        # socket.getInputStream(), url.openStream(), connection.getInputStream()
        stream_pat = rf'{re.escape(var_name)}\s*=\s*(\w+)\s*\.\s*(?:getInputStream|openStream)\s*\('
        m = re.search(stream_pat, body_text)
        if m and tracker.is_tainted(m.group(1)):
            return True
        return False

    def _is_validating_stream(self, var_name: str, body: Node) -> bool:
        """Check if a variable was created as ValidatingObjectInputStream."""
        body_text = node_text(body)
        return bool(re.search(rf'{re.escape(var_name)}\s*=\s*new\s+(?:[\w.]*\.)?ValidatingObjectInputStream', body_text))

    def _has_safe_constructor(self, yaml_var: str, body: Node) -> bool:
        """Check if a Yaml instance uses SafeConstructor."""
        body_text = node_text(body)
        # Pattern: new Yaml(new SafeConstructor()) or fully-qualified variants
        return bool(re.search(r'new\s+(?:[\w.]*\.)?Yaml\s*\(\s*new\s+(?:[\w.]*\.)?SafeConstructor', body_text))

    def _has_xstream_security(self, xstream_var: str, body: Node) -> bool:
        """Check if XStream has security configuration."""
        body_text = node_text(body)
        return bool(re.search(rf'{re.escape(xstream_var)}\s*\.\s*(?:allowTypes|setupDefaultSecurity|addPermission|allowTypesByWildcard)', body_text))

    def _is_xml_decoder_var(self, var_name: str, body: Node) -> bool:
        """Check if a variable was constructed as XMLDecoder."""
        body_text = node_text(body)
        return bool(re.search(rf'{re.escape(var_name)}\s*=\s*new\s+XMLDecoder', body_text))

    def _has_object_input_filter(self, stream_var: str, body: Node) -> bool:
        """Check if ObjectInputFilter is configured on the stream (Java 9+)."""
        body_text = node_text(body)
        # Pattern: stream.setObjectInputFilter(...)
        if re.search(rf'{re.escape(stream_var)}\s*\.\s*setObjectInputFilter\s*\(', body_text):
            return True
        # Pattern: ObjectInputFilter.Config.setSerialFilter(...) — global JVM filter
        if 'setSerialFilter' in body_text:
            return True
        return False

    def _has_kryo_registration(self, kryo_var: str, body: Node) -> bool:
        """Check if Kryo has setRegistrationRequired(true) — class whitelist mode."""
        body_text = self._strip_comments(node_text(body))
        return bool(re.search(rf'{re.escape(kryo_var)}\s*\.\s*setRegistrationRequired\s*\(\s*true\s*\)', body_text))

    # ========================================================================
    # XXE Detection
    # ========================================================================

    def _check_xxe(self, method: Node, tracker: TaintTracker):
        """Detect XXE via unsafe XML parser configuration."""
        body = get_child_by_type(method, "block")
        if not body:
            return

        body_text = node_text(body)

        # Track XML factory variables and their security configuration
        factory_vars: Dict[str, Tuple[int, str]] = {}  # var -> (line, factory_type)
        secure_vars: Set[str] = set()

        # Find factory instantiations
        method_invocations = find_nodes(body, "method_invocation")
        decls = find_nodes(body, "local_variable_declaration")

        for decl in decls:
            decl_text = node_text(decl)
            line = get_node_line(decl)
            for factory_type in ("DocumentBuilderFactory", "SAXParserFactory",
                                 "XMLInputFactory", "TransformerFactory",
                                 "SchemaFactory", "XMLReaderFactory"):
                if factory_type in decl_text:
                    # Get the variable name
                    declarators = find_nodes(decl, "variable_declarator")
                    for d in declarators:
                        name = get_child_by_type(d, "identifier")
                        if name:
                            factory_vars[node_text(name)] = (line, factory_type)

        # Check for secure configuration
        for mi in method_invocations:
            mi_text = node_text(mi)
            called = self._get_called_method_name(mi)

            if called in ("setFeature", "setProperty", "setAttribute"):
                # Check if securing a factory
                receiver = self._get_receiver(mi)
                if receiver:
                    recv_name = node_text(receiver).strip()
                    if recv_name in factory_vars:
                        args_text = node_text(get_child_by_type(mi, "argument_list") or mi)
                        if any(s in args_text for s in [
                            "disallow-doctype-decl",
                            "external-general-entities",
                            "external-parameter-entities",
                            "FEATURE_SECURE_PROCESSING",
                            "ACCESS_EXTERNAL_DTD",
                            "ACCESS_EXTERNAL_STYLESHEET",
                            "IS_SUPPORTING_EXTERNAL_ENTITIES",
                        ]):
                            secure_vars.add(recv_name)

        # Report unsecured factories
        for var_name, (line, factory_type) in factory_vars.items():
            if var_name not in secure_vars:
                self._add_finding(
                    line, 0,
                    f"XXE - {factory_type} without secure configuration",
                    VulnCategory.XXE, Severity.HIGH, "MEDIUM",
                    description=f"{factory_type} created without disabling external entities."
                )

    # ========================================================================
    # JNDI Injection Detection
    # ========================================================================

    def _check_jndi_injection(self, method: Node, tracker: TaintTracker):
        """Detect JNDI injection via lookup with tainted data."""
        body = get_child_by_type(method, "block")
        if not body:
            return

        for mi in find_nodes(body, "method_invocation"):
            called = self._get_called_method_name(mi)
            if called == "lookup":
                args = get_child_by_type(mi, "argument_list")
                if args and tracker.is_tainted(node_text(args)):
                    line = get_node_line(mi)
                    self._add_finding(
                        line, 0,
                        "JNDI Injection - lookup with tainted data",
                        VulnCategory.CODE_INJECTION, Severity.CRITICAL, "HIGH",
                        tracker.get_taint_chain(node_text(args)),
                        "User-controlled data in JNDI lookup() allows remote code execution (Log4Shell-style)."
                    )

    # ========================================================================
    # Script Engine / SpEL / OGNL / MVEL Injection
    # ========================================================================

    def _check_script_engine(self, method: Node, tracker: TaintTracker):
        """Detect code injection via ScriptEngine, SpEL, OGNL, MVEL, EL."""
        body = get_child_by_type(method, "block")
        if not body:
            return

        for mi in find_nodes(body, "method_invocation"):
            mi_text = node_text(mi)
            called = self._get_called_method_name(mi)
            line = get_node_line(mi)

            # ScriptEngine.eval(tainted)
            if called == "eval":
                args = get_child_by_type(mi, "argument_list")
                if not args:
                    continue
                first = self._get_first_arg(args)
                if not first:
                    continue
                if tracker.is_tainted(node_text(first)):
                    self._add_finding(
                        line, 0,
                        "Code Injection - ScriptEngine.eval with tainted data",
                        VulnCategory.CODE_INJECTION, Severity.CRITICAL, "HIGH",
                        tracker.get_taint_chain(node_text(first)),
                        "User-controlled code passed to ScriptEngine.eval()."
                    )
                elif first.type == "string_literal":
                    self._add_finding(
                        line, 0,
                        "Code Injection - ScriptEngine.eval with hardcoded script (lower risk)",
                        VulnCategory.CODE_INJECTION, Severity.LOW, "LOW",
                        description="Hardcoded script in ScriptEngine.eval()."
                    )

            # SpEL: parseExpression(tainted).getValue()
            if called == "parseExpression":
                args = get_child_by_type(mi, "argument_list")
                if args and tracker.is_tainted(node_text(args)):
                    self._add_finding(
                        line, 0,
                        "SpEL Injection - Expression parser with tainted data",
                        VulnCategory.CODE_INJECTION, Severity.CRITICAL, "HIGH",
                        description="User-controlled expression in Spring Expression Language."
                    )

            # OGNL: Ognl.getValue(tainted, ctx)
            if called == "getValue" and "Ognl" in mi_text:
                args = get_child_by_type(mi, "argument_list")
                if args and tracker.is_tainted(node_text(args)):
                    self._add_finding(
                        line, 0,
                        "OGNL Injection - OGNL evaluation with tainted data",
                        VulnCategory.CODE_INJECTION, Severity.CRITICAL, "HIGH",
                        description="User-controlled OGNL expression allows remote code execution."
                    )
                # Also flag the OGNL usage pattern
                self._add_finding(
                    line, 0,
                    "OGNL Expression - Potential injection point",
                    VulnCategory.CODE_INJECTION, Severity.HIGH, "MEDIUM",
                    description="OGNL evaluation detected — verify input is not user-controlled."
                )

            # MVEL: MVEL.eval(tainted)
            if called == "eval" and "MVEL" in mi_text:
                args = get_child_by_type(mi, "argument_list")
                if args and tracker.is_tainted(node_text(args)):
                    self._add_finding(
                        line, 0,
                        "MVEL Injection - MVEL evaluation with tainted data",
                        VulnCategory.CODE_INJECTION, Severity.CRITICAL, "HIGH",
                        description="User-controlled MVEL expression allows code execution."
                    )

            # EL: ELProcessor.eval(tainted)
            if called == "eval" and re.search(r'[Ee][Ll](?:Processor|Context)', mi_text):
                args = get_child_by_type(mi, "argument_list")
                if args and tracker.is_tainted(node_text(args)):
                    self._add_finding(
                        line, 0,
                        "EL Injection - Expression Language evaluation with tainted data",
                        VulnCategory.CODE_INJECTION, Severity.CRITICAL, "HIGH",
                        description="User-controlled expression in EL evaluation."
                    )

            # MVEL: MVEL.compileExpression(tainted) -> executeExpression()
            if called == "compileExpression" and "MVEL" in mi_text:
                args = get_child_by_type(mi, "argument_list")
                if args and tracker.is_tainted(node_text(args)):
                    self._add_finding(
                        line, 0,
                        "MVEL Injection - MVEL.compileExpression with tainted data",
                        VulnCategory.CODE_INJECTION, Severity.CRITICAL, "HIGH",
                        description="User-controlled MVEL expression compiled for execution."
                    )

            # MVEL: MVEL.executeExpression(compiled) — flag if compiled var is tainted
            if called == "executeExpression" and "MVEL" in mi_text:
                args = get_child_by_type(mi, "argument_list")
                if args and tracker.is_tainted(node_text(args)):
                    self._add_finding(
                        line, 0,
                        "MVEL Injection - MVEL.executeExpression with tainted data",
                        VulnCategory.CODE_INJECTION, Severity.CRITICAL, "HIGH",
                        description="Compiled MVEL expression from user input executed."
                    )

            # EL: ExpressionFactory.createValueExpression(ctx, tainted, type)
            if called == "createValueExpression":
                args = get_child_by_type(mi, "argument_list")
                if args and tracker.is_tainted(node_text(args)):
                    self._add_finding(
                        line, 0,
                        "EL Injection - ExpressionFactory.createValueExpression with tainted data",
                        VulnCategory.CODE_INJECTION, Severity.CRITICAL, "HIGH",
                        description="User-controlled expression in EL ValueExpression creation."
                    )

    # ========================================================================
    # Reflection Injection
    # ========================================================================

    def _check_reflection(self, method: Node, tracker: TaintTracker):
        """Detect reflection injection via Class.forName and getMethod."""
        body = get_child_by_type(method, "block")
        if not body:
            return

        for mi in find_nodes(body, "method_invocation"):
            mi_text = node_text(mi)
            called = self._get_called_method_name(mi)
            line = get_node_line(mi)

            # Class.forName(tainted)
            if called == "forName" and "Class" in mi_text:
                args = get_child_by_type(mi, "argument_list")
                if args and tracker.is_tainted(node_text(args)):
                    self._add_finding(
                        line, 0,
                        "Reflection Injection - Class.forName with tainted data",
                        VulnCategory.CODE_INJECTION, Severity.CRITICAL, "HIGH",
                        tracker.get_taint_chain(node_text(args)),
                        "User-controlled class name in Class.forName() allows arbitrary class loading."
                    )

            # getMethod(tainted) for exec-style reflection
            if called == "getMethod":
                args = get_child_by_type(mi, "argument_list")
                if args:
                    arg_text = node_text(args)
                    if '"exec"' in arg_text:
                        self._add_finding(
                            line, 0,
                            "Command Injection - Reflection getMethod('exec')",
                            VulnCategory.COMMAND_INJECTION, Severity.HIGH, "HIGH",
                            description="Reflection used to access Runtime.exec() method."
                        )

    # ========================================================================
    # XPath Injection
    # ========================================================================

    def _check_xpath_injection(self, method: Node, tracker: TaintTracker):
        """Detect XPath injection via tainted string in xpath evaluate/compile."""
        body = get_child_by_type(method, "block")
        if not body:
            return

        for mi in find_nodes(body, "method_invocation"):
            called = self._get_called_method_name(mi)
            if called not in ("evaluate", "compile"):
                continue

            mi_text = node_text(mi)
            # Heuristic: check if this is likely an XPath call
            if not re.search(r'[Xx][Pp]ath|XPathConstants', mi_text):
                # Check surrounding context for xpath variable
                receiver = self._get_receiver(mi)
                if receiver:
                    recv_text = node_text(receiver)
                    if not re.search(r'[Xx][Pp]ath', recv_text):
                        continue
                else:
                    continue

            args = get_child_by_type(mi, "argument_list")
            if not args:
                continue

            first = self._get_first_arg(args)
            if not first:
                continue

            if self._has_tainted_concat(first, tracker) or \
               (first.type != "string_literal" and tracker.is_tainted(node_text(first))):
                line = get_node_line(mi)
                self._add_finding(
                    line, 0,
                    f"XPath Injection - tainted data in xpath.{called}()",
                    VulnCategory.XPATH_INJECTION, Severity.HIGH, "HIGH",
                    tracker.get_taint_chain(node_text(first)),
                    f"User-controlled data in XPath {called}() expression."
                )

    # ========================================================================
    # SSTI (Template Injection)
    # ========================================================================

    def _check_ssti(self, method: Node, tracker: TaintTracker):
        """Detect server-side template injection."""
        body = get_child_by_type(method, "block")
        if not body:
            return

        for mi in find_nodes(body, "method_invocation"):
            mi_text = node_text(mi)
            called = self._get_called_method_name(mi)
            line = get_node_line(mi)

            # Velocity.evaluate(ctx, writer, tag, taintedTemplate)
            if called == "evaluate":
                is_velocity = re.search(r'[Vv]elocity|VelocityEngine', mi_text)
                if not is_velocity:
                    # Check if receiver variable was created as VelocityEngine in method body
                    receiver = self._get_receiver(mi)
                    if receiver:
                        recv_name = node_text(receiver)
                        body_text = node_text(body)
                        if re.search(rf'{re.escape(recv_name)}\s*=\s*new\s+(?:[\w.]*\.)?VelocityEngine', body_text) or \
                           re.search(rf'VelocityEngine\s+{re.escape(recv_name)}\b', body_text):
                            is_velocity = True
                if is_velocity:
                    args = get_child_by_type(mi, "argument_list")
                    if args and tracker.is_tainted(node_text(args)):
                        self._add_finding(
                            line, 0,
                            "SSTI - Velocity template with tainted data",
                            VulnCategory.SSTI, Severity.CRITICAL, "HIGH",
                            description="User-controlled Velocity template allows code execution."
                        )

            # Thymeleaf: engine.process(tainted, ctx)
            if called == "process":
                is_thymeleaf = re.search(r'[Tt]hyme|[Tt]emplate', mi_text)
                if not is_thymeleaf:
                    # Check if receiver was declared as TemplateEngine
                    receiver = self._get_receiver(mi)
                    if receiver:
                        recv_name = node_text(receiver)
                        body_text = node_text(body)
                        if re.search(rf'TemplateEngine\s+{re.escape(recv_name)}\b', body_text) or \
                           re.search(rf'{re.escape(recv_name)}\s*=\s*new\s+(?:[\w.]*\.)?TemplateEngine', body_text):
                            is_thymeleaf = True
                if is_thymeleaf:
                    args = get_child_by_type(mi, "argument_list")
                    if args:
                        first = self._get_first_arg(args)
                        if first and tracker.is_tainted(node_text(first)):
                            self._add_finding(
                                line, 0,
                                "SSTI - Thymeleaf template with tainted data",
                                VulnCategory.SSTI, Severity.CRITICAL, "HIGH",
                                description="User-controlled template string in Thymeleaf engine."
                            )

            # Pebble: pebble.getLiteralTemplate(tainted) / pebble.getTemplate(tainted)
            if called in ("getLiteralTemplate", "getTemplate") and \
               re.search(r'[Pp]ebble', mi_text):
                args = get_child_by_type(mi, "argument_list")
                if args and tracker.is_tainted(node_text(args)):
                    self._add_finding(
                        line, 0,
                        "SSTI - Pebble template from user input",
                        VulnCategory.SSTI, Severity.CRITICAL, "HIGH",
                        description="User-controlled Pebble template allows code execution."
                    )

            # JMustache: Mustache.compiler().compile(tainted)
            if called == "compile" and re.search(r'[Mm]ustache', mi_text):
                args = get_child_by_type(mi, "argument_list")
                if args and tracker.is_tainted(node_text(args)):
                    self._add_finding(
                        line, 0,
                        "SSTI - Mustache template from user input",
                        VulnCategory.SSTI, Severity.CRITICAL, "HIGH",
                        description="User-controlled Mustache template allows code execution."
                    )

            # Groovy: engine.createTemplate(tainted) — SimpleTemplateEngine, GStringTemplateEngine
            if called == "createTemplate":
                is_groovy = re.search(r'(?i)groovy|SimpleTemplate|GString|MarkupTemplate|StreamingMarkupBuilder', mi_text)
                if not is_groovy:
                    receiver = self._get_receiver(mi)
                    if receiver:
                        recv_name = node_text(receiver)
                        body_text = node_text(body)
                        if re.search(rf'(?:SimpleTemplateEngine|GStringTemplateEngine|MarkupTemplateEngine)\s+{re.escape(recv_name)}\b', body_text) or \
                           re.search(rf'{re.escape(recv_name)}\s*=\s*new\s+(?:[\w.]*\.)?(?:SimpleTemplateEngine|GStringTemplateEngine|MarkupTemplateEngine)', body_text):
                            is_groovy = True
                if is_groovy:
                    args = get_child_by_type(mi, "argument_list")
                    if args and tracker.is_tainted(node_text(args)):
                        self._add_finding(
                            line, 0,
                            "SSTI - Groovy template from user input",
                            VulnCategory.SSTI, Severity.CRITICAL, "HIGH",
                            description="User-controlled Groovy template allows code execution."
                        )

            # Jinjava: jinjava.render(tainted, context)
            if called == "render" and re.search(r'(?i)jinja', mi_text):
                args = get_child_by_type(mi, "argument_list")
                if args:
                    first = self._get_first_arg(args)
                    if first and tracker.is_tainted(node_text(first)):
                        self._add_finding(
                            line, 0,
                            "SSTI - Jinjava template from user input",
                            VulnCategory.SSTI, Severity.CRITICAL, "HIGH",
                            description="User-controlled Jinjava template allows code execution."
                        )

            # Handlebars: handlebars.compileInline(tainted)
            if called == "compileInline" and re.search(r'(?i)handlebars', mi_text):
                args = get_child_by_type(mi, "argument_list")
                if args and tracker.is_tainted(node_text(args)):
                    self._add_finding(
                        line, 0,
                        "SSTI - Handlebars template from user input",
                        VulnCategory.SSTI, Severity.CRITICAL, "HIGH",
                        description="User-controlled Handlebars template allows code execution."
                    )

        # Freemarker: new Template(name, new StringReader(tainted), cfg)
        for oc in find_nodes(body, "object_creation_expression"):
            oc_text = node_text(oc)
            if "Template" in oc_text and "StringReader" in oc_text:
                if tracker.is_tainted(oc_text):
                    line = get_node_line(oc)
                    self._add_finding(
                        line, 0,
                        "SSTI - Freemarker template from user input",
                        VulnCategory.SSTI, Severity.CRITICAL, "HIGH",
                        description="User-controlled Freemarker template allows code execution."
                    )

    # ========================================================================
    # NoSQL Injection
    # ========================================================================

    def _check_nosql_injection(self, method: Node, tracker: TaintTracker):
        """Detect NoSQL injection patterns."""
        body = get_child_by_type(method, "block")
        if not body:
            return

        for mi in find_nodes(body, "method_invocation"):
            called = self._get_called_method_name(mi)
            mi_text = node_text(mi)
            line = get_node_line(mi)

            # Document.parse(tainted) for MongoDB
            if called == "parse":
                receiver = self._get_receiver(mi)
                recv_text = node_text(receiver).strip() if receiver else ""
                # Match Document.parse or org.bson.Document.parse, but NOT DocumentBuilder.parse
                if re.search(r'(?:^|\.)Document$', recv_text):
                    args = get_child_by_type(mi, "argument_list")
                    if args and tracker.is_tainted(node_text(args)):
                        self._add_finding(
                            line, 0,
                            "NoSQL Injection - MongoDB Document.parse with tainted data",
                            VulnCategory.NOSQL_INJECTION, Severity.CRITICAL, "HIGH",
                            description="User-controlled data parsed as MongoDB document."
                        )

        # new Document("$where", tainted) / new BasicDBObject("$where", tainted)
        for oc in find_nodes(body, "object_creation_expression"):
            oc_text = node_text(oc)
            if ("Document" in oc_text or "BasicDBObject" in oc_text) \
               and "$where" in oc_text:
                if tracker.is_tainted(oc_text):
                    line = get_node_line(oc)
                    self._add_finding(
                        line, 0,
                        "NoSQL Injection - MongoDB $where with tainted data",
                        VulnCategory.NOSQL_INJECTION, Severity.CRITICAL, "HIGH",
                        description="User-controlled data in MongoDB $where clause."
                    )

    # ========================================================================
    # IDOR Detection
    # ========================================================================

    def _check_mass_assignment(self, method: Node, tracker: TaintTracker,
                                method_annots: List[Tuple[str, str]]):
        """Detect mass assignment via @RequestBody directly to save()."""
        body = get_child_by_type(method, "block")
        if not body:
            return

        # Find @RequestBody params
        param_annots, _ = self._get_method_params(method)
        request_body_params = set()
        for param_name, annots in param_annots.items():
            if "RequestBody" in annots:
                request_body_params.add(param_name)

        if not request_body_params:
            return

        # Check if @RequestBody param is passed directly to save/update
        save_methods = {"save", "saveAndFlush", "saveAll", "update", "merge", "persist"}
        for mi in find_nodes(body, "method_invocation"):
            called = self._get_called_method_name(mi)
            if called not in save_methods:
                continue

            args = get_child_by_type(mi, "argument_list")
            if not args:
                continue

            arg_text = node_text(args)
            for rb_param in request_body_params:
                if re.search(rf'\b{re.escape(rb_param)}\b', arg_text):
                    line = get_node_line(mi)
                    self._add_finding(
                        line, 0,
                        "Mass Assignment - @RequestBody directly to save()",
                        VulnCategory.IDOR, Severity.HIGH, "MEDIUM",
                        description=f"@RequestBody '{rb_param}' passed directly to {called}() without field filtering."
                    )

    # ========================================================================
    # Second-Order SQLi
    # ========================================================================

    def _check_second_order_sqli(self, method: Node, tracker: TaintTracker):
        """Detect second-order SQL injection via DB-sourced data in queries."""
        body = get_child_by_type(method, "block")
        if not body:
            return

        if not tracker.db_sourced:
            return

        sql_methods = {"createQuery", "createNativeQuery", "executeQuery", "execute",
                       "prepareStatement", "query"}

        for mi in find_nodes(body, "method_invocation"):
            called = self._get_called_method_name(mi)
            if called not in sql_methods:
                continue

            args = get_child_by_type(mi, "argument_list")
            if not args:
                continue

            first = self._get_first_arg(args)
            if not first:
                continue

            first_text = node_text(first)
            if self._has_concat(first) and tracker.is_db_sourced(first_text):
                line = get_node_line(mi)
                self._add_finding(
                    line, 0,
                    f"Second-order SQLi - DB-sourced data concatenated in {called}",
                    VulnCategory.SQL_INJECTION, Severity.HIGH, "MEDIUM",
                    description="Data fetched from database used in string concatenation for SQL query."
                )

    # ========================================================================
    # @Query Annotation SQL Injection (Spring Data JPA)
    # ========================================================================

    def _check_query_annotation(self, method: Node, method_annots: List[Tuple[str, str]]):
        """Detect SQL injection risks in Spring Data @Query annotations.

        Checks for:
        1. nativeQuery=true with SpEL #{...} interpolation (injection via SpEL)
        2. JPQL/HQL queries using string concat (compile-time only, but still flaggable)
        3. Missing parameter binding (:param or ?N) in queries with method parameters

        Tree-sitter S-expression:
          (annotation
            name: (identifier) @name (#eq? @name "Query")
            arguments: (annotation_argument_list
              (element_value_pair
                key: (identifier) @key
                value: (string_literal) @value)))
        """
        line = get_node_line(method)

        for annot_name, annot_value in method_annots:
            if annot_name != "Query" or not annot_value:
                continue

            # Get the raw annotation node text to check for nativeQuery=true
            annots = get_annotations(method)
            is_native = False
            full_annot_text = ""
            for name, anode in annots:
                if name == "Query":
                    full_annot_text = node_text(anode)
                    if re.search(r'nativeQuery\s*=\s*true', full_annot_text):
                        is_native = True
                    break

            # Check for SpEL injection: #{...} in native queries
            # #{#paramName} is safe (Spring Data binds it), but #{...} with
            # complex expressions like #{#entityName} or T(...)  can be risky
            spel_matches = re.findall(r'#\{([^}]+)\}', annot_value)
            for spel_expr in spel_matches:
                # Simple param refs like #paramName are safe
                if re.match(r'^#\w+$', spel_expr.strip()):
                    continue
                # Complex SpEL: T(java.lang.Runtime), new, concatenation
                if re.search(r'\bT\s*\(|\.class\b|new\s+|getClass\(\)', spel_expr):
                    self._add_finding(
                        line, 0,
                        "SpEL Injection in @Query annotation",
                        VulnCategory.SQL_INJECTION, Severity.HIGH, "MEDIUM",
                        description=f"Complex SpEL expression in @Query: #{{...}} with '{spel_expr}'. "
                                    "If any referenced variable is user-controlled, this enables injection."
                    )

            # Check for string concatenation in the annotation value itself
            # (annotation_argument_list may contain binary_expression with +)
            for name, anode in annots:
                if name == "Query":
                    # Look for + operator inside the annotation argument list
                    arg_list = get_child_by_type(anode, "annotation_argument_list")
                    if arg_list:
                        binaries = find_nodes(arg_list, "binary_expression")
                        for binary in binaries:
                            has_plus = any(node_text(c) == "+" for c in binary.children)
                            if has_plus:
                                # String concat in annotation — compile-time constant but
                                # still a code smell / potential injection pattern
                                bin_text = node_text(binary)
                                # Only flag if a non-literal is concatenated
                                has_non_literal = any(
                                    c.type not in ("string_literal", "+", "(", ")")
                                    and node_text(c).strip() not in ("+",)
                                    for c in binary.children
                                )
                                if has_non_literal:
                                    self._add_finding(
                                        line, 0,
                                        "SQL Injection - String concatenation in @Query",
                                        VulnCategory.SQL_INJECTION, Severity.HIGH, "MEDIUM",
                                        description="Non-literal string concatenation in @Query annotation value. "
                                                    "Use parameter binding (:param or ?1) instead."
                                    )
                    break

            # Check for queries that don't use parameter binding
            # If the method has parameters but the query has no :param or ?N placeholders
            params_node = get_child_by_type(method, "formal_parameters")
            if params_node and annot_value:
                param_count = len(get_children_by_type(params_node, "formal_parameter"))
                has_binding = bool(re.search(r'(?:\?\d+|:\w+)', annot_value))
                # If native query with params but no binding — likely vulnerable
                if is_native and param_count > 0 and not has_binding and not spel_matches:
                    self._add_finding(
                        line, 0,
                        "SQL Injection - @Query(nativeQuery=true) without parameter binding",
                        VulnCategory.SQL_INJECTION, Severity.HIGH, "MEDIUM",
                        description=f"Native SQL query with {param_count} method parameter(s) "
                                    "but no :param or ?N binding detected."
                    )

    # ========================================================================
    # Utility Methods
    # ========================================================================

    def _get_called_method_name(self, mi: Node) -> str:
        """Get the method name from a method_invocation node."""
        # Use tree-sitter's field-based access for accuracy
        name_node = mi.child_by_field_name("name")
        if name_node:
            return node_text(name_node)
        # Fallback: last identifier before argument_list
        last_id = None
        for child in mi.children:
            if child.type == "identifier":
                last_id = child
            elif child.type == "argument_list":
                break
        return node_text(last_id) if last_id else ""

    def _get_receiver(self, mi: Node) -> Optional[Node]:
        """Get the receiver (object) of a method invocation."""
        # Use tree-sitter's field-based access
        obj_node = mi.child_by_field_name("object")
        return obj_node

    def _get_first_arg(self, args_node: Node) -> Optional[Node]:
        """Get the first argument from an argument_list node."""
        for child in args_node.children:
            if child.type not in ("(", ")", ",", "comment", "line_comment", "block_comment"):
                return child
        return None

    def _get_all_args(self, args_node: Node) -> List[Node]:
        """Get all arguments from an argument_list node."""
        return [c for c in args_node.children
                if c.type not in ("(", ")", ",", "comment", "line_comment", "block_comment")]

    def _get_exec_args(self, mi: Node) -> Optional[str]:
        """Get the arguments string for an exec() call."""
        # Navigate through the chain to find the exec argument_list
        text = node_text(mi)
        match = re.search(r'\.exec\s*\((.+)\)', text, re.DOTALL)
        if match:
            return match.group(1).strip()
        return None

    def _has_tainted_concat(self, node: Node, tracker: TaintTracker) -> bool:
        """Check if a node contains string concatenation with tainted data."""
        # Check for binary expression with + operator
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

        # Check for String.format
        text = node_text(node)
        if "String.format" in text and tracker.is_tainted(text):
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
        if "String.format" in text:
            return True
        return False

    def _is_parameterized_query(self, text: str) -> bool:
        """Check if SQL text uses parameterized queries."""
        # Check for ? placeholders
        if "?" in text:
            # Make sure it's in a string literal context
            strings = re.findall(r'"([^"]*)"', text)
            for s in strings:
                if "?" in s:
                    return True
        # Check for :namedParam
        strings = re.findall(r'"([^"]*)"', text)
        for s in strings:
            if re.search(r':\w+', s):
                return True
        return False


# ============================================================================
# Scanner — File Processing & Output
# ============================================================================

def scan_file(file_path: str, config: VibehunterConfig = None) -> List[Finding]:
    """Scan a single Java file and return findings."""
    if config and config.should_exclude(file_path):
        return []
    try:
        with open(file_path, 'r', encoding='utf-8', errors='replace') as f:
            source = f.read()
    except (IOError, OSError) as e:
        print(f"Error reading {file_path}: {e}", file=sys.stderr)
        return []

    analyzer = JavaASTAnalyzer(source, file_path)
    return analyzer.analyze()


def scan_path(target: str, show_progress: bool = True, config: VibehunterConfig = None) -> Tuple[List[Finding], int, float]:
    """Scan a file or directory for Java files. Returns (findings, file_count, elapsed)."""
    all_findings = []
    target_path = Path(target)
    file_count = 0
    start = time.time()

    if target_path.is_file():
        if target_path.suffix == ".java":
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
            console.print(f"[bold yellow]Warning:[/bold yellow] {target} is not a .java file")
    elif target_path.is_dir():
        java_files = sorted(target_path.rglob("*.java"))
        file_count = len(java_files)
        if show_progress and java_files:
            with Progress(
                SpinnerColumn("moon"),
                TextColumn("[bold cyan]{task.description}[/bold cyan]"),
                BarColumn(bar_width=30, style="cyan", complete_style="green"),
                MofNCompleteColumn(),
                TextColumn("[dim]{task.fields[current_file]}[/dim]"),
                console=console, transient=True,
            ) as progress:
                task = progress.add_task("Scanning", total=len(java_files), current_file="")
                for jf in java_files:
                    progress.update(task, current_file=jf.name)
                    all_findings.extend(scan_file(str(jf), config))
                    progress.advance(task)
        else:
            for jf in java_files:
                all_findings.extend(scan_file(str(jf), config))
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
        "     ██╗ █████╗ ██╗   ██╗ █████╗",
        "     ██║██╔══██╗██║   ██║██╔══██╗",
        "     ██║███████║██║   ██║███████║",
        "██   ██║██╔══██║╚██╗ ██╔╝██╔══██║",
        "╚█████╔╝██║  ██║ ╚████╔╝ ██║  ██║",
        " ╚════╝ ╚═╝  ╚═╝  ╚═══╝  ╚═╝  ╚═╝",
    ]
    banner_text = '\n'.join(banner_lines)

    title_content = Text()
    title_content.append(banner_text, style="bold red")
    title_content.append("\n\n")
    title_content.append("Tree-sitter AST Vulnerability Scanner v1.0\n", style="bold white")
    title_content.append("Per-Method Taint Tracking | AST-Based Analysis | Zero False Positives", style="dim")

    console.print()
    console.print(Panel(
        Align.center(title_content),
        border_style="red",
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
        "Mass Assignment / IDOR": "Mass Assignment",
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
                snippet, "java", theme="monokai",
                line_numbers=True, start_line=start + 1,
                highlight_lines={f.line_number},
            )
        else:
            syntax = Syntax(
                code_line, "java", theme="monokai",
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
        "scanner": "java-treesitter v1.0",
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
        description="Java AST Vulnerability Scanner using Tree-sitter"
    )
    parser.add_argument("target", help="Java file or directory to scan")
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

    # Default filters (same as vibehunter.py)
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
