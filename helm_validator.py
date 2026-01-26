#!/usr/bin/env python3
"""
Helm Template Validator - Erweiterte Quoting-Regeln

Regeln:
1. Control-Flow (if, range, with, define) → NIEMALS quoten
2. Variable Assignment ($var :=) → NIEMALS quoten
3. String Literals in Vergleichen → IMMER quoten ("production")
4. Funktion Parameter Literals → IMMER quoten (replace "-" "_")
5. Default Fallback → Typ-abhängig (default 3 vs default "latest")
6. Output Strings → IMMER quoten ("{{ .Values.name }}")
7. Output Integer/Boolean → NIEMALS quoten ({{ .Values.replicas }})
8. Pipe Functions (upper, lower, etc.) → Output quoten
"""

from ruamel.yaml import YAML
import re
import sys
import os
from pathlib import Path
from dataclasses import dataclass
from enum import Enum
from typing import List, Dict, Optional, Tuple, Set

# Force UTF-8 encoding on Windows
if sys.platform == 'win32':
    os.environ['PYTHONIOENCODING'] = 'utf-8'

# Importiere yamllint als Library
try:
    from yamllint import linter
    from yamllint.config import YamlLintConfig
    YAMLLINT_AVAILABLE = True
except ImportError:
    YAMLLINT_AVAILABLE = False


# =============================================================================
# ENUMS & DATA CLASSES
# =============================================================================

class Severity(Enum):
    """Validierungs-Strictness Level."""
    ERROR = "error"
    WARNING = "warning"
    INFO = "info"


class ErrorType(Enum):
    """Typen von Validierungsfehlern."""
    # Control Flow Errors
    IF_EXPRESSION_QUOTED = "if_expression_quoted"
    RANGE_EXPRESSION_QUOTED = "range_expression_quoted"
    WITH_EXPRESSION_QUOTED = "with_expression_quoted"
    VARIABLE_ASSIGNMENT_QUOTED = "variable_assignment_quoted"
    VARIABLE_IN_CONDITION_QUOTED = "variable_in_condition_quoted"
    
    # Literal Errors
    STRING_LITERAL_NOT_QUOTED = "string_literal_not_quoted"
    FUNCTION_PARAM_NOT_QUOTED = "function_param_not_quoted"
    DEFAULT_STRING_NOT_QUOTED = "default_string_not_quoted"
    DEFAULT_INT_QUOTED = "default_int_quoted"
    TERNARY_LITERAL_NOT_QUOTED = "ternary_literal_not_quoted"
    
    # Output Errors
    OUTPUT_STRING_NOT_QUOTED = "output_string_not_quoted"
    OUTPUT_INT_QUOTED = "output_int_quoted"
    OUTPUT_BOOL_QUOTED = "output_bool_quoted"
    
    # Pipe Function Errors
    PIPE_STRING_OUTPUT_NOT_QUOTED = "pipe_string_output_not_quoted"
    QUOTE_FUNCTION_ON_BOOL = "quote_function_on_bool"
    QUOTE_FUNCTION_ON_INT = "quote_function_on_int"


@dataclass
class ValidationError:
    """Repräsentiert einen Validierungsfehler."""
    line_num: int
    line_content: str
    error_type: ErrorType
    message: str
    expected: str
    actual: str
    severity: Severity = Severity.ERROR
    
    def __str__(self):
        icon = {"error": "❌", "warning": "⚠️", "info": "ℹ️"}[self.severity.value]
        return (
            f"  {icon} Zeile {self.line_num}: {self.message}\n"
            f"      Aktuell:   {self.actual}\n"
            f"      Erwartet:  {self.expected}"
        )


# =============================================================================
# PATTERNS
# =============================================================================

# Control-Flow Patterns (Zeilen die komplett ignoriert werden für Output-Validierung)
HELM_CONTROL_PATTERNS = [
    r'^\s*\{\{-?\s*if\s',
    r'^\s*\{\{-?\s*else\s*if\s',
    r'^\s*\{\{-?\s*else\s+?}\s',
    r'^\s*\{\{-?\s*end\s*-?\}\}',
    r'^\s*\{\{-?\s*range\s',
    r'^\s*\{\{-?\s*with\s',
    r'^\s*\{\{-?\s*define\s',
    r'^\s*\{\{-?\s*template\s',
    r'^\s*\{\{-?\s*include\s',
    r'^\s*\{\{-?\s*block\s',
    r'^\s*\{\{-?\s*/\*',
    r'^\s*\{\{-?\s*\$[a-zA-Z_][a-zA-Z0-9_]*\s*:=',
]

# Pipe Functions die String-Output erzeugen
STRING_PIPE_FUNCTIONS = {
    'upper', 'lower', 'title', 'untitle',
    'trim', 'trimAll', 'trimPrefix', 'trimSuffix',
    'replace', 'repeat', 'substr', 'nospace',
    'trunc', 'abbrev', 'abbrevboth', 'wrap', 'wrapWith',
    'quote', 'squote', 'cat', 'indent', 'nindent',
    'printf', 'toString', 'toJson', 'toPrettyJson', 'toYaml',
    'b64enc', 'b64dec', 'sha256sum', 'sha1sum',
    'default',  # wenn String-Default
}

# Pipe Functions die den Typ beibehalten oder ändern
TYPE_PRESERVING_FUNCTIONS = {
    'int', 'int64', 'float64',  # Konvertiert zu Number
    'bool',  # Konvertiert zu Boolean
    'required',  # Behält Typ
}

# Functions die Literale als Parameter benötigen
FUNCTIONS_WITH_LITERAL_PARAMS = {
    'replace': 2,      # replace "old" "new"
    'trimPrefix': 1,   # trimPrefix "prefix"
    'trimSuffix': 1,   # trimSuffix "suffix"
    'trimAll': 1,      # trimAll "chars"
    'trunc': 1,        # trunc 5
    'substr': 2,       # substr 0 5
    'repeat': 1,       # repeat 3
    'indent': 1,       # indent 4
    'nindent': 1,      # nindent 4
    'printf': -1,      # printf "%s" (variable Anzahl)
    'default': 1,      # default "value" oder default 3
    'ternary': 2,      # ternary "yes" "no"
    'coalesce': -1,    # coalesce (variable Anzahl)
}

# Comparison Functions
COMPARISON_FUNCTIONS = {'eq', 'ne', 'lt', 'le', 'gt', 'ge', 'and', 'or', 'not'}

# Boolean Functions
BOOLEAN_FUNCTIONS = {'and', 'or', 'not', 'empty', 'eq', 'ne', 'lt', 'le', 'gt', 'ge'}


# =============================================================================
# HELM VALIDATOR CLASS
# =============================================================================

class HelmValidator:
    """Validator für Helm Template Quoting-Regeln."""
    
    def __init__(self, type_map: Dict[str, str] = None, strict: bool = False):
        """
        Args:
            type_map: Mapping von Variable-Pfaden zu Typen
            strict: Wenn True, werden auch Warnungen als Fehler behandelt
        """
        self.type_map = type_map or {}
        self.strict = strict
        self.errors: List[ValidationError] = []
    
    def validate_file(self, file_path: str) -> Tuple[bool, List[ValidationError]]:
        """
        Validiert eine Helm-Template-Datei.
        
        Returns:
            Tuple[bool, List[ValidationError]]: (is_valid, errors)
        """
        self.errors = []
        
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()
        except Exception as e:
            print(f"[ERROR] Fehler beim Lesen von {file_path}: {e}", file=sys.stderr)
            return False, []
        
        lines = content.split('\n')
        
        for line_num, line in enumerate(lines, 1):
            self._validate_line(line_num, line)
        
        is_valid = not any(e.severity == Severity.ERROR for e in self.errors)
        if self.strict:
            is_valid = is_valid and not any(e.severity == Severity.WARNING for e in self.errors)
        
        return is_valid, self.errors
    
    def _validate_line(self, line_num: int, line: str):
        """Validiert eine einzelne Zeile."""
        stripped = line.strip()
        
        # Skip leere Zeilen und Kommentare
        if not stripped or stripped.startswith('#'):
            return
        
        # Prüfe Control-Flow Zeilen
        if self._is_control_flow_line(stripped):
            self._validate_control_flow(line_num, line, stripped)
            return
        
        # Prüfe Output-Expressions (normale Zeilen mit {{ }})
        self._validate_output_expressions(line_num, line)
    
    def _is_control_flow_line(self, line: str) -> bool:
        """Prüft ob eine Zeile Control-Flow enthält."""
        for pattern in HELM_CONTROL_PATTERNS:
            if re.search(pattern, line):
                return True
        return False
    
    # =========================================================================
    # CONTROL FLOW VALIDATION
    # =========================================================================
    
    def _validate_control_flow(self, line_num: int, line: str, stripped: str):
        """Validiert Control-Flow Zeilen (if, range, with, etc.)."""
        
        # 1. Variable Assignment: {{- $var := ... }}
        var_assign_match = re.search(
            r'\{\{-?\s*(\$[a-zA-Z_][a-zA-Z0-9_]*)\s*:=\s*(.*?)\s*-?\}\}',
            stripped
        )
        if var_assign_match:
            self._validate_variable_assignment(line_num, line, var_assign_match)
            return
        
        # 2. If Expression: {{- if ... }}
        if_match = re.search(r'\{\{-?\s*(?:else\s+)?if\s+(.*?)\s*-?\}\}', stripped)
        if if_match:
            self._validate_if_expression(line_num, line, if_match.group(1))
            return
        
        # 3. Range Expression: {{- range ... }}
        range_match = re.search(r'\{\{-?\s*range\s+(.*?)\s*-?\}\}', stripped)
        if range_match:
            self._validate_range_expression(line_num, line, range_match.group(1))
            return
        
        # 4. With Expression: {{- with ... }}
        with_match = re.search(r'\{\{-?\s*with\s+(.*?)\s*-?\}\}', stripped)
        if with_match:
            self._validate_with_expression(line_num, line, with_match.group(1))
            return
    
    def _validate_variable_assignment(self, line_num: int, line: str, match):
        """
        Validiert Variable Assignment.
        
        Correct: {{- $var := .Values.name }}
        Wrong:   {{- $var := ".Values.name" }}
        """
        var_name = match.group(1)
        value = match.group(2).strip()
        
        # Prüfe ob Value fälschlicherweise gequoted ist
        if self._is_quoted(value):
            inner = value[1:-1]
            # Wenn es eine Variable ist, sollte sie nicht gequoted sein
            if re.match(r'^\.', inner) or inner.startswith('$'):
                self.errors.append(ValidationError(
                    line_num=line_num,
                    line_content=line.strip(),
                    error_type=ErrorType.VARIABLE_ASSIGNMENT_QUOTED,
                    message=f"Variable Assignment darf nicht gequoted sein",
                    expected=f"{{{{- {var_name} := {inner} }}}}",
                    actual=f"{{{{- {var_name} := {value} }}}}",
                    severity=Severity.ERROR
                ))
    
    def _validate_if_expression(self, line_num: int, line: str, expression: str):
        """
        Validiert If Expression.
        
        Correct: {{- if .Values.enabled }}
        Correct: {{- if eq .Values.env "production" }}
        Wrong:   {{- if ".Values.enabled" }}
        Wrong:   {{- if eq .Values.env production }}
        """
        expression = expression.strip()
        
        # 1. Prüfe auf gequotete Variable/Expression am Anfang
        # Wrong: {{- if ".Values.enabled" }}
        if self._is_quoted(expression):
            inner = expression[1:-1]
            if re.match(r'^\.', inner) or inner.startswith('$') or '{{' in inner:
                self.errors.append(ValidationError(
                    line_num=line_num,
                    line_content=line.strip(),
                    error_type=ErrorType.IF_EXPRESSION_QUOTED,
                    message=f"If-Expression darf nicht gequoted sein",
                    expected=f"{{{{- if {inner} }}}}",
                    actual=f"{{{{- if {expression} }}}}",
                    severity=Severity.ERROR
                ))
            return
        
        # 2. Prüfe Comparison Functions (eq, ne, etc.)
        comp_match = re.match(r'(eq|ne|lt|le|gt|ge)\s+(.+)', expression)
        if comp_match:
            self._validate_comparison(line_num, line, comp_match.group(1), comp_match.group(2))
            return
        
        # 3. Prüfe and/or mit Variablen
        if expression.startswith('and ') or expression.startswith('or '):
            self._validate_boolean_expression(line_num, line, expression)
            return
        
        # 4. Einfache Variable - sollte nicht gequoted sein
        if re.match(r'^\$[a-zA-Z_][a-zA-Z0-9_]*$', expression):
            # Variablen-Check OK
            pass
        elif re.match(r'^\.', expression):
            # .Values.xxx Check OK
            pass
    
    def _validate_comparison(self, line_num: int, line: str, func: str, args: str):
        """
        Validiert Comparison Expressions.
        
        Correct: eq .Values.env "production"
        Wrong:   eq .Values.env production
        """
        args = args.strip()
        
        # Parse Arguments
        # Pattern: Variable/Value dann optionaler String-Literal
        parts = self._parse_comparison_args(args)
        
        if len(parts) >= 2:
            first_arg, second_arg = parts[0], parts[1]
            
            # Wenn zweites Argument ein String-Literal sein sollte
            # (nicht Variable, nicht Zahl, nicht Boolean)
            if not self._is_variable(second_arg) and not self._is_number(second_arg) and not self._is_boolean(second_arg):
                if not self._is_quoted(second_arg):
                    self.errors.append(ValidationError(
                        line_num=line_num,
                        line_content=line.strip(),
                        error_type=ErrorType.STRING_LITERAL_NOT_QUOTED,
                        message=f"String-Literal in Vergleich muss gequoted sein",
                        expected=f'{func} {first_arg} "{second_arg}"',
                        actual=f'{func} {first_arg} {second_arg}',
                        severity=Severity.ERROR
                    ))
    
    def _validate_boolean_expression(self, line_num: int, line: str, expression: str):
        """
        Validiert Boolean Expressions (and, or).
        
        Correct: {{- if and $enabled $isProd }}
        Wrong:   {{- if and "$enabled" $isProd }}
        """
        # Finde alle gequoteten Variablen
        quoted_vars = re.findall(r'"(\$[a-zA-Z_][a-zA-Z0-9_]*)"', expression)
        
        for var in quoted_vars:
            self.errors.append(ValidationError(
                line_num=line_num,
                line_content=line.strip(),
                error_type=ErrorType.VARIABLE_IN_CONDITION_QUOTED,
                message=f"Variable in Bedingung darf nicht gequoted sein",
                expected=var,
                actual=f'"{var}"',
                severity=Severity.ERROR
            ))
    
    def _validate_range_expression(self, line_num: int, line: str, expression: str):
        """
        Validiert Range Expression.
        
        Correct: {{- range .Values.roles }}
        Wrong:   {{- range ".Values.roles" }}
        """
        expression = expression.strip()
        
        # Prüfe ob Expression fälschlicherweise gequoted ist
        if self._is_quoted(expression):
            inner = expression[1:-1]
            if re.match(r'^\.', inner) or inner.startswith('$'):
                self.errors.append(ValidationError(
                    line_num=line_num,
                    line_content=line.strip(),
                    error_type=ErrorType.RANGE_EXPRESSION_QUOTED,
                    message=f"Range-Expression darf nicht gequoted sein",
                    expected=f"{{{{- range {inner} }}}}",
                    actual=f"{{{{- range {expression} }}}}",
                    severity=Severity.ERROR
                ))
    
    def _validate_with_expression(self, line_num: int, line: str, expression: str):
        """
        Validiert With Expression.
        
        Correct: {{- with .Values.ingress }}
        Wrong:   {{- with ".Values.ingress" }}
        """
        expression = expression.strip()
        
        # Prüfe ob Expression fälschlicherweise gequoted ist
        if self._is_quoted(expression):
            inner = expression[1:-1]
            if re.match(r'^\.', inner) or inner.startswith('$'):
                self.errors.append(ValidationError(
                    line_num=line_num,
                    line_content=line.strip(),
                    error_type=ErrorType.WITH_EXPRESSION_QUOTED,
                    message=f"With-Expression darf nicht gequoted sein",
                    expected=f"{{{{- with {inner} }}}}",
                    actual=f"{{{{- with {expression} }}}}",
                    severity=Severity.ERROR
                ))
    
    # =========================================================================
    # OUTPUT EXPRESSION VALIDATION
    # =========================================================================
    
    def _validate_output_expressions(self, line_num: int, line: str):
        """Validiert Output-Expressions in einer Zeile."""
        
        # Finde alle Template-Expressions
        # Pattern: optionale Quotes, {{ content }}, optionale Quotes
        pattern = r'("?)(\{\{-?\s*(.*?)\s*-?\}\})("?)'
        
        for match in re.finditer(pattern, line):
            leading_quote = match.group(1)
            full_expr = match.group(2)
            inner_content = match.group(3).strip()
            trailing_quote = match.group(4)
            
            has_outer_quotes = bool(leading_quote and trailing_quote)
            
            # Skip Control-Flow Expressions
            if self._is_control_expression(inner_content):
                continue
            
            # Validiere die Expression
            self._validate_single_output(
                line_num, line, inner_content, has_outer_quotes, full_expr
            )
    
    def _is_control_expression(self, content: str) -> bool:
        """Prüft ob Content eine Control-Expression ist."""
        control_keywords = ['if', 'else', 'end', 'range', 'with', 'define', 'template', 'include', 'block']
        first_word = content.split()[0] if content.split() else ''
        return first_word in control_keywords or content.startswith('$') and ':=' in content
    
    def _validate_single_output(self, line_num: int, line: str, content: str,
                                 has_outer_quotes: bool, full_expr: str):
        """Validiert eine einzelne Output-Expression."""
        
        # Parse die Expression
        var_path, pipe_functions, has_pipe = self._parse_expression(content)
        
        if not var_path:
            return
        
        # 1. Prüfe Pipe Functions
        if has_pipe:
            self._validate_pipe_functions(line_num, line, content, pipe_functions, has_outer_quotes)
        
        # 2. Bestimme erwarteten Output-Typ
        expected_type = self._determine_output_type(var_path, pipe_functions)
        
        # 3. Validiere Quoting basierend auf Typ
        self._validate_output_quoting(
            line_num, line, content, var_path, expected_type, has_outer_quotes, full_expr
        )
    
    def _parse_expression(self, content: str) -> Tuple[Optional[str], List[str], bool]:
        """
        Parsed eine Template-Expression.
        
        Returns:
            Tuple[var_path, pipe_functions, has_pipe]
        """
        content = content.strip()
        
        # Prüfe auf Pipe
        if '|' in content:
            parts = content.split('|')
            var_part = parts[0].strip()
            pipe_functions = [p.strip() for p in parts[1:]]
            
            # Extrahiere Variable
            var_match = re.match(r'^(\.[A-Za-z][A-Za-z0-9._]*|\$[a-zA-Z_][a-zA-Z0-9_]*)', var_part)
            var_path = var_match.group(1) if var_match else None
            
            return var_path, pipe_functions, True
        else:
            # Keine Pipe
            var_match = re.match(r'^(\.[A-Za-z][A-Za-z0-9._]*|\$[a-zA-Z_][a-zA-Z0-9_]*)', content)
            var_path = var_match.group(1) if var_match else None
            
            return var_path, [], False
    
    def _validate_pipe_functions(self, line_num: int, line: str, content: str,
                                  pipe_functions: List[str], has_outer_quotes: bool):
        """Validiert Pipe Functions und ihre Parameter."""
        
        for pipe_func in pipe_functions:
            func_name = pipe_func.split()[0] if pipe_func.split() else pipe_func
            
            # 1. Prüfe default Function
            if func_name == 'default':
                self._validate_default_function(line_num, line, pipe_func, content)
            
            # 2. Prüfe ternary Function
            elif func_name == 'ternary':
                self._validate_ternary_function(line_num, line, pipe_func, content)
            
            # 3. Prüfe Functions mit Literal-Parametern (replace, trimPrefix, etc.)
            elif func_name in FUNCTIONS_WITH_LITERAL_PARAMS:
                self._validate_function_params(line_num, line, func_name, pipe_func, content)
    
    def _validate_default_function(self, line_num: int, line: str, pipe_func: str, full_content: str):
        """
        Validiert default Function.
        
        Correct: default "latest"  (String)
        Correct: default 3         (Integer)
        Wrong:   default latest    (unquoted String)
        Wrong:   default "3"       (quoted Integer)
        """
        # Parse: default <value>
        match = re.match(r'default\s+(.+)', pipe_func)
        if not match:
            return
        
        default_value = match.group(1).strip()
        
        # Prüfe ob es ein Integer ist
        if self._is_number(default_value):
            # Integer - sollte NICHT gequoted sein
            if self._is_quoted(default_value):
                inner = default_value[1:-1]
                if inner.isdigit() or (inner.startswith('-') and inner[1:].isdigit()):
                    self.errors.append(ValidationError(
                        line_num=line_num,
                        line_content=line.strip(),
                        error_type=ErrorType.DEFAULT_INT_QUOTED,
                        message=f"Default Integer-Wert darf nicht gequoted sein",
                        expected=f"default {inner}",
                        actual=f"default {default_value}",
                        severity=Severity.ERROR
                    ))
        
        # Prüfe ob es ein Boolean ist
        elif default_value.lower() in ('true', 'false'):
            # Boolean - sollte NICHT gequoted sein
            pass
        
        # Sonst ist es ein String - sollte gequoted sein
        elif not self._is_quoted(default_value) and not self._is_variable(default_value):
            self.errors.append(ValidationError(
                line_num=line_num,
                line_content=line.strip(),
                error_type=ErrorType.DEFAULT_STRING_NOT_QUOTED,
                message=f"Default String-Wert muss gequoted sein",
                expected=f'default "{default_value}"',
                actual=f'default {default_value}',
                severity=Severity.ERROR
            ))
    
    def _validate_ternary_function(self, line_num: int, line: str, pipe_func: str, full_content: str):
        """
        Validiert ternary Function.
        
        Correct: ternary "yes" "no"
        Wrong:   ternary yes no
        """
        # Parse: ternary <true_val> <false_val>
        match = re.match(r'ternary\s+(\S+)\s+(\S+)', pipe_func)
        if not match:
            return
        
        true_val = match.group(1)
        false_val = match.group(2)
        
        for val, pos in [(true_val, 'true'), (false_val, 'false')]:
            # Wenn es kein Integer/Boolean ist, muss es gequoted sein
            if not self._is_number(val) and val.lower() not in ('true', 'false'):
                if not self._is_quoted(val) and not self._is_variable(val):
                    self.errors.append(ValidationError(
                        line_num=line_num,
                        line_content=line.strip(),
                        error_type=ErrorType.TERNARY_LITERAL_NOT_QUOTED,
                        message=f"Ternary {pos}-Wert muss gequoted sein (String-Literal)",
                        expected=f'"{val}"',
                        actual=val,
                        severity=Severity.ERROR
                    ))
    
    def _validate_function_params(self, line_num: int, line: str, func_name: str,
                                   pipe_func: str, full_content: str):
        """
        Validiert Function Parameter (replace, trimPrefix, etc.).
        
        Correct: replace "-" "_"
        Wrong:   replace - _
        """
        # Parse Function mit Parametern
        # Pattern: func_name param1 param2 ...
        parts = pipe_func.split()
        if len(parts) < 2:
            return
        
        params = parts[1:]
        
        for param in params:
            # Skip Variablen und Zahlen
            if self._is_variable(param) or self._is_number(param):
                continue
            
            # String-Literale müssen gequoted sein
            if not self._is_quoted(param):
                # Prüfe ob es ein einzelnes Sonderzeichen ist (z.B. - _ /)
                if len(param) <= 2 and not param.isalnum():
                    self.errors.append(ValidationError(
                        line_num=line_num,
                        line_content=line.strip(),
                        error_type=ErrorType.FUNCTION_PARAM_NOT_QUOTED,
                        message=f"Function '{func_name}' Parameter muss gequoted sein",
                        expected=f'"{param}"',
                        actual=param,
                        severity=Severity.ERROR
                    ))
    
    def _determine_output_type(self, var_path: str, pipe_functions: List[str]) -> str:
        """
        Bestimmt den erwarteten Output-Typ basierend auf Variable und Pipes.
        
        Returns:
            'string', 'int', 'float', 'bool'
        """
        # 1. Prüfe Type-Conversion Pipes
        for pipe_func in pipe_functions:
            func_name = pipe_func.split()[0] if pipe_func.split() else pipe_func
            
            if func_name in ('int', 'int64'):
                return 'int'
            if func_name == 'float64':
                return 'float'
            if func_name == 'bool':
                return 'bool'
            if func_name == 'quote' or func_name == 'squote':
                return 'string'
            if func_name in STRING_PIPE_FUNCTIONS and func_name not in ('default',):
                return 'string'
        
        # 2. Prüfe default Function für Typ-Hinweis
        for pipe_func in pipe_functions:
            if pipe_func.startswith('default'):
                match = re.match(r'default\s+(.+)', pipe_func)
                if match:
                    default_val = match.group(1).strip()
                    if self._is_number(default_val):
                        return 'int'
                    if default_val.lower() in ('true', 'false'):
                        return 'bool'
        
        # 3. Prüfe Variable-Typ aus type_map
        if var_path and var_path.startswith('.Values.'):
            lookup_path = var_path[8:]  # Entferne '.Values.'
            return self.type_map.get(lookup_path, 'string')
        
        # 4. Built-in Variablen
        if var_path:
            if var_path.startswith('.Release.') or var_path.startswith('.Chart.'):
                return 'string'
            if var_path.startswith('.Capabilities.'):
                return 'string'
        
        # 5. Default: String
        return 'string'
    
    def _validate_output_quoting(self, line_num: int, line: str, content: str,
                                  var_path: str, expected_type: str,
                                  has_outer_quotes: bool, full_expr: str):
        """Validiert ob Output korrekt gequoted ist."""
        
        # Prüfe auf quote/squote Function
        has_quote_func = '| quote' in content or '| squote' in content
        
        if expected_type == 'string':
            # Strings sollten gequoted sein (außer quote Function wird verwendet)
            if not has_outer_quotes and not has_quote_func:
                self.errors.append(ValidationError(
                    line_num=line_num,
                    line_content=line.strip(),
                    error_type=ErrorType.OUTPUT_STRING_NOT_QUOTED,
                    message=f"String-Output muss gequoted sein",
                    expected=f'"{full_expr}"',
                    actual=full_expr,
                    severity=Severity.WARNING
                ))
        
        elif expected_type == 'int' or expected_type == 'float':
            # Integer/Float sollten NICHT gequoted sein
            if has_outer_quotes:
                self.errors.append(ValidationError(
                    line_num=line_num,
                    line_content=line.strip(),
                    error_type=ErrorType.OUTPUT_INT_QUOTED,
                    message=f"Integer-Output darf nicht gequoted sein",
                    expected=full_expr,
                    actual=f'"{full_expr}"',
                    severity=Severity.ERROR
                ))
            
            # Prüfe auf quote Function bei Integer
            if has_quote_func:
                self.errors.append(ValidationError(
                    line_num=line_num,
                    line_content=line.strip(),
                    error_type=ErrorType.QUOTE_FUNCTION_ON_INT,
                    message=f"quote/squote sollte nicht auf Integer verwendet werden",
                    expected=content.replace('| quote', '').replace('| squote', '').strip(),
                    actual=content,
                    severity=Severity.ERROR
                ))
        
        elif expected_type == 'bool':
            # Boolean sollten NICHT gequoted sein
            if has_outer_quotes:
                self.errors.append(ValidationError(
                    line_num=line_num,
                    line_content=line.strip(),
                    error_type=ErrorType.OUTPUT_BOOL_QUOTED,
                    message=f"Boolean-Output darf nicht gequoted sein",
                    expected=full_expr,
                    actual=f'"{full_expr}"',
                    severity=Severity.ERROR
                ))
            
            # Prüfe auf quote Function bei Boolean
            if has_quote_func:
                self.errors.append(ValidationError(
                    line_num=line_num,
                    line_content=line.strip(),
                    error_type=ErrorType.QUOTE_FUNCTION_ON_BOOL,
                    message=f"quote/squote sollte nicht auf Boolean verwendet werden",
                    expected=content.replace('| quote', '').replace('| squote', '').strip(),
                    actual=content,
                    severity=Severity.ERROR
                ))

    # =========================================================================
    # HELPER METHODS
    # =========================================================================
    
    def _is_quoted(self, value: str) -> bool:
        """Prüft ob ein Wert gequoted ist."""
        value = value.strip()
        return (value.startswith('"') and value.endswith('"')) or \
               (value.startswith("'") and value.endswith("'"))
    
    def _is_variable(self, value: str) -> bool:
        """Prüft ob ein Wert eine Variable ist."""
        value = value.strip()
        return value.startswith('.') or value.startswith('$')
    
    def _is_number(self, value: str) -> bool:
        """Prüft ob ein Wert eine Zahl ist."""
        value = value.strip().strip('"\'')
        try:
            float(value)
            return True
        except ValueError:
            return False
    
    def _is_boolean(self, value: str) -> bool:
        """Prüft ob ein Wert ein Boolean ist."""
        return value.strip().lower() in ('true', 'false')
    
    def _parse_comparison_args(self, args: str) -> List[str]:
        """Parsed Comparison Arguments."""
        result = []
        current = ""
        in_quotes = False
        quote_char = None
        
        for char in args:
            if char in ('"', "'") and not in_quotes:
                in_quotes = True
                quote_char = char
                current += char
            elif char == quote_char and in_quotes:
                in_quotes = False
                quote_char = None
                current += char
            elif char == ' ' and not in_quotes:
                if current.strip():
                    result.append(current.strip())
                current = ""
            else:
                current += char
        
        if current.strip():
            result.append(current.strip())
        
        return result


# =============================================================================
# FILE UTILITIES
# =============================================================================

def find_helm_structure(start_path):
    """Findet die Helm-Chart-Struktur."""
    current_path = Path(start_path)
    search_paths = [current_path]
    
    parent = current_path.parent
    for _ in range(4):
        search_paths.append(parent)
        parent = parent.parent
    
    for search_path in search_paths:
        chart_dir = search_path / 'chart'
        values_dir = search_path / 'values'
        
        if chart_dir.exists() and chart_dir.is_dir():
            chart_file = chart_dir / 'Chart.yaml'
            if chart_file.exists():
                return True, chart_file, values_dir if values_dir.exists() else None
        
        chart_file = search_path / 'Chart.yaml'
        if chart_file.exists():
            values_file = search_path / 'values.yaml'
            return True, chart_file, values_file if values_file.exists() else None
    
    return False, None, None


def is_helm_template_file(file_path):
    """Prüft ob eine Datei Helm-Template-Syntax enthält."""
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            content = f.read()
        
        helm_patterns = [
            r'\{\{\s*\.Values\.',
            r'\{\{\s*\.Release\.',
            r'\{\{\s*\.Chart\.',
            r'\{\{\s*\.Capabilities\.',
            r'\{\{\s*\.Template\.',
            r'\{\{-?\s*if\s',
            r'\{\{-?\s*range\s',
            r'\{\{-?\s*with\s',
        ]
        
        for pattern in helm_patterns:
            if re.search(pattern, content):
                return True
        
        return False
    except:
        return False


def load_values_from_directory(values_dir):
    """Lädt alle YAML-Dateien aus dem values/ Ordner."""
    yaml = YAML()
    yaml.preserve_quotes = True
    combined_type_map = {}
    
    try:
        values_files = list(values_dir.glob('*.yaml')) + list(values_dir.glob('*.yml'))
        
        for values_file in sorted(values_files):
            try:
                with open(values_file, 'r', encoding='utf-8') as f:
                    values_data = yaml.load(f)
                
                if not values_data:
                    continue
                
                def extract_types(data, prefix=''):
                    if isinstance(data, dict):
                        for key, value in data.items():
                            current_path = f"{prefix}.{key}" if prefix else key
                            if isinstance(value, dict):
                                extract_types(value, current_path)
                            elif isinstance(value, list):
                                combined_type_map[current_path] = 'list'
                            elif isinstance(value, bool):
                                combined_type_map[current_path] = 'bool'
                            elif isinstance(value, int):
                                combined_type_map[current_path] = 'int'
                            elif isinstance(value, float):
                                combined_type_map[current_path] = 'float'
                            else:
                                combined_type_map[current_path] = 'string'
                
                extract_types(values_data)
                
            except Exception:
                continue
        
        return combined_type_map
        
    except Exception:
        return {}


def load_values_file(values_file):
    """Lädt eine einzelne values.yaml Datei."""
    yaml = YAML()
    yaml.preserve_quotes = True
    
    try:
        with open(values_file, 'r', encoding='utf-8') as f:
            values_data = yaml.load(f)
        
        type_map = {}
        
        def extract_types(data, prefix=''):
            if isinstance(data, dict):
                for key, value in data.items():
                    current_path = f"{prefix}.{key}" if prefix else key
                    if isinstance(value, dict):
                        extract_types(value, current_path)
                    elif isinstance(value, list):
                        type_map[current_path] = 'list'
                    elif isinstance(value, bool):
                        type_map[current_path] = 'bool'
                    elif isinstance(value, int):
                        type_map[current_path] = 'int'
                    elif isinstance(value, float):
                        type_map[current_path] = 'float'
                    else:
                        type_map[current_path] = 'string'
        
        extract_types(values_data)
        return type_map
        
    except Exception:
        return {}


def remove_helm_template_syntax_for_linting(content):
    """Entfernt Helm-Template-Syntax für yamllint."""
    lines = content.split('\n')
    cleaned_lines = []
    
    control_pattern = re.compile(r'^\s*\{\{-?\s*(if|else|end|range|with|define|template|include|block|\$[a-zA-Z_][a-zA-Z0-9_]*\s*:=)')
    
    for line_num, line in enumerate(lines, 1):
        if control_pattern.search(line):
            cleaned_lines.append(f"# HELM_CONTROL_LINE_{line_num}")
            continue
        
        # Ersetze Template-Expressions mit Platzhaltern
        def replace_template(match):
            leading = match.group(1)
            trailing = match.group(4)
            if leading and trailing:
                return '"__HELM_PLACEHOLDER__"'
            return '__HELM_PLACEHOLDER__'
        
        cleaned_line = re.sub(r'("?)(\{\{-?\s*.*?\s*-?\}\})("?)', replace_template, line)
        cleaned_lines.append(cleaned_line)
    
    return '\n'.join(cleaned_lines)


def run_yamllint(content, config_file=None):
    """Führt yamllint auf dem bereinigten Content aus."""
    if not YAMLLINT_AVAILABLE:
        return True, "yamllint nicht verfügbar"
    
    try:
        if config_file:
            config_path = Path(config_file).resolve()
            if config_path.exists():
                conf = YamlLintConfig(file=str(config_path))
            else:
                conf = YamlLintConfig('extends: default')
        else:
            conf = YamlLintConfig('extends: default')
        
        gen = linter.run(content, conf)
        problems = list(gen)
        
        errors = [p for p in problems if p.level == 'error']
        
        if not errors:
            return True, None
        
        error_output = []
        for problem in errors:
            error_output.append(
                f"  {problem.line}:{problem.column}: {problem.level} {problem.message} ({problem.rule})"
            )
        
        return False, '\n'.join(error_output)
        
    except Exception as e:
        return False, f"yamllint Fehler: {str(e)}"


# =============================================================================
# MAIN VALIDATION FUNCTION
# =============================================================================

def validate_helm_template(input_file, values_source=None, yamllint_config=None,
                           force=False, verbose=False, strict=False):
    """
    Validiert ein Helm-Template.
    
    Args:
        input_file: Pfad zur Eingabedatei
        values_source: Pfad zum values/ Ordner oder values.yaml
        yamllint_config: Pfad zur yamllint Konfiguration
        force: Verarbeitung erzwingen
        verbose: Ausführliche Ausgabe
        strict: Warnungen als Fehler behandeln
    
    Returns:
        int: Exit-Code (0 = OK, 1 = Fehler)
    """
    input_path = Path(input_file)
    
    if not input_path.exists():
        print(f"[ERROR] Datei '{input_file}' nicht gefunden.")
        return 1
    
    is_helm, chart_file, auto_values_source = find_helm_structure(input_path.parent)
    
    if not is_helm and not force:
        if is_helm_template_file(input_file):
            if verbose:
                print(f"[WARNING] Datei enthält Helm-Syntax aber keine Chart-Struktur.")
                print(f"  Verwende --force um trotzdem zu validieren.")
            return 1
        else:
            if verbose:
                print(f"[SKIP] Keine Helm-Template-Datei: {input_file}")
            return 0
    
    if verbose:
        print(f"\n{'='*60}")
        print(f"Validiere: {input_file}")
        print(f"{'='*60}")
    
    with open(input_file, 'r', encoding='utf-8') as f:
        content = f.read()
    
    if not is_helm_template_file(input_file):
        if verbose:
            print(f"[SKIP] Keine Helm-Template-Syntax gefunden.")
        return 0
    
    # Values laden
    type_map = {}
    if values_source:
        values_path = Path(values_source)
        if values_path.is_dir():
            type_map = load_values_from_directory(values_path)
        elif values_path.is_file():
            type_map = load_values_file(values_path)
    elif auto_values_source:
        if auto_values_source.is_dir():
            type_map = load_values_from_directory(auto_values_source)
        elif auto_values_source.is_file():
            type_map = load_values_file(auto_values_source)
    
    if verbose and type_map:
        print(f"[OK] {len(type_map)} Variablen aus Values geladen")
    
    # Phase 1: YAML Linting
    if verbose:
        print(f"\n--- Phase 1: YAML Linting ---")
    
    cleaned_content = remove_helm_template_syntax_for_linting(content)
    lint_success, lint_errors = run_yamllint(cleaned_content, yamllint_config)
    
    if not lint_success:
        print(f"\n[ERROR] yamllint Fehler in {input_file}:")
        print(lint_errors)
        return 1
    
    if verbose:
        print(f"[OK] yamllint: OK")
    
    # Phase 2: Helm Template Validierung
    if verbose:
        print(f"\n--- Phase 2: Helm Template Validierung ---")
    
    validator = HelmValidator(type_map=type_map, strict=strict)
    is_valid, errors = validator.validate_file(input_file)
    
    if errors:
        error_count = sum(1 for e in errors if e.severity == Severity.ERROR)
        warning_count = sum(1 for e in errors if e.severity == Severity.WARNING)
        
        print(f"\n[{'ERROR' if error_count else 'WARNING'}] {input_file}:")
        print(f"  {error_count} Fehler, {warning_count} Warnungen\n")
        
        for error in errors:
            print(error)
            print()
        
        if not is_valid:
            return 1
    
    if verbose:
        print(f"[OK] Helm Template Validierung: OK")
        print(f"\n[OK] {input_file}: Alle Prüfungen bestanden")
    
    return 0


# =============================================================================
# CLI
# =============================================================================

def main():
    """Hauptfunktion mit Argument-Parsing."""
    if len(sys.argv) < 2:
        print("Verwendung: python helm_validator.py <file> [optionen]")
        print("\nOptionen:")
        print("  --values <path>    Pfad zum values/ Ordner oder values.yaml")
        print("  --config <path>    Pfad zur yamllint Konfiguration")
        print("  --force            Verarbeitung erzwingen")
        print("  --strict           Warnungen als Fehler behandeln")
        print("  --verbose, -v      Ausführliche Ausgabe")
        print("\nBeispiele:")t
        print("  python helm_validator.py chart/templates/deployment.yaml")
        print("  python helm_validator.py deployment.yaml --config .yamllint.yaml -v")
        print("  python helm_validator.py deployment.yaml --values ../values/ --strict")
        sys.exit(1)
    
    args = sys.argv[1:]
    
    force = '--force' in args
    verbose = '--verbose' in args or '-v' in args
    strict = '--strict' in args
    
    args = [a for a in args if a not in ['--force', '--verbose', '-v', '--strict']]
    
    values_source = None
    yamllint_config = None
    input_file = None
    
    i = 0
    while i < len(args):
        if args[i] == '--values' and i + 1 < len(args):
            values_source = args[i + 1]
            i += 2
        elif args[i] == '--config' and i + 1 < len(args):
            yamllint_config = args[i + 1]
            i += 2
        elif not args[i].startswith('--'):
            input_file = args[i]
            i += 1
        else:
            i += 1
    
    if not input_file:
        print("[ERROR] Keine Eingabedatei angegeben.")
        sys.exit(1)
    
    exit_code = validate_helm_template(
        input_file,
        values_source=values_source,
        yamllint_config=yamllint_config,
        force=force,
        verbose=verbose,
        strict=strict
    )
    sys.exit(exit_code)


if __name__ == "__main__":
    main()