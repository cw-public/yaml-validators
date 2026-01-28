#!/usr/bin/env python3
"""
Helm Template Validator - Validates quoting rules in Helm templates.

IMPORTANT: This validator does NOT contain file type detection logic.
File type detection is handled by yaml_router.py (FileTypeDetector).
This validator ASSUMES the file is already identified as a Helm template.
"""

import re
import sys
import os
from pathlib import Path
from typing import Dict, Optional


# ============================================================================
# RELATIVE IMPORTS FOR PRE-COMMIT COMPATIBILITY
# ============================================================================

def _import_shared_constants():
    """Import shared_constants with fallback for different installation methods."""
    try:
        from shared_constants import (
            Severity, ErrorType, ValidationError,
            HELM_CONTROL_FLOW_PATTERNS, K8S_INTEGER_FIELDS, K8S_BOOLEAN_FIELDS, K8S_STRING_FIELDS,
            HELM_STRING_PIPE_FUNCTIONS, HELM_NUMERIC_PIPE_FUNCTIONS, HELM_BOOLEAN_PIPE_FUNCTIONS,
            is_quoted,
        )
        return (Severity, ErrorType, ValidationError,
                HELM_CONTROL_FLOW_PATTERNS, K8S_INTEGER_FIELDS, K8S_BOOLEAN_FIELDS, K8S_STRING_FIELDS,
                HELM_STRING_PIPE_FUNCTIONS, HELM_NUMERIC_PIPE_FUNCTIONS, HELM_BOOLEAN_PIPE_FUNCTIONS,
                is_quoted)
    except ImportError:
        pass
    
    # Fallback: Load from same directory
    import importlib.util
    spec = importlib.util.spec_from_file_location(
        "shared_constants",
        Path(__file__).parent / "shared_constants.py"
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return (module.Severity, module.ErrorType, module.ValidationError,
            module.HELM_CONTROL_FLOW_PATTERNS, module.K8S_INTEGER_FIELDS, module.K8S_BOOLEAN_FIELDS, module.K8S_STRING_FIELDS,
            module.HELM_STRING_PIPE_FUNCTIONS, module.HELM_NUMERIC_PIPE_FUNCTIONS, module.HELM_BOOLEAN_PIPE_FUNCTIONS,
            module.is_quoted)

(Severity, ErrorType, ValidationError,
 HELM_CONTROL_FLOW_PATTERNS, K8S_INTEGER_FIELDS, K8S_BOOLEAN_FIELDS, K8S_STRING_FIELDS,
 HELM_STRING_PIPE_FUNCTIONS, HELM_NUMERIC_PIPE_FUNCTIONS, HELM_BOOLEAN_PIPE_FUNCTIONS,
 is_quoted) = _import_shared_constants()

# Force UTF-8 encoding on Windows
if sys.platform == 'win32':
    os.environ['PYTHONIOENCODING'] = 'utf-8'


# ============================================================================
# HELM VALIDATOR CLASS
# ============================================================================

class HelmValidator:
    """Validates Helm template quoting rules."""
    
    def __init__(self, type_map: Dict[str, str] = None, strict: bool = False):
        self.type_map = type_map or {}
        self.strict = strict
        self.errors = []
    
    def validate_content(self, content: str, filepath: str = "<string>"):
        """Validate Helm template content.
        
        Args:
            content: The Helm template content to validate
            filepath: Optional filepath for error messages
            
        Returns:
            Tuple of (is_valid: bool, errors: list of ValidationError)
        """
        self.errors = []
        lines = content.split('\n')
        
        for line_num, line in enumerate(lines, 1):
            self._validate_line(line_num, line)
        
        is_valid = not any(e.severity == Severity.ERROR for e in self.errors)
        if self.strict:
            is_valid = len(self.errors) == 0
        
        return is_valid, self.errors
    
    def validate_file(self, filepath: str):
        """Validate a Helm template file.
        
        Args:
            filepath: Path to the Helm template file
            
        Returns:
            Tuple of (is_valid: bool, errors: list of ValidationError)
        """
        try:
            content = Path(filepath).read_text(encoding='utf-8')
            return self.validate_content(content, filepath)
        except Exception as e:
            return False, [ValidationError(
                line_num=0,
                message=f"Cannot read file: {e}",
                actual="",
                expected="",
                severity=Severity.ERROR
            )]
    
    def _validate_line(self, line_num: int, line: str):
        """Validate a single line."""
        stripped = line.strip()
        
        if not stripped or stripped.startswith('#'):
            return
        
        if self._is_control_flow_line(stripped):
            self._validate_control_flow(line_num, stripped)
            return
        
        if '{{' in line:
            self._validate_output_expressions(line_num, line)
    
    def _is_control_flow_line(self, line: str) -> bool:
        """Check if line is a pure control-flow statement."""
        for pattern in HELM_CONTROL_FLOW_PATTERNS:
            if re.match(pattern, line):
                return True
        return False
    
    def _validate_control_flow(self, line_num: int, line: str):
        """Validate control-flow statements."""
        
        if re.search(r'\{\{-?\s*if\s+"', line):
            self.errors.append(ValidationError(
                line_num=line_num,
                message="Control-flow expression should not be quoted",
                actual=line,
                expected=re.sub(r'if\s+"([^"]+)"', r'if \1', line),
                severity=Severity.ERROR,
                error_type=ErrorType.IF_EXPRESSION_QUOTED
            ))
        
        if re.search(r'\{\{-?\s*range\s+"', line):
            self.errors.append(ValidationError(
                line_num=line_num,
                message="Range expression should not be quoted",
                actual=line,
                expected=re.sub(r'range\s+"([^"]+)"', r'range \1', line),
                severity=Severity.ERROR,
                error_type=ErrorType.RANGE_EXPRESSION_QUOTED
            ))
        
        comparison_match = re.search(
            r'\b(eq|ne)\s+(\.[a-zA-Z_.]+)\s+([a-zA-Z][a-zA-Z0-9_-]*)\s*[}\)]',
            line
        )
        if comparison_match:
            func, var, literal = comparison_match.groups()
            if not literal.isdigit() and literal not in ('true', 'false', 'nil'):
                self.errors.append(ValidationError(
                    line_num=line_num,
                    message=f"String literal '{literal}' in comparison must be quoted",
                    actual=line,
                    expected=line.replace(f'{func} {var} {literal}', f'{func} {var} "{literal}"'),
                    severity=Severity.ERROR,
                    error_type=ErrorType.STRING_LITERAL_NOT_QUOTED
                ))
    
    def _validate_output_expressions(self, line_num: int, line: str):
        """Validate output expressions (key: value lines with {{ }})."""
        
        match = re.match(r'^(\s*)([a-zA-Z_][a-zA-Z0-9_-]*)\s*:\s*(.+)$', line)
        if not match:
            return
        
        indent, key, value = match.groups()
        value = value.strip()
        
        if '{{' not in value:
            return
        
        expected_type = self._get_expected_type(key, value)
        quoted = is_quoted(value)
        
        if expected_type == 'string':
            if not quoted:
                self.errors.append(ValidationError(
                    line_num=line_num,
                    message=f"String value for '{key}' should be quoted",
                    actual=line,
                    expected=f'{indent}{key}: "{value}"',
                    severity=Severity.WARNING,
                    error_type=ErrorType.STRING_OUTPUT_NOT_QUOTED
                ))
        
        elif expected_type == 'int':
            if quoted:
                unquoted = value[1:-1] if quoted else value
                self.errors.append(ValidationError(
                    line_num=line_num,
                    message=f"Integer value for '{key}' should not be quoted",
                    actual=line,
                    expected=f'{indent}{key}: {unquoted}',
                    severity=Severity.WARNING,
                    error_type=ErrorType.NUMERIC_OUTPUT_QUOTED
                ))
        
        elif expected_type == 'bool':
            if quoted:
                unquoted = value[1:-1] if quoted else value
                self.errors.append(ValidationError(
                    line_num=line_num,
                    message=f"Boolean value for '{key}' should not be quoted",
                    actual=line,
                    expected=f'{indent}{key}: {unquoted}',
                    severity=Severity.WARNING,
                    error_type=ErrorType.BOOLEAN_OUTPUT_QUOTED
                ))
        
        self._validate_pipe_functions(line_num, line, value)
    
    def _get_expected_type(self, key: str, value: str) -> str:
        """Determine expected type for a key."""
        
        if key in self.type_map:
            return self.type_map[key]
        
        if key in K8S_INTEGER_FIELDS:
            return 'int'
        if key in K8S_BOOLEAN_FIELDS:
            return 'bool'
        if key in K8S_STRING_FIELDS:
            return 'string'
        
        for func in HELM_STRING_PIPE_FUNCTIONS:
            if f'| {func}' in value or f'|{func}' in value:
                return 'string'
        
        for func in HELM_NUMERIC_PIPE_FUNCTIONS:
            if f'| {func}' in value or f'|{func}' in value:
                return 'int'
        
        for func in HELM_BOOLEAN_PIPE_FUNCTIONS:
            if f'| {func}' in value or f'|{func}' in value:
                return 'bool'
        
        value_path = self._extract_value_path(value)
        if value_path:
            path_lower = value_path.lower()
            if any(x in path_lower for x in ['count', 'size', 'port', 'replica', 'num', 'max', 'min']):
                return 'int'
            if any(x in path_lower for x in ['enable', 'disable', 'flag', 'is', 'has', 'allow']):
                return 'bool'
        
        return 'string'
    
    def _extract_value_path(self, value: str) -> Optional[str]:
        """Extract .Values.xxx path from expression."""
        match = re.search(r'\.Values\.([a-zA-Z_.]+)', value)
        if match:
            return match.group(1)
        return None
    
    def _validate_pipe_functions(self, line_num: int, line: str, value: str):
        """Validate pipe function parameters."""
        
        default_match = re.search(r'\|\s*default\s+([^\s\|]+)', value)
        if default_match:
            default_val = default_match.group(1)
            
            if not default_val.startswith('"') and not default_val.startswith("'"):
                if not default_val.isdigit() and default_val not in ('true', 'false', 'nil', '.'):
                    if not default_val.startswith('.') and not default_val.startswith('$'):
                        self.errors.append(ValidationError(
                            line_num=line_num,
                            message=f"String default value '{default_val}' should be quoted",
                            actual=line,
                            expected=line.replace(f'default {default_val}', f'default "{default_val}"'),
                            severity=Severity.WARNING,
                            error_type=ErrorType.DEFAULT_STRING_NOT_QUOTED
                        ))
        
        ternary_match = re.search(r'\|\s*ternary\s+"([^"]*)"\s+([^\s\|"]+)', value)
        if ternary_match:
            false_val = ternary_match.group(2)
            if not false_val.startswith('"') and not false_val.isdigit():
                if false_val not in ('true', 'false', 'nil'):
                    self.errors.append(ValidationError(
                        line_num=line_num,
                        message=f"Ternary false value '{false_val}' should be quoted",
                        actual=line,
                        expected=line.replace(f'ternary "{ternary_match.group(1)}" {false_val}', 
                                             f'ternary "{ternary_match.group(1)}" "{false_val}"'),
                        severity=Severity.WARNING,
                        error_type=ErrorType.TERNARY_STRING_NOT_QUOTED
                    ))
        
        replace_match = re.search(r'\|\s*replace\s+([^\s]+)\s+([^\s\|]+)', value)
        if replace_match:
            old_val, new_val = replace_match.groups()
            
            if not old_val.startswith('"') and not old_val.startswith("'"):
                self.errors.append(ValidationError(
                    line_num=line_num,
                    message=f"Replace first parameter '{old_val}' should be quoted",
                    actual=line,
                    expected=line.replace(f'replace {old_val}', f'replace "{old_val}"'),
                    severity=Severity.WARNING,
                    error_type=ErrorType.REPLACE_PARAM_NOT_QUOTED
                ))


# ============================================================================
# MAIN (CLI)
# ============================================================================

def main():
    """Command-line interface."""
    import argparse
    
    parser = argparse.ArgumentParser(description='Helm Template Validator')
    parser.add_argument('file', help='Helm template file to validate')
    parser.add_argument('--strict', action='store_true', help='Treat warnings as errors')
    parser.add_argument('-v', '--verbose', action='store_true', help='Verbose output')
    
    args = parser.parse_args()
    
    validator = HelmValidator(type_map={}, strict=args.strict)
    is_valid, errors = validator.validate_file(args.file)
    
    if args.verbose or errors:
        print(f"\n> Helm Template Validator")
        print(f"{'-' * 80}")
    
    for error in errors:
        severity_tag = "[ERROR]" if error.severity == Severity.ERROR else "[WARNING]"
        print(f"{severity_tag} Line {error.line_num}: {error.message}")
        print(f"   CURRENT:  {error.actual}")
        print(f"   EXPECTED: {error.expected}")
        print()
    
    if not errors:
        if args.verbose:
            print("OK - No Helm template issues found\n")
    
    error_count = sum(1 for e in errors if e.severity == Severity.ERROR)
    warning_count = sum(1 for e in errors if e.severity == Severity.WARNING)
    
    if errors:
        print(f"{'-' * 80}")
        print(f"Summary: {error_count} error(s), {warning_count} warning(s)\n")
    
    if args.strict:
        sys.exit(1 if errors else 0)
    sys.exit(1 if error_count > 0 else 0)


if __name__ == '__main__':
    main()