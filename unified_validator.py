#!/usr/bin/env python3
"""
Unified Quote Validator - Combines K8s and Helm quoting rules.

This validator applies:
1. K8s Quote Rules - for ANY file with apiVersion + kind
2. Helm/Go-Template Rules - ADDITIONALLY when {{ }} syntax is present

ALL issues are ERRORS (no warnings).
"""

import re
import sys
from pathlib import Path
from typing import Dict, List, Optional


# ============================================================================
# IMPORTS
# ============================================================================

def _import_shared_constants():
    """Import shared_constants with fallback."""
    try:
        from shared_constants import (
            Severity, IssueType, QuoteIssue, ValidationResult,
            K8S_TOP_LEVEL_NO_QUOTE, K8S_METADATA_NO_QUOTE, K8S_INTEGER_FIELDS,
            K8S_BOOLEAN_FIELDS, K8S_STRING_FIELDS, K8S_PORT_STRING_FIELDS,
            K8S_STRING_FIELDS_REQUIRE_QUOTE, K8S_CONTEXT_KEYS,
            HELM_CONTROL_FLOW_PATTERNS, HELM_INT_BOOL_PATTERNS,
            HELM_STRING_PIPE_FUNCTIONS, HELM_NUMERIC_PIPE_FUNCTIONS, HELM_BOOLEAN_PIPE_FUNCTIONS,
            is_quoted, contains_helm_template, is_int_bool_helm_template, looks_like_integer,
        )
        return locals()
    except ImportError:
        import importlib.util
        spec = importlib.util.spec_from_file_location(
            "shared_constants",
            Path(__file__).parent / "shared_constants.py"
        )
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return {name: getattr(module, name) for name in dir(module) if not name.startswith('_')}

_constants = _import_shared_constants()
Severity = _constants['Severity']
IssueType = _constants['IssueType']
QuoteIssue = _constants['QuoteIssue']
ValidationResult = _constants['ValidationResult']
K8S_TOP_LEVEL_NO_QUOTE = _constants['K8S_TOP_LEVEL_NO_QUOTE']
K8S_METADATA_NO_QUOTE = _constants['K8S_METADATA_NO_QUOTE']
K8S_INTEGER_FIELDS = _constants['K8S_INTEGER_FIELDS']
K8S_BOOLEAN_FIELDS = _constants['K8S_BOOLEAN_FIELDS']
K8S_STRING_FIELDS = _constants['K8S_STRING_FIELDS']
K8S_PORT_STRING_FIELDS = _constants['K8S_PORT_STRING_FIELDS']
K8S_STRING_FIELDS_REQUIRE_QUOTE = _constants['K8S_STRING_FIELDS_REQUIRE_QUOTE']
K8S_CONTEXT_KEYS = _constants['K8S_CONTEXT_KEYS']
HELM_CONTROL_FLOW_PATTERNS = _constants['HELM_CONTROL_FLOW_PATTERNS']
HELM_INT_BOOL_PATTERNS = _constants['HELM_INT_BOOL_PATTERNS']
HELM_STRING_PIPE_FUNCTIONS = _constants['HELM_STRING_PIPE_FUNCTIONS']
HELM_NUMERIC_PIPE_FUNCTIONS = _constants['HELM_NUMERIC_PIPE_FUNCTIONS']
HELM_BOOLEAN_PIPE_FUNCTIONS = _constants['HELM_BOOLEAN_PIPE_FUNCTIONS']
is_quoted = _constants['is_quoted']
contains_helm_template = _constants['contains_helm_template']
is_int_bool_helm_template = _constants['is_int_bool_helm_template']
looks_like_integer = _constants['looks_like_integer']


# ============================================================================
# UNIFIED QUOTE VALIDATOR
# ============================================================================

class UnifiedQuoteValidator:
    """
    Unified validator that combines K8s and Helm quoting rules.
    
    Detection:
    - K8s rules apply when: apiVersion + kind present
    - Helm rules apply when: {{ }} syntax present
    - Both can apply simultaneously
    
    ALL issues are ERRORS.
    """
    
    def __init__(self, strict: bool = False, type_map: Dict[str, str] = None):
        self.strict = strict
        self.type_map = type_map or {}
        self.issues: List[QuoteIssue] = []
    
    def validate_file(self, file_path: str) -> ValidationResult:
        """Validate a file."""
        try:
            content = Path(file_path).read_text(encoding='utf-8')
            return self.validate_content(content, file_path)
        except Exception as e:
            return ValidationResult(
                file_path=file_path,
                is_valid=False,
                issues=[QuoteIssue(
                    line_number=0,
                    line_content="",
                    issue_type=IssueType.BOOLEAN_AS_STRING,
                    field_path="",
                    message=f"Cannot read file: {e}",
                    suggestion="",
                    severity=Severity.ERROR
                )],
                error_count=1
            )
    
    def validate_content(self, content: str, file_path: str = "<string>") -> ValidationResult:
        """Validate content."""
        self.issues = []
        lines = content.split('\n')
        
        # Detect characteristics
        has_helm_syntax = '{{' in content
        has_k8s_structure = self._has_k8s_structure(content)
        
        # Build context for parsing
        context_stack = []
        
        for line_num, line in enumerate(lines, 1):
            stripped = line.strip()
            
            if not stripped or stripped.startswith('#'):
                continue
            
            if stripped == '---':
                context_stack = []
                continue
            
            # Skip pure Helm control-flow lines but validate them
            if has_helm_syntax and self._is_helm_control_flow(stripped):
                self._validate_helm_control_flow(line_num, stripped)
                continue
            
            # Update context
            indent = len(line) - len(line.lstrip())
            context_stack = self._update_context(context_stack, indent, stripped)
            context = [ctx for _, ctx in context_stack]
            
            # Apply rules based on content type
            if has_k8s_structure:
                self._apply_k8s_rules(line_num, line, stripped, context)
            
            if has_helm_syntax and '{{' in line:
                self._apply_helm_rules(line_num, line, stripped, context)
        
        error_count = len(self.issues)
        is_valid = error_count == 0
        
        return ValidationResult(
            file_path=file_path,
            is_valid=is_valid,
            issues=self.issues,
            error_count=error_count
        )
    
    def _has_k8s_structure(self, content: str) -> bool:
        """Check if content has K8s structure (apiVersion + kind)."""
        has_api = bool(re.search(r'^apiVersion:\s*\S+', content, re.MULTILINE))
        has_kind = bool(re.search(r'^kind:\s*\S+', content, re.MULTILINE))
        return has_api and has_kind
    
    def _is_helm_control_flow(self, line: str) -> bool:
        """Check if line is pure Helm control-flow."""
        for pattern in HELM_CONTROL_FLOW_PATTERNS:
            if re.match(pattern, line):
                return True
        return False
    
    def _update_context(self, stack, indent: int, line: str):
        """Update YAML context stack."""
        stack = [(i, ctx) for i, ctx in stack if i < indent]
        if ':' in line:
            key = line.split(':')[0].strip().lstrip('- ')
            if key in K8S_CONTEXT_KEYS:
                stack.append((indent, key))
        return stack
    
    # ========================================================================
    # K8S RULES
    # ========================================================================
    
    def _apply_k8s_rules(self, line_num: int, line: str, stripped: str, context: List[str]):
        """Apply Kubernetes quoting rules."""
        
        # Handle list items
        if stripped.startswith('- '):
            self._check_k8s_list_item(line_num, line, stripped, context)
            return
        
        # Handle key: value pairs
        if ':' not in stripped:
            return
        
        parts = stripped.split(':', 1)
        if len(parts) != 2:
            return
        
        key = parts[0].strip()
        value = parts[1].strip()
        
        if not value:
            return
        
        in_annotations = 'annotations' in context
        
        # Rule: Boolean as string
        if not in_annotations:
            if value.lower() in ('"true"', '"false"', "'true'", "'false'"):
                self._add_issue(
                    line_num, line,
                    IssueType.BOOLEAN_AS_STRING,
                    '.'.join(context + [key]) if context else key,
                    "Boolean must not be quoted as string",
                    f'{key}: {value.strip("\"\'").lower()}'
                )
        
        # Rule: Annotation values must be strings
        if in_annotations:
            if looks_like_integer(value) and not is_quoted(value):
                self._add_issue(
                    line_num, line,
                    IssueType.ANNOTATION_INT_NOT_QUOTED,
                    f'annotations.{key}',
                    f"Annotation value '{value}' must be quoted as string",
                    f'{key}: "{value}"'
                )
            elif '=' in value and not is_quoted(value):
                self._add_issue(
                    line_num, line,
                    IssueType.ANNOTATION_SPECIAL_CHAR_NOT_QUOTED,
                    f'annotations.{key}',
                    "Annotation value with '=' should be quoted",
                    f'{key}: "{value}"'
                )
        
        # Rule: Integer fields must not be quoted
        if key in K8S_INTEGER_FIELDS and not in_annotations:
            if is_quoted(value):
                inner = value.strip('"\'')
                if inner.isdigit() or (inner.startswith('-') and inner[1:].isdigit()):
                    self._add_issue(
                        line_num, line,
                        IssueType.INTEGER_FIELD_QUOTED,
                        '.'.join(context + [key]) if context else key,
                        f"Integer field '{key}' must not be quoted",
                        f'{key}: {inner}'
                    )
        
        # Rule: goTemplateOptions must be quoted
        if key == 'goTemplateOptions':
            self._check_go_template_options(line_num, line, value)
        
        # Rule: Top-level fields usually not quoted
        if not context and key in K8S_TOP_LEVEL_NO_QUOTE:
            if is_quoted(value):
                self._add_issue(
                    line_num, line,
                    IssueType.TOP_LEVEL_QUOTED,
                    key,
                    f"Top-level field '{key}' is usually not quoted",
                    f'{key}: {value.strip("\"\'")}'
                )
        
        # Rule: Metadata name/namespace usually not quoted
        if 'metadata' in context and key in K8S_METADATA_NO_QUOTE:
            if is_quoted(value) and not contains_helm_template(value):
                self._add_issue(
                    line_num, line,
                    IssueType.METADATA_QUOTED,
                    f'metadata.{key}',
                    f"Metadata '{key}' is usually not quoted",
                    f'{key}: {value.strip("\"\'")}'
                )
        
        # Rule: URLs/paths should be quoted
        if 'spec' in context or 'template' in context:
            if not contains_helm_template(value):
                if key in K8S_STRING_FIELDS_REQUIRE_QUOTE:
                    if not is_quoted(value) and value:
                        self._add_issue(
                            line_num, line,
                            IssueType.PATH_NOT_QUOTED,
                            '.'.join(context + [key]) if context else key,
                            f"Field '{key}' should be quoted",
                            f'{key}: "{value}"'
                        )
                elif value.startswith('http://') or value.startswith('https://'):
                    if not is_quoted(value):
                        self._add_issue(
                            line_num, line,
                            IssueType.URL_NOT_QUOTED,
                            '.'.join(context + [key]) if context else key,
                            "URL should be quoted",
                            f'{key}: "{value}"'
                        )
        
        # Rule: Port string fields
        if 'ports' in context and key in K8S_PORT_STRING_FIELDS:
            if not is_quoted(value) and value:
                self._add_issue(
                    line_num, line,
                    IssueType.PORT_STRING_NOT_QUOTED,
                    f'ports[].{key}',
                    f"Port '{key}' should be quoted",
                    f'{key}: "{value}"'
                )
        
        # Rule: Helm templates in K8s context
        if contains_helm_template(value) and not in_annotations:
            quoted = is_quoted(value)
            is_int_bool = is_int_bool_helm_template(value)
            
            if key in K8S_INTEGER_FIELDS or key in K8S_BOOLEAN_FIELDS or is_int_bool:
                if quoted:
                    self._add_issue(
                        line_num, line,
                        IssueType.HELM_TEMPLATE_INT_QUOTED,
                        '.'.join(context + [key]) if context else key,
                        "Helm template for Integer/Boolean must not be quoted",
                        f'{key}: {value.strip("\"\'")}'
                    )
            else:
                if not quoted:
                    self._add_issue(
                        line_num, line,
                        IssueType.HELM_TEMPLATE_STRING_NOT_QUOTED,
                        '.'.join(context + [key]) if context else key,
                        "Helm template string must be quoted",
                        f'{key}: "{value}"'
                    )
    
    def _check_k8s_list_item(self, line_num: int, line: str, stripped: str, context: List[str]):
        """Check K8s list items."""
        value = stripped[2:].strip()
        
        # goTemplateOptions list items
        if 'goTemplateOptions' in context:
            if value and not is_quoted(value):
                self._add_issue(
                    line_num, line,
                    IssueType.GO_TEMPLATE_OPTIONS_NOT_QUOTED,
                    'goTemplateOptions[]',
                    "goTemplateOptions value must be quoted",
                    f'- "{value}"'
                )
        
        # Ports list items (integers)
        if 'ports' in context and ':' not in value:
            if is_quoted(value) and value.strip('"\'').isdigit():
                self._add_issue(
                    line_num, line,
                    IssueType.INTEGER_FIELD_QUOTED,
                    'ports[]',
                    "Integer in array must not be quoted",
                    f'- {value.strip("\"\'")}'
                )
        
        # valueFiles with Helm template
        if 'valueFiles' in context and contains_helm_template(value):
            if not is_quoted(value):
                self._add_issue(
                    line_num, line,
                    IssueType.HELM_TEMPLATE_STRING_NOT_QUOTED,
                    'valueFiles[]',
                    "Helm template string must be quoted",
                    f'- "{value}"'
                )
    
    def _check_go_template_options(self, line_num: int, line: str, value: str):
        """Check goTemplateOptions inline array."""
        if value.startswith('[') and value.endswith(']'):
            inner = value[1:-1]
            if not inner:
                return
            
            items = [item.strip() for item in inner.split(',') if item.strip()]
            unquoted_items = [item for item in items if not is_quoted(item)]
            
            if unquoted_items:
                quoted_items = ', '.join(f'"{item.strip("\"\'")}"' for item in items)
                self._add_issue(
                    line_num, line,
                    IssueType.GO_TEMPLATE_OPTIONS_NOT_QUOTED,
                    'goTemplateOptions',
                    "goTemplateOptions values must be quoted",
                    f'goTemplateOptions: [{quoted_items}]'
                )
    
    # ========================================================================
    # HELM/GO-TEMPLATE RULES
    # ========================================================================
    
    def _apply_helm_rules(self, line_num: int, line: str, stripped: str, context: List[str]):
        """Apply Helm/Go-Template quoting rules for pipe functions."""
        
        # Only check pipe functions here (other Helm checks are in K8s rules)
        if '|' in line:
            self._check_helm_pipe_functions(line_num, line, stripped)
    
    def _validate_helm_control_flow(self, line_num: int, line: str):
        """Validate Helm control-flow statements."""
        
        # Rule: if expression should not be quoted
        if re.search(r'\{\{-?\s*if\s+"', line):
            self._add_issue(
                line_num, line,
                IssueType.IF_EXPRESSION_QUOTED,
                'control-flow',
                "Control-flow 'if' expression should not be quoted",
                re.sub(r'if\s+"([^"]+)"', r'if \1', line)
            )
        
        # Rule: range expression should not be quoted
        if re.search(r'\{\{-?\s*range\s+"', line):
            self._add_issue(
                line_num, line,
                IssueType.RANGE_EXPRESSION_QUOTED,
                'control-flow',
                "Control-flow 'range' expression should not be quoted",
                re.sub(r'range\s+"([^"]+)"', r'range \1', line)
            )
        
        # Rule: String literals in comparisons must be quoted
        comparison_match = re.search(
            r'\b(eq|ne)\s+(\.[a-zA-Z_.]+)\s+([a-zA-Z][a-zA-Z0-9_-]*)\s*[}\)]',
            line
        )
        if comparison_match:
            func, var, literal = comparison_match.groups()
            if not literal.isdigit() and literal not in ('true', 'false', 'nil'):
                self._add_issue(
                    line_num, line,
                    IssueType.STRING_LITERAL_NOT_QUOTED,
                    'comparison',
                    f"String literal '{literal}' in comparison must be quoted",
                    line.replace(f'{func} {var} {literal}', f'{func} {var} "{literal}"')
                )
    
    def _check_helm_pipe_functions(self, line_num: int, line: str, value: str):
        """Check Helm pipe function parameters."""
        
        # Rule: default string parameter should be quoted
        default_match = re.search(r'\|\s*default\s+([^\s\|\}]+)', value)
        if default_match:
            default_val = default_match.group(1)
            if not default_val.startswith('"') and not default_val.startswith("'"):
                if not default_val.isdigit() and default_val not in ('true', 'false', 'nil'):
                    if not default_val.startswith('.') and not default_val.startswith('$'):
                        self._add_issue(
                            line_num, line,
                            IssueType.DEFAULT_STRING_NOT_QUOTED,
                            'pipe-function',
                            f"String default value '{default_val}' should be quoted",
                            line.replace(f'default {default_val}', f'default "{default_val}"')
                        )
        
        # Rule: ternary false value should be quoted
        ternary_match = re.search(r'\|\s*ternary\s+"([^"]*)"\s+([^\s\|\}"\']+)', value)
        if ternary_match:
            false_val = ternary_match.group(2)
            if not false_val.startswith('"') and not false_val.isdigit():
                if false_val not in ('true', 'false', 'nil'):
                    self._add_issue(
                        line_num, line,
                        IssueType.TERNARY_STRING_NOT_QUOTED,
                        'pipe-function',
                        f"Ternary false value '{false_val}' should be quoted",
                        line.replace(
                            f'ternary "{ternary_match.group(1)}" {false_val}',
                            f'ternary "{ternary_match.group(1)}" "{false_val}"'
                        )
                    )
        
        # Rule: replace parameters should be quoted
        replace_match = re.search(r'\|\s*replace\s+([^\s"\']+)\s+([^\s\|]+)', value)
        if replace_match:
            old_val = replace_match.group(1)
            if not old_val.startswith('"') and not old_val.startswith("'"):
                self._add_issue(
                    line_num, line,
                    IssueType.REPLACE_PARAM_NOT_QUOTED,
                    'pipe-function',
                    f"Replace parameter '{old_val}' should be quoted",
                    line.replace(f'replace {old_val}', f'replace "{old_val}"')
                )
    
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
        
        return 'string'
    
    # ========================================================================
    # HELPERS
    # ========================================================================
    
    def _add_issue(self, line_num: int, line: str, issue_type: IssueType,
                   field_path: str, message: str, suggestion: str):
        """Add an issue (always ERROR)."""
        self.issues.append(QuoteIssue(
            line_number=line_num,
            line_content=line.rstrip(),
            issue_type=issue_type,
            field_path=field_path,
            message=message,
            suggestion=suggestion,
            severity=Severity.ERROR
        ))


# ============================================================================
# MAIN
# ============================================================================

def main():
    """CLI entry point."""
    import argparse
    
    parser = argparse.ArgumentParser(description='Unified Quote Validator')
    parser.add_argument('files', nargs='+', help='YAML files to validate')
    parser.add_argument('-v', '--verbose', action='store_true')
    parser.add_argument('--strict', action='store_true')
    
    args = parser.parse_args()
    
    exit_code = 0
    validator = UnifiedQuoteValidator(strict=args.strict)
    
    for filepath in args.files:
        result = validator.validate_file(filepath)
        
        if not result.is_valid:
            exit_code = 1
        
        if result.issues or args.verbose:
            print(f"\n{'=' * 60}")
            print(f"File: {filepath}")
            print(f"{'=' * 60}")
            
            for issue in result.issues:
                print(f"[ERROR] Line {issue.line_number}: {issue.message}")
                print(f"   CURRENT:  {issue.line_content.strip()}")
                print(f"   EXPECTED: {issue.suggestion}")
                print()
            
            if not result.issues:
                print("OK - No issues found\n")
            else:
                print(f"Summary: {result.error_count} error(s)\n")
    
    sys.exit(exit_code)


if __name__ == '__main__':
    main()