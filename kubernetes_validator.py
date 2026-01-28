#!/usr/bin/env python3
"""
Kubernetes Manifest Validator - Quote Rules

This validator does NOT contain file type detection logic.
Detection is handled by yaml_router.py (FileTypeDetector).
This validator ASSUMES the file is already identified as a K8s manifest.
"""

import re
import sys
from pathlib import Path
from typing import List, Tuple


# ============================================================================
# RELATIVE IMPORTS FOR PRE-COMMIT COMPATIBILITY
# ============================================================================

def _import_shared_constants():
    """Import shared_constants with fallback for different installation methods."""
    try:
        from shared_constants import (
            Severity, IssueType, QuoteIssue, ValidationResult,
            K8S_TOP_LEVEL_NO_QUOTE, K8S_METADATA_NO_QUOTE, K8S_INTEGER_FIELDS,
            K8S_PORT_STRING_FIELDS, K8S_STRING_FIELDS_REQUIRE_QUOTE,
            K8S_ANNOTATION_NUMERIC_KEYS, K8S_CONTEXT_KEYS,
            HELM_INT_BOOL_PATTERNS,
            is_quoted, contains_helm_template, is_int_bool_helm_template, looks_like_integer,
        )
        return (Severity, IssueType, QuoteIssue, ValidationResult,
                K8S_TOP_LEVEL_NO_QUOTE, K8S_METADATA_NO_QUOTE, K8S_INTEGER_FIELDS,
                K8S_PORT_STRING_FIELDS, K8S_STRING_FIELDS_REQUIRE_QUOTE,
                K8S_ANNOTATION_NUMERIC_KEYS, K8S_CONTEXT_KEYS,
                HELM_INT_BOOL_PATTERNS,
                is_quoted, contains_helm_template, is_int_bool_helm_template, looks_like_integer)
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
    return (module.Severity, module.IssueType, module.QuoteIssue, module.ValidationResult,
            module.K8S_TOP_LEVEL_NO_QUOTE, module.K8S_METADATA_NO_QUOTE, module.K8S_INTEGER_FIELDS,
            module.K8S_PORT_STRING_FIELDS, module.K8S_STRING_FIELDS_REQUIRE_QUOTE,
            module.K8S_ANNOTATION_NUMERIC_KEYS, module.K8S_CONTEXT_KEYS,
            module.HELM_INT_BOOL_PATTERNS,
            module.is_quoted, module.contains_helm_template, module.is_int_bool_helm_template, module.looks_like_integer)

(Severity, IssueType, QuoteIssue, ValidationResult,
 K8S_TOP_LEVEL_NO_QUOTE, K8S_METADATA_NO_QUOTE, K8S_INTEGER_FIELDS,
 K8S_PORT_STRING_FIELDS, K8S_STRING_FIELDS_REQUIRE_QUOTE,
 K8S_ANNOTATION_NUMERIC_KEYS, K8S_CONTEXT_KEYS,
 HELM_INT_BOOL_PATTERNS,
 is_quoted, contains_helm_template, is_int_bool_helm_template, looks_like_integer) = _import_shared_constants()


# ============================================================================
# Kubernetes Quote Validator
# ============================================================================

class KubernetesQuoteValidator:
    """Validator for Kubernetes manifest quoting rules."""
    
    def __init__(self, strict: bool = False, level: str = 'warning'):
        self.strict = strict
        self.level = Severity(level)
        self.issues: List[QuoteIssue] = []
        self.current_file: str = ""
        self.lines: List[str] = []
    
    def validate_file(self, file_path: str) -> ValidationResult:
        """Validate a YAML file for quoting rules."""
        self.issues = []
        self.current_file = file_path
        
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                self.lines = f.readlines()
        except Exception as e:
            print(f"Error reading file {file_path}: {e}", file=sys.stderr)
            return ValidationResult(file_path=file_path, is_valid=False)
        
        context_stack: List[Tuple[int, str]] = []
        in_annotations = False
        in_labels = False
        in_spec = False
        in_template = False
        in_ports = False
        in_go_template_options = False
        
        for line_num, line in enumerate(self.lines, start=1):
            stripped = line.strip()
            
            if not stripped or stripped.startswith('#'):
                continue
            
            if stripped == '---':
                context_stack = []
                in_annotations = False
                in_labels = False
                in_spec = False
                in_template = False
                in_ports = False
                in_go_template_options = False
                continue
            
            indent = len(line) - len(line.lstrip())
            context_stack = self._update_context(context_stack, indent, stripped)
            context = [ctx for _, ctx in context_stack]
            
            in_annotations = 'annotations' in context
            in_labels = 'labels' in context
            in_spec = 'spec' in context
            in_template = 'template' in context
            in_ports = 'ports' in context
            in_go_template_options = 'goTemplateOptions' in context
            
            self._validate_line(
                line_num, line, stripped, context,
                in_annotations, in_labels, in_spec, in_template, 
                in_ports, in_go_template_options
            )
        
        errors = sum(1 for i in self.issues if i.severity == Severity.ERROR)
        warnings = sum(1 for i in self.issues if i.severity == Severity.WARNING)
        infos = sum(1 for i in self.issues if i.severity == Severity.INFO)
        
        severity_order = {Severity.ERROR: 0, Severity.WARNING: 1, Severity.INFO: 2}
        min_level = severity_order[self.level]
        filtered_issues = [i for i in self.issues if severity_order[i.severity] <= min_level]
        
        has_errors = any(i.severity == Severity.ERROR for i in filtered_issues)
        has_warnings = any(i.severity == Severity.WARNING for i in filtered_issues)
        
        if has_errors:
            is_valid = False
        elif has_warnings and self.strict:
            is_valid = False
        else:
            is_valid = True
        
        return ValidationResult(
            file_path=file_path,
            is_valid=is_valid,
            issues=filtered_issues,
            errors=errors,
            warnings=warnings,
            infos=infos
        )
    
    def _update_context(self, stack: List[Tuple[int, str]], indent: int, line: str) -> List[Tuple[int, str]]:
        """Update context stack based on indentation."""
        stack = [(i, ctx) for i, ctx in stack if i < indent]
        
        if ':' in line:
            key = line.split(':')[0].strip().lstrip('- ')
            if key in K8S_CONTEXT_KEYS:
                stack.append((indent, key))
        
        return stack
    
    def _validate_line(
        self, line_num: int, line: str, stripped: str, context: List[str],
        in_annotations: bool, in_labels: bool, in_spec: bool, in_template: bool,
        in_ports: bool, in_go_template_options: bool
    ):
        """Validate a single line."""
        
        if stripped.startswith('- '):
            self._validate_list_item(
                line_num, line, stripped, context,
                in_annotations, in_ports, in_go_template_options
            )
            return
        
        if ':' not in stripped:
            return
        
        parts = stripped.split(':', 1)
        if len(parts) != 2:
            return
        
        key = parts[0].strip()
        value = parts[1].strip()
        
        if not value:
            return
        
        self._check_boolean_as_string(line_num, line, key, value, context)
        
        if in_annotations:
            self._check_annotation_value(line_num, line, key, value)
        
        if key in K8S_INTEGER_FIELDS:
            self._check_integer_field_quoted(line_num, line, key, value, context)
        
        if contains_helm_template(value):
            self._check_helm_template(line_num, line, key, value, context)
        
        if key == 'goTemplateOptions':
            self._check_go_template_options(line_num, line, value)
        
        if not context and key in K8S_TOP_LEVEL_NO_QUOTE:
            self._check_top_level_quoted(line_num, line, key, value)
        
        if 'metadata' in context and key in K8S_METADATA_NO_QUOTE:
            self._check_metadata_quoted(line_num, line, key, value)
        
        if in_spec or in_template:
            self._check_path_url_quoted(line_num, line, key, value, context)
        
        if in_ports and key in K8S_PORT_STRING_FIELDS:
            self._check_port_string_quoted(line_num, line, key, value)
    
    def _validate_list_item(
        self, line_num: int, line: str, stripped: str, context: List[str],
        in_annotations: bool, in_ports: bool, in_go_template_options: bool
    ):
        """Validate list items."""
        value = stripped[2:].strip()
        
        if in_go_template_options or 'goTemplateOptions' in context:
            if value and not is_quoted(value):
                self._add_issue(
                    line_num, line,
                    IssueType.GO_TEMPLATE_OPTIONS_NOT_QUOTED,
                    'goTemplateOptions[]',
                    "goTemplateOptions value must be quoted",
                    f'- "{value}"',
                    Severity.ERROR
                )
        
        if in_ports and ':' not in value:
            if is_quoted(value) and value.strip('"\'').isdigit():
                self._add_issue(
                    line_num, line,
                    IssueType.INTEGER_FIELD_QUOTED,
                    'ports[]',
                    "Integer in array must not be quoted",
                    f'- {value.strip("\"\'")}',
                    Severity.ERROR
                )
        
        if 'valueFiles' in context and contains_helm_template(value):
            if not is_quoted(value):
                self._add_issue(
                    line_num, line,
                    IssueType.HELM_TEMPLATE_STRING_NOT_QUOTED,
                    'valueFiles[]',
                    "Helm template string must be quoted",
                    f'- "{value}"',
                    Severity.WARNING
                )
    
    def _check_boolean_as_string(self, line_num: int, line: str, key: str, value: str, context: List[str]):
        """Check if boolean is quoted as string (ERROR)."""
        if 'annotations' in context:
            return
        
        if value.lower() in ('"true"', '"false"', "'true'", "'false'"):
            self._add_issue(
                line_num, line,
                IssueType.BOOLEAN_AS_STRING,
                '.'.join(context + [key]) if context else key,
                "Boolean must not be quoted as string",
                f'{key}: {value.strip("\"\'").lower()}',
                Severity.ERROR
            )
    
    def _check_annotation_value(self, line_num: int, line: str, key: str, value: str):
        """Check annotation values."""
        if looks_like_integer(value) and not is_quoted(value):
            self._add_issue(
                line_num, line,
                IssueType.ANNOTATION_INT_NOT_QUOTED,
                f'annotations.{key}',
                f"Annotation value '{value}' must be quoted as string",
                f'{key}: "{value}"',
                Severity.ERROR
            )
        
        elif '=' in value and not is_quoted(value):
            self._add_issue(
                line_num, line,
                IssueType.ANNOTATION_SPECIAL_CHAR_NOT_QUOTED,
                f'annotations.{key}',
                "Annotation value with '=' should be quoted",
                f'{key}: "{value}"',
                Severity.WARNING
            )
    
    def _check_integer_field_quoted(self, line_num: int, line: str, key: str, value: str, context: List[str]):
        """Check if integer fields are quoted (ERROR)."""
        if 'annotations' in context:
            return
        
        if is_quoted(value):
            inner = value.strip('"\'')
            if inner.isdigit() or (inner.startswith('-') and inner[1:].isdigit()):
                self._add_issue(
                    line_num, line,
                    IssueType.INTEGER_FIELD_QUOTED,
                    '.'.join(context + [key]) if context else key,
                    f"Integer field '{key}' must not be quoted",
                    f'{key}: {inner}',
                    Severity.ERROR
                )
    
    def _check_helm_template(self, line_num: int, line: str, key: str, value: str, context: List[str]):
        """Check Helm template quoting."""
        quoted = is_quoted(value)
        is_int_bool = is_int_bool_helm_template(value)
        
        if is_int_bool:
            if quoted:
                self._add_issue(
                    line_num, line,
                    IssueType.HELM_TEMPLATE_INT_QUOTED,
                    '.'.join(context + [key]) if context else key,
                    "Helm template for Integer/Boolean must not be quoted",
                    f'{key}: {value.strip("\"\'")}',
                    Severity.ERROR
                )
        else:
            if not quoted:
                self._add_issue(
                    line_num, line,
                    IssueType.HELM_TEMPLATE_STRING_NOT_QUOTED,
                    '.'.join(context + [key]) if context else key,
                    "Helm template for String should be quoted",
                    f'{key}: "{value}"',
                    Severity.WARNING
                )
    
    def _check_go_template_options(self, line_num: int, line: str, value: str):
        """Check goTemplateOptions (ERROR)."""
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
                    f'goTemplateOptions: [{quoted_items}]',
                    Severity.ERROR
                )
    
    def _check_top_level_quoted(self, line_num: int, line: str, key: str, value: str):
        """Check if top-level fields are quoted (WARNING)."""
        if is_quoted(value):
            self._add_issue(
                line_num, line,
                IssueType.TOP_LEVEL_QUOTED,
                key,
                f"Top-level field '{key}' is usually not quoted",
                f'{key}: {value.strip("\"\'")}',
                Severity.WARNING
            )
    
    def _check_metadata_quoted(self, line_num: int, line: str, key: str, value: str):
        """Check if metadata name/namespace are quoted (WARNING)."""
        if contains_helm_template(value):
            return
        
        if is_quoted(value):
            self._add_issue(
                line_num, line,
                IssueType.METADATA_QUOTED,
                f'metadata.{key}',
                f"Metadata '{key}' is usually not quoted",
                f'{key}: {value.strip("\"\'")}',
                Severity.WARNING
            )
    
    def _check_path_url_quoted(self, line_num: int, line: str, key: str, value: str, context: List[str]):
        """Check if paths/URLs are quoted (WARNING)."""
        if contains_helm_template(value):
            return
        
        if key in ('path', 'repoURL', 'targetRevision', 'chart', 'ref', 'revision'):
            if not is_quoted(value) and value:
                self._add_issue(
                    line_num, line,
                    IssueType.PATH_NOT_QUOTED,
                    '.'.join(context + [key]) if context else key,
                    f"Field '{key}' should be quoted",
                    f'{key}: "{value}"',
                    Severity.WARNING
                )
        
        elif value.startswith('http://') or value.startswith('https://'):
            if not is_quoted(value):
                self._add_issue(
                    line_num, line,
                    IssueType.URL_NOT_QUOTED,
                    '.'.join(context + [key]) if context else key,
                    "URL should be quoted",
                    f'{key}: "{value}"',
                    Severity.WARNING
                )
    
    def _check_port_string_quoted(self, line_num: int, line: str, key: str, value: str):
        """Check if port string fields are quoted (WARNING)."""
        if not is_quoted(value) and value:
            self._add_issue(
                line_num, line,
                IssueType.PORT_STRING_NOT_QUOTED,
                f'ports[].{key}',
                f"Port '{key}' should be quoted",
                f'{key}: "{value}"',
                Severity.WARNING
            )
    
    def _add_issue(
        self, line_num: int, line: str, issue_type: IssueType,
        field_path: str, message: str, suggestion: str, severity: Severity
    ):
        """Add an issue."""
        self.issues.append(QuoteIssue(
            line_number=line_num,
            line_content=line.rstrip(),
            issue_type=issue_type,
            field_path=field_path,
            message=message,
            suggestion=suggestion,
            severity=severity
        ))


# ============================================================================
# Main Function
# ============================================================================

def main():
    """Main function for CLI."""
    import argparse
    
    parser = argparse.ArgumentParser(description='Kubernetes Quote Validator')
    parser.add_argument('files', nargs='+', help='YAML files to validate')
    parser.add_argument('-v', '--verbose', action='store_true', help='Verbose output')
    parser.add_argument('--level', choices=['error', 'warning', 'info'], default='warning', help='Minimum severity level')
    parser.add_argument('--strict', action='store_true', help='Treat warnings as errors')
    
    args = parser.parse_args()
    
    exit_code = 0
    
    for file_path in args.files:
        path = Path(file_path)
        
        if not path.exists():
            print(f"[ERROR] File not found: {file_path}", file=sys.stderr)
            exit_code = 1
            continue
        
        if path.suffix not in ('.yaml', '.yml'):
            if args.verbose:
                print(f"SKIPPED (not a YAML file): {file_path}")
            continue
        
        validator = KubernetesQuoteValidator(strict=args.strict, level=args.level)
        result = validator.validate_file(file_path)
        
        if not result.is_valid:
            exit_code = 1
        
        if result.issues:
            print(f"\n{'=' * 60}")
            print(f"File: {file_path}")
            print(f"{'=' * 60}")
            
            for issue in result.issues:
                severity_tag = "[ERROR]" if issue.severity == Severity.ERROR else "[WARNING]"
                print(f"{severity_tag} Line {issue.line_number}: {issue.message}")
                print(f"   CURRENT:  {issue.line_content.strip()}")
                print(f"   EXPECTED: {issue.suggestion}")
                print()
            
            print(f"Summary: {result.errors} error(s), {result.warnings} warning(s)")
        elif args.verbose:
            print(f"OK - {file_path}: No issues found")
    
    return exit_code


if __name__ == '__main__':
    sys.exit(main())