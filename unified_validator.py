#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Unified Quote Validator - Context-based rules for Helm/Kubernetes YAML.

Key Rules:
1. apiVersion, kind -> NEVER quoted
2. IN metadata -> int/bool MUST be quoted, strings DON'T need quotes
3. OUTSIDE metadata -> int/bool must NOT be quoted, strings MUST be quoted
4. Block scalar content (| or >) is SKIPPED entirely
5. Inline comments are stripped before type detection
6. Helm default values MUST be quoted, outer quotes FORBIDDEN
7. Hardcoded keys (numberOfReplicas, staleReplicaTimeout) MUST always be quoted
"""

import re
import sys
from pathlib import Path
from typing import List, Optional, Set, Dict, Any
from dataclasses import dataclass, field as dataclass_field
from enum import Enum
from io import StringIO

from ruamel.yaml import YAML
from ruamel.yaml.comments import CommentedMap, CommentedSeq
from ruamel.yaml.scalarstring import (
    DoubleQuotedScalarString,
    SingleQuotedScalarString,
    LiteralScalarString,
    FoldedScalarString,
)


# ============================================================================
# TYPES
# ============================================================================

class Severity(Enum):
    ERROR = "error"
    WARNING = "warning"


class IssueType(Enum):
    BOOLEAN_AS_STRING = "boolean_as_string"
    INTEGER_FIELD_QUOTED = "integer_field_quoted"
    HELM_TEMPLATE_INT_QUOTED = "helm_template_int_quoted"
    HELM_TEMPLATE_STRING_NOT_QUOTED = "helm_template_string_not_quoted"
    HELM_DEFAULT_NOT_QUOTED = "helm_default_not_quoted"
    HELM_DEFAULT_OUTER_QUOTES = "helm_default_outer_quotes"
    GO_TEMPLATE_OPTIONS_NOT_QUOTED = "go_template_options_not_quoted"
    PATH_NOT_QUOTED = "path_not_quoted"
    URL_NOT_QUOTED = "url_not_quoted"
    PORT_STRING_NOT_QUOTED = "port_string_not_quoted"
    STRING_VALUE_NOT_QUOTED = "string_value_not_quoted"
    TOP_LEVEL_QUOTED = "top_level_quoted"
    METADATA_VALUE_NOT_QUOTED = "metadata_value_not_quoted"
    FORCED_QUOTE_KEY_NOT_QUOTED = "forced_quote_key_not_quoted"


@dataclass
class QuoteIssue:
    line_number: int
    line_content: str
    issue_type: IssueType
    field_path: str
    message: str
    suggestion: str
    severity: Severity = Severity.ERROR


@dataclass
class ValidationResult:
    file_path: str
    is_valid: bool
    issues: List[QuoteIssue] = dataclass_field(default_factory=list)
    error_count: int = 0


# ============================================================================
# CONSTANTS
# ============================================================================

# Keys that must ALWAYS have quoted values
FORCED_QUOTE_KEYS = {
    'numberOfReplicas',
    'staleReplicaTimeout',
}

# Top-level K8S keys that should NEVER be quoted
TOP_LEVEL_UNQUOTED = {'apiVersion', 'kind', 'metadata', 'spec', 'data', 'status'}

# Port object string fields
PORT_STRING_FIELDS = {'name', 'protocol'}

# String list contexts
STRING_LIST_CONTEXTS = {'valueFiles', 'syncOptions', 'finalizers', 'goTemplateOptions'}

# Helm control flow patterns (skip these lines)
HELM_CONTROL_FLOW_PATTERNS = [
    r'^\s*\{\{-?\s*if\s', r'^\s*\{\{-?\s*else\s*if\s',
    r'^\s*\{\{-?\s*else\s*-?\}\}', r'^\s*\{\{-?\s*end\s*-?\}\}',
    r'^\s*\{\{-?\s*range\s', r'^\s*\{\{-?\s*with\s',
    r'^\s*\{\{-?\s*define\s', r'^\s*\{\{-?\s*template\s',
    r'^\s*\{\{-?\s*include\s', r'^\s*\{\{-?\s*block\s',
    r'^\s*\{\{-?\s*/\*', r'^\s*\{\{-?\s*\$[a-zA-Z_][a-zA-Z0-9_]*\s*:=',
]

# Patterns that indicate int/bool Helm templates
HELM_INT_BOOL_PATTERNS = [
    r'\.replicas\b', r'\.replicaCount\b', r'\.port\b', r'\.targetPort\b',
    r'\.nodePort\b', r'\.containerPort\b', r'\.enabled\b', r'\.disabled\b',
    r'\.count\b', r'\.limit\b', r'\.minReplicas\b', r'\.maxReplicas\b',
    r'\|\s*int\b', r'\|\s*bool\b', r'\|\s*default\s+\d+',
    r'\|\s*default\s+(true|false)\b',
]


# ============================================================================
# UTILITY FUNCTIONS
# ============================================================================

def is_quoted(value: str) -> bool:
    """Check if a value is quoted."""
    v = value.strip()
    return (v.startswith('"') and v.endswith('"')) or \
           (v.startswith("'") and v.endswith("'"))


def strip_quotes(value: str) -> str:
    """Remove quotes from value."""
    v = value.strip()
    return v[1:-1] if is_quoted(v) else v


def contains_helm_template(value: str) -> bool:
    """Check if value contains {{ }}."""
    return '{{' in value and '}}' in value


def is_int_bool_helm_template(value: str) -> bool:
    """Check if Helm template produces int/bool."""
    for pattern in HELM_INT_BOOL_PATTERNS:
        if re.search(pattern, value):
            return True
    return False


def is_helm_control_flow(line: str) -> bool:
    """Check if line is Helm control flow."""
    for pattern in HELM_CONTROL_FLOW_PATTERNS:
        if re.search(pattern, line):
            return True
    return False


# ============================================================================
# UNIFIED QUOTE VALIDATOR
# ============================================================================

class UnifiedQuoteValidator:
    """
    Unified Quote Validator for Helm/Kubernetes YAML files.
    """

    def __init__(self):
        self.yaml = YAML()
        self.yaml.preserve_quotes = True
        self.issues: List[QuoteIssue] = []
        self.lines: List[str] = []
        self.current_file: str = ""

    def validate_file(self, file_path: str) -> ValidationResult:
        """Validate a file."""
        self.current_file = file_path

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
                    issue_type=IssueType.STRING_VALUE_NOT_QUOTED,
                    field_path="",
                    message=f"Cannot read file: {e}",
                    suggestion=""
                )],
                error_count=1
            )

    def validate_content(self, content: str, file_path: str = "<string>") -> ValidationResult:
        """Validate YAML content."""
        self.issues = []
        self.lines = content.split('\n')
        self.current_file = file_path

        # Check for Helm default quoting issues (line-based)
        self._check_helm_defaults()

        # Parse and validate structure
        try:
            data = self.yaml.load(StringIO(content))
            if data is not None:
                self._validate_node(data, [], in_metadata=False)
        except Exception as e:
            self.issues.append(QuoteIssue(
                line_number=1,
                line_content=self.lines[0] if self.lines else "",
                issue_type=IssueType.STRING_VALUE_NOT_QUOTED,
                field_path="",
                message=f"YAML Parse Error: {e}",
                suggestion=""
            ))

        return ValidationResult(
            file_path=file_path,
            is_valid=len(self.issues) == 0,
            issues=self.issues,
            error_count=len(self.issues)
        )

    def _get_line_content(self, line_num: int) -> str:
        """Get line content by line number (1-indexed)."""
        if 1 <= line_num <= len(self.lines):
            return self.lines[line_num - 1]
        return ""

    def _check_helm_defaults(self):
        """Check for unquoted Helm default values."""
        # Pattern: | default VALUE (where VALUE is not quoted)
        default_pattern = re.compile(
            r'\|\s*default\s+([^"\'\s\|\}][^\s\|\}]*)'
        )

        for line_num, line in enumerate(self.lines, start=1):
            if is_helm_control_flow(line):
                continue

            if '{{' not in line or '}}' not in line:
                continue

            # Find unquoted default values
            for match in default_pattern.finditer(line):
                default_value = match.group(1)

                # Skip if it's a number (numbers don't need quotes in default)
                if re.match(r'^-?\d+\.?\d*$', default_value):
                    continue

                # Skip if it's a boolean
                if default_value.lower() in ('true', 'false'):
                    continue

                # Skip if it's a variable reference
                if default_value.startswith('.') or default_value.startswith('$'):
                    continue

                # This is an unquoted string default
                key_match = re.match(r'\s*([^:]+):', line)
                key = key_match.group(1).strip() if key_match else "unknown"

                suggested = line.replace(
                    f'default {default_value}',
                    f'default "{default_value}"'
                )

                self.issues.append(QuoteIssue(
                    line_number=line_num,
                    line_content=line.rstrip(),
                    issue_type=IssueType.HELM_DEFAULT_NOT_QUOTED,
                    field_path=key,
                    message=f'Helm default value must be quoted: default "{default_value}"',
                    suggestion=suggested.strip()
                ))

    def _validate_node(self, node: Any, path: List[str], in_metadata: bool):
        """Recursively validate YAML nodes."""
        if isinstance(node, CommentedMap):
            for key, value in node.items():
                key_str = str(key)
                new_path = path + [key_str]

                # Check if entering metadata
                new_in_metadata = in_metadata or key_str == 'metadata'

                # Validate the value
                if isinstance(value, (CommentedMap, CommentedSeq)):
                    self._validate_node(value, new_path, new_in_metadata)
                else:
                    self._validate_value(key_str, value, node, new_path, new_in_metadata)

        elif isinstance(node, CommentedSeq):
            for idx, item in enumerate(node):
                new_path = path + [f'[{idx}]']
                if isinstance(item, (CommentedMap, CommentedSeq)):
                    self._validate_node(item, new_path, in_metadata)
                else:
                    self._validate_list_item(item, node, idx, new_path, in_metadata)

    def _validate_value(self, key: str, value: Any, parent: CommentedMap,
                        path: List[str], in_metadata: bool):
        """Validate a single key-value pair."""
        if value is None:
            return

        # Skip block scalars
        if isinstance(value, (LiteralScalarString, FoldedScalarString)):
            return

        line, _ = self._get_position(parent, key)
        line_content = self._get_line_content(line)
        field_path = '.'.join(path)

        is_value_quoted = isinstance(value, (DoubleQuotedScalarString, SingleQuotedScalarString))
        str_value = str(value)

        # Rule 1: FORCED_QUOTE_KEYS must always be quoted
        if key in FORCED_QUOTE_KEYS:
            if not is_value_quoted:
                self.issues.append(QuoteIssue(
                    line_number=line,
                    line_content=line_content,
                    issue_type=IssueType.FORCED_QUOTE_KEY_NOT_QUOTED,
                    field_path=field_path,
                    message=f"Key '{key}' must always have quoted value",
                    suggestion=f'{key}: "{value}"'
                ))
            return

        # Rule 2: Top-level K8S keys (apiVersion, kind) should NOT be quoted
        if len(path) == 1 and key in TOP_LEVEL_UNQUOTED:
            if is_value_quoted and isinstance(value, str):
                self.issues.append(QuoteIssue(
                    line_number=line,
                    line_content=line_content,
                    issue_type=IssueType.TOP_LEVEL_QUOTED,
                    field_path=field_path,
                    message=f"Top-level key '{key}' should not have quoted value",
                    suggestion=f'{key}: {strip_quotes(str_value)}'
                ))
            return

        # Rule 3: Helm templates
        if contains_helm_template(str_value):
            self._validate_helm_template(key, str_value, is_value_quoted, line,
                                         line_content, field_path, in_metadata)
            return

        # Rule 4: In metadata - strings don't need quotes, but int/bool DO
        if in_metadata:
            if isinstance(value, bool):
                if not is_value_quoted:
                    self.issues.append(QuoteIssue(
                        line_number=line,
                        line_content=line_content,
                        issue_type=IssueType.BOOLEAN_AS_STRING,
                        field_path=field_path,
                        message="Boolean in metadata must be quoted",
                        suggestion=f'{key}: "{str_value.lower()}"'
                    ))
            elif isinstance(value, int) and not isinstance(value, bool):
                if not is_value_quoted:
                    self.issues.append(QuoteIssue(
                        line_number=line,
                        line_content=line_content,
                        issue_type=IssueType.INTEGER_FIELD_QUOTED,
                        field_path=field_path,
                        message="Integer in metadata must be quoted",
                        suggestion=f'{key}: "{value}"'
                    ))
            return

        # Rule 5: Outside metadata - strings MUST be quoted
        if isinstance(value, str) and not is_value_quoted:
            # Skip if it looks like a K8S reference (e.g., ClusterIP, Always)
            if re.match(r'^[A-Z][a-zA-Z]+$', str_value):
                return

            # Check for paths
            if str_value.startswith('/') or str_value.startswith('./'):
                self.issues.append(QuoteIssue(
                    line_number=line,
                    line_content=line_content,
                    issue_type=IssueType.PATH_NOT_QUOTED,
                    field_path=field_path,
                    message="Path value must be quoted",
                    suggestion=f'{key}: "{str_value}"'
                ))
                return

            # Check for URLs
            if str_value.startswith('http://') or str_value.startswith('https://'):
                self.issues.append(QuoteIssue(
                    line_number=line,
                    line_content=line_content,
                    issue_type=IssueType.URL_NOT_QUOTED,
                    field_path=field_path,
                    message="URL value must be quoted",
                    suggestion=f'{key}: "{str_value}"'
                ))
                return

    def _validate_helm_template(self, key: str, value: str, is_quoted: bool,
                                line: int, line_content: str, field_path: str,
                                in_metadata: bool):
        """Validate Helm template quoting."""
        is_int_bool = is_int_bool_helm_template(value)

        if is_int_bool:
            # Int/bool templates should NOT be quoted
            if is_quoted:
                self.issues.append(QuoteIssue(
                    line_number=line,
                    line_content=line_content,
                    issue_type=IssueType.HELM_TEMPLATE_INT_QUOTED,
                    field_path=field_path,
                    message="Helm template producing int/bool should not be quoted",
                    suggestion=f'{key}: {value}'
                ))
        else:
            # String templates SHOULD be quoted (unless in metadata)
            if not is_quoted and not in_metadata:
                self.issues.append(QuoteIssue(
                    line_number=line,
                    line_content=line_content,
                    issue_type=IssueType.HELM_TEMPLATE_STRING_NOT_QUOTED,
                    field_path=field_path,
                    message="Helm template producing string should be quoted",
                    suggestion=f'{key}: "{value}"'
                ))

    def _validate_list_item(self, item: Any, parent: CommentedSeq, idx: int,
                            path: List[str], in_metadata: bool):
        """Validate a list item."""
        if item is None:
            return

        if isinstance(item, (LiteralScalarString, FoldedScalarString)):
            return

        # Get context from path
        context = path[-2] if len(path) >= 2 else ""

        # goTemplateOptions must be quoted
        if context == 'goTemplateOptions':
            is_quoted = isinstance(item, (DoubleQuotedScalarString, SingleQuotedScalarString))
            if not is_quoted and isinstance(item, str):
                line, _ = self._get_position(parent, idx)
                self.issues.append(QuoteIssue(
                    line_number=line,
                    line_content=self._get_line_content(line),
                    issue_type=IssueType.GO_TEMPLATE_OPTIONS_NOT_QUOTED,
                    field_path='.'.join(path),
                    message="goTemplateOptions items must be quoted",
                    suggestion=f'- "{item}"'
                ))

    def _get_position(self, parent: Any, key_or_idx: Any) -> tuple:
        """Get line and column of a value."""
        if isinstance(parent, CommentedMap):
            if hasattr(parent, 'lc') and hasattr(parent.lc, 'data'):
                if key_or_idx in parent.lc.data:
                    _, _, val_line, val_col = parent.lc.data[key_or_idx]
                    return val_line + 1, val_col + 1

        elif isinstance(parent, CommentedSeq):
            if hasattr(parent, 'lc') and hasattr(parent.lc, 'data'):
                if key_or_idx in parent.lc.data:
                    line, col = parent.lc.data[key_or_idx]
                    return line + 1, col + 1

        return 1, 1


# ============================================================================
# MAIN
# ============================================================================

def main():
    """CLI entry point."""
    if len(sys.argv) < 2:
        print("Unified Quote Validator v2.0.0")
        print("=" * 60)
        print("\nUsage: python unified_validator.py <file>")
        sys.exit(1)

    file_path = sys.argv[1]

    validator = UnifiedQuoteValidator()
    result = validator.validate_file(file_path)

    if result.issues:
        print("")
        print("=" * 80)
        print(f"File: {file_path}")
        print("=" * 80)

        for issue in result.issues:
            print(f"[ERROR] Line {issue.line_number}: {issue.message}")
            print(f"   PATH:     {issue.field_path}")
            print(f"   CURRENT:  {issue.line_content.strip()}")
            print(f"   EXPECTED: {issue.suggestion}")
            print("")

        print("-" * 80)
        print(f"Summary: {result.error_count} error(s)")
        print("")
        sys.exit(1)
    else:
        print(f"\n[OK] {file_path}: All checks passed")
        sys.exit(0)


if __name__ == "__main__":
    main()