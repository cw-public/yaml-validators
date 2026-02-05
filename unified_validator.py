#!/usr/bin/env python3
# filepath: c:\Users\ahryhory\Documents\Git-repos\yaml-validators\unified_validator.py
"""
Unified Quote Validator - Indent-based traversal approach.

Key principles:
1. Track context by INDENT, not by knowing all possible keys
2. Apply rules based on CONTEXT PATTERNS (labels, annotations, etc.)
3. Apply field-specific rules based on FIELD NAME (replicas, port, etc.)

ALL issues are ERRORS (no warnings).
"""

import re
import sys
from pathlib import Path
from typing import Dict, List, Tuple
from dataclasses import dataclass


# ============================================================================
# IMPORTS
# ============================================================================

def _import_shared_constants():
    """Import shared_constants with fallback."""
    try:
        from shared_constants import (
            Severity, IssueType, QuoteIssue, ValidationResult,
            INTEGER_FIELDS, BOOLEAN_FIELDS, STRING_FIELDS_REQUIRE_QUOTE,
            PORT_STRING_FIELDS, STRING_LIST_CONTEXTS, QUOTED_VALUE_CONTEXTS,
            HELM_CONTROL_FLOW_PATTERNS, HELM_INT_BOOL_PATTERNS,
            is_quoted, strip_quotes, contains_helm_template, 
            is_int_bool_helm_template, looks_like_integer, looks_like_boolean,
        )
        return {
            'Severity': Severity, 'IssueType': IssueType,
            'QuoteIssue': QuoteIssue, 'ValidationResult': ValidationResult,
            'INTEGER_FIELDS': INTEGER_FIELDS, 'BOOLEAN_FIELDS': BOOLEAN_FIELDS,
            'STRING_FIELDS_REQUIRE_QUOTE': STRING_FIELDS_REQUIRE_QUOTE,
            'PORT_STRING_FIELDS': PORT_STRING_FIELDS,
            'STRING_LIST_CONTEXTS': STRING_LIST_CONTEXTS,
            'QUOTED_VALUE_CONTEXTS': QUOTED_VALUE_CONTEXTS,
            'HELM_CONTROL_FLOW_PATTERNS': HELM_CONTROL_FLOW_PATTERNS,
            'HELM_INT_BOOL_PATTERNS': HELM_INT_BOOL_PATTERNS,
            'is_quoted': is_quoted, 'strip_quotes': strip_quotes,
            'contains_helm_template': contains_helm_template,
            'is_int_bool_helm_template': is_int_bool_helm_template,
            'looks_like_integer': looks_like_integer,
            'looks_like_boolean': looks_like_boolean,
        }
    except ImportError:
        import importlib.util
        spec = importlib.util.spec_from_file_location(
            "shared_constants", Path(__file__).parent / "shared_constants.py"
        )
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return {name: getattr(module, name) for name in dir(module) if not name.startswith('_')}

_c = _import_shared_constants()
Severity = _c['Severity']
IssueType = _c['IssueType']
QuoteIssue = _c['QuoteIssue']
ValidationResult = _c['ValidationResult']
INTEGER_FIELDS = _c['INTEGER_FIELDS']
BOOLEAN_FIELDS = _c['BOOLEAN_FIELDS']
STRING_FIELDS_REQUIRE_QUOTE = _c['STRING_FIELDS_REQUIRE_QUOTE']
PORT_STRING_FIELDS = _c['PORT_STRING_FIELDS']
STRING_LIST_CONTEXTS = _c['STRING_LIST_CONTEXTS']
QUOTED_VALUE_CONTEXTS = _c['QUOTED_VALUE_CONTEXTS']
HELM_CONTROL_FLOW_PATTERNS = _c['HELM_CONTROL_FLOW_PATTERNS']
is_quoted = _c['is_quoted']
strip_quotes = _c['strip_quotes']
contains_helm_template = _c['contains_helm_template']
is_int_bool_helm_template = _c['is_int_bool_helm_template']
looks_like_integer = _c['looks_like_integer']
looks_like_boolean = _c['looks_like_boolean']


# ============================================================================
# CONTEXT TRACKER (Indent-based)
# ============================================================================

@dataclass
class ContextEntry:
    """Single entry in the context stack."""
    indent: int
    key: str


class ContextTracker:
    """
    Tracks YAML context by indent level - NOT by key names!
    
    This is the KEY innovation - we don't need to know all possible keys,
    we just track the hierarchy based on indentation.
    """
    
    def __init__(self):
        self.stack: List[ContextEntry] = []
    
    def update(self, line: str) -> List[str]:
        """Update context based on current line, return current path."""
        stripped = line.strip()
        
        if not stripped or stripped.startswith('#') or stripped == '---':
            return self.get_path()
        
        indent = len(line) - len(line.lstrip())
        
        # Pop all contexts with same or greater indent
        self.stack = [e for e in self.stack if e.indent < indent]
        
        # Check if this line starts a new context (key with no value)
        if ':' in stripped:
            colon_pos = stripped.find(':')
            key_part = stripped[:colon_pos].strip().lstrip('- ')
            value_part = stripped[colon_pos + 1:].strip()
            
            # If no value after colon, this key starts a new context block
            if not value_part:
                self.stack.append(ContextEntry(indent=indent, key=key_part))
        
        return self.get_path()
    
    def reset(self):
        """Reset context (for document separators)."""
        self.stack = []
    
    def get_path(self) -> List[str]:
        """Get current context as list of keys."""
        return [e.key for e in self.stack]
    
    def get_path_string(self) -> str:
        """Get current context as dot-separated string."""
        return '.'.join(self.get_path())
    
    def contains(self, key: str) -> bool:
        """Check if key is anywhere in current context."""
        return key in self.get_path()
    
    def parent_is(self, key: str) -> bool:
        """Check if immediate parent is key."""
        path = self.get_path()
        return len(path) > 0 and path[-1] == key
    
    def in_any(self, keys: set) -> bool:
        """Check if any of the keys are in current context."""
        return bool(keys.intersection(set(self.get_path())))


# ============================================================================
# UNIFIED VALIDATOR
# ============================================================================

class UnifiedQuoteValidator:
    """
    Unified validator using indent-based context tracking.
    
    Key principles:
    1. Track context by INDENT, not by knowing all keys
    2. Apply rules based on CONTEXT PATTERNS
    3. Apply field-specific rules based on FIELD NAME
    """
    
    def __init__(self, strict: bool = False, type_map: Dict[str, str] = None):
        self.strict = strict
        self.type_map = type_map or {}
        self.issues: List[QuoteIssue] = []
        self.context = ContextTracker()
    
    def validate_file(self, file_path: str) -> ValidationResult:
        """Validate a file."""
        try:
            content = Path(file_path).read_text(encoding='utf-8')
            return self.validate_content(content, file_path)
        except Exception as e:
            return ValidationResult(
                file_path=file_path, is_valid=False,
                issues=[QuoteIssue(0, "", IssueType.STRING_VALUE_NOT_QUOTED,
                                   "", f"Cannot read file: {e}", "")],
                error_count=1
            )
    
    def validate_content(self, content: str, file_path: str = "<string>") -> ValidationResult:
        """Validate content."""
        self.issues = []
        self.context = ContextTracker()
        
        lines = content.split('\n')
        has_helm = '{{' in content
        
        for line_num, line in enumerate(lines, 1):
            stripped = line.strip()
            
            if not stripped or stripped.startswith('#'):
                continue
            
            if stripped == '---':
                self.context.reset()
                continue
            
            # Skip Helm control-flow lines
            if has_helm and self._is_helm_control_flow(stripped):
                continue
            
            # Update context FIRST
            context_path = self.context.update(line)
            
            # Validate the line
            self._validate_line(line_num, line, stripped, context_path, has_helm)
        
        return ValidationResult(
            file_path=file_path,
            is_valid=len(self.issues) == 0,
            issues=self.issues,
            error_count=len(self.issues)
        )
    
    def _is_helm_control_flow(self, line: str) -> bool:
        """Check if line is pure Helm control-flow."""
        for pattern in HELM_CONTROL_FLOW_PATTERNS:
            if re.match(pattern, line):
                return True
        return False
    
    def _validate_line(self, line_num: int, line: str, stripped: str,
                       context_path: List[str], has_helm: bool):
        """Validate a single line."""
        
        # Handle list items
        if stripped.startswith('- '):
            self._validate_list_item(line_num, line, stripped, context_path, has_helm)
            return
        
        # Handle key: value pairs
        if ':' not in stripped:
            return
        
        colon_pos = stripped.find(':')
        key = stripped[:colon_pos].strip()
        value = stripped[colon_pos + 1:].strip()
        
        if not value:
            return
        
        field_path = '.'.join(context_path + [key]) if context_path else key
        
        # Context flags
        in_labels = self.context.in_any({'labels', 'matchLabels'})
        in_annotations = self.context.contains('annotations')
        in_ports = self.context.contains('ports')
        
        # ================================================================
        # RULE 1: Labels/MatchLabels - values MUST be quoted
        # ================================================================
        if in_labels:
            if not is_quoted(value) and not contains_helm_template(value):
                self._add_issue(line_num, line, IssueType.LABEL_VALUE_NOT_QUOTED,
                    field_path, f"Label value '{value}' must be quoted",
                    f'{key}: "{value}"')
            return
        
        # ================================================================
        # RULE 2: Annotations - values MUST be quoted
        # ================================================================
        if in_annotations:
            if not is_quoted(value) and not contains_helm_template(value):
                self._add_issue(line_num, line, IssueType.ANNOTATION_INT_NOT_QUOTED,
                    field_path, f"Annotation value '{value}' must be quoted",
                    f'{key}: "{value}"')
            return
        
        # ================================================================
        # RULE 3: Integer fields - must NOT be quoted
        # ================================================================
        if key in INTEGER_FIELDS:
            if is_quoted(value):
                inner = strip_quotes(value)
                if looks_like_integer(inner):
                    self._add_issue(line_num, line, IssueType.INTEGER_FIELD_QUOTED,
                        field_path, f"Integer field '{key}' must not be quoted",
                        f'{key}: {inner}')
            return
        
        # ================================================================
        # RULE 4: Boolean fields - must NOT be quoted as string
        # ================================================================
        if key in BOOLEAN_FIELDS:
            if is_quoted(value):
                inner = strip_quotes(value).lower()
                if inner in ('true', 'false'):
                    self._add_issue(line_num, line, IssueType.BOOLEAN_AS_STRING,
                        field_path, f"Boolean field '{key}' must not be quoted",
                        f'{key}: {inner}')
            return
        
        # ================================================================
        # RULE 5: Helm templates
        # ================================================================
        if has_helm and contains_helm_template(value):
            self._validate_helm_template(line_num, line, key, value, field_path)
            return
        
        # ================================================================
        # RULE 6: String fields that should be quoted
        # ================================================================
        if key in STRING_FIELDS_REQUIRE_QUOTE:
            if not is_quoted(value) and value:
                if not looks_like_boolean(value) and not looks_like_integer(value):
                    self._add_issue(line_num, line, IssueType.STRING_VALUE_NOT_QUOTED,
                        field_path, f"Field '{key}' should be quoted",
                        f'{key}: "{value}"')
            return
        
        # ================================================================
        # RULE 7: URLs should be quoted
        # ================================================================
        if value.startswith('http://') or value.startswith('https://'):
            if not is_quoted(value):
                self._add_issue(line_num, line, IssueType.URL_NOT_QUOTED,
                    field_path, "URL should be quoted", f'{key}: "{value}"')
            return
        
        # ================================================================
        # RULE 8: Port string fields
        # ================================================================
        if in_ports and key in PORT_STRING_FIELDS:
            if not is_quoted(value) and value:
                self._add_issue(line_num, line, IssueType.PORT_STRING_NOT_QUOTED,
                    f'ports[].{key}', f"Port '{key}' should be quoted",
                    f'{key}: "{value}"')
            return
        
        # ================================================================
        # RULE 9: goTemplateOptions
        # ================================================================
        if key == 'goTemplateOptions':
            self._validate_go_template_options(line_num, line, value)
    
    def _validate_list_item(self, line_num: int, line: str, stripped: str,
                            context_path: List[str], has_helm: bool):
        """Validate list items."""
        value = stripped[2:].strip()
        
        if not value:
            return
        
        # Check if it's a nested object
        if ':' in value and not is_quoted(value):
            colon_pos = value.find(':')
            before_colon = value[:colon_pos].strip()
            if re.match(r'^[a-zA-Z_][a-zA-Z0-9_.-]*$', before_colon):
                return
        
        parent = context_path[-1] if context_path else ''
        
        # String list contexts - ALL items should be quoted
        if parent in STRING_LIST_CONTEXTS:
            if not is_quoted(value):
                self._add_issue(line_num, line, IssueType.PATH_NOT_QUOTED,
                    f'{parent}[]', f"{parent} value should be quoted",
                    f'- "{value}"')
            return
        
        # Path values
        if (value.startswith('../') or value.startswith('./')) and not is_quoted(value):
            self._add_issue(line_num, line, IssueType.PATH_NOT_QUOTED,
                f'{parent}[]' if parent else 'list[]',
                "Path value should be quoted", f'- "{value}"')
    
    def _validate_helm_template(self, line_num: int, line: str, key: str,
                                 value: str, field_path: str):
        """Validate Helm template quoting."""
        quoted = is_quoted(value)
        is_int_bool = is_int_bool_helm_template(value) or \
                      key in INTEGER_FIELDS or key in BOOLEAN_FIELDS
        
        if is_int_bool:
            if quoted:
                self._add_issue(line_num, line, IssueType.HELM_TEMPLATE_INT_QUOTED,
                    field_path, "Helm template for Integer/Boolean must not be quoted",
                    f'{key}: {strip_quotes(value)}')
        else:
            if not quoted:
                self._add_issue(line_num, line, IssueType.HELM_TEMPLATE_STRING_NOT_QUOTED,
                    field_path, "Helm template string must be quoted",
                    f'{key}: "{value}"')
    
    def _validate_go_template_options(self, line_num: int, line: str, value: str):
        """Validate goTemplateOptions."""
        if value.startswith('[') and value.endswith(']'):
            inner = value[1:-1]
            if not inner:
                return
            
            items = [i.strip() for i in inner.split(',') if i.strip()]
            unquoted = [i for i in items if not is_quoted(i)]
            
            if unquoted:
                quoted_items = ', '.join(f'"{strip_quotes(i)}"' for i in items)
                self._add_issue(line_num, line, IssueType.GO_TEMPLATE_OPTIONS_NOT_QUOTED,
                    'goTemplateOptions', "goTemplateOptions values must be quoted",
                    f'goTemplateOptions: [{quoted_items}]')
    
    def _add_issue(self, line_num: int, line: str, issue_type: IssueType,
                   field_path: str, message: str, suggestion: str):
        """Add an issue."""
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
                print(f"   PATH:     {issue.field_path}")
                print(f"   CURRENT:  {issue.line_content.strip()}")
                print(f"   EXPECTED: {issue.suggestion}")
                print()
            
            if not result.issues:
                print("✓ No issues found\n")
            else:
                print(f"Summary: {result.error_count} error(s)\n")
    
    sys.exit(exit_code)


if __name__ == '__main__':
    main()