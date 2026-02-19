#!/usr/bin/env python3
"""
Unified Quote Validator - Context-based rules.

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
from typing import Dict, List, Tuple, Optional
from dataclasses import dataclass


# ============================================================================
# INLINE DEFINITIONS
# ============================================================================

try:
    from shared_constants import (
        Severity, IssueType, QuoteIssue, ValidationResult,
        PORT_STRING_FIELDS, STRING_LIST_CONTEXTS,
        HELM_CONTROL_FLOW_PATTERNS,
        is_quoted, strip_quotes, contains_helm_template,
        is_int_bool_helm_template,
    )
except ImportError:
    from enum import Enum
    from dataclasses import field as dataclass_field
    
    class Severity(Enum):
        ERROR = "error"
    
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
        issues: List['QuoteIssue'] = dataclass_field(default_factory=list)
        error_count: int = 0
    
    PORT_STRING_FIELDS = {'name', 'protocol'}
    STRING_LIST_CONTEXTS = {'valueFiles', 'syncOptions', 'finalizers', 'goTemplateOptions'}
    
    HELM_CONTROL_FLOW_PATTERNS = [
        r'^\s*\{\{-?\s*if\s', r'^\s*\{\{-?\s*else\s*if\s',
        r'^\s*\{\{-?\s*else\s*-?\}\}', r'^\s*\{\{-?\s*end\s*-?\}\}',
        r'^\s*\{\{-?\s*range\s', r'^\s*\{\{-?\s*with\s',
        r'^\s*\{\{-?\s*define\s', r'^\s*\{\{-?\s*template\s',
        r'^\s*\{\{-?\s*include\s', r'^\s*\{\{-?\s*block\s',
        r'^\s*\{\{-?\s*/\*', r'^\s*\{\{-?\s*\$[a-zA-Z_][a-zA-Z0-9_]*\s*:=',
    ]
    
    HELM_INT_BOOL_PATTERNS = [
        r'\.replicas\b', r'\.replicaCount\b', r'\.port\b', r'\.targetPort\b',
        r'\.enabled\b', r'\.disabled\b', r'\|\s*int\b', r'\|\s*bool\b',
        r'\|\s*default\s+\d+', r'\|\s*default\s+(true|false)\b',
    ]
    
    def is_quoted(value: str) -> bool:
        v = value.strip()
        return (v.startswith('"') and v.endswith('"')) or \
               (v.startswith("'") and v.endswith("'"))
    
    def strip_quotes(value: str) -> str:
        v = value.strip()
        return v[1:-1] if is_quoted(v) else v
    
    def contains_helm_template(value: str) -> bool:
        return '{{' in value and '}}' in value
    
    def is_int_bool_helm_template(value: str) -> bool:
        for pattern in HELM_INT_BOOL_PATTERNS:
            if re.search(pattern, value):
                return True
        return False


# ============================================================================
# HARDCODED KEYS THAT MUST ALWAYS BE QUOTED
# ============================================================================

FORCED_QUOTE_KEYS = {
    'numberOfReplicas',
    'staleReplicaTimeout',
}


# ============================================================================
# TYPE DETECTION FUNCTIONS
# ============================================================================

def looks_like_integer(value: str) -> bool:
    """Check if YAML would parse this as integer."""
    v = value.strip()
    if not v:
        return False
    # Pure digits
    if v.isdigit():
        return True
    # Negative numbers
    if v.startswith('-') and len(v) > 1 and v[1:].isdigit():
        return True
    # Octal (0o755)
    if v.startswith('0o') and len(v) > 2:
        return True
    # Hex (0xFF)
    if v.startswith('0x') and len(v) > 2:
        return True
    return False


def looks_like_boolean(value: str) -> bool:
    """Check if YAML would parse this as boolean."""
    return value.strip().lower() in ('true', 'false', 'yes', 'no', 'on', 'off')


def looks_like_float(value: str) -> bool:
    """Check if YAML would parse this as float."""
    v = value.strip()
    if not v:
        return False
    # Special floats
    if v.lower() in ('.inf', '-.inf', '.nan'):
        return True
    # Scientific notation
    if 'e' in v.lower():
        try:
            float(v)
            return True
        except ValueError:
            return False
    # Decimal numbers (but not version strings like 1.2.3)
    if '.' in v:
        parts = v.split('.')
        if len(parts) == 2:  # Only one dot (e.g., 1.5)
            try:
                float(v)
                return True
            except ValueError:
                return False
    return False


def looks_like_null(value: str) -> bool:
    """Check if YAML would parse this as null."""
    return value.strip().lower() in ('null', '~')


def looks_like_date(value: str) -> bool:
    """Check if YAML would parse this as date/timestamp."""
    v = value.strip()
    # ISO date: 2024-01-21
    if re.match(r'^\d{4}-\d{2}-\d{2}$', v):
        return True
    # ISO datetime: 2024-01-21T10:00:00
    if re.match(r'^\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}', v):
        return True
    return False


def would_yaml_parse_as_non_string(value: str) -> tuple:
    """
    Check if YAML would parse this value as something other than string.
    
    Returns: (is_non_string, detected_type)
    """
    if not value or is_quoted(value):
        return (False, None)
    
    v = value.strip()
    
    if looks_like_boolean(v):
        return (True, 'boolean')
    if looks_like_integer(v):
        return (True, 'integer')
    if looks_like_float(v):
        return (True, 'float')
    if looks_like_null(v):
        return (True, 'null')
    if looks_like_date(v):
        return (True, 'date')
    
    return (False, None)


def is_string_value(value: str) -> bool:
    """Check if this is a plain string (not int/bool/float/null/date)."""
    if not value:
        return False
    if is_quoted(value):
        return True
    is_non_string, _ = would_yaml_parse_as_non_string(value)
    return not is_non_string


def strip_inline_comment(value: str) -> str:
    """
    Remove inline comment from value.
    
    YAML inline comments start with # and go to end of line.
    But # inside quotes or Helm templates is NOT a comment.
    
    Examples:
        "5        # comment" -> "5"
        "true  # is enabled" -> "true"
        '"quoted # not comment"' -> '"quoted # not comment"'
        "{{ .Values.x }}  # helm" -> "{{ .Values.x }}"
    """
    if not value:
        return value
    
    v = value.strip()
    
    # If value is quoted, return as-is (# inside quotes is not a comment)
    if (v.startswith('"') and v.endswith('"')) or \
       (v.startswith("'") and v.endswith("'")):
        return v
    
    # Handle Helm templates - find # that's OUTSIDE {{ }}
    if '{{' in v:
        # Track depth of {{ }}
        depth = 0
        i = 0
        while i < len(v):
            if v[i:i+2] == '{{':
                depth += 1
                i += 2
                continue
            elif v[i:i+2] == '}}':
                depth -= 1
                i += 2
                continue
            elif v[i] == '#' and depth == 0:
                # Found comment outside Helm template
                return v[:i].strip()
            i += 1
        return v
    
    # Simple case: find # and strip everything after
    if '#' in v:
        comment_pos = v.find('#')
        return v[:comment_pos].strip()
    
    return v


# ============================================================================
# TOP-LEVEL FIELDS (never quoted)
# ============================================================================

TOP_LEVEL_NO_QUOTE = {'apiVersion', 'kind'}


# ============================================================================
# BLOCK SCALAR DETECTION
# ============================================================================

# Pattern for block scalar indicators: | or > with optional chomping (+/-) and indent
BLOCK_SCALAR_PATTERN = re.compile(r'^[|>][-+]?\d*$')


def is_block_scalar_indicator(value: str) -> bool:
    """
    Check if value is a block scalar indicator.
    
    Valid indicators:
    - |      literal block scalar
    - |+     literal with keep chomping
    - |-     literal with strip chomping
    - |2     literal with explicit indent
    - |2+    literal with indent and chomping
    - >      folded block scalar
    - >+, >-, >2, etc.
    
    NOT a block scalar (Helm pipe):
    - {{ .Values.foo | default "bar" }}
    """
    v = value.strip()
    return bool(BLOCK_SCALAR_PATTERN.match(v))


# ============================================================================
# HELM DEFAULT VALIDATION
# ============================================================================

def validate_helm_default_quoting(value: str) -> Tuple[bool, Optional[str], Optional[str]]:
    """
    Validates Helm template default quoting rules:
    1. default values MUST be quoted: default "value"
    2. Outer quotes around {{ }} are FORBIDDEN when default is used
    
    Returns: (is_valid, error_message, suggestion)
    """
    if not contains_helm_template(value):
        return (True, None, None)
    
    # Check if template contains 'default'
    if 'default' not in value.lower():
        return (True, None, None)
    
    # Pattern to find Helm templates with their outer quotes
    # Matches: "{{ ... }}" or {{ ... }}
    helm_pattern = re.compile(r'^("?)\s*(\{\{-?\s*.*?\s*-?\}\})\s*("?)$')
    
    match = helm_pattern.match(value.strip())
    if not match:
        # Complex case - multiple templates or mixed content
        # Just check for default quoting inside
        return _check_default_value_quoting(value)
    
    outer_quote_start = match.group(1)
    template_content = match.group(2)
    outer_quote_end = match.group(3)
    
    has_outer_quotes = bool(outer_quote_start and outer_quote_end)
    
    # Extract content inside {{ }}
    inner_match = re.search(r'\{\{-?\s*(.*?)\s*-?\}\}', template_content)
    if not inner_match:
        return (True, None, None)
    
    inner_content = inner_match.group(1)
    
    # Check if default value is quoted
    default_quoted, unquoted_value = _is_default_value_quoted(inner_content)
    
    # Error 1: default value not quoted
    if not default_quoted and unquoted_value:
        fixed_inner = _fix_unquoted_default(inner_content, unquoted_value)
        fixed_template = template_content.replace(inner_content, fixed_inner)
        # Remove outer quotes if present
        suggestion = fixed_template
        return (False, 
                'Helm default value must be quoted: default "%s"' % unquoted_value,
                suggestion)
    
    # Error 2: outer quotes with quoted default
    if has_outer_quotes and default_quoted:
        # Remove outer quotes
        suggestion = template_content
        return (False,
                "Helm template with default must NOT have outer quotes",
                suggestion)
    
    return (True, None, None)


def _is_default_value_quoted(template_content: str) -> Tuple[bool, Optional[str]]:
    """
    Check if the default value in a Helm template is quoted.
    
    Returns: (is_quoted, unquoted_value_if_not_quoted)
    
    Patterns to check:
    - | default "value"  -> quoted
    - | default 'value'  -> quoted
    - | default value    -> NOT quoted, return "value"
    - default "value" .Values  -> quoted
    - default value .Values    -> NOT quoted, return "value"
    """
    content = template_content.strip()
    
    # Pattern 1: | default "value" or | default 'value' (quoted)
    if re.search(r'\|\s*default\s+["\']', content):
        return (True, None)
    
    # Pattern 2: default "value" .Values (at start, quoted)
    if re.search(r'^default\s+["\']', content):
        return (True, None)
    
    # Pattern 3: | default value (unquoted after pipe)
    unquoted_match = re.search(r'\|\s*default\s+([^"\'\s\|\}][^\s\|\}]*)', content)
    if unquoted_match:
        return (False, unquoted_match.group(1))
    
    # Pattern 4: default value .Values (unquoted at start)
    unquoted_match = re.search(r'^default\s+([^"\'\s\.][^\s]*)\s+\.', content)
    if unquoted_match:
        return (False, unquoted_match.group(1))
    
    # No default found or default has no value
    return (True, None)


def _fix_unquoted_default(template_content: str, unquoted_value: str) -> str:
    """Fixes unquoted default value by adding quotes around it."""
    # Escape the value for regex
    escaped_value = re.escape(unquoted_value)
    
    # Replace "default value" with "default "value""
    fixed = re.sub(
        r'(default\s+)' + escaped_value,
        r'\1"' + unquoted_value + '"',
        template_content
    )
    return fixed


def _check_default_value_quoting(value: str) -> Tuple[bool, Optional[str], Optional[str]]:
    """
    Check default quoting for complex/multi-template values.
    """
    # Find all default patterns
    # Unquoted: default value (not followed by quote)
    unquoted_pattern = re.compile(r'default\s+([^"\'\s\.\|\}][^\s\.\|\}]*)')
    
    for match in unquoted_pattern.finditer(value):
        potential_value = match.group(1)
        # Check it's not actually quoted (look ahead)
        start = match.start()
        before = value[:start]
        # Make sure this isn't inside quotes
        if before.count('"') % 2 == 0 and before.count("'") % 2 == 0:
            # Not inside quotes - this is an unquoted default
            suggestion = value.replace(
                'default ' + potential_value,
                'default "' + potential_value + '"'
            )
            # Also remove outer quotes if present
            if suggestion.startswith('"') and suggestion.endswith('"'):
                suggestion = suggestion[1:-1]
            return (False,
                    'Helm default value must be quoted: default "%s"' % potential_value,
                    suggestion)
    
    # Check for outer quotes with default
    if value.startswith('"') and value.endswith('"') and 'default' in value:
        # Has outer quotes - check if default inside is quoted
        inner = value[1:-1]
        if re.search(r'default\s+["\']', inner):
            # default is quoted, outer quotes are wrong
            return (False,
                    "Helm template with default must NOT have outer quotes",
                    inner)
    
    return (True, None, None)


# ============================================================================
# CONTEXT TRACKER
# ============================================================================

@dataclass
class ContextEntry:
    """Single entry in the context stack."""
    indent: int
    key: str


class ContextTracker:
    """Tracks YAML context by indent level."""
    
    def __init__(self):
        self.stack: List[ContextEntry] = []
    
    def update(self, line: str) -> List[str]:
        """Update context based on current line, return current path."""
        stripped = line.strip()
        
        if not stripped or stripped.startswith('#') or stripped == '---':
            return self.get_path()
        
        indent = len(line) - len(line.lstrip())
        
        self.stack = [e for e in self.stack if e.indent < indent]
        
        if ':' in stripped:
            temp_stripped = stripped.lstrip('- ')
            colon_pos = temp_stripped.find(':')
            if colon_pos > 0:
                key_part = temp_stripped[:colon_pos].strip()
                value_part = temp_stripped[colon_pos + 1:].strip()
                
                # Strip comment from value part for block scalar detection
                value_part_clean = strip_inline_comment(value_part)
                
                if not value_part_clean or is_block_scalar_indicator(value_part_clean):
                    self.stack.append(ContextEntry(indent=indent, key=key_part))
        
        return self.get_path()
    
    def reset(self):
        self.stack = []
    
    def get_path(self) -> List[str]:
        return [e.key for e in self.stack]
    
    def in_metadata(self) -> bool:
        """Check if we're anywhere inside metadata."""
        return 'metadata' in self.get_path()
    
    def parent_is(self, key: str) -> bool:
        path = self.get_path()
        return len(path) > 0 and path[-1] == key
    
    def contains(self, key: str) -> bool:
        return key in self.get_path()


# ============================================================================
# UNIFIED VALIDATOR
# ============================================================================

class UnifiedQuoteValidator:
    """
    Unified validator with context-based rules.
    
    Rules:
    1. apiVersion, kind -> NEVER quoted
    2. IN metadata -> int/bool MUST be quoted, strings DON'T need quotes
    3. OUTSIDE metadata -> int/bool must NOT be quoted, strings MUST be quoted
    4. Block scalar content (| or >) is SKIPPED entirely
    5. Inline comments are stripped before type detection
    6. Helm default values MUST be quoted, outer quotes FORBIDDEN
    7. Hardcoded keys (numberOfReplicas, staleReplicaTimeout) MUST always be quoted
    """
    
    def __init__(self, strict: bool = False, type_map: Dict[str, str] = None):
        self.strict = strict
        self.type_map = type_map or {}
        self.issues: List[QuoteIssue] = []
        self.context = ContextTracker()
        # Block scalar tracking
        self.in_block_scalar = False
        self.block_scalar_base_indent: int = -1
    
    def validate_file(self, file_path: str) -> ValidationResult:
        try:
            content = Path(file_path).read_text(encoding='utf-8')
            return self.validate_content(content, file_path)
        except Exception as e:
            return ValidationResult(
                file_path=file_path, is_valid=False,
                issues=[QuoteIssue(0, "", IssueType.PATH_NOT_QUOTED,
                                   "", "Cannot read file: %s" % e, "")],
                error_count=1
            )
    
    def validate_content(self, content: str, file_path: str = "<string>") -> ValidationResult:
        self.issues = []
        self.context = ContextTracker()
        self.in_block_scalar = False
        self.block_scalar_base_indent = -1
        
        lines = content.split('\n')
        has_helm = '{{' in content
        
        for line_num, line in enumerate(lines, 1):
            stripped = line.strip()
            
            # Calculate current indent (0 for empty lines)
            if stripped:
                current_indent = len(line) - len(line.lstrip())
            else:
                # Empty line - continue (doesn't end block scalar)
                continue
            
            # Skip comments
            if stripped.startswith('#'):
                continue
            
            # Handle document separator - reset everything
            if stripped == '---':
                self.context.reset()
                self.in_block_scalar = False
                self.block_scalar_base_indent = -1
                continue
            
            # Check if we're inside a block scalar
            if self.in_block_scalar:
                # If indent is greater than base, still in block scalar
                if current_indent > self.block_scalar_base_indent:
                    # Skip this line - it's block scalar content
                    continue
                else:
                    # Indent is same or less - block scalar has ended
                    self.in_block_scalar = False
                    self.block_scalar_base_indent = -1
                    # Continue processing this line normally
            
            # Check if this line STARTS a block scalar
            if self._line_starts_block_scalar(stripped):
                self.in_block_scalar = True
                self.block_scalar_base_indent = current_indent
                # Update context for the key, but don't validate the content
                self.context.update(line)
                continue
            
            # Skip Helm control-flow lines
            if has_helm and self._is_helm_control_flow(stripped):
                continue
            
            # Update context
            self.context.update(line)
            
            # Validate the line
            self._validate_line(line_num, line, stripped, has_helm)
        
        return ValidationResult(
            file_path=file_path,
            is_valid=len(self.issues) == 0,
            issues=self.issues,
            error_count=len(self.issues)
        )
    
    def _line_starts_block_scalar(self, stripped: str) -> bool:
        """
        Check if this line starts a block scalar.
        
        Examples that START block scalar:
          key: |
          key: |+
          key: |-
          key: >
          key: >2
          data: |
        
        Examples that are NOT block scalar (Helm pipe):
          name: {{ .Values.name | default "foo" }}
          value: {{ .Values.x | quote }}
        """
        if ':' not in stripped:
            return False
        
        colon_pos = stripped.find(':')
        if colon_pos < 0:
            return False
        
        value_part = stripped[colon_pos + 1:].strip()
        
        # Empty value is not a block scalar (just a mapping key)
        if not value_part:
            return False
        
        # Strip inline comment before checking
        value_part_clean = strip_inline_comment(value_part)
        
        if not value_part_clean:
            return False
        
        # Check if it's a block scalar indicator
        return is_block_scalar_indicator(value_part_clean)
    
    def _is_helm_control_flow(self, line: str) -> bool:
        for pattern in HELM_CONTROL_FLOW_PATTERNS:
            if re.match(pattern, line):
                return True
        return False
    
    def _validate_line(self, line_num: int, line: str, stripped: str, has_helm: bool):
        """Validate a single line."""
        
        # List items without key: value
        if stripped.startswith('- ') and ':' not in stripped:
            self._validate_list_item(line_num, line, stripped, has_helm)
            return
        
        # List items with key: value
        if stripped.startswith('- ') and ':' in stripped:
            kv_part = stripped[2:].strip()
            colon_pos = kv_part.find(':')
            key = kv_part[:colon_pos].strip()
            value = kv_part[colon_pos + 1:].strip()
            
            # Strip inline comment
            value_clean = strip_inline_comment(value)
            
            if value_clean and not is_block_scalar_indicator(value_clean):
                self._validate_key_value(line_num, line, key, value_clean, has_helm)
            return
        
        # Regular key: value
        if ':' not in stripped:
            return
        
        colon_pos = stripped.find(':')
        key = stripped[:colon_pos].strip()
        value = stripped[colon_pos + 1:].strip()
        
        # Strip inline comment
        value_clean = strip_inline_comment(value)
        
        # Skip if no value or if it's a block scalar indicator
        if not value_clean or is_block_scalar_indicator(value_clean):
            return
        
        self._validate_key_value(line_num, line, key, value_clean, has_helm)
    
    def _validate_key_value(self, line_num: int, line: str, key: str, value: str, has_helm: bool):
        """Validate a key: value pair."""
        
        context_path = self.context.get_path()
        field_path = '.'.join(context_path + [key]) if context_path else key
        
        in_metadata = self.context.in_metadata()
        
        # ================================================================
        # RULE 1: Top-level apiVersion, kind -> NEVER quoted
        # ================================================================
        if not context_path and key in TOP_LEVEL_NO_QUOTE:
            if is_quoted(value):
                self._add_issue(line_num, line, IssueType.TOP_LEVEL_QUOTED,
                    key, "'%s' must not be quoted" % key,
                    '%s: %s' % (key, strip_quotes(value)))
            return
        
        # ================================================================
        # RULE 7: Hardcoded keys that MUST always be quoted
        # ================================================================
        if key in FORCED_QUOTE_KEYS:
            if not is_quoted(value):
                # Get the inner value for suggestion
                inner_value = value
                if contains_helm_template(value):
                    # For Helm templates, just wrap in quotes
                    suggestion_value = '"%s"' % value
                else:
                    suggestion_value = '"%s"' % value
                self._add_issue(line_num, line, IssueType.FORCED_QUOTE_KEY_NOT_QUOTED,
                    field_path, 
                    "Key '%s' must always have quoted value" % key,
                    '%s: %s' % (key, suggestion_value))
            return  # Don't apply other rules for forced quote keys
        
        # ================================================================
        # RULE 6: Helm default quoting (check BEFORE other Helm rules)
        # ================================================================
        if has_helm and contains_helm_template(value) and 'default' in value.lower():
            is_valid, error_msg, suggestion = validate_helm_default_quoting(value)
            if not is_valid:
                issue_type = IssueType.HELM_DEFAULT_NOT_QUOTED if 'must be quoted' in error_msg \
                             else IssueType.HELM_DEFAULT_OUTER_QUOTES
                self._add_issue(line_num, line, issue_type,
                    field_path, error_msg, '%s: %s' % (key, suggestion))
                return  # Don't apply other rules if default rule triggered
        
        # ================================================================
        # RULE 2: Inside metadata -> int/bool MUST be quoted, strings OK without
        # ================================================================
        if in_metadata:
            # Skip Helm templates (without default - already handled above)
            if contains_helm_template(value):
                self._validate_helm_in_metadata(line_num, line, key, value, field_path)
                return
            
            # Check if value would parse as non-string (int/bool/etc)
            is_non_string, detected_type = would_yaml_parse_as_non_string(value)
            
            if is_non_string:
                # Non-string in metadata MUST be quoted
                self._add_issue(line_num, line, IssueType.METADATA_VALUE_NOT_QUOTED,
                    field_path, 
                    "Value '%s' would be parsed as %s, must be quoted" % (value, detected_type),
                    '%s: "%s"' % (key, value))
            
            # Strings in metadata don't need quotes - no error
            return
        
        # ================================================================
        # RULE 3: Outside metadata
        # ================================================================
        
        # Handle Helm templates first (without default - already handled above)
        if has_helm and contains_helm_template(value):
            self._validate_helm_template(line_num, line, key, value, field_path)
            return
        
        # Check what type the value is
        is_non_string, detected_type = would_yaml_parse_as_non_string(value)
        
        if is_quoted(value):
            # Value is quoted - check if it SHOULD be quoted
            inner = strip_quotes(value)
            inner_non_string, inner_type = would_yaml_parse_as_non_string(inner)
            
            if inner_non_string and inner_type in ('integer', 'boolean'):
                # Quoted int/bool outside metadata = ERROR
                issue_type = IssueType.INTEGER_FIELD_QUOTED if inner_type == 'integer' \
                             else IssueType.BOOLEAN_AS_STRING
                self._add_issue(line_num, line, issue_type,
                    field_path, "%s value must not be quoted" % inner_type.title(),
                    '%s: %s' % (key, inner))
            # Quoted string = OK
        else:
            # Value is NOT quoted
            if is_non_string:
                # Non-string without quotes outside metadata = OK (int/bool)
                pass
            else:
                # String without quotes outside metadata = ERROR
                self._add_issue(line_num, line, IssueType.STRING_VALUE_NOT_QUOTED,
                    field_path, "String value must be quoted",
                    '%s: "%s"' % (key, value))
    
    def _validate_list_item(self, line_num: int, line: str, stripped: str, has_helm: bool):
        """Validate pure list items."""
        value = stripped[2:].strip()
        
        if not value:
            return
        
        # Strip inline comment
        value_clean = strip_inline_comment(value)
        
        if not value_clean:
            return
        
        context_path = self.context.get_path()
        parent = context_path[-1] if context_path else ''
        in_metadata = self.context.in_metadata()
        
        # Check Helm default quoting first
        if has_helm and contains_helm_template(value_clean) and 'default' in value_clean.lower():
            is_valid, error_msg, suggestion = validate_helm_default_quoting(value_clean)
            if not is_valid:
                issue_type = IssueType.HELM_DEFAULT_NOT_QUOTED if 'must be quoted' in error_msg \
                             else IssueType.HELM_DEFAULT_OUTER_QUOTES
                self._add_issue(line_num, line, issue_type,
                    '%s[]' % parent, error_msg, '- %s' % suggestion)
                return
        
        # Handle Helm templates
        if has_helm and contains_helm_template(value_clean):
            if in_metadata:
                # In metadata, Helm templates that output int/bool must be quoted
                if is_int_bool_helm_template(value_clean) and not is_quoted(value_clean):
                    self._add_issue(line_num, line, IssueType.HELM_TEMPLATE_STRING_NOT_QUOTED,
                        '%s[]' % parent, 
                        "Helm template in metadata that may output int/bool must be quoted",
                        '- "%s"' % value_clean)
            else:
                # Outside metadata, string Helm templates must be quoted
                if not is_int_bool_helm_template(value_clean) and not is_quoted(value_clean):
                    self._add_issue(line_num, line, IssueType.HELM_TEMPLATE_STRING_NOT_QUOTED,
                        '%s[]' % parent, "Helm template string must be quoted",
                        '- "%s"' % value_clean)
            return
        
        # Check value type
        is_non_string, detected_type = would_yaml_parse_as_non_string(value_clean)
        
        if in_metadata:
            # In metadata: int/bool must be quoted, strings OK without
            if is_non_string:
                self._add_issue(line_num, line, IssueType.METADATA_VALUE_NOT_QUOTED,
                    '%s[]' % parent, 
                    "Value '%s' would be parsed as %s, must be quoted" % (value_clean, detected_type),
                    '- "%s"' % value_clean)
        else:
            # Outside metadata: strings MUST be quoted
            if not is_non_string and not is_quoted(value_clean):
                self._add_issue(line_num, line, IssueType.STRING_VALUE_NOT_QUOTED,
                    '%s[]' % parent, "String value must be quoted",
                    '- "%s"' % value_clean)
    
    def _validate_helm_in_metadata(self, line_num: int, line: str, key: str, 
                                    value: str, field_path: str):
        """Validate Helm templates inside metadata."""
        is_int_bool = is_int_bool_helm_template(value)
        
        # In metadata, if Helm template could output int/bool, must be quoted
        if is_int_bool and not is_quoted(value):
            self._add_issue(line_num, line, IssueType.HELM_TEMPLATE_STRING_NOT_QUOTED,
                field_path, 
                "Helm template in metadata that may output int/bool must be quoted",
                '%s: "%s"' % (key, value))
    
    def _validate_helm_template(self, line_num: int, line: str, key: str,
                                 value: str, field_path: str):
        """Validate Helm template quoting outside metadata."""
        quoted = is_quoted(value)
        is_int_bool = is_int_bool_helm_template(value)
        
        if is_int_bool:
            # Int/bool Helm template should NOT be quoted
            if quoted:
                self._add_issue(line_num, line, IssueType.HELM_TEMPLATE_INT_QUOTED,
                    field_path, "Helm template for Integer/Boolean must not be quoted",
                    '%s: %s' % (key, strip_quotes(value)))
        else:
            # String Helm template MUST be quoted
            if not quoted:
                self._add_issue(line_num, line, IssueType.HELM_TEMPLATE_STRING_NOT_QUOTED,
                    field_path, "Helm template string must be quoted",
                    '%s: "%s"' % (key, value))
    
    def _add_issue(self, line_num: int, line: str, issue_type: IssueType,
                   field_path: str, message: str, suggestion: str):
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
    import argparse
    
    parser = argparse.ArgumentParser(description='Unified Quote Validator')
    parser.add_argument('files', nargs='+', help='YAML files to validate')
    parser.add_argument('-v', '--verbose', action='store_true')
    parser.add_argument('--strict', action='store_true')
    parser.add_argument('--test-helm-default', action='store_true',
                        help='Run Helm default quoting tests')
    
    args = parser.parse_args()
    
    # Run tests if requested
    if args.test_helm_default:
        _run_helm_default_tests()
        return
    
    exit_code = 0
    validator = UnifiedQuoteValidator(strict=args.strict)
    
    for filepath in args.files:
        result = validator.validate_file(filepath)
        
        if not result.is_valid:
            exit_code = 1
        
        if result.issues or args.verbose:
            print("")
            print("=" * 60)
            print("File: %s" % filepath)
            print("=" * 60)
            
            for issue in result.issues:
                print("[ERROR] Line %d: %s" % (issue.line_number, issue.message))
                print("   PATH:     %s" % issue.field_path)
                print("   CURRENT:  %s" % issue.line_content.strip())
                print("   EXPECTED: %s" % issue.suggestion)
                print("")
            
            if not result.issues:
                print("[OK] No issues found")
                print("")
            else:
                print("Summary: %d error(s)" % result.error_count)
                print("")
    
    sys.exit(exit_code)


def _run_helm_default_tests():
    """Run tests for Helm default quoting rules."""
    test_cases = [
        # (value, should_be_valid, description)
        # CORRECT - default quoted, no outer quotes
        ('{{ .Values.x | default "720h" }}', True, "default quoted, no outer quotes"),
        ('{{ default "384" .Values.x | quote }}', True, "default at start, quoted"),
        ('{{ .Values.vault.clusterIssuer | default "vault-issuer" }}', True, "string default"),
        ("{{ .Values.x | default 'value' }}", True, "single quotes OK"),
        
        # WRONG - default not quoted
        ('{{ .Values.x | default 720h }}', False, "default unquoted (after pipe)"),
        ('{{ default 384 .Values.x | quote }}', False, "default at start, unquoted"),
        ('{{ .Values.x | default vault-issuer }}', False, "string default unquoted"),
        
        # WRONG - outer quotes with quoted default
        ('"{{ .Values.x | default "720h" }}"', False, "double quoted - outer + inner"),
        ('"{{ default "384" .Values.x }}"', False, "double quoted at start"),
    ]
    
    print("Testing Helm default quoting rules:")
    print("")
    print("=" * 70)
    
    passed = 0
    failed = 0
    
    for value, should_be_valid, description in test_cases:
        is_valid, error_msg, suggestion = validate_helm_default_quoting(value)
        
        test_passed = is_valid == should_be_valid
        
        if test_passed:
            passed += 1
            status = "[PASS]"
        else:
            failed += 1
            status = "[FAIL]"
        
        print("%s %s" % (status, description))
        print("   Input:    %s" % value)
        print("   Expected: %s" % ('VALID' if should_be_valid else 'INVALID'))
        print("   Got:      %s" % ('VALID' if is_valid else 'INVALID'))
        if error_msg:
            print("   Error:    %s" % error_msg)
        if suggestion:
            print("   Suggest:  %s" % suggestion)
        print("")
    
    print("=" * 70)
    print("Results: %d passed, %d failed" % (passed, failed))
    
    sys.exit(0 if failed == 0 else 1)


if __name__ == '__main__':
    main()