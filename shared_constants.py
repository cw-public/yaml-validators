#!/usr/bin/env python3
# filepath: c:\Users\ahryhory\Documents\Git-repos\yaml-validators\shared_constants.py
"""
Shared Constants - Central definitions for all validators.

This module contains:
- Enums (Severity, IssueType)
- Data classes (QuoteIssue, ValidationResult)
- Field definitions (Integer, Boolean, String fields)
- Utility functions

Note: With indent-based traversal, we NO LONGER need exhaustive context key lists.
We only need to know WHICH contexts trigger WHICH rules.
"""

import re
from enum import Enum
from dataclasses import dataclass, field
from typing import List


# ============================================================================
# ENUMS
# ============================================================================

class Severity(Enum):
    """Validation severity levels."""
    ERROR = "error"


class IssueType(Enum):
    """Types of quoting issues."""
    # Boolean/Type errors
    BOOLEAN_AS_STRING = "boolean_as_string"
    INTEGER_FIELD_QUOTED = "integer_field_quoted"
    
    # Annotation errors
    ANNOTATION_INT_NOT_QUOTED = "annotation_int_not_quoted"
    ANNOTATION_SPECIAL_CHAR_NOT_QUOTED = "annotation_special_char_not_quoted"
    
    # Label errors
    LABEL_VALUE_NOT_QUOTED = "label_value_not_quoted"
    
    # Helm/Go-Template errors
    HELM_TEMPLATE_INT_QUOTED = "helm_template_int_quoted"
    HELM_TEMPLATE_STRING_NOT_QUOTED = "helm_template_string_not_quoted"
    GO_TEMPLATE_OPTIONS_NOT_QUOTED = "go_template_options_not_quoted"
    
    # Quoting style errors
    TOP_LEVEL_QUOTED = "top_level_quoted"
    METADATA_QUOTED = "metadata_quoted"
    PATH_NOT_QUOTED = "path_not_quoted"
    URL_NOT_QUOTED = "url_not_quoted"
    PORT_STRING_NOT_QUOTED = "port_string_not_quoted"
    STRING_VALUE_NOT_QUOTED = "string_value_not_quoted"
    
    # Helm control-flow errors
    IF_EXPRESSION_QUOTED = "if_expression_quoted"
    RANGE_EXPRESSION_QUOTED = "range_expression_quoted"
    STRING_LITERAL_NOT_QUOTED = "string_literal_not_quoted"
    
    # Helm pipe function errors
    DEFAULT_STRING_NOT_QUOTED = "default_string_not_quoted"
    TERNARY_STRING_NOT_QUOTED = "ternary_string_not_quoted"
    REPLACE_PARAM_NOT_QUOTED = "replace_param_not_quoted"


# ============================================================================
# DATA CLASSES
# ============================================================================

@dataclass
class QuoteIssue:
    """Represents a quoting issue."""
    line_number: int
    line_content: str
    issue_type: IssueType
    field_path: str
    message: str
    suggestion: str
    severity: Severity = Severity.ERROR


@dataclass
class ValidationResult:
    """Result of validation."""
    file_path: str
    is_valid: bool
    issues: List[QuoteIssue] = field(default_factory=list)
    error_count: int = 0


# ============================================================================
# HELM TEMPLATE DETECTION PATTERNS
# ============================================================================

HELM_DETECTION_PATTERNS = [
    r'\{\{\s*\.Values\.',
    r'\{\{\s*\.Release\.',
    r'\{\{\s*\.Chart\.',
    r'\{\{\s*\.Capabilities\.',
    r'\{\{\s*\.Files\.',
    r'\{\{\s*\.Template\.',
    r'\{\{-?\s*if\s',
    r'\{\{-?\s*else\s',
    r'\{\{-?\s*end\s*-?\}\}',
    r'\{\{-?\s*range\s',
    r'\{\{-?\s*include\s',
    r'\{\{-?\s*define\s',
    r'\{\{-?\s*template\s',
    r'\{\{-?\s*with\s',
    r'\{\{-?\s*\$\w+\s*:=',
]

HELM_CONTROL_FLOW_PATTERNS = [
    r'^\s*\{\{-?\s*if\s',
    r'^\s*\{\{-?\s*else\s*if\s',
    r'^\s*\{\{-?\s*else\s*-?\}\}',
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

HELM_INT_BOOL_PATTERNS = [
    r'\.replicas\b', r'\.replicaCount\b',
    r'\.port\b', r'\.targetPort\b', r'\.nodePort\b', r'\.containerPort\b',
    r'\.enabled\b', r'\.disabled\b',
    r'\.count\b', r'\.limit\b', r'\.factor\b',
    r'\.minReplicas\b', r'\.maxReplicas\b',
    r'\.retries\b', r'\.timeout\b',
    r'\.terminationGracePeriodSeconds\b',
    r'\|\s*int\b', r'\|\s*bool\b', r'\|\s*default\s+\d+',
    r'\|\s*default\s+(true|false)\b',
]


# ============================================================================
# KUBERNETES FIELD DEFINITIONS
# ============================================================================

# Integer fields - must NEVER be quoted
INTEGER_FIELDS = {
    'replicas', 'minReplicas', 'maxReplicas', 'replicaCount',
    'port', 'targetPort', 'nodePort', 'containerPort', 'hostPort',
    'initialDelaySeconds', 'periodSeconds', 'timeoutSeconds',
    'successThreshold', 'failureThreshold', 'terminationGracePeriodSeconds',
    'revisionHistoryLimit', 'progressDeadlineSeconds', 'minReadySeconds',
    'backoffLimit', 'completions', 'parallelism', 'activeDeadlineSeconds',
}

# Boolean fields - must NOT be quoted as string
BOOLEAN_FIELDS = {
    'enabled', 'disabled', 'prune', 'selfHeal', 'automated',
    'tls', 'hostNetwork', 'hostPID', 'hostIPC', 'privileged',
    'readOnlyRootFilesystem', 'runAsNonRoot', 'allowPrivilegeEscalation',
    'goTemplate', 'stdin', 'stdinOnce', 'tty',
}

# String fields that SHOULD be quoted (paths, URLs, etc.)
STRING_FIELDS_REQUIRE_QUOTE = {
    'path', 'repoURL', 'revision', 'targetRevision', 'chart',
    'ref', 'url', 'image', 'repository', 'tag', 'project',
}

# Port object string fields
PORT_STRING_FIELDS = {'name', 'protocol'}

# String list contexts - lists where ALL items should be quoted
STRING_LIST_CONTEXTS = {
    'valueFiles',
    'syncOptions',
    'finalizers',
    'goTemplateOptions',
}

# Contexts where values MUST be quoted (labels, annotations)
QUOTED_VALUE_CONTEXTS = {
    'labels',
    'matchLabels',
    'annotations',
}


# ============================================================================
# HELM PIPE FUNCTIONS
# ============================================================================

HELM_STRING_PIPE_FUNCTIONS = [
    'upper', 'lower', 'title', 'trim', 'trimAll', 'trimPrefix', 'trimSuffix',
    'replace', 'quote', 'squote', 'nospace', 'indent', 'nindent',
    'b64enc', 'b64dec', 'sha256sum', 'sha1sum', 'md5sum',
    'toString', 'toJson', 'toPrettyJson', 'toYaml', 'toRawJson',
    'printf', 'print', 'println', 'substr', 'trunc', 'abbrev',
    'cat', 'wrap', 'wrapWith', 'repeat', 'join', 'sortAlpha',
]

HELM_NUMERIC_PIPE_FUNCTIONS = [
    'int', 'int64', 'float64', 'len', 'add', 'sub', 'mul', 'div',
    'mod', 'max', 'min', 'floor', 'ceil', 'round', 'atoi',
]

HELM_BOOLEAN_PIPE_FUNCTIONS = [
    'empty', 'not', 'and', 'or', 'eq', 'ne', 'lt', 'le', 'gt', 'ge',
    'contains', 'hasPrefix', 'hasSuffix', 'hasKey', 'kindIs', 'typeIs',
]


# ============================================================================
# ANSIBLE DETECTION
# ============================================================================

ANSIBLE_KEYWORDS = [
    'hosts', 'tasks', 'roles', 'handlers', 'vars', 'become',
    'gather_facts', 'pre_tasks', 'post_tasks', 'block', 'rescue', 'always',
]

ANSIBLE_MODULES = [
    'uri', 'debug', 'shell', 'command', 'copy', 'file',
    'template', 'apt', 'yum', 'pip', 'git', 'service',
    'systemd', 'set_fact', 'include', 'include_tasks',
    'import_tasks', 'include_role', 'import_role',
    'ansible.builtin.', 'community.', 'amazon.aws.',
]

ANSIBLE_DIRECTORIES = [
    '/playbooks/', '/roles/', '/tasks/', '/handlers/',
    '/vars/', '/defaults/', '/group_vars/', '/host_vars/',
]


# ============================================================================
# UTILITY FUNCTIONS
# ============================================================================

def is_quoted(value: str) -> bool:
    """Check if a value is quoted (single or double quotes)."""
    v = value.strip()
    return (v.startswith('"') and v.endswith('"')) or \
           (v.startswith("'") and v.endswith("'"))


def strip_quotes(value: str) -> str:
    """Remove quotes from value."""
    v = value.strip()
    if is_quoted(v):
        return v[1:-1]
    return v


def contains_helm_template(value: str) -> bool:
    """Check if value contains {{ }}."""
    return '{{' in value and '}}' in value


def is_helm_template_content(content: str) -> bool:
    """Check if content contains Helm template patterns."""
    for pattern in HELM_DETECTION_PATTERNS:
        if re.search(pattern, content):
            return True
    return False


def is_int_bool_helm_template(value: str) -> bool:
    """Check if Helm template produces int/bool."""
    for pattern in HELM_INT_BOOL_PATTERNS:
        if re.search(pattern, value):
            return True
    return False


def looks_like_integer(value: str) -> bool:
    """Check if value looks like an integer."""
    v = value.strip()
    if v.isdigit():
        return True
    if v.startswith('-') and len(v) > 1 and v[1:].isdigit():
        return True
    return False


def looks_like_boolean(value: str) -> bool:
    """Check if value looks like a boolean."""
    return value.strip().lower() in ('true', 'false')