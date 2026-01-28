#!/usr/bin/env python3
"""
Shared Constants - Central definitions for all validators.

This module contains:
- Enums (Severity, IssueType, ErrorType)
- Regex patterns for detection
- Kubernetes field definitions
- Helm function lists
- Utility functions

ALL validators should import from here - no duplicate definitions!
"""

import re
from enum import Enum
from dataclasses import dataclass, field
from typing import List, Optional


# ============================================================================
# ENUMS
# ============================================================================

class Severity(Enum):
    """Validation severity levels."""
    ERROR = "error"      # Breaking issues - MUST be fixed
    WARNING = "warning"  # Best practice - SHOULD be fixed
    INFO = "info"        # Optional - CAN be fixed


class IssueType(Enum):
    """Types of quoting issues (used by kubernetes_validator)."""
    # ERROR Level
    BOOLEAN_AS_STRING = "boolean_as_string"
    HELM_TEMPLATE_INT_QUOTED = "helm_template_int_quoted"
    ANNOTATION_INT_NOT_QUOTED = "annotation_int_not_quoted"
    GO_TEMPLATE_OPTIONS_NOT_QUOTED = "go_template_options_not_quoted"
    INTEGER_FIELD_QUOTED = "integer_field_quoted"
    
    # WARNING Level
    TOP_LEVEL_QUOTED = "top_level_quoted"
    METADATA_QUOTED = "metadata_quoted"
    PATH_NOT_QUOTED = "path_not_quoted"
    URL_NOT_QUOTED = "url_not_quoted"
    PORT_STRING_NOT_QUOTED = "port_string_not_quoted"
    HELM_TEMPLATE_STRING_NOT_QUOTED = "helm_template_string_not_quoted"
    ANNOTATION_SPECIAL_CHAR_NOT_QUOTED = "annotation_special_char_not_quoted"


class ErrorType(Enum):
    """Specific error types for Helm validation."""
    # Control-flow errors
    IF_EXPRESSION_QUOTED = "if_expression_quoted"
    RANGE_EXPRESSION_QUOTED = "range_expression_quoted"
    WITH_EXPRESSION_QUOTED = "with_expression_quoted"
    VARIABLE_ASSIGNMENT_QUOTED = "variable_assignment_quoted"
    
    # Comparison errors
    STRING_LITERAL_NOT_QUOTED = "string_literal_not_quoted"
    NUMERIC_LITERAL_QUOTED = "numeric_literal_quoted"
    
    # Output errors
    STRING_OUTPUT_NOT_QUOTED = "string_output_not_quoted"
    NUMERIC_OUTPUT_QUOTED = "numeric_output_quoted"
    BOOLEAN_OUTPUT_QUOTED = "boolean_output_quoted"
    
    # Pipe function errors
    DEFAULT_STRING_NOT_QUOTED = "default_string_not_quoted"
    DEFAULT_NUMERIC_QUOTED = "default_numeric_quoted"
    TERNARY_STRING_NOT_QUOTED = "ternary_string_not_quoted"
    REPLACE_PARAM_NOT_QUOTED = "replace_param_not_quoted"
    
    # General
    GENERIC_QUOTING_ERROR = "generic_quoting_error"


# ============================================================================
# DATA CLASSES
# ============================================================================

@dataclass
class QuoteIssue:
    """Represents a quoting issue (used by kubernetes_validator)."""
    line_number: int
    line_content: str
    issue_type: IssueType
    field_path: str
    message: str
    suggestion: str
    severity: Severity


@dataclass
class ValidationError:
    """Represents a validation error (used by helm_validator)."""
    line_num: int
    message: str
    actual: str
    expected: str
    severity: Severity = Severity.WARNING
    error_type: ErrorType = ErrorType.GENERIC_QUOTING_ERROR
    
    def __str__(self) -> str:
        return f"Line {self.line_num}: {self.message}"


@dataclass
class ValidationResult:
    """Result of validation."""
    file_path: str
    is_valid: bool
    issues: List[QuoteIssue] = field(default_factory=list)
    errors: int = 0
    warnings: int = 0
    infos: int = 0


# ============================================================================
# HELM TEMPLATE DETECTION PATTERNS (Single Source of Truth)
# ============================================================================

# Patterns to detect if a file is a Helm template
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

# Control-flow patterns (lines to skip for output validation)
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

# Patterns to identify Integer/Boolean Helm templates
HELM_INT_BOOL_PATTERNS = [
    r'\.replicas\b', r'\.replicaCount\b',
    r'\.port\b', r'\.targetPort\b', r'\.nodePort\b', r'\.containerPort\b',
    r'\.enabled\b', r'\.disabled\b',
    r'\.count\b', r'\.limit\b', r'\.factor\b',
    r'\.minReplicas\b', r'\.maxReplicas\b',
    r'\.retries\b', r'\.timeout\b',
    r'\.terminationGracePeriodSeconds\b',
    r'\|\s*int\b', r'\|\s*bool\b', r'\|\s*default\s+\d+',
]


# ============================================================================
# KUBERNETES FIELD DEFINITIONS
# ============================================================================

# Top-level fields that should NOT be quoted
K8S_TOP_LEVEL_NO_QUOTE = {'apiVersion', 'kind'}

# Metadata fields that should NOT be quoted
K8S_METADATA_NO_QUOTE = {'name', 'namespace'}

# Integer fields that must NEVER be quoted
K8S_INTEGER_FIELDS = {
    # Replica/scaling
    'replicas', 'minReplicas', 'maxReplicas', 'replicaCount',
    # Ports
    'port', 'targetPort', 'nodePort', 'containerPort', 'hostPort',
    # Probes
    'initialDelaySeconds', 'periodSeconds', 'timeoutSeconds',
    'successThreshold', 'failureThreshold',
    # Other
    'terminationGracePeriodSeconds', 'revisionHistoryLimit',
    'progressDeadlineSeconds', 'minReadySeconds', 'backoffLimit',
    'completions', 'parallelism', 'activeDeadlineSeconds',
    'limit', 'factor', 'retries', 'revision',
}

# Boolean fields
K8S_BOOLEAN_FIELDS = {
    'enabled', 'disabled', 'tls', 'hostNetwork', 'hostPID', 'hostIPC',
    'privileged', 'readOnlyRootFilesystem', 'runAsNonRoot',
    'allowPrivilegeEscalation', 'stdin', 'stdinOnce', 'tty',
}

# String fields that SHOULD be quoted
K8S_STRING_FIELDS = {
    'name', 'namespace', 'image', 'imagePullPolicy', 'restartPolicy',
    'serviceAccountName', 'schedulerName', 'hostname', 'subdomain',
    'nodeName', 'priorityClassName', 'runtimeClassName',
}

# String fields that SHOULD be quoted (paths, URLs, etc.)
K8S_STRING_FIELDS_REQUIRE_QUOTE = {
    'path', 'repoURL', 'revision', 'targetRevision', 'chart',
    'ref', 'url', 'image', 'repository', 'tag',
}

# Port object string fields
K8S_PORT_STRING_FIELDS = {'name', 'protocol'}

# Annotation keys with numeric values that must be quoted
K8S_ANNOTATION_NUMERIC_KEYS = {
    'argocd.argoproj.io/sync-wave',
    'helm.sh/hook-weight',
    'prometheus.io/port',
}

# Context keys for parsing
K8S_CONTEXT_KEYS = {
    'metadata', 'annotations', 'labels', 'spec', 'template',
    'generators', 'sources', 'destination', 'syncPolicy', 'ports',
    'env', 'containers', 'volumes', 'goTemplateOptions', 'helm',
    'valueFiles', 'data', 'stringData', 'rules', 'paths',
}


# ============================================================================
# HELM PIPE FUNCTIONS
# ============================================================================

# Functions that produce string output
HELM_STRING_PIPE_FUNCTIONS = [
    'upper', 'lower', 'title', 'trim', 'trimAll', 'trimPrefix', 'trimSuffix',
    'replace', 'quote', 'squote', 'nospace', 'indent', 'nindent',
    'b64enc', 'b64dec', 'sha256sum', 'sha1sum', 'md5sum',
    'toString', 'toJson', 'toPrettyJson', 'toYaml', 'toRawJson',
    'printf', 'print', 'println', 'substr', 'trunc', 'abbrev',
    'cat', 'wrap', 'wrapWith', 'repeat', 'join', 'sortAlpha',
]

# Functions that produce numeric output
HELM_NUMERIC_PIPE_FUNCTIONS = [
    'int', 'int64', 'float64', 'len', 'add', 'sub', 'mul', 'div',
    'mod', 'max', 'min', 'floor', 'ceil', 'round', 'atoi',
]

# Functions that produce boolean output
HELM_BOOLEAN_PIPE_FUNCTIONS = [
    'empty', 'not', 'and', 'or', 'eq', 'ne', 'lt', 'le', 'gt', 'ge',
    'contains', 'hasPrefix', 'hasSuffix', 'hasKey', 'kindIs', 'typeIs',
]

# Functions with literal parameters that need quoting
HELM_FUNCTIONS_WITH_LITERAL_PARAMS = [
    'replace', 'default', 'ternary', 'coalesce', 'required',
    'trimPrefix', 'trimSuffix', 'trimAll', 'hasPrefix', 'hasSuffix',
    'printf', 'split', 'splitList', 'join', 'lookup',
]

# Comparison functions
HELM_COMPARISON_FUNCTIONS = ['eq', 'ne', 'lt', 'le', 'gt', 'ge', 'not']


# ============================================================================
# ANSIBLE DETECTION
# ============================================================================

# Ansible keywords for detection
ANSIBLE_KEYWORDS = [
    'hosts', 'tasks', 'roles', 'handlers', 'vars', 'become',
    'gather_facts', 'pre_tasks', 'post_tasks', 'block', 'rescue', 'always',
]

# Ansible modules for detection
ANSIBLE_MODULES = [
    'uri', 'debug', 'shell', 'command', 'copy', 'file',
    'template', 'apt', 'yum', 'pip', 'git', 'service',
    'systemd', 'set_fact', 'include', 'include_tasks',
    'import_tasks', 'include_role', 'import_role',
    'ansible.builtin.', 'community.', 'amazon.aws.',
]

# Ansible directories
ANSIBLE_DIRECTORIES = [
    '/playbooks/', '/roles/', '/tasks/', '/handlers/',
    '/vars/', '/defaults/', '/group_vars/', '/host_vars/',
]


# ============================================================================
# UTILITY FUNCTIONS
# ============================================================================

def is_quoted(value: str) -> bool:
    """Check if a value is quoted (single or double quotes)."""
    value = value.strip()
    return (value.startswith('"') and value.endswith('"')) or \
           (value.startswith("'") and value.endswith("'"))


def contains_helm_template(value: str) -> bool:
    """Check if the value contains a Helm template expression."""
    return '{{' in value and '}}' in value


def is_helm_template_content(content: str) -> bool:
    """Check if content contains Helm template patterns."""
    for pattern in HELM_DETECTION_PATTERNS:
        if re.search(pattern, content):
            return True
    return False


def is_int_bool_helm_template(value: str) -> bool:
    """Check if the Helm template produces an Integer/Boolean value."""
    for pattern in HELM_INT_BOOL_PATTERNS:
        if re.search(pattern, value):
            return True
    return False


def looks_like_integer(value: str) -> bool:
    """Check if a value looks like an integer."""
    value = value.strip()
    if value.isdigit():
        return True
    if value.startswith('-') and len(value) > 1 and value[1:].isdigit():
        return True
    return False


def strip_quotes(value: str) -> str:
    """Remove quotes from a value if present."""
    value = value.strip()
    if is_quoted(value):
        return value[1:-1]
    return value