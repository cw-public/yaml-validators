#!/usr/bin/env python3
# filepath: c:\Users\ahryhory\Documents\Git-repos\yaml-validators\shared_constants.py
"""
Shared Constants - Central definitions for all validators.
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
    # Type errors
    BOOLEAN_AS_STRING = "boolean_as_string"
    INTEGER_FIELD_QUOTED = "integer_field_quoted"
    
    # Metadata errors (values that would parse as non-string)
    METADATA_VALUE_NOT_QUOTED = "metadata_value_not_quoted"
    
    # Helm/Go-Template errors
    HELM_TEMPLATE_INT_QUOTED = "helm_template_int_quoted"
    HELM_TEMPLATE_STRING_NOT_QUOTED = "helm_template_string_not_quoted"
    GO_TEMPLATE_OPTIONS_NOT_QUOTED = "go_template_options_not_quoted"
    
    # Quoting style errors
    TOP_LEVEL_QUOTED = "top_level_quoted"
    PATH_NOT_QUOTED = "path_not_quoted"
    URL_NOT_QUOTED = "url_not_quoted"
    PORT_STRING_NOT_QUOTED = "port_string_not_quoted"
    STRING_VALUE_NOT_QUOTED = "string_value_not_quoted"


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
# HELM PATTERNS
# ============================================================================

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
    r'\.nodePort\b', r'\.containerPort\b', r'\.enabled\b', r'\.disabled\b',
    r'\.count\b', r'\.limit\b', r'\.minReplicas\b', r'\.maxReplicas\b',
    r'\|\s*int\b', r'\|\s*bool\b', r'\|\s*default\s+\d+',
    r'\|\s*default\s+(true|false)\b',
]


# ============================================================================
# FIELD DEFINITIONS
# ============================================================================

# String fields in spec that SHOULD be quoted
STRING_FIELDS_REQUIRE_QUOTE = {
    # Paths and URLs
    'path', 'repoURL', 'revision', 'targetRevision', 'ref', 'url',
    # Container/Image
    'image', 'repository', 'tag',
    # Helm/ArgoCD
    'chart', 'releaseName', 'project',
    # Identifiers
    'name', 'namespace', 'server', 'secretName', 'configMapName',
    'serviceAccountName', 'clusterName', 'context', 'cluster',
}

# Port object string fields
PORT_STRING_FIELDS = {'name', 'protocol'}

# String list contexts
STRING_LIST_CONTEXTS = {'valueFiles', 'syncOptions', 'finalizers', 'goTemplateOptions'}


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