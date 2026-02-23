#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Unified YAML Validator - Context-based rules for Helm/Kubernetes AND Ansible.

Supports:
- HELM/K8S: Quote validation for templates, metadata, forced keys
- ANSIBLE: String quoting, Jinja2 templates, special numbers, conditionals

Version: 3.0.0 (Unified Helm + Ansible)
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


class FileType(Enum):
    HELM = "helm"
    KUBERNETES = "kubernetes"
    ANSIBLE = "ansible"
    UNKNOWN = "unknown"


class IssueType(Enum):
    # Common
    PARSE_ERROR = "parse_error"
    STRING_VALUE_NOT_QUOTED = "string_value_not_quoted"
    
    # Helm/K8S specific
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
    TOP_LEVEL_QUOTED = "top_level_quoted"
    METADATA_VALUE_NOT_QUOTED = "metadata_value_not_quoted"
    FORCED_QUOTE_KEY_NOT_QUOTED = "forced_quote_key_not_quoted"
    
    # Ansible specific
    YAML_SYNTAX = "yaml_syntax"
    JINJA2_QUOTING = "jinja2_quoting"
    SPECIAL_NUMBER = "special_number"
    BLOCK_SCALAR = "block_scalar"
    ANSIBLE_STRING_QUOTING = "ansible_string_quoting"


@dataclass
class ValidationIssue:
    """Unified validation issue format."""
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
    file_type: FileType
    is_valid: bool
    issues: List[ValidationIssue] = dataclass_field(default_factory=list)
    error_count: int = 0


# ============================================================================
# CONSTANTS - SHARED
# ============================================================================

# Keys that must ALWAYS have quoted values (all file types)
FORCED_QUOTE_KEYS = {
    'numberOfReplicas',
    'staleReplicaTimeout',
}


# ============================================================================
# CONSTANTS - HELM/K8S
# ============================================================================

TOP_LEVEL_UNQUOTED = {'apiVersion', 'kind', 'metadata', 'spec', 'data', 'status'}
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
    r'\.nodePort\b', r'\.containerPort\b', r'\.enabled\b', r'\.disabled\b',
    r'\.count\b', r'\.limit\b', r'\.minReplicas\b', r'\.maxReplicas\b',
    r'\|\s*int\b', r'\|\s*bool\b', r'\|\s*default\s+\d+',
    r'\|\s*default\s+(true|false)\b',
]


# ============================================================================
# CONSTANTS - ANSIBLE
# ============================================================================

JINJA2_VARIABLE = re.compile(r'\{\{\s*[^}]+\s*\}\}')
JINJA2_CONTROL = re.compile(r'\{%\s*(if|for|set|block|endif|endfor|endblock)\s')

UNQUOTED_JINJA_PATTERN = re.compile(
    r'^\s*(\w+):\s+(\{\{[^}]+\}\}|\{%[^%]+%\})(?:\s*$|\s+[^"\'])',
    re.MULTILINE
)

ANSIBLE_CONDITION_KEYS = {
    'when', 'until', 'changed_when', 'failed_when',
    'custom_when', 'custom_if'
}

CONDITIONAL_PATTERNS = ['_when', '_if', '_condition']

SPECIAL_NUMBER_PATTERNS = [
    (r'^0[0-7]+$', 'Octal'),
    (r'^0x[0-9a-fA-F]+$', 'Hex'),
    (r'^[+-]\d+$', 'Signed'),
    (r'^\d+\.\d+\.\d+', 'Version'),
]

# Ansible modules (for detection)
ANSIBLE_MODULES = {
    'copy', 'template', 'file', 'lineinfile', 'blockinfile',
    'shell', 'command', 'raw', 'script',
    'apt', 'yum', 'dnf', 'pip', 'package',
    'service', 'systemd', 'user', 'group',
    'debug', 'stat', 'get_url', 'uri',
    'ansible.builtin.copy', 'ansible.builtin.template',
    'ansible.builtin.file', 'ansible.builtin.shell',
    'ansible.builtin.command', 'ansible.builtin.debug',
    'kubernetes.core.k8s', 'kubernetes.core.helm',
}

ANSIBLE_KEYWORDS = {
    'hosts', 'tasks', 'roles', 'handlers', 'vars',
    'become', 'become_user', 'gather_facts',
    'when', 'register', 'notify', 'tags', 'block',
    'delegate_to', 'run_once', 'include_tasks',
}


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
# FILE TYPE DETECTION
# ============================================================================

def detect_file_type(content: str, file_path: str = "") -> FileType:
    """Detect if content is Ansible, Helm, or Kubernetes."""
    path_lower = file_path.lower()
    
    # Path-based detection
    if 'ansible' in path_lower or 'playbook' in path_lower:
        return FileType.ANSIBLE
    
    ansible_dirs = ['tasks', 'handlers', 'vars', 'defaults', 'roles', 'playbooks']
    for d in ansible_dirs:
        if f'/{d}/' in path_lower or f'\\{d}\\' in path_lower:
            return FileType.ANSIBLE
    
    if '/templates/' in path_lower or '\\templates\\' in path_lower:
        if 'ansible' not in path_lower:
            return FileType.HELM
    
    # Content-based detection
    lines = content.split('\n')
    ansible_score = 0
    helm_k8s_score = 0
    
    for line in lines:
        stripped = line.strip()
        if not stripped or stripped.startswith('#'):
            continue
        
        # Ansible indicators
        if stripped.startswith('- name:'):
            ansible_score += 2
        for keyword in ANSIBLE_KEYWORDS:
            if stripped.startswith(f'{keyword}:') or f' {keyword}:' in stripped:
                ansible_score += 1
        for module in ANSIBLE_MODULES:
            if f'{module}:' in stripped:
                ansible_score += 3
        
        # K8S indicators
        if stripped.startswith('apiVersion:'):
            helm_k8s_score += 3
        if stripped.startswith('kind:'):
            helm_k8s_score += 3
        if 'metadata:' in stripped or 'spec:' in stripped:
            helm_k8s_score += 1
    
    # Check for Helm templates in K8S context
    if helm_k8s_score > 0 and '{{' in content and '}}' in content:
        return FileType.HELM
    
    if ansible_score > helm_k8s_score and ansible_score >= 2:
        return FileType.ANSIBLE
    
    if helm_k8s_score >= 4:
        return FileType.KUBERNETES
    
    if '{{' in content and '}}' in content:
        return FileType.HELM
    
    return FileType.UNKNOWN


# ============================================================================
# UNIFIED VALIDATOR
# ============================================================================

class UnifiedValidator:
    """
    Unified YAML Validator for Helm, Kubernetes, and Ansible files.
    
    Automatically detects file type and applies appropriate rules.
    """

    def __init__(self):
        self.yaml = YAML()
        self.yaml.preserve_quotes = True
        self.issues: List[ValidationIssue] = []
        self.lines: List[str] = []
        self.current_file: str = ""
        self.file_type: FileType = FileType.UNKNOWN
        self.processed_nodes: Set[int] = set()

    def validate_file(self, file_path: str, file_type: FileType = None) -> ValidationResult:
        """
        Validate a YAML file.
        
        Args:
            file_path: Path to YAML file
            file_type: Optional file type override
            
        Returns:
            ValidationResult with issues
        """
        self.current_file = file_path

        try:
            content = Path(file_path).read_text(encoding='utf-8')
            return self.validate_content(content, file_path, file_type)
        except Exception as e:
            return ValidationResult(
                file_path=file_path,
                file_type=FileType.UNKNOWN,
                is_valid=False,
                issues=[ValidationIssue(
                    line_number=0,
                    line_content="",
                    issue_type=IssueType.PARSE_ERROR,
                    field_path="",
                    message=f"Cannot read file: {e}",
                    suggestion=""
                )],
                error_count=1
            )

    def validate_content(self, content: str, file_path: str = "<string>",
                         file_type: FileType = None) -> ValidationResult:
        """Validate YAML content."""
        self.issues = []
        self.lines = content.split('\n')
        self.current_file = file_path
        self.processed_nodes = set()

        # Detect file type if not provided
        if file_type is None:
            self.file_type = detect_file_type(content, file_path)
        else:
            self.file_type = file_type

        # Route to appropriate validation logic
        if self.file_type == FileType.ANSIBLE:
            self._validate_ansible(content)
        else:
            self._validate_helm_k8s(content)

        return ValidationResult(
            file_path=file_path,
            file_type=self.file_type,
            is_valid=len(self.issues) == 0,
            issues=self.issues,
            error_count=len(self.issues)
        )

    def _get_line_content(self, line_num: int) -> str:
        """Get line content by line number (1-indexed)."""
        if 1 <= line_num <= len(self.lines):
            return self.lines[line_num - 1]
        return ""

    # ========================================================================
    # HELM/K8S VALIDATION
    # ========================================================================

    def _validate_helm_k8s(self, content: str):
        """Validate Helm/Kubernetes content."""
        # Check for Helm default quoting issues
        self._check_helm_defaults()

        # Parse and validate structure
        try:
            data = self.yaml.load(StringIO(content))
            if data is not None:
                self._validate_helm_node(data, [], in_metadata=False)
        except Exception as e:
            self.issues.append(ValidationIssue(
                line_number=1,
                line_content=self.lines[0] if self.lines else "",
                issue_type=IssueType.PARSE_ERROR,
                field_path="",
                message=f"YAML Parse Error: {e}",
                suggestion=""
            ))

    def _check_helm_defaults(self):
        """Check for unquoted Helm default values."""
        default_pattern = re.compile(r'\|\s*default\s+([^"\'\s\|\}][^\s\|\}]*)')

        for line_num, line in enumerate(self.lines, start=1):
            if is_helm_control_flow(line):
                continue

            if '{{' not in line or '}}' not in line:
                continue

            for match in default_pattern.finditer(line):
                default_value = match.group(1)

                if re.match(r'^-?\d+\.?\d*$', default_value):
                    continue
                if default_value.lower() in ('true', 'false'):
                    continue
                if default_value.startswith('.') or default_value.startswith('$'):
                    continue

                key_match = re.match(r'\s*([^:]+):', line)
                key = key_match.group(1).strip() if key_match else "unknown"

                suggested = line.replace(
                    f'default {default_value}',
                    f'default "{default_value}"'
                )

                self.issues.append(ValidationIssue(
                    line_number=line_num,
                    line_content=line.rstrip(),
                    issue_type=IssueType.HELM_DEFAULT_NOT_QUOTED,
                    field_path=key,
                    message=f'Helm default value must be quoted: default "{default_value}"',
                    suggestion=suggested.strip()
                ))

    def _validate_helm_node(self, node: Any, path: List[str], in_metadata: bool):
        """Recursively validate Helm/K8S YAML nodes."""
        if isinstance(node, CommentedMap):
            for key, value in node.items():
                key_str = str(key)
                new_path = path + [key_str]
                new_in_metadata = in_metadata or key_str == 'metadata'

                if isinstance(value, (CommentedMap, CommentedSeq)):
                    self._validate_helm_node(value, new_path, new_in_metadata)
                else:
                    self._validate_helm_value(key_str, value, node, new_path, new_in_metadata)

        elif isinstance(node, CommentedSeq):
            for idx, item in enumerate(node):
                new_path = path + [f'[{idx}]']
                if isinstance(item, (CommentedMap, CommentedSeq)):
                    self._validate_helm_node(item, new_path, in_metadata)
                else:
                    self._validate_helm_list_item(item, node, idx, new_path, in_metadata)

    def _validate_helm_value(self, key: str, value: Any, parent: CommentedMap,
                             path: List[str], in_metadata: bool):
        """Validate a single Helm/K8S key-value pair."""
        if value is None:
            return

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
                self.issues.append(ValidationIssue(
                    line_number=line,
                    line_content=line_content,
                    issue_type=IssueType.FORCED_QUOTE_KEY_NOT_QUOTED,
                    field_path=field_path,
                    message=f"Key '{key}' must always have quoted value",
                    suggestion=f'{key}: "{value}"'
                ))
            return

        # Rule 2: Top-level K8S keys should NOT be quoted
        if len(path) == 1 and key in TOP_LEVEL_UNQUOTED:
            if is_value_quoted and isinstance(value, str):
                self.issues.append(ValidationIssue(
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
            self._validate_helm_template_value(key, str_value, is_value_quoted, line,
                                               line_content, field_path, in_metadata)
            return

        # Rule 4: In metadata - int/bool MUST be quoted
        if in_metadata:
            if isinstance(value, bool):
                if not is_value_quoted:
                    self.issues.append(ValidationIssue(
                        line_number=line,
                        line_content=line_content,
                        issue_type=IssueType.BOOLEAN_AS_STRING,
                        field_path=field_path,
                        message="Boolean in metadata must be quoted",
                        suggestion=f'{key}: "{str_value.lower()}"'
                    ))
            elif isinstance(value, int) and not isinstance(value, bool):
                if not is_value_quoted:
                    self.issues.append(ValidationIssue(
                        line_number=line,
                        line_content=line_content,
                        issue_type=IssueType.INTEGER_FIELD_QUOTED,
                        field_path=field_path,
                        message="Integer in metadata must be quoted",
                        suggestion=f'{key}: "{value}"'
                    ))
            return

        # Rule 5: Outside metadata - paths/URLs must be quoted
        if isinstance(value, str) and not is_value_quoted:
            if re.match(r'^[A-Z][a-zA-Z]+$', str_value):
                return

            if str_value.startswith('/') or str_value.startswith('./'):
                self.issues.append(ValidationIssue(
                    line_number=line,
                    line_content=line_content,
                    issue_type=IssueType.PATH_NOT_QUOTED,
                    field_path=field_path,
                    message="Path value must be quoted",
                    suggestion=f'{key}: "{str_value}"'
                ))
                return

            if str_value.startswith('http://') or str_value.startswith('https://'):
                self.issues.append(ValidationIssue(
                    line_number=line,
                    line_content=line_content,
                    issue_type=IssueType.URL_NOT_QUOTED,
                    field_path=field_path,
                    message="URL value must be quoted",
                    suggestion=f'{key}: "{str_value}"'
                ))

    def _validate_helm_template_value(self, key: str, value: str, is_quoted: bool,
                                      line: int, line_content: str, field_path: str,
                                      in_metadata: bool):
        """Validate Helm template quoting."""
        is_int_bool = is_int_bool_helm_template(value)

        if is_int_bool:
            if is_quoted:
                self.issues.append(ValidationIssue(
                    line_number=line,
                    line_content=line_content,
                    issue_type=IssueType.HELM_TEMPLATE_INT_QUOTED,
                    field_path=field_path,
                    message="Helm template producing int/bool should not be quoted",
                    suggestion=f'{key}: {value}'
                ))
        else:
            if not is_quoted and not in_metadata:
                self.issues.append(ValidationIssue(
                    line_number=line,
                    line_content=line_content,
                    issue_type=IssueType.HELM_TEMPLATE_STRING_NOT_QUOTED,
                    field_path=field_path,
                    message="Helm template producing string should be quoted",
                    suggestion=f'{key}: "{value}"'
                ))

    def _validate_helm_list_item(self, item: Any, parent: CommentedSeq, idx: int,
                                 path: List[str], in_metadata: bool):
        """Validate a Helm/K8S list item."""
        if item is None:
            return

        if isinstance(item, (LiteralScalarString, FoldedScalarString)):
            return

        context = path[-2] if len(path) >= 2 else ""

        if context == 'goTemplateOptions':
            is_quoted = isinstance(item, (DoubleQuotedScalarString, SingleQuotedScalarString))
            if not is_quoted and isinstance(item, str):
                line, _ = self._get_position(parent, idx)
                self.issues.append(ValidationIssue(
                    line_number=line,
                    line_content=self._get_line_content(line),
                    issue_type=IssueType.GO_TEMPLATE_OPTIONS_NOT_QUOTED,
                    field_path='.'.join(path),
                    message="goTemplateOptions items must be quoted",
                    suggestion=f'- "{item}"'
                ))

    # ========================================================================
    # ANSIBLE VALIDATION
    # ========================================================================

    def _validate_ansible(self, content: str):
        """Validate Ansible content."""
        # Pre-parse validation for unquoted Jinja2
        self._validate_ansible_raw_syntax(content)

        # Parse and validate structure
        try:
            data = self.yaml.load(StringIO(content))
            if data is not None:
                self._validate_ansible_node(data)
        except Exception as e:
            self.issues.append(ValidationIssue(
                line_number=1,
                line_content=self.lines[0] if self.lines else "",
                issue_type=IssueType.PARSE_ERROR,
                field_path="",
                message=f"YAML Parse Error: {e}",
                suggestion=""
            ))

    def _validate_ansible_raw_syntax(self, content: str):
        """Pre-parse validation for unquoted Jinja2 in Ansible."""
        lines = content.split('\n')

        for line_num, line in enumerate(lines, start=1):
            stripped = line.strip()
            if not stripped or stripped.startswith('#'):
                continue

            if stripped.endswith('|') or stripped.endswith('>'):
                continue

            match = UNQUOTED_JINJA_PATTERN.search(line)
            if match:
                key = match.group(1)
                jinja_expr = match.group(2)

                is_conditional = (key in ANSIBLE_CONDITION_KEYS or
                                  any(key.endswith(p) for p in CONDITIONAL_PATTERNS))

                if is_conditional:
                    rest_of_line = line[line.index(jinja_expr) + len(jinja_expr):].strip()
                    if rest_of_line and not rest_of_line.startswith('#'):
                        self.issues.append(ValidationIssue(
                            line_number=line_num,
                            line_content=line.rstrip(),
                            issue_type=IssueType.YAML_SYNTAX,
                            field_path=key,
                            message="Unquoted Jinja2 with trailing text will cause YAML parsing issues",
                            suggestion=f'{key}: "{jinja_expr} {rest_of_line}"'
                        ))
                else:
                    self.issues.append(ValidationIssue(
                        line_number=line_num,
                        line_content=line.rstrip(),
                        issue_type=IssueType.YAML_SYNTAX,
                        field_path=key,
                        message="Unquoted Jinja2 expression will be parsed as nested dict",
                        suggestion=f'{key}: "{jinja_expr}"'
                    ))

    def _validate_ansible_node(self, node: Any, path: List[str] = None, parent_key: str = None):
        """Recursively validate Ansible YAML structure."""
        if path is None:
            path = []

        node_id = id(node)
        if node_id in self.processed_nodes:
            return
        self.processed_nodes.add(node_id)

        if isinstance(node, CommentedMap):
            for key, value in node.items():
                key_str = str(key)

                if isinstance(value, (CommentedMap, CommentedSeq)):
                    self._validate_ansible_node(value, path + [key_str], parent_key=key_str)
                else:
                    self._validate_ansible_value(key_str, value, node, path, parent_key=parent_key)

        elif isinstance(node, CommentedSeq):
            for idx, item in enumerate(node):
                if isinstance(item, (CommentedMap, CommentedSeq)):
                    self._validate_ansible_node(item, path + [f'[{idx}]'], parent_key=parent_key)
                else:
                    self._validate_ansible_value(
                        f'[{idx}]', item, node, path,
                        is_list=True, list_idx=idx, parent_key=parent_key
                    )

    def _validate_ansible_value(self, key: str, value: Any, parent: Any, path: List[str],
                                is_list: bool = False, list_idx: int = 0,
                                parent_key: str = None):
        """Validate a single Ansible value."""
        if value is None:
            return

        if isinstance(value, bool):
            return

        if isinstance(value, (int, float)) and not isinstance(value, bool):
            return

        if not isinstance(value, str):
            return

        if isinstance(value, (LiteralScalarString, FoldedScalarString)):
            return

        line, col = self._get_position(parent, key if not is_list else list_idx)
        line_content = self._get_line_content(line)

        is_quoted = isinstance(value, (DoubleQuotedScalarString, SingleQuotedScalarString))
        field_path = '.'.join(path + [key]) if path else key

        # Check for quoted block scalar indicators
        if is_quoted:
            stripped = value.strip()
            if stripped.startswith('|') or stripped.startswith('>'):
                self.issues.append(ValidationIssue(
                    line_number=line,
                    line_content=line_content,
                    issue_type=IssueType.BLOCK_SCALAR,
                    field_path=field_path,
                    message="Block-scalar indicator should not be quoted",
                    suggestion=f"{key}: {stripped}"
                ))
                return

        is_conditional = self._is_ansible_conditional_key(key)

        # Rule 1: Special numbers must be quoted
        if self._is_special_number(value):
            if not is_quoted:
                number_type = self._get_number_type(value)
                self.issues.append(ValidationIssue(
                    line_number=line,
                    line_content=line_content,
                    issue_type=IssueType.SPECIAL_NUMBER,
                    field_path=field_path,
                    message=f"{number_type} number must be quoted to preserve format",
                    suggestion=f'{key}: "{value}"'
                ))
            return

        # Rule 2: Jinja2 quoting
        if JINJA2_VARIABLE.search(value):
            self._validate_ansible_jinja2_quoting(
                key, value, is_quoted, line, line_content, field_path, is_conditional
            )

        # Rule 3: Basic string quoting
        elif not is_quoted:
            if not is_conditional:
                self.issues.append(ValidationIssue(
                    line_number=line,
                    line_content=line_content,
                    issue_type=IssueType.ANSIBLE_STRING_QUOTING,
                    field_path=field_path,
                    message="String value must be quoted",
                    suggestion=f'{key}: "{value}"'
                ))

    def _is_ansible_conditional_key(self, key: str) -> bool:
        """Check if key is an Ansible conditional."""
        if key in ANSIBLE_CONDITION_KEYS:
            return True
        if any(key.endswith(pattern) for pattern in CONDITIONAL_PATTERNS):
            return True
        return False

    def _validate_ansible_jinja2_quoting(self, key: str, value: str, is_quoted: bool,
                                         line: int, line_content: str, field_path: str,
                                         is_conditional: bool):
        """Validate Jinja2 template quoting in Ansible."""
        if JINJA2_CONTROL.search(value):
            return

        stripped = value.strip()

        if is_conditional:
            if is_quoted and stripped.startswith('{{') and stripped.endswith('}}'):
                inner = stripped[2:-2].strip()
                self.issues.append(ValidationIssue(
                    line_number=line,
                    line_content=line_content,
                    issue_type=IssueType.JINJA2_QUOTING,
                    field_path=field_path,
                    message=f"Conditional '{key}' must not wrap expression in {{{{ }}}} (double templating)",
                    suggestion=f"{key}: {inner}"
                ))
            elif not is_quoted and not (stripped.startswith('{{') and stripped.endswith('}}')):
                if '{{' in stripped:
                    self.issues.append(ValidationIssue(
                        line_number=line,
                        line_content=line_content,
                        issue_type=IssueType.JINJA2_QUOTING,
                        field_path=field_path,
                        message="Mixed string with Jinja2 in conditional should be quoted",
                        suggestion=f'{key}: "{value}"'
                    ))
        else:
            if stripped.startswith('{{') and stripped.endswith('}}') and not is_quoted:
                self.issues.append(ValidationIssue(
                    line_number=line,
                    line_content=line_content,
                    issue_type=IssueType.JINJA2_QUOTING,
                    field_path=field_path,
                    message="Jinja2 template must be quoted",
                    suggestion=f'{key}: "{value}"'
                ))
            elif '{{' in stripped and not is_quoted:
                self.issues.append(ValidationIssue(
                    line_number=line,
                    line_content=line_content,
                    issue_type=IssueType.JINJA2_QUOTING,
                    field_path=field_path,
                    message="String containing Jinja2 template must be quoted",
                    suggestion=f'{key}: "{value}"'
                ))

    def _is_special_number(self, value: str) -> bool:
        """Check if value is a special number (Octal, Hex, Version)."""
        for pattern, _ in SPECIAL_NUMBER_PATTERNS:
            if re.match(pattern, value):
                return True
        return False

    def _get_number_type(self, value: str) -> str:
        """Get the type of special number."""
        for pattern, num_type in SPECIAL_NUMBER_PATTERNS:
            if re.match(pattern, value):
                return num_type
        return "Special"

    # ========================================================================
    # SHARED HELPERS
    # ========================================================================

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
# BACKWARDS COMPATIBILITY ALIASES
# ============================================================================

# Alias for yaml_router compatibility
UnifiedQuoteValidator = UnifiedValidator
AnsibleValidator = UnifiedValidator


# ============================================================================
# MAIN
# ============================================================================

def main():
    """CLI entry point."""
    if len(sys.argv) < 2:
        print("Unified YAML Validator v3.0.0")
        print("=" * 60)
        print("\nUsage: python unified_validator.py <file> [--type helm|k8s|ansible]")
        print("\nSupports: Helm, Kubernetes, Ansible")
        print("\nFile type is auto-detected if not specified.")
        sys.exit(1)

    file_path = sys.argv[1]
    
    # Check for type override
    file_type = None
    if len(sys.argv) >= 4 and sys.argv[2] == '--type':
        type_map = {
            'helm': FileType.HELM,
            'k8s': FileType.KUBERNETES,
            'kubernetes': FileType.KUBERNETES,
            'ansible': FileType.ANSIBLE,
        }
        file_type = type_map.get(sys.argv[3].lower())

    validator = UnifiedValidator()
    result = validator.validate_file(file_path, file_type)

    print("")
    print("=" * 80)
    print(f"File: {file_path}")
    print(f"Type: {result.file_type.value.upper()}")
    print("=" * 80)

    if result.issues:
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
        print("[OK] All checks passed")
        print("")
        sys.exit(0)


if __name__ == "__main__":
    main()