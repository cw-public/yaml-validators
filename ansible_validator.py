"""
Ansible Playbook Validator - Combined Rules

Regelsets:
1. Basis: Alle Strings müssen gequotet sein
2. Jinja2: Context-aware Template-Quoting
3. Special Numbers: Octal, Hex, Versions müssen gequotet sein
4. Block-Scalars: | und > brauchen keine Quotes
5. Pre-Parse: Unquoted Jinja2 die YAML-Parsing zerstören

Version: 3.0.0 (Unified Output Format)
"""

import sys
import re
from pathlib import Path
from dataclasses import dataclass, field
from typing import List, Optional, Any, Set
from io import StringIO
from enum import Enum

from ruamel.yaml import YAML
from ruamel.yaml.comments import CommentedMap, CommentedSeq
from ruamel.yaml.scalarstring import (
    DoubleQuotedScalarString,
    SingleQuotedScalarString,
    LiteralScalarString,
    FoldedScalarString,
)


# ============================================================================
# SHARED TYPES (compatible with unified_validator)
# ============================================================================

class Severity(Enum):
    ERROR = "error"
    WARNING = "warning"


class AnsibleIssueType(Enum):
    """Types of Ansible validation issues."""
    PARSE_ERROR = "parse_error"
    YAML_SYNTAX = "yaml_syntax"
    STRING_QUOTING = "string_quoting"
    JINJA2_QUOTING = "jinja2_quoting"
    SPECIAL_NUMBER = "special_number"
    BLOCK_SCALAR = "block_scalar"


@dataclass
class AnsibleIssue:
    """Represents an Ansible validation issue (unified format)."""
    line_number: int
    line_content: str
    issue_type: AnsibleIssueType
    field_path: str
    message: str
    suggestion: str
    severity: Severity = Severity.ERROR


@dataclass
class ValidationResult:
    """Result of validation (compatible with yaml_router)."""
    file_path: str
    is_valid: bool
    issues: List[AnsibleIssue] = field(default_factory=list)
    error_count: int = 0


# ============================================================================
# PATTERNS & DETECTION
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


# ============================================================================
# ANSIBLE VALIDATOR
# ============================================================================

class AnsibleValidator:
    """
    Ansible Validator with unified output format.
    
    Compatible with yaml_router's validation interface.
    """
    
    def __init__(self):
        self.yaml = YAML()
        self.yaml.preserve_quotes = True
        self.issues: List[AnsibleIssue] = []
        self.processed_nodes: Set[int] = set()
        self.current_file: str = ""
        self.lines: List[str] = []
    
    def validate_file(self, file_path: str) -> ValidationResult:
        """
        Validate a file (interface compatible with yaml_router).
        
        Args:
            file_path: Path to YAML file
            
        Returns:
            ValidationResult with issues in unified format
        """
        self.current_file = file_path
        
        try:
            content = Path(file_path).read_text(encoding='utf-8')
            return self.validate_content(content, file_path)
        except Exception as e:
            return ValidationResult(
                file_path=file_path,
                is_valid=False,
                issues=[AnsibleIssue(
                    line_number=0,
                    line_content="",
                    issue_type=AnsibleIssueType.PARSE_ERROR,
                    field_path="",
                    message=f"Cannot read file: {e}",
                    suggestion=""
                )],
                error_count=1
            )
    
    def validate_content(self, content: str, file_path: str = "<string>") -> ValidationResult:
        """Validate YAML content."""
        self.issues = []
        self.processed_nodes = set()
        self.current_file = file_path
        self.lines = content.split('\n')
        
        # Pre-parse validation
        self._validate_raw_syntax(content)
        
        # Parse and validate structure
        try:
            data = self.yaml.load(StringIO(content))
            if data is not None:
                self._validate_node(data)
        except Exception as e:
            self.issues.append(AnsibleIssue(
                line_number=1,
                line_content=self.lines[0] if self.lines else "",
                issue_type=AnsibleIssueType.PARSE_ERROR,
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
    
    def _validate_raw_syntax(self, content: str) -> None:
        """Pre-parse validation for unquoted Jinja2."""
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
                        self.issues.append(AnsibleIssue(
                            line_number=line_num,
                            line_content=line.rstrip(),
                            issue_type=AnsibleIssueType.YAML_SYNTAX,
                            field_path=key,
                            message="Unquoted Jinja2 with trailing text will cause YAML parsing issues",
                            suggestion=f'{key}: "{jinja_expr} {rest_of_line}"'
                        ))
                else:
                    self.issues.append(AnsibleIssue(
                        line_number=line_num,
                        line_content=line.rstrip(),
                        issue_type=AnsibleIssueType.YAML_SYNTAX,
                        field_path=key,
                        message="Unquoted Jinja2 expression will be parsed as nested dict",
                        suggestion=f'{key}: "{jinja_expr}"'
                    ))
    
    def _validate_node(self, node: Any, path: List[str] = None, parent_key: str = None):
        """Recursively validate YAML structure."""
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
                    self._validate_node(value, path + [key_str], parent_key=key_str)
                else:
                    self._validate_value(key_str, value, node, path, parent_key=parent_key)
        
        elif isinstance(node, CommentedSeq):
            for idx, item in enumerate(node):
                if isinstance(item, (CommentedMap, CommentedSeq)):
                    self._validate_node(item, path + [f'[{idx}]'], parent_key=parent_key)
                else:
                    self._validate_value(
                        f'[{idx}]', item, node, path,
                        is_list=True, list_idx=idx, parent_key=parent_key
                    )
    
    def _validate_value(self, key: str, value: Any, parent: Any, path: List[str],
                       is_list: bool = False, list_idx: int = 0,
                       parent_key: str = None):
        """Validate a single value."""
        if value is None:
            return
        
        if isinstance(value, bool):
            return
        
        if isinstance(value, (int, float)) and not isinstance(value, bool):
            return
        
        if not isinstance(value, str):
            return
        
        # Skip block scalars
        if isinstance(value, (LiteralScalarString, FoldedScalarString)):
            return
        
        line, col = self._get_position(parent, key if not is_list else list_idx)
        line_content = self._get_line_content(line)
        
        is_quoted = isinstance(value, (DoubleQuotedScalarString, SingleQuotedScalarString))
        
        # Build field path
        field_path = '.'.join(path + [key]) if path else key
        
        # Check for quoted block scalar indicators
        if is_quoted:
            stripped = value.strip()
            if stripped.startswith('|') or stripped.startswith('>'):
                self.issues.append(AnsibleIssue(
                    line_number=line,
                    line_content=line_content,
                    issue_type=AnsibleIssueType.BLOCK_SCALAR,
                    field_path=field_path,
                    message="Block-scalar indicator should not be quoted",
                    suggestion=f"{key}: {stripped}"
                ))
                return
        
        is_conditional = self._is_conditional_key(key)
        
        # Rule 1: Special numbers must be quoted
        if self._is_special_number(value):
            if not is_quoted:
                number_type = self._get_number_type(value)
                self.issues.append(AnsibleIssue(
                    line_number=line,
                    line_content=line_content,
                    issue_type=AnsibleIssueType.SPECIAL_NUMBER,
                    field_path=field_path,
                    message=f"{number_type} number must be quoted to preserve format",
                    suggestion=f'{key}: "{value}"'
                ))
            return
        
        # Rule 2: Jinja2 quoting
        if JINJA2_VARIABLE.search(value):
            self._validate_jinja2_quoting(
                key, value, is_quoted, line, line_content, field_path, is_conditional
            )
        
        # Rule 3: Basic string quoting
        elif not is_quoted:
            if not is_conditional:
                self.issues.append(AnsibleIssue(
                    line_number=line,
                    line_content=line_content,
                    issue_type=AnsibleIssueType.STRING_QUOTING,
                    field_path=field_path,
                    message="String value must be quoted",
                    suggestion=f'{key}: "{value}"'
                ))
    
    def _is_conditional_key(self, key: str) -> bool:
        """Check if key is a conditional."""
        if key in ANSIBLE_CONDITION_KEYS:
            return True
        if any(key.endswith(pattern) for pattern in CONDITIONAL_PATTERNS):
            return True
        return False
    
    def _validate_jinja2_quoting(self, key: str, value: str, is_quoted: bool,
                                 line: int, line_content: str, field_path: str,
                                 is_conditional: bool):
        """Validate Jinja2 template quoting."""
        if JINJA2_CONTROL.search(value):
            return
        
        stripped = value.strip()
        
        if is_conditional:
            if is_quoted and stripped.startswith('{{') and stripped.endswith('}}'):
                inner = stripped[2:-2].strip()
                self.issues.append(AnsibleIssue(
                    line_number=line,
                    line_content=line_content,
                    issue_type=AnsibleIssueType.JINJA2_QUOTING,
                    field_path=field_path,
                    message=f"Conditional '{key}' must not wrap expression in {{{{ }}}} (double templating)",
                    suggestion=f"{key}: {inner}"
                ))
            elif not is_quoted and not (stripped.startswith('{{') and stripped.endswith('}}')):
                if '{{' in stripped:
                    self.issues.append(AnsibleIssue(
                        line_number=line,
                        line_content=line_content,
                        issue_type=AnsibleIssueType.JINJA2_QUOTING,
                        field_path=field_path,
                        message="Mixed string with Jinja2 in conditional should be quoted",
                        suggestion=f'{key}: "{value}"'
                    ))
        else:
            if stripped.startswith('{{') and stripped.endswith('}}') and not is_quoted:
                self.issues.append(AnsibleIssue(
                    line_number=line,
                    line_content=line_content,
                    issue_type=AnsibleIssueType.JINJA2_QUOTING,
                    field_path=field_path,
                    message="Jinja2 template must be quoted",
                    suggestion=f'{key}: "{value}"'
                ))
            elif '{{' in stripped and not is_quoted:
                self.issues.append(AnsibleIssue(
                    line_number=line,
                    line_content=line_content,
                    issue_type=AnsibleIssueType.JINJA2_QUOTING,
                    field_path=field_path,
                    message="String containing Jinja2 template must be quoted",
                    suggestion=f'{key}: "{value}"'
                ))
    
    def _is_special_number(self, value: str) -> bool:
        """Check if value is a special number."""
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
# MAIN (standalone usage)
# ============================================================================

def main():
    """CLI entry point."""
    if len(sys.argv) < 2:
        print("Ansible Playbook Validator v3.0.0")
        print("=" * 60)
        print("\nUsage: python ansible_validator.py <file>")
        sys.exit(1)
    
    file_path = sys.argv[1]
    
    validator = AnsibleValidator()
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