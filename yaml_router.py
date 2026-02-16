#!/usr/bin/env python3
"""
YAML Router - Detects file type and routes to appropriate validators.
"""

import sys
import os
from pathlib import Path
from typing import List, Tuple, Optional


# ============================================================================
# IMPORT SHARED CONSTANTS
# ============================================================================

def _import_shared_constants():
    """Import from shared_constants with fallback."""
    try:
        from shared_constants import (
            Severity, ValidationResult,
            HELM_DETECTION_PATTERNS, ANSIBLE_KEYWORDS, ANSIBLE_MODULES, ANSIBLE_DIRECTORIES,
            is_helm_template_content
        )
        return (Severity, ValidationResult, HELM_DETECTION_PATTERNS,
                ANSIBLE_KEYWORDS, ANSIBLE_MODULES, ANSIBLE_DIRECTORIES,
                is_helm_template_content)
    except ImportError:
        # Fallback definitions
        from enum import Enum
        from dataclasses import dataclass, field as dataclass_field
        
        class Severity(Enum):
            ERROR = "error"
        
        @dataclass
        class ValidationResult:
            file_path: str
            is_valid: bool
            issues: List = dataclass_field(default_factory=list)
            error_count: int = 0
        
        HELM_DETECTION_PATTERNS = [r'\{\{.*\}\}', r'\{\{-.*-\}\}']
        
        ANSIBLE_KEYWORDS = {
            'hosts', 'tasks', 'roles', 'handlers', 'vars', 'vars_files',
            'pre_tasks', 'post_tasks', 'gather_facts', 'become', 'become_user',
        }
        
        ANSIBLE_MODULES = {
            'ansible.builtin', 'copy', 'template', 'file', 'shell', 'command',
            'apt', 'yum', 'service', 'debug', 'set_fact',
        }
        
        ANSIBLE_DIRECTORIES = {
            'playbooks', 'roles', 'tasks', 'handlers', 'vars', 'defaults',
        }
        
        def is_helm_template_content(content: str) -> bool:
            return '{{' in content and '}}' in content
        
        return (Severity, ValidationResult, HELM_DETECTION_PATTERNS,
                ANSIBLE_KEYWORDS, ANSIBLE_MODULES, ANSIBLE_DIRECTORIES,
                is_helm_template_content)


(Severity, ValidationResult, HELM_DETECTION_PATTERNS,
 ANSIBLE_KEYWORDS, ANSIBLE_MODULES, ANSIBLE_DIRECTORIES,
 is_helm_template_content) = _import_shared_constants()


# ============================================================================
# FILE TYPE DETECTION
# ============================================================================

class FileType:
    """Enum-like class for file types."""
    KUBERNETES = "K8S"
    HELM = "HELM"
    ANSIBLE = "ANSIBLE"
    UNKNOWN = "UNKNOWN"


def detect_file_type(file_path: str) -> str:
    """
    Detect if YAML file is Kubernetes, Helm template, or Ansible.
    
    Priority:
    1. Helm templates (in templates/ or Chart.yaml)
    2. Ansible (playbook keywords or roles structure)
    3. Kubernetes (apiVersion/kind)
    4. Unknown
    """
    try:
        content = Path(file_path).read_text(encoding='utf-8')
        path_obj = Path(file_path)
        
        # Check if in Helm templates directory or Chart.yaml
        if 'templates' in path_obj.parts or path_obj.name == 'Chart.yaml':
            return FileType.HELM
        
        # Check for Helm template syntax
        if is_helm_template_content(content):
            return FileType.HELM
        
        # Check for Ansible indicators
        if _is_ansible_content(content, path_obj):
            return FileType.ANSIBLE
        
        # Check for Kubernetes
        if 'apiVersion:' in content and 'kind:' in content:
            return FileType.KUBERNETES
        
        return FileType.UNKNOWN
        
    except Exception:
        return FileType.UNKNOWN


def _is_ansible_content(content: str, path: Path) -> bool:
    """Check if content is an Ansible playbook/role."""
    
    # Check directory structure
    for ansible_dir in ANSIBLE_DIRECTORIES:
        if ansible_dir in path.parts:
            return True
    
    # Check for Ansible keywords
    content_lower = content.lower()
    for keyword in ANSIBLE_KEYWORDS:
        if f'{keyword}:' in content_lower or f'- {keyword}:' in content_lower:
            return True
    
    # Check for Ansible modules
    for module in ANSIBLE_MODULES:
        if f'{module}:' in content or f'{module}.' in content:
            return True
    
    return False


# ============================================================================
# YAML ROUTER
# ============================================================================

class YamlRouter:
    """Routes YAML files to appropriate validators."""
    
    def __init__(self, 
                 use_yamllint: bool = True,
                 use_quote_validator: bool = True,
                 use_ansible_lint: bool = False,
                 verbose: bool = False):
        self.use_yamllint = use_yamllint
        self.use_quote_validator = use_quote_validator
        self.use_ansible_lint = use_ansible_lint
        self.verbose = verbose
        
        # Initialize validators
        self.yamllint_validator = None
        self.quote_validator = None
        self.ansible_lint_validator = None
        
        if use_yamllint:
            self.yamllint_validator = YamlLintValidator()
        
        if use_quote_validator:
            try:
                from unified_validator import UnifiedQuoteValidator
                self.quote_validator = UnifiedQuoteValidator()
            except ImportError:
                print("Warning: Could not import UnifiedQuoteValidator")
        
        if use_ansible_lint:
            self.ansible_lint_validator = AnsibleLintValidator()
    
    def validate_files(self, file_paths: List[str]) -> int:
        """Validate multiple files and return exit code."""
        total_errors = 0
        
        for file_path in file_paths:
            file_type = detect_file_type(file_path)
            
            print(f"\nFile: {file_path}")
            print(f"Type: {file_type}")
            print("=" * 80)
            
            result = self._validate_with_router(file_path, file_type)
            
            if not result.is_valid:
                total_errors += result.error_count
        
        print("\n" + "=" * 80)
        print(f"TOTAL: {len(file_paths)} file(s), {total_errors} error(s)")
        print("=" * 80)
        
        return 1 if total_errors > 0 else 0
    
    def _validate_with_router(self, file_path: str, file_type: str) -> ValidationResult:
        """Route to appropriate validators based on file type."""
        all_issues = []
        
        # YAMLlint - always run
        if self.yamllint_validator:
            print("\n> YAMLlint")
            print("-" * 80)
            yamllint_result = self.yamllint_validator.validate_file(file_path)
            if yamllint_result.issues:
                all_issues.extend(yamllint_result.issues)
                for issue in yamllint_result.issues:
                    print(f"[ERROR] {issue.message}")
                    if hasattr(issue, 'field_path'):
                        print(f"   Rule: {issue.field_path}")
            else:
                print("✓ No issues found")
        
        # Quote Validator - ONLY for K8S and Helm
        if self.quote_validator and file_type in (FileType.KUBERNETES, FileType.HELM):
            print("\n> Quote Validator")
            print("-" * 80)
            quote_result = self.quote_validator.validate_file(file_path)
            if quote_result.issues:
                all_issues.extend(quote_result.issues)
                for issue in quote_result.issues:
                    print(f"[ERROR] Line {issue.line_number}: {issue.message}")
                    print(f"   CURRENT:  {issue.line_content.strip()}")
                    print(f"   EXPECTED: {issue.suggestion}")
                    print()
            else:
                print("✓ No issues found")
        
        # Ansible-Lint - ONLY for Ansible
        if self.ansible_lint_validator and file_type == FileType.ANSIBLE:
            print("\n> Ansible-Lint")
            print("-" * 80)
            ansible_result = self.ansible_lint_validator.validate_file(file_path)
            if ansible_result.issues:
                all_issues.extend(ansible_result.issues)
                for issue in ansible_result.issues:
                    print(f"[ERROR] {issue.message}")
            else:
                print("✓ No issues found")
        
        print("-" * 80)
        print(f"Summary: {len(all_issues)} error(s)")
        
        return ValidationResult(
            file_path=file_path,
            is_valid=len(all_issues) == 0,
            issues=all_issues,
            error_count=len(all_issues)
        )


# ============================================================================
# YAMLLINT VALIDATOR
# ============================================================================

class YamlLintValidator:
    """Wrapper for yamllint."""
    
    def __init__(self, config_file: Optional[str] = None):
        self.config_file = config_file
        
        # Try to import yamllint
        try:
            from yamllint import linter
            from yamllint.config import YamlLintConfig
            self.linter = linter
            self.YamlLintConfig = YamlLintConfig
            self.available = True
        except ImportError:
            self.available = False
    
    def validate_file(self, file_path: str) -> ValidationResult:
        """Validate file with yamllint."""
        if not self.available:
            return ValidationResult(
                file_path=file_path,
                is_valid=True,
                issues=[],
                error_count=0
            )
        
        try:
            # Load config
            if self.config_file and Path(self.config_file).exists():
                config = self.YamlLintConfig(file=self.config_file)
            else:
                # Default config
                config = self.YamlLintConfig("""
extends: default
rules:
  line-length:
    max: 160
  indentation:
    spaces: 2
  comments:
    min-spaces-from-content: 2
  document-start: disable
  truthy:
    allowed-values: ['true', 'false', 'yes', 'no']
""")
            
            # Run yamllint
            content = Path(file_path).read_text(encoding='utf-8')
            problems = list(self.linter.run(content, config))
            
            # Convert to our format
            issues = []
            for problem in problems:
                # Create a simple issue object
                issue = type('Issue', (), {
                    'message': f"Line {problem.line}, Column {problem.column}: {problem.message} ({problem.rule})",
                    'field_path': problem.rule,
                    'line_number': problem.line
                })()
                issues.append(issue)
            
            return ValidationResult(
                file_path=file_path,
                is_valid=len(issues) == 0,
                issues=issues,
                error_count=len(issues)
            )
            
        except Exception as e:
            return ValidationResult(
                file_path=file_path,
                is_valid=False,
                issues=[type('Issue', (), {'message': f"Error: {e}", 'field_path': ''})()],
                error_count=1
            )


# ============================================================================
# ANSIBLE-LINT VALIDATOR
# ============================================================================

class AnsibleLintValidator:
    """Wrapper for ansible-lint."""
    
    def __init__(self):
        # Try to import ansible-lint
        try:
            import subprocess
            self.subprocess = subprocess
            self.available = True
        except ImportError:
            self.available = False
    
    def validate_file(self, file_path: str) -> ValidationResult:
        """Validate file with ansible-lint."""
        if not self.available:
            return ValidationResult(
                file_path=file_path,
                is_valid=True,
                issues=[],
                error_count=0
            )
        
        try:
            # Run ansible-lint as subprocess
            result = self.subprocess.run(
                ['ansible-lint', '--parseable', file_path],
                capture_output=True,
                text=True,
                timeout=30
            )
            
            # Parse output
            issues = []
            for line in result.stdout.split('\n'):
                if line.strip():
                    issue = type('Issue', (), {'message': line})()
                    issues.append(issue)
            
            return ValidationResult(
                file_path=file_path,
                is_valid=len(issues) == 0,
                issues=issues,
                error_count=len(issues)
            )
            
        except Exception as e:
            return ValidationResult(
                file_path=file_path,
                is_valid=False,
                issues=[type('Issue', (), {'message': f"Error: {e}"})()],
                error_count=1
            )


# ============================================================================
# MAIN
# ============================================================================

def main():
    import argparse
    
    parser = argparse.ArgumentParser(description='YAML Router - Routes to appropriate validators')
    parser.add_argument('files', nargs='+', help='YAML files to validate')
    parser.add_argument('-v', '--verbose', action='store_true', help='Verbose output')
    parser.add_argument('--no-yamllint', action='store_true', help='Disable yamllint')
    parser.add_argument('--no-quotes', action='store_true', help='Disable quote validator')
    parser.add_argument('--ansible-lint', action='store_true', help='Enable ansible-lint')
    
    args = parser.parse_args()
    
    router = YamlRouter(
        use_yamllint=not args.no_yamllint,
        use_quote_validator=not args.no_quotes,
        use_ansible_lint=args.ansible_lint,
        verbose=args.verbose
    )
    
    exit_code = router.validate_files(args.files)
    sys.exit(exit_code)


if __name__ == '__main__':
    main()