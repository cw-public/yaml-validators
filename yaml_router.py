#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
YAML Router - Detects file type and routes to appropriate validators.

Validation Strategy:
- K8S/Helm: YAMLlint + Quote Validator
- Ansible:  SKIP (handled by ansible-lint separately)
- Unknown:  YAMLlint only
"""

import sys
import os
from pathlib import Path
from typing import List, Optional
from dataclasses import dataclass, field as dataclass_field
from enum import Enum


# ============================================================================
# ANSI COLOR CODES
# ============================================================================

class Colors:
    """ANSI color codes for terminal output."""
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    MAGENTA = '\033[95m'
    CYAN = '\033[96m'
    RESET = '\033[0m'
    BOLD = '\033[1m'


# ============================================================================
# SHARED TYPES (fallback if shared_constants not available)
# ============================================================================

class Severity(Enum):
    ERROR = "error"
    WARNING = "warning"


@dataclass
class ValidationResult:
    file_path: str
    is_valid: bool
    issues: List = dataclass_field(default_factory=list)
    error_count: int = 0


# ============================================================================
# DETECTION PATTERNS
# ============================================================================

# Ansible-specific keywords that appear at root or task level
ANSIBLE_KEYWORDS = {
    # Playbook level
    'hosts', 'tasks', 'roles', 'handlers', 'vars', 'vars_files',
    'pre_tasks', 'post_tasks', 'gather_facts', 'become', 'become_user',
    'become_method', 'environment', 'collections', 'connection',
    # Task level
    'when', 'register', 'notify', 'listen', 'tags', 'block', 'rescue',
    'always', 'loop', 'loop_control', 'with_items', 'with_dict',
    'with_fileglob', 'until', 'retries', 'delay', 'changed_when',
    'failed_when', 'ignore_errors', 'delegate_to', 'run_once',
    'include_tasks', 'import_tasks', 'include_role', 'import_role',
    'include_vars', 'set_fact', 'assert', 'fail', 'debug',
}

# Ansible module names (most common ones)
ANSIBLE_MODULES = {
    # Files
    'copy', 'template', 'file', 'lineinfile', 'blockinfile',
    'fetch', 'synchronize', 'unarchive', 'archive', 'stat',
    # Commands
    'shell', 'command', 'raw', 'script', 'expect',
    # Packages
    'apt', 'yum', 'dnf', 'pip', 'package', 'snap',
    # Services
    'service', 'systemd', 'sysvinit',
    # Users
    'user', 'group', 'authorized_key',
    # System
    'hostname', 'cron', 'mount', 'sysctl', 'selinux',
    # Network
    'uri', 'get_url', 'wait_for',
    # Cloud
    'aws_s3', 'ec2', 'azure_rm', 'gcp_compute',
    # Containers
    'docker_container', 'docker_image', 'k8s', 'helm',
    # Misc
    'debug', 'pause', 'wait_for_connection', 'setup',
    # Built-in namespace
    'ansible.builtin.copy', 'ansible.builtin.template',
    'ansible.builtin.file', 'ansible.builtin.shell',
    'ansible.builtin.command', 'ansible.builtin.debug',
    'ansible.builtin.stat', 'ansible.builtin.service',
    'ansible.builtin.user', 'ansible.builtin.group',
    'ansible.builtin.apt', 'ansible.builtin.yum',
    'ansible.builtin.lineinfile', 'ansible.builtin.uri',
}

# Directory names that indicate Ansible structure
ANSIBLE_DIRECTORIES = {
    'playbooks', 'roles', 'tasks', 'handlers', 'vars',
    'defaults', 'files', 'templates', 'meta', 'group_vars',
    'host_vars', 'inventories', 'inventory',
}

# Ansible filename patterns
ANSIBLE_FILENAME_PATTERNS = {
    'playbook', 'site.yml', 'site.yaml', 'main.yml', 'main.yaml',
    'tasks.yml', 'tasks.yaml', 'handlers.yml', 'handlers.yaml',
    'vars.yml', 'vars.yaml', 'defaults.yml', 'defaults.yaml',
}


# ============================================================================
# FILE TYPE DETECTION
# ============================================================================

class FileType:
    """File type constants."""
    KUBERNETES = "K8S"
    HELM = "HELM"
    ANSIBLE = "ANSIBLE"
    UNKNOWN = "UNKNOWN"


def detect_file_type(file_path: str) -> str:
    """
    Detect if YAML file is Kubernetes, Helm template, or Ansible.

    PRIORITY ORDER (important!):
    1. Ansible - Check FIRST because Ansible also uses {{ }} like Helm
    2. Helm templates (in templates/ or has {{ }} without Ansible keywords)
    3. Kubernetes (apiVersion/kind without {{ }})
    4. Unknown
    """
    try:
        content = Path(file_path).read_text(encoding='utf-8')
        path_obj = Path(file_path)

        # ================================================================
        # STEP 1: Check for ANSIBLE first (before Helm!)
        # ================================================================
        if _is_ansible_content(content, path_obj):
            return FileType.ANSIBLE

        # ================================================================
        # STEP 2: Check for HELM
        # ================================================================
        # Check if in Helm templates directory
        if 'templates' in path_obj.parts and 'ansible' not in str(path_obj).lower():
            return FileType.HELM

        # Check for Chart.yaml or values.yaml
        if path_obj.name in ('Chart.yaml', 'values.yaml'):
            return FileType.HELM

        # Check for Helm template syntax ({{ }}) - but only if NOT Ansible
        if '{{' in content and '}}' in content:
            # Double-check it's not Ansible that slipped through
            if not _has_ansible_indicators(content):
                return FileType.HELM

        # ================================================================
        # STEP 3: Check for KUBERNETES
        # ================================================================
        if 'apiVersion:' in content and 'kind:' in content:
            return FileType.KUBERNETES

        # ================================================================
        # STEP 4: Unknown
        # ================================================================
        return FileType.UNKNOWN

    except Exception:
        return FileType.UNKNOWN


def _is_ansible_content(content: str, path: Path) -> bool:
    """
    Check if content is an Ansible playbook/role.

    This checks multiple indicators to be sure.
    """
    path_str = str(path).lower()

    # Check 1: Directory structure
    for ansible_dir in ANSIBLE_DIRECTORIES:
        if f'/{ansible_dir}/' in path_str or f'\\{ansible_dir}\\' in path_str:
            return True
        if path_str.endswith(f'/{ansible_dir}') or path_str.endswith(f'\\{ansible_dir}'):
            return True

    # Check 2: Filename patterns
    filename_lower = path.name.lower()
    if 'ansible' in filename_lower or 'playbook' in filename_lower:
        return True

    # Check 3: Content indicators
    if _has_ansible_indicators(content):
        return True

    return False


def _has_ansible_indicators(content: str) -> bool:
    """
    Check if content has Ansible-specific indicators.

    Returns True if content looks like Ansible.
    """
    content_lower = content.lower()
    lines = content.split('\n')

    ansible_keyword_count = 0
    ansible_module_count = 0

    for line in lines:
        stripped = line.strip()
        if not stripped or stripped.startswith('#'):
            continue

        # Check for Ansible keywords at line start
        for keyword in ANSIBLE_KEYWORDS:
            # Pattern: "keyword:" at start of line or after "- "
            if stripped.startswith(f'{keyword}:') or \
               stripped.startswith(f'- {keyword}:') or \
               f' {keyword}:' in stripped:
                ansible_keyword_count += 1
                if ansible_keyword_count >= 2:  # Found 2+ keywords = Ansible
                    return True

        # Check for Ansible modules
        for module in ANSIBLE_MODULES:
            if f'{module}:' in stripped:
                ansible_module_count += 1
                if ansible_module_count >= 1:  # Found any module = Ansible
                    return True

    # Special check: "- name:" followed by module is very Ansible-specific
    if '- name:' in content_lower:
        # Check if there's also a module following it
        for module in ANSIBLE_MODULES:
            if f'{module}:' in content:
                return True

    # Check for "hosts:" at root level (playbook indicator)
    for line in lines:
        stripped = line.strip()
        if stripped.startswith('- hosts:') or stripped == 'hosts:' or \
           (stripped.startswith('hosts:') and not line.startswith(' ')):
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
                 verbose: bool = False,
                 use_colors: bool = True):
        self.use_yamllint = use_yamllint
        self.use_quote_validator = use_quote_validator
        self.verbose = verbose
        self.use_colors = use_colors

        # Initialize validators
        self.yamllint_validator = None
        self.quote_validator = None

        if use_yamllint:
            self.yamllint_validator = YamlLintValidator()

        if use_quote_validator:
            try:
                from unified_validator import UnifiedQuoteValidator
                self.quote_validator = UnifiedQuoteValidator()
            except ImportError:
                if verbose:
                    print("Warning: Could not import UnifiedQuoteValidator")

    def _color(self, text: str, color: str) -> str:
        """Apply color to text if colors are enabled."""
        if self.use_colors:
            return f"{color}{text}{Colors.RESET}"
        return text

    def _print_error(self, message: str):
        """Print error message with red color."""
        print(self._color(f"[ERROR] {message}", Colors.RED))

    def _print_warning(self, message: str):
        """Print warning message with yellow color."""
        print(self._color(f"[WARNING] {message}", Colors.YELLOW))

    def _print_info(self, message: str):
        """Print info message with cyan color."""
        print(self._color(f"[INFO] {message}", Colors.CYAN))

    def _print_success(self, message: str):
        """Print success message with green color."""
        print(self._color(f"[OK] {message}", Colors.GREEN))

    def _print_section(self, title: str):
        """Print section header."""
        print(f"\n{self._color('>', Colors.CYAN)} {self._color(title, Colors.BOLD)}")
        print(self._color("-" * 80, Colors.CYAN))

    def validate_files(self, file_paths: List[str]) -> int:
        """Validate multiple files and return exit code."""
        total_errors = 0

        for file_path in file_paths:
            file_type = detect_file_type(file_path)

            print(f"\n{self._color('File:', Colors.BOLD)} {file_path}")
            print(f"{self._color('Type:', Colors.BOLD)} {self._color(file_type, Colors.MAGENTA)}")
            print(self._color("=" * 80, Colors.BLUE))

            result = self._validate_with_router(file_path, file_type)

            if not result.is_valid:
                total_errors += result.error_count

        print("\n" + self._color("=" * 80, Colors.BLUE))
        status_color = Colors.RED if total_errors > 0 else Colors.GREEN
        print(self._color(f"TOTAL: {len(file_paths)} file(s), {total_errors} error(s)", status_color))
        print(self._color("=" * 80, Colors.BLUE))

        return 1 if total_errors > 0 else 0

    def _validate_with_router(self, file_path: str, file_type: str) -> ValidationResult:
        """Route to appropriate validators based on file type."""
        all_issues = []

        # ================================================================
        # ANSIBLE - Skip all validation here, ansible-lint handles it
        # ================================================================
        if file_type == FileType.ANSIBLE:
            self._print_section("Ansible Detected")
            self._print_info("Skipping yaml-router validation for Ansible files.")
            self._print_info("Ansible-Lint (WSL hook) will handle this file separately.")
            print(self._color("-" * 80, Colors.CYAN))
            self._print_success("Passed to ansible-lint")

            # Return valid so yaml-router doesn't fail
            return ValidationResult(
                file_path=file_path,
                is_valid=True,
                issues=[],
                error_count=0
            )

        # ================================================================
        # YAMLlint - for K8S, Helm, and Unknown (NOT Ansible!)
        # ================================================================
        if self.yamllint_validator:
            self._print_section("YAMLlint")
            yamllint_result = self.yamllint_validator.validate_file(file_path)
            if yamllint_result.issues:
                all_issues.extend(yamllint_result.issues)
                for issue in yamllint_result.issues:
                    self._print_error(issue.message)
                    if hasattr(issue, 'field_path') and issue.field_path:
                        print(f"   {self._color('Rule:', Colors.YELLOW)} {issue.field_path}")
                    print()
            else:
                self._print_success("No issues found")

        # ================================================================
        # Quote Validator - ONLY for K8S and Helm
        # ================================================================
        if self.quote_validator and file_type in (FileType.KUBERNETES, FileType.HELM):
            self._print_section("Quote Validator")
            quote_result = self.quote_validator.validate_file(file_path)
            if quote_result.issues:
                all_issues.extend(quote_result.issues)
                for issue in quote_result.issues:
                    self._print_error(f"Line {issue.line_number}: {issue.message}")
                    print(f"   {self._color('PATH:', Colors.YELLOW)}     {issue.field_path}")
                    print(f"   {self._color('CURRENT:', Colors.YELLOW)}  {issue.line_content.strip()}")
                    print(f"   {self._color('EXPECTED:', Colors.YELLOW)} {issue.suggestion}")
                    print()
            else:
                self._print_success("No issues found")

        # ================================================================
        # Summary
        # ================================================================
        print(self._color("-" * 80, Colors.CYAN))
        summary_color = Colors.RED if len(all_issues) > 0 else Colors.GREEN
        print(self._color(f"Summary: {len(all_issues)} error(s)", summary_color))

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
# MAIN
# ============================================================================

def main():
    import argparse

    parser = argparse.ArgumentParser(
        description='YAML Router - Routes to appropriate validators',
        epilog='''
Validation Strategy:
  K8S/Helm:  YAMLlint + Quote Validator
  Ansible:   SKIP (handled by ansible-lint separately)
  Unknown:   YAMLlint only
        '''
    )
    parser.add_argument('files', nargs='+', help='YAML files to validate')
    parser.add_argument('-v', '--verbose', action='store_true', help='Verbose output')
    parser.add_argument('--no-yamllint', action='store_true', help='Disable yamllint')
    parser.add_argument('--no-quotes', action='store_true', help='Disable quote validator')
    parser.add_argument('--no-color', action='store_true', help='Disable colored output')

    args = parser.parse_args()

    router = YamlRouter(
        use_yamllint=not args.no_yamllint,
        use_quote_validator=not args.no_quotes,
        verbose=args.verbose,
        use_colors=not args.no_color
    )

    exit_code = router.validate_files(args.files)
    sys.exit(exit_code)


if __name__ == '__main__':
    main()