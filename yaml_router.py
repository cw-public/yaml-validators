#!/usr/bin/env python3
"""
YAML Router - Unified Entry Point for YAML Validation

- YAMLlint for all files (except Helm Templates)
- Auto-detects: Helm Charts, K8s Manifests, Ansible Playbooks
- Routes to appropriate validator

This is the SINGLE source of truth for file type detection.
Validators should NOT contain detection logic.
"""

import re
import sys
import os
import subprocess
import argparse
from pathlib import Path
from ruamel.yaml import YAML

# YAMLlint Import
from yamllint import linter
from yamllint.config import YamlLintConfig

# Force UTF-8 encoding on Windows
if sys.platform == 'win32':
    os.environ['PYTHONIOENCODING'] = 'utf-8'

# Terminal width for separator lines
TERMINAL_WIDTH = 80


# ============================================================================
# RELATIVE IMPORTS FOR PRE-COMMIT COMPATIBILITY
# ============================================================================

def _import_shared_constants():
    """Import shared_constants with fallback for different installation methods."""
    try:
        from shared_constants import (
            Severity, ValidationResult,
            HELM_DETECTION_PATTERNS, ANSIBLE_KEYWORDS, ANSIBLE_MODULES, ANSIBLE_DIRECTORIES,
            is_helm_template_content,
        )
        return (Severity, ValidationResult, HELM_DETECTION_PATTERNS, 
                ANSIBLE_KEYWORDS, ANSIBLE_MODULES, ANSIBLE_DIRECTORIES, is_helm_template_content)
    except ImportError:
        pass
    
    # Fallback: Load from same directory
    import importlib.util
    spec = importlib.util.spec_from_file_location(
        "shared_constants",
        Path(__file__).parent / "shared_constants.py"
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return (module.Severity, module.ValidationResult, module.HELM_DETECTION_PATTERNS,
            module.ANSIBLE_KEYWORDS, module.ANSIBLE_MODULES, module.ANSIBLE_DIRECTORIES,
            module.is_helm_template_content)

(Severity, ValidationResult, HELM_DETECTION_PATTERNS, 
 ANSIBLE_KEYWORDS, ANSIBLE_MODULES, ANSIBLE_DIRECTORIES, 
 is_helm_template_content) = _import_shared_constants()


def _import_validators():
    """Import validators with fallback for different installation methods."""
    k8s_validator = None
    helm_validator = None
    
    # Try direct import
    try:
        from kubernetes_validator import KubernetesQuoteValidator
        k8s_validator = KubernetesQuoteValidator
    except ImportError:
        pass
    
    try:
        from helm_validator import HelmValidator
        helm_validator = HelmValidator
    except ImportError:
        pass
    
    # Fallback: Load from same directory
    if k8s_validator is None:
        import importlib.util
        spec = importlib.util.spec_from_file_location(
            "kubernetes_validator",
            Path(__file__).parent / "kubernetes_validator.py"
        )
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        k8s_validator = module.KubernetesQuoteValidator
    
    if helm_validator is None:
        import importlib.util
        spec = importlib.util.spec_from_file_location(
            "helm_validator",
            Path(__file__).parent / "helm_validator.py"
        )
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        helm_validator = module.HelmValidator
    
    return k8s_validator, helm_validator

KubernetesQuoteValidator, HelmValidator = _import_validators()


# ============================================================================
# ANSI COLOR CODES
# ============================================================================

class Colors:
    """ANSI color codes for terminal output."""
    
    FORCE_COLOR = os.environ.get('FORCE_COLOR') is not None or os.environ.get('PRE_COMMIT') is not None
    ENABLED = FORCE_COLOR or (sys.stdout.isatty() and os.environ.get('NO_COLOR') is None)
    
    RED = '\033[91m' if ENABLED else ''
    YELLOW = '\033[93m' if ENABLED else ''
    GREEN = '\033[92m' if ENABLED else ''
    CYAN = '\033[96m' if ENABLED else ''
    WHITE = '\033[97m' if ENABLED else ''
    BOLD = '\033[1m' if ENABLED else ''
    RESET = '\033[0m' if ENABLED else ''
    
    @classmethod
    def red(cls, text: str) -> str:
        return f"{cls.RED}{text}{cls.RESET}"
    
    @classmethod
    def yellow(cls, text: str) -> str:
        return f"{cls.YELLOW}{text}{cls.RESET}"
    
    @classmethod
    def green(cls, text: str) -> str:
        return f"{cls.GREEN}{text}{cls.RESET}"
    
    @classmethod
    def cyan(cls, text: str) -> str:
        return f"{cls.CYAN}{text}{cls.RESET}"
    
    @classmethod
    def bold(cls, text: str) -> str:
        return f"{cls.BOLD}{text}{cls.RESET}"
    
    @classmethod
    def enable(cls):
        cls.ENABLED = True
        cls.RED = '\033[91m'
        cls.YELLOW = '\033[93m'
        cls.GREEN = '\033[92m'
        cls.CYAN = '\033[96m'
        cls.WHITE = '\033[97m'
        cls.BOLD = '\033[1m'
        cls.RESET = '\033[0m'
    
    @classmethod
    def disable(cls):
        cls.ENABLED = False
        cls.RED = ''
        cls.YELLOW = ''
        cls.GREEN = ''
        cls.CYAN = ''
        cls.WHITE = ''
        cls.BOLD = ''
        cls.RESET = ''


# ============================================================================
# OUTPUT FORMATTER
# ============================================================================

class OutputFormatter:
    """Unified output formatting for all validators."""
    
    def __init__(self, width: int = 80):
        self.width = width
    
    def print_file_header(self, filepath: str, file_type: str):
        print(f"\n{'=' * self.width}")
        print(f"File: {filepath}")
        print(f"Type: {file_type.upper()}")
        print(f"{'=' * self.width}")
    
    def print_section_separator(self):
        print(f"\n{'-' * self.width}\n")
    
    def print_section_header(self, title: str):
        print(f"> {title}")
        print(f"{'-' * self.width}")
    
    def print_issue(self, line_num: int, column: int, message: str, 
                    current: str, suggestion: str, severity: str = "ERROR"):
        if severity.upper() == "ERROR":
            severity_str = Colors.red("[ERROR]")
        elif severity.upper() == "WARNING":
            severity_str = Colors.yellow("[WARNING]")
        else:
            severity_str = f"[{severity.upper()}]"
        
        if column > 0:
            print(f"{severity_str} Line {line_num}, Column {column}: {message}")
        else:
            print(f"{severity_str} Line {line_num}: {message}")
        
        if current and suggestion:
            print(f"   CURRENT:  {current.strip()}")
            print(f"   EXPECTED: {suggestion.strip()}")
        
        print()
    
    def print_yamllint_issue(self, filepath: str, line: int, column: int, 
                             rule: str, message: str, level: str):
        if level == "error":
            severity_str = Colors.red("[ERROR]")
        else:
            severity_str = Colors.yellow("[WARNING]")
        
        print(f"{severity_str} Line {line}, Column {column}: {message} ({rule})")
        print(f"   Rule: {rule}")
        print()
    
    def print_summary(self, errors: int, warnings: int, infos: int = 0):
        print(f"{'-' * self.width}")
        if errors == 0 and warnings == 0:
            print(Colors.green("OK - No issues found"))
        else:
            parts = []
            if errors > 0:
                parts.append(Colors.red(f"{errors} error(s)"))
            if warnings > 0:
                parts.append(Colors.yellow(f"{warnings} warning(s)"))
            if infos > 0:
                parts.append(f"{infos} info(s)")
            print(f"Summary: {', '.join(parts)}")
        print()
    
    def print_skip_message(self, message: str):
        print(f"SKIPPED: {message}")
        print()
    
    def print_ok_message(self, message: str):
        print(Colors.green(f"OK - {message}"))
        print()


formatter = OutputFormatter(TERMINAL_WIDTH)


# ============================================================================
# YAMLLINT VALIDATOR
# ============================================================================

class YamlLintValidator:
    """YAMLlint integration."""
    
    DEFAULT_CONFIG = """
extends: default

rules:
  line-length:
    max: 160
    allow-non-breakable-words: true
    allow-non-breakable-inline-mappings: true
  indentation:
    spaces: 2
    indent-sequences: true
  truthy:
    allowed-values: ['true', 'false', 'yes', 'no']
  comments:
    min-spaces-from-content: 1
  document-start:
    present: false
  trailing-spaces: enable
  new-line-at-end-of-file: enable
  empty-lines:
    max: 2
  brackets:
    min-spaces-inside: 0
    max-spaces-inside: 1
  braces:
    min-spaces-inside: 0
    max-spaces-inside: 1
"""
    
    def __init__(self, config_file: str = None, verbose: bool = False):
        self.verbose = verbose
        self.config = self._load_config(config_file)
    
    def _load_config(self, config_file: str = None) -> YamlLintConfig:
        if config_file and Path(config_file).exists():
            return YamlLintConfig(file=config_file)
        
        search_paths = [
            Path.cwd() / '.yamllint.yaml',
            Path.cwd() / '.yamllint.yml',
            Path.cwd() / '.yamllint',
            Path.home() / '.yamllint.yaml',
        ]
        
        for path in search_paths:
            if path.exists():
                return YamlLintConfig(file=str(path))
        
        return YamlLintConfig(content=self.DEFAULT_CONFIG)
    
    def validate(self, filepath: str, content: str = None, print_output: bool = True) -> dict:
        file_path = Path(filepath)
        
        if content is None:
            if not file_path.exists():
                return {
                    "success": False, "file": filepath,
                    "errors": [{"line": 0, "column": 0, "rule": "file", "message": f"File not found: {filepath}", "level": "error"}],
                    "warnings": [],
                }
            
            try:
                content = file_path.read_text(encoding='utf-8')
            except Exception as e:
                return {
                    "success": False, "file": filepath,
                    "errors": [{"line": 0, "column": 0, "rule": "file", "message": f"Cannot read file: {e}", "level": "error"}],
                    "warnings": [],
                }
        
        errors = []
        warnings = []
        
        try:
            problems = linter.run(content, self.config, filepath)
            
            for problem in problems:
                issue = {
                    "line": problem.line,
                    "column": problem.column,
                    "rule": problem.rule,
                    "message": problem.message,
                    "level": problem.level
                }
                
                if problem.level == 'error':
                    errors.append(issue)
                else:
                    warnings.append(issue)
            
            if print_output and (errors or warnings):
                formatter.print_section_header("YAMLlint")
                
                for issue in errors + warnings:
                    formatter.print_yamllint_issue(
                        filepath, issue["line"], issue["column"],
                        issue["rule"], issue["message"], issue["level"]
                    )
            
            return {"success": len(errors) == 0, "file": filepath, "errors": errors, "warnings": warnings}
            
        except Exception as e:
            return {
                "success": False, "file": filepath,
                "errors": [{"line": 0, "column": 0, "rule": "exception", "message": str(e), "level": "error"}],
                "warnings": [],
            }


# ============================================================================
# FILE TYPE DETECTION (SINGLE SOURCE OF TRUTH)
# ============================================================================

class FileTypeDetector:
    """
    Detects file type: Helm Template, K8s Manifest, Ansible, or Generic YAML.
    
    THIS IS THE SINGLE SOURCE OF TRUTH FOR FILE TYPE DETECTION.
    Validators should NOT contain their own detection logic.
    """
    
    @classmethod
    def is_helm_template(cls, content: str, file_path: Path) -> bool:
        """Check if file is a Helm template."""
        if is_helm_template_content(content):
            return True
        
        path_str = str(file_path).replace('\\', '/')
        if '/templates/' in path_str:
            current = file_path.parent
            for _ in range(5):
                if (current / 'Chart.yaml').exists():
                    return True
                current = current.parent
        
        return False
    
    @classmethod
    def is_k8s_manifest(cls, data: dict) -> bool:
        """Check if file is a Kubernetes manifest."""
        if not isinstance(data, dict):
            return False
        return 'apiVersion' in data and 'kind' in data
    
    @classmethod
    def is_ansible_file(cls, data, file_path: Path) -> bool:
        """Check if file is an Ansible playbook/role/task."""
        path_str = str(file_path).replace('\\', '/').lower()
        in_ansible_dir = any(d in path_str for d in ANSIBLE_DIRECTORIES)
        
        filename_lower = file_path.name.lower()
        
        if isinstance(data, list) and len(data) > 0:
            first_item = data[0]
            if isinstance(first_item, dict):
                if 'hosts' in first_item or 'tasks' in first_item:
                    return True
                
                if 'name' in first_item:
                    for module in ANSIBLE_MODULES:
                        if module in first_item:
                            return True
        
        if isinstance(data, dict):
            ansible_keys = set(data.keys()) & set(ANSIBLE_KEYWORDS)
            if len(ansible_keys) >= 2:
                return True
        
        if 'ansible' in filename_lower:
            return True
        
        if in_ansible_dir:
            if isinstance(data, (list, dict)):
                return True
        
        return False
    
    @classmethod
    def detect(cls, file_path: Path, content: str, data) -> str:
        """Detect file type. Returns: 'helm', 'k8s', 'ansible', or 'generic'"""
        if cls.is_helm_template(content, file_path):
            return 'helm'
        
        if isinstance(data, dict) and cls.is_k8s_manifest(data):
            return 'k8s'
        
        if cls.is_ansible_file(data, file_path):
            return 'ansible'
        
        return 'generic'
    
    @classmethod
    def find_helm_structure(cls, file_path: Path) -> tuple:
        """Find Helm chart structure. Returns: (chart_yaml_path, values_source) or (None, None)"""
        current = file_path.parent
        
        for _ in range(10):
            chart_yaml = current / 'Chart.yaml'
            if chart_yaml.exists():
                values_dir = current / 'values'
                values_file = current / 'values.yaml'
                
                if values_dir.exists() and values_dir.is_dir():
                    return (chart_yaml, values_dir)
                elif values_file.exists():
                    return (chart_yaml, values_file)
                else:
                    return (chart_yaml, None)
            
            if current.parent == current:
                break
            current = current.parent
        
        return (None, None)


# ============================================================================
# HELM VALUES LOADER
# ============================================================================

class HelmValuesLoader:
    """Loads Helm values and extracts type information."""
    
    def __init__(self):
        self.yaml = YAML()
        self.yaml.preserve_quotes = True
    
    def load_type_map(self, values_source: Path) -> dict:
        type_map = {}
        
        if values_source is None:
            return type_map
        
        if values_source.is_file():
            type_map = self._extract_types_from_file(values_source)
        elif values_source.is_dir():
            for yaml_file in values_source.glob('*.yaml'):
                type_map.update(self._extract_types_from_file(yaml_file))
            for yml_file in values_source.glob('*.yml'):
                type_map.update(self._extract_types_from_file(yml_file))
        
        return type_map
    
    def _extract_types_from_file(self, filepath: Path) -> dict:
        type_map = {}
        
        try:
            content = filepath.read_text(encoding='utf-8')
            data = self.yaml.load(content)
            
            if isinstance(data, dict):
                self._extract_types_recursive(data, "", type_map)
        except Exception:
            pass
        
        return type_map
    
    def _extract_types_recursive(self, data: dict, prefix: str, type_map: dict):
        for key, value in data.items():
            full_key = f"{prefix}.{key}" if prefix else key
            
            if isinstance(value, bool):
                type_map[full_key] = "bool"
                type_map[key] = "bool"
            elif isinstance(value, int):
                type_map[full_key] = "int"
                type_map[key] = "int"
            elif isinstance(value, float):
                type_map[full_key] = "float"
                type_map[key] = "float"
            elif isinstance(value, str):
                type_map[full_key] = "string"
                type_map[key] = "string"
            elif isinstance(value, dict):
                type_map[full_key] = "dict"
                self._extract_types_recursive(value, full_key, type_map)
            elif isinstance(value, list):
                type_map[full_key] = "list"
                type_map[key] = "list"


# ============================================================================
# ANSIBLE VALIDATOR (WSL)
# ============================================================================

class AnsibleValidator:
    """Ansible Lint via WSL."""
    
    def __init__(self, verbose: bool = False):
        self.verbose = verbose
        self.wsl_available = self._check_wsl()
        self.ansible_lint_cmd = self._find_ansible_lint() if self.wsl_available else None
    
    def _check_wsl(self) -> bool:
        if sys.platform != 'win32':
            return False
        try:
            result = subprocess.run(['wsl', '--status'], capture_output=True, timeout=5)
            return result.returncode == 0
        except Exception:
            return False
    
    def _find_ansible_lint(self) -> str:
        try:
            result = subprocess.run(
                ['wsl', 'bash', '-l', '-c', 'which ansible-lint'],
                capture_output=True, text=True, timeout=10
            )
            if result.returncode == 0 and result.stdout.strip():
                return result.stdout.strip()
            return None
        except Exception:
            return None
    
    def _windows_to_wsl_path(self, windows_path: str) -> str:
        path = str(Path(windows_path).absolute()).replace('\\', '/')
        if len(path) >= 2 and path[1] == ':':
            drive = path[0].lower()
            path = f'/mnt/{drive}{path[2:]}'
        return path
    
    def validate(self, filepath: str, print_output: bool = True) -> dict:
        if not self.wsl_available:
            if print_output:
                formatter.print_section_header("Ansible-Lint")
                formatter.print_skip_message("WSL not available - skipping ansible-lint")
            return {"success": True, "file": filepath, "type": "ansible", "skipped": True, "errors": [], "warnings": []}
        
        if not self.ansible_lint_cmd:
            if print_output:
                formatter.print_section_header("Ansible-Lint")
                formatter.print_skip_message("ansible-lint not found in WSL")
            return {"success": True, "file": filepath, "type": "ansible", "skipped": True, "errors": [], "warnings": []}
        
        wsl_path = self._windows_to_wsl_path(filepath)
        
        try:
            cmd = f'{self.ansible_lint_cmd} -p --nocolor "{wsl_path}"'
            result = subprocess.run(['wsl', 'bash', '-l', '-c', cmd], capture_output=True, text=True, timeout=120)
            
            errors = []
            warnings = []
            output = result.stdout + result.stderr
            
            if print_output and output.strip():
                formatter.print_section_header("Ansible-Lint")
            
            for line in output.split('\n'):
                line = line.strip()
                if not line or ':' not in line:
                    continue
                
                match = re.match(r'.*?:(\d+):(\d*):?\s*(.*)', line)
                if match:
                    line_num = int(match.group(1))
                    col = int(match.group(2)) if match.group(2) else 0
                    msg = match.group(3)
                    
                    issue = {"line": line_num, "column": col, "message": msg}
                    is_error = any(x in line.lower() for x in ['error', 'fatal', 'syntax-check'])
                    
                    if is_error:
                        errors.append(issue)
                        if print_output:
                            print(f"{Colors.red('[ERROR]')} Line {line_num}, Column {col}: {msg}\n")
                    else:
                        warnings.append(issue)
                        if print_output:
                            print(f"{Colors.yellow('[WARNING]')} Line {line_num}, Column {col}: {msg}\n")
            
            return {"success": result.returncode == 0, "file": filepath, "type": "ansible", "errors": errors, "warnings": warnings}
            
        except subprocess.TimeoutExpired:
            return {"success": False, "file": filepath, "errors": [{"line": 0, "column": 0, "message": "ansible-lint timeout"}], "warnings": []}
        except Exception as e:
            return {"success": False, "file": filepath, "errors": [{"line": 0, "column": 0, "message": str(e)}], "warnings": []}


# ============================================================================
# YAML ROUTER (UNIFIED VALIDATOR)
# ============================================================================

class YamlRouter:
    """Unified Entry Point - YAMLlint + type-specific validation."""
    
    def __init__(self, verbose: bool = False, skip_ansible: bool = False,
                 skip_yamllint: bool = False, yamllint_config: str = None,
                 strict: bool = False, level: str = 'warning'):
        self.verbose = verbose
        self.skip_ansible = skip_ansible
        self.skip_yamllint = skip_yamllint
        self.strict = strict
        self.level = level
        
        self.yaml = YAML()
        self.yaml.preserve_quotes = True
        
        self.yamllint = None if skip_yamllint else YamlLintValidator(config_file=yamllint_config, verbose=verbose)
        self.values_loader = HelmValuesLoader()
        self._ansible_validator = None
    
    @property
    def ansible_validator(self):
        if self._ansible_validator is None:
            self._ansible_validator = AnsibleValidator(verbose=self.verbose)
        return self._ansible_validator
    
    def validate(self, filepath: str) -> dict:
        file_path = Path(filepath)
        
        if not file_path.exists():
            return {"success": False, "file": filepath, "type": "unknown",
                    "errors": [{"line": 0, "column": 0, "message": f"File not found: {filepath}"}], "warnings": []}
        
        try:
            content = file_path.read_text(encoding='utf-8')
        except Exception as e:
            return {"success": False, "file": filepath, "type": "unknown",
                    "errors": [{"line": 0, "column": 0, "message": f"Cannot read file: {e}"}], "warnings": []}
        
        is_helm = FileTypeDetector.is_helm_template(content, file_path)
        
        data = None
        parse_error = None
        try:
            data = self.yaml.load(content)
        except Exception as e:
            if not is_helm:
                parse_error = str(e)
            data = {}
        
        file_type = FileTypeDetector.detect(file_path, content, data)
        
        formatter.print_file_header(filepath, file_type)
        
        if parse_error:
            print(f"{Colors.red('[ERROR]')} YAML Parse Error: {parse_error}\n")
            return {"success": False, "file": filepath, "type": file_type,
                    "errors": [{"line": 0, "column": 0, "message": f"YAML Parse Error: {parse_error}"}], "warnings": []}
        
        total_errors = []
        total_warnings = []
        
        if self.yamllint and not is_helm:
            yamllint_result = self.yamllint.validate(filepath, content, print_output=True)
            total_errors.extend(yamllint_result.get('errors', []))
            total_warnings.extend(yamllint_result.get('warnings', []))
            
            if file_type in ('k8s', 'helm', 'ansible'):
                formatter.print_section_separator()
        
        if file_type == 'helm':
            type_result = self._validate_helm(filepath, content, file_path)
        elif file_type == 'k8s':
            type_result = self._validate_k8s(filepath)
        elif file_type == 'ansible':
            type_result = self._validate_ansible(filepath)
        else:
            type_result = {"errors": [], "warnings": [], "skipped": False}
        
        total_errors.extend(type_result.get('errors', []))
        total_warnings.extend(type_result.get('warnings', []))
        
        formatter.print_summary(len(total_errors), len(total_warnings))
        
        return {"success": len(total_errors) == 0, "file": filepath, "type": file_type,
                "errors": total_errors, "warnings": total_warnings, "skipped": type_result.get('skipped', False)}
    
    def _validate_helm(self, filepath: str, content: str, file_path: Path) -> dict:
        formatter.print_section_header("Helm Template Validator")
        
        try:
            chart_yaml, values_source = FileTypeDetector.find_helm_structure(file_path)
            
            type_map = {}
            if values_source:
                type_map = self.values_loader.load_type_map(values_source)
                if self.verbose:
                    print(f"   Loaded {len(type_map)} type mappings from values")
            
            validator = HelmValidator(type_map=type_map, strict=self.strict)
            is_valid, errors = validator.validate_content(content, filepath)
            
            error_list = []
            warning_list = []
            
            for error in errors:
                issue = {"line": error.line_num, "column": 0, "message": error.message,
                         "current": error.actual, "suggestion": error.expected, "severity": error.severity.value}
                
                if error.severity.value == 'error':
                    error_list.append(issue)
                else:
                    warning_list.append(issue)
                
                formatter.print_issue(error.line_num, 0, error.message, error.actual, error.expected, error.severity.value)
            
            if not errors:
                formatter.print_ok_message("No Helm template issues found")
            
            return {"success": is_valid, "file": filepath, "type": "helm", "errors": error_list, "warnings": warning_list}
            
        except Exception as e:
            print(f"{Colors.red('[ERROR]')} Helm validation error: {e}\n")
            return {"success": False, "file": filepath, "type": "helm",
                    "errors": [{"line": 0, "column": 0, "message": str(e)}], "warnings": []}
    
    def _validate_k8s(self, filepath: str) -> dict:
        formatter.print_section_header("Kubernetes Quote Validator")
        
        try:
            validator = KubernetesQuoteValidator(strict=self.strict, level=self.level)
            result = validator.validate_file(filepath)
            
            error_list = []
            warning_list = []
            
            for issue in result.issues:
                issue_dict = {"line": issue.line_number, "column": 0, "message": issue.message,
                              "current": issue.line_content, "suggestion": issue.suggestion, "severity": issue.severity.value}
                
                if issue.severity == Severity.ERROR:
                    error_list.append(issue_dict)
                else:
                    warning_list.append(issue_dict)
                
                formatter.print_issue(issue.line_number, 0, issue.message, issue.line_content, issue.suggestion, issue.severity.value)
            
            if not result.issues:
                formatter.print_ok_message("No Kubernetes quote issues found")
            
            return {"success": result.is_valid, "file": filepath, "type": "k8s", "errors": error_list, "warnings": warning_list}
            
        except Exception as e:
            print(f"{Colors.red('[ERROR]')} K8s validation error: {e}\n")
            return {"success": False, "file": filepath, "type": "k8s",
                    "errors": [{"line": 0, "column": 0, "message": str(e)}], "warnings": []}
    
    def _validate_ansible(self, filepath: str) -> dict:
        if self.skip_ansible:
            formatter.print_section_header("Ansible-Lint")
            formatter.print_skip_message("Ansible validation skipped (--skip-ansible)")
            return {"success": True, "file": filepath, "type": "ansible", "skipped": True, "errors": [], "warnings": []}
        
        return self.ansible_validator.validate(filepath, print_output=True)


# ============================================================================
# MAIN
# ============================================================================

def main():
    parser = argparse.ArgumentParser(description='YAML Router - Helm, K8s, Ansible Validator with YAMLlint')
    parser.add_argument('files', nargs='+', help='YAML files to validate')
    parser.add_argument('-v', '--verbose', action='store_true', help='Verbose output')
    parser.add_argument('--skip-ansible', action='store_true', help='Skip Ansible validation')
    parser.add_argument('--skip-yamllint', action='store_true', help='Skip YAMLlint validation')
    parser.add_argument('--yamllint-config', type=str, default=None, help='Path to yamllint config')
    parser.add_argument('--strict', action='store_true', help='Treat warnings as errors')
    parser.add_argument('--level', choices=['error', 'warning', 'info'], default='warning', help='Minimum severity level')
    parser.add_argument('--no-color', action='store_true', help='Disable colored output')
    parser.add_argument('--force-color', action='store_true', help='Force colored output')
    
    args = parser.parse_args()
    
    if args.force_color:
        Colors.enable()
    elif args.no_color:
        Colors.disable()
    
    router = YamlRouter(
        verbose=args.verbose,
        skip_ansible=args.skip_ansible,
        skip_yamllint=args.skip_yamllint,
        yamllint_config=args.yamllint_config,
        strict=args.strict,
        level=args.level,
    )
    
    exit_code = 0
    total_errors = 0
    total_warnings = 0
    
    for filepath in args.files:
        result = router.validate(filepath)
        
        if not result.get('success'):
            exit_code = 1
        
        total_errors += len(result.get('errors', []))
        total_warnings += len(result.get('warnings', []))
    
    if len(args.files) > 1:
        print(f"\n{'=' * TERMINAL_WIDTH}")
        summary_parts = [f"{len(args.files)} file(s)"]
        summary_parts.append(Colors.red(f"{total_errors} error(s)") if total_errors > 0 else f"{total_errors} error(s)")
        summary_parts.append(Colors.yellow(f"{total_warnings} warning(s)") if total_warnings > 0 else f"{total_warnings} warning(s)")
        print(f"TOTAL: {', '.join(summary_parts)}")
        print(f"{'=' * TERMINAL_WIDTH}")
    
    sys.exit(exit_code)


if __name__ == '__main__':
    main()