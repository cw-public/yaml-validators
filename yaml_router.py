#!/usr/bin/env python3
"""
YAML Router - Unified Entry Point for YAML Validation

- YAMLlint for ALL files (with Helm trimming when {{ }} present)
- Auto-detects: Helm Charts, K8s Manifests, Ansible Playbooks
- Routes to Unified Quote Validator

This is the SINGLE source of truth for file type detection.
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


def _import_unified_validator():
    """Import UnifiedQuoteValidator with fallback."""
    try:
        from unified_validator import UnifiedQuoteValidator
        return UnifiedQuoteValidator
    except ImportError:
        pass
    
    import importlib.util
    spec = importlib.util.spec_from_file_location(
        "unified_validator",
        Path(__file__).parent / "unified_validator.py"
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.UnifiedQuoteValidator

UnifiedQuoteValidator = _import_unified_validator()


def _import_helm_trimmer():
    """Import HelmTrimmer with fallback."""
    try:
        from helm_trimmer import trim_helm_for_yamllint
        return trim_helm_for_yamllint
    except ImportError:
        pass
    
    import importlib.util
    spec = importlib.util.spec_from_file_location(
        "helm_trimmer",
        Path(__file__).parent / "helm_trimmer.py"
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.trim_helm_for_yamllint

trim_helm_for_yamllint = _import_helm_trimmer()


# ============================================================================
# ANSI COLOR CODES
# ============================================================================

class Colors:
    """ANSI color codes for terminal output."""
    
    FORCE_COLOR = os.environ.get('FORCE_COLOR') is not None or os.environ.get('PRE_COMMIT') is not None
    ENABLED = FORCE_COLOR or (sys.stdout.isatty() and os.environ.get('NO_COLOR') is None)
    
    RED = '\033[91m' if ENABLED else ''
    GREEN = '\033[92m' if ENABLED else ''
    CYAN = '\033[96m' if ENABLED else ''
    BOLD = '\033[1m' if ENABLED else ''
    RESET = '\033[0m' if ENABLED else ''
    
    @classmethod
    def red(cls, text: str) -> str:
        return f"{cls.RED}{text}{cls.RESET}"
    
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
        cls.GREEN = '\033[92m'
        cls.CYAN = '\033[96m'
        cls.BOLD = '\033[1m'
        cls.RESET = '\033[0m'
    
    @classmethod
    def disable(cls):
        cls.ENABLED = False
        cls.RED = ''
        cls.GREEN = ''
        cls.CYAN = ''
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
        print(f"\nFile: {filepath}")
        print(f"Type: {file_type.upper()}")
        print(f"{'=' * self.width}")
    
    def print_section_separator(self):
        print(f"\n{'-' * self.width}\n")
    
    def print_section_header(self, title: str):
        print(f"\n> {title}")
        print(f"{'-' * self.width}")
    
    def print_issue(self, line_num: int, column: int, message: str, 
                    current: str, suggestion: str):
        """Print an issue - ALL issues are errors now."""
        print(f"{Colors.red('[ERROR]')} Line {line_num}: {message}")
        
        if current and suggestion:
            print(f"   CURRENT:  {current.strip()}")
            print(f"   EXPECTED: {suggestion.strip()}")
        
        print()
    
    def print_yamllint_issue(self, filepath: str, line: int, column: int, 
                             rule: str, message: str):
        """Print YAMLlint issue - ALL issues are errors now."""
        print(f"{Colors.red('[ERROR]')} Line {line}, Column {column}: {message} ({rule})")
        print(f"   Rule: {rule}")
        print()
    
    def print_summary(self, errors: int):
        print(f"{'-' * self.width}")
        if errors == 0:
            print(Colors.green("OK - No issues found"))
        else:
            print(f"Summary: {Colors.red(f'{errors} error(s)')}")
        print()
    
    def print_skip_message(self, message: str):
        print(f"SKIPPED: {message}")
        print()
    
    def print_ok_message(self, message: str):
        print(Colors.green(f"OK - {message}"))
        print()


formatter = OutputFormatter(TERMINAL_WIDTH)


# ============================================================================
# YAMLLINT VALIDATOR (with Helm Trimming)
# ============================================================================

class YamlLintValidator:
    """YAMLlint integration with Helm template trimming."""
    
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
    
    def validate(self, filepath: str, content: str = None, 
                 has_helm_syntax: bool = False, print_output: bool = True) -> dict:
        """Validate with YAMLlint (with trimming for Helm)."""
        file_path = Path(filepath)
        
        if content is None:
            if not file_path.exists():
                return {
                    "success": False, "file": filepath,
                    "errors": [{"line": 0, "column": 0, "rule": "file", 
                               "message": f"File not found: {filepath}"}],
                }
            
            try:
                content = file_path.read_text(encoding='utf-8')
            except Exception as e:
                return {
                    "success": False, "file": filepath,
                    "errors": [{"line": 0, "column": 0, "rule": "file", 
                               "message": f"Cannot read file: {e}"}],
                }
        
        # Trim Helm syntax if present
        lint_content = content
        if has_helm_syntax:
            try:
                trim_result = trim_helm_for_yamllint(content)
                lint_content = trim_result.trimmed_content
                if self.verbose:
                    print(f"   [Trimmed {len(trim_result.placeholder_map)} Helm expressions]")
            except Exception as e:
                if self.verbose:
                    print(f"   [Warning: Could not trim Helm syntax: {e}]")
        
        errors = []
        
        try:
            problems = linter.run(lint_content, self.config, filepath)
            
            for problem in problems:
                errors.append({
                    "line": problem.line,
                    "column": problem.column,
                    "rule": problem.rule,
                    "message": problem.message,
                })
            
            if print_output and errors:
                formatter.print_section_header("YAMLlint")
                
                for issue in errors:
                    formatter.print_yamllint_issue(
                        filepath, issue["line"], issue["column"],
                        issue["rule"], issue["message"]
                    )
            
            return {"success": len(errors) == 0, "file": filepath, "errors": errors}
            
        except Exception as e:
            error_msg = str(e)
            # Don't fail on Helm-related parse errors if we tried to trim
            if has_helm_syntax and ('{{' in error_msg or 'expected' in error_msg.lower()):
                if self.verbose:
                    print(f"   [YAMLlint skipped: Complex Helm syntax]")
                return {"success": True, "file": filepath, "errors": [], "skipped": True}
            
            return {
                "success": False, "file": filepath,
                "errors": [{"line": 0, "column": 0, "rule": "exception", 
                           "message": error_msg}],
            }


# ============================================================================
# FILE TYPE DETECTION
# ============================================================================

class FileTypeDetector:
    """Detects file type based on content and location."""
    
    @classmethod
    def is_helm_chart_file(cls, file_path: Path) -> bool:
        """Check if file is part of a Helm chart (in templates/ with Chart.yaml)."""
        path_str = str(file_path).replace('\\', '/')
        
        if '/templates/' not in path_str:
            return False
        
        current = file_path.parent
        for _ in range(10):
            if (current / 'Chart.yaml').exists():
                return True
            if current.parent == current:
                break
            current = current.parent
        
        return False
    
    @classmethod
    def has_helm_syntax(cls, content: str) -> bool:
        """Check if content contains {{ }} syntax."""
        return '{{' in content and '}}' in content
    
    @classmethod
    def has_k8s_structure(cls, content: str) -> bool:
        """Check if content has apiVersion + kind."""
        has_api = bool(re.search(r'^apiVersion:\s*\S+', content, re.MULTILINE))
        has_kind = bool(re.search(r'^kind:\s*\S+', content, re.MULTILINE))
        return has_api and has_kind
    
    @classmethod
    def is_ansible_file(cls, content: str, file_path: Path) -> bool:
        """Check if file is Ansible."""
        path_str = str(file_path).replace('\\', '/').lower()
        in_ansible_dir = any(d in path_str for d in ANSIBLE_DIRECTORIES)
        
        if 'ansible' in file_path.name.lower():
            return True
        
        if 'hosts:' in content and ('tasks:' in content or 'roles:' in content):
            return True
        
        if in_ansible_dir:
            return True
        
        return False
    
    @classmethod
    def detect(cls, file_path: Path, content: str) -> dict:
        """Detect file characteristics."""
        has_helm = cls.has_helm_syntax(content)
        has_k8s = cls.has_k8s_structure(content)
        is_helm_chart = cls.is_helm_chart_file(file_path)
        is_ansible = cls.is_ansible_file(content, file_path)
        
        # Determine primary type for display
        if is_helm_chart:
            if has_k8s:
                file_type = "HELM + K8S"
            else:
                file_type = "HELM"
        elif has_k8s:
            if has_helm:
                file_type = "K8S + GO-TEMPLATE"
            else:
                file_type = "K8S"
        elif is_ansible:
            file_type = "ANSIBLE"
        elif has_helm:
            file_type = "GO-TEMPLATE"
        else:
            file_type = "YAML"
        
        return {
            'file_type': file_type,
            'has_helm_syntax': has_helm,
            'has_k8s_structure': has_k8s,
            'is_helm_chart': is_helm_chart,
            'is_ansible': is_ansible,
        }
    
    @classmethod
    def find_helm_values(cls, file_path: Path) -> Path:
        """Find values.yaml for a Helm chart."""
        current = file_path.parent
        
        for _ in range(10):
            chart_yaml = current / 'Chart.yaml'
            if chart_yaml.exists():
                values_file = current / 'values.yaml'
                if values_file.exists():
                    return values_file
                values_dir = current / 'values'
                if values_dir.exists():
                    return values_dir
            
            if current.parent == current:
                break
            current = current.parent
        
        return None


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
                formatter.print_skip_message("WSL not available")
            return {"success": True, "file": filepath, "skipped": True, "errors": []}
        
        if not self.ansible_lint_cmd:
            if print_output:
                formatter.print_section_header("Ansible-Lint")
                formatter.print_skip_message("ansible-lint not found in WSL")
            return {"success": True, "file": filepath, "skipped": True, "errors": []}
        
        wsl_path = self._windows_to_wsl_path(filepath)
        
        try:
            cmd = f'{self.ansible_lint_cmd} -p --nocolor "{wsl_path}"'
            result = subprocess.run(
                ['wsl', 'bash', '-l', '-c', cmd],
                capture_output=True, text=True, timeout=120
            )
            
            errors = []
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
                    
                    errors.append({"line": line_num, "column": col, "message": msg})
                    if print_output:
                        print(f"{Colors.red('[ERROR]')} Line {line_num}: {msg}\n")
            
            return {"success": result.returncode == 0, "file": filepath, "errors": errors}
            
        except subprocess.TimeoutExpired:
            return {"success": False, "file": filepath, 
                    "errors": [{"line": 0, "message": "ansible-lint timeout"}]}
        except Exception as e:
            return {"success": False, "file": filepath, 
                    "errors": [{"line": 0, "message": str(e)}]}


# ============================================================================
# YAML ROUTER (MAIN VALIDATOR)
# ============================================================================

class YamlRouter:
    """
    Unified Entry Point for YAML Validation.
    
    Flow:
    1. Detect file type and characteristics
    2. Run YAMLlint (with Helm trimming if needed)
    3. Run Unified Quote Validator (K8s + Helm rules)
    4. Run Ansible-lint if applicable
    """
    
    def __init__(self, verbose: bool = False, skip_ansible: bool = False,
                 skip_yamllint: bool = False, yamllint_config: str = None,
                 strict: bool = False):
        self.verbose = verbose
        self.skip_ansible = skip_ansible
        self.skip_yamllint = skip_yamllint
        self.strict = strict
        
        self.yamllint = None if skip_yamllint else YamlLintValidator(
            config_file=yamllint_config, verbose=verbose
        )
        self.values_loader = HelmValuesLoader()
        self._ansible_validator = None
    
    @property
    def ansible_validator(self):
        if self._ansible_validator is None:
            self._ansible_validator = AnsibleValidator(verbose=self.verbose)
        return self._ansible_validator
    
    def validate(self, filepath: str) -> dict:
        """Validate a single file."""
        file_path = Path(filepath)
        
        if not file_path.exists():
            return {"success": False, "file": filepath, "type": "unknown",
                    "errors": [{"line": 0, "message": f"File not found: {filepath}"}]}
        
        try:
            content = file_path.read_text(encoding='utf-8')
        except Exception as e:
            return {"success": False, "file": filepath, "type": "unknown",
                    "errors": [{"line": 0, "message": f"Cannot read file: {e}"}]}
        
        # Detect file characteristics
        detection = FileTypeDetector.detect(file_path, content)
        
        formatter.print_file_header(filepath, detection['file_type'])
        
        total_errors = []
        
        # 1. YAMLlint (always, with trimming if needed)
        if self.yamllint:
            yamllint_result = self.yamllint.validate(
                filepath, content,
                has_helm_syntax=detection['has_helm_syntax'],
                print_output=True
            )
            total_errors.extend(yamllint_result.get('errors', []))
        
        # 2. Unified Quote Validator (if K8s or has {{ }})
        if detection['has_k8s_structure'] or detection['has_helm_syntax']:
            # Load type map if Helm chart
            type_map = {}
            if detection['is_helm_chart']:
                values_source = FileTypeDetector.find_helm_values(file_path)
                if values_source:
                    type_map = self.values_loader.load_type_map(values_source)
                    if self.verbose:
                        print(f"   [Loaded {len(type_map)} type mappings from values]")
            
            quote_result = self._validate_quotes(filepath, content, type_map)
            total_errors.extend(quote_result.get('errors', []))
        
        # 3. Ansible-lint (if Ansible file)
        if detection['is_ansible'] and not self.skip_ansible:
            ansible_result = self.ansible_validator.validate(filepath, print_output=True)
            total_errors.extend(ansible_result.get('errors', []))
        
        formatter.print_summary(len(total_errors))
        
        return {
            "success": len(total_errors) == 0,
            "file": filepath,
            "type": detection['file_type'],
            "errors": total_errors,
        }
    
    def _validate_quotes(self, filepath: str, content: str, type_map: dict) -> dict:
        """Run unified quote validation."""
        formatter.print_section_header("Quote Validator")
        
        try:
            validator = UnifiedQuoteValidator(
                strict=self.strict,
                type_map=type_map
            )
            result = validator.validate_content(content, filepath)
            
            error_list = []
            
            for issue in result.issues:
                error_list.append({
                    "line": issue.line_number,
                    "column": 0,
                    "message": issue.message,
                    "current": issue.line_content,
                    "suggestion": issue.suggestion,
                })
                
                formatter.print_issue(
                    issue.line_number, 0, issue.message,
                    issue.line_content, issue.suggestion
                )
            
            if not result.issues:
                formatter.print_ok_message("No quote issues found")
            
            return {"errors": error_list}
            
        except Exception as e:
            print(f"{Colors.red('[ERROR]')} Quote validation error: {e}\n")
            return {"errors": [{"line": 0, "message": str(e)}]}


# ============================================================================
# MAIN
# ============================================================================

def main():
    parser = argparse.ArgumentParser(
        description='YAML Router - Unified Validator for Helm, K8s, Ansible'
    )
    parser.add_argument('files', nargs='+', help='YAML files to validate')
    parser.add_argument('-v', '--verbose', action='store_true', help='Verbose output')
    parser.add_argument('--skip-ansible', action='store_true', help='Skip Ansible validation')
    parser.add_argument('--skip-yamllint', action='store_true', help='Skip YAMLlint')
    parser.add_argument('--yamllint-config', type=str, help='Path to yamllint config')
    parser.add_argument('--strict', action='store_true', help='Strict mode')
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
    )
    
    exit_code = 0
    total_errors = 0
    
    for filepath in args.files:
        result = router.validate(filepath)
        
        if not result.get('success'):
            exit_code = 1
        
        total_errors += len(result.get('errors', []))
    
    if len(args.files) > 1:
        print(f"\n{'=' * TERMINAL_WIDTH}")
        print(f"TOTAL: {len(args.files)} file(s), {Colors.red(f'{total_errors} error(s)') if total_errors > 0 else f'{total_errors} error(s)'}")
        print(f"{'=' * TERMINAL_WIDTH}")
    
    sys.exit(exit_code)


if __name__ == '__main__':
    main()