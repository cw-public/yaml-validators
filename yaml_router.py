#!/usr/bin/env python3
# filepath: c:\Users\ahryhory\Documents\Git-repos\yaml-validators\yaml_router.py
"""
YAML Router - Unified Entry Point
- YAMLlint für alle Dateien
- Erkennt automatisch Helm Charts, K8s Manifeste, Ansible Playbooks
- Routet zur passenden Validierung
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

# Relative imports für Pre-Commit
try:
    from kubernetes_validator import K8sValidator
    from helm_validator import validate_helm_template
except ImportError:
    import importlib.util
    
    spec = importlib.util.spec_from_file_location(
        "kubernetes_validator", 
        Path(__file__).parent / "kubernetes_validator.py"
    )
    kubernetes_validator = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(kubernetes_validator)
    K8sValidator = kubernetes_validator.K8sValidator
    
    spec = importlib.util.spec_from_file_location(
        "helm_validator",
        Path(__file__).parent / "helm_validator.py"
    )
    helm_validator = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(helm_validator)
    validate_helm_template = helm_validator.validate_helm_template


# ============================================================================
# YAMLLINT VALIDATOR
# ============================================================================

class YamlLintValidator:
    """YAMLlint Integration - prüft Syntax, Indentation, Line Length, etc."""
    
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
    present: true
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
        """Lädt YAMLlint Config aus Datei oder nutzt Default"""
        
        if config_file and Path(config_file).exists():
            if self.verbose:
                print(f"   [INFO] Using yamllint config: {config_file}")
            return YamlLintConfig(file=config_file)
        
        search_paths = [
            Path.cwd() / '.yamllint.yaml',
            Path.cwd() / '.yamllint.yml',
            Path.cwd() / '.yamllint',
            Path.home() / '.yamllint.yaml',
        ]
        
        for path in search_paths:
            if path.exists():
                if self.verbose:
                    print(f"   [INFO] Using yamllint config: {path}")
                return YamlLintConfig(file=str(path))
        
        if self.verbose:
            print(f"   [INFO] Using default yamllint config")
        return YamlLintConfig(content=self.DEFAULT_CONFIG)
    
    def validate(self, filepath: str, content: str = None) -> dict:
        """Führt YAMLlint auf einer Datei aus"""
        
        file_path = Path(filepath)
        
        if content is None:
            if not file_path.exists():
                return {
                    "success": False,
                    "file": filepath,
                    "errors": [f"File not found: {filepath}"],
                    "warnings": [],
                }
            
            try:
                content = file_path.read_text(encoding='utf-8')
            except Exception as e:
                return {
                    "success": False,
                    "file": filepath,
                    "errors": [f"Cannot read file: {e}"],
                    "warnings": [],
                }
        
        errors = []
        warnings = []
        
        try:
            problems = linter.run(content, self.config, filepath)
            
            for problem in problems:
                msg = f"{filepath}:{problem.line}:{problem.column}: [{problem.rule}] {problem.message}"
                
                if problem.level == 'error':
                    errors.append(msg)
                else:
                    warnings.append(msg)
            
            return {
                "success": len(errors) == 0,
                "file": filepath,
                "errors": errors,
                "warnings": warnings,
            }
            
        except Exception as e:
            return {
                "success": False,
                "file": filepath,
                "errors": [f"YAMLlint error: {e}"],
                "warnings": [],
            }


# ============================================================================
# DETECTION LOGIC
# ============================================================================

class FileTypeDetector:
    """Erkennt den Dateityp: Helm Template, K8s Manifest, Ansible, oder Generic YAML"""
    
    HELM_PATTERNS = [
        r'\{\{\s*\.Values\.',
        r'\{\{\s*\.Release\.',
        r'\{\{\s*\.Chart\.',
        r'\{\{\s*\.Capabilities\.',
        r'\{\{-?\s*if\s',
        r'\{\{-?\s*range\s',
        r'\{\{-?\s*include\s',
        r'\{\{-?\s*define\s',
    ]
    
    ANSIBLE_KEYWORDS = [
        'hosts', 'tasks', 'roles', 'handlers', 'vars', 'become',
        'gather_facts', 'pre_tasks', 'post_tasks', 'block', 'rescue', 'always',
    ]
    
    ANSIBLE_MODULES = [
        'uri', 'debug', 'shell', 'command', 'copy', 'file',
        'template', 'apt', 'yum', 'pip', 'git', 'service',
        'systemd', 'set_fact', 'include', 'include_tasks',
        'import_tasks', 'include_role', 'import_role',
        'blockinfile', 'lineinfile', 'user', 'group',
        'package', 'stat', 'loop', 'with_items',
        'when', 'notify', 'block', 'rescue',
        'always', 'assert', 'fail', 'meta', 'pause',
        'wait_for', 'raw', 'script', 'fetch', 'synchronize',
        'unarchive', 'archive', 'get_url', 'ufw',
        'ansible.builtin.', 'community.', 'amazon.aws.',
        'azure.', 'google.cloud.', 'kubernetes.core.',
    ]
    
    @staticmethod
    def is_helm_template(content: str, file_path: Path) -> bool:
        """Prüft ob Datei ein Helm Template ist"""
        for pattern in FileTypeDetector.HELM_PATTERNS:
            if re.search(pattern, content):
                return True
        
        path_str = str(file_path).replace('\\', '/')
        if '/templates/' in path_str:
            current = file_path.parent
            for _ in range(5):
                if (current / 'Chart.yaml').exists():
                    return True
                current = current.parent
        
        return False
    
    @staticmethod
    def is_k8s_manifest(data: dict) -> bool:
        """Prüft ob Datei ein Kubernetes Manifest ist"""
        if not isinstance(data, dict):
            return False
        return 'apiVersion' in data and 'kind' in data
    
    @staticmethod
    def is_ansible_file(data, file_path: Path) -> bool:
        """Prüft ob Datei ein Ansible Playbook/Role/Task ist"""
        path_str = str(file_path).replace('\\', '/').lower()
        ansible_dirs = ['/playbooks/', '/roles/', '/tasks/', '/handlers/', 
                       '/vars/', '/defaults/', '/group_vars/', '/host_vars/']
        in_ansible_dir = any(d in path_str for d in ansible_dirs)
        
        filename_lower = file_path.name.lower()
        ansible_filenames = ['playbook', 'site.yaml', 'site.yml', 'main.yaml', 
                            'main.yml', 'tasks.yaml', 'tasks.yml', 'ansible']
        is_ansible_filename = any(n in filename_lower for n in ansible_filenames)
        
        if isinstance(data, list) and len(data) > 0:
            first_item = data[0]
            if isinstance(first_item, dict):
                if 'hosts' in first_item or 'tasks' in first_item:
                    return True
                
                if 'name' in first_item:
                    for module in FileTypeDetector.ANSIBLE_MODULES:
                        if module in first_item:
                            return True
                    
                    for key in first_item.keys():
                        key_str = str(key)
                        if '.' in key_str and any(x in key_str for x in 
                            ['ansible.', 'community.', 'amazon.', 'azure.', 'google.']):
                            return True
                
                task_keys = set(first_item.keys())
                module_indicators = {'debug', 'uri', 'shell', 'command', 'copy', 
                                   'file', 'template', 'set_fact', 'include',
                                   'include_tasks', 'import_tasks', 'fail',
                                   'assert', 'meta', 'block', 'apt', 'yum',
                                   'service', 'systemd', 'user', 'group'}
                if task_keys & module_indicators:
                    return True
        
        if isinstance(data, dict):
            ansible_keys = set(data.keys()) & set(FileTypeDetector.ANSIBLE_KEYWORDS)
            if len(ansible_keys) >= 2:
                return True
        
        if 'ansible' in filename_lower:
            return True
        
        if in_ansible_dir or is_ansible_filename:
            if isinstance(data, (list, dict)):
                return True
        
        return False
    
    @staticmethod
    def detect(file_path: Path, content: str, data) -> str:
        """Erkennt den Dateityp"""
        if FileTypeDetector.is_helm_template(content, file_path):
            return 'helm'
        
        if isinstance(data, dict) and FileTypeDetector.is_k8s_manifest(data):
            return 'k8s'
        
        if FileTypeDetector.is_ansible_file(data, file_path):
            return 'ansible'
        
        return 'generic'


# ============================================================================
# ANSIBLE VALIDATOR (WSL)
# ============================================================================

class AnsibleValidator:
    """Ansible Lint via WSL - mit Login-Shell für korrekten PATH"""
    
    def __init__(self, verbose: bool = False):
        self.verbose = verbose
        self.wsl_available = self._check_wsl()
        self.ansible_lint_cmd = self._find_ansible_lint()
    
    def _check_wsl(self) -> bool:
        """Prüft ob WSL verfügbar ist"""
        if sys.platform != 'win32':
            return False
        
        try:
            result = subprocess.run(
                ['wsl', '--status'],
                capture_output=True,
                timeout=5
            )
            return result.returncode == 0
        except Exception:
            return False
    
    def _find_ansible_lint(self) -> str:
        """Findet ansible-lint in WSL (mit Login-Shell für korrekten PATH)"""
        if not self.wsl_available:
            return None
        
        try:
            result = subprocess.run(
                ['wsl', 'bash', '-l', '-c', 'which ansible-lint'],
                capture_output=True,
                text=True,
                timeout=10
            )
            
            if result.returncode == 0 and result.stdout.strip():
                return result.stdout.strip()
            
            standard_paths = [
                '$HOME/.local/bin/ansible-lint',
                '/usr/local/bin/ansible-lint',
                '/usr/bin/ansible-lint',
            ]
            
            for path in standard_paths:
                result = subprocess.run(
                    ['wsl', 'bash', '-c', f'test -x {path} && echo {path}'],
                    capture_output=True,
                    text=True,
                    timeout=5
                )
                
                if result.returncode == 0 and result.stdout.strip():
                    return result.stdout.strip()
            
            return None
            
        except Exception:
            return None
    
    def _windows_to_wsl_path(self, windows_path: str) -> str:
        """Konvertiert Windows-Pfad zu WSL-Pfad"""
        path = str(Path(windows_path).absolute())
        path = path.replace('\\', '/')
        
        if len(path) >= 2 and path[1] == ':':
            drive = path[0].lower()
            path = f'/mnt/{drive}{path[2:]}'
        
        return path
    
    def validate(self, filepath: str) -> dict:
        """Führt ansible-lint via WSL aus"""
        
        if not self.wsl_available:
            return {
                "success": True,
                "file": filepath,
                "type": "ansible",
                "skipped": True,
                "message": "WSL not available - skipping ansible-lint",
                "errors": [],
                "warnings": [],
            }
        
        if not self.ansible_lint_cmd:
            return {
                "success": True,
                "file": filepath,
                "type": "ansible",
                "skipped": True,
                "message": "ansible-lint not found in WSL - run 'pip install ansible-lint' in WSL",
                "errors": [],
                "warnings": [],
            }
        
        wsl_path = self._windows_to_wsl_path(filepath)
        
        if self.verbose:
            print(f"   [INFO] Running ansible-lint via WSL...")
            print(f"   [INFO] ansible-lint: {self.ansible_lint_cmd}")
            print(f"   [INFO] WSL path: {wsl_path}")
        
        try:
            cmd = f'{self.ansible_lint_cmd} -p --nocolor "{wsl_path}"'
            
            result = subprocess.run(
                ['wsl', 'bash', '-l', '-c', cmd],
                capture_output=True,
                text=True,
                timeout=120
            )
            
            errors = []
            warnings = []
            
            output = result.stdout + result.stderr
            
            for line in output.split('\n'):
                line = line.strip()
                if not line:
                    continue
                
                if ':' in line:
                    line_lower = line.lower()
                    
                    if any(x in line_lower for x in ['error', 'fatal', 'syntax-check']):
                        errors.append(line)
                    elif any(x in line_lower for x in 
                            ['warning', 'risky', 'deprecated', 'name[', 'yaml[', 
                             'fqcn[', 'no-changed-when', 'command-instead', 
                             'package-latest', 'literal-compare', 'jinja[']):
                        warnings.append(line)
                    elif re.match(r'.*:\d+:\d*:?', line):
                        warnings.append(line)
            
            if result.returncode != 0 and not errors and not warnings:
                errors.append(f"ansible-lint exited with code {result.returncode}")
                if result.stderr.strip():
                    errors.append(result.stderr.strip()[:500])
                if result.stdout.strip():
                    errors.append(result.stdout.strip()[:500])
            
            return {
                "success": result.returncode == 0,
                "file": filepath,
                "type": "ansible",
                "errors": errors,
                "warnings": warnings,
                "exit_code": result.returncode,
            }
            
        except subprocess.TimeoutExpired:
            return {
                "success": False,
                "file": filepath,
                "type": "ansible",
                "errors": ["ansible-lint timeout (120s)"],
                "warnings": [],
            }
        except Exception as e:
            return {
                "success": False,
                "file": filepath,
                "type": "ansible",
                "errors": [f"ansible-lint error: {e}"],
                "warnings": [],
            }


# ============================================================================
# YAML ROUTER (UNIFIED VALIDATOR)
# ============================================================================

class YamlRouter:
    """Unified Entry Point - YAMLlint + Typ-spezifische Validierung"""
    
    def __init__(self, verbose: bool = False, skip_ansible: bool = False,
                 skip_yamllint: bool = False, yamllint_config: str = None):
        self.verbose = verbose
        self.skip_ansible = skip_ansible
        self.skip_yamllint = skip_yamllint
        self.yaml = YAML()
        self.yaml.preserve_quotes = True
        
        if not skip_yamllint:
            self.yamllint = YamlLintValidator(
                config_file=yamllint_config, 
                verbose=verbose
            )
        else:
            self.yamllint = None
    
    def validate(self, filepath: str) -> dict:
        """Hauptmethode: YAMLlint + Typ-spezifische Validierung"""
        file_path = Path(filepath)
        
        if not file_path.exists():
            return {"success": False, "errors": [f"File not found: {filepath}"]}
        
        # Content lesen
        try:
            content = file_path.read_text(encoding='utf-8')
        except Exception as e:
            return {"success": False, "errors": [f"Cannot read file: {e}"]}
        
        # ===== SCHRITT 1: YAMLlint (außer für Helm Templates) =====
        yamllint_result = {"errors": [], "warnings": []}
        is_helm = FileTypeDetector.is_helm_template(content, file_path)
        
        if self.yamllint and not is_helm:
            yamllint_result = self.yamllint.validate(filepath, content)
            
            if self.verbose:
                if yamllint_result.get('errors'):
                    print(f"   [YAMLLINT] {len(yamllint_result['errors'])} errors")
                if yamllint_result.get('warnings'):
                    print(f"   [YAMLLINT] {len(yamllint_result['warnings'])} warnings")
        
        # ===== SCHRITT 2: YAML parsen =====
        data = None
        try:
            data = self.yaml.load(content)
        except Exception as e:
            if '{{' in content:
                data = {}
            else:
                if not yamllint_result.get('errors'):
                    yamllint_result['errors'].append(f"YAML Parse Error: {e}")
        
        # ===== SCHRITT 3: Dateityp erkennen =====
        file_type = FileTypeDetector.detect(file_path, content, data)
        
        if self.verbose:
            print(f"\n[FILE] {filepath}")
            print(f"   Type: {file_type.upper()}")
        
        # ===== SCHRITT 4: Typ-spezifische Validierung =====
        type_result = {"errors": [], "warnings": [], "skipped": False, "message": ""}
        
        if file_type == 'helm':
            type_result = self._validate_helm(filepath)
        elif file_type == 'k8s':
            type_result = self._validate_k8s(filepath)
        elif file_type == 'ansible':
            type_result = self._validate_ansible(filepath)
        
        # ===== SCHRITT 5: Ergebnisse kombinieren =====
        combined_errors = yamllint_result.get('errors', []) + type_result.get('errors', [])
        combined_warnings = yamllint_result.get('warnings', []) + type_result.get('warnings', [])
        
        return {
            "success": len(combined_errors) == 0,
            "file": filepath,
            "type": file_type,
            "errors": combined_errors,
            "warnings": combined_warnings,
            "skipped": type_result.get('skipped', False),
            "message": type_result.get('message', ''),
        }
    
    def _validate_helm(self, filepath: str) -> dict:
        """Route zu validate_helm_template aus helm_validator.py"""
        try:
            exit_code = validate_helm_template(
                input_file=filepath,
                values_source=None,
                yamllint_config=None,
                force=True,
                verbose=self.verbose
            )
            
            return {
                "success": exit_code == 0,
                "file": filepath,
                "type": "helm",
                "errors": [] if exit_code == 0 else ["Helm validation failed (see output above)"],
                "warnings": [],
            }
        except Exception as e:
            return {
                "success": False,
                "file": filepath,
                "type": "helm",
                "errors": [f"Helm validation error: {e}"],
                "warnings": [],
            }
    
    def _validate_k8s(self, filepath: str) -> dict:
        """Route zu K8sValidator aus kubernetes_validator.py"""
        try:
            validator = K8sValidator(verbose=self.verbose)
            result = validator.validate(filepath)
            result['type'] = 'k8s'
            return result
        except Exception as e:
            return {
                "success": False,
                "file": filepath,
                "type": "k8s",
                "errors": [f"K8s validation error: {e}"],
                "warnings": [],
            }
    
    def _validate_ansible(self, filepath: str) -> dict:
        """Route zu AnsibleValidator (WSL)"""
        if self.skip_ansible:
            if self.verbose:
                print(f"   [SKIP] Ansible validation disabled")
            return {
                "success": True,
                "file": filepath,
                "type": "ansible",
                "skipped": True,
                "message": "Ansible validation skipped",
                "errors": [],
                "warnings": [],
            }
        
        try:
            validator = AnsibleValidator(verbose=self.verbose)
            return validator.validate(filepath)
        except Exception as e:
            return {
                "success": False,
                "file": filepath,
                "type": "ansible",
                "errors": [f"Ansible validation error: {e}"],
                "warnings": [],
            }


# ============================================================================
# MAIN
# ============================================================================

def main():
    parser = argparse.ArgumentParser(
        description='YAML Router - Helm, K8s, Ansible Validator with YAMLlint'
    )
    parser.add_argument('files', nargs='+', help='YAML files to validate')
    parser.add_argument('-v', '--verbose', action='store_true', help='Verbose output')
    parser.add_argument('--skip-ansible', action='store_true', 
                        help='Skip Ansible validation')
    parser.add_argument('--skip-yamllint', action='store_true',
                        help='Skip YAMLlint validation')
    parser.add_argument('--yamllint-config', type=str, default=None,
                        help='Path to custom yamllint config file')
    
    args = parser.parse_args()
    
    router = YamlRouter(
        verbose=args.verbose, 
        skip_ansible=args.skip_ansible,
        skip_yamllint=args.skip_yamllint,
        yamllint_config=args.yamllint_config,
    )
    
    exit_code = 0
    
    for filepath in args.files:
        result = router.validate(filepath)
        
        # Output Header
        if not args.verbose and result.get('type') != 'helm':
            print(f"\n[FILE] {filepath}")
            print(f"   Type: {result.get('type', 'unknown').upper()}")
        
        # Skipped
        if result.get('skipped'):
            print(f"   [SKIP] {result.get('message', 'Skipped')}")
        
        # Errors
        if result.get('errors'):
            exit_code = 1
            for err in result['errors']:
                if 'see output above' not in err:
                    print(f"   [ERROR] {err}")
        
        # Warnings
        if result.get('warnings'):
            for warn in result['warnings']:
                print(f"   [WARNING] {warn}")
        
        # Success
        if result.get('success') and not result.get('errors') and not result.get('skipped'):
            if result.get('type') != 'helm':
                print(f"   [OK] Valid")
    
    sys.exit(exit_code)


if __name__ == '__main__':
    main()