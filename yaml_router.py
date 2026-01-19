#!/usr/bin/env python3
# filepath: c:\Users\ahryhory\Documents\Git-repos\yaml-validators\yaml_router.py
"""
YAML Router - Unified Entry Point
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
    
    # Ansible-spezifische Keywords
    ANSIBLE_KEYWORDS = [
        'hosts',
        'tasks',
        'roles',
        'handlers',
        'vars',
        'become',
        'gather_facts',
        'pre_tasks',
        'post_tasks',
        'block',
        'rescue',
        'always',
    ]
    
    # Ansible Module (häufig verwendete)
    ANSIBLE_MODULES = [
        'ansible.builtin.',
        'community.',
        'amazon.aws.',
        'azure.',
        'google.cloud.',
        'kubernetes.core.',
        'shell',
        'command',
        'copy',
        'template',
        'file',
        'apt',
        'yum',
        'pip',
        'git',
        'service',
        'systemd',
        'debug',
        'set_fact',
        'include_tasks',
        'import_tasks',
        'include_role',
        'import_role',
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
                if (current / 'chart' / 'Chart.yaml').exists():
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
        # 1. Check: Pfad enthält typische Ansible-Ordner
        path_str = str(file_path).replace('\\', '/').lower()
        ansible_dirs = ['/playbooks/', '/roles/', '/tasks/', '/handlers/', 
                       '/vars/', '/defaults/', '/group_vars/', '/host_vars/']
        
        in_ansible_dir = any(d in path_str for d in ansible_dirs)
        
        # 2. Check: Dateiname
        ansible_filenames = ['playbook', 'site.yaml', 'site.yml', 'main.yaml', 
                            'main.yml', 'tasks.yaml', 'tasks.yml']
        is_ansible_filename = any(n in file_path.name.lower() for n in ansible_filenames)
        
        # 3. Check: Inhalt - Liste von Tasks oder Plays
        if isinstance(data, list) and len(data) > 0:
            first_item = data[0]
            if isinstance(first_item, dict):
                # Playbook: Hat 'hosts' oder 'tasks'
                if 'hosts' in first_item or 'tasks' in first_item:
                    return True
                
                # Task-Liste: Hat 'name' und ein Modul
                if 'name' in first_item:
                    for module in FileTypeDetector.ANSIBLE_MODULES:
                        if module in first_item:
                            return True
                    # Check für ansible.builtin.* etc.
                    for key in first_item.keys():
                        if '.' in str(key):
                            return True
        
        # 4. Check: Dict mit Ansible-Keywords
        if isinstance(data, dict):
            ansible_keys = set(data.keys()) & set(FileTypeDetector.ANSIBLE_KEYWORDS)
            if len(ansible_keys) >= 2:
                return True
        
        # 5. Kombinierte Heuristik
        if in_ansible_dir or is_ansible_filename:
            if isinstance(data, (list, dict)):
                return True
        
        return False
    
    @staticmethod
    def detect(file_path: Path, content: str, data) -> str:
        """Erkennt den Dateityp"""
        # Priorität 1: Helm Template
        if FileTypeDetector.is_helm_template(content, file_path):
            return 'helm'
        
        # Priorität 2: Kubernetes Manifest
        if isinstance(data, dict) and FileTypeDetector.is_k8s_manifest(data):
            return 'k8s'
        
        # Priorität 3: Ansible
        if FileTypeDetector.is_ansible_file(data, file_path):
            return 'ansible'
        
        # Fallback: Generic YAML
        return 'generic'


# ============================================================================
# ANSIBLE VALIDATOR (WSL)
# ============================================================================

class AnsibleValidator:
    """Ansible Lint via WSL mit Wrapper-Script"""
    
    # Standard-Pfad zum Wrapper (relativ zu $HOME)
    WRAPPER_RELATIVE_PATH = '.local/bin/ansible-lint-wrapper.sh'
    
    def __init__(self, verbose: bool = False):
        self.verbose = verbose
        self.wsl_available = self._check_wsl()
        self.wrapper_path = self._find_wrapper()
    
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
    
    def _find_wrapper(self) -> str:
        """Findet den ansible-lint-wrapper.sh in WSL (unabhängig vom User)"""
        if not self.wsl_available:
            return None
        
        try:
            # Nutze $HOME um den Wrapper zu finden
            result = subprocess.run(
                ['wsl', 'bash', '-c', f'echo $HOME/{self.WRAPPER_RELATIVE_PATH}'],
                capture_output=True,
                text=True,
                timeout=10
            )
            
            if result.returncode == 0:
                wrapper_path = result.stdout.strip()
                
                # Prüfe ob Wrapper existiert und ausführbar ist
                check = subprocess.run(
                    ['wsl', 'test', '-x', wrapper_path],
                    capture_output=True,
                    timeout=5
                )
                
                if check.returncode == 0:
                    return wrapper_path
            
            # Fallback: Versuche ansible-lint direkt zu finden
            result = subprocess.run(
                ['wsl', 'which', 'ansible-lint'],
                capture_output=True,
                text=True,
                timeout=10
            )
            
            if result.returncode == 0:
                return result.stdout.strip()
            
            return None
            
        except Exception:
            return None
    
    def validate(self, filepath: str) -> dict:
        """Führt ansible-lint via WSL Wrapper aus"""
        
        # Check: WSL verfügbar?
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
        
        # Check: Wrapper gefunden?
        if not self.wrapper_path:
            return {
                "success": True,
                "file": filepath,
                "type": "ansible",
                "skipped": True,
                "message": "ansible-lint-wrapper.sh not found in WSL - install with: pip install ansible-lint && create wrapper",
                "errors": [],
                "warnings": [],
            }
        
        # Absoluter Windows-Pfad
        abs_path = str(Path(filepath).absolute())
        
        if self.verbose:
            print(f"   [INFO] Running ansible-lint via WSL...")
            print(f"   [INFO] Wrapper: {self.wrapper_path}")
            print(f"   [INFO] File: {abs_path}")
        
        try:
            # Führe Wrapper aus - der Wrapper macht die Pfad-Konvertierung!
            result = subprocess.run(
                ['wsl', self.wrapper_path, abs_path],
                capture_output=True,
                text=True,
                timeout=120  # Wrapper hat eigenen 60s Timeout
            )
            
            errors = []
            warnings = []
            
            # Parse Output
            output = result.stdout + result.stderr
            
            for line in output.split('\n'):
                line = line.strip()
                if not line:
                    continue
                
                # ansible-lint parseable format: filename:line:column: rule message
                if ':' in line and any(rule in line.lower() for rule in 
                    ['error', 'warning', 'fatal', 'risky', 'deprecated', 
                     'yaml', 'syntax', 'name', 'fqcn', 'no-changed-when']):
                    
                    if 'error' in line.lower() or 'fatal' in line.lower():
                        errors.append(line)
                    else:
                        warnings.append(line)
            
            # Wenn Exit-Code != 0 aber keine spezifischen Fehler gefunden
            if result.returncode != 0 and not errors:
                errors.append(f"ansible-lint exited with code {result.returncode}")
                if result.stderr.strip():
                    errors.append(result.stderr.strip()[:200])
            
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
    """Unified Entry Point - routet zur passenden Validierung"""
    
    def __init__(self, verbose: bool = False, skip_ansible: bool = False):
        self.verbose = verbose
        self.skip_ansible = skip_ansible
        self.yaml = YAML()
        self.yaml.preserve_quotes = True
    
    def validate(self, filepath: str) -> dict:
        """Hauptmethode: Erkennt Dateityp und routet zur Validierung"""
        file_path = Path(filepath)
        
        if not file_path.exists():
            return {"success": False, "errors": [f"File not found: {filepath}"]}
        
        # Read content
        content = file_path.read_text(encoding='utf-8')
        
        # Parse YAML
        data = None
        try:
            data = self.yaml.load(content)
        except Exception as e:
            if '{{' in content:
                data = {}
            else:
                return {"success": False, "errors": [f"YAML Parse Error: {e}"]}
        
        # Detect file type
        file_type = FileTypeDetector.detect(file_path, content, data)
        
        if self.verbose:
            print(f"\n[FILE] {filepath}")
            print(f"   Type: {file_type.upper()}")
        
        # Route to validator
        if file_type == 'helm':
            return self._validate_helm(filepath)
        elif file_type == 'k8s':
            return self._validate_k8s(filepath)
        elif file_type == 'ansible':
            return self._validate_ansible(filepath)
        else:
            return self._validate_generic(filepath)
    
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
    
    def _validate_generic(self, filepath: str) -> dict:
        """Generic YAML - nur Syntax-Check"""
        if self.verbose:
            print(f"   [OK] Valid YAML (generic)")
        return {
            "success": True,
            "file": filepath,
            "type": "generic",
            "errors": [],
            "warnings": [],
        }


# ============================================================================
# MAIN
# ============================================================================

def main():
    parser = argparse.ArgumentParser(
        description='YAML Router - Helm, K8s, Ansible Validator'
    )
    parser.add_argument('files', nargs='+', help='YAML files to validate')
    parser.add_argument('-v', '--verbose', action='store_true', help='Verbose output')
    parser.add_argument('--skip-ansible', action='store_true', 
                        help='Skip Ansible validation (useful if WSL not available)')
    
    args = parser.parse_args()
    
    router = YamlRouter(verbose=args.verbose, skip_ansible=args.skip_ansible)
    exit_code = 0
    
    for filepath in args.files:
        result = router.validate(filepath)
        
        # Output
        if not args.verbose and result.get('type') != 'helm':
            print(f"\n[FILE] {filepath}")
            print(f"   Type: {result.get('type', 'unknown').upper()}")
        
        if result.get('skipped'):
            print(f"   [SKIP] {result.get('message', 'Skipped')}")
            continue
        
        if result.get('errors'):
            exit_code = 1
            for err in result['errors']:
                if 'see output above' not in err:
                    print(f"   [ERROR] {err}")
        
        if result.get('warnings'):
            for warn in result['warnings']:
                print(f"   [WARNING] {warn}")
        
        if result.get('success') and not result.get('errors'):
            if result.get('type') != 'helm':
                print(f"   [OK] Valid")
    
    sys.exit(exit_code)


if __name__ == '__main__':
    main()