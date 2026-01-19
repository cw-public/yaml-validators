#!/usr/bin/env python3
# filepath: c:\Users\ahryhory\Documents\Git-repos\yaml-validators\yaml_router.py
"""
YAML Router - Unified Entry Point
- Erkennt automatisch Helm Charts vs Kubernetes Manifeste
- Routet zur passenden Validierung
"""

import re
import sys
import argparse
from pathlib import Path
from ruamel.yaml import YAML

# Relative imports für Pre-Commit
try:
    from kubernetes_validator import K8sValidator
    from helm_validator import validate_helm_template
except ImportError:
    # Fallback für direkten Aufruf
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
    """Erkennt den Dateityp: Helm Template, K8s Manifest, oder Generic YAML"""
    
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
    
    @staticmethod
    def is_helm_template(content: str, file_path: Path) -> bool:
        """Prüft ob Datei ein Helm Template ist"""
        # 1. Check: Helm Template Syntax im Content
        for pattern in FileTypeDetector.HELM_PATTERNS:
            if re.search(pattern, content):
                return True
        
        # 2. Check: Liegt in templates/ Ordner mit Chart.yaml
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
    def detect(file_path: Path, content: str, data: dict) -> str:
        """
        Erkennt den Dateityp
        
        Returns: 'helm', 'k8s', oder 'generic'
        """
        # Priorität 1: Helm Template
        if FileTypeDetector.is_helm_template(content, file_path):
            return 'helm'
        
        # Priorität 2: Kubernetes Manifest
        if FileTypeDetector.is_k8s_manifest(data):
            return 'k8s'
        
        # Fallback: Generic YAML
        return 'generic'


# ============================================================================
# YAML ROUTER (UNIFIED VALIDATOR)
# ============================================================================

class YamlRouter:
    """
    Unified Entry Point - routet zur passenden Validierung
    """
    
    def __init__(self, verbose: bool = False):
        self.verbose = verbose
        self.yaml = YAML()
        self.yaml.preserve_quotes = True
    
    def validate(self, filepath: str) -> dict:
        """
        Hauptmethode: Erkennt Dateityp und routet zur Validierung
        """
        file_path = Path(filepath)
        
        if not file_path.exists():
            return {"success": False, "errors": [f"File not found: {filepath}"]}
        
        # Read content
        content = file_path.read_text(encoding='utf-8')
        
        # Parse YAML (kann fehlschlagen bei Helm Templates mit {{ }})
        data = None
        try:
            data = self.yaml.load(content)
        except Exception as e:
            # Könnte Helm Template sein - versuche trotzdem
            if '{{' in content:
                data = {}
            else:
                return {"success": False, "errors": [f"YAML Parse Error: {e}"]}
        
        # Detect file type
        file_type = FileTypeDetector.detect(file_path, content, data or {})
        
        if self.verbose:
            print(f"\n[FILE] {filepath}")
            print(f"   Type: {file_type.upper()}")
        
        # Route to validator
        if file_type == 'helm':
            return self._validate_helm(filepath)
        
        elif file_type == 'k8s':
            return self._validate_k8s(filepath)
        
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
    
    def _validate_generic(self, filepath: str) -> dict:
        """Generic YAML - nur Syntax-Check (bereits geparsed = OK)"""
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
        description='YAML Router - Helm Templates & Kubernetes Manifests Validator'
    )
    parser.add_argument('files', nargs='+', help='YAML files to validate')
    parser.add_argument('-v', '--verbose', action='store_true', help='Verbose output')
    
    args = parser.parse_args()
    
    router = YamlRouter(verbose=args.verbose)
    exit_code = 0
    
    for filepath in args.files:
        result = router.validate(filepath)
        
        # Output
        if not args.verbose and result.get('type') != 'helm':
            print(f"\n[FILE] {filepath}")
            print(f"   Type: {result.get('type', 'unknown').upper()}")
        
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