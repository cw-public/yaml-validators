#!/usr/bin/env python3
# filepath: c:\Users\ahryhory\Documents\Git-repos\yaml-validators\kubernetes_validator.py
"""
Kubernetes Manifest Validator
- VOR spec: Nicht quoten (apiVersion, kind, metadata.*)
- NACH spec: Alles quoten AUSSER Integer und Boolean
"""

import re
import sys
import os
import argparse
from pathlib import Path
from ruamel.yaml import YAML
from ruamel.yaml.comments import CommentedMap, CommentedSeq

# Force UTF-8 encoding on Windows
if sys.platform == 'win32':
    os.environ['PYTHONIOENCODING'] = 'utf-8'


class K8sValidator:
    """Kubernetes Manifest Validator mit Quoting-Regeln"""
    
    # Top-Level Keys VOR spec (NICHT quoten)
    PRE_SPEC_KEYS = {
        'apiVersion',
        'kind',
        'metadata',
    }
    
    # Alles unter metadata (NICHT quoten)
    METADATA_NO_QUOTE = True
    
    def __init__(self, verbose: bool = False):
        self.verbose = verbose
        self.yaml = YAML()
        self.yaml.preserve_quotes = True
        self.yaml.default_flow_style = False
        self.errors = []
        self.warnings = []
    
    def is_k8s_manifest(self, data: dict) -> bool:
        """Prüft ob YAML ein Kubernetes Manifest ist"""
        if not isinstance(data, dict):
            return False
        return 'apiVersion' in data and 'kind' in data
    
    def validate_structure(self, data: dict) -> None:
        """Validiert K8s Manifest Struktur"""
        
        api_version = data.get('apiVersion', '')
        if not api_version:
            self.errors.append("ERROR: 'apiVersion' is required")
        
        kind = data.get('kind', '')
        if not kind:
            self.errors.append("ERROR: 'kind' is required")
        
        metadata = data.get('metadata', {})
        if not metadata:
            self.errors.append("ERROR: 'metadata' is required")
        elif 'name' not in metadata and 'generateName' not in metadata:
            self.errors.append("ERROR: 'metadata.name' or 'metadata.generateName' is required")
    
    def is_in_pre_spec_section(self, path: list) -> bool:
        """Prüft ob der aktuelle Pfad VOR spec liegt"""
        if not path:
            return True
        
        # Top-level key prüfen
        root_key = path[0]
        
        # apiVersion, kind = immer pre-spec
        if root_key in ('apiVersion', 'kind'):
            return True
        
        # metadata = komplett pre-spec
        if root_key == 'metadata':
            return True
        
        # spec und alles andere = post-spec
        return False
    
    def is_boolean(self, value) -> bool:
        """Prüft ob Value ein Boolean ist"""
        return isinstance(value, bool)
    
    def is_integer(self, value) -> bool:
        """Prüft ob Value ein Integer ist"""
        return isinstance(value, int) and not isinstance(value, bool)
    
    def is_quoted(self, value) -> bool:
        """Prüft ob ein String-Value bereits gequotet ist"""
        if hasattr(value, 'style') and value.style in ('"', "'"):
            return True
        return False
    
    def should_quote(self, key: str, value, path: list) -> tuple[bool, str]:
        """
        Entscheidet ob ein Value gequotet werden soll
        Returns: (should_quote: bool, reason: str)
        """
        
        # 1. Nicht-Strings: Nie quoten
        if not isinstance(value, str):
            return False, ""
        
        # 2. VOR spec: NICHT quoten
        if self.is_in_pre_spec_section(path):
            return False, "pre-spec section (no quotes)"
        
        # 3. NACH spec: MUSS gequotet werden
        # Ausnahme: Wenn der String wie Integer aussieht (sollte nicht passieren nach YAML parse)
        return True, "post-spec section (must quote strings)"
    
    def get_line_number(self, data, key, default: int = 0) -> int:
        """Holt Line Number aus ruamel.yaml"""
        try:
            if hasattr(data, 'lc') and data.lc.key(key):
                return data.lc.key(key)[0] + 1
        except:
            pass
        return default
    
    def check_quoting(self, data, path: list = None, line_num: int = 1) -> None:
        """Rekursiv durch YAML traversieren und Quoting-Fehler sammeln"""
        if path is None:
            path = []
        
        if isinstance(data, CommentedMap):
            for key, value in data.items():
                current_path = path + [key]
                path_str = '.'.join(str(p) for p in current_path)
                line = self.get_line_number(data, key, line_num)
                
                if isinstance(value, (CommentedMap, CommentedSeq)):
                    self.check_quoting(value, current_path, line)
                
                elif isinstance(value, str):
                    should_quote, reason = self.should_quote(key, value, current_path)
                    is_quoted = self.is_quoted(value)
                    
                    if should_quote and not is_quoted:
                        self.errors.append(
                            f"line {line}: {path_str}: {value} -> should be \"{value}\""
                        )
                    elif not should_quote and is_quoted:
                        # Optional: Warnung wenn pre-spec gequotet ist
                        self.warnings.append(
                            f"line {line}: {path_str}: \"{value}\" -> should NOT be quoted ({reason})"
                        )
                
                elif self.is_boolean(value):
                    # Booleans: OK, nicht quoten
                    pass
                
                elif self.is_integer(value):
                    # Integers: OK, nicht quoten
                    pass
        
        elif isinstance(data, CommentedSeq):
            for i, item in enumerate(data):
                current_path = path + [f"[{i}]"]
                
                try:
                    if hasattr(data, 'lc') and data.lc.item(i):
                        line = data.lc.item(i)[0] + 1
                    else:
                        line = line_num
                except:
                    line = line_num
                
                if isinstance(item, (CommentedMap, CommentedSeq)):
                    self.check_quoting(item, current_path, line)
                
                elif isinstance(item, str):
                    # List items unter spec müssen gequotet sein
                    should_quote, reason = self.should_quote(str(i), item, current_path)
                    is_quoted = self.is_quoted(item)
                    
                    if should_quote and not is_quoted:
                        path_str = '.'.join(str(p) for p in current_path)
                        self.errors.append(
                            f"line {line}: {path_str}: {item} -> should be \"{item}\""
                        )
    
    def validate(self, filepath: str) -> dict:
        """Hauptmethode: Validiere ein Kubernetes Manifest"""
        self.errors = []
        self.warnings = []
        
        path = Path(filepath)
        if not path.exists():
            return {"success": False, "errors": [f"File not found: {filepath}"]}
        
        content = path.read_text(encoding='utf-8')
        
        try:
            data = self.yaml.load(content)
        except Exception as e:
            return {"success": False, "errors": [f"YAML Parse Error: {e}"]}
        
        # 1. Check if K8s Manifest
        if not self.is_k8s_manifest(data):
            return {
                "success": True, 
                "skipped": True,
                "message": "Not a Kubernetes manifest (missing apiVersion/kind)"
            }
        
        if self.verbose:
            kind = data.get('kind', 'Unknown')
            name = data.get('metadata', {}).get('name', 'unknown')
            print(f"[OK] Detected K8s Manifest: {kind}/{name}")
        
        # 2. Validate Structure
        self.validate_structure(data)
        
        # 3. Check Quoting
        self.check_quoting(data)
        
        return {
            "success": len(self.errors) == 0,
            "file": str(filepath),
            "kind": data.get('kind'),
            "name": data.get('metadata', {}).get('name'),
            "errors": self.errors,
            "warnings": self.warnings,
        }


def main():
    parser = argparse.ArgumentParser(description='Kubernetes Manifest Validator')
    parser.add_argument('command', choices=['validate'], 
                        help='validate: check only, report errors')
    parser.add_argument('files', nargs='+', help='YAML files to process')
    parser.add_argument('-v', '--verbose', action='store_true', help='Verbose output')
    
    args = parser.parse_args()
    
    validator = K8sValidator(verbose=args.verbose)
    exit_code = 0
    
    for filepath in args.files:
        result = validator.validate(filepath)
        
        if result.get('skipped'):
            if args.verbose:
                print(f"[SKIP] {filepath} - {result.get('message')}")
            continue
        
        print(f"\n[FILE] {filepath}")
        print(f"   Kind: {result.get('kind')} | Name: {result.get('name')}")
        
        if result.get('errors'):
            exit_code = 1
            for err in result['errors']:
                print(f"   [ERROR] {err}")
        
        if result.get('warnings'):
            for warn in result['warnings']:
                print(f"   [WARNING] {warn}")
        
        if result.get('success') and not result.get('errors'):
            print(f"   [OK] No quoting issues found")
    
    sys.exit(exit_code)


if __name__ == '__main__':
    main()