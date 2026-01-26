"""
YAML Router - Kubernetes Manifest Validator mit Quote-Regeln

Regeln (ERROR Level - Breaking):
1. Boolean als String: enabled: "true" → ERROR
2. Helm Template Integer gequoted: "{{ .replicas }}" → ERROR
3. Annotation Integer ohne Quote: sync-wave: 1 → ERROR
4. goTemplateOptions ohne Quote: [missingkey=error] → ERROR

Regeln (WARNING Level - Idiomatik):
5. Top-Level gequoted: apiVersion: "v1" → WARNING
6. Metadata name/namespace gequoted → WARNING
7. Paths/URLs ohne Quote → WARNING
8. Port name/protocol ohne Quote → WARNING
"""

import re
import sys
from pathlib import Path
from typing import List, Tuple, Dict, Any, Optional
from dataclasses import dataclass, field
from enum import Enum

try:
    from ruamel.yaml import YAML
    HAS_RUAMEL = True
except ImportError:
    HAS_RUAMEL = False
    import yaml


# ============================================================================
# Enums & Data Classes
# ============================================================================

class Severity(Enum):
    """Validierungs-Severity Level."""
    ERROR = "error"      # Breaking Issues - MUSS gefixt werden
    WARNING = "warning"  # Idiomatik - SOLLTE gefixt werden
    INFO = "info"        # Hinweise - KANN gefixt werden


class IssueType(Enum):
    """Typen von Quoting-Problemen."""
    # ERROR Level
    BOOLEAN_AS_STRING = "boolean_as_string"
    HELM_TEMPLATE_INT_QUOTED = "helm_template_int_quoted"
    ANNOTATION_INT_NOT_QUOTED = "annotation_int_not_quoted"
    GO_TEMPLATE_OPTIONS_NOT_QUOTED = "go_template_options_not_quoted"
    INTEGER_FIELD_QUOTED = "integer_field_quoted"
    
    # WARNING Level
    TOP_LEVEL_QUOTED = "top_level_quoted"
    METADATA_QUOTED = "metadata_quoted"
    PATH_NOT_QUOTED = "path_not_quoted"
    URL_NOT_QUOTED = "url_not_quoted"
    PORT_STRING_NOT_QUOTED = "port_string_not_quoted"
    HELM_TEMPLATE_STRING_NOT_QUOTED = "helm_template_string_not_quoted"
    ANNOTATION_SPECIAL_CHAR_NOT_QUOTED = "annotation_special_char_not_quoted"


@dataclass
class QuoteIssue:
    """Repräsentiert ein Quoting-Problem."""
    line_number: int
    line_content: str
    issue_type: IssueType
    field_path: str
    message: str
    suggestion: str
    severity: Severity


@dataclass
class ValidationResult:
    """Ergebnis der Validierung."""
    file_path: str
    is_valid: bool
    issues: List[QuoteIssue] = field(default_factory=list)
    errors: int = 0
    warnings: int = 0
    infos: int = 0


# ============================================================================
# Kubernetes Quote Validator
# ============================================================================

class KubernetesQuoteValidator:
    """Validator für Kubernetes Manifest Quoting-Regeln."""
    
    # ========== Konfiguration ==========
    
    # Top-Level Fields die NICHT gequoted werden sollten
    TOP_LEVEL_NO_QUOTE = {'apiVersion', 'kind'}
    
    # Metadata Fields die NICHT gequoted werden sollten
    METADATA_NO_QUOTE = {'name', 'namespace'}
    
    # Integer Fields die NIEMALS gequoted werden dürfen
    INTEGER_FIELDS = {
        'port', 'targetPort', 'nodePort', 'containerPort',
        'replicas', 'minReplicas', 'maxReplicas',
        'limit', 'factor', 'retries', 'revision',
        'terminationGracePeriodSeconds', 'periodSeconds',
        'timeoutSeconds', 'successThreshold', 'failureThreshold',
        'initialDelaySeconds',
    }
    
    # String Fields in Port-Objekten die gequoted werden sollten
    PORT_STRING_FIELDS = {'name', 'protocol'}
    
    # String Fields die gequoted werden sollten
    STRING_FIELDS_REQUIRE_QUOTE = {
        'path', 'repoURL', 'revision', 'targetRevision', 'chart',
        'ref', 'url', 'image', 'repository', 'tag',
    }
    
    # Helm Template Patterns für Integer/Boolean
    HELM_INT_BOOL_PATTERNS = [
        r'\.replicas\b', r'\.replicaCount\b',
        r'\.port\b', r'\.targetPort\b', r'\.nodePort\b', r'\.containerPort\b',
        r'\.enabled\b', r'\.disabled\b',
        r'\.count\b', r'\.limit\b', r'\.factor\b',
        r'\.minReplicas\b', r'\.maxReplicas\b',
        r'\.retries\b', r'\.timeout\b',
        r'\.terminationGracePeriodSeconds\b',
        r'\|\s*int\b', r'\|\s*bool\b', r'\|\s*default\s+\d+',
    ]
    
    # Annotation Keys deren Werte numerisch sein können aber Strings sein müssen
    ANNOTATION_NUMERIC_KEYS = {
        'argocd.argoproj.io/sync-wave',
        'helm.sh/hook-weight',
        'prometheus.io/port',
    }
    
    def __init__(self, strict: bool = False, level: str = 'warning'):
        """
        Args:
            strict: Wenn True, werden Warnungen als Fehler behandelt
            level: Minimum Severity Level ('error', 'warning', 'info')
        """
        self.strict = strict
        self.level = Severity(level)
        self.issues: List[QuoteIssue] = []
        self.current_file: str = ""
        self.lines: List[str] = []
    
    def validate_file(self, file_path: str) -> ValidationResult:
        """Validiert eine YAML-Datei auf Quoting-Regeln."""
        self.issues = []
        self.current_file = file_path
        
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                self.lines = f.readlines()
        except Exception as e:
            print(f"Error reading file {file_path}: {e}", file=sys.stderr)
            return ValidationResult(file_path=file_path, is_valid=False)
        
        # Parse durch die Datei
        context_stack: List[Tuple[int, str]] = []
        in_annotations = False
        in_labels = False
        in_spec = False
        in_template = False
        in_ports = False
        in_go_template_options = False
        
        for line_num, line in enumerate(self.lines, start=1):
            stripped = line.strip()
            
            # Skip Kommentare und leere Zeilen
            if not stripped or stripped.startswith('#'):
                continue
            
            # Skip Multi-Document Separator
            if stripped == '---':
                context_stack = []
                in_annotations = False
                in_labels = False
                in_spec = False
                in_template = False
                in_ports = False
                in_go_template_options = False
                continue
            
            # Update Kontext basierend auf Indentation
            indent = len(line) - len(line.lstrip())
            context_stack = self._update_context(context_stack, indent, stripped)
            context = [ctx for _, ctx in context_stack]
            
            # Update Flags
            in_annotations = 'annotations' in context
            in_labels = 'labels' in context
            in_spec = 'spec' in context
            in_template = 'template' in context
            in_ports = 'ports' in context
            in_go_template_options = 'goTemplateOptions' in context
            
            # Validiere die Zeile
            self._validate_line(
                line_num, line, stripped, context,
                in_annotations, in_labels, in_spec, in_template, 
                in_ports, in_go_template_options
            )
        
        # Erstelle Ergebnis
        errors = sum(1 for i in self.issues if i.severity == Severity.ERROR)
        warnings = sum(1 for i in self.issues if i.severity == Severity.WARNING)
        infos = sum(1 for i in self.issues if i.severity == Severity.INFO)
        
        # Filtere nach Level
        severity_order = {Severity.ERROR: 0, Severity.WARNING: 1, Severity.INFO: 2}
        min_level = severity_order[self.level]
        filtered_issues = [
            i for i in self.issues 
            if severity_order[i.severity] <= min_level
        ]
        
        # Bestimme Validität
        has_errors = any(i.severity == Severity.ERROR for i in filtered_issues)
        has_warnings = any(i.severity == Severity.WARNING for i in filtered_issues)
        
        if has_errors:
            is_valid = False
        elif has_warnings and self.strict:
            is_valid = False
        else:
            is_valid = True
        
        return ValidationResult(
            file_path=file_path,
            is_valid=is_valid,
            issues=filtered_issues,
            errors=errors,
            warnings=warnings,
            infos=infos
        )
    
    def _update_context(self, stack: List[Tuple[int, str]], indent: int, line: str) -> List[Tuple[int, str]]:
        """Aktualisiert den Kontext-Stack basierend auf Indentation."""
        # Entferne Kontexte mit gleicher oder höherer Indentation
        stack = [(i, ctx) for i, ctx in stack if i < indent]
        
        # Füge neuen Kontext hinzu wenn Key gefunden
        if ':' in line:
            key = line.split(':')[0].strip().lstrip('- ')
            context_keys = {
                'metadata', 'annotations', 'labels', 'spec', 'template',
                'generators', 'sources', 'destination', 'syncPolicy', 'ports',
                'env', 'containers', 'volumes', 'goTemplateOptions', 'helm',
                'valueFiles', 'data', 'stringData', 'rules', 'paths',
            }
            if key in context_keys:
                stack.append((indent, key))
        
        return stack
    
    def _validate_line(
        self, line_num: int, line: str, stripped: str, context: List[str],
        in_annotations: bool, in_labels: bool, in_spec: bool, in_template: bool,
        in_ports: bool, in_go_template_options: bool
    ):
        """Validiert eine einzelne Zeile."""
        
        # Handle List Items
        if stripped.startswith('- '):
            self._validate_list_item(
                line_num, line, stripped, context,
                in_annotations, in_ports, in_go_template_options
            )
            return
        
        # Parse Key-Value
        if ':' not in stripped:
            return
        
        parts = stripped.split(':', 1)
        if len(parts) != 2:
            return
        
        key = parts[0].strip()
        value = parts[1].strip()
        
        # Skip wenn kein Wert
        if not value:
            return
        
        # ========== ERROR Level Checks ==========
        
        # 1. Boolean als String
        self._check_boolean_as_string(line_num, line, key, value, context)
        
        # 2. Annotation Integer ohne Quote
        if in_annotations:
            self._check_annotation_value(line_num, line, key, value)
        
        # 3. Integer Field gequoted
        if key in self.INTEGER_FIELDS:
            self._check_integer_field_quoted(line_num, line, key, value, context)
        
        # 4. Helm Template Integer gequoted
        if self._contains_helm_template(value):
            self._check_helm_template(line_num, line, key, value, context)
        
        # 5. goTemplateOptions
        if key == 'goTemplateOptions':
            self._check_go_template_options(line_num, line, value)
        
        # ========== WARNING Level Checks ==========
        
        # 6. Top-Level Fields gequoted
        if not context and key in self.TOP_LEVEL_NO_QUOTE:
            self._check_top_level_quoted(line_num, line, key, value)
        
        # 7. Metadata name/namespace gequoted
        if 'metadata' in context and key in self.METADATA_NO_QUOTE:
            self._check_metadata_quoted(line_num, line, key, value)
        
        # 8. Path/URL nicht gequoted
        if in_spec or in_template:
            self._check_path_url_quoted(line_num, line, key, value, context)
        
        # 9. Port String Fields
        if in_ports and key in self.PORT_STRING_FIELDS:
            self._check_port_string_quoted(line_num, line, key, value)
    
    def _validate_list_item(
        self, line_num: int, line: str, stripped: str, context: List[str],
        in_annotations: bool, in_ports: bool, in_go_template_options: bool
    ):
        """Validiert List Items."""
        value = stripped[2:].strip()  # Entferne "- "
        
        # goTemplateOptions Array Items
        if in_go_template_options or 'goTemplateOptions' in context:
            if value and not self._is_quoted(value):
                self._add_issue(
                    line_num, line,
                    IssueType.GO_TEMPLATE_OPTIONS_NOT_QUOTED,
                    'goTemplateOptions[]',
                    "goTemplateOptions Wert muss gequoted sein",
                    f'- "{value}"',
                    Severity.ERROR
                )
        
        # Integer Array in ports (nur wenn reiner Wert, kein Key-Value)
        if in_ports and ':' not in value:
            if self._is_quoted(value) and value.strip('"\'').isdigit():
                self._add_issue(
                    line_num, line,
                    IssueType.INTEGER_FIELD_QUOTED,
                    'ports[]',
                    "Integer in Array darf nicht gequoted sein",
                    f'- {value.strip("\"\'")}',
                    Severity.ERROR
                )
        
        # valueFiles Array - Helm Templates in Strings
        if 'valueFiles' in context and self._contains_helm_template(value):
            if not self._is_quoted(value):
                self._add_issue(
                    line_num, line,
                    IssueType.HELM_TEMPLATE_STRING_NOT_QUOTED,
                    'valueFiles[]',
                    "Helm Template String muss gequoted sein",
                    f'- "{value}"',
                    Severity.WARNING
                )
    
    # ========== ERROR Level Checks ==========
    
    def _check_boolean_as_string(self, line_num: int, line: str, key: str, value: str, context: List[str]):
        """Prüft ob Boolean als String gequoted ist (ERROR)."""
        # Skip Annotations (dort sind Booleans als Strings OK)
        if 'annotations' in context:
            return
        
        if value.lower() in ('"true"', '"false"', "'true'", "'false'"):
            self._add_issue(
                line_num, line,
                IssueType.BOOLEAN_AS_STRING,
                '.'.join(context + [key]) if context else key,
                f"Boolean darf nicht als String gequoted sein",
                f'{key}: {value.strip("\"\'").lower()}',
                Severity.ERROR
            )
    
    def _check_annotation_value(self, line_num: int, line: str, key: str, value: str):
        """Prüft Annotation Werte (ERROR für Integer, WARNING für Sonderzeichen)."""
        
        # Integer-Werte müssen gequoted sein
        if self._looks_like_integer(value) and not self._is_quoted(value):
            self._add_issue(
                line_num, line,
                IssueType.ANNOTATION_INT_NOT_QUOTED,
                f'annotations.{key}',
                f"Annotation Wert '{value}' muss als String gequoted sein",
                f'{key}: "{value}"',
                Severity.ERROR
            )
        
        # Sonderzeichen (=) sollten gequoted sein
        elif '=' in value and not self._is_quoted(value):
            self._add_issue(
                line_num, line,
                IssueType.ANNOTATION_SPECIAL_CHAR_NOT_QUOTED,
                f'annotations.{key}',
                f"Annotation Wert mit '=' sollte gequoted sein",
                f'{key}: "{value}"',
                Severity.WARNING
            )
    
    def _check_integer_field_quoted(self, line_num: int, line: str, key: str, value: str, context: List[str]):
        """Prüft ob Integer Fields gequoted sind (ERROR)."""
        # Skip Annotations (dort sind Integer als Strings OK)
        if 'annotations' in context:
            return
        
        if self._is_quoted(value):
            inner = value.strip('"\'')
            if inner.isdigit() or (inner.startswith('-') and inner[1:].isdigit()):
                self._add_issue(
                    line_num, line,
                    IssueType.INTEGER_FIELD_QUOTED,
                    '.'.join(context + [key]) if context else key,
                    f"Integer Feld '{key}' darf nicht gequoted sein",
                    f'{key}: {inner}',
                    Severity.ERROR
                )
    
    def _check_helm_template(self, line_num: int, line: str, key: str, value: str, context: List[str]):
        """Prüft Helm Template Quoting."""
        is_quoted = self._is_quoted(value)
        is_int_bool = self._is_int_bool_helm_template(value)
        
        if is_int_bool:
            # Integer/Boolean Template darf NICHT gequoted sein
            if is_quoted:
                self._add_issue(
                    line_num, line,
                    IssueType.HELM_TEMPLATE_INT_QUOTED,
                    '.'.join(context + [key]) if context else key,
                    f"Helm Template für Integer/Boolean darf nicht gequoted sein",
                    f'{key}: {value.strip("\"\'")}',
                    Severity.ERROR
                )
        else:
            # String Template SOLLTE gequoted sein
            if not is_quoted:
                self._add_issue(
                    line_num, line,
                    IssueType.HELM_TEMPLATE_STRING_NOT_QUOTED,
                    '.'.join(context + [key]) if context else key,
                    f"Helm Template für String sollte gequoted sein",
                    f'{key}: "{value}"',
                    Severity.WARNING
                )
    
    def _check_go_template_options(self, line_num: int, line: str, value: str):
        """Prüft goTemplateOptions (ERROR)."""
        # Flow Style Array: ["option1", "option2"]
        if value.startswith('[') and value.endswith(']'):
            inner = value[1:-1]
            if not inner:
                return
            
            items = [item.strip() for item in inner.split(',') if item.strip()]
            unquoted_items = [item for item in items if not self._is_quoted(item)]
            
            if unquoted_items:
                quoted_items = ', '.join(f'"{item.strip("\"\'")}"' for item in items)
                self._add_issue(
                    line_num, line,
                    IssueType.GO_TEMPLATE_OPTIONS_NOT_QUOTED,
                    'goTemplateOptions',
                    f"goTemplateOptions Werte müssen gequoted sein",
                    f'goTemplateOptions: [{quoted_items}]',
                    Severity.ERROR
                )
    
    # ========== WARNING Level Checks ==========
    
    def _check_top_level_quoted(self, line_num: int, line: str, key: str, value: str):
        """Prüft ob Top-Level Fields gequoted sind (WARNING)."""
        if self._is_quoted(value):
            self._add_issue(
                line_num, line,
                IssueType.TOP_LEVEL_QUOTED,
                key,
                f"Top-Level Field '{key}' ist üblicherweise nicht gequoted",
                f'{key}: {value.strip("\"\'")}',
                Severity.WARNING
            )
    
    def _check_metadata_quoted(self, line_num: int, line: str, key: str, value: str):
        """Prüft ob Metadata name/namespace gequoted sind (WARNING)."""
        # Helm Templates dürfen gequoted sein
        if self._contains_helm_template(value):
            return
        
        if self._is_quoted(value):
            self._add_issue(
                line_num, line,
                IssueType.METADATA_QUOTED,
                f'metadata.{key}',
                f"Metadata '{key}' ist üblicherweise nicht gequoted",
                f'{key}: {value.strip("\"\'")}',
                Severity.WARNING
            )
    
    def _check_path_url_quoted(self, line_num: int, line: str, key: str, value: str, context: List[str]):
        """Prüft ob Paths/URLs gequoted sind (WARNING)."""
        # Skip Helm Templates (werden separat geprüft)
        if self._contains_helm_template(value):
            return
        
        # Path Fields
        if key in ('path', 'repoURL', 'targetRevision', 'chart', 'ref', 'revision'):
            if not self._is_quoted(value) and value:
                self._add_issue(
                    line_num, line,
                    IssueType.PATH_NOT_QUOTED,
                    '.'.join(context + [key]) if context else key,
                    f"Feld '{key}' sollte gequoted sein",
                    f'{key}: "{value}"',
                    Severity.WARNING
                )
        
        # URL Fields
        elif value.startswith('http://') or value.startswith('https://'):
            if not self._is_quoted(value):
                self._add_issue(
                    line_num, line,
                    IssueType.URL_NOT_QUOTED,
                    '.'.join(context + [key]) if context else key,
                    f"URL sollte gequoted sein",
                    f'{key}: "{value}"',
                    Severity.WARNING
                )
    
    def _check_port_string_quoted(self, line_num: int, line: str, key: str, value: str):
        """Prüft ob Port String Fields gequoted sind (WARNING)."""
        if not self._is_quoted(value) and value:
            self._add_issue(
                line_num, line,
                IssueType.PORT_STRING_NOT_QUOTED,
                f'ports[].{key}',
                f"Port '{key}' sollte gequoted sein",
                f'{key}: "{value}"',
                Severity.WARNING
            )
    
    # ========== Helper Methods ==========
    
    def _add_issue(
        self, line_num: int, line: str, issue_type: IssueType,
        field_path: str, message: str, suggestion: str, severity: Severity
    ):
        """Fügt ein Issue hinzu."""
        self.issues.append(QuoteIssue(
            line_number=line_num,
            line_content=line.rstrip(),
            issue_type=issue_type,
            field_path=field_path,
            message=message,
            suggestion=suggestion,
            severity=severity
        ))
    
    def _contains_helm_template(self, value: str) -> bool:
        """Prüft ob der Wert ein Helm Template enthält."""
        return '{{' in value and '}}' in value
    
    def _is_int_bool_helm_template(self, value: str) -> bool:
        """Prüft ob das Helm Template ein Integer/Boolean-Wert ist."""
        for pattern in self.HELM_INT_BOOL_PATTERNS:
            if re.search(pattern, value):
                return True
        return False
    
    def _is_quoted(self, value: str) -> bool:
        """Prüft ob ein Wert gequoted ist."""
        value = value.strip()
        return (value.startswith('"') and value.endswith('"')) or \
               (value.startswith("'") and value.endswith("'"))
    
    def _looks_like_integer(self, value: str) -> bool:
        """Prüft ob ein Wert wie ein Integer aussieht."""
        value = value.strip()
        if value.isdigit():
            return True
        if value.startswith('-') and len(value) > 1 and value[1:].isdigit():
            return True
        return False


# ============================================================================
# Output Functions
# ============================================================================

def print_issues(result: ValidationResult, verbose: bool = False):
    """Gibt die gefundenen Probleme aus."""
    if not result.issues:
        if verbose:
            print(f"✅ {result.file_path}: Keine Quoting-Probleme gefunden")
        return
    
    # Gruppiere nach Severity
    errors = [i for i in result.issues if i.severity == Severity.ERROR]
    warnings = [i for i in result.issues if i.severity == Severity.WARNING]
    infos = [i for i in result.issues if i.severity == Severity.INFO]
    
    print(f"\n{'─' * 60}")
    print(f"📄 {result.file_path}")
    print(f"   Errors: {len(errors)} | Warnings: {len(warnings)} | Infos: {len(infos)}")
    print(f"{'─' * 60}")
    
    # Errors zuerst
    if errors:
        print(f"\n❌ ERRORS (Breaking Issues):\n")
        for issue in errors:
            _print_issue(issue)
    
    # Dann Warnings
    if warnings:
        print(f"\n⚠️  WARNINGS (Best Practice):\n")
        for issue in warnings:
            _print_issue(issue)
    
    # Dann Infos
    if infos:
        print(f"\nℹ️  INFO (Optional):\n")
        for issue in infos:
            _print_issue(issue)


def _print_issue(issue: QuoteIssue):
    """Gibt ein einzelnes Issue aus."""
    severity_icon = {
        Severity.ERROR: "❌",
        Severity.WARNING: "⚠️ ",
        Severity.INFO: "ℹ️ "
    }
    
    print(f"  {severity_icon[issue.severity]} Zeile {issue.line_number}: {issue.message}")
    print(f"     Pfad:      {issue.field_path}")
    print(f"     Aktuell:   {issue.line_content.strip()}")
    print(f"     Vorschlag: {issue.suggestion}")
    print()


# ============================================================================
# Main Function
# ============================================================================

def validate_yaml_quotes(
    file_path: str, 
    strict: bool = False, 
    level: str = 'warning'
) -> ValidationResult:
    """
    Validiert eine YAML-Datei auf Kubernetes Quoting-Regeln.
    
    Args:
        file_path: Pfad zur YAML-Datei
        strict: Wenn True, werden Warnungen als Fehler behandelt
        level: Minimum Severity Level ('error', 'warning', 'info')
    
    Returns:
        ValidationResult mit is_valid und issues
    """
    validator = KubernetesQuoteValidator(strict=strict, level=level)
    return validator.validate_file(file_path)


def main():
    """Hauptfunktion für CLI."""
    import argparse
    
    parser = argparse.ArgumentParser(
        description='YAML Quote Validator für Kubernetes Manifeste',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Beispiele:
  %(prog)s file.yaml                    # Validiere mit Warnings
  %(prog)s --level error file.yaml      # Nur Errors anzeigen
  %(prog)s --strict file.yaml           # Warnings als Errors behandeln
  %(prog)s -v file.yaml                 # Verbose Output
        """
    )
    parser.add_argument(
        'files',
        nargs='+',
        help='YAML Dateien zum Validieren'
    )
    parser.add_argument(
        '-v', '--verbose',
        action='store_true',
        help='Verbose output'
    )
    parser.add_argument(
        '--level',
        choices=['error', 'warning', 'info'],
        default='warning',
        help='Minimum severity level to report (default: warning)'
    )
    parser.add_argument(
        '--strict',
        action='store_true',
        help='Treat warnings as errors (exit code 1)'
    )
    
    args = parser.parse_args()
    
    exit_code = 0
    total_errors = 0
    total_warnings = 0
    
    for file_path in args.files:
        path = Path(file_path)
        
        if not path.exists():
            print(f"❌ Datei nicht gefunden: {file_path}", file=sys.stderr)
            exit_code = 1
            continue
        
        if not path.suffix in ('.yaml', '.yml'):
            if args.verbose:
                print(f"⏭️  Überspringe (keine YAML-Datei): {file_path}")
            continue
        
        result = validate_yaml_quotes(
            file_path, 
            strict=args.strict, 
            level=args.level
        )
        
        total_errors += result.errors
        total_warnings += result.warnings
        
        if not result.is_valid:
            exit_code = 1
        
        print_issues(result, verbose=args.verbose)
    
    # Summary
    if len(args.files) > 1:
        print(f"\n{'═' * 60}")
        print(f"📊 ZUSAMMENFASSUNG: {total_errors} Errors, {total_warnings} Warnings")
        print(f"{'═' * 60}")
    
    return exit_code


if __name__ == '__main__':
    sys.exit(main())