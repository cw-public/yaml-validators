#!/usr/bin/env python3
# filepath: c:\Users\ahryhory\Documents\Git-repos\yaml-validators\helm_validator.py
from ruamel.yaml import YAML
import re
import sys
import os
import tempfile
from pathlib import Path

# Force UTF-8 encoding on Windows
if sys.platform == 'win32':
    os.environ['PYTHONIOENCODING'] = 'utf-8'

# Importiere yamllint als Library
try:
    from yamllint import linter
    from yamllint.config import YamlLintConfig
    YAMLLINT_AVAILABLE = True
except ImportError:
    YAMLLINT_AVAILABLE = False

# Pattern für Helm Control-Flow und Zuweisungen die unverändert bleiben sollen
HELM_CONTROL_PATTERNS = [
    r'^\s*\{\{-?\s*\$[a-zA-Z_][a-zA-Z0-9_]*\s*:=',  # Variable Assignment: {{- $var :=
    r'^\s*\{\{-?\s*if\s',                            # {{- if
    r'^\s*\{\{-?\s*else\s*-?\}\}',                   # {{- else }}
    r'^\s*\{\{-?\s*else\s+if\s',                     # {{- else if
    r'^\s*\{\{-?\s*end\s*-?\}\}',                    # {{- end }}
    r'^\s*\{\{-?\s*range\s',                         # {{- range
    r'^\s*\{\{-?\s*with\s',                          # {{- with
    r'^\s*\{\{-?\s*define\s',                        # {{- define
    r'^\s*\{\{-?\s*template\s',                      # {{- template
    r'^\s*\{\{-?\s*include\s',                       # {{- include
    r'^\s*\{\{-?\s*block\s',                         # {{- block
    r'^\s*\{\{-?\s*/\*',                             # {{- /* (Kommentar)
]

class BracketError:
    """Repräsentiert einen Bracket-Fehler."""
    def __init__(self, line_num, line_content, expected, actual, var_path, var_type):
        self.line_num = line_num
        self.line_content = line_content
        self.expected = expected
        self.actual = actual
        self.var_path = var_path
        self.var_type = var_type
    
    def __str__(self):
        return (f"  {self.line_num}:{self.line_content.strip()}\n"
                f"      Variable: {self.var_path} (Typ: {self.var_type})\n"
                f"      Erwartet: {self.expected}\n"
                f"      Gefunden: {self.actual}")


def is_helm_control_line(line):
    """
    Prüft ob eine Zeile Helm Control-Flow oder Zuweisungen enthält.
    Diese Zeilen sollen unverändert bleiben.
    """
    for pattern in HELM_CONTROL_PATTERNS:
        if re.search(pattern, line):
            return True
    return False


def find_helm_structure(start_path):
    """
    Findet die Helm-Chart-Struktur mit chart/ und values/ Ordnern.
    
    Returns:
        tuple: (is_helm, chart_file, values_dir)
    """
    current_path = Path(start_path)
    search_paths = [current_path]
    
    parent = current_path.parent
    for _ in range(4):
        search_paths.append(parent)
        parent = parent.parent
    
    for search_path in search_paths:
        # Neue Struktur: chart/ und values/ Ordner
        chart_dir = search_path / 'chart'
        values_dir = search_path / 'values'
        
        if chart_dir.exists() and chart_dir.is_dir():
            chart_file = chart_dir / 'Chart.yaml'
            if chart_file.exists():
                return True, chart_file, values_dir if values_dir.exists() else None
        
        # Alte Struktur: Chart.yaml direkt
        chart_file = search_path / 'Chart.yaml'
        if chart_file.exists():
            values_file = search_path / 'values.yaml'
            return True, chart_file, values_file if values_file.exists() else None
    
    return False, None, None


def is_helm_template_file(file_path):
    """
    Prüft ob eine Datei Helm-Template-Syntax enthält.
    """
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            content = f.read()
            
        helm_patterns = [
            r'\{\{\s*\.Values\.',
            r'\{\{\s*\.Release\.',
            r'\{\{\s*\.Chart\.',
            r'\{\{\s*\.Capabilities\.',
            r'\{\{\s*\.Template\.',
        ]
        
        for pattern in helm_patterns:
            if re.search(pattern, content):
                return True
        
        return False
    except:
        return False


def remove_helm_template_syntax_for_linting(content):
    """
    Entfernt Helm-Template-Syntax für yamllint.
    Speichert dabei Informationen über die Original-Brackets.
    
    Returns:
        tuple: (cleaned_content, bracket_info_list)
    """
    lines = content.split('\n')
    cleaned_lines = []
    bracket_info_list = []
    
    for line_num, line in enumerate(lines, 1):
        # Control-Flow Zeilen komplett entfernen für Linting
        if is_helm_control_line(line):
            # Ersetze mit Kommentar um Zeilennummern beizubehalten
            cleaned_lines.append(f"# HELM_CONTROL_LINE_{line_num}")
            continue
        
        # Finde alle Template-Ausdrücke und speichere Info
        template_pattern = r'("?)(\{\{-?\s*(.*?)\s*-?\}\})("?)'
        
        def extract_and_replace(match):
            leading_quote = match.group(1)
            inner_content = match.group(3)
            trailing_quote = match.group(4)
            
            has_quotes = bool(leading_quote and trailing_quote)
            
            # Speichere Info wenn es eine Variable ist
            var_match = re.match(r'(\.[A-Z][a-zA-Z0-9._]*)(?:\s*\|.*)?', inner_content)
            if var_match:
                var_path = var_match.group(1)
                bracket_info_list.append({
                    'line_num': line_num,
                    'original_line': line,
                    'var_path': var_path,
                    'has_quotes': has_quotes,
                    'full_match': match.group(0)
                })
            
            # Ersetze mit Placeholder für Linting
            if has_quotes:
                return f'"__HELM_VAR_{len(bracket_info_list)}__"'
            else:
                return f'__HELM_VAR_{len(bracket_info_list)}__'
        
        cleaned_line = re.sub(template_pattern, extract_and_replace, line)
        cleaned_lines.append(cleaned_line)
    
    return '\n'.join(cleaned_lines), bracket_info_list


def load_values_from_directory(values_dir):
    """
    Lädt alle YAML-Dateien aus dem values/ Ordner.
    """
    yaml = YAML()
    yaml.preserve_quotes = True
    combined_type_map = {}
    
    try:
        values_files = list(values_dir.glob('*.yaml')) + list(values_dir.glob('*.yml'))
        
        for values_file in sorted(values_files):
            try:
                with open(values_file, 'r', encoding='utf-8') as f:
                    values_data = yaml.load(f)
                
                if not values_data:
                    continue
                
                def extract_types(data, prefix=''):
                    if isinstance(data, dict):
                        for key, value in data.items():
                            current_path = f"{prefix}.{key}" if prefix else key
                            if isinstance(value, dict):
                                extract_types(value, current_path)
                            else:
                                if isinstance(value, bool):
                                    combined_type_map[current_path] = 'bool'
                                elif isinstance(value, int):
                                    combined_type_map[current_path] = 'int'
                                elif isinstance(value, float):
                                    combined_type_map[current_path] = 'float'
                                else:
                                    combined_type_map[current_path] = 'string'
                
                extract_types(values_data)
                
            except Exception:
                continue
        
        return combined_type_map
        
    except Exception:
        return {}


def load_values_file(values_file):
    """
    Lädt eine einzelne values.yaml Datei.
    """
    yaml = YAML()
    yaml.preserve_quotes = True
    
    try:
        with open(values_file, 'r', encoding='utf-8') as f:
            values_data = yaml.load(f)
        
        type_map = {}
        
        def extract_types(data, prefix=''):
            if isinstance(data, dict):
                for key, value in data.items():
                    current_path = f"{prefix}.{key}" if prefix else key
                    if isinstance(value, dict):
                        extract_types(value, current_path)
                    else:
                        if isinstance(value, bool):
                            type_map[current_path] = 'bool'
                        elif isinstance(value, int):
                            type_map[current_path] = 'int'
                        elif isinstance(value, float):
                            type_map[current_path] = 'float'
                        else:
                            type_map[current_path] = 'string'
        
        extract_types(values_data)
        return type_map
        
    except Exception:
        return {}


def get_var_type(var_path, type_map):
    """
    Bestimmt den Typ einer Variable basierend auf der type_map.
    """
    if var_path.startswith('.Values.'):
        lookup_path = var_path[8:]  # Entferne '.Values.'
        return type_map.get(lookup_path, 'string')
    else:
        # .Release.Name, .Chart.Name etc. sind immer Strings
        return 'string'


def run_yamllint(content, config_file=None):
    """
    Führt yamllint auf dem bereinigten Content aus.
    
    Returns:
        tuple: (success, error_output)
    """
    if not YAMLLINT_AVAILABLE:
        return True, "yamllint nicht verfügbar - überspringe Linting"
    
    try:
        # Lade Config
        if config_file:
            config_path = Path(config_file).resolve()  # Absoluter Pfad
            print(f"DEBUG: Config-Pfad: {config_path}")
            print(f"DEBUG: Existiert: {config_path.exists()}")
            
            if config_path.exists():
                # Lese Config-Inhalt und zeige ihn
                with open(config_path, 'r', encoding='utf-8') as f:
                    config_content = f.read()
                print(f"DEBUG: Config-Inhalt (erste 200 Zeichen):\n{config_content[:200]}")
                
                # Versuche mit absolutem Pfad als String
                conf = YamlLintConfig(file=str(config_path))
            else:
                print(f"DEBUG: Config nicht gefunden, nutze default")
                conf = YamlLintConfig('extends: default')
        else:
            conf = YamlLintConfig('extends: default')
        
        # Führe Linting durch
        gen = linter.run(content, conf)
        problems = list(gen)
        
        if not problems:
            return True, None
        
        # Filtere nur Errors (keine Warnings)
        errors = [p for p in problems if p.level == 'error']
        
        if not errors:
            return True, None
        
        # Format Fehler
        error_output = []
        for problem in errors:
            error_output.append(
                f"  {problem.line}:{problem.column}: "
                f"{problem.level} {problem.message} ({problem.rule})"
            )
        
        return False, '\n'.join(error_output)
        
    except Exception as e:
        import traceback
        return False, f"yamllint Fehler: {str(e)}\n{traceback.format_exc()}"


def validate_brackets(content, type_map):
    """
    Validiert ob die Brackets korrekt gesetzt sind basierend auf den Variablentypen.
    
    Returns:
        list: Liste von BracketError Objekten
    """
    errors = []
    lines = content.split('\n')
    
    for line_num, line in enumerate(lines, 1):
        # Überspringe Control-Flow Zeilen
        if is_helm_control_line(line):
            continue
        
        # Finde Template-Ausdrücke in dieser Zeile
        # Pattern: optionale Quotes, {{ content }}, optionale Quotes
        template_pattern = r'("?)(\{\{-?\s*(.*?)\s*-?\}\})("?)'
        
        for match in re.finditer(template_pattern, line):
            leading_quote = match.group(1)
            trailing_quote = match.group(4)
            inner_content = match.group(3).strip()
            
            has_quotes = bool(leading_quote and trailing_quote)
            
            # Extrahiere Variable und optionale Pipe
            var_match = re.match(r'(\.[A-Z][a-zA-Z0-9._]*)\s*(\|.*)?', inner_content)
            if not var_match:
                continue
            
            var_path = var_match.group(1)
            has_pipe = bool(var_match.group(2))
            
            # Bestimme erwarteten Typ
            var_type = get_var_type(var_path, type_map)
            
            # Bestimme ob Quotes erwartet werden
            if var_type in ['int', 'float', 'bool'] and not has_pipe:
                expected_quotes = False
            else:
                expected_quotes = True
            
            # Validiere
            if has_quotes != expected_quotes:
                if expected_quotes:
                    expected_str = f'"{{{{{inner_content}}}}}"'
                    actual_str = f'{{{{{inner_content}}}}}'
                else:
                    expected_str = f'{{{{{inner_content}}}}}'
                    actual_str = f'"{{{{{inner_content}}}}}"'
                
                errors.append(BracketError(
                    line_num=line_num,
                    line_content=line,
                    expected=expected_str,
                    actual=actual_str,
                    var_path=var_path,
                    var_type=var_type
                ))
    
    return errors


def validate_helm_template(input_file, values_source=None, yamllint_config=None, force=False, verbose=False):
    """
    Validiert ein Helm-Template:
    1. Konvertiert zu YAML (entfernt Helm-Syntax)
    2. Führt yamllint aus
    3. Validiert Bracket-Quoting
    
    Args:
        input_file: Pfad zur Eingabedatei
        values_source: Pfad zum values/ Ordner oder values.yaml
        yamllint_config: Pfad zur yamllint Konfiguration
        force: Verarbeitung erzwingen
        verbose: Ausführliche Ausgabe
    
    Returns:
        int: Exit-Code (0 = OK, 1 = Fehler)
    """
    input_path = Path(input_file)
    
    # Prüfe ob Eingabedatei existiert
    if not input_path.exists():
        print(f"[ERROR] Fehler: Datei '{input_file}' nicht gefunden.")
        return 1
    
    # Prüfe ob es ein Helm-Chart ist
    is_helm, chart_file, auto_values_source = find_helm_structure(input_path.parent)
    
    if not is_helm and not force:
        # Prüfe ob die Datei Helm-Template-Syntax enthält
        if is_helm_template_file(input_file):
            if verbose:
                print(f"[WARNING] Datei enthält Helm-Template-Syntax aber keine Chart-Struktur gefunden.")
                print(f"  Verwende --force um trotzdem zu validieren.")
            return 1
        else:
            # Keine Helm-Datei, überspringe
            if verbose:
                print(f"[SKIP] Keine Helm-Template-Datei: {input_file}")
            return 0
    
    if verbose:
        print(f"\n{'='*60}")
        print(f"Validiere: {input_file}")
        print(f"{'='*60}")
    
    # Eingabedatei lesen
    with open(input_file, 'r', encoding='utf-8') as f:
        content = f.read()
    
    # Prüfe ob Datei Helm-Template-Syntax enthält
    if not is_helm_template_file(input_file):
        if verbose:
            print(f"[SKIP] Keine Helm-Template-Syntax gefunden, überspringe.")
        return 0
    
    # Values laden
    type_map = {}
    if values_source:
        values_path = Path(values_source)
        if values_path.is_dir():
            type_map = load_values_from_directory(values_path)
        elif values_path.is_file():
            type_map = load_values_file(values_path)
    elif auto_values_source:
        if auto_values_source.is_dir():
            type_map = load_values_from_directory(auto_values_source)
        elif auto_values_source.is_file():
            type_map = load_values_file(auto_values_source)
    
    if verbose and type_map:
        print(f"[OK] {len(type_map)} Variablen aus Values geladen")
    
    # Phase 1: Helm-Syntax entfernen für Linting
    cleaned_content, bracket_info = remove_helm_template_syntax_for_linting(content)
    
    if verbose:
        print(f"\n--- Phase 1: YAML Linting ---")
    
    # Phase 2: yamllint ausführen
    lint_success, lint_errors = run_yamllint(cleaned_content, yamllint_config)
    
    if not lint_success:
        print(f"\n[ERROR] yamllint Fehler in {input_file}:")
        print(lint_errors)
        return 1
    
    if verbose:
        print(f"[OK] yamllint: OK")
        print(f"\n--- Phase 2: Bracket-Validierung ---")
    
    # Phase 3: Bracket-Validierung
    bracket_errors = validate_brackets(content, type_map)
    
    if bracket_errors:
        print(f"\n[ERROR] Bracket-Fehler in {input_file}:")
        print(f"  {len(bracket_errors)} Fehler gefunden:\n")
        
        for error in bracket_errors:
            print(error)
            print()
        
        return 1
    
    if verbose:
        print(f"[OK] Bracket-Validierung: OK")
        print(f"\n[OK] {input_file}: Alle Prüfungen bestanden")
    
    return 0


def main():
    """Hauptfunktion mit Argument-Parsing."""
    if len(sys.argv) < 2:
        print("Verwendung: python yaml-parser.py <file> [optionen]")
        print("\nOptionen:")
        print("  --values <path>    Pfad zum values/ Ordner oder values.yaml")
        print("  --config <path>    Pfad zur yamllint Konfiguration")
        print("  --force            Verarbeitung erzwingen")
        print("  --verbose, -v      Ausführliche Ausgabe")
        print("\nBeispiele:")
        print("  python yaml-parser.py chart/templates/deployment.yaml")
        print("  python yaml-parser.py deployment.yaml --config .yamllint.yaml -v")
        print("  python yaml-parser.py deployment.yaml --values ../values/")
        sys.exit(1)
    
    # Parse Argumente
    args = sys.argv[1:]
    
    # Flags
    force = '--force' in args
    verbose = '--verbose' in args or '-v' in args
    
    # Entferne Flags
    args = [a for a in args if a not in ['--force', '--verbose', '-v']]
    
    # Parse benannte Argumente
    values_source = None
    yamllint_config = None
    input_file = None
    
    i = 0
    while i < len(args):
        if args[i] == '--values' and i + 1 < len(args):
            values_source = args[i + 1]
            i += 2
        elif args[i] == '--config' and i + 1 < len(args):
            yamllint_config = args[i + 1]
            i += 2
        elif not args[i].startswith('--'):
            input_file = args[i]
            i += 1
        else:
            i += 1
    
    if not input_file:
        print("[ERROR] Keine Eingabedatei angegeben.")
        sys.exit(1)
    
    # Validierung ausführen
    exit_code = validate_helm_template(
        input_file,
        values_source=values_source,
        yamllint_config=yamllint_config,
        force=force,
        verbose=verbose
    )
    sys.exit(exit_code)


if __name__ == "__main__":
    main()