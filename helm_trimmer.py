#!/usr/bin/env python3
# filepath: c:\Users\ahryhory\Documents\Git-repos\yaml-validators\helm_trimmer.py
"""
Helm Trimmer - Replaces Helm template syntax with placeholders for YAMLlint.

This module:
1. Replaces {{ }} expressions with valid YAML placeholders
2. Comments out control-flow lines ({{- if }}, {{- end }}, etc.)
3. Preserves line numbers for error reporting
"""

import re
from dataclasses import dataclass, field
from typing import Dict, List, Tuple


@dataclass
class TrimResult:
    """Result of trimming operation."""
    trimmed_content: str
    original_content: str
    placeholder_map: Dict[str, str] = field(default_factory=dict)
    removed_lines: List[int] = field(default_factory=list)


class HelmTrimmer:
    """Trims Helm template syntax for YAMLlint compatibility."""
    
    # Control-flow patterns (entire line should be commented out)
    CONTROL_FLOW_PATTERNS = [
        r'^\s*\{\{-?\s*if\s.*\}\}\s*$',
        r'^\s*\{\{-?\s*else\s*-?\}\}\s*$',
        r'^\s*\{\{-?\s*else\s+if\s.*\}\}\s*$',
        r'^\s*\{\{-?\s*end\s*-?\}\}\s*$',
        r'^\s*\{\{-?\s*range\s.*\}\}\s*$',
        r'^\s*\{\{-?\s*with\s.*\}\}\s*$',
        r'^\s*\{\{-?\s*define\s.*\}\}\s*$',
        r'^\s*\{\{-?\s*template\s.*\}\}\s*$',
        r'^\s*\{\{-?\s*block\s.*\}\}\s*$',
        r'^\s*\{\{-?\s*include\s.*-?\}\}\s*$',
        r'^\s*\{\{-?\s*/\*.*\*/\s*-?\}\}\s*$',
        r'^\s*\{\{-?\s*\$[a-zA-Z_][a-zA-Z0-9_]*\s*:=.*\}\}\s*$',
    ]
    
    # Pattern to match Helm expressions
    HELM_EXPRESSION_PATTERN = re.compile(r'\{\{-?.*?-?\}\}')
    
    def __init__(self):
        self.placeholder_counter = 0
    
    def trim(self, content: str) -> TrimResult:
        """
        Trim Helm template syntax from content.
        
        Args:
            content: Original file content with Helm syntax
            
        Returns:
            TrimResult with trimmed content and mapping
        """
        self.placeholder_counter = 0
        placeholder_map = {}
        removed_lines = []
        
        lines = content.split('\n')
        trimmed_lines = []
        
        for line_num, line in enumerate(lines, 1):
            # Check if entire line is control-flow
            if self._is_control_flow_line(line):
                # Comment out the line to preserve line numbers
                trimmed_lines.append(f'# HELM_TRIMMED: {line.strip()}')
                removed_lines.append(line_num)
                continue
            
            # Replace inline {{ }} expressions with placeholders
            if '{{' in line:
                trimmed_line, line_placeholders = self._replace_expressions(line)
                placeholder_map.update(line_placeholders)
                trimmed_lines.append(trimmed_line)
            else:
                trimmed_lines.append(line)
        
        trimmed_content = '\n'.join(trimmed_lines)
        
        return TrimResult(
            trimmed_content=trimmed_content,
            original_content=content,
            placeholder_map=placeholder_map,
            removed_lines=removed_lines
        )
    
    def _is_control_flow_line(self, line: str) -> bool:
        """Check if line is a pure control-flow statement."""
        for pattern in self.CONTROL_FLOW_PATTERNS:
            if re.match(pattern, line):
                return True
        return False
    
    def _replace_expressions(self, line: str) -> Tuple[str, Dict[str, str]]:
        """
        Replace {{ }} expressions with YAML-valid placeholders.
        
        Handles both:
        - Standalone: value: {{ .Values.foo }}  → value: "__PLACEHOLDER__"
        - In string:  value: "prefix-{{ .Values.foo }}-suffix"  → value: "prefix-__PLACEHOLDER__-suffix"
        """
        placeholders = {}
        result = []
        i = 0
        
        while i < len(line):
            # Look for {{ 
            if line[i:i+2] == '{{':
                # Find the matching }}
                end_pos = line.find('}}', i)
                if end_pos == -1:
                    # No closing }}, just append rest of line
                    result.append(line[i:])
                    break
                
                # Extract the full Helm expression
                helm_expr = line[i:end_pos+2]
                self.placeholder_counter += 1
                
                # Check if we're inside a quoted string
                before = line[:i]
                in_double_quotes = self._is_inside_quotes(before, '"')
                in_single_quotes = self._is_inside_quotes(before, "'")
                
                if in_double_quotes or in_single_quotes:
                    # Inside quotes: use placeholder WITHOUT quotes
                    placeholder = f'__HELM_PLACEHOLDER_{self.placeholder_counter}__'
                else:
                    # Not inside quotes: use placeholder WITH quotes
                    placeholder = f'"__HELM_PLACEHOLDER_{self.placeholder_counter}__"'
                
                placeholders[placeholder] = helm_expr
                result.append(placeholder)
                i = end_pos + 2
            else:
                result.append(line[i])
                i += 1
        
        return ''.join(result), placeholders
    
    def _is_inside_quotes(self, text: str, quote_char: str) -> bool:
        """
        Check if we're inside a quoted string.
        
        Counts unescaped quotes - odd number means we're inside.
        """
        count = 0
        i = 0
        while i < len(text):
            if text[i] == quote_char:
                # Check if escaped
                if i > 0 and text[i-1] == '\\':
                    pass  # Escaped, don't count
                else:
                    count += 1
            i += 1
        
        return count % 2 == 1


def trim_helm_for_yamllint(content: str) -> TrimResult:
    """
    Convenience function to trim Helm syntax for YAMLlint.
    
    Args:
        content: Original Helm template content
        
    Returns:
        TrimResult with trimmed content
    """
    trimmer = HelmTrimmer()
    return trimmer.trim(content)


# ============================================================================
# CLI for testing
# ============================================================================

def main():
    """CLI entry point for testing."""
    import sys
    
    if len(sys.argv) < 2:
        print("Usage: python helm_trimmer.py <file.yaml>")
        sys.exit(1)
    
    filepath = sys.argv[1]
    
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            content = f.read()
    except Exception as e:
        print(f"Error reading file: {e}")
        sys.exit(1)
    
    result = trim_helm_for_yamllint(content)
    
    print("=" * 60)
    print("TRIMMED CONTENT:")
    print("=" * 60)
    print(result.trimmed_content)
    print()
    print("=" * 60)
    print("PLACEHOLDER MAP:")
    print("=" * 60)
    for placeholder, original in result.placeholder_map.items():
        print(f"  {placeholder} → {original}")
    print()
    print(f"Removed lines: {result.removed_lines}")


if __name__ == '__main__':
    main()