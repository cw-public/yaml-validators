#!/usr/bin/env python3
"""
Helm Trimmer - Replaces Helm template syntax with placeholders for YAMLlint.

This module:
1. Replaces {{ }} expressions with valid YAML placeholders
2. Comments out control-flow lines ({{- if }}, {{- end }}, etc.)
3. Preserves line numbers for error reporting
"""

import re
from dataclasses import dataclass, field
from typing import Dict, List


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
    
    def _replace_expressions(self, line: str) -> tuple:
        """Replace {{ }} expressions with YAML-valid placeholders."""
        placeholders = {}
        
        def replace_match(match):
            original = match.group(0)
            self.placeholder_counter += 1
            placeholder = f'"__HELM_PLACEHOLDER_{self.placeholder_counter}__"'
            placeholders[placeholder] = original
            return placeholder
        
        modified_line = self.HELM_EXPRESSION_PATTERN.sub(replace_match, line)
        return modified_line, placeholders


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