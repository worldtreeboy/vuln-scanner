#!/usr/bin/env python3
"""
Formatter for vuln-scanner.py
Aligns all VulnerabilityPattern blocks with consistent formatting.
"""

import re
import sys


def format_vulnerability_patterns(content: str) -> str:
    """
    Format all VulnerabilityPattern blocks with consistent indentation:
    - VulnerabilityPattern( at base indent (4 spaces inside list)
    - name=, category=, patterns=, severity=, languages=, false_positive_patterns= at 8 spaces
    - Pattern strings inside lists at 12 spaces
    - Comments inside lists at 12 spaces
    """
    
    lines = content.split('\n')
    result = []
    
    i = 0
    in_patterns_list = False  # Inside VULNERABILITY_PATTERNS = [...]
    in_vuln_pattern = False   # Inside a VulnerabilityPattern(...)
    in_patterns_array = False # Inside patterns=[...]
    in_fp_array = False       # Inside false_positive_patterns=[...]
    in_languages_array = False # Inside languages=[...]
    bracket_depth = 0
    vuln_pattern_depth = 0
    
    while i < len(lines):
        line = lines[i]
        stripped = line.strip()
        
        # Detect start of VULNERABILITY_PATTERNS list
        if 'VULNERABILITY_PATTERNS' in line and '=' in line and '[' in line:
            result.append(line)
            in_patterns_list = True
            i += 1
            continue
        
        # Detect end of VULNERABILITY_PATTERNS list (final ])
        if in_patterns_list and stripped == ']' and not in_vuln_pattern:
            result.append(']')
            in_patterns_list = False
            i += 1
            continue
        
        # Inside VULNERABILITY_PATTERNS list
        if in_patterns_list:
            # Section comment headers (# ===... or # ---)
            if stripped.startswith('# ===') or stripped.startswith('# ---'):
                result.append(f'    {stripped}')
                i += 1
                continue
            
            # Regular comments
            if stripped.startswith('#') and not in_vuln_pattern:
                result.append(f'    {stripped}')
                i += 1
                continue
            
            # Empty lines
            if not stripped:
                result.append('')
                i += 1
                continue
            
            # Start of VulnerabilityPattern
            if stripped.startswith('VulnerabilityPattern('):
                in_vuln_pattern = True
                vuln_pattern_depth = 1
                result.append('    VulnerabilityPattern(')
                i += 1
                continue
            
            # Inside VulnerabilityPattern
            if in_vuln_pattern:
                # Track depth
                open_count = stripped.count('(') + stripped.count('[') + stripped.count('{')
                close_count = stripped.count(')') + stripped.count(']') + stripped.count('}')
                
                # End of VulnerabilityPattern
                if stripped in ['),', ')']:
                    result.append('    ),')
                    in_vuln_pattern = False
                    in_patterns_array = False
                    in_fp_array = False
                    in_languages_array = False
                    vuln_pattern_depth = 0
                    i += 1
                    continue
                
                # name= line
                if stripped.startswith('name='):
                    result.append(f'        {stripped}')
                    i += 1
                    continue
                
                # category= line
                if stripped.startswith('category='):
                    result.append(f'        {stripped}')
                    i += 1
                    continue
                
                # severity= line
                if stripped.startswith('severity='):
                    result.append(f'        {stripped}')
                    i += 1
                    continue
                
                # patterns= start
                if stripped.startswith('patterns=') or stripped == 'patterns=[':
                    in_patterns_array = True
                    in_fp_array = False
                    in_languages_array = False
                    result.append('        patterns=[')
                    i += 1
                    continue
                
                # languages= line (usually single line)
                if stripped.startswith('languages='):
                    in_languages_array = '[' in stripped and ']' not in stripped
                    result.append(f'        {stripped}')
                    i += 1
                    continue
                
                # false_positive_patterns= start
                if stripped.startswith('false_positive_patterns=') or stripped == 'false_positive_patterns=[':
                    in_patterns_array = False
                    in_fp_array = True
                    in_languages_array = False
                    if stripped == 'false_positive_patterns=[' or stripped.endswith('['):
                        result.append('        false_positive_patterns=[')
                    elif ']' in stripped:
                        # Single line false_positive_patterns
                        result.append(f'        {stripped}')
                        in_fp_array = False
                    else:
                        result.append(f'        {stripped}')
                    i += 1
                    continue
                
                # End of patterns array
                if stripped == '],' and (in_patterns_array or in_fp_array or in_languages_array):
                    result.append('        ],')
                    in_patterns_array = False
                    in_fp_array = False
                    in_languages_array = False
                    i += 1
                    continue
                
                # Pattern strings (r'...' or r"...")
                if stripped.startswith("r'") or stripped.startswith('r"'):
                    result.append(f'            {stripped}')
                    i += 1
                    continue
                
                # Comments inside pattern block
                if stripped.startswith('#'):
                    if in_patterns_array or in_fp_array:
                        result.append(f'            {stripped}')
                    else:
                        result.append(f'        {stripped}')
                    i += 1
                    continue
                
                # Other content inside VulnerabilityPattern
                result.append(f'        {stripped}')
                i += 1
                continue
        
        # Outside VULNERABILITY_PATTERNS - keep as-is
        result.append(line)
        i += 1
    
    return '\n'.join(result)


def fix_specific_issues(content: str) -> str:
    """Fix specific known issues in the scanner"""
    
    # Fix JNDI import false positive
    if "Code Injection - Java JNDI" in content:
        if "r'^import\\s+'" not in content:
            pattern = r'(name="Code Injection - Java JNDI".*?false_positive_patterns=\[)(\s*)'
            match = re.search(pattern, content, re.DOTALL)
            if match:
                insert_text = match.group(1) + "\n            r'^import\\s+',\n            r'import\\s+javax\\.naming',"
                content = content[:match.start()] + insert_text + content[match.end():]
                print('[+] Added import exclusion to JNDI patterns')
    
    # Fix SSTI matching reflection
    if "SSTI - " in content:
        if 'getDeclaredConstructor' not in content.split("SSTI")[1][:2000]:
            # Find any SSTI pattern's false_positive_patterns
            pattern = r'(name="SSTI -[^"]*".*?false_positive_patterns=\[)(\s*)'
            for match in re.finditer(pattern, content, re.DOTALL):
                if 'getDeclaredConstructor' not in content[match.start():match.start()+1500]:
                    insert_pos = match.end()
                    new_fps = "\n            r'getDeclaredConstructor',\n            r'clazz\\.',\n            r'Class\\.forName',\n            r'\\.newInstance\\(\\)',"
                    content = content[:insert_pos] + new_fps + content[insert_pos:]
                    print('[+] Added reflection exclusion to SSTI patterns')
                    break
    
    return content


def add_new_auth_patterns(content: str) -> str:
    """Add improved auth patterns if missing"""
    
    # Check if we already have the improved patterns
    if "Auth Bypass - Empty/Null Check Bypass" in content:
        return content
    
    # Find the auth bypass section
    auth_section_pattern = r'(# =+\s*\n\s*# AUTHENTICATION BYPASS PATTERNS\s*\n\s*# =+)'
    match = re.search(auth_section_pattern, content)
    
    if not match:
        return content
    
    # New patterns to add after existing auth patterns
    new_patterns = '''
    VulnerabilityPattern(
        name="Auth Bypass - Empty/Null Check Bypass",
        category=VulnCategory.AUTH_BYPASS,
        patterns=[
            # Java empty/null bypasses
            r'\\|\\|\\s*\\w+\\s*\\.\\s*isEmpty\\s*\\(\\s*\\)',
            r'\\|\\|\\s*\\w+\\s*\\.\\s*isBlank\\s*\\(\\s*\\)',
            r'\\|\\|\\s*\\w+\\s*==\\s*null',
            r'(?:password|token|key|secret|auth)\\w*\\s*\\.\\s*isEmpty\\s*\\(\\s*\\)',
            # Python empty/None bypasses
            r'if\\s+not\\s+(?:password|token|key|secret|auth)\\w*\\s*:',
            r'(?:password|token|key|secret|auth)\\w*\\s*(?:==|is)\\s*None',
            # JS/TS falsy bypasses
            r'!\\s*(?:password|token|key|secret|auth)\\w*\\s*[&|{)\\]]',
            # PHP empty bypasses
            r'empty\\s*\\(\\s*\\$(?:password|token|key|secret|auth)',
        ],
        severity=Severity.CRITICAL,
        languages=[".js", ".ts", ".py", ".php", ".java", ".cs", ".rb", ".go", ".kt"],
        false_positive_patterns=[
            r'throw',
            r'raise',
            r'return\\s+false',
            r'deny',
            r'reject',
        ],
    ),

    VulnerabilityPattern(
        name="Auth Bypass - Broken Access Control",
        category=VulnCategory.AUTH_BYPASS,
        patterns=[
            # OR conditions that bypass auth
            r'\\|\\|\\s*\\w+\\s*\\.\\s*isEmpty\\s*\\(\\s*\\)',
            r'\\|\\|\\s*\\w+\\s*\\.\\s*isBlank\\s*\\(\\s*\\)',
            r'\\|\\|\\s*\\w+\\s*[=!]=\\s*["\\'"]["\\'"]',
            r'\\|\\|\\s*!\\s*\\w+',
            # Commented out auth checks
            r'//\\s*if\\s*\\(\\s*!?\\s*(?:auth|isAdmin|checkPermission|verify)',
            # Always-true conditions
            r'if\\s*\\(\\s*true\\s*\\)',
            r'if\\s+True\\s*:',
        ],
        severity=Severity.CRITICAL,
        languages=[".js", ".ts", ".py", ".php", ".java", ".cs", ".rb", ".go", ".kt"],
        false_positive_patterns=[
            r'test',
            r'spec',
            r'mock',
        ],
    ),
'''
    
    # Find position after the last auth pattern before next section
    # Look for the next section header after auth bypass
    next_section = re.search(r'\n\s*# =+\s*\n\s*# (?!AUTHENTICATION)[A-Z]', content[match.end():])
    
    if next_section:
        insert_pos = match.end() + next_section.start()
        # Find the last ), before the next section
        last_pattern_end = content.rfind('),', match.end(), insert_pos)
        if last_pattern_end > 0:
            content = content[:last_pattern_end+2] + new_patterns + content[last_pattern_end+2:]
            print('[+] Added new auth bypass patterns')
    
    return content


def main():
    if len(sys.argv) < 2:
        filepath = 'vuln-scanner.py'
    else:
        filepath = sys.argv[1]
    
    print(f'[*] Processing {filepath}...')
    
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            content = f.read()
    except FileNotFoundError:
        print(f'[!] File not found: {filepath}')
        return 1
    
    # Backup
    backup_path = filepath + '.backup'
    with open(backup_path, 'w', encoding='utf-8') as f:
        f.write(content)
    print(f'[+] Backup saved to {backup_path}')
    
    # Apply fixes
    content = fix_specific_issues(content)
    content = add_new_auth_patterns(content)
    content = format_vulnerability_patterns(content)
    
    # Clean up multiple blank lines
    content = re.sub(r'\n{3,}', '\n\n', content)
    
    # Write back
    with open(filepath, 'w', encoding='utf-8') as f:
        f.write(content)
    
    print(f'[+] Formatted {filepath}')
    print('[*] Done!')
    
    # Verify syntax
    print('[*] Verifying syntax...')
    import subprocess
    result = subprocess.run(['python3', '-m', 'py_compile', filepath], capture_output=True, text=True)
    if result.returncode == 0:
        print('[+] Syntax OK')
    else:
        print('[!] Syntax error:')
        print(result.stderr)
        return 1
    
    return 0


if __name__ == '__main__':
    sys.exit(main())
