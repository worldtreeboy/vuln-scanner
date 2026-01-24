<h1 align="center">
  <br>
  <pre>
██╗    ██╗ ██████╗ ██████╗ ██╗     ██████╗ ████████╗██████╗ ███████╗███████╗██████╗  ██████╗ ██╗   ██╗
██║    ██║██╔═══██╗██╔══██╗██║     ██╔══██╗╚══██╔══╝██╔══██╗██╔════╝██╔════╝██╔══██╗██╔═══██╗╚██╗ ██╔╝
██║ █╗ ██║██║   ██║██████╔╝██║     ██║  ██║   ██║   ██████╔╝█████╗  █████╗  ██████╔╝██║   ██║ ╚████╔╝
██║███╗██║██║   ██║██╔══██╗██║     ██║  ██║   ██║   ██╔══██╗██╔══╝  ██╔══╝  ██╔══██╗██║   ██║  ╚██╔╝
╚███╔███╔╝╚██████╔╝██║  ██║███████╗██████╔╝   ██║   ██║  ██║███████╗███████╗██████╔╝╚██████╔╝   ██║
 ╚══╝╚══╝  ╚═════╝ ╚═╝  ╚═╝╚══════╝╚═════╝    ╚═╝   ╚═╝  ╚═╝╚══════╝╚══════╝╚═════╝  ╚═════╝    ╚═╝
  </pre>
</h1>

<h4 align="center">Advanced Multi-Language Static Analysis Security Scanner with Taint Tracking</h4>

<p align="center">
  <a href="#features">Features</a> •
  <a href="#installation">Installation</a> •
  <a href="#usage">Usage</a> •
  <a href="#detection-patterns">Detection Patterns</a> •
  <a href="#integration">Integration</a>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/python-3.8+-3776ab?style=for-the-badge&logo=python&logoColor=white" alt="Python 3.8+">
  <img src="https://img.shields.io/badge/platform-Windows%20|%20Linux%20|%20macOS-0078D4?style=for-the-badge" alt="Platform">
  <img src="https://img.shields.io/badge/license-MIT-22c55e?style=for-the-badge" alt="License">
  <img src="https://img.shields.io/badge/version-2.0-red?style=for-the-badge" alt="Version">
</p>

<p align="center">
  <img src="https://img.shields.io/badge/C%23-239120?style=flat-square&logo=csharp&logoColor=white" alt="C#">
  <img src="https://img.shields.io/badge/Java-ED8B00?style=flat-square&logo=openjdk&logoColor=white" alt="Java">
  <img src="https://img.shields.io/badge/JavaScript-F7DF1E?style=flat-square&logo=javascript&logoColor=black" alt="JavaScript">
  <img src="https://img.shields.io/badge/Python-3776AB?style=flat-square&logo=python&logoColor=white" alt="Python">
  <img src="https://img.shields.io/badge/PHP-777BB4?style=flat-square&logo=php&logoColor=white" alt="PHP">
  <img src="https://img.shields.io/badge/Go-00ADD8?style=flat-square&logo=go&logoColor=white" alt="Go">
  <img src="https://img.shields.io/badge/Ruby-CC342D?style=flat-square&logo=ruby&logoColor=white" alt="Ruby">
  <img src="https://img.shields.io/badge/TypeScript-3178C6?style=flat-square&logo=typescript&logoColor=white" alt="TypeScript">
</p>

---

## Overview

**WORLDTREEBOY** is a next-generation static analysis security scanner that uses **taint tracking** to trace user-controlled data from sources to dangerous sinks. Unlike simple pattern matching, it understands code flow, detects evasion techniques, and provides high-confidence findings with minimal false positives.

```
┌─────────────────────┐     ┌─────────────────────┐     ┌─────────────────────┐
│    TAINT SOURCE     │────▶│    PROPAGATION      │────▶│   DANGEROUS SINK    │
│                     │     │                     │     │                     │
│ • request.args      │     │ • Variable assign   │     │ • cursor.execute()  │
│ • req.query.id      │     │ • Template literals │     │ • Process.Start()   │
│ • Request.Form[]    │     │ • String.Format()   │     │ • eval() / exec()   │
│ • Constructor args  │     │ • Field propagation │     │ • innerHTML         │
└─────────────────────┘     └─────────────────────┘     └─────────────────────┘
```

---

## Features

<table>
<tr>
<td width="50%">

### Core Capabilities
- **Taint Tracking Engine** - Traces data flow from input to sink
- **Multi-Language Support** - 8+ languages with framework awareness
- **Evasion Detection** - Catches obfuscation, encoding, indirection
- **Confidence Scoring** - HIGH/MEDIUM/LOW confidence levels
- **Context-Aware Analysis** - Understands code semantics

</td>
<td width="50%">

### Detection Categories
- SQL/NoSQL Injection
- Command Injection
- Code Injection (eval/exec)
- XXE & XSLT Attacks
- SSRF & SSTI
- Insecure Deserialization
- Path Traversal
- Prototype Pollution

</td>
</tr>
</table>

### Detection Status

| Category | Detection Quality | Notes |
|----------|:-----------------:|-------|
| Command Injection | Excellent | Full taint tracking, ProcessStartInfo analysis, destructor patterns |
| SQL/NoSQL Injection | Excellent | MongoDB $where, sprintf patterns, taint propagation |
| Code Injection | Excellent | eval/exec, ScriptEngine, reflection, getattr attacks |
| Deserialization | Excellent | TypeNameHandling, pickle, ViewState, YAML |
| XXE/XSLT | Excellent | XslCompiledTransform, XsltSettings, XmlResolver |
| SSRF/SSTI | Good | HttpClient, RazorEngine, template injection |
| XSS | Basic | DOM sinks detected, but **taint tracking not fully implemented for XSS** |

> **Note:** XSS detection currently relies on pattern matching rather than full taint analysis. It catches obvious DOM-based XSS (innerHTML, document.write) and framework-specific patterns, but may miss complex data flow scenarios. Improvements planned for future releases.

---

## Installation

```bash
# Clone the repository
git clone https://github.com/worldtreeboy/vuln-scanner.git
cd vuln-scanner

# No dependencies required - pure Python 3.8+
python3 ast-scanner.py --help
```

---

## Usage

### Quick Start

```bash
# Scan a project directory
python3 ast-scanner.py /path/to/project

# Scan a single file
python3 ast-scanner.py vulnerable_app.cs

# Scan with JSON output
python3 ast-scanner.py project/ --output json -o report.json
```

### Filter by Category

```bash
# Focus on injection vulnerabilities
python3 ast-scanner.py project/ --category sql command code

# Check for deserialization issues
python3 ast-scanner.py project/ --category deser

# NoSQL and XXE only
python3 ast-scanner.py project/ --category nosql xxe
```

### Filter by Confidence

```bash
# High-confidence findings only (fewer false positives)
python3 ast-scanner.py project/ --min-confidence HIGH

# Include medium confidence
python3 ast-scanner.py project/ --min-confidence MEDIUM
```

### Vendor File Handling

By default, vendor libraries and minified files are excluded to reduce noise:

```bash
# Default scan (excludes node_modules, *.min.js, etc.)
python3 ast-scanner.py project/

# Scan everything including vendor files
python3 ast-scanner.py project/ --scan-all
```

**Excluded by default:** `*.min.js`, `*.bundle.js`, `jquery*.js`, `bootstrap*.js`, `angular*.js`, `react*.js`, `vue*.js`, `lodash*.js`, `node_modules/`, `vendor/`, `dist/`, `build/`

---

## Detection Patterns

### Logic-Based Evasion Detection

Catches sophisticated patterns that hide the connection between source and sink:

<details>
<summary><b>Python: getattr Shadow Attack</b></summary>

```python
# DETECTED: getattr with user-controlled attribute name
func_name = user_data.get("action")
method = getattr(module, func_name)   # Can access any attribute
method(user_data.get("arg"))          # Execute arbitrary code

# DETECTED: getattr accessing os module
method_name = request.args.get('method')
handler = getattr(os, method_name)    # Attacker calls os.system, etc.
```
</details>

<details>
<summary><b>PHP: strrev() Variable Function Evasion</b></summary>

```php
// DETECTED: strrev() hides 'passthru'
$func = strrev("urhtssap");  // Decodes to "passthru"
$func($_GET['cmd']);         // Variable function executes command

// DETECTED: strrev() hides 'system', 'shell_exec', 'exec'
$exec = strrev("metsys");    // Decodes to "system"
$exec($user_input);          // Command injection
```
</details>

<details>
<summary><b>C#: LINQ Taint Tunnel</b></summary>

```csharp
// DETECTED: LINQ Select transforms tainted data for shell
var commands = new List<string> { userInput };
var shellCmds = commands.Select(x => $"/c {x}").ToList();
Process.Start("cmd.exe", shellCmds.FirstOrDefault());

// DETECTED: LINQ chain with FirstOrDefault to Process.Start
var result = userInputs
    .Where(x => x.Length > 0)
    .Select(x => $"-Command {x}")
    .FirstOrDefault();
Process.Start("powershell.exe", result);
```
</details>

<details>
<summary><b>JavaScript: Proxy Trap Evasion</b></summary>

```javascript
// DETECTED: Proxy get trap with eval
const evasiveProxy = new Proxy({}, {
    get: (target, prop) => eval(sessionStorage.getItem(prop))
});
evasiveProxy.anything;  // Any property access triggers eval

// DETECTED: Proxy set trap with innerHTML
const proxy = new Proxy({}, {
    set: (t, p, v) => { element.innerHTML = v; return true; }
});
proxy.content = location.hash;
```
</details>

<details>
<summary><b>Java: Base64 + ScriptEngine Evasion</b></summary>

```java
// DETECTED: Base64 decoded data flows to ScriptEngine
byte[] decoded = Base64.getDecoder().decode(userInput);
String script = new String(decoded);
engine.eval(script);

// DETECTED: Inline ScriptEngine chain
new ScriptEngineManager().getEngineByName("js").eval(userInput);
```
</details>

---

### Evasive XSS Detection

<details>
<summary><b>ASCII Array Encoding</b></summary>

```javascript
// DETECTED: ASCII codes spelling "innerHTML"
const _0x5f21 = [105, 110, 110, 101, 114, 72, 84, 77, 76];
const decode = (arr) => arr.map(c => String.fromCharCode(c)).join('');
element[decode(_0x5f21)] = userInput;
```
</details>

<details>
<summary><b>Computed Property Access</b></summary>

```javascript
// DETECTED: Building sink name from fragments
const sink = "inn" + "erHT" + "ML";
element[sink] = userInput;
```
</details>

<details>
<summary><b>Async Taint Flow</b></summary>

```javascript
// DETECTED: setTimeout/Promise/RAF with taint source + sink
setTimeout(() => {
    document.body.innerHTML = sessionStorage.getItem('payload');
}, 0);
```
</details>

<details>
<summary><b>Sanitization Bypass Detection</b></summary>

```javascript
// DETECTED: .replace() only removes FIRST occurrence (no /g flag)
let sanitized = input.replace("<script>", "");

// DETECTED: Case-sensitive filter bypass
let clean = input.replace(/<script>/g, "");  // Missing 'i' flag

// DETECTED: Non-recursive sanitization
let safe = input.replace("<script>", "");
// Input: "<scr<script>ipt>" → Output: "<script>"
```
</details>

---

### C# Advanced Detection

<details>
<summary><b>Destructor Command Injection</b></summary>

```csharp
// DETECTED: Taint flows from constructor to destructor
public class TimeDelayedPayload {
    private string _payload;

    public TimeDelayedPayload(string userInput) {
        _payload = userInput;  // Constructor taint source
    }

    ~TimeDelayedPayload() {
        // CRITICAL: Destructor executes with tainted field
        Process.Start("cmd.exe", "/c " + _payload);
    }
}
```
</details>

<details>
<summary><b>ProcessStartInfo Block Analysis</b></summary>

```csharp
// DETECTED: Object initializer with tainted Arguments
ProcessStartInfo psi = new ProcessStartInfo {
    FileName = "cmd.exe",
    Arguments = "/c ping " + userInput,
    UseShellExecute = false
};
Process.Start(psi);
```
</details>

<details>
<summary><b>XSLT XXE Detection</b></summary>

```csharp
// DETECTED: XsltSettings enables dangerous features
var xslt = new XslCompiledTransform();
xslt.Load(xslPath, XsltSettings.TrustedXslt, new XmlUrlResolver());
```
</details>

---

### Configuration Security

<details>
<summary><b>ASP.NET web.config Analysis</b></summary>

```xml
<!-- CRITICAL: ViewState MAC globally disabled -->
<pages enableViewStateMac="false" />

<!-- CRITICAL: MachineKey validation disabled -->
<machineKey validation="None" />

<!-- HIGH: Debug mode in production -->
<compilation debug="true" />

<!-- HIGH: Cookieless sessions enable fixation -->
<sessionState cookieless="true" />
```
</details>

---

## Sample Output

```
================================================================================
AST-BASED VULNERABILITY SCAN REPORT
================================================================================
Scan Date: 2026-01-24 09:15:00
Files Scanned: 42
Total Findings: 8

Summary by Severity:
  CRITICAL  : 4
  HIGH      : 3
  MEDIUM    : 1

Summary by Confidence:
  HIGH      : 7
  MEDIUM    : 1
================================================================================

FILE: Controllers/NetworkController.cs
--------------------------------------------------------------------------------
[CRITICAL] OS Command Injection - ProcessStartInfo with tainted Arguments (Confidence: HIGH)
  Line 45: Arguments = "/c ping " + address,
  -> ProcessStartInfo.Arguments built with tainted variable 'address'.

[CRITICAL] Destructor Command Injection (Confidence: HIGH)
  Line 67: Process.Start("cmd.exe", "/c " + _payload);
  -> Destructor executes shell command with tainted field '_payload'.

FILE: Services/XmlProcessor.cs
--------------------------------------------------------------------------------
[CRITICAL] XXE - XslCompiledTransform with TrustedXslt (Confidence: HIGH)
  Line 23: xslt.Load(xslPath, XsltSettings.TrustedXslt, new XmlUrlResolver());
  -> XsltSettings.TrustedXslt enables scripts and document() - allows XXE/RCE.

FILE: web.config
--------------------------------------------------------------------------------
[CRITICAL] Insecure Deserialization - ViewState MAC Disabled (Confidence: HIGH)
  Line 12: <pages enableViewStateMac="false" />
  -> ViewState MAC disabled. Vulnerable to ysoserial.net gadgets.

================================================================================
```

---

## Integration

### GitHub Actions

```yaml
name: Security Scan
on: [push, pull_request]

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: '3.11'

      - name: Run Security Scanner
        run: |
          python3 ast-scanner.py . --min-confidence HIGH --output json -o results.json

      - name: Check for Critical Findings
        run: |
          if grep -q '"severity": "CRITICAL"' results.json; then
            echo "::error::Critical vulnerabilities found!"
            exit 1
          fi

      - name: Upload Results
        uses: actions/upload-artifact@v4
        with:
          name: security-report
          path: results.json
```

### Pre-commit Hook

```bash
#!/bin/bash
# .git/hooks/pre-commit

python3 ast-scanner.py . --min-confidence HIGH --category sql command code deser
if [ $? -ne 0 ]; then
    echo "Security vulnerabilities found. Commit blocked."
    exit 1
fi
```

### GitLab CI

```yaml
security-scan:
  stage: test
  image: python:3.11
  script:
    - python3 ast-scanner.py . --output json -o gl-sast-report.json
  artifacts:
    reports:
      sast: gl-sast-report.json
```

---

## CLI Reference

```
usage: ast-scanner.py [-h] [-v] [-c CATEGORY] [--output {text,json}]
                      [-o OUTPUT_FILE] [--min-confidence {HIGH,MEDIUM,LOW}]
                      [--scan-all] target

Arguments:
  target                    File or directory to scan

Options:
  -h, --help                Show help message
  -v, --verbose             Enable detailed output
  -c, --category CATEGORY   Filter by category (sql, nosql, code, command, etc.)
  --output {text,json}      Output format (default: text)
  -o, --output-file FILE    Save report to file
  --min-confidence LEVEL    Minimum confidence level (HIGH, MEDIUM, LOW)
  --scan-all                Include vendor libraries and minified files
```

### Categories

| Category | Description |
|----------|-------------|
| `sql` | SQL Injection |
| `nosql` | NoSQL Injection (MongoDB, etc.) |
| `code` | Code Injection (eval, exec, ScriptEngine) |
| `command` | Command Injection (system, Process.Start) |
| `deser` | Insecure Deserialization |
| `ssti` | Server-Side Template Injection |
| `ssrf` | Server-Side Request Forgery |
| `xxe` | XML External Entity |
| `xpath` | XPath Injection |
| `xss` | Cross-Site Scripting |
| `path` | Path Traversal |
| `all` | All categories (default) |

---

## Language Support

| Language | Extensions | Framework Support |
|----------|------------|-------------------|
| **Python** | `.py` | Flask, Django, FastAPI |
| **JavaScript** | `.js`, `.jsx` | Express.js, React, Angular, Vue, jQuery |
| **TypeScript** | `.ts`, `.tsx` | Node.js, Express, React |
| **Java** | `.java` | Spring, Servlet API |
| **Kotlin** | `.kt` | Android, Spring |
| **C#** | `.cs` | ASP.NET, .NET Core |
| **PHP** | `.php`, `.phtml` | Laravel, WordPress |
| **Go** | `.go` | net/http, gin, echo |
| **Ruby** | `.rb`, `.erb` | Rails, Sinatra |

---

## Taint Sources by Framework

| Framework | Tracked Sources |
|-----------|-----------------|
| **Flask** | `request.args`, `request.form`, `request.json`, `request.data`, `request.cookies` |
| **Django** | `request.GET`, `request.POST`, `request.body`, `request.META` |
| **FastAPI** | `Query()`, `Body()`, `Form()`, `File()`, `Header()`, `Cookie()` |
| **Express.js** | `req.query.*`, `req.body.*`, `req.params.*`, `req.cookies`, `req.headers` |
| **ASP.NET** | `Request.QueryString`, `Request.Form`, `Request[]`, `HttpContext.Request` |
| **Spring** | `@RequestParam`, `@PathVariable`, `@RequestBody`, `HttpServletRequest` |
| **General** | `input()`, `sys.argv`, `os.environ`, `process.argv`, `Environment.GetCommandLineArgs()` |

---

## Project Structure

```
vuln-scanner/
├── ast-scanner.py      # Main scanner with taint tracking
├── vuln-scanner.py     # Regex-based pattern scanner (legacy)
├── README.md
├── LICENSE
└── test-files/         # Intentionally vulnerable test cases
    ├── evasive-*.{py,php,cs,js,java}  # Evasion pattern tests
    ├── sanitization-bypass.js          # Weak sanitization tests
    ├── xss-test.{js,php}               # XSS pattern tests
    ├── web.config                       # ASP.NET config tests
    └── ...
```

---

## Contributing

Contributions are welcome! Areas of focus:

- Improving XSS taint tracking
- Adding new language support
- Framework-specific detection rules
- False positive reduction

---

## Disclaimer

This tool is intended for **authorized security testing only**.

- Obtain proper authorization before scanning third-party code
- Verify findings manually - automated tools can produce false positives
- Use as part of a comprehensive security program
- The authors are not responsible for misuse of this tool

---

## License

MIT License - see [LICENSE](LICENSE) for details.

---

<p align="center">
  <b>worldtreeboy</b><br>
  <a href="https://github.com/worldtreeboy">github.com/worldtreeboy</a>
</p>

<p align="center">
  <sub>Built for security researchers, by security researchers.</sub>
</p>
