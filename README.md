# WORLDTREEBOY Vulnerability Scanner

```
██╗    ██╗ ██████╗ ██████╗ ██╗     ██████╗ ████████╗██████╗ ███████╗███████╗██████╗  ██████╗ ██╗   ██╗
██║    ██║██╔═══██╗██╔══██╗██║     ██╔══██╗╚══██╔══╝██╔══██╗██╔════╝██╔════╝██╔══██╗██╔═══██╗╚██╗ ██╔╝
██║ █╗ ██║██║   ██║██████╔╝██║     ██║  ██║   ██║   ██████╔╝█████╗  █████╗  ██████╔╝██║   ██║ ╚████╔╝
██║███╗██║██║   ██║██╔══██╗██║     ██║  ██║   ██║   ██╔══██╗██╔══╝  ██╔══╝  ██╔══██╗██║   ██║  ╚██╔╝
╚███╔███╔╝╚██████╔╝██║  ██║███████╗██████╔╝   ██║   ██║  ██║███████╗███████╗██████╔╝╚██████╔╝   ██║
 ╚══╝╚══╝  ╚═════╝ ╚═╝  ╚═╝╚══════╝╚═════╝    ╚═╝   ╚═╝  ╚═╝╚══════╝╚══════╝╚═════╝  ╚═════╝    ╚═╝
                        ╔═╗╔═╗╔╦╗  ╔╗ ┌─┐┌─┐┌─┐┌┬┐  ╔═╗┌─┐┌─┐┌┐┌┌┐┌┌─┐┬─┐
                        ╠═╣╚═╗ ║   ╠╩╗├─┤└─┐├┤  ││  ╚═╗│  ├─┤││││││├┤ ├┬┘
                        ╩ ╩╚═╝ ╩   ╚═╝┴ ┴└─┘└─┘─┴┘  ╚═╝└─┘┴ ┴┘└┘┘└┘└─┘┴└─
                                   Security Scanner v2.0
                      Taint Tracking | Multi-Language | Deep Analysis
```

<p align="center">
  <strong>Advanced Multi-Language Static Code Security Analysis</strong><br>
  <sub>Taint Tracking | AST Analysis | Evasion Detection | Configuration Auditing</sub>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/python-3.8+-3776ab?style=for-the-badge&logo=python&logoColor=white" alt="Python 3.8+">
  <img src="https://img.shields.io/badge/platform-Windows%20|%20Linux%20|%20macOS-0078D4?style=for-the-badge" alt="Platform">
  <img src="https://img.shields.io/badge/license-MIT-22c55e?style=for-the-badge" alt="License">
</p>

<p align="center">
  <img src="https://img.shields.io/badge/C%23-239120?style=flat-square&logo=csharp&logoColor=white" alt="C#">
  <img src="https://img.shields.io/badge/Java-ED8B00?style=flat-square&logo=openjdk&logoColor=white" alt="Java">
  <img src="https://img.shields.io/badge/JavaScript-F7DF1E?style=flat-square&logo=javascript&logoColor=black" alt="JavaScript">
  <img src="https://img.shields.io/badge/Python-3776AB?style=flat-square&logo=python&logoColor=white" alt="Python">
  <img src="https://img.shields.io/badge/PHP-777BB4?style=flat-square&logo=php&logoColor=white" alt="PHP">
  <img src="https://img.shields.io/badge/Go-00ADD8?style=flat-square&logo=go&logoColor=white" alt="Go">
  <img src="https://img.shields.io/badge/Ruby-CC342D?style=flat-square&logo=ruby&logoColor=white" alt="Ruby">
</p>

---

## Overview

A powerful cross-platform static analysis toolkit for detecting security vulnerabilities across multiple languages. Features advanced taint tracking, evasion detection, and configuration security auditing.

<table>
<tr>
<td width="50%">

### AST Scanner
**Deep analysis with taint tracking**

- Traces user input through code paths
- Context-aware detection with confidence scoring
- Constant folding & obfuscation detection
- Destructor/Finalizer delayed execution detection
- Constructor-to-field taint propagation
- JNI native method detection (Java)
- ASP.NET ViewState & web.config analysis
- Shadow eval & dynamic code detection (JS)

</td>
<td width="50%">

### Regex Scanner
**Fast pattern-based detection**

- High-speed directory scanning
- Binary & DLL analysis
- .NET decompilation (ILSpy)
- Broad pattern coverage
- CI/CD integration ready

</td>
</tr>
</table>

---

## What's New

### Latest Features

| Feature | Description | Languages |
|---------|-------------|-----------|
| **Destructor Command Injection** | Detects delayed execution attacks via C# finalizers | C# |
| **XSLT XXE Detection** | XslCompiledTransform with XsltSettings.TrustedXslt | C# |
| **ViewState Vulnerability Scanner** | EnableViewStateMac, ViewStateEncryptionMode analysis | C#, ASP.NET |
| **Web.config Analyzer** | MachineKey, CustomErrors, Debug mode, Session settings | ASP.NET |
| **Shadow Eval Detection** | Reversed strings, indirect eval, dynamic global access | JavaScript |
| **Express.js Taint Propagation** | req.query/body/params through template literals to exec | JavaScript |
| **Evasive Pattern Detection** | XPath, SSRF, SSTI, TypeNameHandling, string.Format SQLi | C#, Java |

---

## AST Scanner - Deep Analysis Engine

The AST scanner (`ast-scanner.py`) provides advanced vulnerability detection through **taint tracking** - following user-controlled data from sources to dangerous sinks.

### How Taint Tracking Works

```
┌─────────────────────┐     ┌─────────────────────┐     ┌─────────────────────┐
│    TAINT SOURCE     │────▶│    PROPAGATION      │────▶│   DANGEROUS SINK    │
│                     │     │                     │     │                     │
│ • request.args      │     │ • Assignment        │     │ • cursor.execute()  │
│ • req.query.id      │     │ • Template literals │     │ • childProcess.exec │
│ • Request.Form[]    │     │ • String.Format()   │     │ • ProcessStartInfo  │
│ • Constructor args  │     │ • Field propagation │     │ • Destructors (~)   │
└─────────────────────┘     └─────────────────────┘     └─────────────────────┘
```

### Taint Sources by Framework

| Framework | Sources |
|-----------|---------|
| **Flask** | `request.args`, `request.form`, `request.json`, `request.data`, `request.cookies` |
| **Django** | `request.GET`, `request.POST`, `request.body`, `request.META`, `request.FILES` |
| **FastAPI** | `Query()`, `Body()`, `Form()`, `File()`, `Header()`, `Cookie()`, `Path()` |
| **Express.js** | `req.query.*`, `req.body.*`, `req.params.*`, `req.cookies`, `req.headers` |
| **ASP.NET** | `Request.QueryString`, `Request.Form`, `Request[]`, `HttpContext.Request` |
| **Spring** | `@RequestParam`, `@PathVariable`, `@RequestBody`, `HttpServletRequest` |
| **General** | `input()`, `sys.argv`, `os.environ`, `process.argv`, `Environment.GetCommandLineArgs()` |

---

## Vulnerability Categories

<table>
<tr>
<th>Category</th>
<th>Severity</th>
<th>Detection Techniques</th>
</tr>
<tr>
<td><strong>XSS (Cross-Site Scripting)</strong></td>
<td><code>CRITICAL</code></td>
<td>DOM-based (innerHTML, document.write), Reflected (res.send), jQuery, React, Angular, Vue</td>
</tr>
<tr>
<td><strong>SQL Injection</strong></td>
<td><code>CRITICAL</code></td>
<td>Taint tracking, String.Format patterns, StringBuilder analysis</td>
</tr>
<tr>
<td><strong>Command Injection</strong></td>
<td><code>CRITICAL</code></td>
<td>ProcessStartInfo blocks, shell=True, destructor patterns</td>
</tr>
<tr>
<td><strong>Code Injection</strong></td>
<td><code>CRITICAL</code></td>
<td>eval/exec taint, shadow eval, indirect invocation</td>
</tr>
<tr>
<td><strong>Deserialization</strong></td>
<td><code>CRITICAL</code></td>
<td>TypeNameHandling, pickle, ViewState MAC disabled</td>
</tr>
<tr>
<td><strong>XXE</strong></td>
<td><code>CRITICAL</code></td>
<td>XslCompiledTransform, XsltSettings.TrustedXslt, XmlResolver</td>
</tr>
<tr>
<td><strong>SSTI</strong></td>
<td><code>CRITICAL</code></td>
<td>RazorEngine.RunCompile, Jinja2, Velocity taint flow</td>
</tr>
<tr>
<td><strong>SSRF</strong></td>
<td><code>HIGH</code></td>
<td>HttpClient, WebRequest, RestSharp with user URLs</td>
</tr>
<tr>
<td><strong>XPath Injection</strong></td>
<td><code>HIGH</code></td>
<td>XPathNavigator.Select, XmlDocument.SelectNodes taint</td>
</tr>
<tr>
<td><strong>Path Traversal</strong></td>
<td><code>HIGH</code></td>
<td>File operations with user-controlled paths</td>
</tr>
<tr>
<td><strong>ViewState Attacks</strong></td>
<td><code>CRITICAL</code></td>
<td>EnableViewStateMac=false, MachineKey validation=None</td>
</tr>
<tr>
<td><strong>Session Fixation</strong></td>
<td><code>HIGH</code></td>
<td>Cookieless sessions, URL-embedded session IDs</td>
</tr>
<tr>
<td><strong>Info Disclosure</strong></td>
<td><code>MEDIUM</code></td>
<td>Debug mode, custom errors off, directory browsing</td>
</tr>
</table>

---

## Quick Start

### Basic Scanning

```bash
# AST-based scan with taint tracking (recommended for code review)
python3 ast-scanner.py /path/to/project

# Scan single file
python3 ast-scanner.py vulnerable_app.cs

# Scan ASP.NET configuration files
python3 ast-scanner.py web.config
```

### Filter by Category

```bash
# Focus on injection vulnerabilities
python3 ast-scanner.py project/ --category sql code command

# Check for deserialization issues (including ViewState)
python3 ast-scanner.py project/ --category deser

# SSRF and XXE only
python3 ast-scanner.py project/ --category ssrf xxe
```

### Filter by Confidence

```bash
# Only high-confidence findings (fewer false positives)
python3 ast-scanner.py project/ --min-confidence HIGH

# Include medium confidence
python3 ast-scanner.py project/ --min-confidence MEDIUM
```

### Output Formats

```bash
# JSON output for integration
python3 ast-scanner.py project/ --output json -o report.json

# Verbose mode for debugging
python3 ast-scanner.py project/ -v
```

---

## Language Support

<table>
<tr>
<th>Language</th>
<th>Extensions</th>
<th>Special Features</th>
</tr>
<tr>
<td><strong>Python</strong></td>
<td><code>.py</code></td>
<td>Full AST parsing, pickle/yaml/marshal detection, virtual sinks</td>
</tr>
<tr>
<td><strong>JavaScript/TypeScript</strong></td>
<td><code>.js</code>, <code>.ts</code>, <code>.jsx</code>, <code>.tsx</code></td>
<td>Shadow eval detection, Express.js taint propagation, template literals</td>
</tr>
<tr>
<td><strong>Java/Kotlin/Scala</strong></td>
<td><code>.java</code>, <code>.kt</code>, <code>.scala</code></td>
<td>JNI detection, Spring annotations, reflection-based evasion</td>
</tr>
<tr>
<td><strong>C#</strong></td>
<td><code>.cs</code></td>
<td>ProcessStartInfo blocks, destructors, ViewState, XSLT XXE, async methods</td>
</tr>
<tr>
<td><strong>ASP.NET Config</strong></td>
<td><code>.config</code></td>
<td>MachineKey, ViewState settings, authentication, session state</td>
</tr>
<tr>
<td><strong>PHP</strong></td>
<td><code>.php</code>, <code>.phtml</code></td>
<td>Variable tracking, include/require analysis</td>
</tr>
<tr>
<td><strong>Go</strong></td>
<td><code>.go</code></td>
<td>os/exec detection, template injection</td>
</tr>
<tr>
<td><strong>Ruby</strong></td>
<td><code>.rb</code>, <code>.erb</code></td>
<td>ERB injection, system/exec/backtick detection</td>
</tr>
</table>

---

## Advanced Detection Features

### Cross-Site Scripting (XSS) Detection

Comprehensive XSS detection for DOM-based, Reflected, and framework-specific patterns:

**DOM-Based XSS (JavaScript)**:
```javascript
// DETECTED: innerHTML with location.hash
document.getElementById('content').innerHTML = location.hash;

// DETECTED: document.write with referrer
document.write('<div>' + document.referrer + '</div>');

// DETECTED: jQuery .html() with user data
$('#output').html(userInput);
```

**Reflected XSS (Express.js)**:
```javascript
// DETECTED: Template literal in response
res.send(`<h1>Search: ${req.query.q}</h1>`);

// DETECTED: Concatenation in response
res.send('<h1>Hello, ' + req.query.name + '</h1>');
```

**Framework-Specific**:
```javascript
// DETECTED: React dangerouslySetInnerHTML
<div dangerouslySetInnerHTML={{ __html: userContent }} />

// DETECTED: Angular innerHTML binding
<div [innerHTML]="userContent"></div>

// DETECTED: Vue v-html directive
<div v-html="userContent"></div>
```

**PHP XSS**:
```php
// DETECTED: Direct superglobal output
echo $_GET['name'];

// DETECTED: Tainted variable output
$input = $_POST['data'];
echo $input;
```

### Evasive DOM-Based XSS Detection

Advanced detection for obfuscated XSS patterns that bypass simple AST analysis:

**Pattern 1: ASCII Array Encoding (String.fromCharCode)**
```javascript
// DETECTED: ASCII codes spelling "innerHTML" and "eval"
const _0x5f21 = [105, 110, 110, 101, 114, 72, 84, 77, 76]; // "innerHTML"
const _0x9922 = [101, 118, 97, 108];                      // "eval"

// DETECTED: Decoding via map/fromCharCode/join
const decode = (arr) => arr.map(c => String.fromCharCode(c)).join('');
```

**Pattern 2: Computed Property Access (String Fragments)**
```javascript
// DETECTED: Building sink name from fragments
const p1 = "inn";
const p2 = "erHT";
const p3 = "ML";
const sink = p1 + p2 + p3;  // Resolves to "innerHTML"

// DETECTED: Dynamic property assignment
element[sink] = userInput;
```

**Pattern 3: Prototype Descriptor Abuse**
```javascript
// DETECTED: Indirect innerHTML setter via prototype
Object.getOwnPropertyDescriptor(Element.prototype, sink).set.call(target, source);
```

**Pattern 4: Async Taint Flow (setTimeout/Promise/RAF)**
```javascript
// DETECTED: Taint source + sink in setTimeout callback
setTimeout(() => {
    document.body.innerHTML = sessionStorage.getItem('payload');
}, 0);

// DETECTED: Promise-based evasion
Promise.resolve(localStorage.getItem('data'))
    .then(data => elem.innerHTML = data);

// DETECTED: requestAnimationFrame evasion
requestAnimationFrame(() => {
    document.body.outerHTML = window.name;
});
```

**Pattern 5: Array-Based Taint Tunnel**
```javascript
// DETECTED: Taint hidden in array, sink built from indices
const fragments = [
    new URLSearchParams(location.search).get('xss'), // [0] Taint
    "inner",                                         // [1]
    "HTML"                                           // [2]
];
const sinkName = fragments[1] + fragments[2];
body[sinkName] = fragments[0];
```

**Pattern 6: eval/Function Aliasing**
```javascript
// DETECTED: Aliasing eval to innocent variable name
const run = window[decode(_0x9922)];  // run = eval

// DETECTED: Aliased eval invocation with template literal
run(`document.body.${sink} = "${data}"`);
```

### Sanitization Bypass Detection

Detects flawed sanitization that can be bypassed:

**First Occurrence Only (No Global Flag)**
```javascript
// DETECTED: .replace() only removes FIRST occurrence
let sanitized = input.replace("<script>", "");
// Input: "<script><script>alert(1)" → Output: "<script>alert(1)"
document.body.innerHTML = sanitized;
```

**Case-Sensitive Filters**
```javascript
// DETECTED: Missing 'i' flag - <SCRIPT> or <ScRiPt> bypasses
let clean = input.replace(/<script>/g, "");
```

**Blacklist-Based Sanitization**
```javascript
// DETECTED: Fundamentally flawed approach
if (input.includes("<script>") || input.includes("javascript:")) {
    return "blocked";
}
// Bypassed by: <img onerror=...>, <svg onload=...>, data: URLs
```

**Nested Payload Vulnerability**
```javascript
// DETECTED: Removing "javascript" creates new vector
let url = "javjavascriptascript:alert(1)";
let safe = url.replace("javascript", "");  // → "javascript:alert(1)"
```

**Non-Recursive Sanitization**
```javascript
// DETECTED: Single-pass sanitization
let clean = input.replace("<script>", "");
// Input: "<scr<script>ipt>" → Output: "<script>"
```

**Prototype Pollution to XSS**
```javascript
// DETECTED: __proto__ can override sanitization
Object.assign({}, userConfig);  // userConfig may contain __proto__
```

### C# Destructor/Finalizer Command Injection

Detects the "Bomb" pattern where command injection is hidden in destructors for delayed execution:

```csharp
// DETECTED: Taint flows from constructor to destructor via field
public class TimeDelayedPayload {
    private string _payload;

    public TimeDelayedPayload(string userInput) {
        _payload = userInput;  // Constructor taint source
    }

    ~TimeDelayedPayload() {
        // CRITICAL: Destructor command injection with field taint
        Process.Start("cmd.exe", "/c " + _payload);
    }
}
```

### XSLT XXE Detection

Detects XslCompiledTransform with dangerous settings:

```csharp
// DETECTED: XsltSettings enables scripts and document() function
var xslt = new XslCompiledTransform();
xslt.Load(xslPath, XsltSettings.TrustedXslt, new XmlUrlResolver());

// DETECTED: Explicit enable scripts
var settings = new XsltSettings(true, true);
xslt.Load(xslPath, settings, null);
```

### ASP.NET ViewState Vulnerability Detection

```csharp
// DETECTED in .aspx files
<%@ Page EnableViewStateMac="false" %>

// DETECTED in code-behind
ViewStateEncryptionMode = ViewStateEncryptionMode.Never;
EnableViewStateMac = false;
```

### Web.config Security Analysis

```xml
<!-- CRITICAL: ViewState MAC globally disabled -->
<pages enableViewStateMac="false" />

<!-- CRITICAL: MachineKey validation disabled -->
<machineKey validation="None" />

<!-- HIGH: Debug mode in production -->
<compilation debug="true" />

<!-- HIGH: Cookieless sessions enable fixation -->
<sessionState cookieless="true" />

<!-- HIGH: Custom errors exposes stack traces -->
<customErrors mode="Off" />
```

### JavaScript Shadow Eval Detection

Detects obfuscated code injection via string manipulation:

```javascript
// DETECTED: Reversed eval string
const lave = "lave";
const fn = global[lave.split('').reverse().join('')];
fn(userInput);

// DETECTED: Indirect eval via global object
const g = (function(){return this})();
g["ev" + "al"](code);

// DETECTED: Bracket notation with string building
const f = "ev";
window[f + "al"](payload);
```

### Express.js Command Injection with Taint Propagation

```javascript
// DETECTED: Taint flows through template literal to exec
const userInput = req.query.ip;           // Taint source
const cmd = `ping -c 1 ${userInput}`;     // Taint propagates via ${}
childProcess.exec(cmd, (err, stdout) => { // CRITICAL: Tainted var in exec
    res.send(stdout);
});
```

### Evasive C# Patterns

```csharp
// DETECTED: TypeNameHandling deserialization
JsonConvert.DeserializeObject(data, new JsonSerializerSettings {
    TypeNameHandling = TypeNameHandling.All  // RCE via gadget chains
});

// DETECTED: XPath Injection
var nodes = doc.SelectNodes("/users/user[@id='" + userId + "']");

// DETECTED: SSRF
var client = new HttpClient();
var response = await client.GetAsync(userProvidedUrl);

// DETECTED: SSTI via RazorEngine
Engine.Razor.RunCompile(userTemplate, "key", null, model);

// DETECTED: SQL Injection via String.Format
string query = String.Format("SELECT * FROM users WHERE id = {0}", userId);
```

### ProcessStartInfo Block Analysis

```csharp
// DETECTED: Object initializer block with shell command
ProcessStartInfo psi = new ProcessStartInfo {
    FileName = "cmd.exe",
    Arguments = "/c ping " + userInput,  // Tainted concatenation
    UseShellExecute = false
};
Process.Start(psi);

// DETECTED: 30+ system tools
// ping, ipconfig, nslookup, tracert, netstat, git, curl, wget,
// ssh, scp, nmap, sqlcmd, mysql, psql, docker, kubectl, etc.
```

---

## Sample Output

### AST Scanner (Taint Tracking)

```
================================================================================
AST-BASED VULNERABILITY SCAN REPORT
================================================================================
Scan Date: 2026-01-24 09:15:00
Files Scanned: 42
Parse Errors: 0
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
  -> ProcessStartInfo.Arguments built with tainted variable 'address' from Request.QueryString.

[CRITICAL] Destructor Command Injection - Process execution in finalizer (Confidence: HIGH)
  Line 67: Process.Start("cmd.exe", "/c " + _payload);
  -> Destructor executes shell command with tainted field '_payload'.

FILE: Services/XmlProcessor.cs
--------------------------------------------------------------------------------
[CRITICAL] XXE - XslCompiledTransform with XsltSettings.TrustedXslt (Confidence: HIGH)
  Line 23: xslt.Load(xslPath, XsltSettings.TrustedXslt, new XmlUrlResolver());
  -> XsltSettings.TrustedXslt enables scripts and document() - allows XXE/RCE.

FILE: web.config
--------------------------------------------------------------------------------
[CRITICAL] Insecure Deserialization - Global ViewState MAC Disabled (Confidence: HIGH)
  Line 12: <pages enableViewStateMac="false" />
  -> ViewState MAC disabled globally. Vulnerable to ysoserial.net gadgets.

[HIGH] Information Disclosure - Debug Mode Enabled (Confidence: HIGH)
  Line 18: <compilation debug="true" />
  -> Debug mode exposes stack traces and compilation info.

================================================================================
```

---

## CLI Reference

### AST Scanner

```
usage: ast-scanner.py [-h] [-v] [-c CATEGORY] [--output {text,json}]
                      [-o OUTPUT_FILE] [--min-confidence {HIGH,MEDIUM,LOW}]
                      target

Options:
  target                    File or directory to scan
  -v, --verbose             Enable detailed output
  -c, --category CATEGORY   Filter by category (sql, code, command, etc.)
  --output {text,json}      Output format
  -o, --output-file FILE    Save report to file
  --min-confidence LEVEL    Minimum confidence (HIGH, MEDIUM, LOW)
```

### Categories

| Flag | Description |
|------|-------------|
| `sql` | SQL Injection |
| `nosql` | NoSQL Injection |
| `code` | Code Injection (eval, exec) |
| `command` | Command Injection (system, subprocess, ProcessStartInfo) |
| `deser` | Insecure Deserialization (pickle, TypeNameHandling, ViewState) |
| `ssti` | Server-Side Template Injection |
| `ssrf` | Server-Side Request Forgery |
| `xxe` | XML External Entity (including XSLT) |
| `xpath` | XPath Injection |
| `path` | Path Traversal |
| `auth` | Authentication Bypass |
| `proto` | Prototype Pollution |
| `xss` | Cross-Site Scripting |
| `all` | All categories (default) |

---

## Integration Examples

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

      - name: Run AST Scanner
        run: |
          python3 ast-scanner.py . --min-confidence HIGH --output json -o results.json

      - name: Check for Critical Findings
        run: |
          if grep -q '"severity": "CRITICAL"' results.json; then
            echo "Critical vulnerabilities found!"
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

python3 ast-scanner.py . --min-confidence HIGH --category sql code command deser
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

## Project Structure

```
vuln-scanner/
├── ast-scanner.py      # AST-based scanner with taint tracking
├── vuln-scanner.py     # Regex-based pattern scanner
├── README.md           # Documentation
├── LICENSE             # MIT License
└── test-files/         # Sample vulnerable configurations for testing
    ├── sanitization-bypass.js        # JavaScript - Weak sanitization patterns
    ├── evasive-xss.js                # JavaScript - Advanced evasion patterns
    ├── xss-test.js                   # JavaScript - DOM-based & Reflected XSS
    ├── xss-test.php                  # PHP - Superglobal & tainted XSS
    ├── web.config                    # ASP.NET - ViewState, MachineKey
    ├── django-settings.py            # Django - DEBUG, SECRET_KEY, Pickle
    ├── flask-config.py               # Flask - Debug, hardcoded keys
    ├── express-config.js             # Express.js - Sessions, CORS, secrets
    ├── typescript-config.ts          # TypeScript - Injection patterns
    ├── rails-config.rb               # Ruby on Rails - Mass assignment, secrets
    ├── spring-application.properties # Spring Boot - Actuator, H2 console
    ├── php.ini                       # PHP - allow_url_include, display_errors
    └── nginx.conf                    # Nginx - Path traversal, SSRF proxy
```

### Test Files

The `test-files/` directory contains **intentionally vulnerable** configuration samples for testing the scanner. These demonstrate real-world security misconfigurations:

| File | Framework | Key Vulnerabilities |
|------|-----------|---------------------|
| `sanitization-bypass.js` | JavaScript | Weak replace(), blacklist filters, nested payloads |
| `evasive-xss.js` | JavaScript | ASCII encoding, prototype abuse, async taint, eval aliasing |
| `xss-test.js` | JavaScript | DOM-based XSS, Reflected XSS, jQuery, React, Angular, Vue |
| `xss-test.php` | PHP | Direct superglobal output, tainted variable XSS |
| `web.config` | ASP.NET | ViewState MAC disabled, MachineKey validation=None |
| `django-settings.py` | Django | DEBUG=True, PickleSerializer, hardcoded SECRET_KEY |
| `flask-config.py` | Flask | Debug mode, hardcoded credentials, insecure cookies |
| `express-config.js` | Express.js | Weak sessions, CORS *, exposed stack traces |
| `typescript-config.ts` | TypeScript | Command injection, SQLi, prototype pollution |
| `rails-config.rb` | Rails | Mass assignment, YAML.load, hardcoded secrets |
| `spring-application.properties` | Spring | Actuator exposed, H2 console, credentials |
| `php.ini` | PHP | allow_url_include, disabled functions, display_errors |
| `nginx.conf` | Nginx | Path traversal via alias, SSRF proxy_pass |

> **Note:** These files are for testing only. The scanner works on any real code you provide.

---

## Comparison: AST vs Regex Scanner

| Feature | AST Scanner | Regex Scanner |
|---------|:-----------:|:-------------:|
| **Speed** | Moderate | Fast |
| **Accuracy** | Higher | Lower |
| **Taint Tracking** | Yes | No |
| **Confidence Scores** | Yes | No |
| **Evasion Detection** | Yes | Limited |
| **Config Analysis** | Yes (web.config) | No |
| **Binary/DLL Analysis** | No | Yes |
| **.NET Decompile** | No | Yes |
| **Best For** | Security audits | CI/CD, quick scans |

**Recommendation:**
- Use `ast-scanner.py` for thorough security audits and code review
- Use `vuln-scanner.py` for quick scans, CI pipelines, and binary analysis

---

## Disclaimer

This tool is for **authorized security testing only**.

- Obtain proper authorization before scanning third-party code
- Verify findings manually - automated tools can produce false positives
- Use as part of a comprehensive security program, not as a sole measure
- The authors are not responsible for misuse of this tool

---

## License

MIT License - see [LICENSE](LICENSE) for details.

---

<p align="center">
  <strong>worldtreeboy</strong><br>
  <a href="https://github.com/worldtreeboy">github.com/worldtreeboy</a>
</p>

<p align="center">
  <sub>Built for security researchers, by security researchers.</sub>
</p>
