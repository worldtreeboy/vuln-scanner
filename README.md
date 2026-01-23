# 🛡️ WORLDTREEBOY Vulnerability Scanner

```
██╗    ██╗ ██████╗ ██████╗ ██╗     ██████╗ ████████╗██████╗ ███████╗███████╗██████╗  ██████╗ ██╗   ██╗
██║    ██║██╔═══██╗██╔══██╗██║     ██╔══██╗╚══██╔══╝██╔══██╗██╔════╝██╔════╝██╔══██╗██╔═══██╗╚██╗ ██╔╝
██║ █╗ ██║██║   ██║██████╔╝██║     ██║  ██║   ██║   ██████╔╝█████╗  █████╗  ██████╔╝██║   ██║ ╚████╔╝ 
██║███╗██║██║   ██║██╔══██╗██║     ██║  ██║   ██║   ██╔══██╗██╔══╝  ██╔══╝  ██╔══██╗██║   ██║  ╚██╔╝  
╚███╔███╔╝╚██████╔╝██║  ██║███████╗██████╔╝   ██║   ██║  ██║███████╗███████╗██████╔╝╚██████╔╝   ██║   
 ╚══╝╚══╝  ╚═════╝ ╚═╝  ╚═╝╚══════╝╚═════╝    ╚═╝   ╚═╝  ╚═╝╚══════╝╚══════╝╚═════╝  ╚═════╝    ╚═╝   
                              Source Code Security Scanner v3.1
```

[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)
[![Platform](https://img.shields.io/badge/platform-Windows%20%7C%20Linux%20%7C%20Kali-lightgrey.svg)]()
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)

A **cross-platform static code analysis tool** for detecting security vulnerabilities in source code. Supports multiple programming languages with .NET DLL decompilation and comprehensive vulnerability pattern detection.

**Now with dual scanning modes:**
- **Regex-based scanning** (`vuln-scanner.py`) - Fast, comprehensive pattern matching
- **AST-based scanning** (`ast-scanner.py`) - Deep code analysis with taint tracking for reduced false positives

---

## ✨ Features

### 🔍 Multi-Language Support
| Language | Extensions |
|----------|------------|
| **JavaScript/TypeScript** | `.js`, `.ts`, `.jsx`, `.tsx`, `.mjs` |
| **Python** | `.py` |
| **PHP** | `.php`, `.phtml` |
| **Java** | `.java`, `.scala` |
| **C#/.NET** | `.cs`, `.vb` |
| **Ruby** | `.rb`, `.erb` |

### 🎯 Vulnerability Categories

| Category | Severity | Description |
|----------|----------|-------------|
| **SQL Injection** | 🔴 CRITICAL | String concatenation, template literals, raw queries |
| **NoSQL Injection** | 🔴 CRITICAL | MongoDB, Redis, CouchDB injection patterns |
| **Code Injection** | 🔴 CRITICAL | `eval()`, `exec()`, command injection, RCE |
| **Insecure Deserialization** | 🔴 CRITICAL | pickle, yaml.load, ObjectInputStream, BinaryFormatter |
| **SSTI** | 🔴 CRITICAL | Jinja2, Twig, Freemarker, Thymeleaf, ERB |
| **XXE** | 🔴 CRITICAL | XML External Entity injection |
| **SSRF** | 🟠 HIGH | Server-side request forgery patterns |
| **Path Traversal** | 🟠 HIGH | File operations with user-controlled paths |
| **XPath Injection** | 🟠 HIGH | Dynamic XPath query construction |
| **Authentication Bypass** | 🟠 HIGH | Hardcoded credentials, weak JWT, insecure comparison |
| **Prototype Pollution** | 🟠 HIGH | `__proto__`, constructor.prototype, unsafe merge functions |

### 🔬 Binary Analysis (Optional)
- **.NET DLL Decompilation** via ILSpy (Linux) or dnSpy (Windows)
- **String extraction** from compiled binaries
- **Credential detection** in binaries (AWS keys, API tokens, connection strings)

### 🧠 AST-Based Scanner v2.2 (ast-scanner.py)
A multi-language scanner providing deeper code analysis through:
- **Taint Tracking** - Traces user input through variable assignments and function calls
- **Data Flow Analysis** - Follows data from sources (request params, user input) to dangerous sinks
- **Lambda/Closure Tracking** - Tracks taint flow through lambdas and functional interfaces (Java)
- **Callback Sink Detection** - Identifies vulnerabilities in arrow functions and callbacks (JS)
- **Evasion Detection** - Detects obfuscation and anti-pattern techniques (26+ JS, 18+ Python patterns)
- **Context-Aware Detection** - Understands function calls, imports, and code structure
- **Confidence Scoring** - HIGH/MEDIUM/LOW confidence ratings for each finding
- **Reduced False Positives** - Semantic analysis filters out safe patterns

#### Supported Languages (AST Scanner)
| Language | Extensions | Taint Sources |
|----------|------------|---------------|
| **Python** | `.py` | request.args/form, input(), sys.argv, os.environ |
| **JavaScript/TypeScript** | `.js`, `.ts`, `.jsx`, `.tsx` | req.body/query/params, process.argv |
| **Java** | `.java` | Method parameters, HttpServletRequest |
| **PHP** | `.php`, `.phtml` | $_GET, $_POST, $_REQUEST, $_COOKIE, $_SERVER |

#### Scanner Comparison
| Feature | vuln-scanner.py | ast-scanner.py |
|---------|-----------------|----------------|
| Speed | Fast | Moderate |
| Languages | 15+ | 4 (with taint tracking) |
| Analysis Depth | Pattern matching | Taint tracking + Data flow |
| False Positive Rate | Higher | Lower |
| Taint Chain Visibility | No | Yes |
| Lambda/Callback Tracking | No | Yes (Java, JS) |
| Prototype Pollution | Basic | Comprehensive (merge functions, calls) |
| Evasion Detection | Basic | Advanced (44+ patterns) |
| Use Case | Broad scanning, CI/CD | Deep analysis, verification |

---

## 🚀 Quick Start

### Installation

```bash
# Clone the repository
git clone https://github.com/worldtreeboy/vuln-scanner.git
cd vuln-scanner

# No dependencies required for basic usage!
# Python 3.8+ is all you need
```

### Basic Usage

```bash
# Scan a single file
python3 vuln-scanner.py target.py

# Scan a directory
python3 vuln-scanner.py /path/to/project

# Scan with verbose output
python3 vuln-scanner.py /path/to/project -v

# Output as JSON
python3 vuln-scanner.py /path/to/project --output json -o report.json
```

### Category-Specific Scans

```bash
# Scan only for SQL injection
python3 vuln-scanner.py /path/to/project --category sql

# Scan for multiple categories
python3 vuln-scanner.py /path/to/project --category sql code auth ssrf

# Scan all categories (default)
python3 vuln-scanner.py /path/to/project --category all
```

### AST-Based Scanner Usage

```bash
# Basic scan with AST analysis
python3 ast-scanner.py /path/to/project

# Verbose output showing taint tracking
python3 ast-scanner.py /path/to/project -v

# Scan specific categories with confidence filtering
python3 ast-scanner.py /path/to/project --category sql code ssrf --min-confidence HIGH

# Output as JSON
python3 ast-scanner.py /path/to/project --output json -o ast-report.json

# Combined workflow: Use both scanners
python3 vuln-scanner.py /path/to/project -o regex-report.json --output json
python3 ast-scanner.py /path/to/project -o ast-report.json --output json
```

### Binary Analysis

```bash
# Enable binary scanning (DLL, EXE)
python3 vuln-scanner.py /path/to/project --scan-binaries

# Enable .NET decompilation (requires ilspycmd)
python3 vuln-scanner.py /path/to/app.dll --scan-binaries --decompile
```

---

## 📋 Command Line Options

### vuln-scanner.py (Regex-based)

| Option | Short | Description |
|--------|-------|-------------|
| `--output` | | Output format: `text` (default) or `json` |
| `--output-file` | `-o` | Save report to file |
| `--verbose` | `-v` | Show detailed scanning progress |
| `--category` | `-c` | Categories to scan (sql, nosql, code, auth, ssti, ssrf, etc.) |
| `--scan-binaries` | `-b` | Enable DLL/EXE binary analysis |
| `--decompile` | `-d` | Decompile .NET binaries using ILSpy |
| `--exclude-dir` | | Additional directories to exclude |
| `--exclude-file` | | Additional files to exclude |
| `--exclude-ext` | | File extensions to exclude |
| `--include-ext` | | Only scan these extensions |
| `--no-default-excludes` | | Don't use default exclusion lists |

### ast-scanner.py (AST-based v2.2)

| Option | Short | Description |
|--------|-------|-------------|
| `--output` | | Output format: `text` (default) or `json` |
| `--output-file` | `-o` | Save report to file |
| `--verbose` | `-v` | Show detailed scanning progress with taint tracking |
| `--category` | `-c` | Categories: sql, nosql, code, command, deser, ssti, ssrf, auth, proto, xpath, xxe, path, xss, lfi, ldap |
| `--min-confidence` | | Minimum confidence level: HIGH, MEDIUM, LOW (default) |

#### Vulnerability Categories (AST Scanner)
| Category | Flag | Languages | Description |
|----------|------|-----------|-------------|
| SQL Injection | `sql` | All | String concatenation, dynamic queries |
| Command Injection | `command` | All | system(), exec(), Runtime.exec() |
| Code Injection | `code` | All | eval(), reflection, vm module, dynamic execution |
| Deserialization | `deser` | All | pickle, unserialize(), Marshal, node-serialize |
| SSTI | `ssti` | All | Template injection (EJS, Pug, Jinja2, etc.) |
| SSRF | `ssrf` | All | Server-side request forgery |
| Path Traversal | `path` | All | File operations with user paths |
| Prototype Pollution | `proto` | JavaScript | `__proto__`, unsafe merge, Object.assign |
| XSS | `xss` | PHP, C# | Cross-site scripting |
| LFI/RFI | `lfi` | PHP | Local/Remote file inclusion |
| XXE | `xxe` | Java, C#, JS | XML External Entity |
| XPath Injection | `xpath` | All | Dynamic XPath query construction |
| Auth Bypass | `auth` | All | JWT vulnerabilities, hardcoded creds |
| LDAP Injection | `ldap` | C# | LDAP filter injection |

---

## 📊 Sample Output

```
================================================================================
VULNERABILITY SCAN REPORT
================================================================================
Platform: LINUX
Files scanned: 142 | Binaries: 3
Total findings: 28

  CRITICAL  : 8
  HIGH      : 12
  MEDIUM    : 6
  LOW       : 2

================================================================================

FILE: app/controllers/user_controller.py
--------------------------------------------------------------------------------
[CRITICAL] SQL Injection - String Concatenation
  Line 45: query = "SELECT * FROM users WHERE id = " + user_id

[CRITICAL] Code Injection - Python eval
  Line 89: result = eval(user_input)

FILE: api/handlers/auth.js
--------------------------------------------------------------------------------
[HIGH] Auth Bypass - Hardcoded Credentials
  Line 12: const API_KEY = "sk_live_abc123xyz789"
```

### AST Scanner Sample Output (v2.2)

```
    ╔═══════════════════════════════════════════════════════════════╗
    ║            AST-Based Vulnerability Scanner v2.0               ║
    ║         Deeper code analysis, fewer false positives           ║
    ╚═══════════════════════════════════════════════════════════════╝

================================================================================
AST-BASED VULNERABILITY SCAN REPORT
================================================================================
Scan Date: 2026-01-23 14:30:00
Files Scanned: 45
Parse Errors: 0
Total Findings: 18

Summary by Severity:
  CRITICAL  : 8
  HIGH      : 7
  MEDIUM    : 3

Summary by Confidence:
  HIGH      : 15
  MEDIUM    : 3

================================================================================

FILE: app/controllers/UserController.java
--------------------------------------------------------------------------------
[CRITICAL] SQL Injection - executeQuery with tainted input (Confidence: HIGH)
  Line 45: conn.createStatement().executeQuery(query);
  -> User-controlled data in SQL query execution.
  Taint: tainted: query (line 44)

[CRITICAL] Command Injection - Runtime.exec with tainted input (Confidence: HIGH)
  Line 78: Runtime.getRuntime().exec(cmd);
  -> User-controlled data passed to Runtime.exec().
  Taint: tainted: cmd (line 76)

FILE: api/handlers/upload.php
--------------------------------------------------------------------------------
[CRITICAL] File Inclusion - LFI/RFI with tainted data (Confidence: HIGH)
  Line 12: include($page);
  -> User input in file inclusion allows LFI/RFI.
  Taint: tainted: $page (line 10)

[CRITICAL] Command Injection - Shell function with tainted data (Confidence: HIGH)
  Line 25: system($cmd);
  -> User input passed to shell execution function.
  Taint: tainted: $cmd (line 23)

FILE: services/database.py
--------------------------------------------------------------------------------
[CRITICAL] SQL Injection - execute() with tainted query (Confidence: HIGH)
  Line 23: cursor.execute(query)
  -> User-controlled data in SQL query.
  Taint: request: request.args.get('id') (line 21)
```

---

## 🔧 .NET Decompilation Setup

### Linux/Kali

```bash
# Install .NET SDK
wget https://dot.net/v1/dotnet-install.sh
chmod +x dotnet-install.sh
./dotnet-install.sh --channel 8.0

# Install ILSpy CLI
dotnet tool install -g ilspycmd

# Add to PATH
export PATH="$PATH:$HOME/.dotnet/tools"
```

### Windows

1. Download [dnSpy](https://github.com/dnSpy/dnSpy/releases) or install ilspycmd
2. Add to system PATH
3. Run scanner with `--decompile` flag

---

## 🛠️ Default Exclusions

The scanner automatically excludes common non-source directories and files to reduce noise:

**Directories:** `node_modules`, `.git`, `__pycache__`, `venv`, `vendor`, `dist`, `build`, `test`, `tests`, `docs`

**Files:** `package-lock.json`, `yarn.lock`, `*.min.js`, `jquery*.js`, `bootstrap*.js`, `react*.js`

Use `--no-default-excludes` to scan everything.

---

## 🎯 Detection Examples

### SQL Injection

```python
# String concatenation
query = "SELECT * FROM users WHERE id = " + user_id  # ✅ Detected

# F-strings
cursor.execute(f"SELECT * FROM users WHERE name = '{name}'")  # ✅ Detected

# Format strings  
query = "SELECT * FROM users WHERE id = %s" % user_id  # ✅ Detected
```

### Code Injection

```python
# Direct eval
eval(user_input)  # ✅ Detected

# Command injection
os.system("ping " + host)  # ✅ Detected
subprocess.call(cmd, shell=True)  # ✅ Detected
```

### Deserialization

```python
# Python pickle
pickle.loads(user_data)  # ✅ Detected

# YAML unsafe load
yaml.load(data)  # ✅ Detected (missing SafeLoader)

# PHP unserialize
unserialize($_GET['data'])  # ✅ Detected
```

### JavaScript/TypeScript Detection (AST Scanner)

```javascript
// Prototype Pollution - Unsafe merge function
function deepMerge(target, source) {
    for (let key in source) {  // ✅ Detected: Unsafe Object Manipulation
        target[key] = source[key];
    }
}  // ✅ Detected: Unsafe deepMerge function

// Prototype Pollution - __proto__ in JSON
const input = JSON.parse('{"__proto__": {"admin": true}}');  // ✅ Detected
deepMerge(config, input);  // ✅ Detected: deepMerge with untrusted input

// Prototype Pollution - Lodash vulnerable functions
_.merge(target, req.body);  // ✅ Detected
_.defaultsDeep(config, userInput);  // ✅ Detected

// Path Traversal
fs.readFile(req.query.file);  // ✅ Detected
path.join(basePath, userInput);  // ✅ Detected

// RCE via vm module
vm.runInNewContext(userCode);  // ✅ Detected
new Function(userInput)();  // ✅ Detected

// XXE
xml2js.parseString(req.body.xml);  // ✅ Detected

// Auth Bypass
jwt.decode(token);  // ✅ Detected (should use verify)
if (password === 'admin123') { }  // ✅ Detected: Hardcoded password
```

### Java Detection (AST Scanner)

```java
// SQL Injection with taint tracking
String id = request.getParameter("id");
String query = "SELECT * FROM users WHERE id = " + id;  // ✅ Detected
stmt.executeQuery(query);  // ✅ Detected with taint chain

// Command Injection
String cmd = request.getParameter("cmd");
Runtime.getRuntime().exec(cmd);  // ✅ Detected

// Deserialization
ObjectInputStream ois = new ObjectInputStream(userInput);
ois.readObject();  // ✅ Detected

// Lambda taint tracking (NEW)
Consumer<String> action = (path) -> {
    new File("/app/" + path).delete();  // ✅ Detected via lambda taint flow
};
executeAction(userInput, action);  // Taint flows through lambda
```

### PHP Detection (AST Scanner)

```php
// SQL Injection with superglobal tracking
$id = $_GET['id'];
mysql_query("SELECT * FROM users WHERE id = " . $id);  // ✅ Detected

// Command Injection
$cmd = $_POST['cmd'];
system($cmd);  // ✅ Detected

// LFI/RFI
$page = $_REQUEST['page'];
include($page);  // ✅ Detected
```

### C# Detection

```csharp
// SQL Injection
string id = Request.QueryString["id"];
SqlCommand cmd = new SqlCommand("SELECT * FROM users WHERE id = " + id);  // ✅ Detected

// Command Injection
string command = Request.Form["cmd"];
Process.Start(command);  // ✅ Detected

// Insecure Deserialization
BinaryFormatter bf = new BinaryFormatter();
bf.Deserialize(stream);  // ✅ Detected (always dangerous)
```

### Ruby Detection

```ruby
# SQL Injection
id = params[:id]
User.where("id = #{id}")  # ✅ Detected

# Command Injection
cmd = params[:cmd]
system(cmd)  # ✅ Detected

# Deserialization
data = params[:data]
Marshal.load(data)  # ✅ Detected
```

### 🕵️ Evasion Technique Detection (AST Scanner v2.2)

The AST scanner detects 44+ evasion techniques designed to bypass traditional regex-based scanners:

#### JavaScript Evasion Patterns

```javascript
// Function constructor evasion
const builder = [].constructor.constructor;  // ✅ Detected
const fn = builder('return ' + expr);  // ✅ Detected

// Function.prototype.constructor.bind
const indirect = Function.prototype.constructor.bind(null, code);  // ✅ Detected

// setTimeout with string argument (code execution)
setTimeout(codeString, 1000);  // ✅ Detected

// SQL via Array.join()
const parts = ['SELECT * FROM', table, 'WHERE 1=1'];
parts.push('AND', col, '=', value);
return parts.join(' ');  // ✅ Detected

// SQL via tagged template literals
return sql`SELECT * FROM users WHERE email = '${email}'`;  // ✅ Detected

// Dynamic require obfuscation
const mod = require('child_' + 'process');  // ✅ Detected
const method = 'exec' + 'Sync';
mod[method](cmd);  // ✅ Detected

// spawn with shell:true
spawn(command, params, { shell: true });  // ✅ Detected

// Prototype pollution via Reflect.ownKeys
for (const key of Reflect.ownKeys(source)) {  // ✅ Detected
    target[key] = source[key];
}

// Loose comparison auth bypass
return provided == expected;  // ✅ Detected (should use ===)

// Manual JWT extraction without verify
const segments = token.split('.');
return JSON.parse(Buffer.from(segments[1], 'base64'));  // ✅ Detected
```

#### Python Evasion Patterns

```python
# ROT13/Base64/Hex string obfuscation
codecs.decode(s, 'rot_13')  # ✅ Detected
base64.b64decode(encoded)  # ✅ Detected
bytes.fromhex(hex_str)  # ✅ Detected

# Dynamic __import__ evasion
obj = __import__(parts[0])  # ✅ Detected

# getattr with obfuscated attribute names
fn = getattr(mod, E.r13('Pbcra'))  # ✅ Detected

# Metaclass __call__ code execution
class ExecutorMeta(type):
    def __call__(cls, code):
        return eval(code)  # ✅ Detected

# Descriptor __get__ code execution
class CodeDescriptor:
    def __get__(self, obj, objtype):
        return lambda code: exec(compile(code))  # ✅ Detected

# functools.reduce SQL building
return functools.reduce(fmt, conditions.items(), base)  # ✅ Detected (with SQL context)

# Generator-based SQL building
query = base
while True:
    col, val = yield query  # ✅ Detected

# Context manager hiding subprocess
@contextmanager
def shell_context(cmd):
    proc = subprocess.Popen(cmd, shell=True)  # ✅ Detected
    yield proc

# __getattr__ shell proxy
class ShellProxy:
    def __getattr__(self, cmd):  # ✅ Detected
        return ShellProxy(f"{self._base} {cmd}")

# lxml XMLParser with dangerous options
parser = etree.XMLParser(resolve_entities=True, load_dtd=True)  # ✅ Detected

# format_map SSTI
template.format_map(user_dict)  # ✅ Detected

# LDAP injection via f-string
filter = f"(&(uid={uid})(objectClass=person))"  # ✅ Detected

# Obfuscated pickle reference
_resolve(E.hex('7069636b6c65')).loads(data)  # ✅ Detected (hex = 'pickle')
```

---

## 📁 Project Structure

```
vuln-scanner/
├── vuln-scanner.py      # Regex-based scanner (fast, comprehensive)
├── ast-scanner.py       # AST-based scanner (deep analysis, lower FP)
├── README.md
└── LICENSE
```

### When to Use Each Scanner

| Scenario | Recommended Scanner |
|----------|---------------------|
| Initial broad scan of large codebase | vuln-scanner.py |
| Deep analysis with taint tracking | ast-scanner.py |
| CI/CD pipeline quick check | vuln-scanner.py |
| Reviewing specific vulnerability reports | ast-scanner.py (with --min-confidence HIGH) |
| Need to see data flow / taint chain | ast-scanner.py |
| Binary analysis (DLL, EXE) | vuln-scanner.py |
| Python/JS/Java/PHP projects | ast-scanner.py (better accuracy) |
| C/C++, other languages | vuln-scanner.py |

---

## 🤝 Contributing

Contributions are welcome! Here's how you can help:

1. **Add new vulnerability patterns** - Submit PRs with new regex patterns
2. **Improve false positive handling** - Help reduce noise
3. **Add language support** - Extend to new languages
4. **Report bugs** - Open issues for any problems found

---

## ⚠️ Disclaimer

This tool is for **authorized security testing only**. 

- Always obtain proper authorization before scanning code
- False positives are possible - verify findings manually
- This is a static analysis tool - it cannot detect all vulnerabilities
- Use as part of a comprehensive security program, not as the only measure

---

## 📜 License

MIT License - see [LICENSE](LICENSE) for details.

---

## 👤 Author

**worldtreeboy**

- GitHub: [@worldtreeboy](https://github.com/worldtreeboy)

---

## 🌟 Star History

If this tool helps you, please consider giving it a ⭐!

---

<p align="center">
  <b>Happy Hunting! 🎯</b>
</p>
