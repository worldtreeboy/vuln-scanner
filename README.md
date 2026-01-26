<h1 align="center">
  <br>
  <pre>
 █████╗ ███████╗████████╗    ███████╗ ██████╗ █████╗ ███╗   ██╗███╗   ██╗███████╗██████╗
██╔══██╗██╔════╝╚══██╔══╝    ██╔════╝██╔════╝██╔══██╗████╗  ██║████╗  ██║██╔════╝██╔══██╗
███████║███████╗   ██║       ███████╗██║     ███████║██╔██╗ ██║██╔██╗ ██║█████╗  ██████╔╝
██╔══██║╚════██║   ██║       ╚════██║██║     ██╔══██║██║╚██╗██║██║╚██╗██║██╔══╝  ██╔══██╗
██║  ██║███████║   ██║       ███████║╚██████╗██║  ██║██║ ╚████║██║ ╚████║███████╗██║  ██║
╚═╝  ╚═╝╚══════╝   ╚═╝       ╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝╚═╝  ╚═══╝╚══════╝╚═╝  ╚═╝
  </pre>
</h1>

<h3 align="center">Advanced Multi-Language SAST with 2nd-Order Injection Detection</h3>

<p align="center">
  <a href="#proven-results">Proven Results</a> •
  <a href="#2nd-order-detection">2nd-Order Detection</a> •
  <a href="#features">Features</a> •
  <a href="#quick-start">Quick Start</a> •
  <a href="#detection-patterns">Detection Patterns</a> •
  <a href="#language-support">Languages</a>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/python-3.8+-3776ab?style=for-the-badge&logo=python&logoColor=white" alt="Python 3.8+">
  <img src="https://img.shields.io/badge/languages-8+-22c55e?style=for-the-badge" alt="8+ Languages">
  <img src="https://img.shields.io/badge/2nd--Order-Detection-ff6b6b?style=for-the-badge" alt="2nd-Order">
  <img src="https://img.shields.io/badge/version-3.0-blueviolet?style=for-the-badge" alt="Version">
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

## Proven Results

<p align="center">
  <b>Tested against industry-standard vulnerable applications</b>
</p>

<table align="center">
<tr>
<th align="center">Application</th>
<th align="center">Files</th>
<th align="center">Critical</th>
<th align="center">High</th>
<th align="center">Medium</th>
<th align="center">Total</th>
</tr>
<tr>
<td><b>WebGoat (OWASP)</b></td>
<td align="center">469</td>
<td align="center"><code>32</code></td>
<td align="center"><code>86</code></td>
<td align="center"><code>4</code></td>
<td align="center"><b>122</b></td>
</tr>
<tr>
<td><b>Damn Vulnerable RESTaurant API</b></td>
<td align="center">74</td>
<td align="center"><code>21</code></td>
<td align="center"><code>1</code></td>
<td align="center"><code>0</code></td>
<td align="center"><b>22</b></td>
</tr>
<tr>
<td><b>Vulnerable-Flask-App</b></td>
<td align="center">2</td>
<td align="center"><code>10</code></td>
<td align="center"><code>8</code></td>
<td align="center"><code>0</code></td>
<td align="center"><b>18</b></td>
</tr>
<tr>
<td><b>NodeGoat (OWASP)</b></td>
<td align="center">39</td>
<td align="center"><code>3</code></td>
<td align="center"><code>5</code></td>
<td align="center"><code>4</code></td>
<td align="center"><b>12</b></td>
</tr>
<tr>
<td colspan="2" align="right"><b>TOTAL</b></td>
<td align="center"><b><code>66</code></b></td>
<td align="center"><b><code>100</code></b></td>
<td align="center"><b><code>8</code></b></td>
<td align="center"><b>174</b></td>
</tr>
</table>

<p align="center">
  <sub>584 files scanned across Python, Java, JavaScript, and TypeScript codebases</sub>
</p>

### Vulnerabilities Detected

<table>
<tr>
<td width="50%" valign="top">

**WebGoat (Java)**
- SQL Injection via string concatenation
- SSRF in URL construction
- XStream deserialization vulnerabilities
- Prototype pollution patterns

</td>
<td width="50%" valign="top">

**Damn Vulnerable RESTaurant API (Python)**
- Command Injection with `shell=True`
- 2nd-Order Code Injection via `db.query()`
- SSRF in requests with variable URLs
- SQLAlchemy taint propagation

</td>
</tr>
<tr>
<td width="50%" valign="top">

**Vulnerable-Flask-App (Python)**
- SSTI via `render_template_string()`
- Command Injection in subprocess calls
- Insecure Pickle deserialization
- SQL Injection via string formatting

</td>
<td width="50%" valign="top">

**NodeGoat (JavaScript)**
- `eval()` with user input (RCE)
- NoSQL Injection with `$ne` operator
- Dynamic `require()` for RCE

</td>
</tr>
</table>

---

## What Makes AST-Scanner Different?

Most SAST tools detect **1st-order injection** - where user input flows directly to a sink. **AST-Scanner** goes deeper, detecting **2nd-order injection** where payloads are:

```
┌─────────────────┐     ┌─────────────────┐     ┌─────────────────┐     ┌─────────────────┐
│  PHASE 1: STORE │     │  PHASE 2: FETCH │     │  PHASE 3: USE   │     │  PHASE 4: BOOM  │
│                 │     │                 │     │                 │     │                 │
│ Attacker stores │────▶│ App loads data  │────▶│ Data used in    │────▶│ Payload         │
│ payload in DB   │     │ from database   │     │ query/command   │     │ executes        │
└─────────────────┘     └─────────────────┘     └─────────────────┘     └─────────────────┘
```

**The payload sleeps in the database, waiting to strike.**

---

## 2nd-Order Detection

### The "FINAL BOSS" Patterns Other Scanners Miss

<table>
<tr>
<td width="50%">

#### SQL/HQL Injection
```java
// Entity value → HQL query
User user = repo.findById(id).get();
String filter = user.getSavedFilter();

// DETECTED: 2nd-Order HQL Injection
String hql = "FROM Product WHERE " + filter;
em.createQuery(hql).getResultList();
```

</td>
<td width="50%">

#### XPath Injection
```java
// Entity value → XPath query
User user = repo.findById(id).get();
String dept = user.getDepartment();

// DETECTED: 2nd-Order XPath Injection
String expr = "//dept[@name='" + dept + "']";
xpath.evaluate(expr, doc);
```

</td>
</tr>
<tr>
<td width="50%">

#### MongoDB NoSQL Injection
```javascript
// DB value → $where operator
const user = await User.findById(id);
const filter = user.savedFilter;

// DETECTED: 2nd-Order NoSQL Injection
Items.find({ $where: filter });
```

</td>
<td width="50%">

#### Pandas Code Injection
```python
# DB value → df.query() (executes code!)
row = cursor.fetchone()
expr = row['filter_expression']

// DETECTED: 2nd-Order Code Injection
df.query(expr)  # Pandas evaluates as code
```

</td>
</tr>
<tr>
<td width="50%">

#### PHP Double-Unserialize
```php
// Serialized payload → unserialize → SQL
$row = $pdo->fetch();
$prefs = unserialize($row['prefs']);

// DETECTED: Double-Unserialize SQLi
$sql = "SELECT * FROM t WHERE id=" . $prefs->id;
```

</td>
<td width="50%">

#### C# Entity Framework
```csharp
// Entity value → FromSqlRaw
var user = db.Users.Find(id);
var filter = user.CustomFilter;

// DETECTED: 2nd-Order SQLi
db.Products.FromSqlRaw(
    $"SELECT * FROM Products WHERE {filter}");
```

</td>
</tr>
</table>

---

## Features

<table>
<tr>
<td width="50%">

### Core Engine
- **Taint Tracking** - Traces data flow source → sink
- **Entity-Source Detection** - Tracks ORM/Repository patterns
- **Cross-Function Analysis** - Follows data through methods
- **Evasion Detection** - Catches obfuscation tricks
- **Confidence Scoring** - HIGH/MEDIUM/LOW ratings
- **Minified File Detection** - Warns about potential false positives

</td>
<td width="50%">

### Detection Categories
- SQL/NoSQL/HQL Injection
- Command Injection
- Code Injection (eval/exec)
- XPath/XQuery Injection
- XXE & XSLT Attacks
- SSRF & SSTI
- Insecure Deserialization
- Prototype Pollution RCE

### Not Detected
The following vulnerability types are **not** scanned:
- Cross-Site Scripting (XSS)
- Path Traversal
- Weak Cryptography
- Session Fixation

</td>
</tr>
</table>

### Detection Quality Matrix

| Category | 1st-Order | 2nd-Order | Evasion Detection |
|----------|:---------:|:---------:|:-----------------:|
| SQL Injection | Excellent | Excellent | strrev, base64 |
| NoSQL Injection | Excellent | $where, $function | JSON poisoning |
| Command Injection | Excellent | DB-sourced | getattr, LINQ, Ghost Sink |
| Code Injection | Excellent | pandas, ScriptEngine | Proxy traps, toString hijack |
| XPath Injection | Excellent | Entity-sourced | StringBuilder |
| Deserialization | Excellent | Double-unserialize | ViewState, SnakeYAML |
| XXE/XSLT | Excellent | - | XmlResolver |
| Expression Language | Excellent | - | SpEL, OGNL, MVEL, EL |
| Prototype Pollution | Excellent | Ghost Sink RCE | __proto__, Object.assign |

---

## Quick Start

```bash
# Clone (rename repo on GitHub: Settings → Repository name)
git clone https://github.com/worldtreeboy/ast-scanner.git
cd ast-scanner

# Scan a project (no dependencies required!)
python3 ast-scanner.py /path/to/project

# Scan single file
python3 ast-scanner.py vulnerable_app.java

# JSON output for CI/CD
python3 ast-scanner.py project/ --output json -o report.json

# High-confidence only
python3 ast-scanner.py project/ --min-confidence HIGH
```

---

## Detection Patterns

### 2nd-Order Source Tracking

The scanner tracks data from these **entity sources**:

| Language | Tracked Patterns |
|----------|-----------------|
| **Java** | `repo.findById()`, `em.find()`, `entityManager.createQuery().getSingleResult()`, getter chains |
| **C#** | `db.Users.Find()`, `context.Set<T>().FirstOrDefault()`, EF Core navigation properties |
| **JavaScript** | `Model.findOne()`, `Model.findById()`, Mongoose/Sequelize results |
| **Python** | `session.query().first()`, `cursor.fetchone()`, `pd.read_sql()` |
| **PHP** | `fetch_assoc()`, `fetch_object()`, `PDO::fetch()`, `json_decode()`, `unserialize()` |
| **Ruby** | `Model.find()`, `Model.find_by()`, ActiveRecord results |

### Dangerous Sinks Detected

| Sink Type | Examples |
|-----------|----------|
| **SQL** | `executeQuery()`, `createNativeQuery()`, `FromSqlRaw()`, `cursor.execute()` |
| **HQL/JPQL** | `createQuery()`, Criteria API `root.get()`, `cb.asc()`/`cb.desc()` |
| **NoSQL** | `$where`, `$accumulator`, `$function`, `mapReduce` |
| **XPath** | `xpath.evaluate()`, `SelectNodes()`, `DOMXPath->query()` |
| **Command** | `Process.Start()`, `Runtime.exec()`, `os.system()`, `exec()` |
| **Code** | `eval()`, `ScriptEngine.eval()`, `df.query()`, `df.eval()` |

---

## Evasion Detection

AST-Scanner catches sophisticated evasion techniques:

<details>
<summary><b>Python: getattr Shadow Attack</b></summary>

```python
# DETECTED: Dynamic attribute access on dangerous module
func_name = user_data.get("action")  # "system"
method = getattr(os, func_name)       # os.system
method(user_data.get("arg"))          # RCE!
```
</details>

<details>
<summary><b>PHP: strrev() Evasion</b></summary>

```php
// DETECTED: strrev hides "system"
$func = strrev("metsys");  // "system"
$func($_GET['cmd']);       // Command injection
```
</details>

<details>
<summary><b>C#: LINQ Taint Tunnel</b></summary>

```csharp
// DETECTED: LINQ transforms taint to shell
var cmds = inputs.Select(x => $"/c {x}").ToList();
Process.Start("cmd.exe", cmds.First());
```
</details>

<details>
<summary><b>JavaScript: Proxy Trap</b></summary>

```javascript
// DETECTED: Proxy get trap with eval
const proxy = new Proxy({}, {
    get: (t, p) => eval(sessionStorage.getItem(p))
});
proxy.payload;  // Any property triggers eval
```
</details>

<details>
<summary><b>Java: SnakeYAML Deserialization</b></summary>

```java
// DETECTED: SnakeYAML unsafe deserialization
String yamlConfig = request.getParameter("config");
Yaml yaml = new Yaml();  // No SafeConstructor!
Object obj = yaml.load(yamlConfig);  // RCE via !!javax.script.ScriptEngineManager
```
</details>

<details>
<summary><b>Java: Expression Language Injection (SpEL/OGNL)</b></summary>

```java
// DETECTED: Spring Expression Language Injection
String expr = request.getParameter("filter");
ExpressionParser parser = new SpelExpressionParser();
parser.parseExpression(expr).getValue();  // RCE via T(java.lang.Runtime)

// DETECTED: OGNL Injection (Struts)
String input = request.getParameter("expr");
OgnlContext ctx = new OgnlContext();
Ognl.getValue(input, ctx);  // RCE via @java.lang.Runtime@getRuntime().exec()
```
</details>

### Advanced Node.js Evasion Detection

The scanner detects sophisticated obfuscation techniques that bypass traditional scanners:

<details>
<summary><b>Level 1: Lazy Property Attack (String Concatenation)</b></summary>

```javascript
// DETECTED: Obfuscated child_process exec
const cp = require('child_process');
const method = 'ex' + 'ec';  // Hides "exec" from grep
cp[method](userInput);       // Dynamic method invocation
```
</details>

<details>
<summary><b>Level 2: Prototype Pollution "Ghost Sink" RCE</b></summary>

```javascript
// DETECTED: Prototype pollution enables "safe-looking" exec
const config = {};
Object.assign(config.__proto__, JSON.parse(userInput));
// Attacker sets: {"shell": true}

// This LOOKS safe but inherits polluted shell option!
execSync('echo hello');  // Now executes with shell=true from __proto__
```
</details>

<details>
<summary><b>Level 3: Worker Thread Cross-Context Taint</b></summary>

```javascript
// DETECTED: Taint flows through Worker threads
const { Worker, workerData } = require('worker_threads');
const payload = req.body.data;
new Worker('./worker.js', { workerData: payload });

// worker.js - executes in separate thread
const { execSync } = require('child_process');
execSync(workerData);  // Taint from main thread!
```
</details>

<details>
<summary><b>Level 4: toString Hijack Implicit Execution</b></summary>

```javascript
// DETECTED: Implicit code execution via toString hijack
const obj = JSON.parse(userInput);
obj.toString = function() {
    require('child_process').exec(this.cmd);
};

// ANY string coercion triggers execution:
console.log("Value: " + obj);  // toString() called implicitly
`Template ${obj}`;              // Also triggers toString()
```
</details>

---

## Sample Output

```
================================================================================
                            AST-SCANNER REPORT
================================================================================
Scan Date: 2026-01-25
Files Scanned: 156
Total Findings: 12

Summary by Severity:
  CRITICAL  : 7
  HIGH      : 4
  MEDIUM    : 1
================================================================================

FILE: services/ReportService.java
--------------------------------------------------------------------------------
[CRITICAL] 2nd-Order SQLi - HQL string with entity value (FINAL BOSS)
  Line 45: String hql = "FROM Report WHERE " + user.getFilter();
  -> Entity value from Repository.find.getFilter() used in HQL construction.
     Enables DB function hijacking (dbms_pipe.receive_message, pg_sleep).

[CRITICAL] 2nd-Order XPath Injection - evaluate() with entity value
  Line 89: xpath.evaluate("//dept[@name='" + dept + "']", doc);
  -> Entity value from Repository.find.getDepartment() in XPath.evaluate().
     Payload can break out of XML tree logic or enumerate nodes.

FILE: controllers/DataController.py
--------------------------------------------------------------------------------
[CRITICAL] 2nd-Order Code Injection - pandas df.query() with DB-sourced value
  Line 34: result = df.query(filter_expr)
  -> DB value from SQLAlchemy query result passed to df.query().
     Pandas query() evaluates strings as expressions with @var syntax.

FILE: models/UserPrefs.php
--------------------------------------------------------------------------------
[CRITICAL] 2nd-Order SQLi - Unserialized object in SQL (Double-Unserialize)
  Line 67: $sql = "SELECT * FROM items WHERE cat = " . $prefs->category;
  -> Unserialized object from unserialize(PDO::fetch) used in SQL.
     Payload chain: DB -> unserialize -> property -> SQL sink.
================================================================================
```

### Minified File Warning

When the scanner detects a minified JavaScript file, it displays a prominent warning:

```
  ╔══════════════════════════════════════════════════════════════════════════════╗
  ║  ⚠️  MINIFIED FILE DETECTED                                                   ║
  ║  File: loader.min.js                                                         ║
  ║                                                                              ║
  ║  WARNING: Minified files may produce MORE FALSE POSITIVES.                  ║
  ║  Findings from this file should be reviewed carefully.                      ║
  ╚══════════════════════════════════════════════════════════════════════════════╝
```

**Detection heuristics:**
- Very few lines with large file size
- Average line length > 500 characters
- Single lines > 1000 characters
- High semicolon density with minimal newlines
- Filename contains `.min.`
- High frequency of single-letter variables

---

## Language Support

| Language | Extensions | Frameworks | 2nd-Order | Status |
|----------|------------|------------|:---------:|:------:|
| **Java** | `.java` | Spring, JPA/Hibernate, Criteria API | Yes | Full |
| **C#** | `.cs` | ASP.NET, Entity Framework, EF Core | Yes | Full |
| **JavaScript** | `.js`, `.jsx` | Express, Mongoose, Sequelize | Yes | Full |
| **TypeScript** | `.ts`, `.tsx` | Node.js, TypeORM | Yes | Full |
| **Python** | `.py` | Flask, Django, SQLAlchemy, Pandas | Yes | Full |
| **PHP** | `.php` | Laravel, PDO, mysqli | Yes | Full |
| **Go** | `.go` | GORM, database/sql | Limited | Basic |
| **Ruby** | `.rb` | Rails, ActiveRecord | Limited | Basic |

> **Note:** Go and Ruby support is basic. Core vulnerability patterns are detected, but advanced 2nd-order flows and framework-specific sinks may be missing.

---

## CLI Reference

```bash
usage: ast-scanner.py [-h] [-v] [--output {text,json}]
                      [-o FILE] [--min-confidence {HIGH,MEDIUM,LOW}]
                      [--scan-all] target

positional arguments:
  target                    File or directory to scan

options:
  -h, --help                Show help message
  -v, --verbose             Detailed output
  --output {text,json}      Output format
  -o, --output-file FILE    Save to file
  --min-confidence LEVEL    HIGH, MEDIUM, or LOW
  --scan-all                Include vendor/minified files
```

---

## CI/CD Integration

### GitHub Actions

```yaml
- name: Security Scan
  run: |
    python3 ast-scanner.py . --min-confidence HIGH --output json -o results.json
    if grep -q '"severity": "CRITICAL"' results.json; then
      echo "::error::Critical vulnerabilities found!"
      exit 1
    fi
```

### Pre-commit Hook

```bash
#!/bin/bash
python3 ast-scanner.py . --min-confidence HIGH
[ $? -ne 0 ] && echo "Security issues found!" && exit 1
```

---

## Project Structure

```
ast-scanner/
├── ast-scanner.py          # Main scanner engine
├── README.md
├── LICENSE
└── test-files/
    ├── xpath-2nd-order.java       # XPath injection tests
    ├── hql-function-injection.java # HQL FINAL BOSS tests
    ├── pandas-2nd-order.py        # Pandas df.query() tests
    ├── php-double-unserialize.php # Double-unserialize tests
    ├── criteria-api-injection.java # Criteria API tests
    └── ...
```

---

## Disclaimer

This tool is for **authorized security testing only**. Always obtain proper authorization before scanning. Verify findings manually. The authors are not responsible for misuse.

---

## License

MIT License - see [LICENSE](LICENSE) for details.

---

<p align="center">
  <b>Created by worldtreeboy</b><br>
  <sub>Hunting 2nd-order vulnerabilities that others miss.</sub>
</p>

<p align="center">
  <a href="https://github.com/worldtreeboy">
    <img src="https://img.shields.io/badge/GitHub-worldtreeboy-181717?style=for-the-badge&logo=github" alt="GitHub">
  </a>
</p>
