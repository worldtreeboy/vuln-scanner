<h1 align="center">
  <br>
  <pre>
██╗   ██╗██╗   ██╗██╗     ███╗   ██╗██╗  ██╗██╗   ██╗███╗   ██╗████████╗███████╗██████╗
██║   ██║██║   ██║██║     ████╗  ██║██║  ██║██║   ██║████╗  ██║╚══██╔══╝██╔════╝██╔══██╗
██║   ██║██║   ██║██║     ██╔██╗ ██║███████║██║   ██║██╔██╗ ██║   ██║   █████╗  ██████╔╝
╚██╗ ██╔╝██║   ██║██║     ██║╚██╗██║██╔══██║██║   ██║██║╚██╗██║   ██║   ██╔══╝  ██╔══██╗
 ╚████╔╝ ╚██████╔╝███████╗██║ ╚████║██║  ██║╚██████╔╝██║ ╚████║   ██║   ███████╗██║  ██║
  ╚═══╝   ╚═════╝ ╚══════╝╚═╝  ╚═══╝╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═══╝   ╚═╝   ╚══════╝╚═╝  ╚═╝
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
  <img src="https://img.shields.io/badge/languages-7+-22c55e?style=for-the-badge" alt="7+ Languages">
  <img src="https://img.shields.io/badge/2nd--Order-Detection-ff6b6b?style=for-the-badge" alt="2nd-Order">
  <img src="https://img.shields.io/badge/version-3.0-blueviolet?style=for-the-badge" alt="Version">
</p>

<p align="center">
  <img src="https://img.shields.io/badge/C%23-239120?style=flat-square&logo=csharp&logoColor=white" alt="C#">
  <img src="https://img.shields.io/badge/Java-ED8B00?style=flat-square&logo=openjdk&logoColor=white" alt="Java">
  <img src="https://img.shields.io/badge/JavaScript-F7DF1E?style=flat-square&logo=javascript&logoColor=black" alt="JavaScript">
  <img src="https://img.shields.io/badge/Python-3776AB?style=flat-square&logo=python&logoColor=white" alt="Python">
  <img src="https://img.shields.io/badge/PHP-777BB4?style=flat-square&logo=php&logoColor=white" alt="PHP">
  <img src="https://img.shields.io/badge/Ruby-CC342D?style=flat-square&logo=ruby&logoColor=white" alt="Ruby">
  <img src="https://img.shields.io/badge/TypeScript-3178C6?style=flat-square&logo=typescript&logoColor=white" alt="TypeScript">
</p>

---

> **Disclaimer:** This is a **hobby/learning project** built for fun and educational purposes. It is **NOT** intended to replace professional SAST tools like [Semgrep](https://semgrep.dev/), [CodeQL](https://codeql.github.com/), [Snyk](https://snyk.io/), or [SonarQube](https://www.sonarqube.org/). For production security scanning, please use established tools with active maintenance and comprehensive rule sets. Use this project to learn about static analysis concepts, experiment with vulnerability patterns, or as a starting point for your own security research.

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
<td><b>RailsGoat (OWASP)</b></td>
<td align="center">22</td>
<td align="center"><code>5</code></td>
<td align="center"><code>15</code></td>
<td align="center"><code>0</code></td>
<td align="center"><b>20</b></td>
</tr>
<tr>
<td><b>DVCSharp API</b></td>
<td align="center">10</td>
<td align="center"><code>3</code></td>
<td align="center"><code>6</code></td>
<td align="center"><code>0</code></td>
<td align="center"><b>9</b></td>
</tr>
<tr>
<td colspan="2" align="right"><b>TOTAL</b></td>
<td align="center"><b><code>74</code></b></td>
<td align="center"><b><code>121</code></b></td>
<td align="center"><b><code>12</code></b></td>
<td align="center"><b>203</b></td>
</tr>
</table>

<p align="center">
  <sub>616 files scanned across Python, Java, JavaScript, TypeScript, Ruby, and C# codebases</sub>
</p>

### Vulnerabilities Detected

<table>
<tr>
<td width="50%" valign="top">

**WebGoat (Java)**
- SQL Injection via string concatenation
- SSRF in URL construction
- XStream deserialization vulnerabilities

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
<tr>
<td width="50%" valign="top">

**RailsGoat (Ruby)**
- SQL Injection via string interpolation in ActiveRecord
- IDOR via `find_by_id`, `where` without ownership check
- Code Injection via `constantize` and `.try()` with user input
- Insecure Deserialization via `Marshal.load`
- Command Injection in `system()` call

</td>
<td width="50%" valign="top">

**DVCSharp API (C#)**
- SQL Injection via EF Core `FromSql` with interpolated string
- IDOR via LINQ `Where` with cookie-sourced ID
- Deserialization via `Type.GetType()` with user-controlled type
- XXE in XML parser without secure configuration
- SSRF in URL construction

</td>
</tr>
</table>

---

## What Makes VulnHunter Different?

Most SAST tools detect **1st-order injection** - where user input flows directly to a sink. **VulnHunter** goes deeper, detecting **2nd-order injection** where payloads are:

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
- **False Positive Reduction** - Recognizes safe patterns:
  - Parameterized queries (`:param`, `?`, `%s` placeholders)
  - SQLAlchemy bound parameters with `execute(query, params)`
  - Input sanitization (`escapeshellarg`, `escapeshellcmd`)
  - Allowlist validation before dangerous operations
  - Safe deserialization options (`allowed_classes`)
  - Static/hardcoded values (no user input)
  - String literals excluded from taint matching

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
- **IDOR** (Insecure Direct Object Reference)
- **MFLAC** (Missing Function Level Access Control)

### Not Detected
The following vulnerability types are **not** scanned:
- Cross-Site Scripting (XSS)
- Path Traversal
- Weak Cryptography
- Session Fixation
- Prototype Pollution

</td>
</tr>
</table>

### Detection Mechanism by Language

Each language uses a different mix of analysis techniques depending on parser availability and framework complexity:

| Language | AST Taint Tracking | Regex Taint Tracking | Regex Pattern Matching | Notes |
|----------|:------------------:|:--------------------:|:----------------------:|-------|
| **Python** | ~60% | ~10% | ~30% | Full AST via `ast.NodeVisitor` — traces assignments, calls, returns. Regex for evasion & IDOR post-pass. |
| **Java** | — | ~45% | ~55% | Regex identifies `@PathVariable`/`@RequestParam` sources, tracks through getters & entity chains to sinks. Spring annotation analysis for MFLAC. |
| **JavaScript** | — | ~30% | ~70% | Regex-based source identification (`req.params`, `req.body`), variable assignment tracking. Direct pattern matching for IDOR/MFLAC/NoSQL. |
| **TypeScript** | — | ~30% | ~70% | Same engine as JavaScript. Covers NestJS decorators and TypeORM patterns. |
| **PHP** | — | ~35% | ~65% | Tracks `$_GET`/`$_POST`/`$request->input()` through variable assignments. Regex for Laravel/PDO/mysqli sink detection. |
| **C#** | — | ~40% | ~60% | Constructor parameter flow, LINQ taint tunnel, field tracking. Brace-depth-aware method body analysis for IDOR ownership checks. |
| **Ruby** | — | ~30% | ~70% | Tracks `params[]` through variable assignments. Regex for ActiveRecord sinks, 2nd-order structural/calculation/destructive SQLi. |

> **AST Taint Tracking** = Full abstract syntax tree parsing with data flow analysis (only Python).
> **Regex Taint Tracking** = Regex-based source identification → variable propagation → sink detection (all other languages).
> **Regex Pattern Matching** = Direct pattern matching without variable flow tracking (e.g., `findById(req.params.id)` matched as a single pattern).

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
| IDOR | Excellent | - | Destructuring, dynamic finders, scoped query detection |
| MFLAC | Excellent | - | AST-based (Java), route analysis, before_action (Rails) |

### Multi-Language Test Validation

The scanner has been validated against comprehensive test suites covering all vulnerability categories across 7 languages/frameworks:

| Language | Framework | True Positives | Categories Covered |
|----------|-----------|:--------------:|:-------------------|
| **Java** | Spring Boot, JPA/Hibernate | 50+ | SQL/HQL/NoSQL, Command, Code (SpEL, OGNL, MVEL), XPath, XXE, XSLT, SSRF, SSTI, Deserialization, IDOR, MFLAC |
| **Python** | Flask, Django | 35+ | SQL/NoSQL, Command, Code, XPath, XXE, SSRF, SSTI, Deserialization, Evasion, IDOR, MFLAC |
| **JavaScript** | Express.js, Node.js | 40+ | SQL/NoSQL, Command, Code (eval, vm), XPath, XXE, SSRF, SSTI, Deserialization, IDOR, MFLAC |
| **TypeScript** | NestJS, Express, TypeORM | 45+ | SQL/NoSQL, Command, Code, XPath, XXE, SSRF, SSTI, Deserialization, IDOR, MFLAC |
| **PHP** | Laravel, Symfony | 40+ | SQL/NoSQL, Command, Code, XPath, XXE, XSLT, SSRF, SSTI, Deserialization, Evasion, IDOR, MFLAC |
| **C#** | ASP.NET, Entity Framework | 35+ | SQL/NoSQL, Command, Code, XPath, XXE, XSLT, SSRF, SSTI, Deserialization, Evasion, IDOR, MFLAC |
| **Ruby** | Rails, ActiveRecord, Sinatra | 30+ | SQL/NoSQL, Command, Code, XPath, XXE, SSRF, SSTI, Deserialization, Evasion, IDOR, MFLAC |

**Test categories include:**
- SQL/NoSQL/HQL Injection (string concat, format, interpolation, 2nd-order)
- Command Injection (system, exec, subprocess, ProcessBuilder, child_process)
- Code Injection (eval, exec, ScriptEngine, SpEL, OGNL, vm.runInContext)
- XPath/XQuery Injection (XPath, SelectNodes, DOMXPath)
- XXE & XSLT Attacks (XMLParser, DocumentBuilder, XslTransform)
- SSRF (requests, HttpClient, cURL, Net::HTTP, axios, fetch)
- SSTI (Jinja2, Twig, ERB, Freemarker, Velocity, Blade, EJS)
- Insecure Deserialization (pickle, unserialize, Marshal, BinaryFormatter, SnakeYAML, node-serialize)
- IDOR (direct object lookup, mass assignment, path traversal in object access)
- MFLAC (missing auth middleware, auth-only guards on admin endpoints, privilege escalation sinks)

---

## Quick Start

```bash
# Clone (rename repo on GitHub: Settings → Repository name)
git clone https://github.com/worldtreeboy/vulnhunter.git
cd vulnhunter

# Install dependencies
pip3 install -r requirements.txt

# Scan a project
python3 vulnhunter.py /path/to/project

# Scan single file
python3 vulnhunter.py vulnerable_app.java

# JSON output for CI/CD
python3 vulnhunter.py project/ --output json -o report.json

# High-confidence only
python3 vulnhunter.py project/ --min-confidence HIGH
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

## IDOR & MFLAC Detection

VulnHunter detects **Insecure Direct Object Reference (IDOR)** and **Missing Function Level Access Control (MFLAC)** across all 7 supported languages.

### IDOR Patterns Detected

| Pattern | Languages | Example |
|---------|-----------|---------|
| **Direct DB lookup by user ID** | All | `repo.findById(req.params.id)`, `Model.objects.get(pk=request.GET['id'])` |
| **Hash/dict access by user input** | Python, JS, Ruby, PHP | `invoices.get(invoice_id)`, `users[params[:id]]` |
| **Collection lookup without ownership** | C#, Java | `_records.Find(r => r.Id == id)`, `documents.get(docId)` |
| **Mass assignment** | All | `Model.update(req.body)`, `User(**request.data)`, `params.permit!` |
| **Indirect taint to ORM lookup** | Python, PHP | `user_id = request.args.get('id'); User.objects.get(pk=user_id)` |
| **Indirect taint to PDO/Laravel** | PHP | `$id = $request->input('id'); Item::find($id)` |
| **EntityManager.find** | Java | `em.find(User.class, id)` with `@PathVariable` |
| **Dynamic finder lookup** | Ruby | `Pay.find_by_id(params[:id])` without ownership check |
| **Destructuring to DB lookup** | JS/TS | `const { userId } = req.params; data[userId]` |
| **Arbitrary method dispatch** | Ruby | `self.try(params[:graph])` — user-controlled method invocation |

### MFLAC Patterns Detected

| Pattern | Languages | Example |
|---------|-----------|---------|
| **Admin route without auth** | All | `@app.route('/admin/...')` without `@login_required` |
| **Auth-only on admin endpoint** | All | `[Authorize]` without `Roles="Admin"`, `isLoggedIn` without `isAdmin` |
| **Missing security annotation** | Java | `@GetMapping("/admin/reset")` without `@PreAuthorize` (AST-based) |
| **Privilege escalation sinks** | Java | `updateRole()`, `promoteToAdmin()` with auth-only guard |
| **Annotation inheritance bypass** | Java | `@Service` + class-level `@PreAuthorize` with unprotected `deleteAll()` methods |
| **Sinatra/Express unprotected routes** | Ruby, JS | `get '/admin' do` without role check |

### False Positive Reduction

- Ownership checks detected (e.g., `record.OwnerId != currentUserId`, `invoice['user_id'] != get_current_user()`, `Forbid()`)
- Scoped queries recognized (e.g., `current_user.orders.find(...)`, `Order.find({ userId: req.user.id })`)
- Role checks in method body suppress MFLAC (e.g., `User.IsInRole("Admin")`, `user['role'] == 'admin'`)
- Function definitions excluded from auth context matching (Python)
- Comment lines excluded from auth context (Python, Java) — prevents `// no check for getOwnerId()` from suppressing findings
- String literals in route attributes excluded from brace-depth analysis (C#)
- Class-level `[Route]` combined with method `[Http*]` for admin path detection (C#)
- PHP `abort(403)`, `!= auth()->id()` recognized as ownership verification
- `req.user.*` excluded from NoSQL injection patterns (session values, not user input)
- Ruby IDOR: same-line scoping (`current_user.orders.find(...)`) vs narrow-context (±3 lines) ownership checks — prevents unrelated `current_user` mentions from suppressing findings
- Google jsapi and third-party JS libraries auto-skipped to avoid minified file false positives

> **Note:** IDOR and MFLAC detection is **not comprehensive**. These are pattern-based heuristics that catch common anti-patterns but may miss complex authorization logic, custom middleware chains, or framework-specific security configurations. For thorough access control testing, combine static analysis with dynamic testing (e.g., Burp Suite, OWASP ZAP) and manual code review.

---

## Evasion Detection

VulnHunter catches sophisticated evasion techniques:

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
<summary><b>Level 2: Worker Thread Cross-Context Taint</b></summary>

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
<summary><b>Level 3: toString Hijack Implicit Execution</b></summary>

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
                            VULNHUNTER REPORT
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
| **Ruby** | `.rb` | Rails, ActiveRecord, Sinatra | Yes | Full |

> **Note:** Ruby 2nd-order detection covers structural SQLi (order/group/pluck), calculation injection, and destructive sink patterns via ActiveRecord. Validated against OWASP RailsGoat with 20 true positives and 0 false positives.

---

## CLI Reference

```bash
usage: vulnhunter.py [-h] [-v] [--output {text,json}]
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
    python3 vulnhunter.py . --min-confidence HIGH --output json -o results.json
    if grep -q '"severity": "CRITICAL"' results.json; then
      echo "::error::Critical vulnerabilities found!"
      exit 1
    fi
```

### Pre-commit Hook

```bash
#!/bin/bash
python3 vulnhunter.py . --min-confidence HIGH
[ $? -ne 0 ] && echo "Security issues found!" && exit 1
```

---

## JSHunter - JavaScript Vulnerability Scanner

<p align="center">
  <img src="https://img.shields.io/badge/JavaScript-ES6+-F7DF1E?style=for-the-badge&logo=javascript&logoColor=black" alt="ES6+">
  <img src="https://img.shields.io/badge/Node.js-Express-339933?style=for-the-badge&logo=node.js&logoColor=white" alt="Express">
  <img src="https://img.shields.io/badge/AST-Parsing-blue?style=for-the-badge" alt="AST">
</p>

**jshunter.py** is a specialized AST-based scanner for JavaScript (ES6+) and Node.js/Express.js applications.

> **Note:** JSHunter provides **comprehensive detection** for **XSS** and **Prototype Pollution** vulnerabilities. Other vulnerability types (Path Traversal, Command Injection, etc.) have basic detection but are **not as comprehensive**. For full coverage, combine with other tools.

### Core Strengths

| Category | Coverage | Description |
|----------|----------|-------------|
| **XSS Detection** | Comprehensive | DOM XSS, Reflected XSS, template literals, tagged templates, jQuery sinks |
| **Prototype Pollution** | Comprehensive | For-in loops, spread, Object.assign, defineProperty, deep merge, function params |
| **Path Traversal** | Basic | fs.readFile, readFileSync, createReadStream |
| **Command Injection** | Basic | child_process.exec, spawn, fork |
| **Eval/Code Injection** | Basic | eval(), new Function(), setTimeout(string) |

### Features

| Feature | Description |
|---------|-------------|
| **ES6+ Support** | Full ES6 syntax via `esprima` (const, let, arrows, destructuring, template literals, spread) |
| **Taint Tracking** | Source-to-sink data flow across assignments, function calls, and transformations |
| **Express.js Detection** | `req.query`, `req.body`, `req.params` → `res.send()`, `res.render()` |
| **Inter-procedural Analysis** | Tracks taint through wrapper functions like respond(), sendError() |
| **Encoding Bypass Detection** | Tracks taint through toString, join, split, map, filter, reduce |
| **Minified File Detection** | Warns when scanning minified/obfuscated code |

### Installation

```bash
pip3 install esprima        # Recommended: ES6+ support
pip3 install pyjsparser     # Fallback: ES5 only
```

### Usage

```bash
# Scan JavaScript file
python3 jshunter.py app.js

# Scan Express.js project
python3 jshunter.py /path/to/express/app --verbose

# JSON output
python3 jshunter.py src/ --output json -o vuln-report.json

# Include medium/low confidence
python3 jshunter.py src/ --min-confidence MEDIUM
```

### Detection Categories

#### XSS Detection

| Source Type | Examples |
|-------------|----------|
| **URL Sources** | `location.hash`, `location.search`, `document.URL`, `document.referrer` |
| **Express.js** | `req.query.*`, `req.body.*`, `req.params.*`, `req.headers`, `req.cookies` |
| **User Input** | `URLSearchParams.get()`, `event.data` (postMessage), `.value` (form inputs) |
| **Storage** | `localStorage.getItem()`, `sessionStorage.getItem()` |

| Sink Type | Examples |
|-----------|----------|
| **DOM XSS** | `innerHTML`, `outerHTML`, `document.write()`, `insertAdjacentHTML()` |
| **Eval Sinks** | `eval()`, `new Function()`, `setTimeout(string)`, `setInterval(string)` |
| **Express.js** | `res.send()`, `res.write()`, `res.end()`, `res.render()` |
| **jQuery** | `.html()`, `.append()`, `.prepend()`, `.after()`, `.before()` |

#### Prototype Pollution Detection

| Pattern | Example |
|---------|---------|
| **For-in Loop** | `for (key in userObj) { target[key] = userObj[key] }` |
| **Spread Operator** | `const merged = { ...req.body }` |
| **Object.assign** | `Object.assign({}, JSON.parse(userInput))` |
| **Object.assign to __proto__** | `Object.assign(obj.__proto__, data)` |
| **Object.defineProperty** | `Object.defineProperty(obj.__proto__, key, desc)` |
| **Function Parameters** | `function set(obj, key, val) { obj[key] = val }` |
| **Dynamic Method Call** | `obj[userInput]()` |
| **Lodash/jQuery Merge** | `_.merge()`, `_.defaultsDeep()`, `$.extend(true, ...)` |

#### Advanced Patterns

| Pattern | Detection |
|---------|-----------|
| **ES6 Destructuring** | `const { q } = req.query` → taint tracked to `q` |
| **Tagged Templates** | `` customTag`...${tainted}` `` → XSS if tag outputs to DOM |
| **Array Method Flow** | `arr.map().join()` → taint propagates through chain |
| **Logical Operators** | `val \|\| default` → taint preserved |
| **Template Literals** | `` `<div>${userInput}</div>` `` → detected in res.send() |

### Example Output

```
======================================================================
JSHunter Scan Report (AST-Based Analysis)
======================================================================
Files Scanned: 15
Vulnerabilities Found: 8

[1] Prototype Pollution via Object.assign() to __proto__
    File: api.js:15:8
    Severity: CRITICAL
    Description: Object.assign() directly modifying __proto__ with tainted data
    Source: req.body
    Sink: Object.assign(__proto__, ...)
    Remediation: Never use __proto__ as Object.assign target

[2] Reflected XSS via send()
    File: routes.js:42:4
    Severity: HIGH
    Description: Tainted data from 'express_query' reflected in HTTP response
    Source: req.query.name
    Sink: res.send()
    Remediation: Escape HTML entities or use res.json()

[3] XSS via Tagged Template Literal
    File: logger.js:27:0
    Severity: HIGH
    Description: Tainted data passed to tagged template function
    Source: URLSearchParams.get()
    Sink: customLogger`...`
    Remediation: Ensure tag function sanitizes interpolated values
```

### Test Coverage

| Test File | Patterns | Findings |
|-----------|----------|----------|
| `nodejs-express-tests.js` | Express.js XSS & PP | 36 |
| `advanced-express-tests.js` | ES6 destructuring, arrays, WebSocket | 34 |
| `edge-cases-tests.js` | Multi-hop taint, closures, async | 22 |
| `encoding-bypass-tests.js` | toString, Base64, URL encoding | 35 |

---

## Project Structure

```
vulnhunter/
├── vulnhunter.py          # Multi-language SAST scanner
├── jshunter.py            # Specialized JavaScript vulnerability scanner
├── requirements.txt       # Python dependencies
├── README.md
├── LICENSE
└── test-files/
    ├── vulnerability-tests-*.ext        # Core vulnerability tests per language
    ├── 2nd-order-*.java/php             # 2nd-order injection tests
    ├── evasive-*.js/py/php              # Evasion technique tests
    ├── idor-access-control-tests.*      # IDOR test cases per language
    ├── mflac-tests.*                    # MFLAC test cases per language
    ├── xss-tests.js                     # JSHunter JavaScript test cases
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
