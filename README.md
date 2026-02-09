<h1 align="center">
  <br>
  <pre>
██╗   ██╗██╗██████╗ ███████╗██╗  ██╗██╗   ██╗███╗   ██╗████████╗███████╗██████╗
██║   ██║██║██╔══██╗██╔════╝██║  ██║██║   ██║████╗  ██║╚══██╔══╝██╔════╝██╔══██╗
██║   ██║██║██████╔╝█████╗  ███████║██║   ██║██╔██╗ ██║   ██║   █████╗  ██████╔╝
╚██╗ ██╔╝██║██╔══██╗██╔══╝  ██╔══██║██║   ██║██║╚██╗██║   ██║   ██╔══╝  ██╔══██╗
 ╚████╔╝ ██║██████╔╝███████╗██║  ██║╚██████╔╝██║ ╚████║   ██║   ███████╗██║  ██║
  ╚═══╝  ╚═╝╚═════╝ ╚══════╝╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═══╝   ╚═╝   ╚══════╝╚═╝  ╚═╝
  </pre>
</h1>

<h3 align="center">Multi-Language SAST with 2nd-Order Injection Detection</h3>

<p align="center">
  <img src="https://img.shields.io/badge/python-3.8+-3776ab?style=for-the-badge&logo=python&logoColor=white" alt="Python 3.8+">
  <img src="https://img.shields.io/badge/languages-8+-22c55e?style=for-the-badge" alt="8+ Languages">
  <img src="https://img.shields.io/badge/2nd--Order-Detection-ff6b6b?style=for-the-badge" alt="2nd-Order">
  <img src="https://img.shields.io/badge/version-1.1-blueviolet?style=for-the-badge" alt="Version">
</p>

<p align="center">
  <img src="https://img.shields.io/badge/C%23-239120?style=flat-square&logo=csharp&logoColor=white" alt="C#">
  <img src="https://img.shields.io/badge/Java-ED8B00?style=flat-square&logo=openjdk&logoColor=white" alt="Java">
  <img src="https://img.shields.io/badge/JavaScript-F7DF1E?style=flat-square&logo=javascript&logoColor=black" alt="JavaScript">
  <img src="https://img.shields.io/badge/Python-3776AB?style=flat-square&logo=python&logoColor=white" alt="Python">
  <img src="https://img.shields.io/badge/PHP-777BB4?style=flat-square&logo=php&logoColor=white" alt="PHP">
  <img src="https://img.shields.io/badge/Ruby-CC342D?style=flat-square&logo=ruby&logoColor=white" alt="Ruby">
  <img src="https://img.shields.io/badge/TypeScript-3178C6?style=flat-square&logo=typescript&logoColor=white" alt="TypeScript">
  <img src="https://img.shields.io/badge/Go-00ADD8?style=flat-square&logo=go&logoColor=white" alt="Go">
</p>

---

> **Disclaimer:** This is a **hobby/learning project** for educational purposes. It is **NOT** a replacement for professional SAST tools like [Semgrep](https://semgrep.dev/), [CodeQL](https://codeql.github.com/), [Snyk](https://snyk.io/), or [SonarQube](https://www.sonarqube.org/). Use this to learn about static analysis concepts or as a starting point for security research.

---

## Quick Start

```bash
git clone https://github.com/worldtreeboy/vibehunter.git
cd vibehunter
pip3 install -r requirements.txt

# Scan a project (Python, Java, JS/TS, PHP, C#, Ruby, Go)
python3 vibehunter.py /path/to/project

# JSON output
python3 vibehunter.py project/ --output json -o report.json

# Java AST scanner (deeper analysis via tree-sitter)
pip3 install tree-sitter tree-sitter-java
python3 java-treesitter.py /path/to/java/project

# JavaScript AST scanner (deeper analysis via tree-sitter)
pip3 install tree-sitter tree-sitter-javascript
python3 js-treesitter.py /path/to/js/project

# PHP AST scanner (deeper analysis via tree-sitter)
pip3 install tree-sitter tree-sitter-php
python3 php-treesitter.py /path/to/php/project

# Go AST scanner (deeper analysis via tree-sitter)
pip3 install tree-sitter tree-sitter-go
python3 go-treesitter.py /path/to/go/project
```

---

## What's New in v1.1

### Inter-Procedural Analysis (Tree-sitter Scanners)
All three tree-sitter scanners now perform **two-pass inter-procedural analysis** within each file. A first pass builds function summaries (which parameters flow to return values, which reach sinks), and a second pass uses those summaries to propagate taint through user-defined function calls.

```java
// Previously missed — now detected:
private String wrapInput(String data) { return data.trim(); }

public void vulnerable(HttpServletRequest req) throws SQLException {
    String input = req.getParameter("id");
    String wrapped = wrapInput(input);  // Taint flows through wrapInput()
    stmt.executeQuery("SELECT * FROM users WHERE id = '" + wrapped + "'");
}
```

### YAML Config File (`.vibehunter.yml`)
Define custom sources, sinks, sanitizers, path exclusions, and suppression settings per project. Place `.vibehunter.yml` in your project root or pass `--config path/to/config.yml`.

```yaml
sources:
  java: ["getCustomInput"]
  php: ["$customGlobal"]
sinks:
  java:
    sql: ["customQuery", "rawExecute"]
sanitizers:
  java:
    universal: ["MySanitizer.clean"]
exclude_paths:
  - "vendor/"
  - "test/"
suppression_keyword: "nosec"
min_confidence: "HIGH"
```

### Inline Suppression
Suppress known-safe findings with `// nosec` or `// vibehunter:ignore` comments on any line:

```java
stmt.executeQuery(knownSafeQuery); // nosec
stmt.executeQuery(anotherSafe);    // vibehunter:ignore
```

### vibehunter.py FP Reduction
- **Java**: Annotation-aware parameter tainting — only taints params with `@RequestParam`, `@PathVariable`, `@RequestBody`, `@RequestHeader`, `@CookieValue`, or `HttpServletRequest` types, instead of all method parameters
- **JavaScript**: Sanitizer function recognition — `escapeHtml()`, `DOMPurify.sanitize()`, `parseInt()`, `encodeURIComponent()`, and others now break the taint chain
- **PHP**: Context-aware sanitizer discrimination — `escapeshellarg()` kills command injection taint but not SQL injection taint, matching the tree-sitter scanner behavior

---

## What Makes Vibehunter Different?

Most SAST tools detect **1st-order injection** where user input flows directly to a sink. Vibehunter also detects **2nd-order injection** where payloads are stored in the database first, then retrieved and used unsafely later.

```
Attacker stores payload in DB  ──>  App fetches data  ──>  Data used in query/command  ──>  Payload executes
```

Tracked sources include `repo.findById()`, `cursor.fetchone()`, `Model.findOne()`, `pd.read_sql()`, `fetch_assoc()`, ActiveRecord finders, and more across all 7 languages.

---

## Detection Categories

| Category | 1st-Order | 2nd-Order | Languages |
|----------|:---------:|:---------:|-----------|
| SQL/NoSQL/HQL Injection | Yes | Yes | All 7 |
| Command Injection | Yes | Yes | All 7 |
| Code Injection (eval, SpEL, OGNL, pandas) | Yes | Yes | All 7 |
| XPath/XQuery Injection | Yes | Yes | All 7 |
| XXE & XSLT | Yes | - | All 7 |
| SSTI (Velocity, Freemarker, Thymeleaf, Pebble, Mustache, Groovy, Jinjava, Handlebars) | Yes | - | All 7 |
| Insecure Deserialization (OIS, SnakeYAML, XStream, XMLDecoder, Jackson, Kryo, Hessian, node-serialize, serialijse, js-yaml, phar://) | Yes | Yes | All 7 |
| Expression Language (SpEL, OGNL, MVEL, EL) | Yes | - | Java |
| Reflection Injection | Yes | - | Java |

| Vulnerable Dependencies (`npm audit`) | Yes | - | JS (both scanners) |

**Not detected:** XSS (use js-treesitter.py for JS), Weak Crypto, Session Fixation, Prototype Pollution (use js-treesitter.py for JS), vm module code injection (use js-treesitter.py for JS), NoSQL Injection in JS (use js-treesitter.py), SQL Injection in JS (use js-treesitter.py).

---

## Language Support

| Language | Extensions | Frameworks | Scanner |
|----------|------------|------------|---------|
| **Java** | `.java` | Spring, JPA/Hibernate, Struts2, Servlets | vibehunter.py (regex) or java-treesitter.py (AST) |
| **C#** | `.cs` | ASP.NET, Entity Framework | vibehunter.py |
| **JavaScript** | `.js`, `.jsx`, `.mjs` | Express, Mongoose, Sequelize, mysql, pg, knex, prisma, ejs, pug, nunjucks, Handlebars | vibehunter.py (regex) or js-treesitter.py (AST) |
| **TypeScript** | `.ts`, `.tsx` | Node.js, TypeORM, NestJS | vibehunter.py or js-treesitter.py (AST) |
| **Python** | `.py` | Flask, Django, SQLAlchemy, Pandas | vibehunter.py |
| **PHP** | `.php` | Laravel, PDO, mysqli, Twig, MongoDB | vibehunter.py (regex) or php-treesitter.py (AST) |
| **Go** | `.go` | net/http, Gin, Echo, Fiber, GORM, sqlx | go-treesitter.py (AST) |
| **Ruby** | `.rb` | Rails, ActiveRecord, Sinatra | vibehunter.py |

### Analysis Techniques

| Language | AST Taint | Regex Taint | Pattern Match | Notes |
|----------|:---------:|:-----------:|:------------:|-------|
| Python | ~60% | ~10% | ~30% | Full AST via `ast.NodeVisitor` |
| Java <sup>TS</sup> | **~90%** | - | ~10% | Tree-sitter per-method taint, inter-procedural summaries, taint killers |
| Java | - | ~45% | ~55% | Regex-based Spring annotation analysis |
| JS/TS <sup>TS</sup> | **~90%** | - | ~10% | Tree-sitter file-level taint, inter-procedural summaries, safe-literal tracking |
| JS/TS | - | ~30% | ~70% | Regex source-sink tracking |
| PHP <sup>TS</sup> | **~85%** | - | ~15% | Tree-sitter per-function taint, inter-procedural summaries |
| Go <sup>TS</sup> | **~85%** | - | ~15% | Tree-sitter per-function taint, inter-procedural summaries, multi-framework support |
| PHP | - | ~35% | ~65% | `$_GET`/`$_POST` variable tracking |
| C# | - | ~40% | ~60% | Constructor flow, LINQ taint tunnel |
| Ruby | - | ~30% | ~70% | `params[]` tracking, ActiveRecord sinks |

---

## Scanners

### vibehunter.py - Multi-Language Scanner

The main scanner supporting all 7 languages with taint tracking, evasion detection, confidence scoring, and false positive reduction (parameterized queries, sanitization, allowlists, safe deserialization). Includes `npm audit` integration for JavaScript dependency vulnerability detection.

```bash
python3 vibehunter.py target/ [options]
  --output {text,json}        Output format
  -o, --output-file FILE      Save to file
  --min-confidence LEVEL      HIGH, MEDIUM, or LOW
  --scan-all                  Include vendor/minified files
  --config FILE               Path to .vibehunter.yml config file
  -v, --verbose               Detailed output
```

### java-treesitter.py - Java AST Scanner

Deep Java analysis using [tree-sitter](https://tree-sitter.github.io/) with **per-method taint scoping** and **inter-procedural function summaries**. Covers 12 vulnerability categories including JNDI injection, mass assignment, reflection injection, Spring Data `@Query` annotation analysis, comprehensive deserialization detection (ObjectInputStream, SnakeYAML, XStream, XMLDecoder, Jackson polymorphic typing, Kryo, Hessian/Burlap), SSTI for 8 template engines (Velocity, Freemarker, Thymeleaf, Pebble, JMustache, Groovy, Jinjava, Handlebars), and NoSQL injection (Document.parse, BasicDBObject `$where`). Safe pattern recognition: `ValidatingObjectInputStream`, `ObjectInputFilter` (Java 9+), `SafeConstructor`, `setRegistrationRequired(true)`. Framework-agnostic (Spring, Spring Data JPA, Struts2, Servlets, plain Java).

**Taint tracking features:**
- Per-method taint scoping with multi-pass propagation
- **Inter-procedural analysis** — function summaries track param-to-return and param-to-sink flows across method calls within the same file
- Enhanced for-loop propagation (`for (String x : taintedList)`)
- Try-with-resources propagation (`try (InputStream is = req.getInputStream())`)
- Taint-killing type conversions (`Integer.parseInt()`, `Long.parseLong()`, `UUID.fromString()`, `Boolean.parseBoolean()`, `Math.*`) — eliminates false positives when input is validated via type conversion
- StringBuilder/List taint propagation via `.append()` and `.add()`
- Partial parameterization detection — `"SELECT FROM " + table + " WHERE id = ?"` is correctly flagged (the `?` only covers `id`, not `table`)
- SQL receiver gating for ambiguous method names (`execute`, `query`) to prevent false positives on non-SQL receivers

```bash
pip3 install tree-sitter tree-sitter-java
python3 java-treesitter.py target/ [options]
  --output {text,json}        Output format
  -o, --output-file FILE      Save to file
  --min-severity LEVEL        CRITICAL, HIGH, MEDIUM, or LOW
  --all                       Show all confidence levels
  --config FILE               Path to .vibehunter.yml config file
```

### js-treesitter.py - JavaScript/TypeScript AST Scanner

Deep JavaScript/TypeScript analysis using [tree-sitter](https://tree-sitter.github.io/) with **file-level taint tracking** and **inter-procedural function summaries**. Covers 11 vulnerability categories: **SQL Injection** (mysql, pg, sequelize, knex, prisma), DOM XSS, Reflected XSS, **Server-Side Template Injection** (ejs, pug, nunjucks, Handlebars, mustache, doT), Prototype Pollution, Dangerous Eval, Command Injection, **NoSQL Injection**, Unsafe Deserialization, **Open Redirect** (including `res.redirect()`), and Vulnerable Dependencies (`npm audit`).

**Taint tracking features:**
- Multi-pass source-to-sink propagation with destructuring support (`const { a } = req.body`)
- **Inter-procedural analysis** — function summaries track param-to-return flows, propagating taint through user-defined function calls within the same file
- **`await` expression taint propagation** — `const data = await fetch(url)` correctly propagates taint through `await`
- **`.then()` callback taint propagation** — `fetch(url).then(data => sink(data))` taints the callback parameter
- **SQL injection detection** — mysql/mysql2 `connection.query()`, pg `pool.query()`, sequelize `sequelize.query()`, knex `.raw()`/`.whereRaw()`, prisma `$queryRaw`/`$queryRawUnsafe`. Parameterized queries with `?` placeholders correctly suppressed
- **SSTI detection** — `ejs.render(tainted)`, `pug.compile(tainted)`, `nunjucks.renderString(tainted)`, `Handlebars.compile(tainted)`, `doT.template(tainted)`. Static template strings correctly suppressed
- **`res.redirect()` open redirect detection** — Express/response redirect with tainted URL
- Safe literal tracking — `const cmd = 'ls'; exec(cmd)` is correctly ignored (no FP)
- `require()` and ES module `import` alias resolution — distinguishes `child_process.exec()` from Mongoose `Query.exec()`
- DOM-context-aware sink detection — `append`/`before`/`after` only flagged in DOM contexts (not array methods)
- NoSQL injection detection with safe-object-literal analysis, type-coercion sanitizer recognition, and multi-argument checking
- Taint-neutralizing functions (`encodeURIComponent`, `parseInt`, `DOMPurify.sanitize`) break the taint chain
- `process.argv` / `process.env` tracked as taint sources
- `spawn`/`spawnSync` with array args and no `{shell: true}` correctly suppressed
- TypeScript `.ts`/`.tsx` file support

Supports ES6+, Express.js, Mongoose, jQuery, and HTML inline scripts. Automatically skips vendor/third-party library files.

```bash
pip3 install tree-sitter tree-sitter-javascript
python3 js-treesitter.py target/ [options]
  --output {text,json}        Output format
  -o, --output-file FILE      Save to file
  --min-confidence LEVEL      HIGH, MEDIUM, or LOW
  --config FILE               Path to .vibehunter.yml config file
  -v, --verbose               Detailed output
```

### go-treesitter.py - Go AST Scanner

Deep Go analysis using [tree-sitter](https://tree-sitter.github.io/) with **per-function taint tracking** and **inter-procedural function summaries**. Covers 10 vulnerability categories: SQL Injection (database/sql, GORM, sqlx, pgx), Command Injection (exec.Command, os.StartProcess), SSTI (text/template), XSS (fmt.Fprintf, io.WriteString, template.HTML, Gin/Echo), Open Redirect, NoSQL Injection (MongoDB driver), LDAP Injection, Insecure Deserialization (gob, yaml, xml), Code Injection (reflect, plugin), and XXE.

**Taint tracking features:**
- Per-function taint scoping with multi-pass propagation
- **Inter-procedural analysis** — function summaries track param-to-return flows across calls within the same file
- Multi-framework support: net/http, Gin, Echo, Fiber, Gorilla mux, Chi
- Short variable declarations (`:=`), assignments, var declarations, range loops
- Taint-killing type conversions (`strconv.Atoi`, `strconv.ParseInt`, `net.ParseIP`, `uuid.Parse`, `filepath.Base`)
- Taint propagators (`fmt.Sprintf`, `strings.TrimSpace`, `string()`, `[]byte()`)
- Builder pattern tracking (`strings.Builder.WriteString`, `bytes.Buffer.Write`)
- Safe pattern recognition: parameterized queries, separate exec args, `html.EscapeString`, `ldap.EscapeFilter`, `filepath.Base`

```bash
pip3 install tree-sitter tree-sitter-go
python3 go-treesitter.py target/ [options]
  --output {text,json}        Output format
  -o, --output-file FILE      Save to file
  --min-severity LEVEL        CRITICAL, HIGH, MEDIUM, or LOW
  --all                       Show all confidence levels
  --config FILE               Path to .vibehunter.yml config file
```

### php-treesitter.py - PHP AST Scanner

Deep PHP analysis using [tree-sitter](https://tree-sitter.github.io/) with **per-function taint tracking**, **inter-procedural function summaries**, and sanitizer awareness. Covers 12 vulnerability categories across all major PHP sinks including phar:// deserialization, second-order deserialization, and gadget chain detection. Taint sources: `$_GET`, `$_POST`, `$_REQUEST`, `$_COOKIE`, `$_SERVER`, `$_FILES`, `$_ENV`, `file_get_contents("php://input")`, `getenv()`, and public function parameters.

```bash
pip3 install tree-sitter tree-sitter-php
python3 php-treesitter.py target/ [options]
  --output {text,json}        Output format
  -o, --output-file FILE      Save to file
  --min-severity LEVEL        CRITICAL, HIGH, MEDIUM, or LOW
  --all                       Show all confidence levels
  --config FILE               Path to .vibehunter.yml config file
```

#### Detection Quality Matrix

| Category | Sinks | Severity |
|---|---|---|
| SQL Injection | `mysql_query`, `mysqli_query`, `pg_query`, `->query()`, `->exec()`, `->prepare()` with concat | CRITICAL |
| Command Injection | `exec`, `system`, `passthru`, `shell_exec`, `popen`, `proc_open`, `pcntl_exec`, backtick | CRITICAL |
| Code Injection | `eval`, `assert`, `create_function`, `preg_replace /e` | CRITICAL |
| Insecure Deserialization | `unserialize`, `yaml_parse`, `igbinary_unserialize`, `msgpack_unpack`, `wddx_deserialize`, `json_decode` (without assoc), phar:// trigger functions | CRITICAL |
| Gadget Chain Indicators | Magic methods (`__wakeup`, `__destruct`, `__toString`, etc.) calling dangerous functions | LOW |
| XXE | `DOMDocument->loadXML/loadHTML`, `simplexml_load_string`, `XMLReader` | HIGH |
| XPath Injection | `DOMXPath->query/evaluate` | HIGH |
| SSTI | Twig `->render`/`->createTemplate`, Smarty `->fetch("string:")` | HIGH |
| NoSQL Injection | MongoDB `->find`, `->findOne`, `->aggregate`, `->count`, `->distinct`, `->deleteMany`, `->updateMany`, `->insertOne`, `->bulkWrite`, and 10+ more methods | CRITICAL |
| Second-order SQLi | DB-fetched data (`->fetch()`, `mysqli_fetch_*`, `pg_fetch_*`) in raw SQL concat | HIGH |
| Second-order Deserialization | DB-fetched data in `unserialize`, `yaml_parse`, `igbinary_unserialize`, `msgpack_unpack`, `wddx_deserialize` | HIGH |
| Phar Deserialization | Tainted paths in `file_get_contents`, `file_exists`, `fopen`, `getimagesize`, `include`/`require`, and 20+ filesystem functions | CRITICAL |

Sanitizer-aware: `intval`, `(int)` cast, `escapeshellarg`, `escapeshellcmd`, `filter_var`, `basename`, `realpath`, and more are recognized as taint-killing operations.

---

## Config File

Create a `.vibehunter.yml` in your project root to customize scanner behavior. All scanners auto-discover this file by walking up from the scan target directory.

```yaml
# Custom taint sources (appended to built-in)
sources:
  java:
    - "getCustomInput"
    - "readUntrustedData"
  php:
    - "$customGlobal"
  js:
    - "getUntrustedData"

# Custom sinks (appended to built-in, organized by category)
sinks:
  java:
    sql: ["customQuery", "rawExecute"]
    command: ["shellRun"]
  php:
    sql: ["customDbExec"]

# Custom sanitizers (appended to built-in)
sanitizers:
  java:
    universal: ["MySanitizer.clean"]
    sql: ["MyEscaper.escapeSQL"]
  php:
    universal: ["customSanitize"]

# Paths to exclude from scanning
exclude_paths:
  - "vendor/"
  - "test/"
  - "**/*_test.java"

# Inline suppression keyword (default: nosec)
suppression_keyword: "nosec"

# Minimum confidence to report (default: HIGH)
min_confidence: "HIGH"
```

Or specify a config path explicitly:

```bash
python3 vibehunter.py project/ --config /path/to/.vibehunter.yml
```

---

## CI/CD Integration

```yaml
# GitHub Actions
- name: Security Scan
  run: |
    python3 vibehunter.py . --min-confidence HIGH --output json -o results.json
    if grep -q '"severity": "CRITICAL"' results.json; then
      echo "::error::Critical vulnerabilities found!"
      exit 1
    fi
```

---

## Release Files

```
vibehunter/
├── README.md
├── vibehunter.py               # Multi-language SAST scanner (7 languages)
├── java-treesitter.py          # Java AST scanner (tree-sitter)
├── js-treesitter.py            # JavaScript AST scanner (tree-sitter)
├── php-treesitter.py           # PHP AST scanner (tree-sitter)
├── go-treesitter.py            # Go AST scanner (tree-sitter)
├── vibehunter_config.py        # YAML config file loader
└── requirements.txt
```

---

## Disclaimer

This tool is for **authorized security testing only**. Always obtain proper authorization before scanning. Verify findings manually.

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
