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

<h3 align="center">Multi-Language SAST with 2nd-Order Injection Detection</h3>

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

> **Disclaimer:** This is a **hobby/learning project** for educational purposes. It is **NOT** a replacement for professional SAST tools like [Semgrep](https://semgrep.dev/), [CodeQL](https://codeql.github.com/), [Snyk](https://snyk.io/), or [SonarQube](https://www.sonarqube.org/). Use this to learn about static analysis concepts or as a starting point for security research.

---

## Quick Start

```bash
git clone https://github.com/worldtreeboy/vulnhunter.git
cd vulnhunter
pip3 install -r requirements.txt

# Scan a project (Python, Java, JS/TS, PHP, C#, Ruby)
python3 vulnhunter.py /path/to/project

# JSON output
python3 vulnhunter.py project/ --output json -o report.json

# Java AST scanner (deeper analysis via tree-sitter)
pip3 install tree-sitter tree-sitter-java
python3 java-treesitter.py /path/to/java/project

# JavaScript AST scanner (deeper analysis via tree-sitter)
pip3 install tree-sitter tree-sitter-javascript
python3 js-treesitter.py /path/to/js/project
```

---

## Proven Results

Tested against industry-standard vulnerable applications:

| Application | Files | Critical | High | Medium | Total |
|---|:---:|:---:|:---:|:---:|:---:|
| **WebGoat (OWASP)** | 469 | 32 | 86 | 4 | **122** |
| **Damn Vulnerable RESTaurant API** | 74 | 21 | 1 | 0 | **22** |
| **Vulnerable-Flask-App** | 2 | 10 | 8 | 0 | **18** |
| **NodeGoat (OWASP)** | 39 | 3 | 5 | 4 | **12** |
| **RailsGoat (OWASP)** | 22 | 5 | 15 | 0 | **20** |
| **DVCSharp API** | 10 | 3 | 6 | 0 | **9** |
| **DVJA (Struts2)** <sup>TS</sup> | 21 | 2 | 2 | 0 | **4** |
| **TOTAL** | **637** | **76** | **123** | **12** | **207** |

<sub><sup>TS</sup> = Scanned with java-treesitter.py (AST-based scanner)</sub>

---

## What Makes VulnHunter Different?

Most SAST tools detect **1st-order injection** where user input flows directly to a sink. VulnHunter also detects **2nd-order injection** where payloads are stored in the database first, then retrieved and used unsafely later.

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
| SSRF | Yes | - | All 7 |
| SSTI | Yes | - | All 7 |
| Insecure Deserialization | Yes | Double-unserialize | All 7 |
| IDOR | Yes | - | All 7 |
| MFLAC | Yes | - | All 7 |
| Expression Language (SpEL, OGNL, MVEL, EL) | Yes | - | Java |
| Reflection Injection | Yes | - | Java |

**Not detected:** XSS (use js-treesitter.py for JS), Path Traversal, Weak Crypto, Session Fixation, Prototype Pollution (use js-treesitter.py for JS).

---

## Language Support

| Language | Extensions | Frameworks | Scanner |
|----------|------------|------------|---------|
| **Java** | `.java` | Spring, JPA/Hibernate, Struts2, Servlets | vulnhunter.py (regex) or java-treesitter.py (AST) |
| **C#** | `.cs` | ASP.NET, Entity Framework | vulnhunter.py |
| **JavaScript** | `.js`, `.jsx` | Express, Mongoose, Sequelize | vulnhunter.py (regex) or js-treesitter.py (AST) |
| **TypeScript** | `.ts`, `.tsx` | Node.js, TypeORM, NestJS | vulnhunter.py |
| **Python** | `.py` | Flask, Django, SQLAlchemy, Pandas | vulnhunter.py |
| **PHP** | `.php` | Laravel, PDO, mysqli | vulnhunter.py |
| **Ruby** | `.rb` | Rails, ActiveRecord, Sinatra | vulnhunter.py |

### Analysis Techniques

| Language | AST Taint | Regex Taint | Pattern Match | Notes |
|----------|:---------:|:-----------:|:------------:|-------|
| Python | ~60% | ~10% | ~30% | Full AST via `ast.NodeVisitor` |
| Java <sup>TS</sup> | **~85%** | - | ~15% | Tree-sitter per-method taint |
| Java | - | ~45% | ~55% | Regex-based Spring annotation analysis |
| JS/TS <sup>TS</sup> | **~85%** | - | ~15% | Tree-sitter file-level taint |
| JS/TS | - | ~30% | ~70% | Regex source-sink tracking |
| PHP | - | ~35% | ~65% | `$_GET`/`$_POST` variable tracking |
| C# | - | ~40% | ~60% | Constructor flow, LINQ taint tunnel |
| Ruby | - | ~30% | ~70% | `params[]` tracking, ActiveRecord sinks |

---

## Scanners

### vulnhunter.py - Multi-Language Scanner

The main scanner supporting all 7 languages with taint tracking, evasion detection, confidence scoring, and false positive reduction (parameterized queries, sanitization, allowlists, safe deserialization).

```bash
python3 vulnhunter.py target/ [options]
  --output {text,json}        Output format
  -o, --output-file FILE      Save to file
  --min-confidence LEVEL      HIGH, MEDIUM, or LOW
  --scan-all                  Include vendor/minified files
  -v, --verbose               Detailed output
```

### java-treesitter.py - Java AST Scanner

Deep Java analysis using [tree-sitter](https://tree-sitter.github.io/) with **per-method taint scoping**. Covers 15 vulnerability categories including JNDI injection, mass assignment, and reflection injection. Framework-agnostic (Spring, Struts2, Servlets, plain Java).

```bash
pip3 install tree-sitter tree-sitter-java
python3 java-treesitter.py target/ [options]
  --output {text,json}        Output format
  -o, --output-file FILE      Save to file
  --min-severity LEVEL        CRITICAL, HIGH, MEDIUM, or LOW
  --all                       Show all confidence levels
```

### js-treesitter.py - JavaScript AST Scanner

Deep JavaScript analysis using [tree-sitter](https://tree-sitter.github.io/) with **file-level taint tracking**. Covers 7 vulnerability categories: DOM XSS, Reflected XSS, Prototype Pollution, Dangerous Eval, Open Redirect, Path Traversal, Command Injection. Supports ES6+, Express.js, jQuery, and HTML inline scripts.

```bash
pip3 install tree-sitter tree-sitter-javascript
python3 js-treesitter.py target/ [options]
  --output {text,json}        Output format
  -o, --output-file FILE      Save to file
  --min-confidence LEVEL      HIGH, MEDIUM, or LOW
  -v, --verbose               Detailed output
```

---

## CI/CD Integration

```yaml
# GitHub Actions
- name: Security Scan
  run: |
    python3 vulnhunter.py . --min-confidence HIGH --output json -o results.json
    if grep -q '"severity": "CRITICAL"' results.json; then
      echo "::error::Critical vulnerabilities found!"
      exit 1
    fi
```

---

## Project Structure

```
vulnhunter/
├── vulnhunter.py          # Multi-language SAST scanner (7 languages)
├── java-treesitter.py     # Java AST scanner (tree-sitter)
├── js-treesitter.py       # JavaScript AST scanner (tree-sitter)
├── requirements.txt
└── test-files/            # Vulnerability test cases per language
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
