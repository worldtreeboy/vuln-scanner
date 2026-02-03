// ============================================================================
// jshunter.py FALSE POSITIVE / FALSE NEGATIVE test suite
// Each case is marked:
//   [FP-xxx] = False Positive – scanner should NOT flag this
//   [FN-xxx] = False Negative – scanner SHOULD flag this (may be missed)
//   [TP-xxx] = True Positive  – scanner SHOULD flag this (baseline check)
// ============================================================================

const express = require('express');
const app = express();
const fs = require('fs');
const { exec, execSync, spawn } = require('child_process');
const path = require('path');

// ============================================================================
// SECTION 1: DOM XSS – FALSE POSITIVES (safe patterns)
// ============================================================================

// [FP-001] textContent is a safe sink – no XSS possible
function safeTextContent() {
    const userInput = location.hash.slice(1);
    document.getElementById('output').textContent = userInput;
}

// [FP-002] innerText is a safe sink
function safeInnerText() {
    const q = new URLSearchParams(location.search).get('q');
    document.getElementById('search').innerText = q;
}

// [FP-003] DOMPurify.sanitize() before innerHTML
function safeDOMPurify() {
    const dirty = location.hash.slice(1);
    document.body.innerHTML = DOMPurify.sanitize(dirty);
}

// [FP-004] encodeURIComponent before location.href assignment
function safeEncodedRedirect() {
    const target = location.hash.slice(1);
    location.href = '/safe?q=' + encodeURIComponent(target);
}

// [FP-005] res.json() is safe – JSON content-type prevents XSS
app.get('/api/safe-json', (req, res) => {
    const name = req.query.name;
    res.json({ greeting: `Hello ${name}` });
});

// [FP-006] Static hardcoded string to innerHTML
function staticInnerHTML() {
    document.body.innerHTML = '<h1>Welcome</h1>';
}

// [FP-007] parseInt-validated input to eval (numeric only)
function safeEvalNumeric() {
    const raw = location.hash.slice(1);
    const num = parseInt(raw, 10);
    if (isNaN(num)) return;
    eval(num);
}

// [FP-008] createElement + textContent (safe DOM construction)
function safeDOMCreate() {
    const input = location.search;
    const el = document.createElement('div');
    el.textContent = input;
    document.body.appendChild(el);
}

// [FP-009] setAttribute with safe attribute (class, id)
function safeSetAttribute() {
    const cls = location.hash.slice(1);
    document.getElementById('box').setAttribute('class', cls);
}

// [FP-010] Strict allowlist validation before redirect
function safeAllowlistRedirect() {
    const target = req.query.redirect;
    const allowed = ['/home', '/dashboard', '/profile'];
    if (allowed.includes(target)) {
        location.href = target;
    }
}

// [FP-011] Template literal with no user input
function safeLiteralTemplate() {
    const greeting = 'World';
    document.body.innerHTML = `<h1>Hello ${greeting}</h1>`;
}

// [FP-012] res.send() with static content
app.get('/static', (req, res) => {
    res.send('<h1>Hello World</h1>');
});

// [FP-013] escapeHtml custom function wrapping output
function safeEscapedOutput() {
    const input = location.hash;
    document.body.innerHTML = escapeHtml(input);
}

// [FP-014] htmlEncode before insertion
function safeHtmlEncode() {
    const input = document.referrer;
    document.getElementById('ref').innerHTML = htmlEncode(input);
}

// [FP-015] sanitizeHtml library usage
function safeSanitizeHtml() {
    const data = req.body.content;
    res.send(sanitizeHtml(data));
}

// ============================================================================
// SECTION 2: PROTOTYPE POLLUTION – FALSE POSITIVES (safe merge)
// ============================================================================

// [FP-016] for-in with hasOwnProperty guard
function safeMerge(target, source) {
    for (let key in source) {
        if (source.hasOwnProperty(key)) {
            target[key] = source[key];
        }
    }
    return target;
}

// [FP-017] for-in with Object.hasOwn guard
function safeMergeModern(target, source) {
    for (const key in source) {
        if (Object.hasOwn(source, key)) {
            target[key] = source[key];
        }
    }
    return target;
}

// [FP-018] Object.keys iteration (no __proto__ leak)
function safeObjectKeys(target, source) {
    Object.keys(source).forEach(key => {
        target[key] = source[key];
    });
    return target;
}

// [FP-019] Object.create(null) – null prototype, no pollution
function safeNullProto() {
    const obj = Object.create(null);
    obj.key = 'value';
    return obj;
}

// [FP-020] for-in with explicit __proto__ skip
function safeForInSkip(target, source) {
    for (let key in source) {
        if (key === '__proto__') continue;
        target[key] = source[key];
    }
}

// [FP-021] Map instead of plain object (immune to PP)
function safeMapUsage(userInput) {
    const store = new Map();
    store.set(userInput.key, userInput.value);
    return store;
}

// ============================================================================
// SECTION 3: PATH TRAVERSAL – FALSE POSITIVES
// ============================================================================

// [FP-022] path.join with path.basename strips traversal
app.get('/safe-file', (req, res) => {
    const filename = path.basename(req.query.file);
    const filePath = path.join(__dirname, 'uploads', filename);
    fs.readFile(filePath, 'utf8', (err, data) => res.send(data));
});

// [FP-023] Regex validation of filename chars
app.get('/safe-file2', (req, res) => {
    const file = req.params.name;
    if (!/^[a-zA-Z0-9_-]+\.(txt|pdf)$/.test(file)) return res.status(400).end();
    fs.readFileSync(path.join('/safe', file));
});

// [FP-024] Hardcoded path – no user input
function readConfig() {
    return fs.readFileSync('/etc/app/config.json', 'utf8');
}

// ============================================================================
// SECTION 4: COMMAND INJECTION – FALSE POSITIVES
// ============================================================================

// [FP-025] exec with hardcoded command
function safeSysInfo() {
    exec('uname -a', (err, stdout) => console.log(stdout));
}

// [FP-026] spawn with array args (no shell)
function safeSpawn(filename) {
    spawn('convert', ['-resize', '100x100', filename, 'out.png']);
}

// [FP-027] execSync with static command
function safePing() {
    return execSync('ping -c 1 127.0.0.1').toString();
}

// ============================================================================
// SECTION 5: REFLECTED XSS – FALSE POSITIVES
// ============================================================================

// [FP-028] res.send with Content-Type set to text/plain
app.get('/safe-text', (req, res) => {
    const name = req.query.name;
    res.type('text/plain').send(name);
});

// [FP-029] res.render with auto-escaping template engine
app.get('/safe-render', (req, res) => {
    res.render('profile', { name: req.query.name });
});

// [FP-030] Response with status code only
app.get('/safe-status', (req, res) => {
    const id = req.params.id;
    res.status(id ? 200 : 404).end();
});

// ============================================================================
// SECTION 6: DOM XSS – TRUE POSITIVES (baseline checks)
// ============================================================================

// [TP-001] Classic location.hash to innerHTML
function tpHashToInnerHTML() {
    const data = location.hash.slice(1);
    document.getElementById('out').innerHTML = data;
}

// [TP-002] document.URL to document.write
function tpURLToWrite() {
    const url = document.URL;
    document.write('<a href="' + url + '">link</a>');
}

// [TP-003] location.search via URLSearchParams to innerHTML
function tpSearchParam() {
    const q = new URLSearchParams(location.search).get('q');
    document.body.innerHTML = q;
}

// [TP-004] window.name to eval
function tpWindowNameEval() {
    const payload = window.name;
    eval(payload);
}

// [TP-005] document.referrer to outerHTML
function tpReferrerOuter() {
    const ref = document.referrer;
    document.getElementById('x').outerHTML = ref;
}

// [TP-006] postMessage data to innerHTML
window.addEventListener('message', function(e) {
    document.body.innerHTML = e.data;
});

// [TP-007] cookie to document.write
function tpCookieWrite() {
    const c = document.cookie;
    document.write('<p>' + c + '</p>');
}

// [TP-008] req.query to res.send – reflected XSS
app.get('/vuln', (req, res) => {
    res.send('<h1>' + req.query.name + '</h1>');
});

// [TP-009] req.body to res.send via template literal
app.post('/vuln2', (req, res) => {
    res.send(`<div>${req.body.comment}</div>`);
});

// [TP-010] req.params to fs.readFile – path traversal
app.get('/file/:name', (req, res) => {
    fs.readFile('/uploads/' + req.params.name, (err, data) => res.send(data));
});

// [TP-011] req.query to exec – command injection
app.get('/run', (req, res) => {
    exec('ls ' + req.query.dir, (err, out) => res.send(out));
});

// [TP-012] req.body to eval – code injection
app.post('/calc', (req, res) => {
    const result = eval(req.body.expression);
    res.json({ result });
});

// ============================================================================
// SECTION 7: DOM XSS – FALSE NEGATIVES (tricky patterns)
// ============================================================================

// [FN-001] Taint through ternary operator
function fnTernaryTaint() {
    const raw = location.hash.slice(1);
    const data = raw ? raw : 'default';
    document.body.innerHTML = data;
}

// [FN-002] Taint through array destructuring
function fnArrayDestructTaint() {
    const parts = location.search.split('&');
    const [first, second] = parts;
    document.body.innerHTML = first;
}

// [FN-003] Taint through object destructuring with rename
function fnObjectDestructRename() {
    const { name: username } = req.query;
    res.send(`<p>${username}</p>`);
}

// [FN-004] Taint through string concatenation chain
function fnConcatChain() {
    const base = location.hash;
    const step1 = 'prefix' + base;
    const step2 = step1 + 'suffix';
    const step3 = '<div>' + step2 + '</div>';
    document.body.innerHTML = step3;
}

// [FN-005] Taint through template literal nesting
function fnNestedTemplate() {
    const user = req.query.user;
    const greeting = `Hello ${user}`;
    const html = `<div>${greeting}</div>`;
    res.send(html);
}

// [FN-006] Taint through array .join()
function fnArrayJoin() {
    const parts = [req.query.a, '<br>', req.query.b];
    const html = parts.join('');
    res.send(html);
}

// [FN-007] Taint through .replace() – still tainted
function fnReplaceTaint() {
    const raw = location.hash.slice(1);
    const processed = raw.replace(/\s/g, '-');
    document.body.innerHTML = processed;
}

// [FN-008] Taint through .toLowerCase()
function fnToLowerCase() {
    const input = location.search.substring(1);
    const lower = input.toLowerCase();
    document.body.innerHTML = lower;
}

// [FN-009] Taint through .split().join() round-trip
function fnSplitJoinRoundTrip() {
    const raw = location.hash;
    const tokens = raw.split('/');
    const rebuilt = tokens.join('/');
    document.body.innerHTML = rebuilt;
}

// [FN-010] Taint through spread into new array
function fnSpreadArray() {
    const items = [location.hash];
    const copy = [...items];
    document.body.innerHTML = copy[0];
}

// [FN-011] Taint through Object.assign
function fnObjectAssign() {
    const data = { content: location.hash };
    const merged = Object.assign({}, data);
    document.body.innerHTML = merged.content;
}

// [FN-012] Taint through Promise .then() chain
function fnPromiseTaint() {
    fetch('/api/data')
        .then(r => r.text())
        .then(data => {
            document.body.innerHTML = data;
        });
}

// [FN-013] Taint through async/await
async function fnAsyncTaint() {
    const resp = await fetch('/api/data');
    const html = await resp.text();
    document.body.innerHTML = html;
}

// [FN-014] Taint through .map() transformation
app.get('/fn14', (req, res) => {
    const names = req.body.names;
    const items = names.map(n => `<li>${n}</li>`);
    res.send(`<ul>${items.join('')}</ul>`);
});

// [FN-015] Taint through .reduce() accumulator
function fnReduceTaint() {
    const parts = [location.hash, location.search];
    const combined = parts.reduce((acc, p) => acc + p, '');
    document.body.innerHTML = combined;
}

// [FN-016] Taint through closure variable
function fnClosureTaint() {
    const dirty = location.hash;
    function render() {
        document.body.innerHTML = dirty;
    }
    render();
}

// [FN-017] Taint through callback parameter
function fnCallbackTaint() {
    fetchData(location.hash, function(result) {
        document.body.innerHTML = result;
    });
}

// [FN-018] Taint through += augmented assignment
function fnAugmentedAssign() {
    let html = '<div>';
    html += location.hash;
    html += '</div>';
    document.body.innerHTML = html;
}

// [FN-019] Taint through conditional assignment (||)
function fnOrAssign() {
    const val = location.hash || '';
    document.body.innerHTML = val;
}

// [FN-020] Taint through .toString() call
function fnToStringTaint() {
    const raw = location.search;
    const str = raw.toString();
    document.body.innerHTML = str;
}

// ============================================================================
// SECTION 8: PROTOTYPE POLLUTION – FALSE NEGATIVES
// ============================================================================

// [FN-021] Computed property from function parameter
function fnParamKey(key, value) {
    const obj = {};
    obj[key] = value;  // key could be __proto__
    return obj;
}

// [FN-022] Nested property setting via bracket chain
function fnNestedBracket(obj, path, value) {
    const keys = path.split('.');
    let current = obj;
    for (let i = 0; i < keys.length - 1; i++) {
        current = current[keys[i]];
    }
    current[keys[keys.length - 1]] = value;
}

// [FN-023] Object.defineProperty with user key
function fnDefineProperty(obj, userKey) {
    Object.defineProperty(obj, userKey, {
        value: 'pwned',
        writable: true
    });
}

// [FN-024] Reflect.set with tainted key
function fnReflectSet(target, key, value) {
    Reflect.set(target, key, value);
}

// [FN-025] Array.reduce building object with user keys
function fnReducePolluton(pairs) {
    return pairs.reduce((obj, [key, val]) => {
        obj[key] = val;
        return obj;
    }, {});
}

// [FN-026] JSON.parse output in for-in without guard
function fnJsonParseForIn(jsonStr) {
    const data = JSON.parse(jsonStr);
    const target = {};
    for (let key in data) {
        target[key] = data[key];
    }
}

// [FN-027] Spread of user-controlled object
function fnSpreadPollution(userObj) {
    const config = { ...userObj, admin: false };
    return config;
}

// [FN-028] Object.setPrototypeOf with user input
function fnSetPrototypeOf(obj, proto) {
    Object.setPrototypeOf(obj, proto);
}

// ============================================================================
// SECTION 9: COMMAND INJECTION – FALSE NEGATIVES
// ============================================================================

// [FN-029] exec via template literal with req.query
app.get('/fn29', (req, res) => {
    exec(`grep -r "${req.query.pattern}" /var/log/`, (err, out) => {
        res.send(out);
    });
});

// [FN-030] execSync with string concat
app.post('/fn30', (req, res) => {
    const out = execSync('find /tmp -name ' + req.body.filename);
    res.send(out.toString());
});

// [FN-031] spawn with shell: true option
app.get('/fn31', (req, res) => {
    spawn('echo', [req.query.msg], { shell: true });
});

// [FN-032] Taint through variable to exec
app.get('/fn32', (req, res) => {
    const cmd = 'cat ' + req.query.file;
    exec(cmd, (err, out) => res.send(out));
});

// ============================================================================
// SECTION 10: PATH TRAVERSAL – FALSE NEGATIVES
// ============================================================================

// [FN-033] fs.readFile with concatenated user path
app.get('/fn33', (req, res) => {
    fs.readFile('/data/' + req.query.path, (err, data) => res.send(data));
});

// [FN-034] fs.createReadStream with user input
app.get('/fn34', (req, res) => {
    const stream = fs.createReadStream(req.query.filepath);
    stream.pipe(res);
});

// [FN-035] writeFile with user-controlled path
app.post('/fn35', (req, res) => {
    fs.writeFile(req.body.path, req.body.content, () => res.end());
});

// [FN-036] unlink with user path
app.delete('/fn36', (req, res) => {
    fs.unlink(req.query.file, () => res.json({ deleted: true }));
});

// ============================================================================
// SECTION 11: OPEN REDIRECT – FALSE NEGATIVES
// ============================================================================

// [FN-037] location.assign with user URL
function fnLocationAssign() {
    const url = new URLSearchParams(location.search).get('next');
    location.assign(url);
}

// [FN-038] location.replace with user URL
function fnLocationReplace() {
    const next = location.hash.slice(1);
    location.replace(next);
}

// [FN-039] window.open with user URL
function fnWindowOpen() {
    const target = new URLSearchParams(location.search).get('url');
    window.open(target);
}

// [FN-040] location.href via req.query
app.get('/fn40', (req, res) => {
    res.send(`<script>location.href="${req.query.next}"</script>`);
});

// ============================================================================
// SECTION 12: DANGEROUS EVAL – FALSE NEGATIVES
// ============================================================================

// [FN-041] new Function() with user input
function fnFunctionConstructor() {
    const code = location.hash.slice(1);
    const fn = new Function(code);
    fn();
}

// [FN-042] setTimeout with string argument from user
function fnSetTimeoutString() {
    const action = location.hash.slice(1);
    setTimeout(action, 1000);
}

// [FN-043] setInterval with tainted string
function fnSetIntervalString() {
    const code = new URLSearchParams(location.search).get('code');
    setInterval(code, 5000);
}

// [FN-044] eval through variable hop
function fnEvalHop() {
    const raw = location.search.substring(1);
    const parsed = decodeURIComponent(raw);
    eval(parsed);
}

// ============================================================================
// SECTION 13: REFLECTED XSS – FALSE NEGATIVES (multi-hop taint)
// ============================================================================

// [FN-045] Taint through helper function
function buildGreeting(name) {
    return '<h1>Hello ' + name + '</h1>';
}
app.get('/fn45', (req, res) => {
    const html = buildGreeting(req.query.name);
    res.send(html);
});

// [FN-046] Taint through destructured body with spread
app.post('/fn46', (req, res) => {
    const { title, ...rest } = req.body;
    res.send(`<h1>${title}</h1><pre>${JSON.stringify(rest)}</pre>`);
});

// [FN-047] Taint through .concat()
app.get('/fn47', (req, res) => {
    const prefix = '<div>';
    const html = prefix.concat(req.query.content, '</div>');
    res.send(html);
});

// [FN-048] Taint through ternary to send
app.get('/fn48', (req, res) => {
    const msg = req.query.msg ? req.query.msg : 'default';
    res.send(`<p>${msg}</p>`);
});

// [FN-049] Taint through multiple assignments
app.get('/fn49', (req, res) => {
    let data = req.query.input;
    let processed = data;
    let final = processed;
    res.send(`<span>${final}</span>`);
});

// [FN-050] Taint through array index access
app.get('/fn50', (req, res) => {
    const items = [req.query.a, req.query.b];
    res.send(`<p>${items[0]}</p>`);
});

// ============================================================================
// SECTION 14: MIXED – EDGE CASES
// ============================================================================

// [FP-031] JSON.stringify output is safe (encoded)
function safeJSONStringify() {
    const data = location.hash;
    document.body.innerHTML = JSON.stringify(data);
}

// [FP-032] Number() coercion makes input safe
function safeNumberCoercion() {
    const raw = location.search.substring(1);
    const num = Number(raw);
    document.body.innerHTML = num;
}

// [FP-033] Boolean check – no taint to sink
function safeBooleanCheck() {
    const exists = !!location.hash;
    document.body.innerHTML = exists ? 'yes' : 'no';
}

// [FP-034] typeof check – no taint to sink
function safeTypeofCheck() {
    const t = typeof location.hash;
    document.body.innerHTML = t;
}

// [FP-035] Regex .test() result is boolean – safe
function safeRegexTest() {
    const input = location.hash;
    const isValid = /^[a-z]+$/.test(input);
    document.body.innerHTML = isValid.toString();
}

// [FN-051] insertAdjacentHTML with tainted data
function fnInsertAdjacent() {
    const html = location.hash.slice(1);
    document.body.insertAdjacentHTML('beforeend', html);
}

// [FN-052] jQuery .html() with tainted data
function fnJQueryHtml() {
    const data = location.hash.slice(1);
    $('#output').html(data);
}

// [FN-053] jQuery .append() with tainted data
function fnJQueryAppend() {
    const data = location.search;
    $('#container').append(data);
}

// [FN-054] srcdoc attribute with tainted data
function fnSrcdoc() {
    const content = location.hash.slice(1);
    document.querySelector('iframe').srcdoc = content;
}

// [FN-055] document.writeln with tainted data
function fnWriteln() {
    const data = document.referrer;
    document.writeln(data);
}

// [FP-036] Lodash merge with safe static objects
function safeLodashMerge() {
    const defaults = { color: 'blue', size: 10 };
    const custom = { color: 'red' };
    _.merge(defaults, custom);
}

// [FP-037] for-in on Object.keys result (safe)
function safeForInKeys(source) {
    const keys = Object.keys(source);
    const target = {};
    for (let i = 0; i < keys.length; i++) {
        target[keys[i]] = source[keys[i]];
    }
}

// [FN-056] sessionStorage to innerHTML (2nd order)
function fnStorageXSS() {
    const saved = sessionStorage.getItem('profile');
    document.body.innerHTML = saved;
}

// [FN-057] localStorage to eval (2nd order)
function fnStorageEval() {
    const code = localStorage.getItem('script');
    eval(code);
}

// [FN-058] fetch response to innerHTML (2nd order)
async function fnFetchToInnerHTML() {
    const resp = await fetch('/api/user');
    const data = await resp.json();
    document.getElementById('bio').innerHTML = data.bio;
}

// [FN-059] Taint through .slice()
function fnSliceTaint() {
    const raw = location.hash;
    const sliced = raw.slice(1, 50);
    document.body.innerHTML = sliced;
}

// [FN-060] Taint through .substring()
function fnSubstringTaint() {
    const raw = location.search;
    const sub = raw.substring(1);
    document.body.innerHTML = sub;
}

// [FP-038] res.redirect() is not a direct XSS sink (framework handles encoding)
app.get('/safe-redirect', (req, res) => {
    res.redirect('/login');
});

// [FP-039] Console.log with tainted data – no security impact
function safeConsoleLog() {
    const input = location.hash;
    console.log('User input:', input);
}

// [FP-040] alert() with tainted data – not a real XSS sink in code review
function safeAlert() {
    const msg = location.hash;
    alert(msg);
}
