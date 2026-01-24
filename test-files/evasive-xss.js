/**
 * Evasive DOM XSS Test File - INTENTIONALLY VULNERABLE
 * Advanced patterns that bypass simple AST analysis
 */

// ==================== PATTERN 1: SHADOW PROTOCOL ====================
// Uses sessionStorage, setTimeout, computed property access, and prototype descriptors

(function shadowProtocol() {
    // 1. DATA SOURCE HIDDEN IN STORAGE
    const source = sessionStorage.getItem('debug_state') || new URLSearchParams(window.location.search).get('cfg');

    // 2. INDIRECT SINK VIA EVENT LOOPS
    setTimeout(() => {

        // 3. COMPUTED MEMBER ACCESS
        const p1 = "inn";
        const p2 = "erHT";
        const p3 = "ML";
        const sink = p1 + p2 + p3;

        // 4. FUNCTIONAL ABSTRACTION
        const target = document.querySelector('#app');

        // Prototype descriptor abuse
        Object.getOwnPropertyDescriptor(Element.prototype, sink).set.call(target, source);

    }, 0);
})();


// ==================== PATTERN 2: ARRAY-JOIN TAINT TUNNEL ====================
// Hides taint in array, uses array indices to build sink name

(function arrayTunnel() {
    const fragments = [
        new URLSearchParams(window.location.search).get('xss'), // [0] The Taint
        "inner",                                               // [1]
        "HTML"                                                 // [2]
    ];

    // Scanner sees array index access, not dangerous sink
    const sinkName = fragments[1] + fragments[2];
    const payload = fragments[0];

    const d = document;
    const body = d.body;

    // Dynamic property access hides innerHTML
    body[sinkName] = payload;
})();


// ==================== PATTERN 3: ENCODED CONSTRUCTOR ====================
// Uses String.fromCharCode to build strings, aliases eval

const _0x5f21 = [105, 110, 110, 101, 114, 72, 84, 77, 76]; // "innerHTML" in ASCII
const _0x9922 = [101, 118, 97, 108];                      // "eval" in ASCII

// Helper to turn numbers into strings
const decode = (arr) => arr.map(c => String.fromCharCode(c)).join('');

// Alias 'eval' to something innocent
const run = window[decode(_0x9922)];

const sink = decode(_0x5f21);
const data = new URL(location).searchParams.get('q');

// Aliased eval with template literal injection
run(`document.body.${sink} = "${data}"`);


// ==================== PATTERN 4: INDIRECT GLOBAL ACCESS ====================
// Access eval through global object with computed property

(function indirectGlobal() {
    const g = (function(){return this})() || globalThis;
    const fn = "ev" + "al";
    const code = location.hash.substring(1);

    // Indirect eval invocation
    g[fn](code);
})();


// ==================== PATTERN 5: PROMISE-BASED ASYNC TAINT ====================
// Uses Promise chain to break taint tracking

(function promiseEvasion() {
    const userInput = localStorage.getItem('payload');

    Promise.resolve(userInput)
        .then(data => {
            const elem = document.getElementById('target');
            elem.innerHTML = data;
        });
})();


// ==================== PATTERN 6: REQUESTANIMATIONFRAME EVASION ====================

(function rafEvasion() {
    const malicious = window.name;

    requestAnimationFrame(() => {
        document.body.outerHTML = malicious;
    });
})();


// ==================== PATTERN 7: QUEUEMICROTASK EVASION ====================

(function microtaskEvasion() {
    const payload = document.referrer;

    queueMicrotask(() => {
        const target = document.querySelector('.content');
        target.insertAdjacentHTML('beforeend', payload);
    });
})();


// ==================== PATTERN 8: SETTER REFLECTION ====================
// Uses Reflect API to invoke setter

(function reflectEvasion() {
    const prop = ['inner', 'HTML'].join('');
    const value = new URLSearchParams(location.search).get('inject');
    const elem = document.body;

    // Reflect.set bypasses direct innerHTML detection
    Reflect.set(elem, prop, value);
})();
