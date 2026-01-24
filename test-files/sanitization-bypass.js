/**
 * Sanitization Bypass Test File - INTENTIONALLY VULNERABLE
 * Demonstrates weak sanitization patterns that can be bypassed
 */

// ==================== PATTERN 1: FIRST OCCURRENCE ONLY ====================
// .replace() without 'g' flag only removes FIRST match

function firstOccurrenceBypass(userInput) {
    // VULNERABLE: Only removes first <script>
    // Input: "<script><script>alert(1)</script></script>"
    // After: "<script>alert(1)</script></script>"
    let sanitized = userInput.replace("<script>", "");
    document.body.innerHTML = sanitized;
}


// ==================== PATTERN 2: CASE SENSITIVITY ====================
// Regex without 'i' flag can be bypassed with different case

function caseSensitiveBypass(input) {
    // VULNERABLE: <SCRIPT> or <ScRiPt> bypasses this filter
    let clean = input.replace(/<script>/g, "");
    document.getElementById('output').innerHTML = clean;
}


// ==================== PATTERN 3: INCOMPLETE TAG FILTERING ====================
// Only filtering <script> but not event handlers

function incompleteFiltering(data) {
    // VULNERABLE: <img src=x onerror=alert(1)> bypasses this
    let safe = data.replace(/<script>/gi, "").replace(/<\/script>/gi, "");
    document.body.innerHTML = safe;
}


// ==================== PATTERN 4: BLACKLIST APPROACH ====================
// Blacklist sanitization is fundamentally flawed

function blacklistBypass(input) {
    // VULNERABLE: Countless bypass vectors exist
    // <svg onload=...>, <body onpageshow=...>, <marquee onstart=...>
    if (input.includes("<script>") || input.includes("javascript:")) {
        return "blocked";
    }
    document.body.innerHTML = input;
}


// ==================== PATTERN 5: NESTED PAYLOAD ====================
// Single-pass sanitization vulnerable to nested payloads

function nestedPayloadBypass(input) {
    // VULNERABLE: "<scr<script>ipt>" becomes "<script>" after sanitization
    let sanitized = input.replace("<script>", "");
    document.body.innerHTML = sanitized;
}


// ==================== PATTERN 6: JAVASCRIPT PROTOCOL NESTING ====================
// Removing "javascript" creates new javascript: from nested input

function protocolNesting(url) {
    // VULNERABLE: "javjavascriptascript:alert(1)" becomes "javascript:alert(1)"
    let safeUrl = url.replace("javascript", "");
    location.href = safeUrl;
}


// ==================== PATTERN 7: REGEX WITHOUT GLOBAL FLAG ====================

function regexNoGlobalBypass(html) {
    // VULNERABLE: Only first match removed (no /g flag)
    let clean = html.replace(/<iframe/, "");
    document.body.innerHTML = clean;
}


// ==================== PATTERN 8: FILTER EVASION VIA ENCODING ====================

function encodingMismatch(input) {
    // VULNERABLE: Filters HTML entities but input is raw
    let filtered = input.replace("&lt;script&gt;", "");
    // If input is "<script>", it bypasses the entity filter
    document.body.innerHTML = filtered;
}


// ==================== PATTERN 9: DOUBLE ENCODING NEEDED ====================
// URL decoding creates XSS after sanitization

function doubleEncodingBypass(param) {
    // VULNERABLE: %3Cscript%3E after decoding becomes <script>
    let decoded = decodeURIComponent(param);
    // Sanitization happens BEFORE full decoding
    document.body.innerHTML = decoded;
}


// ==================== PATTERN 10: PROTOTYPE POLLUTION TO XSS ====================
// Polluting prototype can override sanitization or inject XSS

function prototypePollutionXSS(userConfig) {
    // VULNERABLE: userConfig could contain __proto__
    Object.assign({}, userConfig);

    // If __proto__.innerHTML is set, it affects all elements
    document.body.innerHTML = "Safe content";
}


// ==================== PATTERN 11: MUTATION XSS ====================
// Browser DOM mutation can recreate XSS after sanitization

function mutationXSS(input) {
    // VULNERABLE: <noscript><img src=x onerror=alert(1)></noscript>
    // Some browsers parse <noscript> content differently in innerHTML context
    let div = document.createElement('div');
    div.innerHTML = input.replace(/<script>/gi, "");
    document.body.appendChild(div);
}


// ==================== PATTERN 12: NULL BYTE INJECTION ====================

function nullByteBypass(input) {
    // VULNERABLE in some contexts: <scr\x00ipt>
    let clean = input.replace(/<script>/gi, "");
    document.body.innerHTML = clean;
}


// ==================== SAFE PATTERNS (for comparison) ====================

function properSanitization(input) {
    // SAFE: Using DOMPurify or similar trusted library
    // let clean = DOMPurify.sanitize(input);

    // SAFE: Using textContent instead of innerHTML
    document.getElementById('output').textContent = input;

    // SAFE: Proper encoding
    const encoded = input
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#x27;');
}
