<?php

// 1. XXE (XML External Entity)
// Scanner must detect: User input passed to XML parsers.
// Attack: <!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
$xml_data = $_POST['xml'];
// VULNERABLE: LIBXML_NOENT enables entity substitution
$dom = new DOMDocument();
$dom->loadXML($xml_data, LIBXML_NOENT | LIBXML_DTDLOAD);


// 2. SSRF (Server-Side Request Forgery)
// Scanner must detect: User input controlling a URL in curl_init or file_get_contents.
// Attack: http://localhost:22 or http://169.254.169.254/latest/meta-data/
$url = $_GET['url'];
$ch = curl_init();
curl_setopt($ch, CURLOPT_URL, $url); // VULNERABLE
curl_exec($ch);


// 3. LDAP INJECTION
// Scanner must detect: User input in LDAP filters.
// Attack: *)(uid=*))(|(uid=*
$user = $_POST['user'];
$ds = ldap_connect("localhost");
// VULNERABLE: No escaping of special characters like * ( ) \ NUL
$search = ldap_search($ds, "dc=example,dc=com", "(uid=$user)");


// 4. SANITIZATION TEST (SAFE)
// Scanner must detect: intval() kills the taint.
// If your scanner flags this, it is a False Positive.
$safe_id = $_GET['id'];
$clean_id = intval($safe_id); 
$conn->query("SELECT * FROM products WHERE id = " . $clean_id); // SAFE


// 5. WRONG SANITIZATION (VULNERABLE)
// Scanner must detect: htmlspecialchars() does NOT prevent SQL Injection.
// A smart scanner knows that sanitizers are context-specific.
$name = $_POST['name'];
// This protects against XSS, but it does NOT escape single quotes for SQL.
$clean_name = htmlspecialchars($name); 
$conn->query("SELECT * FROM users WHERE username = '$clean_name'"); // VULNERABLE

?>
