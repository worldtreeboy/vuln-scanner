<?php
/**
 * Comprehensive False Positive / False Negative test suite for php-treesitter.py
 *
 * Naming convention:
 *   FP_*  = False Positive test  — safe code, scanner must NOT flag
 *   FN_*  = False Negative test  — vulnerable code, scanner MUST flag
 *
 * Each function is annotated with:
 *   @expect VULN <category>   — scanner MUST produce a finding
 *   @expect SAFE              — scanner must NOT produce a finding
 */

// ============================================================================
// 1. SQL INJECTION
// ============================================================================

class SQLInjectionTests {

    // ---- FALSE POSITIVES (safe code — must NOT flag) ----

    /** @expect SAFE — parameterized query with ? placeholders */
    public function FP_sqli_prepared_pdo($pdo) {
        $id = $_GET["id"];
        $stmt = $pdo->prepare("SELECT * FROM users WHERE id = ?");
        $stmt->execute([$id]);
        return $stmt->fetchAll();
    }

    /** @expect SAFE — named parameters :id */
    public function FP_sqli_named_params($pdo) {
        $name = $_POST["name"];
        $stmt = $pdo->prepare("SELECT * FROM users WHERE name = :name");
        $stmt->execute(['name' => $name]);
        return $stmt->fetchAll();
    }

    /** @expect SAFE — hardcoded query string, no taint */
    public function FP_sqli_hardcoded_query($pdo) {
        $result = $pdo->query("SELECT * FROM users WHERE active = 1");
        return $result;
    }

    /** @expect SAFE — string concat but NO tainted variable */
    public function FP_sqli_safe_concat($pdo) {
        $table = "users";
        $query = "SELECT * FROM " . $table . " WHERE 1=1";
        $pdo->query($query);
    }

    /** @expect SAFE — mysqli with hardcoded query */
    public function FP_sqli_mysqli_hardcoded($conn) {
        $result = mysqli_query($conn, "SELECT COUNT(*) FROM logs");
        return $result;
    }

    /** @expect SAFE — intval() cast sanitizes the input */
    public function FP_sqli_intval_sanitized($pdo) {
        $id = intval($_GET["id"]);
        $pdo->query("SELECT * FROM users WHERE id = " . $id);
    }

    /** @expect SAFE — (int) cast sanitizes the input */
    public function FP_sqli_int_cast($conn) {
        $id = (int)$_GET["id"];
        mysqli_query($conn, "SELECT * FROM users WHERE id = " . $id);
    }

    /** @expect SAFE — pg_query_params is parameterized */
    public function FP_sqli_pg_query_params($conn) {
        $name = $_GET["name"];
        $result = pg_query_params($conn, "SELECT * FROM users WHERE name = $1", [$name]);
        return $result;
    }

    /** @expect SAFE — private method, params should not be tainted */
    private function FP_sqli_private_helper($query) {
        // Private methods' parameters are not tainted
        return "SELECT * FROM " . $query;
    }

    /** @expect SAFE — query built from constants only */
    public function FP_sqli_constant_only($pdo) {
        $columns = "id, name, email";
        $table = "users";
        $query = "SELECT " . $columns . " FROM " . $table;
        $pdo->query($query);
    }

    // ---- FALSE NEGATIVES (vulnerable code — MUST flag) ----

    /** @expect VULN SQL Injection — direct superglobal in mysql_query */
    public function FN_sqli_direct_superglobal($conn) {
        mysql_query("SELECT * FROM users WHERE id = " . $_GET["id"]);
    }

    /** @expect VULN SQL Injection — tainted var two hops away */
    public function FN_sqli_taint_chain($pdo) {
        $raw = $_POST["search"];
        $term = $raw;
        $query = "SELECT * FROM products WHERE name LIKE '%" . $term . "%'";
        $pdo->query($query);
    }

    /** @expect VULN SQL Injection — sprintf with tainted input */
    public function FN_sqli_sprintf($pdo) {
        $id = $_GET["id"];
        $query = sprintf("SELECT * FROM users WHERE id = %s", $id);
        $pdo->query($query);
    }

    /** @expect VULN SQL Injection — tainted in pg_query */
    public function FN_sqli_pg_query($conn) {
        $table = $_GET["table"];
        pg_query($conn, "SELECT * FROM " . $table);
    }

    /** @expect VULN SQL Injection — tainted concat in prepare (defeats parameterization) */
    public function FN_sqli_prepare_concat($pdo) {
        $order = $_GET["order"];
        $stmt = $pdo->prepare("SELECT * FROM users ORDER BY " . $order);
        $stmt->execute();
    }

    /** @expect VULN SQL Injection — tainted data in ->exec() */
    public function FN_sqli_pdo_exec($pdo) {
        $table = $_GET["table"];
        $pdo->exec("DROP TABLE " . $table);
    }

    /** @expect VULN SQL Injection — multi-line concat */
    public function FN_sqli_multiline($conn) {
        $where = $_POST["filter"];
        $sql = "SELECT * FROM orders "
             . "WHERE status = 'active' "
             . "AND " . $where;
        mysqli_query($conn, $sql);
    }

    /** @expect VULN SQL Injection — getenv() taint source */
    public function FN_sqli_getenv($pdo) {
        $dbName = getenv("USER_DB");
        $pdo->query("SELECT * FROM " . $dbName . ".users");
    }

    /** @expect VULN SQL Injection — $_REQUEST superglobal */
    public function FN_sqli_request($conn) {
        $id = $_REQUEST["id"];
        mysqli_query($conn, "SELECT * FROM users WHERE id = " . $id);
    }

    /** @expect VULN SQL Injection — $_COOKIE taint source */
    public function FN_sqli_cookie($pdo) {
        $token = $_COOKIE["session_token"];
        $pdo->query("SELECT * FROM sessions WHERE token = '" . $token . "'");
    }

    /** @expect VULN SQL Injection — sqlite_query */
    public function FN_sqli_sqlite($db) {
        $name = $_GET["name"];
        sqlite_query($db, "SELECT * FROM users WHERE name = '" . $name . "'");
    }

    /** @expect VULN SQL Injection — file_get_contents php://input as taint source */
    public function FN_sqli_php_input($pdo) {
        $body = file_get_contents("php://input");
        $data = json_decode($body, true);
        $name = $data["name"];
        $pdo->query("SELECT * FROM users WHERE name = '" . $name . "'");
    }
}


// ============================================================================
// 2. COMMAND INJECTION
// ============================================================================

class CommandInjectionTests {

    // ---- FALSE POSITIVES ----

    /** @expect SAFE — hardcoded command, no taint */
    public function FP_cmdi_hardcoded() {
        system("ls -la /var/log");
    }

    /** @expect SAFE — escapeshellarg sanitized */
    public function FP_cmdi_escapeshellarg() {
        $file = $_GET["file"];
        $safe = escapeshellarg($file);
        exec("cat " . $safe);
    }

    /** @expect SAFE — escapeshellcmd sanitized */
    public function FP_cmdi_escapeshellcmd() {
        $cmd = $_POST["cmd"];
        $safe = escapeshellcmd($cmd);
        system($safe);
    }

    /** @expect SAFE — private method, no taint on params */
    private function FP_cmdi_private($cmd) {
        exec($cmd);
    }

    /** @expect SAFE — constant string in exec */
    public function FP_cmdi_constant() {
        exec("whoami");
        system("date");
        passthru("uptime");
    }

    // ---- FALSE NEGATIVES ----

    /** @expect VULN Command Injection — direct $_GET in system() */
    public function FN_cmdi_system() {
        $cmd = $_GET["cmd"];
        system($cmd);
    }

    /** @expect VULN Command Injection — concat with tainted in exec */
    public function FN_cmdi_exec_concat() {
        $host = $_POST["host"];
        exec("ping -c 3 " . $host);
    }

    /** @expect VULN Command Injection — passthru */
    public function FN_cmdi_passthru() {
        $arg = $_REQUEST["arg"];
        passthru("ls " . $arg);
    }

    /** @expect VULN Command Injection — shell_exec */
    public function FN_cmdi_shell_exec() {
        $dir = $_GET["dir"];
        shell_exec("find " . $dir . " -type f");
    }

    /** @expect VULN Command Injection — popen */
    public function FN_cmdi_popen() {
        $file = $_POST["file"];
        $handle = popen("cat " . $file, "r");
        fclose($handle);
    }

    /** @expect VULN Command Injection — proc_open */
    public function FN_cmdi_proc_open() {
        $cmd = $_GET["command"];
        $process = proc_open($cmd, [], $pipes);
    }

    /** @expect VULN Command Injection — pcntl_exec */
    public function FN_cmdi_pcntl_exec() {
        $bin = $_POST["binary"];
        pcntl_exec($bin);
    }

    /** @expect VULN Command Injection — taint chain through variable */
    public function FN_cmdi_chain() {
        $input = $_GET["input"];
        $cmd = "grep " . $input . " /var/log/syslog";
        system($cmd);
    }

    /** @expect VULN Command Injection — backtick operator */
    public function FN_cmdi_backtick() {
        $host = $_GET["host"];
        $out = `nslookup $host`;
        echo $out;
    }

    /** @expect VULN Command Injection — $_SERVER taint source */
    public function FN_cmdi_server() {
        $uri = $_SERVER["REQUEST_URI"];
        exec("echo " . $uri . " >> /var/log/access.log");
    }
}


// ============================================================================
// 3. CODE INJECTION
// ============================================================================

class CodeInjectionTests {

    // ---- FALSE POSITIVES ----

    /** @expect SAFE — eval with hardcoded string */
    public function FP_codei_eval_hardcoded() {
        eval('$x = 1 + 2;');
    }

    /** @expect SAFE — assert with boolean expression, not tainted */
    public function FP_codei_assert_safe() {
        $x = 5;
        assert($x > 0);
    }

    /** @expect SAFE — preg_replace without /e modifier */
    public function FP_codei_preg_no_e() {
        $input = $_GET["input"];
        $result = preg_replace('/[^a-z]/i', '', $input);
    }

    /** @expect SAFE — private method eval (params not tainted) */
    private function FP_codei_private_eval($code) {
        eval($code);
    }

    // ---- FALSE NEGATIVES ----

    /** @expect VULN Code Injection — eval with tainted input */
    public function FN_codei_eval() {
        $code = $_POST["code"];
        eval($code);
    }

    /** @expect VULN Code Injection — eval with concat tainted */
    public function FN_codei_eval_concat() {
        $expr = $_GET["expr"];
        eval('$result = ' . $expr . ';');
    }

    /** @expect VULN Code Injection — assert with tainted string */
    public function FN_codei_assert() {
        $check = $_GET["check"];
        assert($check);
    }

    /** @expect VULN Code Injection — create_function with tainted body */
    public function FN_codei_create_function() {
        $body = $_POST["func_body"];
        $func = create_function('$x', $body);
    }

    /** @expect VULN Code Injection — preg_replace with /e and tainted replacement */
    public function FN_codei_preg_replace_e() {
        $replacement = $_GET["replace"];
        preg_replace('/(.+)/e', $replacement, "test");
    }

    /** @expect VULN Code Injection — eval with getenv taint */
    public function FN_codei_eval_getenv() {
        $config = getenv("PHP_EVAL_CODE");
        eval($config);
    }

    /** @expect VULN Code Injection — eval through taint chain */
    public function FN_codei_eval_chain() {
        $raw = $_POST["payload"];
        $decoded = base64_decode($raw);
        eval($decoded);
    }
}


// ============================================================================
// 4. INSECURE DESERIALIZATION
// ============================================================================

class DeserializationTests {

    // ---- FALSE POSITIVES ----

    /** @expect SAFE — unserialize with allowed_classes=false */
    public function FP_deser_allowed_classes() {
        $data = $_COOKIE["prefs"];
        $obj = unserialize($data, ["allowed_classes" => false]);
    }

    /** @expect SAFE — unserialize with hardcoded data */
    public function FP_deser_hardcoded() {
        $obj = unserialize('a:1:{s:4:"name";s:5:"admin";}');
    }

    /** @expect SAFE — private method */
    private function FP_deser_private($data) {
        return unserialize($data);
    }

    // ---- FALSE NEGATIVES ----

    /** @expect VULN Deserialization — unserialize with tainted input */
    public function FN_deser_cookie() {
        $data = $_COOKIE["session"];
        $obj = unserialize($data);
    }

    /** @expect VULN Deserialization — unserialize $_POST */
    public function FN_deser_post() {
        $payload = $_POST["data"];
        unserialize($payload);
    }

    /** @expect VULN Deserialization — unserialize with taint chain */
    public function FN_deser_chain() {
        $raw = $_GET["obj"];
        $decoded = base64_decode($raw);
        unserialize($decoded);
    }

    /** @expect VULN Deserialization — unserialize from file_get_contents php://input */
    public function FN_deser_php_input() {
        $body = file_get_contents("php://input");
        unserialize($body);
    }
}


// ============================================================================
// 5. LFI / RFI
// ============================================================================

class LFIRFITests {

    // ---- FALSE POSITIVES ----

    /** @expect SAFE — hardcoded include path */
    public function FP_lfi_hardcoded() {
        include "config/database.php";
    }

    /** @expect SAFE — hardcoded require_once */
    public function FP_lfi_require_once() {
        require_once "vendor/autoload.php";
    }

    /** @expect SAFE — include with constant */
    public function FP_lfi_constant() {
        $file = "header.php";
        include $file;
    }

    /** @expect SAFE — private method */
    private function FP_lfi_private($page) {
        include $page;
    }

    // ---- FALSE NEGATIVES ----

    /** @expect VULN LFI/RFI — include with direct superglobal */
    public function FN_lfi_include() {
        $page = $_GET["page"];
        include $page;
    }

    /** @expect VULN LFI/RFI — require with tainted path */
    public function FN_lfi_require() {
        $module = $_POST["module"];
        require $module;
    }

    /** @expect VULN LFI/RFI — include_once with tainted concat */
    public function FN_lfi_include_once_concat() {
        $lang = $_GET["lang"];
        include_once "langs/" . $lang . ".php";
    }

    /** @expect VULN LFI/RFI — require_once with tainted path */
    public function FN_lfi_require_once() {
        $plugin = $_COOKIE["plugin"];
        require_once "plugins/" . $plugin . "/init.php";
    }

    /** @expect VULN LFI/RFI — include with $_REQUEST */
    public function FN_lfi_request() {
        $tpl = $_REQUEST["template"];
        include $tpl;
    }

    /** @expect VULN LFI/RFI — require with taint chain */
    public function FN_lfi_chain() {
        $raw = $_GET["file"];
        $path = "modules/" . $raw;
        include $path;
    }
}


// ============================================================================
// 6. SSRF
// ============================================================================

class SSRFTests {

    // ---- FALSE POSITIVES ----

    /** @expect SAFE — file_get_contents with hardcoded URL */
    public function FP_ssrf_hardcoded() {
        $content = file_get_contents("https://api.example.com/data");
    }

    /** @expect SAFE — file_get_contents with php://input (taint source, not SSRF) */
    public function FP_ssrf_php_input() {
        $body = file_get_contents("php://input");
    }

    /** @expect SAFE — curl with hardcoded URL */
    public function FP_ssrf_curl_hardcoded() {
        $ch = curl_init();
        curl_setopt($ch, CURLOPT_URL, "https://api.example.com/data");
        curl_exec($ch);
    }

    /** @expect SAFE — fopen with hardcoded path */
    public function FP_ssrf_fopen_hardcoded() {
        $fp = fopen("/var/log/app.log", "r");
    }

    /** @expect SAFE — private method */
    private function FP_ssrf_private($url) {
        file_get_contents($url);
    }

    // ---- FALSE NEGATIVES ----

    /** @expect VULN SSRF — file_get_contents with tainted URL */
    public function FN_ssrf_file_get_contents() {
        $url = $_GET["url"];
        $data = file_get_contents($url);
    }

    /** @expect VULN SSRF — curl_setopt CURLOPT_URL tainted */
    public function FN_ssrf_curl_setopt() {
        $url = $_POST["target"];
        $ch = curl_init();
        curl_setopt($ch, CURLOPT_URL, $url);
        curl_exec($ch);
    }

    /** @expect VULN SSRF — curl_init with tainted URL */
    public function FN_ssrf_curl_init() {
        $url = $_GET["endpoint"];
        $ch = curl_init($url);
        curl_exec($ch);
    }

    /** @expect VULN SSRF — fopen with tainted URL */
    public function FN_ssrf_fopen() {
        $url = $_POST["url"];
        $fp = fopen($url, "r");
    }

    /** @expect VULN SSRF — SoapClient with tainted WSDL */
    public function FN_ssrf_soap() {
        $wsdl = $_GET["wsdl"];
        $client = new SoapClient($wsdl);
    }

    /** @expect VULN SSRF — taint chain through concat */
    public function FN_ssrf_chain() {
        $host = $_GET["host"];
        $url = "http://" . $host . "/api/data";
        file_get_contents($url);
    }
}


// ============================================================================
// 7. XXE
// ============================================================================

class XXETests {

    // ---- FALSE POSITIVES ----

    /** @expect SAFE — DOMDocument with libxml_disable_entity_loader(true) */
    public function FP_xxe_entity_loader_disabled() {
        $xml = file_get_contents("php://input");
        libxml_disable_entity_loader(true);
        $doc = new DOMDocument();
        $doc->loadXML($xml);
    }

    /** @expect SAFE — loadXML with hardcoded XML */
    public function FP_xxe_hardcoded() {
        $doc = new DOMDocument();
        $doc->loadXML("<root><item>test</item></root>");
    }

    /** @expect SAFE — simplexml_load_string with hardcoded */
    public function FP_xxe_simplexml_hardcoded() {
        $xml = simplexml_load_string("<data><name>test</name></data>");
    }

    /** @expect SAFE — private method */
    private function FP_xxe_private($xml) {
        $doc = new DOMDocument();
        $doc->loadXML($xml);
    }

    // ---- FALSE NEGATIVES ----

    /** @expect VULN XXE — DOMDocument->loadXML with tainted input */
    public function FN_xxe_loadxml() {
        $xml = $_POST["xml"];
        $doc = new DOMDocument();
        $doc->loadXML($xml);
    }

    /** @expect VULN XXE — simplexml_load_string with tainted input */
    public function FN_xxe_simplexml() {
        $xml = $_POST["data"];
        $result = simplexml_load_string($xml);
    }

    /** @expect VULN XXE — loadXML with php://input taint source */
    public function FN_xxe_php_input() {
        $rawXml = file_get_contents("php://input");
        $doc = new DOMDocument();
        $doc->loadXML($rawXml);
    }

    /** @expect VULN XXE — DOMDocument->loadHTML with tainted */
    public function FN_xxe_loadhtml() {
        $html = $_POST["html"];
        $doc = new DOMDocument();
        $doc->loadHTML($html);
    }

    /** @expect VULN XXE — simplexml_load_file with tainted path */
    public function FN_xxe_simplexml_file() {
        $path = $_GET["xmlfile"];
        $xml = simplexml_load_file($path);
    }
}


// ============================================================================
// 8. XPATH INJECTION
// ============================================================================

class XPathInjectionTests {

    // ---- FALSE POSITIVES ----

    /** @expect SAFE — DOMXPath with hardcoded expression */
    public function FP_xpath_hardcoded() {
        $doc = new DOMDocument();
        $xpath = new DOMXPath($doc);
        $result = $xpath->query("/users/user[@active='1']");
    }

    /** @expect SAFE — ->query() on non-XPath object */
    public function FP_xpath_non_xpath_query($pdo) {
        $result = $pdo->query("SELECT * FROM users");
    }

    /** @expect SAFE — private method */
    private function FP_xpath_private($expr) {
        $doc = new DOMDocument();
        $xpath = new DOMXPath($doc);
        $xpath->query($expr);
    }

    // ---- FALSE NEGATIVES ----

    /** @expect VULN XPath Injection — tainted concat in xpath->query */
    public function FN_xpath_query() {
        $name = $_GET["name"];
        $doc = new DOMDocument();
        $xpath = new DOMXPath($doc);
        $result = $xpath->query("/users/user[@name='" . $name . "']");
    }

    /** @expect VULN XPath Injection — tainted concat in xpath->evaluate */
    public function FN_xpath_evaluate() {
        $id = $_POST["id"];
        $doc = new DOMDocument();
        $xpath = new DOMXPath($doc);
        $result = $xpath->evaluate("count(/users/user[@id=" . $id . "])");
    }

    /** @expect VULN XPath Injection — tainted variable in query */
    public function FN_xpath_tainted_var() {
        $expr = $_GET["xpath"];
        $doc = new DOMDocument();
        $xpath = new DOMXPath($doc);
        $result = $xpath->query($expr);
    }
}


// ============================================================================
// 9. PATH TRAVERSAL
// ============================================================================

class PathTraversalTests {

    // ---- FALSE POSITIVES ----

    /** @expect SAFE — file_get_contents with hardcoded path */
    public function FP_path_hardcoded() {
        $content = file_get_contents("/etc/config.ini");
    }

    /** @expect SAFE — realpath() sanitization present */
    public function FP_path_realpath() {
        $file = $_GET["file"];
        $safe = realpath("/uploads/" . $file);
        readfile($safe);
    }

    /** @expect SAFE — basename() sanitization present */
    public function FP_path_basename() {
        $file = $_GET["file"];
        $safe = basename($file);
        readfile("/uploads/" . $safe);
    }

    /** @expect SAFE — hardcoded unlink */
    public function FP_path_unlink_hardcoded() {
        unlink("/tmp/cache/temp.txt");
    }

    /** @expect SAFE — private method */
    private function FP_path_private($path) {
        readfile($path);
    }

    /** @expect SAFE — file_put_contents with hardcoded path */
    public function FP_path_put_hardcoded() {
        file_put_contents("/var/log/app.log", "entry\n", FILE_APPEND);
    }

    // ---- FALSE NEGATIVES ----

    /** @expect VULN Path Traversal — readfile with tainted path */
    public function FN_path_readfile() {
        $file = $_GET["file"];
        readfile("/uploads/" . $file);
    }

    /** @expect VULN Path Traversal — file_get_contents with tainted path */
    public function FN_path_file_get_contents() {
        $path = $_POST["path"];
        $content = file_get_contents($path);
    }

    /** @expect VULN Path Traversal — file_put_contents with tainted path */
    public function FN_path_file_put_contents() {
        $filename = $_POST["filename"];
        file_put_contents("/uploads/" . $filename, "data");
    }

    /** @expect VULN Path Traversal — unlink with tainted path */
    public function FN_path_unlink() {
        $file = $_GET["delete"];
        unlink("/uploads/" . $file);
    }

    /** @expect VULN Path Traversal — fopen with tainted path */
    public function FN_path_fopen() {
        $log = $_GET["logfile"];
        $fp = fopen("/var/log/" . $log, "r");
    }

    /** @expect VULN Path Traversal — copy with tainted source */
    public function FN_path_copy() {
        $src = $_POST["source"];
        copy($src, "/tmp/backup.dat");
    }

    /** @expect VULN Path Traversal — rename with tainted path */
    public function FN_path_rename() {
        $old = $_GET["old"];
        $new = $_GET["new"];
        rename($old, $new);
    }

    /** @expect VULN Path Traversal — mkdir with tainted path */
    public function FN_path_mkdir() {
        $dir = $_POST["dirname"];
        mkdir("/var/data/" . $dir, 0755);
    }

    /** @expect VULN Path Traversal — rmdir with tainted path */
    public function FN_path_rmdir() {
        $dir = $_GET["dir"];
        rmdir("/var/data/" . $dir);
    }
}


// ============================================================================
// 10. SSTI (Server-Side Template Injection)
// ============================================================================

class SSTITests {

    // ---- FALSE POSITIVES ----

    /** @expect SAFE — Twig render with hardcoded template name */
    public function FP_ssti_twig_hardcoded($twig) {
        $twig->render("dashboard.html.twig", ["user" => $user]);
    }

    /** @expect SAFE — render on non-template object */
    public function FP_ssti_non_template($view) {
        $view->render("home");
    }

    /** @expect SAFE — private method */
    private function FP_ssti_private($twig, $tpl) {
        $twig->render($tpl);
    }

    // ---- FALSE NEGATIVES ----

    /** @expect VULN SSTI — Twig createTemplate with tainted source */
    public function FN_ssti_twig_createTemplate($twig) {
        $template = $_POST["template"];
        $twig->createTemplate($template);
    }

    /** @expect VULN SSTI — Twig render with tainted template name */
    public function FN_ssti_twig_render($twig) {
        $tpl = $_GET["tpl"];
        $twig->render($tpl);
    }

    /** @expect VULN SSTI — Smarty fetch with tainted string template */
    public function FN_ssti_smarty_fetch($smarty) {
        $code = $_POST["code"];
        $smarty->fetch("string:" . $code);
    }

    /** @expect VULN SSTI — template display with tainted */
    public function FN_ssti_template_display($template) {
        $tpl = $_GET["tpl"];
        $template->display($tpl);
    }
}


// ============================================================================
// 11. NOSQL INJECTION
// ============================================================================

class NoSQLInjectionTests {

    // ---- FALSE POSITIVES ----

    /** @expect SAFE — MongoDB find with hardcoded query */
    public function FP_nosql_hardcoded($collection) {
        $result = $collection->find(["status" => "active"]);
    }

    /** @expect SAFE — find on non-mongo object */
    public function FP_nosql_non_mongo($array) {
        $result = $array->find("needle");
    }

    /** @expect SAFE — private method */
    private function FP_nosql_private($collection, $query) {
        $collection->find($query);
    }

    // ---- FALSE NEGATIVES ----

    /** @expect VULN NoSQL Injection — MongoDB find with tainted query */
    public function FN_nosql_find($mongoCollection) {
        $filter = $_POST["filter"];
        $mongoCollection->find($filter);
    }

    /** @expect VULN NoSQL Injection — MongoDB findOne with tainted */
    public function FN_nosql_findOne($mongoCollection) {
        $query = $_GET["query"];
        $mongoCollection->findOne($query);
    }

    /** @expect VULN NoSQL Injection — MongoDB aggregate with tainted pipeline */
    public function FN_nosql_aggregate($mongoCollection) {
        $pipeline = $_POST["pipeline"];
        $mongoCollection->aggregate($pipeline);
    }

    /** @expect VULN NoSQL Injection — MongoDB deleteMany */
    public function FN_nosql_deleteMany($mongoCollection) {
        $filter = $_POST["filter"];
        $mongoCollection->deleteMany($filter);
    }

    /** @expect VULN NoSQL Injection — MongoDB updateMany */
    public function FN_nosql_updateMany($mongoCollection) {
        $filter = $_GET["filter"];
        $mongoCollection->updateMany($filter, ['$set' => ['active' => false]]);
    }

    /** @expect VULN NoSQL Injection — taint chain */
    public function FN_nosql_chain($mongoCollection) {
        $raw = $_POST["search"];
        $criteria = json_decode($raw, true);
        $mongoCollection->find($criteria);
    }
}


// ============================================================================
// 12. SECOND-ORDER SQLI
// ============================================================================

class SecondOrderSQLiTests {

    // ---- FALSE POSITIVES ----

    /** @expect SAFE — DB-sourced data used with parameterized query */
    public function FP_second_order_parameterized($pdo) {
        $stmt = $pdo->prepare("SELECT * FROM users WHERE id = ?");
        $stmt->execute([1]);
        $row = $stmt->fetch();
        $name = $row["name"];
        $stmt2 = $pdo->prepare("SELECT * FROM orders WHERE customer = ?");
        $stmt2->execute([$name]);
    }

    /** @expect SAFE — DB data used in non-SQL context */
    public function FP_second_order_non_sql($pdo) {
        $stmt = $pdo->prepare("SELECT * FROM users WHERE id = ?");
        $stmt->execute([1]);
        $row = $stmt->fetch();
        echo $row["name"];
    }

    // ---- FALSE NEGATIVES ----

    /** @expect VULN Second-order SQLi — DB-fetched data in raw SQL concat */
    public function FN_second_order_pdo($pdo) {
        $stmt = $pdo->prepare("SELECT * FROM users WHERE id = ?");
        $stmt->execute([1]);
        $row = $stmt->fetch();
        $username = $row["username"];
        $pdo->query("SELECT * FROM audit_log WHERE user = '" . $username . "'");
    }

    /** @expect VULN Second-order SQLi — mysqli_fetch_assoc + concat */
    public function FN_second_order_mysqli($conn) {
        $result = mysqli_query($conn, "SELECT * FROM users WHERE id = 1");
        $row = $result->fetch_assoc();
        $name = $row["name"];
        mysqli_query($conn, "SELECT * FROM orders WHERE customer = '" . $name . "'");
    }
}


// ============================================================================
// 13. TAINT PROPAGATION EDGE CASES
// ============================================================================

class TaintPropagationTests {

    /** @expect VULN SQL Injection — taint through multiple assignments */
    public function FN_taint_multi_hop($pdo) {
        $a = $_GET["x"];
        $b = $a;
        $c = $b;
        $pdo->query("SELECT * FROM t WHERE id = " . $c);
    }

    /** @expect VULN Command Injection — taint through string concat assignment */
    public function FN_taint_concat_assign() {
        $base = $_POST["cmd"];
        $full = "ls " . $base;
        system($full);
    }

    /** @expect SAFE — overwritten tainted variable with safe value */
    public function FP_taint_overwrite($pdo) {
        $id = $_GET["id"];
        $id = 42;
        $pdo->query("SELECT * FROM users WHERE id = " . $id);
    }

    /** @expect VULN Code Injection — taint from $_FILES */
    public function FN_taint_files() {
        $name = $_FILES["upload"]["name"];
        eval($name);
    }

    /** @expect VULN SQL Injection — taint from $_ENV */
    public function FN_taint_env($pdo) {
        $dbHost = $_ENV["DB_HOST"];
        $pdo->query("SELECT * FROM " . $dbHost . ".users");
    }

    /** @expect VULN SSRF — taint from $_SERVER */
    public function FN_taint_server() {
        $referer = $_SERVER["HTTP_REFERER"];
        file_get_contents($referer);
    }

    /** @expect SAFE — taint killed by intval */
    public function FP_taint_intval($pdo) {
        $raw = $_GET["id"];
        $safe = intval($raw);
        $pdo->query("SELECT * FROM users WHERE id = " . $safe);
    }

    /** @expect VULN SQL Injection — taint through sprintf */
    public function FN_taint_sprintf($pdo) {
        $name = $_GET["name"];
        $query = sprintf("SELECT * FROM users WHERE name = '%s'", $name);
        $pdo->query($query);
    }

    /** @expect VULN LFI/RFI — taint propagated through ternary operator */
    public function FN_taint_ternary() {
        $page = isset($_GET["page"]) ? $_GET["page"] : "default";
        include $page;
    }
}


// ============================================================================
// 14. MIXED / EDGE CASES
// ============================================================================

class MixedEdgeCases {

    /** @expect SAFE — query method on non-DB object (array helper) */
    public function FP_query_on_collection($cache) {
        $key = $_GET["key"];
        $cache->query($key);
    }

    /** @expect SAFE — exec() called as method on non-DB object */
    public function FP_exec_method($scheduler) {
        $cmd = $_GET["cmd"];
        $scheduler->exec($cmd);
    }

    /** @expect VULN SQL Injection — multiple vulns in one function */
    public function FN_multi_vuln($pdo, $conn) {
        $id = $_GET["id"];
        $name = $_POST["name"];
        $pdo->query("SELECT * FROM users WHERE id = " . $id);
        mysqli_query($conn, "SELECT * FROM logs WHERE user = '" . $name . "'");
    }

    /** @expect VULN Command Injection — nested function call taint */
    public function FN_nested_taint() {
        $input = trim($_GET["input"]);
        system($input);
    }

    /** @expect SAFE — empty function, no vulnerability */
    public function FP_empty_function() {
        // No code
    }

    /** @expect SAFE — only local variables, no taint source */
    public function FP_local_only($pdo) {
        $limit = 10;
        $offset = 0;
        $query = "SELECT * FROM users LIMIT " . $limit . " OFFSET " . $offset;
        $pdo->query($query);
    }

    /** @expect VULN SQL Injection — public method param is tainted by default */
    public function FN_public_param_tainted($pdo, $userInput) {
        $pdo->query("SELECT * FROM users WHERE name = '" . $userInput . "'");
    }

    /** @expect VULN Path Traversal — file() function with tainted path */
    public function FN_file_func() {
        $path = $_GET["logfile"];
        $lines = file($path);
    }

    /** @expect VULN SSRF — file_get_contents with concat tainted URL */
    public function FN_ssrf_concat() {
        $domain = $_POST["domain"];
        $url = "https://" . $domain . "/api/status";
        $data = file_get_contents($url);
    }

    /** @expect VULN Command Injection — shell_exec through variable chain */
    public function FN_cmdi_deep_chain() {
        $raw = $_POST["input"];
        $step1 = $raw;
        $step2 = $step1;
        $step3 = "whoami && " . $step2;
        shell_exec($step3);
    }
}


// ============================================================================
// 15. TOP-LEVEL FUNCTIONS (not in a class)
// ============================================================================

/** @expect VULN SQL Injection — top-level function with superglobal */
function FN_toplevel_sqli() {
    $id = $_GET["id"];
    $conn = mysqli_connect("localhost", "root", "", "test");
    mysqli_query($conn, "SELECT * FROM users WHERE id = " . $id);
}

/** @expect VULN Command Injection — top-level with direct superglobal */
function FN_toplevel_cmdi() {
    $cmd = $_POST["cmd"];
    exec($cmd);
}

/** @expect SAFE — top-level with hardcoded values */
function FP_toplevel_safe() {
    system("date");
    include "footer.php";
}

/** @expect VULN LFI/RFI — top-level include */
function FN_toplevel_lfi() {
    $page = $_GET["p"];
    include_once $page;
}

/** @expect VULN Code Injection — top-level eval */
function FN_toplevel_eval() {
    $code = $_REQUEST["eval"];
    eval($code);
}

/** @expect VULN Deserialization — top-level unserialize */
function FN_toplevel_deser() {
    $obj = $_COOKIE["data"];
    unserialize($obj);
}

/** @expect VULN SSRF — top-level curl */
function FN_toplevel_ssrf() {
    $url = $_GET["target"];
    $ch = curl_init($url);
    curl_exec($ch);
}

/** @expect VULN Path Traversal — top-level file operation */
function FN_toplevel_path() {
    $file = $_POST["file"];
    unlink("/uploads/" . $file);
}

/** @expect VULN XXE — top-level simplexml */
function FN_toplevel_xxe() {
    $xml = $_POST["xml"];
    simplexml_load_string($xml);
}


// ============================================================================
// 16. OVERLAP / DUAL-CATEGORY TESTS
// ============================================================================

class OverlapTests {

    /**
     * @expect VULN SSRF AND Path Traversal
     * fopen with tainted path — dual category: could be SSRF or path traversal
     * Scanner should flag at least one (preferably SSRF since it covers both)
     */
    public function FN_overlap_fopen_ssrf_and_path() {
        $target = $_GET["target"];
        $fp = fopen($target, "r");
    }

    /**
     * @expect VULN Path Traversal AND SSRF
     * file_get_contents with tainted concat — both path traversal and SSRF
     */
    public function FN_overlap_fgc_dual() {
        $input = $_POST["resource"];
        $content = file_get_contents($input);
    }

    /**
     * @expect VULN SQL Injection — PDO->exec flagged as SQL not cmd injection
     * The ->exec() should be treated as SQL execution, not command execution
     */
    public function FN_overlap_exec_sql($pdo) {
        $table = $_GET["table"];
        $pdo->exec("TRUNCATE TABLE " . $table);
    }
}


// ============================================================================
// 17. SANITIZER AWARENESS TESTS
// ============================================================================

class SanitizerTests {

    /** @expect SAFE — htmlspecialchars does not prevent SQLi but
     *  the query uses prepared statements so it's still safe */
    public function FP_sanitizer_htmlspecialchars($pdo) {
        $name = htmlspecialchars($_GET["name"]);
        $stmt = $pdo->prepare("SELECT * FROM users WHERE name = ?");
        $stmt->execute([$name]);
    }

    /** @expect SAFE — filter_var FILTER_VALIDATE_INT */
    public function FP_sanitizer_filter_var($pdo) {
        $id = filter_var($_GET["id"], FILTER_VALIDATE_INT);
        $pdo->query("SELECT * FROM users WHERE id = " . $id);
    }

    /** @expect SAFE — realpath prevents path traversal */
    public function FP_sanitizer_realpath() {
        $file = $_GET["file"];
        $safe_path = realpath("/uploads/" . $file);
        if ($safe_path && strpos($safe_path, "/uploads/") === 0) {
            readfile($safe_path);
        }
    }

    /** @expect SAFE — basename prevents path traversal */
    public function FP_sanitizer_basename_readfile() {
        $file = $_GET["file"];
        readfile("/uploads/" . basename($file));
    }

    /** @expect SAFE — escapeshellarg prevents command injection */
    public function FP_sanitizer_escapeshellarg() {
        $file = $_GET["file"];
        $safe = escapeshellarg($file);
        system("cat " . $safe);
    }
}


// ============================================================================
// 18. HEREDOC / NOWDOC EDGE CASES
// ============================================================================

class HeredocTests {

    /** @expect VULN SQL Injection — heredoc with tainted interpolation */
    public function FN_heredoc_sqli($pdo) {
        $id = $_GET["id"];
        $query = "SELECT * FROM users WHERE id = " . $id;
        $pdo->query($query);
    }

    /** @expect SAFE — query string built from constants */
    public function FP_heredoc_safe($pdo) {
        $status = "active";
        $limit = 10;
        $query = "SELECT * FROM users WHERE status = '" . $status . "' LIMIT " . $limit;
        $pdo->query($query);
    }
}


// ============================================================================
// 19. OBJECT METHOD DISAMBIGUATION
// ============================================================================

class MethodDisambiguationTests {

    /** @expect SAFE — ->find() on Doctrine repository (not MongoDB) */
    public function FP_find_doctrine($entityManager) {
        $id = $_GET["id"];
        $user = $entityManager->find("App\\Entity\\User", $id);
    }

    /** @expect SAFE — ->execute() on PDOStatement (not exec) */
    public function FP_execute_stmt($pdo) {
        $id = $_GET["id"];
        $stmt = $pdo->prepare("SELECT * FROM users WHERE id = ?");
        $stmt->execute([$id]);
    }

    /** @expect SAFE — ->query() on cache/search object */
    public function FP_query_search($elasticsearch) {
        $term = $_GET["q"];
        $elasticsearch->query($term);
    }

    /** @expect SAFE — ->update() on non-mongo object */
    public function FP_update_orm($user) {
        $name = $_POST["name"];
        $user->update(["name" => $name]);
    }
}


// ============================================================================
// 20. COMPLEX REAL-WORLD PATTERNS
// ============================================================================

class RealWorldPatterns {

    /** @expect VULN SQL Injection — WordPress-style wpdb->query */
    public function FN_wordpress_sqli() {
        global $wpdb;
        $search = $_GET["s"];
        $wpdb->query("SELECT * FROM wp_posts WHERE post_title LIKE '%" . $search . "%'");
    }

    /** @expect VULN SQL Injection — Laravel raw query */
    public function FN_laravel_raw($pdo) {
        $sort = $_GET["sort"];
        $pdo->query("SELECT * FROM products ORDER BY " . $sort);
    }

    /** @expect VULN Command Injection — image processing */
    public function FN_image_processing() {
        $filename = $_FILES["image"]["name"];
        exec("convert /uploads/" . $filename . " -resize 100x100 /thumbs/" . $filename);
    }

    /** @expect VULN LFI/RFI — template inclusion pattern */
    public function FN_template_include() {
        $theme = $_COOKIE["theme"];
        include "themes/" . $theme . "/layout.php";
    }

    /** @expect VULN SSRF — webhook/callback URL */
    public function FN_webhook_ssrf() {
        $callbackUrl = $_POST["callback"];
        file_get_contents($callbackUrl);
    }

    /** @expect VULN Deserialization — session handler */
    public function FN_session_deser() {
        $sessionData = $_COOKIE["custom_session"];
        $session = unserialize($sessionData);
    }

    /** @expect SAFE — prepared statement in WordPress style */
    public function FP_wordpress_prepared() {
        global $wpdb;
        $id = $_GET["id"];
        $stmt = $wpdb->prepare("SELECT * FROM wp_posts WHERE ID = %d", $id);
    }

    /** @expect VULN Command Injection — PDF generation */
    public function FN_pdf_generation() {
        $html = $_POST["html_content"];
        exec("wkhtmltopdf - " . $html . " output.pdf");
    }

    /** @expect VULN XXE — API endpoint accepting XML */
    public function FN_api_xxe() {
        $body = file_get_contents("php://input");
        $doc = new DOMDocument();
        $doc->loadXML($body);
    }

    /** @expect VULN SQL Injection — dynamic table name */
    public function FN_dynamic_table($pdo) {
        $entity = $_GET["entity"];
        $pdo->query("SELECT COUNT(*) FROM " . $entity);
    }
}


// ============================================================================
// 21. TOP-LEVEL CODE & VARIABLE FUNCTION CALLS (ghost file patterns)
// ============================================================================

/** @expect VULN Deserialization — top-level unserialize from cookie (ghost.php pattern) */
function FN_toplevel_deser_base64() {
    $user_data = unserialize(base64_decode($_COOKIE['data']));
}

/** @expect VULN LFI/RFI — top-level include with concat (ghost2.php pattern) */
function FN_toplevel_lfi_concat() {
    $page = $_GET['page'];
    include("pages/" . $page);
}

/** @expect VULN Code Injection — variable function call (ghost3.php pattern) */
function FN_variable_function_call() {
    $method = $_GET['action'];
    $payload = $_GET['cmd'];
    $method($payload);
}

/** @expect SAFE — variable function call with hardcoded name */
function FP_variable_function_safe() {
    $func = "strtolower";
    $result = $func("HELLO");
}

/** @expect VULN Command Injection — shell_exec through taint chain (ghost4.php pattern) */
function FN_shell_exec_concat_chain() {
    $width = $_GET['width'];
    $cmd = "convert image.jpg -resize " . $width . " thumb.jpg";
    shell_exec($cmd);
}

// ==========================================================================
// Section 22: Cross-Method Taint Propagation (ghost5.php pattern)
// ==========================================================================

class VulnUserProfile {
    public $id;
    private $db;

    public function __construct($userId, $dbConnection) {
        $this->id = $userId;
        $this->db = $dbConnection;
    }

    /** @expect VULN SQL Injection — $this->id tainted from constructor param */
    public function FN_cross_method_sqli_this_prop() {
        $query = "SELECT * FROM profiles WHERE user_id = " . $this->id;
        return $this->db->query($query);
    }
}

class VulnConfigLoader {
    private $path;

    public function __construct($configPath) {
        $this->path = $configPath;
    }

    /** @expect VULN Path Traversal — $this->path tainted from constructor param */
    public function FN_cross_method_path_traversal() {
        return file_get_contents($this->path);
    }
}

class SafeUserProfile {
    private $id;
    private $db;

    public function __construct($userId, $dbConnection) {
        $this->id = intval($userId);
        $this->db = $dbConnection;
    }

    /** @expect SAFE — $this->id sanitized with intval in constructor */
    public function FP_cross_method_sanitized_constructor() {
        $query = "SELECT * FROM profiles WHERE user_id = " . $this->id;
        return $this->db->query($query);
    }
}

// ==========================================================================
// Section 23: Encapsed String Interpolation in SQL (ghost8 pattern)
// ==========================================================================

class EncapsedSQLTests {
    /** @expect VULN SQL Injection — tainted var interpolated in double-quoted SQL */
    public function FN_sqli_encapsed_interpolation($db) {
        $pref = $_GET['pref'];
        $db->query("UPDATE settings SET val = '$pref' WHERE name = 'sort_order'");
    }

    /** @expect VULN SQL Injection — tainted var interpolated via curly syntax */
    public function FN_sqli_encapsed_curly($db) {
        $table = $_GET['table'];
        $db->query("SELECT * FROM {$table} WHERE 1");
    }

    /** @expect SAFE — hardcoded interpolation */
    public function FP_sqli_encapsed_hardcoded($db) {
        $table = "users";
        $db->query("SELECT * FROM $table WHERE active = 1");
    }
}

// ==========================================================================
// Section 24: Second-Order SQL Injection
// ==========================================================================

class SecondOrderTests {
    /** @expect VULN Second-order SQLi — DB-fetched data concat'd into SQL */
    public function FN_second_order_fetch_concat($db) {
        $res = $db->query("SELECT username FROM users WHERE id = 1");
        $user = $res->fetch_assoc();
        $stored = $user['username'];
        $sql = "UPDATE profiles SET name = '" . $stored . "'";
        $db->query($sql);
    }

    /** @expect VULN Second-order SQLi — DB-fetched data interpolated into SQL */
    public function FN_second_order_fetch_interpolation($db) {
        $res = $db->query("SELECT username FROM users WHERE id = 1");
        $row = $res->fetch_assoc();
        $name = $row['name'];
        $db->query("UPDATE profiles SET last_login = NOW() WHERE display_name = '$name'");
    }

    /** @expect VULN Second-order SQLi — PREPARE FROM with DB-loaded variable */
    public function FN_second_order_prepare_from($db) {
        $db->query("SET @table = (SELECT last_val FROM user_settings WHERE user_id = 1)");
        $db->query("PREPARE stmt FROM 'OPTIMIZE TABLE ' + @table");
        $db->query("EXECUTE stmt");
    }

    /** @expect SAFE — hardcoded PREPARE without SELECT subquery */
    public function FP_prepare_hardcoded($db) {
        $db->query("PREPARE stmt FROM 'SELECT * FROM users'");
        $db->query("EXECUTE stmt");
    }
}
?>
