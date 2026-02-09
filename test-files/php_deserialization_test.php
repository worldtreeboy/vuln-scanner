<?php
/**
 * PHP Deserialization Test Suite
 * ==============================
 * Comprehensive TP/TN/FP/FN tests for deserialization detection.
 *
 * Covers:
 *   - Direct deserialization (unserialize, yaml_parse, igbinary, msgpack, wddx, json_decode)
 *   - Phar deserialization (file_get_contents, file_exists, getimagesize, include)
 *   - Gadget chain indicators (magic methods with dangerous ops)
 */

// =====================================================================
// 1. DIRECT DESERIALIZATION — TRUE POSITIVES
// =====================================================================

// TP-DESER-001: unserialize with user input
function tp_unserialize_get($input) {
    $data = $_GET['data'];
    $obj = unserialize($data);  // TP: CRITICAL
    return $obj;
}

// TP-DESER-002: unserialize with POST input
function tp_unserialize_post() {
    $payload = $_POST['payload'];
    return unserialize($payload);  // TP: CRITICAL
}

// TP-DESER-003: unserialize with allowed_classes not set to false
function tp_unserialize_allowed_classes_true() {
    $data = $_REQUEST['data'];
    return unserialize($data, ['allowed_classes' => true]);  // TP: still dangerous
}

// TP-DESER-004: yaml_parse with user input
function tp_yaml_parse() {
    $yaml = $_POST['yaml'];
    $result = yaml_parse($yaml);  // TP: CRITICAL
    return $result;
}

// TP-DESER-005: yaml_parse_file with user-controlled path
function tp_yaml_parse_file() {
    $path = $_GET['config'];
    return yaml_parse_file($path);  // TP: CRITICAL
}

// TP-DESER-006: yaml_parse_url with user input
function tp_yaml_parse_url() {
    $url = $_GET['url'];
    return yaml_parse_url($url);  // TP: CRITICAL
}

// TP-DESER-007: igbinary_unserialize with tainted data
function tp_igbinary() {
    $bin = $_POST['binary'];
    return igbinary_unserialize($bin);  // TP: CRITICAL
}

// TP-DESER-008: msgpack_unpack with user input
function tp_msgpack() {
    $packed = $_POST['msg'];
    return msgpack_unpack($packed);  // TP: HIGH
}

// TP-DESER-009: wddx_deserialize with user input
function tp_wddx() {
    $xml = $_POST['wddx'];
    return wddx_deserialize($xml);  // TP: HIGH
}

// TP-DESER-010: json_decode without assoc=true
function tp_json_decode_objects() {
    $json = $_POST['json'];
    $obj = json_decode($json);  // TP: MEDIUM (returns objects)
    return $obj;
}

// =====================================================================
// 2. DIRECT DESERIALIZATION — TRUE NEGATIVES
// =====================================================================

// TN-DESER-001: unserialize with allowed_classes => false
function tn_unserialize_safe() {
    $data = $_GET['data'];
    return unserialize($data, ['allowed_classes' => false]);  // TN: mitigated
}

// TN-DESER-002: unserialize with hardcoded string
function tn_unserialize_hardcoded() {
    $data = 'a:1:{s:4:"test";i:1;}';
    return unserialize($data);  // TN: not tainted
}

// TN-DESER-003: json_decode with assoc=true
function tn_json_decode_assoc() {
    $json = $_POST['json'];
    return json_decode($json, true);  // TN: returns array, not objects
}

// TN-DESER-004: yaml_parse with hardcoded YAML
function tn_yaml_hardcoded() {
    $yaml = "key: value\nlist:\n  - item1\n  - item2";
    return yaml_parse($yaml);  // TN: not tainted
}

// TN-DESER-005: igbinary_unserialize with internal data
function tn_igbinary_safe() {
    $data = file_get_contents('/etc/app/cache.bin');
    return igbinary_unserialize($data);  // TN: not user-tainted
}

// =====================================================================
// 3. PHAR DESERIALIZATION — TRUE POSITIVES
// =====================================================================

// TP-PHAR-001: file_get_contents with tainted path
function tp_phar_file_get_contents() {
    $path = $_GET['file'];
    return file_get_contents($path);  // TP: phar:// deserialization
}

// TP-PHAR-002: file_exists with tainted path
function tp_phar_file_exists() {
    $path = $_GET['path'];
    if (file_exists($path)) {  // TP: phar:// deserialization
        return true;
    }
    return false;
}

// TP-PHAR-003: getimagesize with tainted path
function tp_phar_getimagesize() {
    $img = $_POST['image'];
    $info = getimagesize($img);  // TP: phar:// deserialization
    return $info;
}

// TP-PHAR-004: is_file with tainted path
function tp_phar_is_file() {
    $file = $_GET['check'];
    return is_file($file);  // TP: phar:// deserialization
}

// TP-PHAR-005: fopen with tainted path
function tp_phar_fopen() {
    $path = $_GET['doc'];
    $handle = fopen($path, 'r');  // TP: phar:// deserialization
    return fread($handle, 1024);
}

// TP-PHAR-006: copy with tainted source
function tp_phar_copy() {
    $src = $_GET['source'];
    copy($src, '/tmp/output.dat');  // TP: phar:// deserialization
}

// TP-PHAR-007: unlink with tainted path
function tp_phar_unlink() {
    $file = $_POST['delete'];
    unlink($file);  // TP: phar:// deserialization
}

// TP-PHAR-008: include with tainted path
function tp_phar_include() {
    $module = $_GET['module'];
    include $module;  // TP: phar:// deserialization
}

// TP-PHAR-009: exif_imagetype with tainted path
function tp_phar_exif() {
    $img = $_POST['photo'];
    return exif_imagetype($img);  // TP: phar:// deserialization
}

// TP-PHAR-010: filesize with tainted path
function tp_phar_filesize() {
    $f = $_GET['f'];
    return filesize($f);  // TP: phar:// deserialization
}

// =====================================================================
// 4. PHAR DESERIALIZATION — TRUE NEGATIVES
// =====================================================================

// TN-PHAR-001: file_get_contents with hardcoded path
function tn_phar_hardcoded() {
    return file_get_contents('/etc/config.json');  // TN: not tainted
}

// TN-PHAR-002: file_exists with phar:// check before use
function tn_phar_validated() {
    $path = $_GET['path'];
    if (strpos($path, 'phar') !== false) {
        die('Invalid path');  // mitigation
    }
    return file_exists($path);  // TN: phar wrapper validated
}

// TN-PHAR-003: is_file with internal path
function tn_phar_internal() {
    $path = '/var/www/uploads/' . basename($_GET['name']);
    return is_file($path);  // TN: basename strips path traversal (still tainted though for other checks)
}

// =====================================================================
// 5. GADGET CHAIN INDICATORS — TRUE POSITIVES
// =====================================================================

// TP-GADGET-001: __destruct with exec
class VulnDestruct {
    public $cmd;
    public function __destruct() {
        exec($this->cmd);  // TP: gadget chain indicator
    }
}

// TP-GADGET-002: __wakeup with eval
class VulnWakeup {
    public $code;
    public function __wakeup() {
        eval($this->code);  // TP: gadget chain indicator
    }
}

// TP-GADGET-003: __toString with system
class VulnToString {
    public $command;
    public function __toString() {
        system($this->command);  // TP: gadget chain indicator
        return "";
    }
}

// TP-GADGET-004: __call with call_user_func
class VulnCall {
    public $callback;
    public $args;
    public function __call($name, $arguments) {
        call_user_func($this->callback, $this->args);  // TP: gadget chain indicator
    }
}

// TP-GADGET-005: __destruct with file_put_contents
class VulnFileWrite {
    public $path;
    public $content;
    public function __destruct() {
        file_put_contents($this->path, $this->content);  // TP: gadget chain indicator
    }
}

// TP-GADGET-006: __invoke with passthru
class VulnInvoke {
    public $cmd;
    public function __invoke() {
        passthru($this->cmd);  // TP: gadget chain indicator
    }
}

// TP-GADGET-007: __get with unlink
class VulnGet {
    public $file;
    public function __get($name) {
        unlink($this->file);  // TP: gadget chain indicator
    }
}

// =====================================================================
// 6. GADGET CHAIN INDICATORS — TRUE NEGATIVES
// =====================================================================

// TN-GADGET-001: __destruct with harmless operations
class SafeDestruct {
    private $conn;
    public function __destruct() {
        if ($this->conn) {
            $this->conn->close();  // TN: no dangerous function
        }
    }
}

// TN-GADGET-002: __toString with safe string return
class SafeToString {
    private $name;
    public function __toString() {
        return htmlspecialchars($this->name);  // TN: safe operation
    }
}

// TN-GADGET-003: __wakeup with re-initialization
class SafeWakeup {
    private $cache;
    public function __wakeup() {
        $this->cache = [];  // TN: just re-initializes
    }
}

// TN-GADGET-004: regular method with exec (not magic)
class SafeRegularMethod {
    public function execute($cmd) {
        exec($cmd);  // TN for gadget check: not a magic method
    }
}

// TN-GADGET-005: __set with harmless logging
class SafeSet {
    private $data = [];
    public function __set($name, $value) {
        $this->data[$name] = $value;  // TN: no dangerous function
        error_log("Property set: $name");
    }
}
