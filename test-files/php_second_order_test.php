<?php
/**
 * Second-Order SQLi & Deserialization Test Suite
 * ================================================
 * Comprehensive TP/TN tests for second-order attack detection.
 *
 * Second-order = data flows FROM the database INTO a dangerous sink.
 * The attacker controls what was stored earlier; the victim code trusts it.
 *
 * DB source patterns recognized:
 *   ->fetch(), ->fetchAll(), ->fetchColumn(), ->fetch_assoc(),
 *   ->fetch_array(), ->fetch_row(), ->fetch_object(),
 *   mysql_fetch_*, mysqli_fetch_*, pg_fetch_*, ->result()
 *
 * SQLi sinks:  mysql_query, mysqli_query, pg_query, ->query(), ->exec()
 * Deser sinks: unserialize, yaml_parse, igbinary_unserialize, msgpack_unpack, wddx_deserialize
 */

// =====================================================================
// 1. SECOND-ORDER SQLi — TRUE POSITIVES
// =====================================================================

// TP-2SQLI-001: PDO fetch -> concat into ->query()
function tp_2sqli_pdo_query($pdo) {
    $stmt = $pdo->prepare("SELECT username FROM users WHERE id = ?");
    $stmt->execute([1]);
    $row = $stmt->fetch(PDO::FETCH_ASSOC);
    $name = $row['username'];
    $pdo->query("SELECT * FROM logs WHERE user = '" . $name . "'");  // TP
}

// TP-2SQLI-002: PDO fetchAll -> loop concat into ->query()
function tp_2sqli_pdo_fetchall($pdo) {
    $stmt = $pdo->prepare("SELECT tag FROM tags");
    $stmt->execute();
    $rows = $stmt->fetchAll(PDO::FETCH_ASSOC);
    foreach ($rows as $row) {
        $tag = $row['tag'];
        $pdo->query("DELETE FROM posts WHERE tag = '" . $tag . "'");  // TP
    }
}

// TP-2SQLI-003: PDO fetchColumn -> interpolation into ->query()
function tp_2sqli_pdo_fetchcolumn($pdo) {
    $stmt = $pdo->prepare("SELECT email FROM users WHERE id = ?");
    $stmt->execute([42]);
    $email = $stmt->fetchColumn();
    $pdo->query("SELECT * FROM audit WHERE email = '$email'");  // TP
}

// TP-2SQLI-004: mysqli fetch_assoc -> concat into mysqli_query()
function tp_2sqli_mysqli_fetch_assoc($conn) {
    $result = mysqli_query($conn, "SELECT role FROM users WHERE id = 1");
    $row = $result->fetch_assoc();
    $role = $row['role'];
    mysqli_query($conn, "SELECT * FROM permissions WHERE role = '" . $role . "'");  // TP
}

// TP-2SQLI-005: mysqli_fetch_array -> concat into ->query()
function tp_2sqli_mysqli_fetch_array($conn) {
    $result = mysqli_query($conn, "SELECT category FROM items LIMIT 1");
    $row = mysqli_fetch_array($result);
    $cat = $row['category'];
    $conn->query("UPDATE stats SET count = count+1 WHERE cat = '" . $cat . "'");  // TP
}

// TP-2SQLI-006: mysqli_fetch_row -> concat into mysql_query()
function tp_2sqli_mysqli_fetch_row($conn) {
    $result = mysqli_query($conn, "SELECT title FROM posts LIMIT 1");
    $row = mysqli_fetch_row($result);
    $title = $row[0];
    mysql_query("INSERT INTO search_index (term) VALUES ('" . $title . "')");  // TP
}

// TP-2SQLI-007: pg_fetch_result -> concat into pg_query()
function tp_2sqli_pg_fetch($conn) {
    $result = pg_query($conn, "SELECT hostname FROM servers LIMIT 1");
    $row = pg_fetch_assoc($result);
    $host = $row['hostname'];
    pg_query($conn, "SELECT * FROM logs WHERE host = '" . $host . "'");  // TP
}

// TP-2SQLI-008: PDO fetch -> ->exec()
function tp_2sqli_pdo_exec($pdo) {
    $stmt = $pdo->prepare("SELECT table_name FROM schema_cache WHERE id = ?");
    $stmt->execute([1]);
    $row = $stmt->fetch(PDO::FETCH_ASSOC);
    $table = $row['table_name'];
    $pdo->exec("DROP TABLE " . $table);  // TP
}

// TP-2SQLI-009: fetch_object -> property concat into ->query()
function tp_2sqli_fetch_object($pdo) {
    $stmt = $pdo->query("SELECT description FROM products LIMIT 1");
    $obj = $stmt->fetch_object();
    $desc = $obj->description;
    $pdo->query("INSERT INTO fts (text) VALUES ('" . $desc . "')");  // TP
}

// TP-2SQLI-010: DB-sourced propagation through intermediate variable
function tp_2sqli_propagation($pdo) {
    $stmt = $pdo->prepare("SELECT comment FROM reviews WHERE id = ?");
    $stmt->execute([5]);
    $row = $stmt->fetch(PDO::FETCH_ASSOC);
    $comment = $row['comment'];
    $snippet = $comment;  // propagation
    $pdo->query("SELECT * FROM replies WHERE parent_text = '" . $snippet . "'");  // TP
}

// TP-2SQLI-011: DB data interpolated in double-quoted SQL string
function tp_2sqli_interpolation($pdo) {
    $stmt = $pdo->prepare("SELECT slug FROM pages WHERE id = ?");
    $stmt->execute([10]);
    $row = $stmt->fetch(PDO::FETCH_ASSOC);
    $slug = $row['slug'];
    $pdo->query("SELECT * FROM redirects WHERE old_slug = '$slug'");  // TP
}

// TP-2SQLI-012: PREPARE FROM pattern — server-side dynamic SQL
function tp_2sqli_prepare_from($pdo) {
    $pdo->query("SET @filter = (SELECT filter_expr FROM saved_filters WHERE id = 1)");
    $pdo->query("PREPARE dynstmt FROM CONCAT('SELECT * FROM data WHERE ', @filter)");  // TP
    $pdo->query("EXECUTE dynstmt");
}

// =====================================================================
// 2. SECOND-ORDER SQLi — TRUE NEGATIVES
// =====================================================================

// TN-2SQLI-001: DB fetch used in parameterized query
function tn_2sqli_parameterized($pdo) {
    $stmt = $pdo->prepare("SELECT username FROM users WHERE id = ?");
    $stmt->execute([1]);
    $row = $stmt->fetch(PDO::FETCH_ASSOC);
    $name = $row['username'];

    $stmt2 = $pdo->prepare("SELECT * FROM logs WHERE user = ?");
    $stmt2->execute([$name]);  // TN: parameterized
}

// TN-2SQLI-002: DB fetch used only for display, not in SQL
function tn_2sqli_display_only($pdo) {
    $stmt = $pdo->prepare("SELECT bio FROM profiles WHERE id = ?");
    $stmt->execute([1]);
    $row = $stmt->fetch(PDO::FETCH_ASSOC);
    $bio = $row['bio'];
    echo htmlspecialchars($bio);  // TN: no SQL sink
}

// TN-2SQLI-003: DB fetch cast to int before SQL use
function tn_2sqli_intval($pdo) {
    $stmt = $pdo->prepare("SELECT priority FROM tasks WHERE id = ?");
    $stmt->execute([1]);
    $row = $stmt->fetch(PDO::FETCH_ASSOC);
    $priority = (int)$row['priority'];
    $pdo->query("SELECT * FROM tasks WHERE priority > " . $priority);  // TN: cast to int
}

// TN-2SQLI-004: hardcoded query, no DB-sourced data
function tn_2sqli_hardcoded($pdo) {
    $pdo->query("SELECT * FROM users WHERE active = 1");  // TN: no DB-sourced
}

// TN-2SQLI-005: DB fetch into variable, but variable not used in SQL
function tn_2sqli_unused_in_sql($pdo) {
    $stmt = $pdo->prepare("SELECT avatar_url FROM users WHERE id = ?");
    $stmt->execute([1]);
    $row = $stmt->fetch(PDO::FETCH_ASSOC);
    $avatar = $row['avatar_url'];
    $pdo->query("SELECT COUNT(*) FROM users");  // TN: $avatar not in query
    return $avatar;
}

// TN-2SQLI-006: DB fetch with prepared statement re-use
function tn_2sqli_prepared_reuse($pdo) {
    $stmt = $pdo->prepare("SELECT parent_id FROM categories WHERE id = ?");
    $stmt->execute([5]);
    $row = $stmt->fetch(PDO::FETCH_ASSOC);
    $parentId = $row['parent_id'];

    $stmt2 = $pdo->prepare("SELECT * FROM categories WHERE id = ?");
    $stmt2->execute([$parentId]);  // TN: parameterized
}

// =====================================================================
// 3. SECOND-ORDER DESERIALIZATION — TRUE POSITIVES
// =====================================================================

// TP-2DESER-001: PDO fetch -> unserialize (the ghost.php pattern)
function tp_2deser_pdo_unserialize($pdo) {
    $stmt = $pdo->prepare("SELECT payload FROM jobs WHERE id = ?");
    $stmt->execute([1]);
    $row = $stmt->fetch(PDO::FETCH_ASSOC);
    $obj = unserialize($row['payload']);  // TP
    return $obj;
}

// TP-2DESER-002: mysqli fetch -> unserialize
function tp_2deser_mysqli_unserialize($conn) {
    $result = mysqli_query($conn, "SELECT session_data FROM sessions WHERE id = 'abc'");
    $row = $result->fetch_assoc();
    return unserialize($row['session_data']);  // TP
}

// TP-2DESER-003: DB fetch -> propagation -> unserialize
function tp_2deser_propagation($pdo) {
    $stmt = $pdo->prepare("SELECT config FROM app_settings WHERE id = ?");
    $stmt->execute([1]);
    $row = $stmt->fetch(PDO::FETCH_ASSOC);
    $config = $row['config'];
    $data = $config;  // propagation through intermediate var
    return unserialize($data);  // TP
}

// TP-2DESER-004: DB fetch -> yaml_parse
function tp_2deser_yaml_parse($pdo) {
    $stmt = $pdo->prepare("SELECT yaml_config FROM templates WHERE id = ?");
    $stmt->execute([1]);
    $row = $stmt->fetch(PDO::FETCH_ASSOC);
    $yaml = $row['yaml_config'];
    return yaml_parse($yaml);  // TP
}

// TP-2DESER-005: DB fetch -> igbinary_unserialize
function tp_2deser_igbinary($pdo) {
    $stmt = $pdo->prepare("SELECT binary_data FROM cache WHERE key = ?");
    $stmt->execute(['session']);
    $row = $stmt->fetch(PDO::FETCH_ASSOC);
    return igbinary_unserialize($row['binary_data']);  // TP
}

// TP-2DESER-006: DB fetch -> msgpack_unpack
function tp_2deser_msgpack($pdo) {
    $stmt = $pdo->prepare("SELECT packed FROM messages WHERE id = ?");
    $stmt->execute([1]);
    $row = $stmt->fetch(PDO::FETCH_ASSOC);
    $packed = $row['packed'];
    return msgpack_unpack($packed);  // TP
}

// TP-2DESER-007: DB fetch -> wddx_deserialize
function tp_2deser_wddx($pdo) {
    $stmt = $pdo->prepare("SELECT wddx_packet FROM legacy_data WHERE id = ?");
    $stmt->execute([1]);
    $row = $stmt->fetch(PDO::FETCH_ASSOC);
    return wddx_deserialize($row['wddx_packet']);  // TP
}

// TP-2DESER-008: fetchAll -> loop unserialize
function tp_2deser_fetchall_loop($pdo) {
    $stmt = $pdo->prepare("SELECT serialized FROM queue");
    $stmt->execute();
    $rows = $stmt->fetchAll(PDO::FETCH_ASSOC);
    $objects = [];
    foreach ($rows as $row) {
        $objects[] = unserialize($row['serialized']);  // TP
    }
    return $objects;
}

// TP-2DESER-009: fetchColumn -> unserialize
function tp_2deser_fetchcolumn($pdo) {
    $stmt = $pdo->prepare("SELECT blob FROM storage WHERE id = ?");
    $stmt->execute([42]);
    $blob = $stmt->fetchColumn();
    return unserialize($blob);  // TP
}

// TP-2DESER-010: pg_fetch -> unserialize
function tp_2deser_pg_fetch($conn) {
    $result = pg_query($conn, "SELECT object_data FROM objects LIMIT 1");
    $row = pg_fetch_assoc($result);
    return unserialize($row['object_data']);  // TP
}

// =====================================================================
// 4. SECOND-ORDER DESERIALIZATION — TRUE NEGATIVES
// =====================================================================

// TN-2DESER-001: DB fetch -> json_decode with assoc=true
function tn_2deser_json_assoc($pdo) {
    $stmt = $pdo->prepare("SELECT json_data FROM configs WHERE id = ?");
    $stmt->execute([1]);
    $row = $stmt->fetch(PDO::FETCH_ASSOC);
    return json_decode($row['json_data'], true);  // TN: returns array, not objects
}

// TN-2DESER-002: DB fetch -> unserialize with allowed_classes=false
function tn_2deser_allowed_classes($pdo) {
    $stmt = $pdo->prepare("SELECT data FROM cache WHERE key = ?");
    $stmt->execute(['user_prefs']);
    $row = $stmt->fetch(PDO::FETCH_ASSOC);
    return unserialize($row['data'], ['allowed_classes' => false]);  // TN: mitigated
}

// TN-2DESER-003: hardcoded string -> unserialize (no DB source)
function tn_2deser_hardcoded() {
    $data = 'a:2:{s:4:"name";s:4:"test";s:3:"age";i:25;}';
    return unserialize($data);  // TN: not DB-sourced
}

// TN-2DESER-004: DB fetch used only for display
function tn_2deser_display_only($pdo) {
    $stmt = $pdo->prepare("SELECT serialized FROM objects WHERE id = ?");
    $stmt->execute([1]);
    $row = $stmt->fetch(PDO::FETCH_ASSOC);
    echo "Raw data: " . htmlspecialchars($row['serialized']);  // TN: no deser sink
}

// TN-2DESER-005: DB fetch -> base64_decode only (no unserialize)
function tn_2deser_base64_only($pdo) {
    $stmt = $pdo->prepare("SELECT encoded FROM files WHERE id = ?");
    $stmt->execute([1]);
    $row = $stmt->fetch(PDO::FETCH_ASSOC);
    return base64_decode($row['encoded']);  // TN: base64 is not deserialization
}

// TN-2DESER-006: DB fetch, but unserialize called on unrelated hardcoded data
function tn_2deser_unrelated($pdo) {
    $stmt = $pdo->prepare("SELECT name FROM users WHERE id = ?");
    $stmt->execute([1]);
    $row = $stmt->fetch(PDO::FETCH_ASSOC);
    $name = $row['name'];
    echo $name;
    $defaults = 'a:1:{s:7:"theme";s:5:"light";}';
    return unserialize($defaults);  // TN: unserialize on hardcoded, not DB var
}

// =====================================================================
// 5. MIXED / COMPLEX PATTERNS
// =====================================================================

// TP-MIX-001: DB fetch flows into BOTH SQL and unserialize
function tp_mix_dual_sink($pdo) {
    $stmt = $pdo->prepare("SELECT payload FROM events WHERE id = ?");
    $stmt->execute([1]);
    $row = $stmt->fetch(PDO::FETCH_ASSOC);
    $payload = $row['payload'];

    // Sink 1: SQL injection
    $pdo->query("INSERT INTO event_log (data) VALUES ('" . $payload . "')");  // TP: 2nd-order SQLi

    // Sink 2: deserialization
    $obj = unserialize($payload);  // TP: 2nd-order deser
    return $obj;
}

// TP-MIX-002: Multiple DB fetches, only one flows to sink
function tp_mix_selective($pdo) {
    $stmt1 = $pdo->prepare("SELECT safe_count FROM stats WHERE id = ?");
    $stmt1->execute([1]);
    $safe = $stmt1->fetch(PDO::FETCH_ASSOC);
    $count = $safe['safe_count'];

    $stmt2 = $pdo->prepare("SELECT filter FROM user_filters WHERE id = ?");
    $stmt2->execute([1]);
    $dangerous = $stmt2->fetch(PDO::FETCH_ASSOC);
    $filter = $dangerous['filter'];

    $pdo->query("SELECT * FROM items WHERE " . $filter);  // TP: 2nd-order SQLi from $filter
}

// TP-MIX-003: Class method with DB fetch and unserialize
class CacheManager {
    private $pdo;

    public function __construct($pdo) {
        $this->pdo = $pdo;
    }

    public function loadCachedObject($key) {
        $stmt = $this->pdo->prepare("SELECT value FROM cache WHERE cache_key = ?");
        $stmt->execute([$key]);
        $row = $stmt->fetch(PDO::FETCH_ASSOC);
        if ($row) {
            return unserialize($row['value']);  // TP: 2nd-order deser
        }
        return null;
    }
}

// TN-MIX-001: DB fetch -> intval -> SQL (sanitized)
function tn_mix_sanitized($pdo) {
    $stmt = $pdo->prepare("SELECT ref_id FROM links WHERE id = ?");
    $stmt->execute([1]);
    $row = $stmt->fetch(PDO::FETCH_ASSOC);
    $refId = intval($row['ref_id']);
    $pdo->query("SELECT * FROM items WHERE id = " . $refId);  // TN: intval sanitized
}
