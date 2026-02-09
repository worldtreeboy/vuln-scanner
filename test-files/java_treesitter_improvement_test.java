/**
 * Test suite for java-treesitter.py structural improvements.
 *
 * Each test function targets a specific fix, with expected results in comments:
 *   // EXPECT: FINDING   — scanner MUST report this
 *   // EXPECT: CLEAN     — scanner must NOT report this (false positive check)
 *
 * Improvements tested:
 *   1. Command Injection - hardcoded concat FP fix
 *   2. Taint-killer type conversions (Integer.parseInt, etc.)
 *   3. Partial parameterization false negative fix
 *   4. Enhanced for-loop taint propagation
 *   5. Try-with-resources taint propagation
 *   6. StringBuilder SQL receiver gating
 *   7. @Query annotation detection
 */

import java.sql.*;
import java.util.*;
import java.io.*;
import javax.servlet.http.*;
import org.springframework.data.jpa.repository.*;
import org.springframework.data.repository.query.Param;

// ============================================================================
// 1. Command Injection — hardcoded concat FP fix
// ============================================================================

class CmdInjectionFPTest {

    // EXPECT: CLEAN — hardcoded string concatenation, no tainted data
    public void hardcodedConcatSafe() {
        Runtime.getRuntime().exec("ls" + " -la" + " /tmp");
    }

    // EXPECT: FINDING — tainted data in exec
    public void taintedExec(HttpServletRequest request) {
        String cmd = request.getParameter("cmd");
        Runtime.getRuntime().exec("bash -c " + cmd);
    }

    // EXPECT: FINDING — tainted variable directly
    public void taintedExecVar(HttpServletRequest request) {
        String cmd = request.getParameter("cmd");
        Runtime.getRuntime().exec(cmd);
    }
}


// ============================================================================
// 2. Taint-killer type conversions
// ============================================================================

class TaintKillerTest {

    // EXPECT: CLEAN — parseInt kills taint, result is an int
    public void parseIntKillsTaint(HttpServletRequest request) throws Exception {
        String input = request.getParameter("id");
        int safeId = Integer.parseInt(input);
        Statement stmt = null;
        stmt.executeQuery("SELECT * FROM users WHERE id = " + safeId);
    }

    // EXPECT: CLEAN — parseLong kills taint
    public void parseLongKillsTaint(HttpServletRequest request) throws Exception {
        String input = request.getParameter("id");
        long safeId = Long.parseLong(input);
        Statement stmt = null;
        stmt.executeQuery("SELECT * FROM users WHERE id = " + safeId);
    }

    // EXPECT: CLEAN — UUID.fromString kills taint (fixed format)
    public void uuidKillsTaint(HttpServletRequest request) throws Exception {
        String input = request.getParameter("uuid");
        UUID safeUuid = UUID.fromString(input);
        Statement stmt = null;
        stmt.executeQuery("SELECT * FROM users WHERE uuid = '" + safeUuid + "'");
    }

    // EXPECT: CLEAN — Boolean.parseBoolean kills taint
    public void booleanKillsTaint(HttpServletRequest request) throws Exception {
        String input = request.getParameter("active");
        boolean safe = Boolean.parseBoolean(input);
        Statement stmt = null;
        stmt.executeQuery("SELECT * FROM users WHERE active = " + safe);
    }

    // EXPECT: FINDING — trim() does NOT kill taint, it preserves it
    public void trimPreservesTaint(HttpServletRequest request) throws Exception {
        String input = request.getParameter("name");
        String trimmed = input.trim();
        Statement stmt = null;
        stmt.executeQuery("SELECT * FROM users WHERE name = '" + trimmed + "'");
    }

    // EXPECT: FINDING — toLowerCase does NOT kill taint
    public void toLowerPreservesTaint(HttpServletRequest request) throws Exception {
        String input = request.getParameter("name");
        String lower = input.toLowerCase();
        Statement stmt = null;
        stmt.executeQuery("SELECT * FROM users WHERE name = '" + lower + "'");
    }
}


// ============================================================================
// 3. Partial parameterization false negative fix
// ============================================================================

class PartialParamTest {

    // EXPECT: FINDING — tableName is injected raw, ? only covers id
    public void partialParam(HttpServletRequest request) throws Exception {
        String tableName = request.getParameter("table");
        Connection conn = null;
        conn.prepareStatement("SELECT * FROM " + tableName + " WHERE id = ?");
    }

    // EXPECT: FINDING — orderBy is injected raw, ? covers the value
    public void partialParamOrderBy(HttpServletRequest request) throws Exception {
        String orderBy = request.getParameter("sort");
        Connection conn = null;
        conn.prepareStatement("SELECT * FROM users WHERE id = ? ORDER BY " + orderBy);
    }

    // EXPECT: CLEAN — fully parameterized query, no concatenation
    public void fullyParameterized() throws Exception {
        Connection conn = null;
        conn.prepareStatement("SELECT * FROM users WHERE id = ? AND name = ?");
    }

    // EXPECT: FINDING — tainted variable as query string (still checks _is_parameterized_query)
    public void taintedVarAsQuery(HttpServletRequest request) throws Exception {
        String query = request.getParameter("q");
        Connection conn = null;
        conn.prepareStatement(query);
    }
}


// ============================================================================
// 4. Enhanced for-loop taint propagation
// ============================================================================

class ForEachTaintTest {

    // EXPECT: FINDING — id inherits taint from tainted list via for-each
    public void forEachFromTaintedList(HttpServletRequest request) throws Exception {
        String[] ids = request.getParameterValues("ids");
        Statement stmt = null;
        for (String id : ids) {
            stmt.executeQuery("SELECT * FROM users WHERE id = " + id);
        }
    }

    // EXPECT: FINDING — item inherits taint from tainted collection
    public void forEachFromTaintedCollection(HttpServletRequest request) throws Exception {
        List<String> items = new ArrayList<>();
        items.add(request.getParameter("item"));
        Statement stmt = null;
        for (String item : items) {
            stmt.executeQuery("SELECT * FROM products WHERE name = '" + item + "'");
        }
    }

    // EXPECT: CLEAN — iterating over a hardcoded list
    public void forEachSafe() throws Exception {
        List<String> tables = Arrays.asList("users", "products", "orders");
        Statement stmt = null;
        for (String table : tables) {
            stmt.executeQuery("SELECT COUNT(*) FROM " + table);
        }
    }
}


// ============================================================================
// 5. Try-with-resources taint propagation
// ============================================================================

class TryWithResourcesTest {

    // EXPECT: FINDING — InputStream from request in try-with-resources
    public void taintedTryResource(HttpServletRequest request) throws Exception {
        try (InputStream is = request.getInputStream()) {
            ObjectInputStream ois = new ObjectInputStream(is);
            ois.readObject();
        }
    }

    // EXPECT: FINDING — Reader from request
    public void taintedReader(HttpServletRequest request) throws Exception {
        try (BufferedReader br = request.getReader()) {
            String line = br.readLine();
            Statement stmt = null;
            stmt.executeQuery("SELECT * FROM users WHERE name = '" + line + "'");
        }
    }
}


// ============================================================================
// 6. StringBuilder SQL receiver gating
// ============================================================================

class StringBuilderReceiverTest {

    // EXPECT: FINDING — StringBuilder used in actual SQL method on DB connection
    public void sbInRealSqlMethod(HttpServletRequest request) throws Exception {
        String input = request.getParameter("name");
        StringBuilder sb = new StringBuilder("SELECT * FROM users WHERE name = '");
        sb.append(input);
        sb.append("'");
        Connection conn = null;
        conn.createNativeQuery(sb.toString());
    }

    // EXPECT: CLEAN — execute() on a non-SQL receiver (e.g. task executor)
    // The ambiguous method "execute" should require a SQL receiver pattern
    public void sbInNonSqlExecute(HttpServletRequest request) {
        String input = request.getParameter("task");
        StringBuilder sb = new StringBuilder("task:");
        sb.append(input);
        Runnable taskRunner = null;
        // taskRunner.execute(sb.toString());  // Not a SQL method
    }
}


// ============================================================================
// 7. @Query annotation detection (Spring Data JPA)
// ============================================================================

@Repository
interface UserRepository extends JpaRepository<Object, Long> {

    // EXPECT: CLEAN — properly parameterized with :name
    @Query("SELECT u FROM User u WHERE u.name = :name")
    List<Object> findByNameSafe(@Param("name") String name);

    // EXPECT: CLEAN — properly parameterized with ?1
    @Query("SELECT u FROM User u WHERE u.id = ?1")
    Object findByIdSafe(Long id);
}
