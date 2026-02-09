/**
 * Comprehensive Evasive Vulnerability Test Cases for Java
 * ========================================================
 * Designed to test scanner detection of hard-to-spot patterns across ALL categories:
 * - SQL/NoSQL/HQL Injection (with evasion tricks)
 * - Command Injection (reflection, indirection, arrays)
 * - Code Injection (ScriptEngine, SpEL, OGNL, MVEL, EL, JNDI)
 * - XPath/XQuery Injection
 * - XXE & XSLT Injection
 * - SSTI (Velocity, Freemarker, Thymeleaf, Pebble, JMustache)
 * - Insecure Deserialization (OIS, SnakeYAML, XStream, XMLDecoder, Jackson, Kryo, Hessian)
 * - Expression Language (SpEL, OGNL, MVEL, EL)
 * - Reflection Injection (Class.forName, getMethod, invoke chains)
 *
 * TRUE POSITIVES (TP): Vulnerable code that MUST be detected
 * FALSE POSITIVES (FP): Safe code that MUST NOT be flagged
 * FALSE NEGATIVES (FN): Tricky patterns that scanners commonly miss
 */

import java.io.*;
import java.lang.reflect.*;
import java.net.*;
import java.sql.*;
import java.util.*;
import java.util.Base64;
import javax.naming.*;
import javax.script.*;
import javax.servlet.http.*;
import javax.xml.parsers.*;
import javax.xml.transform.*;
import javax.xml.transform.stream.*;
import javax.xml.xpath.*;
import org.springframework.expression.*;
import org.springframework.expression.spel.standard.*;
import org.springframework.web.bind.annotation.*;
import com.mongodb.client.*;
import org.bson.Document;
import ognl.Ognl;
import org.mvel2.MVEL;
import com.esotericsoftware.kryo.Kryo;
import com.esotericsoftware.kryo.io.Input;
import com.caucho.hessian.io.*;
import org.yaml.snakeyaml.Yaml;
import org.yaml.snakeyaml.constructor.SafeConstructor;
import com.thoughtworks.xstream.XStream;
import freemarker.template.*;
import org.apache.velocity.app.VelocityEngine;
import org.apache.velocity.VelocityContext;

@RestController
@RequestMapping("/api/evasive")
public class EvasiveComprehensiveVulnTest {

    // ==============================================================================
    // SQL INJECTION - EVASIVE PATTERNS
    // ==============================================================================

    // --- TRUE POSITIVES (MUST be detected) ---

    // TP-SQL-1: Tainted var assigned through ternary then used in SQL
    @PostMapping("/sql/ternary")
    public void sqlTernaryInjection(@RequestParam String input, Connection conn) throws SQLException {
        String val = (input != null) ? input : "default";
        String query = "SELECT * FROM users WHERE name = '" + val + "'";
        conn.createStatement().executeQuery(query); // VULNERABLE - tainted through ternary
    }

    // TP-SQL-2: String.replace that doesn't actually sanitize
    @GetMapping("/sql/fake-sanitize")
    public void sqlFakeSanitize(@RequestParam String userId, Connection conn) throws SQLException {
        String cleaned = userId.replace("--", "");  // Weak sanitization, still injectable
        String sql = "SELECT * FROM accounts WHERE id = " + cleaned;
        conn.createStatement().executeQuery(sql); // VULNERABLE - replace doesn't stop injection
    }

    // TP-SQL-3: Multi-step variable reassignment chain
    @PostMapping("/sql/chain")
    public void sqlVariableChain(@RequestParam String raw, Connection conn) throws SQLException {
        String step1 = raw;
        String step2 = step1;
        String step3 = step2.trim();
        String query = "DELETE FROM records WHERE key = '" + step3 + "'";
        conn.prepareStatement(query).executeUpdate(); // VULNERABLE - taint flows through chain
    }

    // TP-SQL-4: HQL injection via createQuery with concat
    @PostMapping("/sql/hql")
    public void hqlInjection(@RequestParam String category, EntityManager em) {
        String hql = "FROM Product p WHERE p.category = '" + category + "'";
        em.createQuery(hql); // VULNERABLE - HQL injection
    }

    // TP-SQL-5: String.format with %s placeholder (not parameterized)
    @GetMapping("/sql/format")
    public void sqlStringFormat(@RequestParam String email, Connection conn) throws SQLException {
        String q = String.format("SELECT * FROM users WHERE email = '%s'", email);
        conn.createStatement().executeQuery(q); // VULNERABLE - String.format is not parameterized
    }

    // TP-SQL-6: StringBuilder built across multiple lines
    @PostMapping("/sql/builder")
    public void sqlStringBuilder(@RequestParam String table, Connection conn) throws SQLException {
        StringBuilder sb = new StringBuilder();
        sb.append("SELECT * FROM ");
        sb.append(table);
        sb.append(" WHERE active = 1");
        conn.createStatement().executeQuery(sb.toString()); // VULNERABLE - tainted table name
    }

    // TP-SQL-7: concat() method instead of + operator
    @GetMapping("/sql/concat-method")
    public void sqlConcatMethod(@RequestParam String col, Connection conn) throws SQLException {
        String q = "SELECT ".concat(col).concat(" FROM users");
        conn.createStatement().executeQuery(q); // VULNERABLE - concat() propagates taint
    }

    // TP-SQL-8: Second-order SQLi - data from DB used unsafely
    @PostMapping("/sql/second-order")
    public void sqlSecondOrder(Connection conn, long id) throws SQLException {
        // Phase 1: fetch stored data from DB
        ResultSet rs = conn.createStatement().executeQuery("SELECT name FROM templates WHERE id = " + id);
        String templateName = rs.getString("name");  // DB-sourced

        // Phase 2: use in another query without parameterization
        String sql = "SELECT * FROM reports WHERE template = '" + templateName + "'";
        conn.createStatement().executeQuery(sql); // VULNERABLE - second-order SQLi
    }

    // --- FALSE POSITIVES (MUST NOT be flagged) ---

    // FP-SQL-1: PreparedStatement with ? placeholder
    @GetMapping("/sql/safe/prepared")
    public void sqlSafePrepared(@RequestParam String name, Connection conn) throws SQLException {
        PreparedStatement ps = conn.prepareStatement("SELECT * FROM users WHERE name = ?");
        ps.setString(1, name);
        ps.executeQuery(); // SAFE - parameterized
    }

    // FP-SQL-2: Named parameter in JPA
    @GetMapping("/sql/safe/named")
    public void sqlSafeNamed(@RequestParam String status, EntityManager em) {
        em.createQuery("FROM User u WHERE u.status = :status")
          .setParameter("status", status); // SAFE - named parameter
    }

    // FP-SQL-3: Constant-only concatenation (no user input)
    public void sqlConstantConcat(Connection conn) throws SQLException {
        String table = "audit_log";
        String query = "SELECT * FROM " + table + " WHERE archived = false";
        conn.createStatement().executeQuery(query); // SAFE - only constants
    }

    // ==============================================================================
    // NOSQL INJECTION - EVASIVE PATTERNS
    // ==============================================================================

    // --- TRUE POSITIVES ---

    // TP-NOSQL-1: MongoDB Document.parse with tainted JSON string
    @PostMapping("/nosql/parse")
    public void nosqlDocParse(@RequestParam String filter, MongoCollection<Document> coll) {
        Document query = Document.parse(filter);
        coll.find(query); // VULNERABLE - user controls the entire query document
    }

    // TP-NOSQL-2: $where operator with user data
    @PostMapping("/nosql/where")
    public void nosqlWhereInjection(@RequestParam String jsExpr, MongoCollection<Document> coll) {
        Document query = new Document("$where", jsExpr);
        coll.find(query); // VULNERABLE - $where executes JavaScript
    }

    // TP-NOSQL-3: String concatenation to build JSON query
    @GetMapping("/nosql/concat")
    public void nosqlConcatQuery(@RequestParam String username, MongoCollection<Document> coll) {
        String jsonQuery = "{\"username\": \"" + username + "\"}";
        Document query = Document.parse(jsonQuery);
        coll.find(query); // VULNERABLE - injectable JSON
    }

    // ==============================================================================
    // COMMAND INJECTION - EVASIVE PATTERNS
    // ==============================================================================

    // --- TRUE POSITIVES ---

    // TP-CMD-1: Runtime.exec with string concatenation
    @PostMapping("/cmd/exec")
    public void cmdRuntimeExec(@RequestParam String filename) throws Exception {
        Runtime.getRuntime().exec("cat /tmp/" + filename); // VULNERABLE
    }

    // TP-CMD-2: ProcessBuilder with tainted list
    @PostMapping("/cmd/process-builder")
    public void cmdProcessBuilder(@RequestParam String host) throws Exception {
        List<String> cmd = new ArrayList<>();
        cmd.add("ping");
        cmd.add("-c");
        cmd.add("4");
        cmd.add(host);
        new ProcessBuilder(cmd).start(); // VULNERABLE - tainted host in command args
    }

    // TP-CMD-3: Reflection-based exec invocation
    @PostMapping("/cmd/reflection-exec")
    public void cmdReflectionExec(@RequestParam String command) throws Exception {
        Class<?> runtimeClass = Class.forName("java.lang.Runtime");
        Method getRuntimeMethod = runtimeClass.getMethod("getRuntime");
        Object runtime = getRuntimeMethod.invoke(null);
        Method execMethod = runtime.getClass().getMethod("exec", String.class);
        execMethod.invoke(runtime, command); // VULNERABLE - reflection-based command injection
    }

    // TP-CMD-4: ProcessBuilder via array construction
    @PostMapping("/cmd/array")
    public void cmdArrayExec(@RequestParam String target) throws Exception {
        String[] cmd = {"/bin/sh", "-c", "nslookup " + target};
        new ProcessBuilder(cmd).start(); // VULNERABLE - tainted in shell command
    }

    // --- FALSE POSITIVES ---

    // FP-CMD-1: Hardcoded command, no user input
    public void cmdSafeHardcoded() throws Exception {
        Runtime.getRuntime().exec("ls -la /var/log"); // SAFE - hardcoded
    }

    // ==============================================================================
    // CODE INJECTION - ScriptEngine, SpEL, OGNL, MVEL, EL, JNDI
    // ==============================================================================

    // --- TRUE POSITIVES ---

    // TP-CODE-1: ScriptEngine.eval with tainted Groovy script
    @PostMapping("/code/groovy")
    public void codeGroovyEval(@RequestParam String groovyCode) throws Exception {
        ScriptEngine engine = new ScriptEngineManager().getEngineByName("groovy");
        engine.eval(groovyCode); // VULNERABLE - arbitrary Groovy execution
    }

    // TP-CODE-2: Nashorn ScriptEngine with tainted JS via variable chain
    @PostMapping("/code/nashorn")
    public void codeNashornEval(@RequestParam String expr) throws Exception {
        ScriptEngineManager mgr = new ScriptEngineManager();
        ScriptEngine js = mgr.getEngineByName("nashorn");
        String script = "var result = " + expr;
        js.eval(script); // VULNERABLE - tainted concatenation into eval
    }

    // TP-CODE-3: SpEL injection via ExpressionParser
    @PostMapping("/code/spel")
    public void codeSpelInjection(@RequestParam String expression) {
        ExpressionParser parser = new SpelExpressionParser();
        Expression exp = parser.parseExpression(expression); // VULNERABLE - tainted SpEL
        exp.getValue();
    }

    // TP-CODE-4: SpEL with StandardEvaluationContext (full power)
    @PostMapping("/code/spel-context")
    public void codeSpelContext(@RequestParam String userExpr) {
        SpelExpressionParser parser = new SpelExpressionParser();
        StandardEvaluationContext ctx = new StandardEvaluationContext();
        ctx.setVariable("input", "test");
        parser.parseExpression(userExpr).getValue(ctx); // VULNERABLE - SpEL with full context
    }

    // TP-CODE-5: OGNL injection
    @PostMapping("/code/ognl")
    public void codeOgnlInjection(@RequestParam String ognlExpr) throws Exception {
        Map<String, Object> context = new HashMap<>();
        Object value = Ognl.getValue(ognlExpr, context); // VULNERABLE - OGNL RCE
    }

    // TP-CODE-6: MVEL injection
    @PostMapping("/code/mvel")
    public void codeMvelInjection(@RequestParam String mvelExpr) {
        Object result = MVEL.eval(mvelExpr); // VULNERABLE - MVEL code execution
    }

    // TP-CODE-7: EL injection via ELProcessor
    @PostMapping("/code/el")
    public void codeElInjection(@RequestParam String elExpr) throws Exception {
        javax.el.ELProcessor elProcessor = new javax.el.ELProcessor();
        elProcessor.eval(elExpr); // VULNERABLE - EL injection
    }

    // TP-CODE-8: JNDI lookup with tainted data (Log4Shell-style)
    @PostMapping("/code/jndi")
    public void codeJndiInjection(@RequestParam String resource) throws Exception {
        InitialContext ctx = new InitialContext();
        ctx.lookup(resource); // VULNERABLE - JNDI injection -> RCE
    }

    // TP-CODE-9: JNDI via variable indirection
    @GetMapping("/code/jndi-indirect")
    public void codeJndiIndirect(@RequestParam String url) throws Exception {
        String jndiName = "ldap://" + url + "/exploit";
        Context ctx = new InitialContext();
        ctx.lookup(jndiName); // VULNERABLE - constructed JNDI URL
    }

    // TP-CODE-10: Base64-decoded script to ScriptEngine
    @PostMapping("/code/base64-eval")
    public void codeBase64Eval(@RequestParam String encoded) throws Exception {
        byte[] decoded = Base64.getDecoder().decode(encoded);
        String script = new String(decoded);
        ScriptEngine engine = new ScriptEngineManager().getEngineByName("javascript");
        engine.eval(script); // VULNERABLE - Base64 bypass
    }

    // TP-CODE-11: ScriptEngine eval with Reader from user input
    @PostMapping("/code/reader-eval")
    public void codeReaderEval(HttpServletRequest request) throws Exception {
        ScriptEngine engine = new ScriptEngineManager().getEngineByName("js");
        engine.eval(new InputStreamReader(request.getInputStream())); // VULNERABLE - stream eval
    }

    // --- FALSE POSITIVES ---

    // FP-CODE-1: Hardcoded safe script
    public void codeSafeHardcoded() throws Exception {
        ScriptEngine engine = new ScriptEngineManager().getEngineByName("javascript");
        engine.eval("var x = 1 + 2;"); // SAFE - hardcoded
    }

    // FP-CODE-2: SpEL with only constant expression
    public void codeSafeSpel() {
        ExpressionParser parser = new SpelExpressionParser();
        parser.parseExpression("'Hello World'"); // SAFE - constant expression
    }

    // ==============================================================================
    // XPATH / XQUERY INJECTION - EVASIVE PATTERNS
    // ==============================================================================

    // --- TRUE POSITIVES ---

    // TP-XPATH-1: XPath evaluate with string concat
    @GetMapping("/xpath/eval")
    public void xpathEvalInjection(@RequestParam String username) throws Exception {
        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
        factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
        org.w3c.dom.Document doc = factory.newDocumentBuilder().parse("users.xml");
        XPath xpath = XPathFactory.newInstance().newXPath();
        String expr = "//user[@name='" + username + "']";
        xpath.evaluate(expr, doc, XPathConstants.NODESET); // VULNERABLE - XPath injection
    }

    // TP-XPATH-2: XPath compile with tainted expression
    @PostMapping("/xpath/compile")
    public void xpathCompileInjection(@RequestParam String field) throws Exception {
        XPath xpath = XPathFactory.newInstance().newXPath();
        String expression = "/data/record[" + field + "]";
        xpath.compile(expression); // VULNERABLE - XPath injection via compile
    }

    // TP-XPATH-3: XPath with tainted variable (no string literal)
    @GetMapping("/xpath/var")
    public void xpathVariableInjection(@RequestParam String query) throws Exception {
        XPath xpath = XPathFactory.newInstance().newXPath();
        xpath.evaluate(query, new org.xml.sax.InputSource("data.xml")); // VULNERABLE - full XPath control
    }

    // TP-XPATH-4: XPath via String.format
    @PostMapping("/xpath/format")
    public void xpathFormatInjection(@RequestParam String id) throws Exception {
        XPath xpath = XPathFactory.newInstance().newXPath();
        String expr = String.format("//item[@id='%s']", id);
        xpath.evaluate(expr, new org.xml.sax.InputSource("items.xml")); // VULNERABLE - String.format XPath
    }

    // --- FALSE POSITIVES ---

    // FP-XPATH-1: XPath with hardcoded expression
    public void xpathSafeHardcoded() throws Exception {
        XPath xpath = XPathFactory.newInstance().newXPath();
        xpath.evaluate("//config/setting[@name='version']", new org.xml.sax.InputSource("config.xml")); // SAFE
    }

    // ==============================================================================
    // XXE & XSLT INJECTION
    // ==============================================================================

    // --- TRUE POSITIVES ---

    // TP-XXE-1: DocumentBuilderFactory without security features
    @PostMapping("/xxe/basic")
    public void xxeBasic(HttpServletRequest request) throws Exception {
        DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
        // No setFeature calls -> XXE vulnerable
        dbf.newDocumentBuilder().parse(request.getInputStream()); // VULNERABLE - XXE
    }

    // TP-XXE-2: SAXParserFactory without entity disabling
    @PostMapping("/xxe/sax")
    public void xxeSax(HttpServletRequest request) throws Exception {
        SAXParserFactory spf = SAXParserFactory.newInstance();
        // Missing: spf.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
        spf.newSAXParser().parse(request.getInputStream(), new org.xml.sax.helpers.DefaultHandler()); // VULNERABLE
    }

    // TP-XXE-3: XMLInputFactory without IS_SUPPORTING_EXTERNAL_ENTITIES=false
    @PostMapping("/xxe/stax")
    public void xxeStax(HttpServletRequest request) throws Exception {
        javax.xml.stream.XMLInputFactory xif = javax.xml.stream.XMLInputFactory.newInstance();
        // Missing: xif.setProperty(XMLInputFactory.IS_SUPPORTING_EXTERNAL_ENTITIES, false);
        xif.createXMLStreamReader(request.getInputStream()); // VULNERABLE - XXE via StAX
    }

    // TP-XXE-4: TransformerFactory without secure processing
    @PostMapping("/xxe/xslt")
    public void xxeXslt(HttpServletRequest request) throws Exception {
        TransformerFactory tf = TransformerFactory.newInstance();
        // Missing: tf.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);
        StreamSource xslt = new StreamSource(request.getInputStream());
        tf.newTransformer(xslt); // VULNERABLE - XSLT injection / XXE (detected at factory creation line)
    }

    // TP-XXE-5: SchemaFactory without secure processing
    @PostMapping("/xxe/schema")
    public void xxeSchema(HttpServletRequest request) throws Exception {
        javax.xml.validation.SchemaFactory sf = javax.xml.validation.SchemaFactory.newInstance(
            javax.xml.XMLConstants.W3C_XML_SCHEMA_NS_URI);
        // Missing: sf.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);
        sf.newSchema(new StreamSource(request.getInputStream())); // VULNERABLE - XXE (detected at factory creation line)
    }

    // --- FALSE POSITIVES ---

    // FP-XXE-1: DocumentBuilderFactory with disallow-doctype-decl
    @PostMapping("/xxe/safe")
    public void xxeSafe(HttpServletRequest request) throws Exception {
        DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
        dbf.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
        dbf.newDocumentBuilder().parse(request.getInputStream()); // SAFE - XXE disabled
    }

    // FP-XXE-2: SAXParserFactory with external entities disabled
    @PostMapping("/xxe/sax/safe")
    public void xxeSaxSafe(HttpServletRequest request) throws Exception {
        SAXParserFactory spf = SAXParserFactory.newInstance();
        spf.setFeature("http://xml.org/sax/features/external-general-entities", false);
        spf.newSAXParser().parse(request.getInputStream(), new org.xml.sax.helpers.DefaultHandler()); // SAFE
    }

    // FP-XXE-3: XMLInputFactory with external entities disabled
    @PostMapping("/xxe/stax/safe")
    public void xxeStaxSafe(HttpServletRequest request) throws Exception {
        javax.xml.stream.XMLInputFactory xif = javax.xml.stream.XMLInputFactory.newInstance();
        xif.setProperty(javax.xml.stream.XMLInputFactory.IS_SUPPORTING_EXTERNAL_ENTITIES, false);
        xif.createXMLStreamReader(request.getInputStream()); // SAFE
    }

    // ==============================================================================
    // SSTI - SERVER-SIDE TEMPLATE INJECTION
    // ==============================================================================

    // --- TRUE POSITIVES ---

    // TP-SSTI-1: Velocity with tainted template string
    @PostMapping("/ssti/velocity")
    public void sstiVelocity(@RequestParam String template) {
        VelocityEngine engine = new VelocityEngine();
        VelocityContext context = new VelocityContext();
        StringWriter writer = new StringWriter();
        engine.evaluate(context, writer, "tag", template); // VULNERABLE - tainted Velocity template
    }

    // TP-SSTI-2: Freemarker with tainted template via StringReader
    @PostMapping("/ssti/freemarker")
    public void sstiFreemarker(@RequestParam String templateStr) throws Exception {
        Configuration cfg = new Configuration(Configuration.VERSION_2_3_31);
        Template tpl = new Template("user_template", new StringReader(templateStr), cfg);
        tpl.process(new HashMap<>(), new StringWriter()); // VULNERABLE - tainted Freemarker template
    }

    // TP-SSTI-3: Thymeleaf with tainted template name
    @PostMapping("/ssti/thymeleaf")
    public void sstiThymeleaf(@RequestParam String templateContent) {
        org.thymeleaf.TemplateEngine templateEngine = new org.thymeleaf.TemplateEngine();
        org.thymeleaf.context.Context ctx = new org.thymeleaf.context.Context();
        templateEngine.process(templateContent, ctx); // VULNERABLE - tainted template
    }

    // TP-SSTI-4: Velocity via concatenated template
    @PostMapping("/ssti/velocity-concat")
    public void sstiVelocityConcat(@RequestParam String name) {
        VelocityEngine engine = new VelocityEngine();
        VelocityContext ctx = new VelocityContext();
        StringWriter w = new StringWriter();
        String tmpl = "Hello " + name + "! Welcome.";
        engine.evaluate(ctx, w, "log", tmpl); // VULNERABLE - tainted data in Velocity template
    }

    // TP-SSTI-5: Pebble template with user-controlled string
    @PostMapping("/ssti/pebble")
    public void sstiPebble(@RequestParam String tpl) throws Exception {
        com.mitchellbosecke.pebble.PebbleEngine pebble = new com.mitchellbosecke.pebble.PebbleEngine.Builder().build();
        com.mitchellbosecke.pebble.template.PebbleTemplate compiledTemplate = pebble.getLiteralTemplate(tpl);
        compiledTemplate.evaluate(new StringWriter()); // VULNERABLE - user controls template
    }

    // TP-SSTI-6: JMustache with tainted template
    @PostMapping("/ssti/mustache")
    public void sstiMustache(@RequestParam String templateSource) throws Exception {
        com.samskivert.mustache.Mustache.compiler().compile(templateSource)
            .execute(new HashMap<>(), new StringWriter()); // VULNERABLE - user controls template
    }

    // --- FALSE POSITIVES ---

    // FP-SSTI-1: Velocity with hardcoded template
    public void sstiSafeVelocity() {
        VelocityEngine engine = new VelocityEngine();
        VelocityContext ctx = new VelocityContext();
        engine.evaluate(ctx, new StringWriter(), "tag", "Hello $name!"); // SAFE - hardcoded
    }

    // ==============================================================================
    // INSECURE DESERIALIZATION - EVASIVE PATTERNS
    // ==============================================================================

    // --- TRUE POSITIVES ---

    // TP-DESER-1: ObjectInputStream from HTTP request stream
    @PostMapping("/deser/ois")
    public void deserOIS(HttpServletRequest request) throws Exception {
        ObjectInputStream ois = new ObjectInputStream(request.getInputStream());
        Object obj = ois.readObject(); // VULNERABLE - untrusted deserialization
    }

    // TP-DESER-2: OIS via ByteArrayInputStream from Base64 decoded user data
    @PostMapping("/deser/base64-ois")
    public void deserBase64OIS(@RequestParam String data) throws Exception {
        byte[] bytes = Base64.getDecoder().decode(data);
        ByteArrayInputStream bais = new ByteArrayInputStream(bytes);
        ObjectInputStream ois = new ObjectInputStream(bais);
        ois.readObject(); // VULNERABLE - deserialization of Base64-encoded user data
    }

    // TP-DESER-3: readUnshared (alternative to readObject)
    @PostMapping("/deser/unshared")
    public void deserReadUnshared(HttpServletRequest request) throws Exception {
        ObjectInputStream ois = new ObjectInputStream(request.getInputStream());
        ois.readUnshared(); // VULNERABLE - readUnshared is equally dangerous
    }

    // TP-DESER-4: SnakeYAML without SafeConstructor
    @PostMapping("/deser/snakeyaml")
    public void deserSnakeYaml(@RequestParam String yamlData) {
        Yaml yaml = new Yaml(); // DANGEROUS - no SafeConstructor
        Object obj = yaml.load(yamlData); // VULNERABLE - arbitrary class instantiation
    }

    // TP-DESER-5: XStream without security configuration
    @PostMapping("/deser/xstream")
    public void deserXStream(@RequestParam String xml) {
        XStream xstream = new XStream();
        // No security: xstream.allowTypes(...) or xstream.setupDefaultSecurity(...)
        Object obj = xstream.fromXML(xml); // VULNERABLE - XStream RCE
    }

    // TP-DESER-6: XMLDecoder with user input
    @PostMapping("/deser/xmldecoder")
    public void deserXmlDecoder(HttpServletRequest request) throws Exception {
        XMLDecoder decoder = new XMLDecoder(request.getInputStream()); // VULNERABLE
        Object obj = decoder.readObject(); // VULNERABLE - XMLDecoder executes arbitrary methods
    }

    // TP-DESER-7: Jackson with enableDefaultTyping
    @PostMapping("/deser/jackson")
    public void deserJackson() {
        com.fasterxml.jackson.databind.ObjectMapper mapper =
            new com.fasterxml.jackson.databind.ObjectMapper();
        mapper.enableDefaultTyping(); // VULNERABLE - polymorphic deserialization
    }

    // TP-DESER-8: Kryo without registration required
    @PostMapping("/deser/kryo")
    public void deserKryo(@RequestParam String data) throws Exception {
        Kryo kryo = new Kryo();
        // Missing: kryo.setRegistrationRequired(true);
        byte[] bytes = Base64.getDecoder().decode(data);
        Input input = new Input(new ByteArrayInputStream(bytes));
        kryo.readClassAndObject(input); // VULNERABLE - arbitrary class instantiation
    }

    // TP-DESER-9: Hessian deserialization
    @PostMapping("/deser/hessian")
    public void deserHessian(HttpServletRequest request) throws Exception {
        HessianInput hessianInput = new HessianInput(request.getInputStream());
        Object obj = hessianInput.readObject(); // VULNERABLE - Hessian deserialization
    }

    // TP-DESER-10: Hessian2 deserialization
    @PostMapping("/deser/hessian2")
    public void deserHessian2(HttpServletRequest request) throws Exception {
        Hessian2Input hessian2 = new Hessian2Input(request.getInputStream());
        hessian2.readObject(); // VULNERABLE - Hessian2 deserialization
    }

    // TP-DESER-11: BurlapInput deserialization
    @PostMapping("/deser/burlap")
    public void deserBurlap(HttpServletRequest request) throws Exception {
        BurlapInput burlap = new BurlapInput(request.getInputStream());
        burlap.readObject(); // VULNERABLE - Burlap deserialization
    }

    // TP-DESER-12: OIS from Socket (network source)
    @PostMapping("/deser/socket")
    public void deserFromSocket(@RequestParam String host, @RequestParam int port) throws Exception {
        Socket socket = new Socket(host, port);
        ObjectInputStream ois = new ObjectInputStream(socket.getInputStream());
        ois.readObject(); // VULNERABLE - untrusted network deserialization
    }

    // TP-DESER-13: OIS via URL connection stream
    @PostMapping("/deser/url")
    public void deserFromUrl(@RequestParam String url) throws Exception {
        URL u = new URL(url);
        ObjectInputStream ois = new ObjectInputStream(u.openStream());
        ois.readObject(); // VULNERABLE - deserialization from remote URL
    }

    // --- FALSE POSITIVES ---

    // FP-DESER-1: SnakeYAML with SafeConstructor
    @PostMapping("/deser/safe/yaml")
    public void deserSafeYaml(@RequestParam String yamlData) {
        Yaml yaml = new Yaml(new SafeConstructor());
        yaml.load(yamlData); // SAFE - SafeConstructor prevents arbitrary class instantiation
    }

    // FP-DESER-2: Kryo with registration required
    @PostMapping("/deser/safe/kryo")
    public void deserSafeKryo(@RequestParam String data) throws Exception {
        Kryo kryo = new Kryo();
        kryo.setRegistrationRequired(true); // Safe - only registered classes
        byte[] bytes = Base64.getDecoder().decode(data);
        Input input = new Input(new ByteArrayInputStream(bytes));
        kryo.readClassAndObject(input); // SAFE - whitelist only
    }

    // FP-DESER-3: ValidatingObjectInputStream
    @PostMapping("/deser/safe/validating")
    public void deserSafeValidating(HttpServletRequest request) throws Exception {
        org.apache.commons.io.serialization.ValidatingObjectInputStream vois =
            new org.apache.commons.io.serialization.ValidatingObjectInputStream(request.getInputStream());
        vois.accept("com.myapp.model.*");
        vois.readObject(); // SAFE - whitelist validation
    }

    // FP-DESER-4: OIS with ObjectInputFilter (Java 9+)
    @PostMapping("/deser/safe/filter")
    public void deserSafeFilter(HttpServletRequest request) throws Exception {
        ObjectInputStream ois = new ObjectInputStream(request.getInputStream());
        ois.setObjectInputFilter(info ->
            info.serialClass() != null && info.serialClass().getPackageName().startsWith("com.myapp")
                ? ObjectInputFilter.Status.ALLOWED
                : ObjectInputFilter.Status.REJECTED);
        ois.readObject(); // SAFE - ObjectInputFilter configured
    }

    // FP-DESER-5: XStream with security
    @PostMapping("/deser/safe/xstream")
    public void deserSafeXStream(@RequestParam String xml) {
        XStream xstream = new XStream();
        xstream.allowTypes(new Class[]{com.myapp.model.User.class});
        xstream.fromXML(xml); // SAFE - restricted types
    }

    // ==============================================================================
    // EXPRESSION LANGUAGE INJECTION - DEEP PATTERNS
    // ==============================================================================

    // --- TRUE POSITIVES ---

    // TP-EL-1: SpEL via reflection-like pattern (parser stored in variable)
    @PostMapping("/el/spel-var")
    public void elSpelVariable(@RequestParam String input) {
        ExpressionParser p = new SpelExpressionParser();
        String expr = "T(java.lang.Runtime).getRuntime().exec('" + input + "')";
        p.parseExpression(expr); // VULNERABLE - constructed SpEL with tainted data
    }

    // TP-EL-2: OGNL via OgnlUtil (Struts2-style)
    @PostMapping("/el/ognl-util")
    public void elOgnlUtil(@RequestParam String action) throws Exception {
        Object tree = Ognl.parseExpression(action);
        Map context = Ognl.createDefaultContext(this);
        Ognl.getValue(tree, context, this); // VULNERABLE - OGNL from parsed expression
    }

    // TP-EL-3: MVEL compiled expression with tainted input
    @PostMapping("/el/mvel-compiled")
    public void elMvelCompiled(@RequestParam String rule) {
        Serializable compiled = MVEL.compileExpression(rule);
        MVEL.executeExpression(compiled); // VULNERABLE - compiled MVEL expression
    }

    // TP-EL-4: EL via ValueExpression
    @PostMapping("/el/value-expr")
    public void elValueExpression(@RequestParam String expr) throws Exception {
        javax.el.ExpressionFactory ef = javax.el.ExpressionFactory.newInstance();
        javax.el.ELContext elCtx = new javax.el.StandardELContext(ef);
        ef.createValueExpression(elCtx, expr, Object.class); // VULNERABLE - tainted EL expression
    }

    // --- FALSE POSITIVES ---

    // FP-EL-1: SpEL with hardcoded safe expression
    public void elSafeSpel() {
        SpelExpressionParser parser = new SpelExpressionParser();
        parser.parseExpression("#root.name"); // SAFE - hardcoded
    }

    // ==============================================================================
    // REFLECTION INJECTION
    // ==============================================================================

    // --- TRUE POSITIVES ---

    // TP-REFLECT-1: Class.forName with user-controlled class name
    @PostMapping("/reflect/forname")
    public void reflectForName(@RequestParam String className) throws Exception {
        Class<?> clazz = Class.forName(className); // VULNERABLE - arbitrary class loading
        Object instance = clazz.getDeclaredConstructor().newInstance();
    }

    // TP-REFLECT-2: getMethod("exec") for Runtime exec
    @PostMapping("/reflect/getmethod-exec")
    public void reflectGetMethodExec(@RequestParam String cmd) throws Exception {
        Class<?> rt = Class.forName("java.lang.Runtime");
        Method getRuntime = rt.getMethod("getRuntime");
        Object runtime = getRuntime.invoke(null);
        Method exec = runtime.getClass().getMethod("exec", String.class);
        exec.invoke(runtime, cmd); // VULNERABLE - reflected exec
    }

    // TP-REFLECT-3: Method.invoke with tainted receiver/target
    @PostMapping("/reflect/invoke")
    public void reflectInvoke(@RequestParam String methodName, @RequestParam String className) throws Exception {
        Class<?> clazz = Class.forName(className); // VULNERABLE - tainted class
        Method m = clazz.getMethod(methodName); // Tainted method name
        m.invoke(clazz.getDeclaredConstructor().newInstance());
    }

    // TP-REFLECT-4: Class.forName from decoded Base64
    @PostMapping("/reflect/base64")
    public void reflectBase64(@RequestParam String encoded) throws Exception {
        String className = new String(Base64.getDecoder().decode(encoded));
        Class<?> clazz = Class.forName(className); // VULNERABLE - obfuscated class loading
        clazz.getDeclaredConstructor().newInstance();
    }

    // TP-REFLECT-5: Reflection chained through multiple variables
    @PostMapping("/reflect/chain")
    public void reflectChain(@RequestParam String target) throws Exception {
        String pkg = "java.lang.";
        String fullClass = pkg + target;
        Class<?> c = Class.forName(fullClass); // VULNERABLE - tainted via concat
    }

    // --- FALSE POSITIVES ---

    // FP-REFLECT-1: Class.forName with hardcoded class
    public void reflectSafeHardcoded() throws Exception {
        Class<?> clazz = Class.forName("java.util.ArrayList"); // SAFE - hardcoded
        clazz.getDeclaredConstructor().newInstance();
    }

    // ==============================================================================
    // COMBINED ATTACK CHAINS - MULTI-STAGE EXPLOITS
    // ==============================================================================

    // TP-CHAIN-1: Base64 decode -> OIS deserialization -> RCE
    @PostMapping("/chain/deser-rce")
    public void chainDeserRce(@RequestParam String payload) throws Exception {
        byte[] decoded = Base64.getDecoder().decode(payload);
        ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(decoded));
        Object gadget = ois.readObject(); // VULNERABLE - deserialization gadget chain
    }

    // TP-CHAIN-2: DB fetch -> OGNL eval (second-order code injection)
    @PostMapping("/chain/db-ognl")
    public void chainDbOgnl(EntityManager em) throws Exception {
        String rule = em.find(String.class, 1L); // DB-sourced
        Map ctx = Ognl.createDefaultContext(this);
        Ognl.getValue(rule, ctx, this); // VULNERABLE - second-order OGNL injection
    }

    // TP-CHAIN-3: HTTP header -> StringBuilder -> SQL injection
    @PostMapping("/chain/header-sqli")
    public void chainHeaderSqli(HttpServletRequest request, Connection conn) throws SQLException {
        String userAgent = request.getHeader("User-Agent");
        StringBuilder sb = new StringBuilder("INSERT INTO access_log (ua) VALUES ('");
        sb.append(userAgent);
        sb.append("')");
        conn.createStatement().executeUpdate(sb.toString()); // VULNERABLE - header injection
    }

    // TP-CHAIN-4: Cookie value -> XPath injection
    @PostMapping("/chain/cookie-xpath")
    public void chainCookieXpath(HttpServletRequest request) throws Exception {
        String token = request.getHeader("X-Auth-Token");
        XPath xpath = XPathFactory.newInstance().newXPath();
        String expr = "//session[@token='" + token + "']/user";
        xpath.evaluate(expr, new org.xml.sax.InputSource("sessions.xml")); // VULNERABLE
    }

    // TP-CHAIN-5: URL parameter -> XSLT injection via TransformerFactory
    @PostMapping("/chain/xslt")
    public void chainXsltInjection(@RequestParam String stylesheet) throws Exception {
        TransformerFactory tf = TransformerFactory.newInstance();
        StreamSource xsltSource = new StreamSource(new StringReader(stylesheet));
        tf.newTransformer(xsltSource); // VULNERABLE - XSLT injection + XXE
    }

    // TP-CHAIN-6: Request body -> ScriptEngine (polyglot)
    @PostMapping("/chain/polyglot")
    public void chainPolyglot(@RequestBody String code, @RequestParam String lang) throws Exception {
        ScriptEngine engine = new ScriptEngineManager().getEngineByName(lang);
        engine.eval(code); // VULNERABLE - user picks language AND code
    }
}
