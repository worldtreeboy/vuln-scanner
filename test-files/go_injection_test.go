package main

import (
	"database/sql"
	"encoding/gob"
	"encoding/xml"
	"fmt"
	"html"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"text/template"

	"github.com/gin-gonic/gin"
	"github.com/jmoiron/sqlx"
	ldap "github.com/go-ldap/ldap/v3"
	"go.mongodb.org/mongo-driver/mongo"
	"gopkg.in/yaml.v3"
	"gorm.io/gorm"
)

// =============================================================================
// TRUE POSITIVES — Should be detected
// =============================================================================

// TP1: SQL Injection — db.Query with string concatenation
func handleSQLi1(w http.ResponseWriter, r *http.Request) {
	id := r.FormValue("id")
	query := "SELECT * FROM users WHERE id = '" + id + "'"
	db, _ := sql.Open("postgres", "")
	db.Query(query)
}

// TP2: SQL Injection — fmt.Sprintf in db.Exec
func handleSQLi2(w http.ResponseWriter, r *http.Request) {
	name := r.FormValue("name")
	query := fmt.Sprintf("DELETE FROM users WHERE name = '%s'", name)
	db, _ := sql.Open("postgres", "")
	db.Exec(query)
}

// TP3: SQL Injection — GORM db.Raw()
func handleGORMRaw(w http.ResponseWriter, r *http.Request) {
	search := r.FormValue("search")
	db := &gorm.DB{}
	query := "SELECT * FROM products WHERE name LIKE '%" + search + "%'"
	db.Raw(query)
}

// TP4: SQL Injection — GORM db.Where() with string concatenation
func handleGORMWhere(w http.ResponseWriter, r *http.Request) {
	status := r.FormValue("status")
	db := &gorm.DB{}
	db.Where("status = '" + status + "'")
}

// TP5: Command Injection — exec.Command with shell invocation
func handleCmdInjection1(w http.ResponseWriter, r *http.Request) {
	input := r.FormValue("cmd")
	cmd := exec.Command("bash", "-c", input)
	cmd.Run()
}

// TP6: Command Injection — exec.Command with tainted command name
func handleCmdInjection2(w http.ResponseWriter, r *http.Request) {
	program := r.FormValue("program")
	cmd := exec.Command(program)
	cmd.Run()
}

// TP7: SSTI — template.New("").Parse(tainted)
func handleSSTI(w http.ResponseWriter, r *http.Request) {
	userTemplate := r.FormValue("template")
	tmpl, _ := template.New("user").Parse(userTemplate)
	tmpl.Execute(w, nil)
}

// TP8: XSS — template.HTML(tainted)
func handleXSSTemplateHTML(w http.ResponseWriter, r *http.Request) {
	content := r.FormValue("content")
	unsafeHTML := template.HTML(content)
	_ = unsafeHTML
}

// TP9: XSS — fmt.Fprintf(w, tainted)
func handleXSSFprintf(w http.ResponseWriter, r *http.Request) {
	message := r.FormValue("msg")
	fmt.Fprintf(w, message)
}

// TP10: Open Redirect — http.Redirect with tainted URL
func handleOpenRedirect(w http.ResponseWriter, r *http.Request) {
	redirectTo := r.FormValue("next")
	http.Redirect(w, r, redirectTo, http.StatusFound)
}

// TP15: NoSQL Injection — collection.Find with tainted filter
func handleNoSQLi(w http.ResponseWriter, r *http.Request) {
	collection := &mongo.Collection{}
	filter := r.FormValue("filter")
	collection.Find(nil, filter)
}

// TP16: LDAP Injection — unescaped filter string
func handleLDAPi(w http.ResponseWriter, r *http.Request) {
	username := r.FormValue("user")
	filter := fmt.Sprintf("(uid=%s)", username)
	searchReq := ldap.NewSearchRequest("dc=example,dc=com", ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false, filter, []string{"dn"}, nil)
	_ = searchReq
}

// TP17: Insecure Deserialization — gob.Decode from request body
func handleGobDecode(w http.ResponseWriter, r *http.Request) {
	decoder := gob.NewDecoder(r.Body)
	var data map[string]interface{}
	decoder.Decode(&data)
}

// TP18: Second-order SQLi — DB-fetched data in SQL concatenation
func handleSecondOrderSQLi(db *sql.DB) {
	row := db.QueryRow("SELECT username FROM users WHERE id = 1")
	var username string
	row.Scan(&username)
	query := "SELECT * FROM orders WHERE user = '" + username + "'"
	db.Query(query)
}

// TP19: XSS — Gin c.String with tainted data
func handleGinXSS(c *gin.Context) {
	input := c.Query("input")
	c.String(200, input)
}

// TP20: SQL Injection — sqlx db.Get with concatenation
func handleSqlxSQLi(w http.ResponseWriter, r *http.Request) {
	id := r.FormValue("id")
	db := &sqlx.DB{}
	var user struct{ Name string }
	query := "SELECT name FROM users WHERE id = " + id
	db.Get(&user, query)
}

// TP21: Insecure Deserialization — yaml.Unmarshal with tainted data
func handleYamlUnmarshal(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(r.Body)
	var config map[string]interface{}
	yaml.Unmarshal(body, &config)
}

// TP22: XSS — io.WriteString to ResponseWriter
func handleXSSWriteString(w http.ResponseWriter, r *http.Request) {
	userInput := r.FormValue("data")
	io.WriteString(w, userInput)
}

// TP23: Insecure Deserialization — xml.Unmarshal with tainted data
func handleXmlUnmarshal(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(r.Body)
	var result interface{}
	xml.Unmarshal(body, &result)
}

// TP25: Code Injection — reflect.MethodByName with tainted input
func handleReflection(w http.ResponseWriter, r *http.Request) {
	methodName := r.FormValue("method")
	v := reflect.ValueOf(&http.Server{})
	m := v.MethodByName(methodName)
	_ = m
}

// =============================================================================
// TRUE NEGATIVES — Should NOT be detected
// =============================================================================

// TN1: Parameterized query — db.Query with ? placeholder
func safeSQLParam(w http.ResponseWriter, r *http.Request) {
	id := r.FormValue("id")
	db, _ := sql.Open("postgres", "")
	db.Query("SELECT * FROM users WHERE id = ?", id)
}

// TN2: Safe exec — exec.Command with separate args (no shell)
func safeExecCommand(w http.ResponseWriter, r *http.Request) {
	filename := r.FormValue("file")
	cmd := exec.Command("ls", "-la", filename)
	cmd.Run()
}

// TN3: Taint killed — strconv.Atoi kills taint
func safeStrconvAtoi(w http.ResponseWriter, r *http.Request) {
	idStr := r.FormValue("id")
	id, _ := strconv.Atoi(idStr)
	query := fmt.Sprintf("SELECT * FROM users WHERE id = %d", id)
	db, _ := sql.Open("postgres", "")
	db.Query(query)
}

// TN4: Safe path — filepath.Base sanitizes path traversal
func safeFilepathBase(w http.ResponseWriter, r *http.Request) {
	filename := r.FormValue("file")
	safeName := filepath.Base(filename)
	os.Open(safeName)
}

// TN5: Safe XSS — html.EscapeString sanitizes output
func safeHTMLEscape(w http.ResponseWriter, r *http.Request) {
	input := r.FormValue("input")
	safe := html.EscapeString(input)
	fmt.Fprintf(w, safe)
}

// TN6: GORM struct — db.Where with struct (not string concat)
func safeGORMStruct(w http.ResponseWriter, r *http.Request) {
	name := r.FormValue("name")
	db := &gorm.DB{}
	type User struct{ Name string }
	db.Where(&User{Name: name})
}

// TN7: Safe LDAP — ldap.EscapeFilter sanitizes input
func safeLDAPFilter(w http.ResponseWriter, r *http.Request) {
	username := r.FormValue("user")
	safe := ldap.EscapeFilter(username)
	filter := fmt.Sprintf("(uid=%s)", safe)
	_ = filter
}

// TN8: Safe template — template.ParseFiles (not user-controlled)
func safeTemplateParse() {
	template.ParseFiles("templates/page.html")
}

// TN9: Prepared statement — stmt.Query with input as parameter
func safePreparedStmt(w http.ResponseWriter, r *http.Request) {
	id := r.FormValue("id")
	db, _ := sql.Open("postgres", "")
	stmt, _ := db.Prepare("SELECT * FROM users WHERE id = $1")
	stmt.Query(id)
}

// TN10: Safe redirect — static URL (not user-controlled)
func safeRedirect(w http.ResponseWriter, r *http.Request) {
	http.Redirect(w, r, "/dashboard", http.StatusFound)
}

// TN11: Safe string operations on non-tainted data
func safeStringOps() {
	msg := "hello world"
	upper := strings.ToUpper(msg)
	_ = upper
}

// TN12: Nosec suppression — should be suppressed
func suppressedFinding(w http.ResponseWriter, r *http.Request) {
	id := r.FormValue("id")
	query := "SELECT * FROM users WHERE id = '" + id + "'"
	db, _ := sql.Open("postgres", "")
	db.Query(query) // nosec
}

// TN13: vibehunter:ignore suppression
func suppressedFinding2(w http.ResponseWriter, r *http.Request) {
	cmd := r.FormValue("cmd")
	exec.Command("bash", "-c", cmd) // vibehunter:ignore - known safe
}
