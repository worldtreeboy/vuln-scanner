// =============================================================================
// TRUE POSITIVES — Should be detected
// =============================================================================

const express = require('express');
const mysql = require('mysql');
const pg = require('pg');
const ejs = require('ejs');
const pug = require('pug');
const nunjucks = require('nunjucks');
const Handlebars = require('handlebars');
const { exec } = require('child_process');

const app = express();
const connection = mysql.createConnection({});
const pool = new pg.Pool();

// TP1: SQL Injection — mysql query with string concatenation
app.get('/sqli1', (req, res) => {
    const id = req.query.id;
    const query = "SELECT * FROM users WHERE id = '" + id + "'";
    connection.query(query);
});

// TP2: SQL Injection — pg query with template literal
app.get('/sqli2', (req, res) => {
    const name = req.query.name;
    pool.query(`SELECT * FROM users WHERE name = '${name}'`);
});

// TP3: SQL Injection — mysql execute with fmt
app.get('/sqli3', (req, res) => {
    const email = req.body.email;
    const q = "DELETE FROM users WHERE email = '" + email + "'";
    connection.execute(q);
});

// TP4: SSTI — ejs.render with tainted template
app.get('/ssti1', (req, res) => {
    const template = req.query.template;
    const output = ejs.render(template, { user: 'admin' });
    res.send(output);
});

// TP5: SSTI — pug.compile with tainted template
app.get('/ssti2', (req, res) => {
    const tmpl = req.body.template;
    const fn = pug.compile(tmpl);
    res.send(fn({ name: 'test' }));
});

// TP6: SSTI — nunjucks.renderString with tainted input
app.get('/ssti3', (req, res) => {
    const userTemplate = req.query.tmpl;
    const result = nunjucks.renderString(userTemplate, { name: 'test' });
    res.send(result);
});

// TP7: SSTI — Handlebars.compile with tainted input
app.get('/ssti4', (req, res) => {
    const src = req.body.source;
    const compiled = Handlebars.compile(src);
    res.send(compiled({ name: 'world' }));
});

// TP8: Open Redirect — res.redirect with tainted URL
app.get('/redirect1', (req, res) => {
    const next = req.query.next;
    res.redirect(next);
});

// TP9: Open Redirect — res.redirect with status and tainted URL
app.get('/redirect2', (req, res) => {
    const url = req.query.url;
    res.redirect(301, url);
});

// TP10: XSS — res.send with tainted data (existing check)
app.get('/xss1', (req, res) => {
    const input = req.query.input;
    res.send(input);
});

// TP11: Command Injection — exec with tainted data (existing check)
app.get('/cmd1', (req, res) => {
    const cmd = req.query.cmd;
    exec(cmd);
});

// TP12: await expression taint propagation
app.get('/await1', async (req, res) => {
    const url = req.query.url;
    const response = await fetch(url);
    const data = await response.text();
    res.send(data);
});

// TP13: .then() callback taint propagation
app.get('/then1', (req, res) => {
    const userUrl = req.query.url;
    fetch(userUrl).then(response => {
        res.send(response);
    });
});

// TP14: SQL Injection — sequelize raw query
const sequelize = require('sequelize');
app.get('/sqli4', (req, res) => {
    const search = req.query.search;
    sequelize.query("SELECT * FROM products WHERE name LIKE '%" + search + "%'");
});

// =============================================================================
// TRUE NEGATIVES — Should NOT be detected
// =============================================================================

// TN1: Parameterized SQL query — mysql with ? placeholder
app.get('/safe-sql1', (req, res) => {
    const id = req.query.id;
    connection.query('SELECT * FROM users WHERE id = ?', [id]);
});

// TN2: Parameterized SQL query — pg with $1 placeholder
app.get('/safe-sql2', (req, res) => {
    const name = req.query.name;
    pool.query('SELECT * FROM users WHERE name = $1', [name]);
});

// TN3: Static SQL query — no user input
app.get('/safe-sql3', (req, res) => {
    connection.query('SELECT * FROM users WHERE active = true');
});

// TN4: Safe template — ejs.render with static template string
app.get('/safe-ssti1', (req, res) => {
    const data = req.query.name;
    const output = ejs.render('<h1><%= name %></h1>', { name: data });
    res.send(output);
});

// TN5: Safe redirect — static URL
app.get('/safe-redirect', (req, res) => {
    res.redirect('/dashboard');
});

// TN6: Safe command — static string
app.get('/safe-cmd', (req, res) => {
    exec('ls -la /tmp');
});

// TN7: Taint killed by parseInt (use unique var name to avoid file-level taint collision)
app.get('/safe-taint', (req, res) => {
    const safeNumericId = parseInt(req.query.numid);
    connection.query(`SELECT * FROM users WHERE id = ${safeNumericId}`);
});

// TN8: nosec suppression
app.get('/suppressed', (req, res) => {
    const suppressedInput = req.query.sinput;
    res.send(suppressedInput); // nosec
});

// TN9: Safe array append (not DOM)
app.get('/safe-append', (req, res) => {
    const items = [];
    items.push(req.query.item);
    res.json(items);
});

// TN10: Safe Handlebars — static template (res.send with compiled output is valid XSS concern)
app.get('/safe-ssti2', (req, res) => {
    const safeCompiled = Handlebars.compile('<h1>{{name}}</h1>');
    res.json({ html: safeCompiled({ name: req.query.sname }) });
});
