const express = require('express');
const fs = require('fs');
const app = express();
app.use(express.json());

// A utility function for sanitization (that is actually broken)
function weakSanitize(str) {
    return str.replace('<script>', '');
}

// A wrapper for sending responses
function respond(res, data, isError) {
    if (isError) {
        // VULNERABILITY: XSS in error message
        res.send("Internal Error: " + data);
    } else {
        res.json({ status: "success", data: data });
    }
}

app.get('/v12/test', (req, res) => {
    const userInput = req.query.input;
    const sanitized = weakSanitize(userInput);

    // Does the scanner follow 'userInput' through 'weakSanitize'
    // and then through the 'respond' function?
    if (userInput.length > 100) {
        respond(res, sanitized, true);
    } else {
        respond(res, sanitized, false);
    }
});

app.get('/v12/read', (req, res) => {
    const filename = req.query.file;

    // VULNERABILITY: Path Traversal (LFI)
    // Testing if 'fs.readFileSync' is in the sink list
    fs.readFile(filename, 'utf8', (err, data) => {
        if (err) return res.send(err.message);
        res.send(data);
    });
});

app.listen(3000);
