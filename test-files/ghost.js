const express = require('express');
const app = express();
app.use(express.json());

/**
 * SCENARIO 1: The "Lazy" Object Merger
 * Instead of using a library like Lodash, a dev writes a quick 'patch' 
 * function. It uses the bracket notation, which is the #1 way 
 * Prototype Pollution enters a system.
 */
function applyPatch(target, patch) {
    for (const key in patch) {
        // The dev forgets to check if key === '__proto__'
        // This is a classic "Developer Mistake"
        target[key] = patch[key];
    }
}

app.patch('/api/v1/user/settings', (req, res) => {
    const userSettings = { theme: 'light', lang: 'en' };
    applyPatch(userSettings, req.body); // Pollution Point
    res.status(200).json(userSettings);
});

/**
 * SCENARIO 2: The "Safe" Template Helper
 * A developer creates a "helper" to render user notifications. 
 * They think that because it's inside a specific function, it's 
 * "isolated" from the rest of the app.
 */
const renderNotification = (msg) => {
    // Implicit Sink: Using a template literal to build HTML
    return `<div class="alert">${msg}</div>`;
};

app.get('/api/v1/notify', (req, res) => {
    const userMsg = req.query.message;
    if (userMsg) {
        const html = renderNotification(userMsg);
        res.set('Content-Type', 'text/html');
        res.send(html); // XSS Point
    } else {
        res.sendStatus(400);
    }
});

/**
 * SCENARIO 3: The Alias Trap
 * This tests if the scanner follows a sink when it's assigned to a variable.
 * Devs often rename functions for brevity.
 */
app.get('/api/v1/debug', (req, res) => {
    const out = res.send.bind(res); // Alias the sink
    const info = req.query.info;
    
    // Does the scanner realize 'out' is a dangerous sink?
    out("Debug Info: " + info); 
});

app.listen(3000);
