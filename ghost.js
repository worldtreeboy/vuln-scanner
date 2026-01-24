const express = require('express');
const app = express();

app.get('/user/:id', (req, res) => {
  const id = req.params.id;
  const func = new Function('id', `return 'Hello, ' + id;`);
  res.send(func(id));
});

app.listen(3000, () => {
  console.log('Server running on port 3000');
});give me vulnerable express js code. but hard to detect normally!
