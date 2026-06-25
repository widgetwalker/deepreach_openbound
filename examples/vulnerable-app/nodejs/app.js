const axios = require('axios');
const express = require('express');
const app = express();

app.get('/', async (req, res) => {
    const response = await axios.get('https://example.com');
    res.send(response.data);
});

app.listen(3000);
