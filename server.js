const express = require('express');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 5000;

// Serve static files from the 'public' directory
app.use(express.static(path.join(__dirname, 'public')));

// Root route serves the landing page
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// SEO-friendly practice area routes
app.get('/practice/criminal-lawyer', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'expertise.html'));
});

app.get('/practice/traffic-lawyer', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'expertise.html'));
});

app.get('/practice/administrative-lawyer', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'expertise.html'));
});

app.get('/practice/employment-lawyer', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'expertise.html'));
});

app.get('/practice/accessibility-lawyer', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'expertise.html'));
});

// Legal and Policy Routes
app.get('/privacy', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'expertise.html'));
});

app.get('/terms', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'expertise.html'));
});

app.get('/cookies', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'expertise.html'));
});

app.get('/disclaimer', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'expertise.html'));
});

app.get('/accessibility-statement', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'expertise.html'));
});

app.listen(PORT, '0.0.0.0', () => {
    console.log(`Server is running on http://0.0.0.0:${PORT}`);
});