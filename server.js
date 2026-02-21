const express = require('express');
const path = require('path');
const nodemailer = require('nodemailer');
const helmet = require('helmet');
const compression = require('compression');
const rateLimit = require('express-rate-limit');

const app = express();
const PORT = process.env.PORT || 5000;

// HTML-escape helper to prevent XSS in email templates
function esc(str) {
    return String(str)
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;');
}

// Security headers
app.use(helmet({
    contentSecurityPolicy: {
        directives: {
            defaultSrc: ["'self'"],
            scriptSrc: ["'self'", "'unsafe-inline'"],
            styleSrc: ["'self'", "'unsafe-inline'", "https://fonts.googleapis.com"],
            fontSrc: ["'self'", "https://fonts.gstatic.com"],
            imgSrc: ["'self'", "https://images.unsplash.com", "data:"],
            connectSrc: ["'self'"]
        }
    }
}));

// Compression
app.use(compression());

// Parse JSON bodies
app.use(express.json({ limit: '16kb' }));

// Serve static files with caching (HTML excluded — served via routes with no-cache)
app.use(express.static(path.join(__dirname, 'public'), {
    maxAge: '7d',
    setHeaders: (res, filePath) => {
        if (filePath.endsWith('.html')) {
            res.setHeader('Cache-Control', 'no-cache');
        }
    }
}));

// Reuse transporter (created once, not per-request)
const transporter = process.env.SMTP_PASS
    ? nodemailer.createTransport({
        service: 'gmail',
        auth: {
            user: process.env.SMTP_USER || 'pardooren@gmail.com',
            pass: process.env.SMTP_PASS
        }
    })
    : null;

// Rate limit for contact endpoint: 5 requests per 15 minutes per IP
const contactLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 5,
    standardHeaders: true,
    legacyHeaders: false,
    message: { ok: false, error: 'Too many requests, please try again later' }
});

// Contact form email endpoint
// Required env vars: SMTP_USER (Gmail address), SMTP_PASS (Gmail App Password)
app.post('/api/contact', contactLimiter, async (req, res) => {
    const { name, phone, caseType, email, message, lang } = req.body || {};

    const required = { name, phone, caseType };
    const missing = Object.entries(required)
        .filter(([, v]) => v == null || String(v).trim() === '')
        .map(([k]) => k);
    if (missing.length) {
        return res.status(400).json({ ok: false, error: 'Missing required fields', fields: missing });
    }

    // Input length validation
    const limits = { name: 200, phone: 30, caseType: 100, email: 254, message: 5000 };
    for (const [field, max] of Object.entries(limits)) {
        if (req.body[field] && String(req.body[field]).length > max) {
            return res.status(400).json({ ok: false, error: `${field} exceeds maximum length of ${max}` });
        }
    }

    // Basic phone format validation
    if (!/^[\d\s\-+().]+$/.test(phone)) {
        return res.status(400).json({ ok: false, error: 'Invalid phone format' });
    }

    if (!transporter) {
        console.warn('SMTP_PASS not configured – email skipped');
        return res.status(503).json({ ok: false, error: 'Email not configured' });
    }

    const safeName = esc(name.trim());
    const safePhone = esc(phone.trim());
    const safeCaseType = esc(caseType.trim());
    const safeEmail = email ? esc(email.trim()) : '';
    const safeMessage = esc((message ?? '').trim()).replace(/\n/g, '<br>');

    const isHe = lang === 'he';
    const subject = isHe
        ? `פנייה חדשה: ${safeName} – ${safeCaseType}`
        : `New Contact: ${safeName} – ${safeCaseType}`;

    const html = `
        <div dir="${isHe ? 'rtl' : 'ltr'}" style="font-family:sans-serif;max-width:600px;margin:0 auto">
            <h2 style="color:#835e21">${isHe ? 'פנייה חדשה מאתר אלון פרדו' : 'New contact from Alon Pardo website'}</h2>
            <table style="width:100%;border-collapse:collapse">
                <tr><td style="padding:8px;font-weight:bold;border-bottom:1px solid #eee;width:30%">${isHe ? 'שם' : 'Name'}</td><td style="padding:8px;border-bottom:1px solid #eee">${safeName}</td></tr>
                <tr><td style="padding:8px;font-weight:bold;border-bottom:1px solid #eee">${isHe ? 'טלפון' : 'Phone'}</td><td style="padding:8px;border-bottom:1px solid #eee">${safePhone}</td></tr>
                <tr><td style="padding:8px;font-weight:bold;border-bottom:1px solid #eee">${isHe ? 'סוג התיק' : 'Case Type'}</td><td style="padding:8px;border-bottom:1px solid #eee">${safeCaseType}</td></tr>
                ${safeEmail ? `<tr><td style="padding:8px;font-weight:bold;border-bottom:1px solid #eee">${isHe ? 'אימייל' : 'Email'}</td><td style="padding:8px;border-bottom:1px solid #eee">${safeEmail}</td></tr>` : ''}
                <tr><td style="padding:8px;font-weight:bold;border-bottom:1px solid #eee;vertical-align:top">${isHe ? 'פרטים' : 'Message'}</td><td style="padding:8px;border-bottom:1px solid #eee">${safeMessage}</td></tr>
            </table>
        </div>`;

    try {
        await transporter.sendMail({
            from: `"Alon Pardo Website" <${process.env.SMTP_USER || 'pardooren@gmail.com'}>`,
            to: 'pardooren@gmail.com',
            subject,
            html
        });
        res.json({ ok: true });
    } catch (err) {
        console.error('Email send error:', err.message);
        res.status(500).json({ ok: false, error: 'Failed to send email' });
    }
});

// Root route serves the landing page
app.get('/', (req, res) => {
    res.set('Cache-Control', 'no-cache');
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// All routes that serve expertise.html (practice areas + legal/policy pages)
const expertisePath = path.join(__dirname, 'public', 'expertise.html');
const expertiseRoutes = [
    '/practice/criminal-lawyer',
    '/practice/traffic-lawyer',
    '/practice/administrative-lawyer',
    '/practice/employment-lawyer',
    '/practice/accessibility-lawyer',
    '/privacy',
    '/terms',
    '/cookies',
    '/disclaimer',
    '/accessibility-statement'
];
expertiseRoutes.forEach(route => {
    app.get(route, (req, res) => {
        res.set('Cache-Control', 'no-cache');
        res.sendFile(expertisePath);
    });
});

app.listen(PORT, '0.0.0.0', () => {
    console.log(`Server is running on http://0.0.0.0:${PORT}`);
});
