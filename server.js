const express = require('express');
const path = require('path');
const fs = require('fs');
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

// ── Security headers ─────────────────────────────────────────────
app.use(helmet({
    contentSecurityPolicy: {
        directives: {
            defaultSrc: ["'self'"],
            scriptSrc: ["'self'", "'unsafe-inline'"],
            styleSrc: ["'self'", "'unsafe-inline'", "https://fonts.googleapis.com"],
            fontSrc: ["'self'", "https://fonts.gstatic.com"],
            imgSrc: ["'self'", "https://images.unsplash.com", "data:"],
            connectSrc: ["'self'"],
            frameAncestors: ["'none'"],
            formAction: ["'self'"],
            baseUri: ["'self'"]
        }
    },
    strictTransportSecurity: {
        maxAge: 31536000,
        includeSubDomains: true,
        preload: true
    },
    referrerPolicy: { policy: 'strict-origin-when-cross-origin' }
}));

// Permissions-Policy: block unused browser APIs
app.use((req, res, next) => {
    res.setHeader('Permissions-Policy',
        'camera=(), microphone=(), geolocation=(), payment=(), usb=(), magnetometer=(), gyroscope=(), accelerometer=()'
    );
    next();
});

// ── General rate limiter (DoS protection) ────────────────────────
const generalLimiter = rateLimit({
    windowMs: 60 * 1000,
    max: 60,
    standardHeaders: true,
    legacyHeaders: false,
    message: 'Too many requests'
});
app.use(generalLimiter);

// Compression
app.use(compression());

// Parse JSON bodies
app.use(express.json({ limit: '16kb' }));

// Serve static files with caching (HTML excluded — served via routes with no-cache)
app.use(express.static(path.join(__dirname, 'public'), {
    maxAge: '7d',
    index: false,
    setHeaders: (res, filePath) => {
        if (filePath.endsWith('.html')) {
            res.setHeader('Cache-Control', 'no-cache');
        }
    }
}));

// ── Email transporter (created once, not per-request) ────────────
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

// ── Contact form endpoint ────────────────────────────────────────
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

    // Phone format validation
    if (!/^[\d\s\-+().]+$/.test(phone)) {
        return res.status(400).json({ ok: false, error: 'Invalid phone format' });
    }

    // Email format validation (optional field)
    if (email && !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email.trim())) {
        return res.status(400).json({ ok: false, error: 'Invalid email format' });
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

// ── SEO metadata per route ───────────────────────────────────────
const routeMeta = {
    '/practice/criminal-lawyer': {
        he: { title: 'עורך דין פלילי | אלון פרדו', desc: 'עורך דין פלילי - ייצוג בחקירות משטרה, כתבי אישום, דיוני מעצר וערעורים. ייעוץ משפטי ישיר ומקצועי.' },
        en: { title: 'Criminal Defense Lawyer | Alon Pardo', desc: 'Criminal defense lawyer - representation in police investigations, indictments, detention hearings and appeals.' }
    },
    '/practice/traffic-lawyer': {
        he: { title: 'עורך דין תעבורה | אלון פרדו', desc: 'עורך דין תעבורה - ייצוג בעבירות תנועה, פסילת רישיון, נהיגה בשכרות ותאונות דרכים.' },
        en: { title: 'Traffic Law Lawyer | Alon Pardo', desc: 'Traffic law lawyer - representation for traffic offenses, license suspension, DUI and road accidents.' }
    },
    '/practice/administrative-lawyer': {
        he: { title: 'עורך דין מנהלי | אלון פרדו', desc: 'עורך דין מנהלי - ערעורים על החלטות רשויות, היתרים, רישוי וסכסוכים מוניציפליים.' },
        en: { title: 'Administrative Law Lawyer | Alon Pardo', desc: 'Administrative law lawyer - appeals against authority decisions, permits, licensing and municipal disputes.' }
    },
    '/practice/employment-lawyer': {
        he: { title: 'עורך דין דיני עבודה | אלון פרדו', desc: 'עורך דין דיני עבודה - ייצוג עובדים ומעסיקים בפיטורין, שימועים, תביעות שכר וסכסוכי עבודה.' },
        en: { title: 'Employment Law Lawyer | Alon Pardo', desc: 'Employment law lawyer - representing employees and employers in termination, hearings, wage claims and disputes.' }
    },
    '/practice/accessibility-lawyer': {
        he: { title: 'עורך דין נגישות | אלון פרדו', desc: 'עורך דין נגישות - ייעוץ, ציות ותביעות נגישות לעסקים ויחידים. הנחיה מעשית ותיקון.' },
        en: { title: 'Accessibility Law Lawyer | Alon Pardo', desc: 'Accessibility law lawyer - compliance, claims and enforcement for businesses and individuals.' }
    },
    '/privacy': {
        he: { title: 'מדיניות פרטיות | אלון פרדו', desc: 'מדיניות הפרטיות של אתר עו"ד אלון פרדו - איסוף מידע, שמירה, אבטחה וזכויותיך.' },
        en: { title: 'Privacy Policy | Alon Pardo', desc: 'Privacy policy for Alon Pardo Attorney at Law - data collection, retention, security and your rights.' }
    },
    '/terms': {
        he: { title: 'תנאי שירות | אלון פרדו', desc: 'תנאי השירות של אתר עו"ד אלון פרדו - שימוש באתר, הגבלות ודין חל.' },
        en: { title: 'Terms of Service | Alon Pardo', desc: 'Terms of service for Alon Pardo Attorney at Law website.' }
    },
    '/cookies': {
        he: { title: 'מדיניות עוגיות | אלון פרדו', desc: 'מדיניות העוגיות של אתר עו"ד אלון פרדו - סוגי עוגיות, שימוש והגדרות.' },
        en: { title: 'Cookie Policy | Alon Pardo', desc: 'Cookie policy for Alon Pardo Attorney at Law website.' }
    },
    '/disclaimer': {
        he: { title: 'הצהרה משפטית | אלון פרדו', desc: 'הצהרה משפטית של אתר עו"ד אלון פרדו - הגבלות, אחריות ודין חל.' },
        en: { title: 'Legal Disclaimer | Alon Pardo', desc: 'Legal disclaimer for Alon Pardo Attorney at Law website.' }
    },
    '/accessibility-statement': {
        he: { title: 'הצהרת נגישות | אלון פרדו', desc: 'הצהרת הנגישות של אתר עו"ד אלון פרדו - תקן WCAG 2.2 AA, תכונות נגישות ויצירת קשר.' },
        en: { title: 'Accessibility Statement | Alon Pardo', desc: 'Accessibility statement - WCAG 2.2 AA standard, accessibility features and contact information.' }
    }
};

// ── Cache HTML templates in memory at startup ────────────────────
const indexTemplate = fs.readFileSync(path.join(__dirname, 'public', 'index.html'), 'utf-8');
const expertiseTemplate = fs.readFileSync(path.join(__dirname, 'public', 'expertise.html'), 'utf-8');

// OG image for social sharing
const ogImage = 'https://images.unsplash.com/photo-1505664194779-8beaceb93744?auto=format&fit=crop&q=80&w=1200';

// Root route — serves landing page with og:image injection
app.get('/', (req, res) => {
    res.set('Cache-Control', 'no-cache');
    let html = indexTemplate;

    // Inject og:image if not already present
    if (!html.includes('og:image')) {
        html = html.replace('<!-- Twitter Card -->',
            `<meta property="og:image" content="${ogImage}">\n    <meta property="og:image:width" content="1200">\n    <meta property="og:image:height" content="630">\n\n    <!-- Twitter Card -->`);
    }

    res.type('html').send(html);
});

// Expertise routes — serve with server-side SEO injection
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

        const lang = req.query.lang === 'en' ? 'en' : 'he';
        const meta = routeMeta[route]?.[lang] || routeMeta[route]?.he;
        const canonical = lang === 'en' ? route + '?lang=en' : route;

        let html = expertiseTemplate
            .replace(/<title[^>]*>[^<]*<\/title>/,
                `<title id="page-title">${meta.title}</title>`)
            .replace(/<meta name="description"[^>]*>/,
                `<meta name="description" id="meta-description" content="${meta.desc}">`)
            .replace(/<meta property="og:title"[^>]*>/,
                `<meta property="og:title" id="og-title" content="${meta.title}">`)
            .replace(/<meta property="og:description"[^>]*>/,
                `<meta property="og:description" id="og-description" content="${meta.desc}">`)
            .replace(/<meta name="twitter:title"[^>]*>/,
                `<meta name="twitter:title" id="twitter-title" content="${meta.title}">`)
            .replace(/<meta name="twitter:description"[^>]*>/,
                `<meta name="twitter:description" id="twitter-description" content="${meta.desc}">`)
            .replace(/<link rel="canonical"[^>]*>/,
                `<link rel="canonical" id="canonical-link" href="${canonical}">`);

        // Inject hreflang tags
        const hreflangBlock = `<link rel="alternate" hreflang="he" href="${route}">\n    <link rel="alternate" hreflang="en" href="${route}?lang=en">\n    <link rel="alternate" hreflang="x-default" href="${route}">`;
        html = html.replace('<!-- Canonical & hreflang -->', `<!-- Canonical & hreflang -->\n    ${hreflangBlock}`);

        // Inject og:image
        if (!html.includes('og:image')) {
            html = html.replace('<!-- Twitter Card -->', `<meta property="og:image" content="${ogImage}">\n    <meta property="og:image:width" content="1200">\n    <meta property="og:image:height" content="630">\n\n    <!-- Twitter Card -->`);
        }

        // Inject JSON-LD structured data for practice area pages
        if (route.startsWith('/practice/')) {
            const jsonLd = JSON.stringify({
                "@context": "https://schema.org",
                "@type": "LegalService",
                "name": meta.title.split('|')[0].trim(),
                "description": meta.desc,
                "url": canonical,
                "provider": {
                    "@type": "Person",
                    "name": "Alon Pardo",
                    "jobTitle": "Attorney at Law",
                    "telephone": "+972524203401"
                },
                "areaServed": { "@type": "Country", "name": "Israel" },
                "availableLanguage": ["Hebrew", "English"]
            });
            const breadcrumb = JSON.stringify({
                "@context": "https://schema.org",
                "@type": "BreadcrumbList",
                "itemListElement": [
                    { "@type": "ListItem", "position": 1, "name": lang === 'en' ? "Home" : "דף הבית", "item": "/" },
                    { "@type": "ListItem", "position": 2, "name": meta.title.split('|')[0].trim(), "item": canonical }
                ]
            });
            html = html.replace('</head>',
                `    <script type="application/ld+json">${jsonLd}</script>\n    <script type="application/ld+json">${breadcrumb}</script>\n</head>`);
        }

        res.type('html').send(html);
    });
});

// ── Start server ─────────────────────────────────────────────────
const server = app.listen(PORT, '0.0.0.0', () => {
    console.log(`Server is running on http://0.0.0.0:${PORT}`);
});

// Keep-alive tuning for reverse proxies / load balancers
server.keepAliveTimeout = 65000;
server.headersTimeout = 66000;
