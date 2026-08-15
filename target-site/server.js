const express = require('express');
const helmet = require('helmet');
const morgan = require('morgan');
const app = express();

app.use(helmet({ contentSecurityPolicy: false }));
app.use(morgan('combined'));
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static('public'));

// ── Routes ──────────────────────────────────────────────

// Home
app.get('/', (req, res) => res.sendFile('index.html', { root: './public' }));

// Product listing — paginated (gives bots something to crawl)
const PRODUCTS = Array.from({ length: 100 }, (_, i) => ({
    id: i + 1,
    name: `Product ${i + 1}`,
    price: (Math.random() * 500 + 10).toFixed(2),
    category: ['electronics', 'books', 'clothing', 'sports'][i % 4],
}));

app.get('/api/products', (req, res) => {
    const page = parseInt(req.query.page) || 1;
    const limit = parseInt(req.query.limit) || 10;
    const start = (page - 1) * limit;
    res.json({
        products: PRODUCTS.slice(start, start + limit),
        total: PRODUCTS.length,
        page,
        pages: Math.ceil(PRODUCTS.length / limit),
    });
});

// Search
app.get('/api/search', (req, res) => {
    const q = (req.query.q || '').toLowerCase();
    const results = PRODUCTS.filter(p => p.name.toLowerCase().includes(q));
    res.json({ results, count: results.length });
});

// Login (fake auth — always succeeds with correct body shape)
app.post('/api/login', (req, res) => {
    const { username, password } = req.body;
    if (!username || !password) {
        return res.status(400).json({ error: 'Missing credentials' });
    }
    // Always succeed — this is a honeypot, not real auth
    res.json({ token: 'fake-jwt-token', user: { id: 1, username } });
});

// Profile (requires token header — bots often skip this)
app.get('/api/profile', (req, res) => {
    const auth = req.headers['authorization'];
    if (!auth) return res.status(401).json({ error: 'Unauthorized' });
    res.json({ id: 1, username: 'testuser', plan: 'premium' });
});

// Health check for orchestrator
app.get('/health', (req, res) => res.json({ status: 'ok' }));

const PORT = 3000;
app.listen(PORT, () => console.log(`Target site running on http://localhost:${PORT}`));
