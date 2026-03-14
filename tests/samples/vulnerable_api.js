/**
 * Intentionally vulnerable Express.js API for API Security Scanner testing.
 * DO NOT use this code in production.
 */
const express = require('express');
const jwt = require('jsonwebtoken');
const axios = require('axios');
const { MongoClient } = require('mongodb');

const app = express();
app.use(express.json());

// API2-002: JWT secret hardcoded
const JWT_SECRET = "my-super-secret-jwt-key-12345678";
const token = jwt.sign({ user: "admin" }, JWT_SECRET, { algorithm: "HS256" });

// API2-003: JWT weak algorithm
const decoded = jwt.verify(token, JWT_SECRET, { algorithms: ["HS256"] });

// API2-004: JWT verify disabled
const unsafe = jwt.decode(token, { verify: false });

// API1-003: Express route with ID param
const router = express.Router();
router.get('/:userId/profile', (req, res) => {
    const userId = req.params.userId;
    res.json(db.findUser(userId));
});

router.delete('/:id/account', (req, res) => {
    db.delete(req.params.id);
    res.json({ deleted: true });
});

// API3-001: Mass assignment
app.put('/api/profile', (req, res) => {
    const updated = Object.assign(user, req.body);
    res.json(updated);
});

// API3-002: Excessive data exposure
app.get('/api/user/:id', (req, res) => {
    const user = getUser(req.params.id);
    res.json(JSON.stringify(user));
});

// API5-001: Admin endpoint
router.post('/admin/users/create', (req, res) => {
    return res.json({ created: true });
});

// API5-003: HTTP method override
app.use(require('method-override')('X-HTTP-Method-Override'));

// API7-001: SSRF
app.get('/api/proxy', async (req, res) => {
    const resp = await axios.get(req.query.url);
    res.json(resp.data);
});

// API7-003: Webhook SSRF
app.post('/api/webhooks', (req, res) => {
    const webhook_url = req.body.callback_url;
    res.json({ registered: true });
});

// API8-001: CORS wildcard
app.use((req, res, next) => {
    res.header('Access-Control-Allow-Origin', '*');
    res.header('Access-Control-Allow-Methods', '*');
    next();
});

// API8-002: Debug mode
process.env.DEBUG = true;

// API8-003: Stack trace exposed
app.use((err, req, res, next) => {
    res.status(500).json({ error: err.stack });
});

// API8-006: Server tech exposed
app.use((req, res, next) => {
    res.header('X-Powered-By', 'Express');
    next();
});

// API8-008: TLS verify disabled
process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0';

// API8-009: CORS credentials
app.use((req, res, next) => {
    res.header('Access-Control-Allow-Credentials', true);
    next();
});

// API9-002: Swagger publicly exposed
app.get('/swagger', (req, res) => res.json(swaggerDoc));
app.get('/api-docs', (req, res) => res.json(swaggerDoc));

// API-INJ-001: SQL injection
app.get('/api/search', (req, res) => {
    const query = "SELECT * FROM products WHERE name = '" + req.query.q + "'";
    db.query(query);
});

// API-INJ-002: NoSQL injection
app.get('/api/users', async (req, res) => {
    const users = await db.collection('users').find(req.query).toArray();
    res.json(users);
});

// API-INJ-004: XSS
app.get('/render', (req, res) => {
    document.write(req.query.content);
    element.innerHTML = req.body.html;
});

// API-INJ-007: Path traversal
app.get('/api/files', (req, res) => {
    const data = require('fs').readFile(req.query.path);
    res.send(data);
});

// API-SEC-001: Hardcoded API key
const api_key = "sk_live_1234567890abcdef";

// API-SEC-005: DB connection string
const mongoUrl = "mongodb://admin:password123@mongo.example.com:27017/production";

// API-SEC-006: Bearer token
const headers = { Authorization: "Bearer eyJhbGciOiJIUzI1NiJ9.abc.def" };

// API-TLS-001: HTTP endpoint
const partnerApi = "http://api.partner-service.com/v2/data";

// API-LOG-001: Sensitive data in logs
console.log(`Auth token: ${token}, password: ${password}`);
console.log(`Request body: ${JSON.stringify(req.body)}`);

// API4-004: No timeout
axios.get("https://slow-api.com/data", { timeout: null });

// API10-001: Unvalidated third-party response
const resp = await fetch("https://api.third-party.com/data");
const data = resp.json()["items"];

app.listen(3000, '0.0.0.0');
