require('dotenv').config();
const express = require('express');
const cookieParser = require('cookie-parser');
const cors = require('cors');
const helmet = require('helmet');
const fs = require('fs');
const path = require('path');

const app = express();

// ========== SECURITY HEADERS (helmet) ==========
app.use(helmet());

// ========== CORS ==========
app.use(cors({
  origin: 'https://ashura.site',
  credentials: true,
}));

app.use(express.json());
app.use(cookieParser(process.env.COOKIE_SECRET)); // signed cookies

// ========== SYSTEM PROMPT ==========
let systemPromptTemplate = '';
try {
  const promptPath = path.join(__dirname, 'system-prompt.txt');
  systemPromptTemplate = fs.readFileSync(promptPath, 'utf8');
  console.log('System prompt loaded successfully');
} catch (err) {
  console.error('Failed to load system-prompt.txt:', err.message);
  systemPromptTemplate = 'You are a helpful assistant.';
}

// ========== LOGIN RATE LIMITER ==========
const loginAttempts = new Map();
const MAX_LOGIN_ATTEMPTS = 5;
const LOGIN_LOCKOUT_MS = 15 * 60 * 1000; // 15 minutes

function checkLoginRateLimit(ip) {
  const now = Date.now();
  const record = loginAttempts.get(ip);
  if (!record) return true;
  if (now - record.firstAttempt > LOGIN_LOCKOUT_MS) {
    loginAttempts.delete(ip);
    return true;
  }
  return record.count < MAX_LOGIN_ATTEMPTS;
}

function recordFailedLogin(ip) {
  const now = Date.now();
  const record = loginAttempts.get(ip);
  if (!record) {
    loginAttempts.set(ip, { count: 1, firstAttempt: now });
  } else {
    record.count++;
  }
}

function resetLoginAttempts(ip) {
  loginAttempts.delete(ip);
}

// ========== CHAT RATE LIMITER ==========
const chatAttempts = new Map();
const MAX_CHAT_PER_MIN = 20;

function checkChatRateLimit(ip) {
  const now = Date.now();
  const record = chatAttempts.get(ip);
  if (!record || now - record.window > 60 * 1000) {
    chatAttempts.set(ip, { count: 1, window: now });
    return true;
  }
  if (record.count >= MAX_CHAT_PER_MIN) return false;
  record.count++;
  return true;
}

// Clean up stale records every 30 minutes
setInterval(() => {
  const now = Date.now();
  for (const [ip, record] of loginAttempts.entries()) {
    if (now - record.firstAttempt > LOGIN_LOCKOUT_MS) loginAttempts.delete(ip);
  }
  for (const [ip, record] of chatAttempts.entries()) {
    if (now - record.window > 60 * 1000) chatAttempts.delete(ip);
  }
}, 30 * 60 * 1000);


// ========== LOGIN ==========
app.post('/api/login', (req, res) => {
  const ip = req.ip;

  if (!checkLoginRateLimit(ip)) {
    return res.status(429).json({ success: false, error: 'Too many attempts. Try again in 15 minutes.' });
  }

  const { username, password } = req.body;

  if (!username || !password || typeof username !== 'string' || typeof password !== 'string') {
    return res.status(400).json({ success: false, error: 'Username and password are required.' });
  }

  const validUser = process.env.ADMIN_USERNAME;
  const validPass = process.env.ADMIN_PASSWORD;

  if (username === validUser && password === validPass) {
    resetLoginAttempts(ip);
    res.cookie('auth', 'true', {
      httpOnly: true,
      secure: true,
      sameSite: 'none',
      signed: true, // FIX: signed with COOKIE_SECRET — can't be forged
      maxAge: 24 * 60 * 60 * 1000
    });
    res.json({ success: true });
  } else {
    recordFailedLogin(ip);
    res.status(401).json({ success: false });
  }
});


// ========== CHAT API ==========
app.post('/api/chat', async (req, res) => {
  // FIX: check signed cookie, not plain cookie
  if (!req.signedCookies || req.signedCookies.auth !== 'true') {
    return res.status(401).json({ error: 'Unauthorized' });
  }

  // FIX: rate limit chat requests to protect Groq API budget
  if (!checkChatRateLimit(req.ip)) {
    return res.status(429).json({ error: 'Too many requests. Slow down.' });
  }

  const { messages } = req.body;

  if (!messages || !Array.isArray(messages)) {
    return res.status(400).json({ error: 'Messages array is required' });
  }

  const MAX_MESSAGES = 20;
  if (messages.length > MAX_MESSAGES) {
    return res.status(400).json({ error: `Too many messages. Max ${MAX_MESSAGES} allowed per request.` });
  }

  const allowedRoles = ['user', 'assistant'];
  const sanitized = messages.filter(m =>
    m &&
    typeof m === 'object' &&
    allowedRoles.includes(m.role) &&
    typeof m.content === 'string' &&
    m.content.trim().length > 0 &&
    m.content.length <= 4000
  );

  if (sanitized.length === 0) {
    return res.status(400).json({ error: 'No valid messages provided.' });
  }

  // FIX: sanitize username cookie before injecting into system prompt
  // Strip to alphanumeric + spaces, cap at 30 chars to block prompt injection
  let username = 'User';
  if (req.cookies.username) {
    try {
      const raw = decodeURIComponent(req.cookies.username);
      username = raw.replace(/[^a-zA-Z0-9 ]/g, '').slice(0, 30) || 'User';
    } catch(e) { /* fallback to 'User' */ }
  }

  const systemPrompt = systemPromptTemplate.replace(/{{username}}/g, username);

  const messagesWithSystem = [
    { role: 'system', content: systemPrompt },
    ...sanitized
  ];

  const GROQ_API_KEY = process.env.GROQ_API_KEY;

  if (!GROQ_API_KEY) {
    console.error('GROQ_API_KEY is not set in environment variables.');
    return res.status(500).json({ error: 'Server configuration error.' });
  }

  const GROQ_API_URL = 'https://api.groq.com/openai/v1/chat/completions';

  try {
    const response = await fetch(GROQ_API_URL, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${GROQ_API_KEY}`
      },
      body: JSON.stringify({
        model: 'llama-3.3-70b-versatile',
        messages: messagesWithSystem,
        temperature: 0.7,
        max_tokens: 1000
      })
    });

    if (!response.ok) {
      const errorText = await response.text();
      console.error('Groq API error:', response.status, errorText);
      return res.status(response.status).json({ error: `API error: ${response.status}` });
    }

    const data = await response.json();
    const reply = data.choices[0].message.content;
    res.json({ reply });
  } catch (error) {
    console.error('Server error:', error);
    res.status(500).json({ error: 'Something went wrong' });
  }
});


// ========== VERIFY AUTH ==========
app.get('/api/verify', (req, res) => {
  if (req.signedCookies && req.signedCookies.auth === 'true') {
    res.status(200).json({ authenticated: true });
  } else {
    res.status(401).json({ authenticated: false });
  }
});


// ========== LOGOUT ==========
app.post('/api/logout', (req, res) => {
  res.clearCookie('auth', { httpOnly: true, secure: true, sameSite: 'none', signed: true });
  res.json({ success: true });
});


// ========== HEALTH CHECK ==========
app.get('/api/health', (req, res) => {
  res.json({ status: 'ok' });
});

app.get('/', (req, res) => {
  res.send('Backend is alive');
});


const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Backend running on port ${PORT}`);
});