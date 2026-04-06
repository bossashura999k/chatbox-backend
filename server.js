require('dotenv').config();
const express = require('express');
const cookieParser = require('cookie-parser');
const cors = require('cors');

const app = express();

// CORS configuration: allow your frontend domain
app.use(cors({
  origin: 'https://ashura.site',
  credentials: true,
}));

app.use(express.json());
app.use(cookieParser());

// ========== SIMPLE RATE LIMITER (no extra package needed) ==========
// Tracks login attempts per IP to block brute-force attacks
const loginAttempts = new Map();
const MAX_ATTEMPTS = 5;         // max tries before lockout
const LOCKOUT_MS = 15 * 60 * 1000; // 15 minute lockout

function checkRateLimit(ip) {
  const now = Date.now();
  const record = loginAttempts.get(ip);

  if (!record) return true; // first attempt, allow

  // If lockout period has passed, reset
  if (now - record.firstAttempt > LOCKOUT_MS) {
    loginAttempts.delete(ip);
    return true;
  }

  return record.count < MAX_ATTEMPTS;
}

function recordFailedAttempt(ip) {
  const now = Date.now();
  const record = loginAttempts.get(ip);
  if (!record) {
    loginAttempts.set(ip, { count: 1, firstAttempt: now });
  } else {
    record.count++;
  }
}

function resetAttempts(ip) {
  loginAttempts.delete(ip);
}

// Clean up old records every 30 minutes so the Map doesn't grow forever
setInterval(() => {
  const now = Date.now();
  for (const [ip, record] of loginAttempts.entries()) {
    if (now - record.firstAttempt > LOCKOUT_MS) {
      loginAttempts.delete(ip);
    }
  }
}, 30 * 60 * 1000);


// ========== LOGIN ==========
app.post('/api/login', (req, res) => {
  const ip = req.ip;

  // FIX 1: Rate limit login attempts to prevent brute-force
  if (!checkRateLimit(ip)) {
    return res.status(429).json({ success: false, error: 'Too many attempts. Try again in 15 minutes.' });
  }

  const { username, password } = req.body;

  // FIX 2: Validate that both fields are present and are strings
  if (!username || !password || typeof username !== 'string' || typeof password !== 'string') {
    return res.status(400).json({ success: false, error: 'Username and password are required.' });
  }

  const validUser = process.env.ADMIN_USERNAME;
  const validPass = process.env.ADMIN_PASSWORD;

  if (username === validUser && password === validPass) {
    resetAttempts(ip); // reset counter on success
    res.cookie('auth', 'true', {
      httpOnly: true,
      secure: true,
      sameSite: 'none',
      maxAge: 24 * 60 * 60 * 1000
    });
    res.json({ success: true });
  } else {
    recordFailedAttempt(ip); // count the failed attempt
    res.status(401).json({ success: false });
  }
});


// ========== CHAT API (only if authenticated) ==========
app.post('/api/chat', async (req, res) => {
  // Check authentication cookie
  if (!req.cookies || req.cookies.auth !== 'true') {
    return res.status(401).json({ error: 'Unauthorized' });
  }

  const { messages } = req.body;

  // FIX 3: Validate messages array
  if (!messages || !Array.isArray(messages)) {
    return res.status(400).json({ error: 'Messages array is required' });
  }

  // FIX 4: Cap message history length to avoid huge Groq API bills
  const MAX_MESSAGES = 20;
  if (messages.length > MAX_MESSAGES) {
    return res.status(400).json({ error: `Too many messages. Max ${MAX_MESSAGES} allowed per request.` });
  }

  // FIX 5: Sanitize each message — only allow role + string content
  const allowedRoles = ['user', 'assistant'];
  const sanitized = messages.filter(m =>
    m &&
    typeof m === 'object' &&
    allowedRoles.includes(m.role) &&
    typeof m.content === 'string' &&
    m.content.trim().length > 0 &&
    m.content.length <= 4000  // cap individual message length
  );

  if (sanitized.length === 0) {
    return res.status(400).json({ error: 'No valid messages provided.' });
  }

  // FIX 6: Always inject a server-side system prompt — client cannot override this
  const messagesWithSystem = [
    {
      role: 'system',
      content: 'You are a helpful AI assistant on Ashura IZZI\'s website (ashura.site). Be friendly, concise, and helpful. Do not discuss harmful, illegal, or inappropriate topics.'
    },
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
  if (req.cookies && req.cookies.auth === 'true') {
    res.status(200).json({ authenticated: true });
  } else {
    res.status(401).json({ authenticated: false });
  }
});


// ========== LOGOUT ==========
app.post('/api/logout', (req, res) => {
  res.clearCookie('auth', { httpOnly: true, secure: true, sameSite: 'none' });
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

// .env added