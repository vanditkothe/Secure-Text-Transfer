// server.js
const express = require('express');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const app = express();
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

const USERS_FILE = path.join(__dirname, 'users.json');
const MSG_FILE = path.join(__dirname, 'messages.json');

function readJson(file, fallback) {
  try {
    if (!fs.existsSync(file)) { fs.writeFileSync(file, JSON.stringify(fallback, null, 2)); return fallback; }
    return JSON.parse(fs.readFileSync(file));
  } catch (e) {
    return fallback;
  }
}
function writeJson(file, obj) {
  fs.writeFileSync(file, JSON.stringify(obj, null, 2));
}

// Register: client sends username + publicKeyPem -> server stores and returns an API token
app.post('/api/register', (req, res) => {
  const { username, publicKeyPem } = req.body;
  if (!username || !publicKeyPem) return res.status(400).json({ error: 'username and publicKeyPem required' });

  const users = readJson(USERS_FILE, {});
  const token = crypto.randomBytes(16).toString('hex');

  users[username] = { publicKeyPem, token, createdAt: new Date().toISOString() };
  writeJson(USERS_FILE, users);

  return res.json({ token });
});

// Fetch a user's public key
app.get('/api/publicKey/:username', (req, res) => {
  const users = readJson(USERS_FILE, {});
  const u = users[req.params.username];
  if (!u) return res.status(404).json({ error: 'user not found' });
  return res.json({ publicKeyPem: u.publicKeyPem });
});

// Send encrypted message - server requires x-api-key header matching sender's token
app.post('/api/send', (req, res) => {
  const { from, to, ciphertext, encryptedKey, iv } = req.body;
  if (!from || !to || !ciphertext || !encryptedKey || !iv) return res.status(400).json({ error: 'missing fields' });

  const users = readJson(USERS_FILE, {});
  const user = users[from];
  if (!user) return res.status(400).json({ error: 'unknown sender' });

  const apiKey = req.headers['x-api-key'];
  if (!apiKey || apiKey !== user.token) return res.status(401).json({ error: 'invalid api key' });

  const messages = readJson(MSG_FILE, []);
  messages.push({ from, to, ciphertext, encryptedKey, iv, timestamp: new Date().toISOString() });
  writeJson(MSG_FILE, messages);

  return res.json({ ok: true });
});

// Fetch messages for a user (server only checks token; returns encrypted blobs)
app.get('/api/messages/:username', (req, res) => {
  const username = req.params.username;
  const users = readJson(USERS_FILE, {});
  const user = users[username];
  if (!user) return res.status(404).json({ error: 'unknown user' });

  const apiKey = req.headers['x-api-key'];
  if (!apiKey || apiKey !== user.token) return res.status(401).json({ error: 'invalid api key' });

  const messages = readJson(MSG_FILE, []).filter(m => m.to === username);
  return res.json({ messages });
});

// Convenience: list usernames
app.get('/api/users', (req, res) => {
  const users = readJson(USERS_FILE, {});
  return res.json({ users: Object.keys(users) });
});

const PORT = 3000;
app.listen(PORT, () => {
  console.log(`Server listening at http://localhost:${PORT}`);
});
