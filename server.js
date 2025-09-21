// server.js
require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const path = require('path');
const crypto = require('crypto');

const app = express();
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

// Optionally enable CORS if frontend will be on a different origin
// const cors = require('cors');
// app.use(cors({ origin: process.env.FRONTEND_ORIGIN || '*' }));

// --- MongoDB connection ---
const MONGO_URI = process.env.MONGO_URI;
if (!MONGO_URI) {
  console.error('MONGO_URI not set in environment');
  process.exit(1);
}

mongoose.connect(MONGO_URI, { useNewUrlParser: true, useUnifiedTopology: true })
  .then(() => console.log('Connected to MongoDB Atlas'))
  .catch(err => { console.error('MongoDB connection error', err); process.exit(1); });

// --- Schemas & Models ---
const userSchema = new mongoose.Schema({
  username: { type: String, required: true, unique: true },
  publicKeyPem: { type: String, required: true },
  token: { type: String, required: true },
  createdAt: { type: Date, default: Date.now },
}, { versionKey: false });
userSchema.index({ username: 1 }, { unique: true });

const messageSchema = new mongoose.Schema({
  from: { type: String, required: true },
  to: { type: String, required: true },
  ciphertext: { type: String, required: true },
  encryptedKey: { type: String, required: true },
  iv: { type: String, required: true },
  timestamp: { type: Date, default: Date.now },
}, { versionKey: false });

const User = mongoose.model('User', userSchema);
const Message = mongoose.model('Message', messageSchema);

// --- API endpoints (same shapes as before) ---

// Register
app.post('/api/register', async (req, res) => {
  try {
    const { username, publicKeyPem } = req.body;
    if (!username || !publicKeyPem) return res.status(400).json({ error: 'username and publicKeyPem required' });

    // If user exists, return existing token (safer than overwriting)
    const existing = await User.findOne({ username }).lean();
    if (existing) {
      return res.json({ token: existing.token });
    }

    const token = crypto.randomBytes(16).toString('hex');
    const user = new User({ username, publicKeyPem, token });
    await user.save();
    return res.json({ token });
  } catch (err) {
    console.error(err);
    return res.status(500).json({ error: 'internal error' });
  }
});

// Fetch a user's public key
app.get('/api/publicKey/:username', async (req, res) => {
  try {
    const u = await User.findOne({ username: req.params.username }).lean();
    if (!u) return res.status(404).json({ error: 'user not found' });
    return res.json({ publicKeyPem: u.publicKeyPem });
  } catch (err) {
    console.error(err);
    return res.status(500).json({ error: 'internal error' });
  }
});

// Send encrypted message - server requires x-api-key header matching sender's token
app.post('/api/send', async (req, res) => {
  try {
    const { from, to, ciphertext, encryptedKey, iv } = req.body;
    if (!from || !to || !ciphertext || !encryptedKey || !iv) return res.status(400).json({ error: 'missing fields' });

    const user = await User.findOne({ username: from }).lean();
    if (!user) return res.status(400).json({ error: 'unknown sender' });

    const apiKey = req.headers['x-api-key'];
    if (!apiKey || apiKey !== user.token) return res.status(401).json({ error: 'invalid api key' });

    const msg = new Message({ from, to, ciphertext, encryptedKey, iv });
    await msg.save();

    return res.json({ ok: true });
  } catch (err) {
    console.error(err);
    return res.status(500).json({ error: 'internal error' });
  }
});

// Fetch messages for a user
app.get('/api/messages/:username', async (req, res) => {
  try {
    const username = req.params.username;
    const user = await User.findOne({ username }).lean();
    if (!user) return res.status(404).json({ error: 'unknown user' });

    const apiKey = req.headers['x-api-key'];
    if (!apiKey || apiKey !== user.token) return res.status(401).json({ error: 'invalid api key' });

    const messages = await Message.find({ to: username }).sort({ timestamp: 1 }).lean();
    return res.json({ messages });
  } catch (err) {
    console.error(err);
    return res.status(500).json({ error: 'internal error' });
  }
});

// Convenience: list usernames
app.get('/api/users', async (req, res) => {
  try {
    const docs = await User.find({}, 'username').lean();
    return res.json({ users: docs.map(d => d.username) });
  } catch (err) {
    console.error(err);
    return res.status(500).json({ error: 'internal error' });
  }
});

// Start
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Server listening at http://localhost:${PORT}`));
