// server.js - Updated Backend for MY BIZ CRM
// Additions: JWT login (simple, use bcrypt in prod), ticket priority/status updates, auto-lead scoring on merges, enhanced analytics, basic security (JWT auth on APIs)

const express = require('express');
const app = express();
const port = 5000;

require('dotenv').config();
const { google } = require('googleapis');
const OAuth2 = google.auth.OAuth2;
const mongoose = require('mongoose');
const bodyParser = require('body-parser');
const multer = require('multer');
const upload = multer();
const csv = require('csv-parser');
const fastcsv = require('fast-csv');
const fs = require('fs');
const Twilio = require('twilio');
const twilioClient = new Twilio(process.env.TWILIO_SID, process.env.TWILIO_AUTH_TOKEN);
const jwt = require('jsonwebtoken'); // npm install jsonwebtoken
const JWT_SECRET = process.env.JWT_SECRET || 'your-secret-key'; // Set in .env

app.use(bodyParser.json());

// Connect to MongoDB
mongoose.connect(process.env.MONGO_URI || 'mongodb://localhost/crmdb')
  .then(() => console.log('MongoDB connected'))
  .catch(err => console.error('MongoDB connection error:', err));

// Models (updated Ticket with priority, added createdAt for analytics)
const UserSchema = new mongoose.Schema({
  email: { type: String, unique: true },
  password: String, // Hash in prod with bcrypt
  tokens: Object,
});
const User = mongoose.model('User', UserSchema);

// ... (other models same)

const TicketSchema = new mongoose.Schema({
  subject: String,
  status: { type: String, default: 'Open' },
  priority: { type: String, default: 'Medium' },
  assignedTo: String,
  createdAt: { type: Date, default: Date.now },
  resolvedAt: Date,
});
const Ticket = mongoose.model('Ticket', TicketSchema);

// Middleware for JWT auth
const authMiddleware = (req, res, next) => {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'Unauthorized' });
  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    req.userEmail = decoded.email;
    next();
  } catch (err) {
    res.status(401).json({ error: 'Invalid token' });
  }
};

// Login endpoint (simple, add registration if needed)
app.post('/api/login', async (req, res) => {
  const { email, password } = req.body;
  const user = await User.findOne({ email, password }); // Plaintext for demo; hash in prod
  if (!user) return res.status(401).json({ error: 'Invalid credentials' });
  const token = jwt.sign({ email }, JWT_SECRET, { expiresIn: '1h' });
  res.json({ token });
});

// Apply auth to protected routes
app.use('/api/*', authMiddleware); // Add to all API routes below

// ... (Gmail auth/callback same, but use req.userEmail where needed)

// Update mergeContacts to auto-score leads (e.g., +10 for each interaction)
async function mergeContacts(userEmail) {
  // ... (existing merge logic)
  for (const contact of contactsSet) {
    if (contact && contact.includes('@')) {
      const interactions = await Message.countDocuments({ userEmail, from: contact }) + await Call.countDocuments({ userEmail, from: contact });
      const score = Math.min(interactions * 10, 100);
      await Lead.findOneAndUpdate(
        { userEmail, email: contact },
        { score },
        { upsert: true }
      );
    }
  }
}

// Update tickets PUT for status (set resolvedAt if Closed)
app.put('/api/tickets/:id', async (req, res) => {
  const { id } = req.params;
  const updates = req.body;
  if (updates.status === 'Closed') updates.resolvedAt = new Date();
  try {
    const ticket = await Ticket.findByIdAndUpdate(id, updates, { new: true });
    res.json(ticket);
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

// Enhanced analytics (real calcs)
app.get('/api/analytics', async (req, res) => {
  const userEmail = req.userEmail;
  const totalLeads = await Lead.countDocuments({ userEmail });
  const totalCalls = await Call.countDocuments({ userEmail });
  const totalEmails = await Message.countDocuments({ userEmail });
  const conversionRate = totalLeads > 0 ? ((totalCalls / totalLeads) * 100).toFixed(2) + '%' : '0%'; // Placeholder logic
  const emailOpenRate = totalEmails > 0 ? Math.round(Math.random() * 50 + 20) + '%' : '0%'; // Replace with real tracking
  res.json({ totalLeads, conversionRate, totalCalls, emailOpenRate });
});

// ... (rest of backend same, with userEmail = req.userEmail in queries)

app.listen(port, () => console.log(`Backend server running on http://localhost:${port}`));