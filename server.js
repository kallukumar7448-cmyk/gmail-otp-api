const express = require('express');
const nodemailer = require('nodemailer');
const crypto = require('crypto');
const cors = require('cors');
const path = require('path');
require('dotenv').config();

const app = express();
app.use(express.json());
app.use(cors());

// Serve static frontend
app.use(express.static(path.join(__dirname, 'public')));

// In-memory OTP store (Use Redis in production)
const otpStore = new Map();

// Email transporter
const transporter = nodemailer.createTransport({
  service: 'gmail',
  auth: {
    user: process.env.GMAIL_USER,
    pass: process.env.GMAIL_PASS
  }
});

// Verify email config
transporter.verify((err) => {
  if (err) {
    console.error('❌ Email config error:', err.message);
  } else {
    console.log('✅ Email server ready');
  }
});

// Generate 6-digit OTP
function generateOTP() {
  return crypto.randomInt(100000, 999999).toString();
}

// ===================== ROUTES =====================

// POST /api/send-otp
app.post('/api/send-otp', async (req, res) => {
  try {
    const { email } = req.body;

    if (!email) {
      return res.status(400).json({ success: false, message: 'Email is required' });
    }

    // Cooldown — 60 seconds
    const existing = otpStore.get(email);
    if (existing && (Date.now() - existing.sentAt) < 60000) {
      const sec = Math.ceil((60000 - (Date.now() - existing.sentAt)) / 1000);
      return res.status(429).json({ success: false, message: `Wait ${sec}s before requesting again` });
    }

    const otp = generateOTP();
    const expiryMin = parseInt(process.env.OTP_EXPIRY_MINUTES) || 5;
    const expiresAt = Date.now() + (expiryMin * 60 * 1000);

    otpStore.set(email, { otp, expiresAt, sentAt: Date.now(), attempts: 0 });

    console.log(`📧 OTP ${otp} → ${email}`);

    await transporter.sendMail({
      from: `"OTP Verification" <${process.env.GMAIL_USER}>`,
      to: email,
      subject: 'Your OTP Code',
      html: `
        <div style="font-family:Arial,sans-serif;max-width:400px;margin:auto;padding:20px;">
          <h2>🔐 OTP Verification</h2>
          <p>Your One-Time Password:</p>
          <h1 style="letter-spacing:8px;font-size:38px;background:#f4f4f4;padding:15px;text-align:center;border-radius:8px;">
            ${otp}
          </h1>
          <p>Valid for <strong>${expiryMin} minutes</strong></p>
          <p style="color:#888;font-size:12px;">Ignore if not requested</p>
        </div>
      `
    });

    res.json({ success: true, message: 'OTP sent! Check your email.', expiresIn: `${expiryMin} min` });

  } catch (error) {
    console.error('❌ Send error:', error);
    res.status(500).json({ success: false, message: 'Failed to send OTP' });
  }
});

// POST /api/verify-otp
app.post('/api/verify-otp', (req, res) => {
  try {
    const { email, otp } = req.body;

    if (!email || !otp) {
      return res.status(400).json({ success: false, message: 'Email and OTP required' });
    }

    const stored = otpStore.get(email);
    if (!stored) {
      return res.status(400).json({ success: false, message: 'No OTP found. Request a new one.' });
    }

    if (Date.now() > stored.expiresAt) {
      otpStore.delete(email);
      return res.status(400).json({ success: false, message: 'OTP expired. Request a new one.' });
    }

    stored.attempts++;
    if (stored.attempts > 5) {
      otpStore.delete(email);
      return res.status(429).json({ success: false, message: 'Too many attempts. Request new OTP.' });
    }

    if (stored.otp !== otp) {
      return res.status(400).json({ success: false, message: 'Invalid OTP', remaining: 5 - stored.attempts });
    }

    otpStore.delete(email);
    console.log(`✅ Verified: ${email}`);

    res.json({ success: true, message: 'OTP verified successfully!', verified: true });

  } catch (error) {
    console.error('❌ Verify error:', error);
    res.status(500).json({ success: false, message: 'Verification failed' });
  }
});

// GET /api/health
app.get('/api/health', (req, res) => {
  res.json({ status: 'ok', activeOTPs: otpStore.size, time: new Date().toISOString() });
});

// Cleanup expired OTPs
setInterval(() => {
  const now = Date.now();
  for (const [email, data] of otpStore.entries()) {
    if (now > data.expiresAt) otpStore.delete(email);
  }
}, 5 * 60 * 1000);

// Start server
const PORT = process.env.PORT || 3000;
app.listen(PORT, '0.0.0.0', () => {
  console.log(`🚀 OTP API running on port ${PORT}`);
});
