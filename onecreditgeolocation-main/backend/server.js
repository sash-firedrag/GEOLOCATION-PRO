// server.js (Updated with REAL Email Verification - CORRECTED)
const express = require("express");
const mongoose = require("mongoose");
const bodyParser = require("body-parser");
const cors = require("cors");
const path = require('path');
const nodemailer = require('nodemailer');

const app = express();
const PORT = 3000;

mongoose.connect("mongodb://127.0.0.1:27017/location-attendance").then(() => {
  console.log('Connected to MongoDB');
}).catch(err => {
  console.error('MongoDB connection error:', err);
  process.exit(1);
});

// Updated User Schema with email verification
const UserSchema = new mongoose.Schema({
  username: { type: String, unique: true },
  password: String,
  email: { type: String, unique: true },
  isVerified: { type: Boolean, default: false },
  verificationToken: String,
  verificationExpires: Date
});
const User = mongoose.model("User", UserSchema);

const PunchSchema = new mongoose.Schema({
  username: String,
  punchInTime: Date,
  punchOutTime: Date,
  location: {
    lat: Number,
    lon: Number,
  },
});
const Punch = mongoose.model("Punch", PunchSchema);

const session = require('express-session');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

app.use(cors({
  origin: 'http://localhost:3000',
  credentials: true
}));
app.use(express.static(path.join(__dirname, '../frontend')));
app.use(bodyParser.json());
app.use(session({
  secret: 'attendance_secret',
  resave: false,
  saveUninitialized: false,
  cookie: { secure: false, httpOnly: true }
}));

// ✅ CORRECTED: It's createTransport (not createTransporter)
const transporter = nodemailer.createTransport({
  service: 'gmail',
  auth: {
    user: 'roshinim.23csd@kongu.edu',     // ⬅️ CHANGE TO YOUR GMAIL
    pass: 'twxr axna uxnc afur'         // ⬅️ CHANGE TO YOUR APP PASSWORD
  }
});

// Generate random token
function generateVerificationToken() {
  return Math.random().toString(36).substring(2, 15) + 
         Math.random().toString(36).substring(2, 15);
}

// REAL Email function - sends actual emails
async function sendVerificationEmail(email, token) {
  const verificationLink = `http://localhost:3000/verify-email.html?token=${token}`;
  
  const mailOptions = {
    from: 'your-email@gmail.com', // ⬅️ SAME AS ABOVE
    to: email,
    subject: 'Verify Your Email - GeoAttendance Pro',
    html: `
      <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px; border: 1px solid #ddd; border-radius: 10px;">
        <div style="text-align: center; margin-bottom: 20px;">
          <h2 style="color: #667eea; margin: 0;">GeoAttendance Pro</h2>
          <p style="color: #666; margin: 5px 0;">Smart Location-Based Attendance System</p>
        </div>
        
        <h3 style="color: #333;">Email Verification Required</h3>
        <p>Hello!</p>
        <p>Please verify your email address to complete your registration and start using GeoAttendance Pro.</p>
        
        <div style="text-align: center; margin: 30px 0;">
          <a href="${verificationLink}" 
             style="background: linear-gradient(135deg, #667eea, #764ba2); color: white; padding: 15px 30px; 
                    text-decoration: none; border-radius: 25px; display: inline-block; font-weight: bold;
                    font-size: 16px; box-shadow: 0 4px 15px rgba(102, 126, 234, 0.4);">
            Verify Email Address
          </a>
        </div>
        
        <p style="color: #666; font-size: 14px;">Or copy and paste this link in your browser:</p>
        <p style="background: #f5f5f5; padding: 10px; border-radius: 5px; word-break: break-all; font-size: 12px;">
          ${verificationLink}
        </p>
        
        <div style="margin-top: 30px; padding-top: 20px; border-top: 1px solid #eee;">
          <p style="color: #999; font-size: 12px;">
            This verification link will expire in 24 hours.<br>
            If you didn't create an account with GeoAttendance Pro, please ignore this email.
          </p>
        </div>
      </div>
    `
  };

  try {
    await transporter.sendMail(mailOptions);
    console.log('✅ Verification email sent to:', email);
    return true;
  } catch (error) {
    console.error('❌ Failed to send email:', error);
    throw new Error('Failed to send verification email');
  }
}

// Updated Signup API with REAL email verification
app.post('/api/signup', async (req, res) => {
  try {
    const { username, password, email } = req.body;
    
    if (!username || !password || !email) {
      return res.status(400).json({ message: 'Username, password and email required' });
    }

    const existingUser = await User.findOne({ 
      $or: [{ username }, { email }] 
    });
    
    if (existingUser) {
      return res.status(409).json({ 
        message: 'Username or email already exists' 
      });
    }

    const hash = await bcrypt.hash(password, 10);
    const verificationToken = generateVerificationToken();
    const verificationExpires = new Date(Date.now() + 24 * 60 * 60 * 1000); // 24 hours

    const user = new User({ 
      username, 
      password: hash, 
      email,
      verificationToken,
      verificationExpires
    });
    
    await user.save();
    
    // Send REAL verification email
    await sendVerificationEmail(email, verificationToken);
    
    res.json({ 
      message: 'Signup successful! Please check your email for verification link.',
      requiresVerification: true
    });
    
  } catch (err) {
    console.error('Signup error:', err);
    res.status(500).json({ message: 'Server error' });
  }
});

// Email Verification API
app.get('/api/verify-email', async (req, res) => {
  try {
    const { token } = req.query;
    
    if (!token) {
      return res.status(400).json({ message: 'Verification token required' });
    }

    const user = await User.findOne({ 
      verificationToken: token,
      verificationExpires: { $gt: new Date() }
    });

    if (!user) {
      return res.status(400).json({ 
        message: 'Invalid or expired verification token' 
      });
    }

    user.isVerified = true;
    user.verificationToken = undefined;
    user.verificationExpires = undefined;
    await user.save();

    res.json({ message: 'Email verified successfully! You can now login.' });
    
  } catch (err) {
    console.error('Verification error:', err);
    res.status(500).json({ message: 'Server error' });
  }
});

// Updated Login API with verification check
app.post('/api/login', async (req, res) => {
  try {
    const { username, password } = req.body;
    
    if (!username || !password) {
      return res.status(400).json({ message: 'Username and password required' });
    }
    
    let user;
    if (username === 'admin') {
      // Admin bypass (no email verification needed for admin)
      if (password !== 'admin123') {
        return res.status(401).json({ message: 'Invalid credentials' });
      }
      user = await User.findOne({ username: 'admin' });
      if (!user) {
        const hash = await bcrypt.hash('admin123', 10);
        user = new User({ 
          username: 'admin', 
          password: hash,
          email: 'admin@geoattendance.com',
          isVerified: true
        });
        await user.save();
      }
    } else {
      // Regular user - check verification
      user = await User.findOne({ username });
      
      if (!user) {
        return res.status(401).json({ message: 'Invalid credentials' });
      }
      
      const valid = await bcrypt.compare(password, user.password);
      if (!valid) {
        return res.status(401).json({ message: 'Invalid credentials' });
      }
      
      // Check if email is verified
      if (!user.isVerified) {
        return res.status(403).json({ 
          message: 'Please verify your email before logging in. Check your inbox.',
          requiresVerification: true,
          email: user.email
        });
      }
    }
    
    req.session.user = { username: user.username };
    let response = { message: 'Login successful' };
    
    if (username === 'admin') {
      const token = jwt.sign({ username }, 'attendance_secret');
      response.token = token;
    }
    
    res.json(response);
    
  } catch (err) {
    res.status(500).json({ message: 'Server error' });
  }
});

// ... REST OF YOUR APIS (punch-in, punch-out, etc.) remain the same
app.post('/api/logout', (req, res) => {
  req.session.destroy(() => {
    res.json({ message: 'Logged out' });
  });
});

function requireAuth(req, res, next) {
  if (req.session && req.session.user) {
    next();
  } else {
    res.status(401).json({ message: 'Unauthorized' });
  }
}

function requireAdmin(req, res, next) {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ message: 'No token provided' });
  }
  const token = authHeader.split(' ')[1];
  try {
    const decoded = jwt.verify(token, 'attendance_secret');
    if (decoded.username !== 'admin') {
      return res.status(403).json({ message: 'Not authorized' });
    }
    req.user = decoded;
    next();
  } catch (err) {
    res.status(401).json({ message: 'Invalid token' });
  }
}

const OFFICE_LAT = 10.575111;
const OFFICE_LON = 77.244652;
const GEOFENCE_RADIUS_METERS = 100;

function getDistance(lat1, lon1, lat2, lon2) {
  const R = 6371e3;
  const toRad = (deg) => (deg * Math.PI) / 180;
  const dLat = toRad(lat2 - lat1);
  const dLon = toRad(lon2 - lon1);
  const a =
    Math.sin(dLat / 2) ** 2 +
    Math.cos(toRad(lat1)) *
      Math.cos(toRad(lat2)) *
      Math.sin(dLon / 2) ** 2;
  const c = 2 * Math.atan2(Math.sqrt(a), Math.sqrt(1 - a));
  return R * c;
}

// Punch In API (requires auth)
app.post("/api/punch-in", requireAuth, async (req, res) => {
  try {
    const username = req.session.user.username;
    const { lat, lon } = req.body;
    const distance = getDistance(lat, lon, OFFICE_LAT, OFFICE_LON);
    if (distance > GEOFENCE_RADIUS_METERS) {
      return res.status(403).json({ message: "Outside geofence area" });
    }
    const punch = new Punch({
      username,
      punchInTime: new Date(),
      location: { lat, lon },
    });
    await punch.save();
    res.json({ message: "Punch In successful" });
  } catch (err) {
    res.status(500).json({ message: 'Server error' });
  }
});

// Punch Out API (requires auth)
app.post("/api/punch-out", requireAuth, async (req, res) => {
  try {
    const username = req.session.user.username;
    const { lat, lon } = req.body;
    const distance = getDistance(lat, lon, OFFICE_LAT, OFFICE_LON);
    if (distance > GEOFENCE_RADIUS_METERS) {
      return res.status(403).json({ message: "Outside geofence area" });
    }
    const latest = await Punch.findOne({ username, punchOutTime: null }).sort({ punchInTime: -1 });
    if (!latest) {
      return res.status(400).json({ message: "No active punch-in found" });
    }
    latest.punchOutTime = new Date();
    await latest.save();
    res.json({ message: "Punch Out successful" });
  } catch (err) {
    res.status(500).json({ message: 'Server error' });
  }
});

// Get all punches (requires auth)
app.get("/api/punches", requireAuth, async (req, res) => {
  try {
    const data = await Punch.find({ username: req.session.user.username }).sort({ punchInTime: -1 });
    res.json(data);
  } catch (err) {
    res.status(500).json({ message: 'Server error' });
  }
});

app.get('/api/admin/attendance', requireAdmin, async (req, res) => {
  try {
    const data = await Punch.find({}).sort({ punchInTime: -1 });
    res.json(data);
  } catch (err) {
    res.status(500).json({ message: 'Server error' });
  }
});

// Resend verification email endpoint
app.post('/api/resend-verification', async (req, res) => {
  try {
    const { email } = req.body;
    
    if (!email) {
      return res.status(400).json({ message: 'Email required' });
    }

    const user = await User.findOne({ email });
    
    if (!user) {
      return res.status(404).json({ message: 'User not found' });
    }

    if (user.isVerified) {
      return res.status(400).json({ message: 'Email already verified' });
    }

    const verificationToken = generateVerificationToken();
    const verificationExpires = new Date(Date.now() + 24 * 60 * 60 * 1000);

    user.verificationToken = verificationToken;
    user.verificationExpires = verificationExpires;
    await user.save();

    await sendVerificationEmail(email, verificationToken);

    res.json({ 
      message: 'Verification email sent! Please check your inbox.'
    });
    
  } catch (err) {
    console.error('Resend verification error:', err);
    res.status(500).json({ message: 'Server error' });
  }
});

app.use((err, req, res, next) => {
  console.error(err);
  res.status(500).json({ message: 'Internal server error' });
});

app.listen(PORT, () => {
  console.log(`Server running on http://localhost:${PORT}`);
  console.log('👑 Admin login: admin / admin123');
  console.log('📧 Email verification: Enabled (REAL Emails)');
});