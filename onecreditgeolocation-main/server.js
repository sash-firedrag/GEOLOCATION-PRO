// server.js (Updated with correct static path)
const express = require("express");
const mongoose = require("mongoose");
const bodyParser = require("body-parser");
const cors = require("cors");
const path = require('path');

const app = express();
const PORT = 3000;

mongoose.connect("mongodb://127.0.0.1:27017/location-attendance").then(() => {
  console.log('Connected to MongoDB');
}).catch(err => {
  console.error('MongoDB connection error:', err);
  process.exit(1);
});

const UserSchema = new mongoose.Schema({
  username: { type: String, unique: true },
  password: String,
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

// ✅✅✅ FIXED LINE - Changed from 'frontend' to '../frontend' ✅✅✅
app.use(express.static(path.join(__dirname, '..', 'frontend')));

app.use(bodyParser.json());
app.use(session({
  secret: 'attendance_secret',
  resave: false,
  saveUninitialized: false,
  cookie: { secure: false, httpOnly: true }
}));

// Signup API
app.post('/api/signup', async (req, res) => {
  try {
    const { username, password } = req.body;
    if (!username || !password) {
      return res.status(400).json({ message: 'Username and password required' });
    }
    const existing = await User.findOne({ username });
    if (existing) {
      return res.status(409).json({ message: 'Username already exists' });
    }
    const hash = await bcrypt.hash(password, 10);
    const user = new User({ username, password: hash });
    await user.save();
    res.json({ message: 'Signup successful' });
  } catch (err) {
    res.status(500).json({ message: 'Server error' });
  }
});

// Login API
app.post('/api/login', async (req, res) => {
  try {
    const { username, password } = req.body;
    if (!username || !password) {
      return res.status(400).json({ message: 'Username and password required' });
    }
    
    let user;
    if (username === 'admin') {
      // Special handling for admin
      if (password !== 'admin123') {
        return res.status(401).json({ message: 'Invalid credentials' });
      }
      user = await User.findOne({ username: 'admin' });
      if (!user) {
        // Create admin user if not exists
        const hash = await bcrypt.hash('admin123', 10);
        user = new User({ username: 'admin', password: hash });
        await user.save();
      }
    } else {
      user = await User.findOne({ username });
      if (!user) {
        return res.status(401).json({ message: 'Invalid credentials' });
      }
      const valid = await bcrypt.compare(password, user.password);
      if (!valid) {
        return res.status(401).json({ message: 'Invalid credentials' });
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

// Logout API
app.post('/api/logout', (req, res) => {
  req.session.destroy(() => {
    res.json({ message: 'Logged out' });
  });
});

// Auth middleware
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

const OFFICE_LAT = 10.575161;
const OFFICE_LON = 77.245014;
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

app.use((err, req, res, next) => {
  console.error(err);
  res.status(500).json({ message: 'Internal server error' });
});

app.listen(PORT, () => {
  console.log(`Server running on http://localhost:${PORT}`);
});