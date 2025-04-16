const express = require('express');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const { getUserByUserId, getPayments, getTransactions } = require('../utils/MockApi');
const { checkInactivity, validateTokens } = require('./authMiddleware');

const router = express.Router();

// Secrets and Expiry Constants
const accessSecret = process.env.ACCESS_SECRET;
const refreshSecret = process.env.REFRESH_SECRET;
const ACCESS_COOKIE_EXPIRY = 5 * 60 * 1000;
const REFRESH_COOKIE_EXPIRY = 10 * 60 * 1000;
const LAST_ACTIVITY_EXPIRY = 3 * 60 * 1000;


// In-memory storage (demo purposes)
let refreshTokens = [];
const loginAttempts = {};
const impMiddleware = [validateTokens, checkInactivity]

// GET /auth/product - Protected route
router.get('/payment', impMiddleware, async (req, res) => {
  const products = await getPayments();
  res.json({ products });
});

router.get('/transaction', impMiddleware, async (req, res) => {
  const transactions = await getTransactions();
  res.json({ transactions });
})

// POST /auth/login
router.post('/login', async (req, res) => {
  const { userId, password } = req.body;
  const user = await getUserByUserId(userId);
  const attempt = loginAttempts[userId] || { count: 0, isLocked: false, lockedUntil: null };

  // Check if account is locked
  if (attempt.isLocked && Date.now() < attempt.lockedUntil) {
    return res.status(403).json({ message: 'Account is locked. Reset your password' });
  }

  // Invalid credentials
  if (!user || !bcrypt.compareSync(password, user.password)) {
    attempt.count += 1;

    // Lock account after 5 failed attempts
    if (attempt.count >= 5) {
      attempt.isLocked = true;
      attempt.lockedUntil = Date.now() + 15 * 60 * 1000; // 15 minutes
      loginAttempts[userId] = attempt;
      return res.status(403).json({ message: 'Account is locked. Reset your password' });
    }

    loginAttempts[userId] = attempt;
    return res.status(401).json({ message: 'Invalid credentials' });
  }

  // Successful login
  delete loginAttempts[userId];

  const accessToken = jwt.sign({ id: user.id }, accessSecret, { expiresIn: process.env.ACCESS_EXPIRY });
  const refreshToken = jwt.sign({ id: user.id }, refreshSecret, { expiresIn: process.env.REFRESH_EXPIRY });

  refreshTokens.push(refreshToken);

  // Set cookies
  res.cookie('accessToken', accessToken, {
    httpOnly: true,
    sameSite: 'Strict',
    maxAge: ACCESS_COOKIE_EXPIRY
  });
  res.cookie('refreshToken', refreshToken, {
    httpOnly: true,
    sameSite: 'Strict',
    maxAge: REFRESH_COOKIE_EXPIRY
  });
  res.cookie('lastActivity', Date.now().toString(), {
    httpOnly: true,
    sameSite: 'Strict',
    maxAge: LAST_ACTIVITY_EXPIRY
  });

  res.json({
    role: user.type,
    email: user.email,
    name: user.name
  });
});

// POST /auth/refresh - Refresh access token
router.post('/refresh', (req, res) => {
  const token = req.cookies?.refreshToken;

  if (!token) {
    return res.status(401).json({ message: 'Refresh token missing' });
  }

  if (!refreshTokens.includes(token)) {
    return res.status(403).json({ message: 'Invalid refresh token' });
  }

  try {
    const payload = jwt.verify(token, refreshSecret);

    const newAccessToken = jwt.sign({ id: payload.id }, accessSecret, {
      expiresIn: process.env.ACCESS_EXPIRY
    });

    res.cookie('accessToken', newAccessToken, {
      httpOnly: true,
      sameSite: 'Strict',
      maxAge: ACCESS_COOKIE_EXPIRY
    });
    res.cookie('lastActivity', Date.now().toString(), {
      httpOnly: true,
      sameSite: 'Strict',
      maxAge: LAST_ACTIVITY_EXPIRY
    });

    res.json({ message: 'Access token refreshed' });
  } catch (err) {
    console.error(err);
    res.status(403).json({ message: 'Invalid or expired refresh token' });
  }
});

// GET /auth/logout - Logout and clear cookies
router.get('/logout', (req, res) => {
  const refreshToken = req.cookies.refreshToken;

  if (!refreshToken) {
    return res.status(401).json({ message: 'Not a valid call' });
  }

  refreshTokens = refreshTokens.filter(token => token !== refreshToken);

  res.clearCookie('accessToken');
  res.clearCookie('refreshToken');
  res.clearCookie('lastActivity');

  res.json({ message: 'Logged out successfully' });
});

module.exports = router;
