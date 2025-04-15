const jwt = require('jsonwebtoken');
const accessSecret = process.env.ACCESS_SECRET;
const refreshSecret = process.env.REFRESH_SECRET;
const THREE_MINUTES = 3 * 60 * 1000;

// Middleware to authenticate using Authorization Header (Bearer token)
function authenticate(req, res, next) {
  const token = req.headers['authorization']?.split(' ')[1];
  if (!token) return res.sendStatus(401); // No token provided

  try {
    const user = jwt.verify(token, accessSecret);
    req.user = user;
    next(); // Valid token
  } catch {
    res.sendStatus(403); // Invalid token
  }
}

// Middleware to validate accessToken and refreshToken from cookies
function validateTokens(req, res, next) {
  const { accessToken, refreshToken } = req.cookies;
  console.log('Tokens (Decoded):', jwt.decode(accessToken), jwt.decode(refreshToken));

  // No tokens present
  if (!accessToken && !refreshToken) {
    return res.status(401).json({ message: 'No tokens provided' });
  }

  // Access token missing, refresh token present
  if (!accessToken && refreshToken) {
    return res.status(402).json({ message: 'Access token missing. Refresh required.', refresh: true });
  }

  // Try validating access token
  try {
    const user = jwt.verify(accessToken, accessSecret);
    req.user = user;
    return next(); // Valid access token
  } catch (err) {
    if (err.name !== 'TokenExpiredError') {
      return res.status(403).json({ message: 'Invalid access token' });
    }
  }

  // Access token expired - validate refresh token
  try {
    const user = jwt.verify(refreshToken, refreshSecret);
    req.user = user;
    return next(); // Valid refresh token
  } catch (err) {
    if (err.name === 'TokenExpiredError') {
      return res.status(440).json({ message: 'Session expired. Please log in again.' });
    }
    return res.status(403).json({ message: 'Invalid refresh token' });
  }
}

// Middleware to check user inactivity via lastActivity cookie
function checkInactivity(req, res, next) {
  const lastActivity = req.cookies.lastActivity;
  const now = Date.now();

  // No activity cookie - session likely expired
  if (!lastActivity) {
    return res.status(440).json({ message: 'Session expired due to inactivity' });
  }

  const inactiveTooLong = now - parseInt(lastActivity) > THREE_MINUTES;

  if (inactiveTooLong) {
    console.log('Session expired due to inactivity');
    res.clearCookie('accessToken');
    res.clearCookie('refreshToken');
    res.clearCookie('lastActivity');
    return res.status(440).json({ message: 'Session expired due to inactivity' });
  }

  // Update lastActivity cookie
  res.cookie('lastActivity', now.toString(), {
    httpOnly: true,
    sameSite: 'Strict',
    maxAge: THREE_MINUTES,
  });

  next();
}

module.exports = {
  authenticate,
  validateTokens,
  checkInactivity
};
