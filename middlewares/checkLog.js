// middlewares/checkLog.js
const jwt = require('jsonwebtoken');
const dotenv = require('dotenv');
dotenv.config();

function authenticateToken(req, res, next) {
  const token = req.cookies.token;

  if (!token) {
    req.flash('error', 'You must be logged in to access this page.');
    return res.redirect('/login');
  }

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    req.user = { _id: decoded.userId }; // optionally attach to req
    return next();
  } catch (err) {
    res.clearCookie('token');
    req.flash('error', 'Session expired. Please log in again.');
    return res.redirect('/login');
  }
}

module.exports = authenticateToken;
