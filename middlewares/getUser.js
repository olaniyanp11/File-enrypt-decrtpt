const User = require("../models/User");
const dotenv = require('dotenv');
const jwt = require('jsonwebtoken');

dotenv.config();

async function getUser(req, res, next) {
  const token = req.cookies.token;
  let user = null;

  if (!token) {
    req.user = null;
    return next();
  }

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET || 'your_jwt_secret');

    user = await User.findById(decoded.userId);
    if (!user) {
      req.user = null;
      return next();
    }

    req.user = user;
    next();
  } catch (err) {
    if (err.name === 'TokenExpiredError') {
      req.flash('error_msg', 'Session expired. Please log in again.');
      res.clearCookie('token');
      return res.redirect('/logout');
    }

    console.error('JWT Error:', err.message);
    req.user = null;
    return res.redirect('/logout');
  }
}

module.exports = getUser;
