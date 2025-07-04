const jwt = require('jsonwebtoken');
const dotenv = require('dotenv');
dotenv.config();

function redirectIfAuthenticated(req, res, next) {
  const token = req.cookies.token;

  if (!token) return next(); // Not authenticated, continue to login/register

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);

    const dashboard = decoded.role === 'admin'
      ? '/admin/dashboard'
      : '/user';
      console.log(token)
    return res.redirect(dashboard);

  } catch (err) {
    // Token is invalid or expired
    res.clearCookie('token');
    return next();
  }
}

module.exports = redirectIfAuthenticated;
