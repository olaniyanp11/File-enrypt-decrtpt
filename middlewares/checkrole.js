// middleware/roleCheck.js
function requireRole(role){
  return (req, res, next) => {
    if (req.user && req.user.role === role) {
      return next();
    }
    return res.status(403).send('Access denied');
  };
};

module.exports = requireRole