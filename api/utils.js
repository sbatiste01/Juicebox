require("dotenv").config()
const jwt = require("jsonwebtoken")

// FOR PROBLEM 2
function requireUser(req, res, next) {
if (req.headers.authorization) {
  const authHeader = req.headers.authorization;
  const headerParts = authHeader.split(' ');

  if (headerParts.length === 2 && headerParts[0] === 'Bearer') {
    const token = headerParts[1];
   
    try {
      const data = jwt.verify(token, process.env.JWT_SECRET);
      req.user = data;
      next();
    } catch (err) {
      res.status(401).json({ error: 'Token is invalid or expired' });
    }
  } else {
    res.status(401).json({ error: 'Invalid Authorization Header format' });
  }
} else {
  res.status(401).json({ error: 'Authorization Header missing' });
}
}

module.exports = {
  requireUser
}