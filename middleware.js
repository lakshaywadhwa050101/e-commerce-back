const jwt = require("jsonwebtoken");

const SECRET_KEY = "your_secret_key"; // Change this to a more secure secret key

// Middleware to verify JWT token
const verifyToken = (req, res, next) => {
  const token = req.headers["authorization"];
  if (!token) {
    return res.status(403).json({ error: "Token is required" });
  }
  jwt.verify(token, SECRET_KEY, (err, decoded) => {
    if (err) {
      return res.status(401).json({ error: "Invalid token" });
    }
    req.user = decoded.user;
    next();
  });
};

module.exports = verifyToken;
