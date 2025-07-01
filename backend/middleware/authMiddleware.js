// authMiddleware.js content goes here
import jwt from "jsonwebtoken";
const SECRET = "mysecretkey";

export function verifyToken(req, res, next) {
  const token = req.headers.authorization?.split(" ")[1];
  if (!token) return res.status(401).json({ msg: "Unauthorized" });

  jwt.verify(token, SECRET, (err, decoded) => {
    if (err) return res.status(403).json({ msg: "Invalid token" });
    req.userId = decoded.id;
    next();
  });
}
