// routes/auth.js
import express from "express";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import crypto from "crypto";
import User from "../models/User.js";
import transporter from "../config/email.js";

const router = express.Router();
const SECRET = "mysecretkey";

// Password validation helper
function isValidPassword(password) {
  return password.length >= 6 && /\d/.test(password) && /[!@#$%^&*]/.test(password);
}

// Register
router.post("/register", (req, res) => {
  const { username, password } = req.body;

  if (!isValidPassword(password)) {
    return res.status(400).json({ msg: "Weak password" });
  }

  User.findOne({ username })
    .then(existing => {
      if (existing) return res.status(400).json({ msg: "User already exists" });
      return bcrypt.hash(password, 10);
    })
    .then(hashed => {
      const token = crypto.randomBytes(32).toString("hex");
      const newUser = new User({
        username,
        password: hashed,
        verifyToken: token,
        verifyTokenExpiry: Date.now() + 3600000
      });
      return newUser.save().then(() => {
        const link = `https://user-authentication-system-1-jlq3.onrender.com/verify.html?token=${token}`;
        transporter.sendMail({
          to: username,
          from: "c.sec.balls@gmail.com",
          subject: "Verify Your Email",
          html: `<p>Click <a href="${link}">here</a> to verify your email.</p>`
        });
        res.json({ msg: "Registered successfully. Check your email for verification." });
      });
    })
    .catch(err => {
      console.error("❌ Register Error:", err);
      res.status(500).json({ msg: "Server error" });
    });
});

// ✅ Updated Email Verification Route (JSON Response)
router.get("/verify-email", (req, res) => {
  const { token } = req.query;
  console.log("🔍 Verifying email with token:", token);

  if (!token) {
    return res.status(400).json({ msg: "Missing token" });
  }

  User.findOne({
    verifyToken: token,
    verifyTokenExpiry: { $gt: Date.now() }
  })
    .then(user => {
      if (!user) return res.status(400).json({ msg: "Invalid or expired token" });

      user.isVerified = true;
      user.verifyToken = undefined;
      user.verifyTokenExpiry = undefined;

      return user.save().then(() =>
        res.json({ msg: "Email verified successfully" })
      );
    })
    .catch(err => {
      console.error("❌ Verification Error:", err);
      res.status(500).json({ msg: "Verification failed due to server error" });
    });
});

// Login
router.post("/login", (req, res) => {
  const { username, password } = req.body;

  User.findOne({ username })
    .then(user => {
      if (!user) return res.status(400).json({ msg: "Invalid credentials" });
      if (!user.isVerified) return res.status(403).json({ msg: "Email not verified" });

      bcrypt.compare(password, user.password).then(match => {
        if (!match) return res.status(400).json({ msg: "Invalid credentials" });

        const token = jwt.sign({ id: user._id, username: user.username }, SECRET, { expiresIn: "1h" });
        res.json({ token });
      });
    })
    .catch(err => {
      console.error("❌ Login Error:", err);
      res.status(500).json({ msg: "Login failed" });
    });
});

// Forgot Password
router.post("/forgot-password", (req, res) => {
  const { username } = req.body;
  const token = crypto.randomBytes(32).toString("hex");

  console.log("📨 Forgot password request for:", username);

  User.findOne({ username: { $regex: new RegExp(`^${username}$`, "i") } })
    .then(user => {
      if (!user) return res.status(400).json({ msg: "User not found" });
      if (!user.isVerified) return res.status(403).json({ msg: "Email not verified" });

      user.resetToken = token;
      user.tokenExpiry = Date.now() + 3600000;

      return user.save().then(() => {
        const link = `https://user-authentication-system-1-jlq3.onrender.com/reset-password.html?token=${token}`;
        transporter.sendMail({
          to: user.username,
          from: "c.sec.balls@gmail.com",
          subject: "Reset Your Password",
          html: `<p><a href="${link}">Click here</a> to reset your password.</p>`
        });
        res.json({ msg: "Reset password link sent to your email." });
      });
    })
    .catch(err => {
      console.error("❌ Forgot Password Error:", err);
      res.status(500).json({ msg: "Server error" });
    });
});

// Reset Password
router.post("/reset-password", (req, res) => {
  const { token, newPassword } = req.body;

  if (!isValidPassword(newPassword)) {
    return res.status(400).json({ msg: "Weak password" });
  }

  User.findOne({ resetToken: token, tokenExpiry: { $gt: Date.now() } })
    .then(user => {
      if (!user) return res.status(400).json({ msg: "Token expired or invalid" });

      return bcrypt.hash(newPassword, 10).then(hashed => {
        user.password = hashed;
        user.resetToken = undefined;
        user.tokenExpiry = undefined;

        return user.save().then(() =>
          res.json({ msg: "Password reset successful" })
        );
      });
    })
    .catch(err => {
      console.error("❌ Reset Password Error:", err);
      res.status(500).json({ msg: "Reset failed" });
    });
});

export default router;
