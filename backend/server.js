import express from "express";
import mongoose from "mongoose";
import authRoutes from "./routes/auth.js";
import path from "path";
import { fileURLToPath } from "url";
import cors from "cors";

const app = express();
const PORT = process.env.PORT || 3000;

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// Middleware
app.use(cors());
app.use(express.json());

// ✅ Serve HTML from public folder
app.use(express.static(path.join(__dirname, "../public")));

// Routes
app.use("/api/auth", authRoutes);

// ✅ Handle HTML direct access
app.get("*", (req, res) => {
  const filePath = path.join(__dirname, "../public", req.path);
  if (path.extname(req.path)) {
    res.sendFile(filePath, err => {
      if (err) res.status(404).send("Page not found");
    });
  } else {
    res.sendFile(path.join(__dirname, "../public/index.html"));
  }
});

// MongoDB Connection
mongoose.connect("mongodb+srv://22f01a0540:Authentication@cluster0.qw3z1ik.mongodb.net/")
  .then(() => {
  console.log("✅ MongoDB connected");
  app.listen(PORT, () => console.log(`🚀 Server running on port ${PORT}`));
}).catch(err => {
  console.error("❌ MongoDB connection error:", err);
});
