// db.js content goes here
import mongoose from "mongoose";

const connectDB = () => {
  mongoose.connect("mongodb+srv://maheshburla562:Authentication@cluster0.t3zuxnl.mongodb.net/")
    .then(() => console.log("MongoDB connected"))
    .catch((err) => {
      console.error("MongoDB error:", err);
      process.exit(1);
    });
};

export default connectDB;