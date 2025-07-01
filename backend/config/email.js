
import nodemailer from "nodemailer";

const transporter = nodemailer.createTransport({
  service: "gmail",
  auth: {
        user: "c.sec.balls@gmail.com",
        pass: "wuim utok aaxv rbwk"
  }
});

export default transporter;
