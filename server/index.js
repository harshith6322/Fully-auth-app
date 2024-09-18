import express from "express";
import dotenv from "dotenv";
import cors from "cors";
import { z } from "zod";
import mongoose from "mongoose";
import { Otp, User } from "./auth.js";
import bcrypt from "bcrypt";
import randomstring from "randomstring";
import nodemailer from "nodemailer";
dotenv.config();

const Port = process.env.PORT || 3000;
const mongoUri = process.env.MONGODB_URL;

if (!mongoUri) {
  console.error("MONGODB_URL is not defined in .env file");
  process.exit(1);
}

mongoose
  .connect(mongoUri)
  .then(() => console.log("Connected to MongoDB"))
  .catch((err) => {
    console.error("Error connecting to MongoDB:", err);
    process.exit(1);
  });

const app = express();
app.use(express.json());
app.use(cors());

const zsignup = z.object({
  username: z.string().min(3, "Username must be at least 3 characters long."),
  gmail: z
    .string()
    .email("Invalid email format")
    .max(50)
    .min(3, "Email must be at least 3 characters long."),
  password: z
    .string()
    .min(7, "Password must be at least 7 characters long")
    .max(50, "Password must be at most 50 characters long."),
});

app.post("/signup", async (req, res) => {
  const body = req.body;
  const result = zsignup.safeParse(body);

  if (!result.success) {
    const errorMessage = result.error.issues[0].message;
    return res.status(400).json({
      status: "error",
      message: errorMessage,
    });
  }

  try {
    const userdb = await User.findOne({ gmail: body.gmail });

    if (userdb) {
      return res.status(406).json({
        status: "error",
        message: "Email already taken",
      });
    }

    const salt = await bcrypt.genSalt(10);
    const hashpass = await bcrypt.hash(body.password, salt);
    const userdb1 = await User.create({
      username: body.username,
      gmail: body.gmail,
      password: hashpass,
    });

    if (!userdb1) {
      return res.status(500).json({
        status: "error",
        message: "Account not created ❌",
      });
    }

    res.json({
      err: false,
      msg: "Account created ✔️",
    });
  } catch (err) {
    console.error("Error processing request:", err);
    res.status(500).json({
      status: "error",
      message: "Something went wrong",
    });
  }
});

const zsignin = z.object({
  gmail: z
    .string()
    .email("Invalid email format")
    .max(50)
    .min(3, "Email must be at least 3 characters long."),
  password: z
    .string()
    .min(7, "Password must be at least 7 characters long")
    .max(50, "Password must be at most 50 characters long."),
});

app.post("/signin", async (req, res) => {
  try {
    const body = req.body;
    const { success } = zsignin.safeParse(body);

    if (!success) {
      return res.status(401).json({
        status: "error",
        message: "input error",
      });
    }
    const db1 = await User.findOne({
      gmail: body.gmail,
    });

    // console.log(db1);
    if (!db1._id) {
      return res.status(401).json({
        status: "error",
        message: "no gmail found",
      });
    }
    const compare = await bcrypt.compare(body.password, db1.password);
    // res.json({ good: "good" });

    if (!compare) {
      return res.status(401).json({
        status: "error",
        message: "incorrect password",
      });
    }

    res.status(200).json({
      status: compare,
      message: "login",
    });
  } catch (err) {
    res.status(400).json({
      status: "error",
      message: "something went wrong",
      code: err,
    });
  }
});

const zodotp = z.object({
  gmail: z
    .string()
    .email("Invalid email format")
    .max(50)
    .min(3, "Email must be at least 3 characters long."),
});

const transporter = nodemailer.createTransport({
  service: "gmail", // Use your email service (e.g., Gmail, Outlook, etc.)
  auth: {
    user: process.env.EMAIL, // Your email address
    pass: process.env.PASSWORD, // Your email password or app password (if using Gmail)
  },
});

app.post("/otp-gen", async (req, res) => {
  const body = req.body;
  const { success } = zodotp.safeParse(body);
  if (!success) {
    return res.status(400).json({
      status: "error",
      message: "incorrect inputs",
    });
  }

  const db1 = await User.findOne({
    gmail: body.gmail,
  });

  if (!db1) {
    return res.status(400).json({
      status: "error",
      message: "incorrect email",
    });
  }

  const existingOtp = await Otp.findOne({ userId: db1._id });

  if (existingOtp) {
    // OTP exists and hasn't expired
    return res.status(400).json({
      status: "error",
      message:
        "An OTP has already been generated for this user. Please wait until it expires.",
    });
  }
  const otpgen = randomstring.generate({
    length: 6,
    charset: "numeric",
  });
  const otpIDgen = randomstring.generate({
    length: 6,
    charset: "numeric",
  });

  const db2 = await Otp.create({
    userId: db1._id,
    otp: otpgen,
    otpId: otpIDgen,
    gmail: body.gmail,
  });

  const mailOptions = {
    from: process.env.EMAIL, // Sender's email address
    to: "harshithreddy6322@gmail.com", // Recipient's email address
    subject: "Your OTP Code", // Email subject
    text: `<h3>Your OTP code is <strong>${otpgen}</strong></h3>.`, // Email content (OTP code)
  };
  await transporter.sendMail(mailOptions, (error, info) => {
    if (error) {
      console.log(error); // Log the error
      return res.status(500).json({ message: "Error sending email", error });
    }
    res.status(200).json({
      message: "Email sent successfully",
      otpid: otpIDgen,
      otp: otpgen,
    });
  });
});

const zodotpveri = z.object({
  gmail: z
    .string()
    .email("Invalid email format")
    .max(50)
    .min(3, "Email must be at least 3 characters long."),

  otp: z.string().min(6).max(6),
  password: z
    .string()
    .min(7, "Password must be at least 7 characters long")
    .max(50, "Password must be at most 50 characters long."),
  otpID: z.string().min(6).max(6),
});
app.post("/opt-verify", async (req, res) => {
  const body = req.body;

  const { success } = zodotpveri.safeParse(body);

  if (!success) {
    return res.status(400).json({
      status: "error",
      message: "incorrect inputs",
    });
  }

  const db1 = await Otp.findOne({
    otpId: body.otpID,
    otp: body.otp,
    gmail: body.gmail,
  });
  console.log(db1);
  if (!db1) {
    return res.status(400).json({
      status: "error",
      message: "incorrect otp",
    });
  }

  const hashpassword = await bcrypt.hash(body.password, 10);
  console.log(hashpassword);
  const db3 = await User.updateOne(
    { gmail: body.gmail }, // Find the user by email
    {
      $set: { password: hashpassword }, // Update the password
    }
  );
  console.log(db3);

  if (db3.modifiedCount === 0) {
    return res.status(400).json({ message: "Password update failed" });
  }

  return res.status(200).json({ message: "Password updated successfully" });
});

app.listen(Port, () => {
  console.log("Server running on http://localhost:" + Port);
});
