import * as mongoose from "mongoose";
import { string } from "zod";

const Userschema = new mongoose.Schema({
  username: {
    type: String,
    required: true,
    minLength: 3,
    maxLength: 255,
    trim: true,
  },
  gmail: {
    type: String,
    required: true,
    maxLength: 30,
    trim: true,
    unique: true,
    trim: true,
    lowercase: true,
    minLength: 3,
    maxLength: 30,
  },
  password: {
    type: String,
    required: true,
    minLength: 3,
    maxLength: 255,
    trim: true,
  },
  creationAt: { type: Date, default: Date.now },
});

const otpschema = new mongoose.Schema({
  userId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: "User",
    required: true,
  },
  otp: {
    type: String,
    required: true,
  },
  otpId: {
    type: String,
    required: true,
  },
  gmail: {
    type: String,
    required: true,
    maxLength: 30,
    trim: true,
    unique: true,
    trim: true,
    lowercase: true,
    minLength: 3,
    maxLength: 30,
  },

  createdAt: {
    type: Date,
    default: Date.now,
    expires: 120, // The document will automatically be removed after 120 seconds (2 minutes)
  },
});

const User = mongoose.model("User", Userschema);
const Otp = mongoose.model("Otp", otpschema);

export { User, Otp };
