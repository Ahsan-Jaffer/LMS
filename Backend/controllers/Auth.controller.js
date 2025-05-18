import User from "../models/User.model.js";
import OTP from "../models/OTP.model.js";
import otpGenerator from "otp-generator";
import z from "zod";

// Validation schema for otp-generation
const sendOtpSchema = z.object({
  email: z.string().email("Invalid email format"),
});

// sendOtp
exports.sendOtp = async (req, res) => {
  try {
    // Validate the input using Zod
    const result = sendOtpSchema.safeParse(req.body);

    if (!result.success) {
      return res.status(400).json({
        success: false,
        message: result.error.errors[0].message,
      });
    }

    const { email } = result.data;
    // Check if user already exists
    const user = await User.findOne({ email });
    if (user) {
      return res.status(400).json({
        success: false,
        message: "User already exists",
      });
    }

    // Generate OTP
    const otp = otpGenerator.generate(6, {
      upperCase: false,
      lowerCase: false,
      specialChars: false,
    });
    console.log("Generated OTP:", otp);

    //Check Uniqueness of OTP
    let existingOtp = await OTP.findOne({ otp });
    while (existingOtp) {
      otp = otpGenerator.generate(6, {
        upperCase: false,
        lowerCase: false,
        specialChars: false,
      });
      existingOtp = await OTP.findOne({ otp });
    }
    console.log("Unique OTP:", otp);

    const otpPayload = {
      email,
      otp,
    };

    // CREATE  an entry in DB
    const otpBody = await OTP.create(otpPayload);
    console.log("OTP entry created:", otpBody);

    // return response successfull
    return res.status(200).json({
      success: true,
      message: "OTP sent successfully",
      otp,
    });
  } catch (error) {
    return res.status(500).json({ message: error.message });
  }
};

// signup

//login

//changePassword
