import User from "../models/User.model.js";
import Profile from "../models/Profile.model.js";
import OTP from "../models/OTP.model.js";
import otpGenerator from "otp-generator";
import z, { date } from "zod";
import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";
import dotenv from "dotenv";
dotenv.config();

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

// ************************************signup**************************************

exports.signup = async (req, res) => {
  try {
    // data fetching from the request ki body
    const {
      firstName,
      lastName,
      email,
      password,
      confirmPassword,
      accountType,
      contactNumber,
      otp,
    } = req.body;

    // validate the data
    if (
      !firstName ||
      !lastName ||
      !email ||
      !password ||
      !confirmPassword ||
      !otp
    ) {
      return res.status(403).json({
        success: false,
        message: "All fields are required",
      });
    }
    // password matching
    if (password !== confirmPassword) {
      return res.status(400).json({
        success: false,
        message: "Password and Confirm Password do not match.",
      });
    }
    // chech user already exists or not
    const existingUser = await User.findOne({ email });
    if (existingUser) {
      return res.status(400).json({
        success: false,
        message: "User already exists.",
      });
    }
    //  find most recent OTP for the user
    const recentOtp = await OTP.findOne({ email })
      .sort({ createdAt: -1 })
      .limit(1);
    console.log("Most recent OTP: ", recentOtp);

    // check if otp is valid
    if (recentOtp.length === 0) {
      return res.status(400).json({
        success: false,
        message: "OTP Not Found.",
      });
    } else if (recentOtp.otp !== otp) {
      return res.status(400).json({
        success: false,
        message: "Invalid OTP.",
      });
    }
    // hash the password
    const hashedPassword = await bcrypt.hash(password, 10);

    // create a new user entry in the database

    const profileDetails = await Profile.create({
      gender: null,
      dateOfBirth: null,
      about: null,
      contactNumber: null,
    });

    const userPayload = {
      firstName,
      lastName,
      email,
      password: hashedPassword,
      accountType,
      contactNumber,
      additionalDetails: profileDetails._id,
      image: `https://api.dicebear.com/5.x/initials/svg?seed=${firstName}%20${lastName}`,
    };
    const user = await User.create(userPayload);
    // return success response
    return res.status(200).json({
      success: true,
      message: "User is registered successfully",
      user,
    });
  } catch (error) {
    console.log(error);
    return res.status(500).json({
      success: false,
      message: "User cannot be registered. Please try again.",
    });
  }
};

//***********************************************login************************************

exports.login = async (req, res) => {
  try {
    // get data request's body
    const { email, password } = req.body;
    //validate data
    if (!email || !password) {
      return res.status(403).json({
        success: false,
        message: "All fields are required",
      });
    }
    //user check exist or not
    const user = await User.findOne({ email }).populate("additionalDetails");
    if (!user) {
      return res.status(400).json({
        success: false,
        message: "User does not exist. Please signup first.",
      });
    }
    // generate JWT, after matching password
    const isPasswordMatch = await bcrypt.compare(password, user.password);
    if (!isPasswordMatch) {
      return res.status(400).json({
        success: false,
        message: "Invalid credentials.",
      });
    }
    // create JWT token
    const token = jwt.sign(
      { id: user._id, email: user.email, role:user.role },
      process.env.JWT_SECRET,
      {
        expiresIn: "2h",
      }
    );

    user.token = token;
    user.password = undefined; // remove password from the response



    //create cookie and send response
    const options = {
      expires: new Date(
        Date.now() + 3 * 24 * 60 * 60 * 1000
      ),
      httpOnly: true,
    };
    res.cookie("token", token, options).status(200).json({
      success: true,
      message: "User logged in successfully",
      user,
      token
    });


  } catch (error) {
    console.log(error);
    return res.status(500).json({
      success: false,
      message: "Login Failure. Please try again.",
    });
    
  }
}

//*******************************changePassword*************************

exports.changePassword = async (req, res) => {
  try {
    const { oldPassword, newPassword, confirmPassword } = req.body;
    //validate data
    if (!oldPassword || !newPassword || !confirmPassword) {
      return res.status(403).json({
        success: false,
        message: "All fields are required",
      });
    }
    // check if new password and confirm password match
    if (newPassword !== confirmPassword) {
      return res.status(400).json({
        success: false,
        message: "New Password and Confirm Password do not match.",
      });
    }
    // get user from the token
    const user = await User.findById(req.user.id);
    // check if user exists
    if (!user) {
      return res.status(400).json({
        success: false,
        message: "User not found.",
      });
    }
    // check if old password is correct
    const isOldPasswordMatch = await bcrypt.compare(
      oldPassword,
      user.password
    );
    if (!isOldPasswordMatch) {
      return res.status(400).json({
        success: false,
        message: "Old Password is incorrect.",
      });
    }
    // hash the new password
    const hashedNewPassword = await bcrypt.hash(newPassword, 10);
    // update the password in the database
    user.password = hashedNewPassword;
    await user.save();
    // return success response
    return res.status(200).json({
      success: true,
      message: "Password changed successfully.",
    });
  } catch (error) {
    console.log(error);
    return res.status(500).json({
      success: false,
      message: "Internal server error. Please try again.",
    });
  }
}
