import { User } from "../models/User.js";
import mailSender from "../utils/mailSender.js";
import crypto from "crypto";
import bcrypt from "bcrypt";

// resetPasswordToken
exports.resetPasswordToken = async (req, res) => {
  try {
    // get email from req body
    const { email } = req.body;
    // check user for this email, email validation
    const user = await User.findOne({ email });
    if (!user) {
      return res.status(404).json({
        success: false,
        message: "Your email is not registered with us",
      });
    }
    //generate token
    const token = crypto.randomUUID();
    //update user by adding token and expiration time
    const updatedDetails = await User.findOneAndUpdate(
      { email: email },
      {
        token: token,
        resetPasswordExpire: Date.now() + 5 * 60 * 1000, // 5 minutes
      },
      { new: true } // to return the updated document
    );

    // create url
    const url = `https://localhost:3000/update-password/${token}`;

    // send mail containing url
    await mailSender({
      email: updatedDetails.email,
      subject: "Reset Password Link",
      message: `Click on the link to reset your password: ${url}`,
    });
    //send response
    res.status(200).json({
      success: true,
      message: `Email sent to ${updatedDetails.email} successfully`,
    });
  } catch (error) {
    console.log(error);
    return res.status(500).json({
      success: false,
      message: "Something went wrong while reseting password email",
    });
  }
};

// resetPassword
exports.resetPassword = async (req, res) => {
  try {
    // get token from params and password and confirm password from req body

    const { password, confirmPassword, token } = req.body;

    // check if password and confirm password match
    if (password !== confirmPassword) {
      return res.status(400).json({
        success: false,
        message: "Password and Confirm Password do not match",
      });
    }

    // get user details from db using token
    const userDetails = await User.findOne({
      token,
      resetPasswordExpire: { $gt: Date.now() },
    });
    if (!userDetails) {
      return res.status(400).json({
        success: false,
        message: "Token is invalid or has expired",
      });
    }

    // hash the password
    const hashedPassword = await bcrypt.hash(password, 10);
    // update password
    await User.findOneAndUpdate(
      { token: token },
      { password: hashedPassword },
      { new: true }
    );

    // send response
    return res.status(200).json({
      success: true,
      message: "Password updated successfully",
    });
  } catch (error) {
    console.log(error);
    return res.status(500).json({
      success: false,
      message: "Something went wrong while updating password",
    });
  }
};
