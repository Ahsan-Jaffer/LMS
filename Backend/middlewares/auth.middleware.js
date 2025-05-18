import jwt from "jsonwebtoken";
import dotenv from "dotenv";
dotenv.config();
import User from "../models/User.model.js";

// auth

export const auth = async (req, res, next) => {
    try {
    // extract token
    const token = req.headers.authorization?.split(" ")[1] || req.cookies.token || req.body.token;
     // if token is missing, return response
    if (!token) {
      return res.status(401).json({
        success: false,
        message: "No token provided",
      });
    }

    // verify token
    try {
      const decoded = jwt.verify(token, process.env.JWT_SECRET);
      console.log("Decoded token:", decoded);
      req.user = decoded;
      
    }
    
   catch (error) {
    return res.status(401).json({
      success: false,
      message: "Invalid token",
    });
  }
  next();

} catch (error) {
    return res.status(500).json({
      success: false,
      message: "Something went wrong while validating token"
    });
  }
};

//  isStudent

export const isStudent = async (req, res, next) => {
    try {
        if (req.user.accountType !== "Student") {
        return res.status(401).json({
            success: false,
            message: "Access denied. You are not a student.",
        });
        }
        next();
    } catch (error) {
        return res.status(500).json({
        success: false,
        message: "Something went wrong while validating role. Please try again.",
        });
    }
    }

// isInstructor
export const isInstructor = async (req, res, next) => {
    try {
        if (req.user.accountType !== "Instructor") {
        return res.status(401).json({
            success: false,
            message: "Access denied. You are not an instructor.",
        });
        }
        next();
    } catch (error) {
        return res.status(500).json({
        success: false,
        message: "Something went wrong while validating role. Please try again.",
        });
    }
}

// isAdmin

export const isAdmin = async (req, res, next) => {
    try {
        if (req.user.accountType !== "Admin") {
        return res.status(401).json({
            success: false,
            message: "Access denied. You are not an admin.",
        });
        }
        next();
    } catch (error) {
        return res.status(500).json({
        success: false,
        message: "Something went wrong while validating role. Please try again.",
        });
    }
}
