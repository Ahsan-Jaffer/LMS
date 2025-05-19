import mongoose from "mongoose";

const userSchema = new mongoose.Schema({
  firstName: {
    type: String,
    required: true,
    trim: true,
  },
  lastName: {
    type: String,
    trim: true,
  },
  email: {
    type: String,
    required: true,
    trim: true,
  },
  password: {
    type: String,
    required: true,
  },
  accountType: {
    type: String,
    enum: ["Amin", "Student", "Instructor"],
    required: true,
  },
  additionalDetails: {
    type: mongoose.Schema.Types.ObjectId,
    ref: "Profile",
    required: true,
  },
  courses: [
    {
      type: mongoose.Schema.Types.ObjectId,
      ref: "Course",
    },
  ],
  image: {
    type: String,
    required: true,
  },
  courseProgress: [
    {
      type: mongoose.Schema.Types.ObjectId,
      ref: "CourseProgress",
    },
  ],
  token: {
    type: String,
    default: null,
  },

  resetPasswordExpire: {
    type: Date,
    default: null,
  },
});

module.exports = mongoose.model("User", userSchema);
