import mongoose from "mongoose";
import mailSender  from "../utils/mailSender.js";

const otpSchema = new mongoose.Schema({
    email: {
        type: String,
        required: true,
        trim: true,
    },
    otp: {
        type: String,
        required: true,
    },
    createdAt: {
        type: Date,
        default: Date.now(),
        expires: 5* 60, 
    },
    
});

//  a function to send emails
async function sendVerificationEmail(email, otp) {
    try {
        const mailResponse = await mailSender(email, "Verification Email from SkillNest", otp);    
        if (!mailResponse) {
            console.log("Error occurs while sending email");
            return;
        }
        console.log("Email sent successfully" + mailResponse.response);
        
    } catch (error) {
        console.log("Error occurs while sending email:", error);
        throw error;
    }
}


// pre middleware

otpSchema.pre("save", async function (next){
    
    try {
        
        if (this.isNew) {
            const otp = this.otp;
            const email = this.email;
            console.log("Sending OTP to email:", email);
            await sendVerificationEmail(email, otp);
        }
    
        next();

    } catch (error) {
        console.log("Error occurs in pre-save middleware: ", error);
    }

})

module.exports = mongoose.model("OTP", otpSchema);

