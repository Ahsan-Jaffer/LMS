import mongoose from "mongoose";

const sectionSchema = new mongoose.Schema({
    name: {
        type: String,
    },
    subSection:{
        type: mongoose.Schema.Types.ObjectId,
        ref: "SubSection",
        required: true,
    },


});


module.exports = mongoose.model("Section", sectionSchema);  