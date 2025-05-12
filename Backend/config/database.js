import mongoose from "mongoose";
require("dotenv").config()

const dbConnect = () => {
    mongoose.connect(process.env.MONGODB_URL)
    .then(() => console.log("Database is connected Successfully"))
    .catch((e) => {
        console.log("DB Connection failed");
        console.error(e);
        process.exit(1);
    })
}