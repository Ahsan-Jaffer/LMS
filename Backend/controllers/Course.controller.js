import Course from '../models/Course.model.js';
import Tag from '../models/Tag.model.js';
import User from '../models/User.model.js';
import {uploadImageToCloudinary} from '../utils/imageUploader.js';

exports.createCourse = async (req, res) => {
    try {
        // Fetch data from request body
        const { title, description, tags } = req.body;

        //fetch the file
        

        // Validation
        if (!title || !description || !tags) {
            return res.status(400).json({
                success: false,
                message: "All fields are required",
            });
        }

        // Check if user is authenticated
        if (!req.user) {
            return res.status(401).json({
                success: false,
                message: "Unauthorized",
            });
        }

        // Upload image to Cloudinary
        const image = await uploadImageToCloudinary(req.file, 'courses', 500, 60);

        // Create course entry in database
        const course = await Course.create({
            title,
            description,
            image: image.secure_url,
            user: req.user._id,
        });

        // Associate tags with the course
        if (tags && tags.length > 0) {
            const tagDocs = await Tag.find({ _id: { $in: tags } });
            course.tags = tagDocs.map(tag => tag._id);
            await course.save();
        }

        // Return response
        return res.status(201).json({
            success: true,
            message: "Course created successfully",
            course,
        });
    } catch (error) {
        res.status(500).json({
            success: false,
            message: error.message,
        });
    }
}