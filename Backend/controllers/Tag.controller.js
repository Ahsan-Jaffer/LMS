import Tag from "../models/Tag.model.js"

// create Tag ka Handler function

exports.createTag = async (req, res) => {
    try {
        //fetch data from request body
        const { name, description } = req.body;
        //validation
        if (!name || !description) {
            return res.status(400).json({
                success: false,
                message: "All fields are required",
            });
        }

        //create entry in db
        const tag = await Tag.create({ name, description });
        console.log(tag);

        //return respsonse
        return res.status(201).json({
        success: true,
        message: "Tag created successfully",
        tag,
        })
    } catch (error) {
        res.status(500).json({
        success: false,
        message: error.message,
        })
    }
    };


// get all tags ka Handler function
exports.showAllTags = async (req, res) => {
    try {
        //fetch data from request body
        const tags = await Tag.find({}, {name: true, description: true});

        //return respsonse
        return res.status(200).json({
            success: true,
            message: "All Tags fetched successfully.",
            tags,
        })
    } catch (error) {
        res.status(500).json({
            success: false,
            message: error.message,
        })
    }
};

