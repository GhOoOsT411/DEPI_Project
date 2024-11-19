const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const userModel = require("../../models/userModel");

const changePassword = async (req, res) => {
    const { newPassword } = req.body;

    // Extract the token from the Authorization header
    const token = req.header('Authorization')?.replace('Bearer ', '');

    if (!token) {
        return res.status(401).json({ message: 'Unauthorized. Token missing.' });
    }

    try {
        // Verify the token and decode it using the TOKEN_SECRET_KEY
        const decoded = jwt.verify(token, process.env.TOKEN_SECRET_KEY); // Use your secret key here

        // Assuming the token contains the user's email as 'email'
        const userEmail = decoded.email;

        if (!userEmail) {
            return res.status(401).json({ message: 'Unauthorized. Invalid token.' });
        }

        // Check if the password meets the minimum length requirement
        if (!newPassword || newPassword.length < 6) {
            return res.status(400).json({ message: 'Password must be at least 6 characters long.' });
        }

        // Hash the new password
        const hashedPassword = await bcrypt.hash(newPassword, 10);

        // Find the user by email and update the password
        const user = await userModel.findOne({ email: userEmail });

        if (!user) {
            return res.status(404).json({ message: 'User not found.' });
        }

        // Update password and save
        user.password = hashedPassword;
        await user.save();

        return res.status(200).json({ message: 'Password changed successfully.' });
    } catch (error) {
        console.error(error);
        return res.status(500).json({ message: 'Internal server error.' });
    }
};

module.exports = changePassword;
