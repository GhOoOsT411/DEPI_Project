const express = require('express');
const bcrypt = require('bcryptjs');
const bodyParser = require('body-parser');
const cors = require('cors');
const cookieParser = require('cookie-parser');
const path = require('path');
const fs = require('fs');
const nodemailer = require('nodemailer');
const crypto = require('crypto'); // Import the crypto module
const axios = require('axios'); // Import axios for internal redirect requests
require('dotenv').config();
const connectDB = require('./config/db');
const router = require('./routes');
const rceMiddleware = require('./middleware/rce');
const User = require('./models/userModel'); // Import the user model

const app = express();

// CORS configuration
app.use(cors({
    origin: process.env.FRONTEND_URL,
    credentials: true
}));

app.use(express.json());
app.use(cookieParser());
app.use(express.urlencoded({ extended: true })); // Middleware to parse URL-encoded data (form submissions)

//
app.get('/api/current_balance', (req, res) => {
    res.status(200).json({
        success: true,
        balance: userData.balance // Send current balance
    });
});
// Simulating user data (You can replace this with a real database in production)
let userData = {
    balance: 1000,  // Initial balance
};

// Payment endpoint to handle payment submissions
app.post('/api/payment', (req, res) => {
    const { totalPrice } = req.body; // Use the same name as frontend sends

    console.log(`Current Balance: ₹${userData.balance}`); // Log the current balance

    if (!totalPrice || totalPrice <= 0) {
        return res.status(400).json({ status: 'error', message: 'Invalid amount.' });
    }

    // Check if the user has enough balance
    if (userData.balance < totalPrice) {
        return res.status(200).json({ status: 'insufficient_balance', message: 'Insufficient balance. Please check your account.' });
    }

    // Deduct the amount from the user's balance (simulate payment)
    userData.balance -= totalPrice;

    // Log the updated balance after the payment
    console.log(`New Balance after Payment: ₹${userData.balance}`);

    // Respond with success
    return res.status(200).json({ success: true, message: 'Payment processed successfully.' });
});

// Setup Nodemailer transporter
const transporter = nodemailer.createTransport({
    service: 'gmail',
    auth: {
        user: 'osamy7593@gmail.com',
        pass: 'uflajadkesetfxyp',
    },
});

app.post('/api/forgot-password', async (req, res) => {
    const { email } = req.body;

    if (!email) {
        return res.status(400).json({ message: 'Email is required.' });
    }

    const host = req.headers.host; // Extract host (IP or domain)
    if (!host) {
        return res.status(400).json({ message: 'Host header is missing.' });
    }

    // Generate a token for password reset
    const token = crypto.randomBytes(20).toString('hex');

    // Find user by email
    const user = await User.findOne({ email });
    if (!user) {
        return res.status(400).json({ message: 'User not found.' });
    }

    // Store the reset token and expiration time in the database
    const expirationDate = new Date();
    expirationDate.setHours(expirationDate.getHours() + 1); // Token expires in 1 hour

    user.resetPasswordToken = token;
    user.resetPasswordTokenExpiration = expirationDate;
    await user.save();

    // Construct the password reset link
    const resetLink = `http://${host}/reset-password/${token}`;

    // Set up email content
    const mailOptions = {
        from: 'osamy7593@gmail.com',
        to: email,
        subject: 'Password Reset Request',
        text: `Click here to reset your password: ${resetLink}`,
    };

    // Send the email
    transporter.sendMail(mailOptions, (error, info) => {
        if (error) {
            console.error(error);
            return res.status(500).json({ message: 'Failed to send email.' });
        }

        res.status(200).json({
            message: 'Password reset link has been sent to your email.',
            resetLink: resetLink, // Just for testing purposes
        });
    });
});

// Handle the password reset page (GET request for testing)
app.get('/reset-password/:token', (req, res) => {
    const { token } = req.params;
    res.send(`
        <html>
            <head>
                <style>
                    body {
                        font-family: Arial, sans-serif;
                        background-color: #f4f4f4;
                        margin: 0;
                        padding: 0;
                        display: flex;
                        justify-content: center;
                        align-items: center;
                        height: 100vh;
                        color: #333;
                    }
                    .container {
                        background-color: #fff;
                        padding: 20px;
                        border-radius: 8px;
                        box-shadow: 0 4px 8px rgba(0, 0, 0, 0.1);
                        width: 300px;
                        text-align: center;
                    }
                    h1 {
                        font-size: 24px;
                        margin-bottom: 20px;
                        color: #4CAF50;
                    }
                    label {
                        display: block;
                        margin-bottom: 8px;
                        font-weight: bold;
                    }
                    input[type="password"] {
                        width: 100%;
                        padding: 10px;
                        margin-bottom: 20px;
                        border: 1px solid #ccc;
                        border-radius: 4px;
                        font-size: 16px;
                    }
                    button {
                        width: 100%;
                        padding: 10px;
                        background-color: #4CAF50;
                        color: white;
                        border: none;
                        border-radius: 4px;
                        font-size: 16px;
                        cursor: pointer;
                    }
                    button:hover {
                        background-color: #45a049;
                    }
                </style>
            </head>
            <body>
                <div class="container">
                    <h1>Reset Your Password</h1>
                    <form action="/reset-password/${token}" method="POST">
                        <label for="password">New Password:</label>
                        <input type="password" id="password" name="password" required>
                        <button type="submit">Reset Password</button>
                    </form>
                </div>
            </body>
        </html>
    `);
});

// Handle the POST request when the victim submits the new password
app.post('/reset-password/:token', async (req, res) => {
    const { token } = req.params;
    const { password } = req.body;

    if (!password) {
        return res.status(400).json({ message: 'Password is required.' });
    }

    // Find user by resetPasswordToken
    const user = await User.findOne({ resetPasswordToken: token });
    if (!user || user.resetPasswordTokenExpiration < Date.now()) {
        return res.status(400).json({ message: 'Invalid or expired token.' });
    }

    // Hash the new password
    const hashedPassword = await bcrypt.hash(password, 10);
    user.password = hashedPassword;
    user.resetPasswordToken = undefined; // Clear the reset token

    await user.save();

    res.status(200).json({
        message: 'Your password has been successfully reset.',
    });
});

// Download endpoint with LFI vulnerability (for demo purposes)

app.get('/file', (req, res) => {
    const baseDirectory = '/home/omarsamy/Full-Stack-E-Commerce-MERN-APP'; // Base directory for downloads
    const file = req.query.file || 'default.txt'; // Default to 'default.txt' if no file is specified
    const filePath = path.join(baseDirectory, file); // Construct the full file path

    console.log("Requested file:", filePath); // Log the full file path

    fs.access(filePath, fs.constants.F_OK, (err) => {
        if (err) {
            console.error("File does not exist:", filePath);
            return res.status(404).send("File not found.");
        }

        // Attempt to send the specified file
        res.download(filePath, (err) => {
            if (err) {
                console.error("File download error:", err);
                res.status(500).send("Could not download the file.");
            }
        });
    });
});
// Apply the RCE middleware globally
app.use(rceMiddleware);

// API routes
app.use("/api", router);

// Set the port for the server
const PORT = process.env.PORT || 8080;

connectDB().then(() => {
    app.listen(PORT, () => {
        console.log("Connected to DB");
        console.log("Server is running on port " + PORT);
    });
});
