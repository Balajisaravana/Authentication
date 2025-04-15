// Load environment variables
require('dotenv').config();

// Third-party modules
const express = require('express');
const cors = require('cors');
const cookieParser = require('cookie-parser');

// Local modules
const authRoutes = require('./auth/authController');

// Initialize app
const app = express();

// Middleware
app.use(cookieParser());
app.use(cors({
    origin: process.env.CLIENT_ORIGIN || 'http://localhost:4201', // Use environment variable for flexibility
    credentials: true,
    methods: ['GET', 'POST', 'PUT', 'DELETE'],
}));
app.use(express.json());

// Routes
app.use('/auth', authRoutes);

// Error handling middleware
app.use((err, req, res, next) => {
    console.error(err.stack);
    res.status(500).json({ message: 'Internal Server Error' });
});

// Start server
const PORT = process.env.PORT || 3000;
if (!process.env.PORT) {
    console.warn('Warning: PORT is not defined in the environment variables. Using default port 3000.');
}
app.listen(PORT, () => {
    console.log(`Server running on http://localhost:${PORT}`);
});