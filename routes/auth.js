// routes/auth.js

const express = require('express');
const router = express.Router();
const authController = require('../controllers/authController');
const authMiddleware = require('../middleware/authMiddleware');
const addTokenToHeader = require('../middleware/addTokenToHeader'); // Import middleware baru

// Terapkan middleware addTokenToHeader sebelum middleware authMiddleware
router.use(addTokenToHeader);

// Rute-rute untuk autentikasi
router.post('/register', authController.register);
router.post('/login', authController.login);
router.post('/change-password', authMiddleware, authController.changePassword);
router.post('/forgot-password', authController.forgotPassword);
router.post('/reset-password', authController.resetPassword);

module.exports = router;
