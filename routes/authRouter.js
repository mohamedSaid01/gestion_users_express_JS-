import express from 'express';
import { signup, signin, signout, getCurrentUser, sendResetCode, validateResetCode, newPassword, changePassword, updateUserProfile, predictUserCategory, predictAllUsers, predictFailedLogins } from '../controllers/authController.js';
import { verifyToken } from '../helpers/authMiddleware.js';

const router = express.Router();

router.post('/signup', signup);
router.post('/signin', signin);   
router.post('/signout', verifyToken ,signout);
router.get('/me', verifyToken, getCurrentUser);
router.post('/send-reset-code', sendResetCode);
router.post('/validate-reset-code', validateResetCode);
router.post('/new-password', newPassword);
router.post('/change-password', verifyToken, changePassword);
router.patch('/update-profile', verifyToken, updateUserProfile);
router.get('/predict', verifyToken, predictUserCategory); 
router.get('/predict-all', verifyToken, predictAllUsers);
router.get('/predict-failed-logins', verifyToken, predictFailedLogins);


export default router;
