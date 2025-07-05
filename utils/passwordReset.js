import transport from '../middlewares/sendMail.js'
import crypto from 'crypto';
import User from '../database/models/usersModel.js';
import bcrypt from 'bcryptjs';

// Génère un code de 6 chiffres
export const generateResetCode = () => crypto.randomInt(100000, 999999).toString();

// Envoie le code par email
export const sendResetCodeByEmail = async (email) => {
  try {
    // 1. Vérifier l'utilisateur
    const user = await User.findOne({ email });
    if (!user) throw new Error('User not found');

    // 2. Générer le code
    const resetCode = generateResetCode();
    const saltRounds = 10;
    const hashedResetCode = await bcrypt.hash(resetCode, saltRounds);
    
    // 3. Sauvegarder dans la BDD (valide 15min)
    user.resetPasswordCode = hashedResetCode;
    user.resetPasswordExpires = Date.now() + 900000; // 15 minutes
    await user.save();

    // 4. Envoyer l'email
    await transport.sendMail({
      from: `"Password Reset" <${process.env.NODE_CODE_SENDING_EMAIL_ADDRESS}>`,
      to: email,
      subject: 'Your Password Reset Code',
      text: `Your reset code is: ${resetCode}`,
      html: `
        <div>
          <h2>Password Reset Request</h2>
          <p>Your verification code is: <strong>${resetCode}</strong></p>
          <p>This code will expire in 15 minutes.</p>
        </div>
      `
    });

    return { success: true };
  } catch (error) {
    console.error('Email sending error:', error);
    throw error;
  }
};
