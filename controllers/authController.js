import bcrypt from 'bcryptjs';
import { signupSchema, signinSchema, updateProfileSchema } from '../middlewares/validatorUser.js';
import User from '../database/models/usersModel.js';
import jwt from 'jsonwebtoken';
import { comparePasswords } from '../utils/authUtils.js';
import { sendResetCodeByEmail } from '../utils/passwordReset.js';
import { randomBytes } from 'crypto';


export const signup = async (req, res) => {
  const { email, password, firstName, lastName, phone, birthDate, address } = req.body;
  
  try {
    const { error } = signupSchema.validate(req.body, { abortEarly: false });
    if (error) {
      const errors = error.details.map(detail => detail.message);
      return res.status(400).json({ 
        success: false, 
        message: 'Validation error',
        errors 
      });
    }

    const existingUser = await User.findOne({ email });
    if (existingUser) {
      return res.status(409).json({ 
        success: false, 
        message: 'Email already in use' 
      });
    }

    const saltRounds = 12;
    const hashedPassword = await bcrypt.hash(password, saltRounds);

    const newUser = new User({
      email,
      password: hashedPassword,
      firstName,
      lastName,
      phone: phone || null,
      birthDate: birthDate || null,
      address: address || null,
      role: 'user'
    });

    const savedUser = await newUser.save();
    savedUser.password = undefined;

    res.status(200).json({
      success: true,
      message: 'Account created successfully',
      user: savedUser
    });

  } catch (error) {
    console.error('Signup error:', error);
    res.status(500).json({ 
      success: false, 
      message: 'Internal server error',
      error: error.message 
    });
  }
};


export const signin = async (req, res) => {
  const { email, password } = req.body;

  try {
    // 1. Validation Joi
    const { error } = signinSchema.validate(req.body);
    if (error) {
      return res.status(400).json({
        success: false,
        message: error.details[0].message
      });
    }

    // 2. Vérifier si l'utilisateur existe
    const user = await User.findOne({ email }).select('+password');
    if (!user) {
      return res.status(401).json({
        success: false,
        message: 'Invalid credentials'
      });
    }

    // 3. Comparer les mots de passe
    const isMatch = await comparePasswords(password, user.password);
    if (!isMatch) {
      return res.status(401).json({
        success: false,
        message: 'Invalid credentials'
      });
    }

    // 4. Générer le token JWT
    const token = jwt.sign(
      { id: user._id, role: user.role },
      process.env.TOKEN_SECRET,
      { expiresIn: '8h' }
    );

        res
      .cookie('Authorization', 'Bearer ' + token, {
        expires: new Date(Date.now() + 8 * 3600000),
        httpOnly: process.env.NODE_ENV,
        secure: process.env.NODE_ENV,
      })

    // 5. Réponse sans le mot de passe
    const userWithoutPassword = user.toObject();
    delete userWithoutPassword.password;

    res.status(200).json({
      success: true,
      message: 'Login successful',
      token,
      user: userWithoutPassword
    });

  } catch (error) {
    console.error('Signin error:', error);
    res.status(500).json({
      success: false,
      message: 'Server error during authentication'
    });
  }
};

export const signout = async (req, res) => {
  res
    .clearCookie('Authorization')
    .status(200)
    .json({ success: true, message: 'logged out successfully' });
};


export const getCurrentUser = async (req, res) => {
  try {
    const { id } = req.user;

    const user = await User.findById(id).select('-password');

    if (!user) {
      return res.status(404).json({ success: false, message: 'User not found' });
    }

    res.status(200).json({ success: true, user });
  } catch (error) {
    console.error(error);
    res.status(500).json({ success: false, message: 'Server error' });
  }
};


export const sendResetCode = async (req, res) => {
  const { email } = req.body;

  if (!email) {
    return res.status(400).json({
      success: false,
      message: 'Email is required'
    });
  }

  try {
    await sendResetCodeByEmail(email);
    
    res.status(200).json({
      success: true,
      message: 'Reset code sent successfully'
    });
  } catch (error) {
    const status = error.message === 'User not found' ? 404 : 500;
    res.status(status).json({
      success: false,
      message: error.message || 'Failed to send reset code'
    });
  }
};


export const validateResetCode = async (req, res) => {
  const { code } = req.body;

  try {
    // 1. Trouver l'utilisateur avec code non expiré
    const user = await User.findOne({
      resetPasswordExpires: { $gt: Date.now() }
    });

    if (!user || !user.resetPasswordCode) {
      return res.status(400).json({
        success: false,
        message: 'Code invalide ou expiré'
      });
    }

    // 2. Vérifier le code
    const isCodeValid = await bcrypt.compare(code, user.resetPasswordCode);
    if (!isCodeValid) {
      return res.status(400).json({
        success: false,
        message: 'Code incorrect'
      });
    }

    // 3. Générer et stocker un token
    const resetToken = randomBytes(32).toString('hex');
    user.resetToken = resetToken;
    user.resetTokenExpires = Date.now() + 3600000; // 1 heure
    await user.save();

    // 4. Réponse avec cookie httpOnly
    res.cookie('resetToken', resetToken, {
      httpOnly: true,
      secure: process.env.NODE_ENV,
      maxAge: 3600000, // 1 heure
      sameSite: 'strict'
    });

    return res.status(200).json({
      success: true,
      message: 'Code validé'
    });

  } catch (error) {
    console.error('Erreur:', error);
    return res.status(500).json({
      success: false,
      message: 'Erreur serveur'
    });
  }
};


export const newPassword = async (req, res) => {
  const { newPassword, confirmPassword } = req.body;

  try {
    // 1. Récupérer le token depuis les cookies
    const resetToken = req.cookies.resetToken;
    
    if (!resetToken) {
      return res.status(401).json({
        success: false,
        message: 'Authentification requise'
      });
    }

    // 2. Vérifier l'utilisateur et le token
    const user = await User.findOne({
      resetToken,
      resetTokenExpires: { $gt: Date.now() }
    });

    if (!user) {
      return res.status(401).json({
        success: false,
        message: 'Session invalide ou expirée'
      });
    }

    // 3. Valider les mots de passe
    if (newPassword !== confirmPassword) {
      return res.status(400).json({
        success: false,
        message: 'Les mots de passe ne correspondent pas'
      });
    }

    // 4. Mettre à jour le mot de passe et nettoyer
    user.password = await bcrypt.hash(newPassword, 12);
    user.resetToken = undefined;
    user.resetTokenExpires = undefined;
    user.resetPasswordCode = undefined;
    user.resetPasswordExpires = undefined;
    await user.save();

    // 5. Réponse + suppression du cookie
    return res
      .clearCookie('resetToken')
      .status(200)
      .json({
        success: true,
        message: 'Mot de passe réinitialisé'
      });

  } catch (error) {
    console.error('Erreur:', error);
    return res.status(500).json({
      success: false,
      message: 'Erreur serveur'
    });
  }
};


export const changePassword = async (req, res) => {
  const { currentPassword, newPassword, confirmPassword } = req.body;
  const userId = req.user.id;

  try {
    // 1. Validation des données
    if (!currentPassword || !newPassword || !confirmPassword) {
      return res.status(400).json({
        success: false,
        message: 'Tous les champs sont requis'
      });
    }

    if (newPassword !== confirmPassword) {
      return res.status(400).json({
        success: false,
        message: 'Les nouveaux mots de passe ne correspondent pas'
      });
    }

    // 2. Récupérer l'utilisateur avec le mot de passe
    const user = await User.findById(userId).select('+password');
    if (!user) {
      return res.status(404).json({
        success: false,
        message: 'Utilisateur non trouvé'
      });
    }

    // 3. Vérifier l'ancien mot de passe
    const isPasswordValid = await bcrypt.compare(currentPassword, user.password);
    if (!isPasswordValid) {
      return res.status(401).json({
        success: false,
        message: 'Mot de passe actuel incorrect'
      });
    }

    // 4. Vérifier que le nouveau mot de passe est différent
    if (await bcrypt.compare(newPassword, user.password)) {
      return res.status(400).json({
        success: false,
        message: 'Le nouveau mot de passe doit être différent de l\'actuel'
      });
    }

    // 5. Hacher et sauvegarder le nouveau mot de passe
    const hashedPassword = await bcrypt.hash(newPassword, 12);
    user.password = hashedPassword;
    await user.save();

    // 6. Réponse (on retire le mot de passe de la réponse)
    user.password = undefined;

    return res.status(200).json({
      success: true,
      message: 'Mot de passe mis à jour avec succès'
    });

  } catch (error) {
    console.error('Erreur changement mot de passe:', error);
    return res.status(500).json({
      success: false,
      message: 'Erreur serveur lors du changement de mot de passe'
    });
  }
};


export const updateUserProfile = async (req, res) => {
  const userId = req.user.id;

  try {
    // 1. Validation avec Joi
    const { error, value } = updateProfileSchema.validate(req.body, {
      abortEarly: false
    });

    if (error) {
      const errors = error.details.map(detail => ({
        field: detail.path[0],
        message: detail.message
      }));
      
      return res.status(400).json({
        success: false,
        message: 'Erreurs de validation',
        errors
      });
    }

    // 2. Mise à jour de l'utilisateur
    const updatedUser = await User.findByIdAndUpdate(
      userId,
      { $set: value },
      { new: true, runValidators: true }
    ).select('-password -resetPasswordCode -resetPasswordExpires');

    if (!updatedUser) {
      return res.status(404).json({
        success: false,
        message: 'Utilisateur non trouvé'
      });
    }

    // 3. Réponse
    return res.status(200).json({
      success: true,
      message: 'Profil mis à jour avec succès',
      user: updatedUser
    });

  } catch (error) {
    console.error('Erreur mise à jour profil:', error);
    return res.status(500).json({
      success: false,
      message: 'Erreur serveur lors de la mise à jour'
    });
  }
};