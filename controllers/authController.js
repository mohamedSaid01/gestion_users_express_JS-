import bcrypt from 'bcryptjs';
import { signupSchema, signinSchema, updateProfileSchema } from '../middlewares/validatorUser.js';
import User from '../database/models/usersModel.js';
import jwt from 'jsonwebtoken';
import { comparePasswords } from '../utils/authUtils.js';
import { sendResetCodeByEmail } from '../utils/passwordReset.js';
import { sendSuspiciousActivityEmail } from '../utils/sendEmailConnexionEchouees.js';
import { randomBytes } from 'crypto';
import axios from 'axios';

// Constantes pour les seuils
const MAX_LOGIN_ATTEMPTS = 3;
const LOCK_DURATION = 15 * 60 * 1000; // 15 minutes en millisecondes

// Inscription d'un nouvel utilisateur
export const signup = async (req, res) => {
  const { email, password, firstName, lastName, phone, birthDate, address, nb_connexions = 0, duree_session = 0 } = req.body;
  
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
      role: 'user',
      nb_connexions,
      duree_session,
      lastLogin: null,
      failedLoginAttempts: 0,
      lastFailedLogin: null,
      isLocked: false,
      lockUntil: null
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

// Connexion d'un utilisateur
export const signin = async (req, res) => {
  if (!req.body) {
    return res.status(400).json({
      success: false,
      message: 'Request body is missing'
    });
  }

  const { email, password } = req.body;

  try {
    const { error } = signinSchema.validate(req.body);
    if (error) {
      return res.status(400).json({
        success: false,
        message: error.details[0].message
      });
    }

    const user = await User.findOne({ email }).select('+password');
    if (!user) {
      return res.status(401).json({
        success: false,
        message: 'Invalid credentials'
      });
    }

    // Vérifier si le compte est verrouillé
    if (user.isLocked && user.lockUntil && user.lockUntil > new Date()) {
      const timeLeft = Math.ceil((user.lockUntil - new Date()) / 60000); // Temps restant en minutes
      return res.status(403).json({
        success: false,
        message: `Compte verrouillé. Veuillez réessayer dans ${timeLeft} minute(s).`
      });
    }

    const isMatch = await comparePasswords(password, user.password);
    if (!isMatch) {
      // Incrémenter failedLoginAttempts et enregistrer lastFailedLogin
      user.failedLoginAttempts += 1;
      user.lastFailedLogin = new Date();

      // Vérifier si le compte doit être verrouillé
      if (user.failedLoginAttempts >= MAX_LOGIN_ATTEMPTS) {
        user.isLocked = true;
        user.lockUntil = new Date(Date.now() + LOCK_DURATION);
      }

      await user.save();

      // Calculer le temps depuis la dernière tentative échouée
      const timeSinceLastFailed = user.lastFailedLogin
        ? (new Date() - user.lastFailedLogin) / 60000 // Temps en minutes
        : 9999;

      // Appeler l'API Flask pour prédire si l'utilisateur est suspect
      try {
        const response = await axios.post('http://localhost:5000/predict-failed-logins', {
          failedLoginAttempts: user.failedLoginAttempts,
          time_since_last_failed: timeSinceLastFailed,
          nb_connexions: user.nb_connexions
        });

        const prediction = response.data.prediction;

        // Si suspect ou compte verrouillé, envoyer un email d'alerte
        if (prediction === 'suspect' || user.isLocked) {
          await sendSuspiciousActivityEmail(
            user.email,
            user.fullName,
            user.failedLoginAttempts,
            timeSinceLastFailed
          );
        }

        return res.status(401).json({
          success: false,
          message: user.isLocked
            ? `Compte verrouillé après ${MAX_LOGIN_ATTEMPTS} tentatives incorrectes. Veuillez réessayer dans 15 minutes.`
            : 'Invalid credentials',
          failedAttempts: user.failedLoginAttempts,
          status: prediction
        });
      } catch (apiError) {
        console.error('Erreur lors de l’appel à l’API Flask:', apiError.message);
        return res.status(500).json({
          success: false,
          message: user.isLocked
            ? `Compte verrouillé après ${MAX_LOGIN_ATTEMPTS} tentatives incorrectes. Veuillez réessayer dans 15 minutes.`
            : 'Invalid credentials, prediction failed',
          failedAttempts: user.failedLoginAttempts,
          error: apiError.message
        });
      }
    }

    // Réinitialiser failedLoginAttempts, isLocked et lockUntil en cas de succès
    user.failedLoginAttempts = 0;
    user.isLocked = false;
    user.lockUntil = null;
    user.lastLogin = new Date();
    user.nb_connexions += 1;
    await user.save();

    const token = jwt.sign(
      { id: user._id, role: user.role },
      process.env.TOKEN_SECRET,
      { expiresIn: '8h' }
    );

    res.cookie('Authorization', 'Bearer ' + token, {
      expires: new Date(Date.now() + 8 * 3600000),
      httpOnly: process.env.NODE_ENV === 'production',
      secure: process.env.NODE_ENV === 'production'
    });

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

// Déconnexion
export const signout = async (req, res) => {
  try {
    const authHeader = req.cookies.Authorization;
    const token = authHeader && authHeader.split(' ')[1];

    if (!token) {
      return res.status(401).json({
        success: false,
        message: 'Aucun token fourni'
      });
    }

    const decoded = jwt.verify(token, process.env.TOKEN_SECRET);
    const user = await User.findById(decoded.id);

    if (!user) {
      return res.status(404).json({
        success: false,
        message: 'Utilisateur non trouvé'
      });
    }

    if (user.lastLogin) {
      const currentTime = new Date();
      const sessionDurationMs = currentTime - user.lastLogin;
      const sessionDurationMinutes = Math.floor(sessionDurationMs / 60000);
      user.duree_session += sessionDurationMinutes;
      user.lastLogin = null;
      await user.save();
    }

    res
      .clearCookie('Authorization')
      .status(200)
      .json({ success: true, message: 'Logged out successfully' });
  } catch (error) {
    console.error('Signout error:', error);
    res.status(500).json({
      success: false,
      message: 'Erreur serveur lors de la déconnexion'
    });
  }
};

// Obtenir l'utilisateur actuel
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

// Envoyer un code de réinitialisation
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

// Valider le code de réinitialisation
export const validateResetCode = async (req, res) => {
  const { code } = req.body;

  try {
    const user = await User.findOne({
      resetPasswordExpires: { $gt: Date.now() }
    });

    if (!user || !user.resetPasswordCode) {
      return res.status(400).json({
        success: false,
        message: 'Code invalide ou expiré'
      });
    }

    const isCodeValid = await bcrypt.compare(code, user.resetPasswordCode);
    if (!isCodeValid) {
      return res.status(400).json({
        success: false,
        message: 'Code incorrect'
      });
    }

    const resetToken = randomBytes(32).toString('hex');
    user.resetToken = resetToken;
    user.resetTokenExpires = Date.now() + 3600000;
    await user.save();

    res.cookie('resetToken', resetToken, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      maxAge: 3600000,
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

// Réinitialiser le mot de passe
export const newPassword = async (req, res) => {
  const { newPassword, confirmPassword } = req.body;

  try {
    const resetToken = req.cookies.resetToken;
    
    if (!resetToken) {
      return res.status(401).json({
        success: false,
        message: 'Authentification requise'
      });
    }

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

    if (newPassword !== confirmPassword) {
      return res.status(400).json({
        success: false,
        message: 'Les mots de passe ne correspondent pas'
      });
    }

    user.password = await bcrypt.hash(newPassword, 12);
    user.resetToken = undefined;
    user.resetTokenExpires = undefined;
    user.resetPasswordCode = undefined;
    user.resetPasswordExpires = undefined;
    await user.save();

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

// Changer le mot de passe
export const changePassword = async (req, res) => {
  const { currentPassword, newPassword, confirmPassword } = req.body;
  const userId = req.user.id;

  try {
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

    const user = await User.findById(userId).select('+password');
    if (!user) {
      return res.status(404).json({
        success: false,
        message: 'Utilisateur non trouvé'
      });
    }

    const isPasswordValid = await bcrypt.compare(currentPassword, user.password);
    if (!isPasswordValid) {
      return res.status(401).json({
        success: false,
        message: 'Mot de passe actuel incorrect'
      });
    }

    if (await bcrypt.compare(newPassword, user.password)) {
      return res.status(400).json({
        success: false,
        message: 'Le nouveau mot de passe doit être différent de l\'actuel'
      });
    }

    const hashedPassword = await bcrypt.hash(newPassword, 12);
    user.password = hashedPassword;
    await user.save();

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

// Mettre à jour le profil utilisateur
export const updateUserProfile = async (req, res) => {
  const userId = req.user.id;

  try {
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

// Prédire la catégorie de l'utilisateur
export const predictUserCategory = async (req, res) => {
  const userId = req.user.id;

  try {
    const user = await User.findById(userId);
    if (!user) {
      return res.status(404).json({
        success: false,
        message: 'Utilisateur non trouvé'
      });
    }

    if (user.role === 'admin') {
      return res.status(403).json({
        success: false,
        message: 'Les prédictions ne s\'appliquent pas aux administrateurs'
      });
    }

    const response = await axios.post('http://localhost:5000/predict', {
      nb_connexions: user.nb_connexions,
      duree_session: user.duree_session
    });

    const category = response.data.prediction;

    user.category = category;
    await user.save();

    res.status(200).json({
      success: true,
      message: 'Prédiction réussie',
      user: {
        username: user.fullName,
        nb_connexions: user.nb_connexions,
        duree_session: user.duree_session,
        category
      }
    });
  } catch (error) {
    console.error('Erreur lors de la prédiction:', error.message);
    res.status(500).json({
      success: false,
      message: 'Erreur lors de la prédiction',
      error: error.message
    });
  }
};

// Prédire la catégorie de tous les utilisateurs
export const predictAllUsers = async (req, res) => {
  try {
    if (req.user.role !== 'admin') {
      return res.status(403).json({
        success: false,
        message: 'Accès refusé : réservé aux administrateurs'
      });
    }

    const users = await User.find({ role: 'user' }).select('firstName lastName nb_connexions duree_session category');

    if (!users || users.length === 0) {
      return res.status(404).json({
        success: false,
        message: 'Aucun utilisateur non-admin trouvé'
      });
    }

    const predictions = [];
    for (const user of users) {
      try {
        const response = await axios.post('http://localhost:5000/predict', {
          nb_connexions: user.nb_connexions,
          duree_session: user.duree_session
        });

        const category = response.data.prediction;

        user.category = category;
        await user.save();

        predictions.push({
          username: user.fullName,
          nb_connexions: user.nb_connexions,
          duree_session: user.duree_session,
          category
        });
      } catch (error) {
        console.error(`Erreur lors de la prédiction pour l'utilisateur ${user.fullName}:`, error.message);
        predictions.push({
          username: user.fullName,
          nb_connexions: user.nb_connexions,
          duree_session: user.duree_session,
          category: null,
          error: `Erreur lors de la prédiction : ${error.message}`
        });
      }
    }

    res.status(200).json({
      success: true,
      message: 'Prédictions terminées pour tous les utilisateurs non-admin',
      predictions
    });
  } catch (error) {
    console.error('Erreur lors de la prédiction pour tous les utilisateurs:', error);
    res.status(500).json({
      success: false,
      message: 'Erreur serveur lors de la prédiction',
      error: error.message
    });
  }
};

// Prédire les connexions échouées suspectes pour tous les utilisateurs
export const predictFailedLogins = async (req, res) => {
  try {
    if (req.user.role !== 'admin') {
      return res.status(403).json({
        success: false,
        message: 'Accès refusé : réservé aux administrateurs'
      });
    }

    const users = await User.find({ role: 'user' }).select('firstName lastName failedLoginAttempts lastFailedLogin nb_connexions');

    if (!users || users.length === 0) {
      return res.status(404).json({
        success: false,
        message: 'Aucun utilisateur non-admin trouvé'
      });
    }

    const predictions = [];
    for (const user of users) {
      try {
        const timeSinceLastFailed = user.lastFailedLogin
          ? (new Date() - user.lastFailedLogin) / 60000 // Temps en minutes
          : 9999; // Valeur élevée si pas de tentative échouée

        console.log(`Prédiction pour ${user.fullName}:`, {
          failedLoginAttempts: user.failedLoginAttempts,
          timeSinceLastFailed,
          nb_connexions: user.nb_connexions
        });

        const response = await axios.post('http://localhost:5000/predict-failed-logins', {
          failedLoginAttempts: user.failedLoginAttempts,
          time_since_last_failed: timeSinceLastFailed,
          nb_connexions: user.nb_connexions
        });

        const prediction = response.data.prediction;

        predictions.push({
          username: user.fullName,
          failedLoginAttempts: user.failedLoginAttempts,
          timeSinceLastFailed,
          nb_connexions: user.nb_connexions,
          status: prediction
        });
      } catch (error) {
        console.error(`Erreur lors de la prédiction pour l'utilisateur ${user.fullName}:`, error.message);
        predictions.push({
          username: user.fullName,
          failedLoginAttempts: user.failedLoginAttempts,
          timeSinceLastFailed,
          nb_connexions: user.nb_connexions,
          status: null,
          error: `Erreur lors de la prédiction : ${error.message}`
        });
      }
    }

    res.status(200).json({
      success: true,
      message: 'Prédictions des connexions échouées terminées pour tous les utilisateurs non-admin',
      predictions
    });
  } catch (error) {
    console.error('Erreur lors de la prédiction des connexions échouées:', error);
    res.status(500).json({
      success: false,
      message: 'Erreur serveur lors de la prédiction',
      error: error.message
    });
  }
};