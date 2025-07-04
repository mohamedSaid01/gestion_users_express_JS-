import bcrypt from 'bcryptjs'; // Importez directement bcrypt
import { signupSchema } from '../middlewares/validatorUser.js'; // Importez sans doHash
import User from '../database/models/usersModel.js';

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