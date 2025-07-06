import bcrypt from 'bcryptjs';


export const comparePasswords = async (candidatePassword, hashedPassword) => {
  try {
    return await bcrypt.compare(candidatePassword, hashedPassword);
  } catch (error) {
    console.error('Password comparison failed:', error);
    return false;
  }
};
  