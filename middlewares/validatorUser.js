import Joi from 'joi';

export const signupSchema = Joi.object({
  email: Joi.string()
    .min(6)
    .max(60)
    .required()
    .email({ tlds: { allow: ['com', 'net', 'fr', 'tn'] } })
    .messages({
      'string.email': 'Email must be a valid address',
      'string.empty': 'Email is required'
    }),

  password: Joi.string()
    .required()
    .pattern(new RegExp('^(?=.*[a-z])(?=.*[A-Z])(?=.*\\d).{8,}$'))
    .messages({
      'string.pattern.base': 'Password must contain at least one lowercase, one uppercase, and one digit'
    }),

  firstName: Joi.string()
    .required()
    .max(50)
    .messages({
      'string.empty': 'First name is required'
    }),

  lastName: Joi.string()
    .required()
    .max(50)
    .messages({
      'string.empty': 'Last name is required'
    }),

  phone: Joi.string()
    .pattern(/^[259]\d{7}$/)
    .messages({
      'string.pattern.base': 'Phone must be 8 digits starting with 2, 5 or 9'
    }),

  birthDate: Joi.date()
    .less('now')
    .messages({
      'date.less': 'Birth date must be in the past'
    }),

  address: Joi.string()
    .max(200)
    .allow(null, '')
});
