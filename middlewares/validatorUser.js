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
    .allow(null, ''),

  nb_connexions: Joi.number()
    .min(0)
    .optional()
    .default(0)
    .messages({
      'number.min': 'Number of connections cannot be negative'
    }),

  duree_session: Joi.number()
    .min(0)
    .optional()
    .default(0)
    .messages({
      'number.min': 'Session duration cannot be negative'
    })
});

export const signinSchema = Joi.object({
  email: Joi.string().email().required(),
  password: Joi.string().required()
});

export const newPasswordSchema = Joi.object({
  userId: Joi.string().required(),
  resetToken: Joi.string().required(),
  newPassword: Joi.string()
    .min(8)
    .pattern(new RegExp('^(?=.*[a-z])(?=.*[A-Z])(?=.*\\d).{8,}$'))
    .required()
});

export const updateProfileSchema = Joi.object({
  firstName: Joi.string()
    .min(2)
    .max(50)
    .messages({
      'string.empty': 'Le prénom est requis',
      'string.min': 'Le prénom doit contenir au moins 2 caractères',
      'string.max': 'Le prénom ne peut dépasser 50 caractères'
    }),

  lastName: Joi.string()
    .min(2)
    .max(50)
    .messages({
      'string.empty': 'Le nom est requis',
      'string.min': 'Le nom doit contenir au moins 2 caractères',
      'string.max': 'Le nom ne peut dépasser 50 caractères'
    }),

  phone: Joi.string()
    .pattern(/^[259]\d{7}$/)
    .messages({
      'string.pattern.base': 'Le téléphone doit contenir 8 chiffres commençant par 2, 5 ou 9'
    }),

  birthDate: Joi.date()
    .less('now')
    .messages({
      'date.base': 'Date de naissance invalide',
      'date.less': 'La date de naissance doit être dans le passé'
    }),

  address: Joi.string()
    .max(200)
    .messages({
      'string.max': 'L\'adresse ne peut dépasser 200 caractères'
    }),

  nb_connexions: Joi.number()
    .min(0)
    .optional()
    .messages({
      'number.min': 'Number of connections cannot be negative'
    }),

  duree_session: Joi.number()
    .min(0)
    .optional()
    .messages({
      'number.min': 'Session duration cannot be negative'
    })
}).min(1).messages({
  'object.min': 'Au moins un champ doit être fourni pour la mise à jour'
});
