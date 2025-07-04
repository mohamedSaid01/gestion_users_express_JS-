import mongoose from "mongoose";

const userSchema = mongoose.Schema(
  {
    email: {
      type: String,
      required: [true, 'Email is required!'],
      trim: true,
      unique: [true, 'Email must be unique!'],
      minLength: [5, 'Email must have 5 characters!'],
      lowercase: true,
      match: [/^\w+([\.-]?\w+)*@\w+([\.-]?\w+)*(\.\w{2,3})+$/, 'Please fill a valid email address']
    },
    password: {
      type: String,
      required: [true, 'Password must be provided!'],
      trim: true,
      select: false,
      minLength: [6, 'Password should be at least 6 characters']
    },
    role: {
      type: String,
      enum: ['user', 'admin'],
      default: 'user'
    },
    firstName: {
      type: String,
      required: [true, 'First name is required'],
      trim: true,
      maxLength: [50, 'First name cannot exceed 50 characters']
    },
    lastName: {
      type: String,
      required: [true, 'Last name is required'],
      trim: true,
      maxLength: [50, 'Last name cannot exceed 50 characters']
    },
    address: { 
      type: String,
      trim: true,
      maxLength: [200, 'Address cannot exceed 200 characters']
    },
    phone: {
      type: String,
      trim: true,
    },
    birthDate: {
      type: Date,
      validate: {
        validator: function(date) {
          return date < new Date();
        },
        message: 'Birth date must be in the past'
      }
    }
  },
  {
    timestamps: true,
    toJSON: { virtuals: true },
    toObject: { virtuals: true }
  }
);

// Virtual pour le nom complet
userSchema.virtual('fullName').get(function() {
  return `${this.firstName} ${this.lastName}`;
});

// Virtual pour l'âge
userSchema.virtual('age').get(function() {
  if (!this.birthDate) return null;
  const diff = Date.now() - this.birthDate.getTime();
  return Math.floor(new Date(diff).getUTCFullYear() - 1970);
});

export default mongoose.model('User', userSchema);