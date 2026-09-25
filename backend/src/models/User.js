const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const crypto = require('crypto');

const ROLES = ['user', 'manager', 'admin'];

const userSchema = new mongoose.Schema(
  {
    name: { type: String, trim: true, required: true, maxlength: 100 },
    email: {
      type: String,
      required: true,
      unique: true,
      lowercase: true,
      trim: true,
      index: true,
    },
    // Missing when the account was created purely via Google OAuth.
    password: { type: String, select: false },
    role: { type: String, enum: ROLES, default: 'user' },

    googleId: { type: String, index: true, sparse: true },
    authProviders: { type: [String], default: ['local'] }, // ['local','google']

    isEmailVerified: { type: Boolean, default: false },
    emailVerificationTokenHash: { type: String, select: false },
    emailVerificationExpires: { type: Date, select: false },

    passwordResetTokenHash: { type: String, select: false },
    passwordResetExpires: { type: Date, select: false },

    isActive: { type: Boolean, default: true }, // soft-disable / ban switch
  },
  { timestamps: true }
);

// --- Password hashing ---
userSchema.pre('save', async function hashPassword(next) {
  if (!this.isModified('password') || !this.password) return next();
  const salt = await bcrypt.genSalt(12);
  this.password = await bcrypt.hash(this.password, salt);
  next();
});

userSchema.methods.comparePassword = function comparePassword(candidate) {
  if (!this.password) return Promise.resolve(false); // Google-only account
  return bcrypt.compare(candidate, this.password);
};

// --- Verification / reset token helpers ---
// We store only a SHA-256 hash of the token in the DB and email the raw
// token to the user, same pattern as a password: if the DB leaks, the
// tokens in it are useless.
function makeRawAndHash() {
  const raw = crypto.randomBytes(32).toString('hex');
  const hash = crypto.createHash('sha256').update(raw).digest('hex');
  return { raw, hash };
}

userSchema.methods.createEmailVerificationToken = function createEmailVerificationToken() {
  const { raw, hash } = makeRawAndHash();
  this.emailVerificationTokenHash = hash;
  const minutes = Number(process.env.EMAIL_VERIFICATION_EXPIRES_IN_MIN || 60);
  this.emailVerificationExpires = new Date(Date.now() + minutes * 60 * 1000);
  return raw;
};

userSchema.methods.createPasswordResetToken = function createPasswordResetToken() {
  const { raw, hash } = makeRawAndHash();
  this.passwordResetTokenHash = hash;
  const minutes = Number(process.env.PASSWORD_RESET_EXPIRES_IN_MIN || 30);
  this.passwordResetExpires = new Date(Date.now() + minutes * 60 * 1000);
  return raw;
};

userSchema.statics.hashToken = function hashToken(raw) {
  return crypto.createHash('sha256').update(raw).digest('hex');
};

userSchema.methods.toSafeJSON = function toSafeJSON() {
  return {
    id: this._id,
    name: this.name,
    email: this.email,
    role: this.role,
    isEmailVerified: this.isEmailVerified,
    authProviders: this.authProviders,
    createdAt: this.createdAt,
  };
};

module.exports = mongoose.model('User', userSchema);
module.exports.ROLES = ROLES;
