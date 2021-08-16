const crypto = require('crypto');
const { promisify } = require('util');
const jwt = require('jsonwebtoken');

const User = require('../models/userModel');

const catchAsync = require('../utils/catchAsync');
const AppError = require('../utils/appError');
const sendMail = require('../utils/email');

const genJWTToken = id => {
  return jwt.sign({ id }, process.env.JWT_SECRET, {
    expiresIn: process.env.JWT_EXPIRES_IN
  });
};

const createSendToken = (user, statusCode, res) => {
  const token = genJWTToken(user._id);

  const cookieOptions = {
    expires: new Date(
      Date.now + process.env.JWT_COOKIE_EXPIRES_IN * 24 * 60 * 60 * 1000
    ),
    httpOnly: true
  };

  if (process.env.NODE_ENV === 'production') cookieOptions.secure = true;

  res.cookie('jwt', token, cookieOptions);

  user.password = undefined;

  res.status(statusCode).json({
    status: 'success',
    token,
    data: {
      user
    }
  });
};

exports.signup = catchAsync(async (req, res) => {
  const { name, email, password, passwordConfirm } = req.body;
  const newUser = await User.create({ name, email, password, passwordConfirm });
  createSendToken(newUser, 201, res);
});

exports.login = catchAsync(async (req, res) => {
  const { email, password } = req.body;

  if (!(email && password)) {
    throw new AppError('Please provide email and password.', 400);
  }

  const user = await User.findOne({ email }).select('+password');

  if (!(user && (await user.correctPassword(password, user.password)))) {
    throw new AppError('Incorrect email or password.', 401);
  }

  createSendToken(user, 200, res);
});

exports.protect = catchAsync(async (req, res, next) => {
  let token;

  if (
    req.headers.authorization &&
    req.headers.authorization.startsWith('Bearer')
  ) {
    token = req.headers.authorization.split(' ')[1];
  }

  if (!token) {
    throw new AppError('Please login to get access.', 401);
  }

  const decoded = await promisify(jwt.verify)(token, process.env.JWT_SECRET);

  const user = await User.findById(decoded.id);

  if (!user) {
    throw new AppError('User belonging to this token does not exist.', 401);
  }

  if (user.changedPasswordAfter(decoded.iat)) {
    throw new AppError('Password recently changed, Please login again.', 401);
  }

  req.user = user;

  next();
});

exports.restrictTo = (...roles) => (req, res, next) => {
  if (!roles.includes(req.user.role)) {
    throw new AppError('You do not have permission to do this action', 403);
  }

  next();
};

exports.forgetPassword = catchAsync(async (req, res) => {
  const { email } = req.body;

  if (!email) {
    throw new AppError('Please provide your email', 400);
  }

  const user = await User.findOne({ email });

  if (!user) {
    throw new AppError('No user found with this email', 404);
  }

  const resetToken = user.createPasswordRestToken();

  await user.save({ validateBeforeSave: false });

  const resetUrl = `${req.protocol}://${req.get(
    'host'
  )}/api/v1/users/resetPassword/${resetToken}`;

  const message = `Forgot your password? Submit a patch request to ${resetUrl} with your new password`;

  try {
    await sendMail({
      email,
      message,
      subject: 'Your password reset token (Valid for 10 min)'
    });

    res.status(200).json({
      status: 'success',
      message: `A reset token sent to ${email}`
    });
  } catch (err) {
    user.passwordResetToken = undefined;
    user.passwordRestExpires = undefined;
    await user.save({ validateBeforeSave: false });

    throw new AppError(
      'There was an error sending email please try again.',
      500
    );
  }
});

exports.resetPassword = catchAsync(async (req, res) => {
  const { token } = req.params;

  const hashedToken = crypto
    .createHash('sha256')
    .update(token)
    .digest('hex');

  const user = await User.findOne({
    passwordResetToken: hashedToken,
    passwordRestExpires: { $gt: Date.now() }
  });

  if (!user) {
    throw new AppError('Token is invalid or has been expired', 400);
  }

  user.password = req.body.password;
  user.passwordConfirm = req.body.passwordConfirm;

  user.passwordResetToken = undefined;
  user.passwordRestExpires = undefined;

  await user.save();

  createSendToken(user, 200, res);
});

exports.updatePassword = catchAsync(async (req, res) => {
  const { password, newPassword, newPasswordConfirm } = req.body;

  if (!(password && newPassword && newPasswordConfirm)) {
    throw new AppError(
      'PLease provide your password, the new password and the new password confirm',
      400
    );
  }

  const user = await User.findById(req.user._id).select('+password');

  if (!(user && (await user.correctPassword(password, user.password)))) {
    throw new AppError('Incorrect password.', 401);
  }

  user.password = newPassword;
  user.passwordConfirm = newPasswordConfirm;

  await user.save();

  createSendToken(user, 200, res);
});
