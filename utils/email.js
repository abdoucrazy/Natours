const nodemailer = require('nodemailer');

const catchAsync = require('../utils/catchAsync');

const sendEmail = catchAsync(async options => {
  const transport = nodemailer.createTransport({
    host: process.env.EMAIL_HOST,
    port: process.env.EMAIL_PORT,
    auth: {
      user: process.env.EMAIL_USERNAME,
      pass: process.env.EMAIL_PASSWORD
    }
  });

  const mailOptions = {
    from: 'Abdelmouine Boussaid <aminebssd@gmail.com>',
    to: options.email,
    subject: options.subject,
    text: options.message
  };

  await transport.sendMail(mailOptions);
});

module.exports = sendEmail;
