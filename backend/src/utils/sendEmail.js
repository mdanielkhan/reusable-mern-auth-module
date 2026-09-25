const nodemailer = require('nodemailer');

let transporter;
const getTransporter = () => {
  if (!transporter) {
    transporter = nodemailer.createTransport({
      host: process.env.SMTP_HOST,
      port: Number(process.env.SMTP_PORT || 587),
      secure: Number(process.env.SMTP_PORT) === 465,
      auth: { user: process.env.SMTP_USER, pass: process.env.SMTP_PASS },
    });
  }
  return transporter;
};

const sendEmail = async ({ to, subject, html, text }) => {
  await getTransporter().sendMail({
    from: process.env.EMAIL_FROM,
    to,
    subject,
    html,
    text: text || html.replace(/<[^>]+>/g, ''),
  });
};

const verificationEmailHtml = (link) => `<p>Verify your email by clicking the link below. This link expires soon.</p>
<p><a href="${link}">${link}</a></p>`;

const resetPasswordEmailHtml = (link) => `<p>You requested a password reset. Click the link below to set a new password. If you didn't request this, ignore this email.</p>
<p><a href="${link}">${link}</a></p>`;

module.exports = { sendEmail, verificationEmailHtml, resetPasswordEmailHtml };