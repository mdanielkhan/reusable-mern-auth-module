const express = require('express');
const cors = require('cors');
const cookieParser = require('cookie-parser');
const authRoutes = require('./routes/authRoutes');
const errorHandler = require('./middleware/errorHandler');
const AppError = require('./utils/AppError');

const app = express();

app.use(
  cors({
    origin: process.env.CLIENT_URL, // must be an exact origin, not '*', when credentials:true
    credentials: true, // required for the browser to send/receive httpOnly cookies
  })
);
app.use(express.json());
app.use(cookieParser());

app.use('/api/auth', authRoutes);

app.get('/api/health', (req, res) => res.json({ status: 'ok' }));

// Anything that falls through to here is an unmatched route.
app.all('*', (req, res, next) => {
  next(new AppError(`Route ${req.originalUrl} not found.`, 404));
});

app.use(errorHandler);

module.exports = app;
