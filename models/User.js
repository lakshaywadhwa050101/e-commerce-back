// models/User.js

const mongoose = require('mongoose');

const User = new mongoose.Schema({
  name: String,
  email: { type: String, unique: true },
  phone: String,
  password: String,
});

module.exports = mongoose.model('User', User);
