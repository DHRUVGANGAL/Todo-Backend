// db.js
const mongoose = require('mongoose');
const Schema = mongoose.Schema;
const objectId = mongoose.Schema.ObjectId;

// User Schema
const user = new Schema({
  userName: String,
  email: { type: "string", unique: true },
  password: String
});

const UserModel = mongoose.model('user', user);

// Todo Schema
const todoSchema = new mongoose.Schema({
  userId: {
    type: mongoose.Schema.Types.ObjectId,
    required: true
  },
  title: {
    type: String,
    required: true
  },
  completed: {
    type: Boolean
  }
}, {
  timestamps: true
});

const TodoModel = mongoose.model('todos', todoSchema);

module.exports = {
  UserModel,
  TodoModel
};