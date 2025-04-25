// api/index.js
const express = require('express');
const serverless = require('serverless-http');
require('dotenv').config();
const app = express();
app.use(express.json());
const Jwt = require('jsonwebtoken');
const JWT_secret = process.env.JWT_SECRET || "hiitheresecret";
const mongoose = require('mongoose');
const { UserModel, TodoModel } = require("./db");
const bcrypt = require('bcrypt');
const { z } = require('zod');
const cors = require("cors");

// Connect to MongoDB using environment variable
const MONGODB_URI = process.env.MONGODB_URI;
mongoose.connect(MONGODB_URI)
  .then(() => console.log('Connected to MongoDB'))
  .catch(err => console.error('MongoDB connection error:', err));

app.use(cors());
app.get('/',async function (req,res) {
    res.send("hello world");
})
app.post('/signup', async function(req, res) {
  console.log("Received data:", req.body);
  // Validation schema
  const schema = z.object({
    userName: z.string(),
    email: z.string().email(),
    password: z.string().min(5)
  });
  // Validate request body
  const data = schema.safeParse(req.body);
  if (!data.success) {
    return res.status(400).json({
      message: data.error.issues[0].message // Access first error message
    });
  }
  // Destructure validated data
  const { userName, email, password } = data.data;
  try {
    // Check if email exists first
    const existingUser = await UserModel.findOne({ email });
    if (existingUser) {
      return res.status(400).json({ message: "Email already exists" });
    }
    // Hash password
    const hashPassword = await bcrypt.hash(password, 10);
    // Create user using the exact schema field names
    const user = await UserModel.create({
      userName: userName,
      email: email,
      password: hashPassword
    });
    res.status(201).json({
      message: "User created successfully",
      user
    });
  } catch (err) {
    console.log(err);
    return res.status(500).json({ message: "Error creating user" });
  }
});

app.post('/signin', async (req, res) => {
  try { 
    console.log("Received data:", req.body);
    const { email, password } = req.body;
    const user = await UserModel.findOne({ email });
    if (!user || !await bcrypt.compare(password, user.password)) {
      return res.status(401).json({
        success: false,
        message: 'Invalid email or password'
      });
    }
    // Create token
    const token = Jwt.sign(
      { id: user._id },
      JWT_secret,
      { expiresIn: '24h' }
    );
    // Send response with token
    res.json({
      success: true,
      message: 'Successfully signed in',
      token: token
    });
  } catch (error) {
    console.error('Signin error:', error);
    res.status(500).json({
      success: false,
      message: 'Server error during signin'
    });
  }
});

// Auth Middleware
function auth(req, res, next) {
  const token = req.headers.token;
  if (!token) return res.status(401).json({ message: "No token provided" });
  try {
    const data = Jwt.verify(token, JWT_secret);
    req.userId = data.id;
    next();
  } catch (err) {
    return res.status(403).json({ message: "Invalid token" });
  }
}

// Routes
app.post("/todo", auth, async function(req, res) {
  try {
    const userId = req.userId;
    const todo = await TodoModel.create({
      userId: userId,
      title: req.body.title,
      completed: false
    });
    res.status(201).json(todo);
  } catch (error) {
    res.status(500).json({ message: "Error creating todo", error: error.message });
  }
});

app.get('/todos', auth, async function(req, res) {
  try {
    const userId = req.userId;
    const todos = await TodoModel.find({ userId: userId });
    if (!todos || todos.length === 0) {
      return res.status(404).json({ message: "No todos found" });
    }
    res.json(todos);
  } catch (error) {
    res.status(500).json({ message: "Error fetching todos", error: error.message });
  }
});

app.delete('/delete-todo/:id', auth, async function(req, res) {
  try {
    const userId = req.userId;
    const todoId = req.params.id;
    const todo = await TodoModel.findOne({ _id: todoId, userId: userId });
    if (!todo) {
      return res.status(404).json({ message: "Todo not found or not authorized to delete" });
    }
    await TodoModel.findByIdAndDelete(todoId);
    res.json({ message: "Todo deleted successfully" });
  } catch (error) {
    res.status(500).json({ message: "Error deleting todo", error: error.message });
  }
});

app.put('/update-todo/:id', auth, async function(req, res) {
  try {
    const userId = req.userId;
    const todoId = req.params.id;
    // Input validation
    if (!todoId || typeof req.body.completed !== 'boolean') {
      return res.status(400).json({
        message: "Invalid input. Todo ID and completed status required"
      });
    }
    // Find and update in one operation using findOneAndUpdate
    const updatedTodo = await TodoModel.findOneAndUpdate(
      { _id: todoId, userId: userId },
      { completed: req.body.completed },
      { new: true } // Return the updated document
    );
    if (!updatedTodo) {
      return res.status(404).json({
        message: "Todo not found or not authorized to update"
      });
    }
    res.json(updatedTodo);
  } catch (error) {
    console.error('Todo update error:', error);
    res.status(500).json({
      message: "Error updating todo",
      error: error.message
    });
  }
});

// Export handler for serverless function
module.exports = serverless(app);