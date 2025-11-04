const express = require('express');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const { authenticate, authorizeAdmin } = require('../middleware/auth');
const { validateUser } = require('../utils/validate');

const router = express.Router();
const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

// ============================
// Mock DB
// ============================

let users = [
  {
    id: 1,
    name: 'Admin',
    email: 'admin@example.com',
    password: bcrypt.hashSync('admin123', 10),
    role: 'admin',
  },
];

// ============================
// GET current user (safe way)
// ============================

router.get('/me', authenticate, (req, res) => {
  const user = users.find((u) => u.id === req.user.id);
  if (!user) return res.status(404).json({ message: 'User not found' });

  res.status(200).json({
    id: user.id,
    name: user.name,
    email: user.email,
    role: user.role,
  });
});

// ============================
// LOGOUT
// ============================

router.post('/logout', (req, res) => {
  res.clearCookie('token', {
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',
    sameSite: process.env.NODE_ENV === 'production' ? 'Strict' : 'Lax',
  });
  res.status(200).json({ message: 'Logged out successfully' });
});

// ============================
// REGISTER
// ============================

router.post('/register', (req, res) => {
  const { name, email, password } = req.body;

  if (!validateUser({ name, email, password }))
    return res.status(400).json({ message: 'Invalid input' });

  if (!emailRegex.test(email))
    return res.status(400).json({ message: 'Invalid email format' });

  if (password.length < 8)
    return res.status(400).json({ message: 'Password too short' });

  if (users.some((user) => user.email === email))
    return res.status(400).json({ message: 'Email already exists' });

  const hashedPassword = bcrypt.hashSync(password, 10);

  const newUser = {
    id: users.length + 1,
    name,
    email,
    password: hashedPassword,
    role: 'user',
  };

  users.push(newUser);
  res.status(201).json({ message: 'User registered successfully' });
});

// ============================
// LOGIN
// ============================

router.post('/login', (req, res) => {
  const { email, password } = req.body;
  const user = users.find((u) => u.email === email);
  console.log(req.body);
  if (!user) return res.status(400).json({ message: 'Invalid credentials' });
  if (!bcrypt.compareSync(password, user.password))
    return res.status(400).json({ message: 'Invalid credentials' });

  const token = jwt.sign(
    { id: user.id, role: user.role, email: user.email, name: user.name },
    process.env.JWT_SECRET,
    { expiresIn: '1h' }
  );

  res.cookie('token', token, {
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',
    sameSite: process.env.NODE_ENV === 'production' ? 'Strict' : 'Lax',
    maxAge: 60 * 60 * 1000,
  });

  res.status(200).json({ message: 'User logged in successfully' });
});

// ============================
// ADMIN ROUTES
// ============================

// Only admin can view all users
router.get('/', authenticate, authorizeAdmin, (req, res) => {
  res.json(users.map((u) => ({
    id: u.id,
    name: u.name,
    email: u.email,
    role: u.role,
  })));
});

// Admin-only console route
router.get('/console',  (req, res) => {
  res.status(200).json(
    users.map((u) => ({
      id: u.id,
      name: u.name,
      email: u.email,
      role: u.role,
    }))
  );
});

// UPDATE USER
router.put('/:id', authenticate, authorizeAdmin, (req, res) => {
  const user = users.find((u) => u.id === parseInt(req.params.id));
  if (!user) return res.status(404).json({ message: 'User not found' });

  const { name, email, role } = req.body;

  if (email && users.some((u) => u.email === email && u.id !== user.id))
    return res.status(400).json({ message: 'Email already in use' });

  if (name) user.name = name;
  if (email) user.email = email;
  if (role) user.role = role;

  res.json({ message: 'User updated', user });
});

// DELETE USER
router.delete('/:id', authenticate, authorizeAdmin, (req, res) => {
  const targetId = parseInt(req.params.id);
  const targetUser = users.find((u) => u.id === targetId);
  if (!targetUser) return res.status(404).json({ message: 'User not found' });

  users = users.filter((u) => u.id !== targetId);
  res.json({ message: 'User deleted', deletedUser: targetUser });
});

module.exports = router;
