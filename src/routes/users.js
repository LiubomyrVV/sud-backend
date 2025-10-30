const express = require('express');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const { authenticate, authorizeAdmin } = require('../middleware/auth');
const { validateUser } = require('../utils/validate');

const router = express.Router();

// ============================
// Mock DB
// In prod: replace with real database (PostgreSQL, MongoDB, etc.)
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

router.get('/console', (req, res) => {
  res.status(200).json(users);
});

router.get('/me', (req, res) => {
  const token = req.cookies.token; 
  console.log('Token from cookies:', token);
  if (!token) return res.status(401).json({ message: 'Unauthorized' });

  try {
    const userData = jwt.verify(token, process.env.JWT_SECRET);
    res.status(200).json(userData);
  } catch (err) {
    res.status(401).json({ message: 'Invalid token' });
  }
});

router.post('/logout', (req, res) => {
  res.clearCookie('token', { httpOnly: true, secure: true, sameSite: 'Strict' });
  res.json({ message: 'Logged out' });
});

router.post('/register', (req, res) => {
  const { name, email, password } = req.body;

  // Validate input
  if (!validateUser({ name, email, password }))
    return res.status(400).json({ message: 'Invalid input' });

  // Check if user exists
  if (users.find((user) => user.email === email))
    return res.status(400).json({ message: 'Email already exists' });

  // Hash password
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

router.post('/login', (req, res) => {
  const { email, password } = req.body;
  const user = users.find((u) => u.email === email);
  if (!user) return res.status(400).json({ message: 'Invalid credentials' });

  // Compare passwords
  if (!bcrypt.compareSync(password, user.password))
    return res.status(400).json({ message: 'Invalid credentials' });

  // Generate JWT
  const token = jwt.sign(
    { id: user.id, role: user.role, email: user.email, name: user.name },
    process.env.JWT_SECRET,
    { expiresIn: '1h' }
  );

  // Set HttpOnly cookie
  res.cookie('token', token, {
    httpOnly: true,        
    secure: process.env.NODE_ENV === 'production', 
    sameSite: 'Strict',   
    maxAge: 60 * 60 * 1000 
  });

  res.status(200).json({ message: 'User logged successfully' });
});

router.get('/', authenticate, (req, res) => {
  res.json(
    users.map((u) => ({ id: u.id, name: u.name, email: u.email, role: u.role }))
  );
});
// ============================
// Admin ACTIONS
// ============================

// UPDATE USER
router.put('/:id', authenticate, authorizeAdmin, (req, res) => {
  const user = users.find((u) => u.id === parseInt(req.params.id));
  if (!user) return res.status(404).json({ message: 'User not found' });

  const { name, email, role } = req.body;
  if (name) user.name = name;
  if (email) user.email = email;
  if (role) user.role = role;

  res.json({ message: 'User updated', user });
});

// DELETE USER
router.delete('/:id', authenticate, authorizeAdmin, (req, res) => {
  users = users.filter((u) => u.id !== parseInt(req.params.id));
  res.json({ message: 'User deleted' });
});

module.exports = router;
