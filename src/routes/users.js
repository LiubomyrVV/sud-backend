const express = require('express');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const { authenticate, authorizeAdmin } = require('../middleware/auth');
const { validateUser } = require('../utils/validate');
const { query } = require('../db/db');

const router = express.Router();
const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

// ============================
// GET current user
// ============================
router.get('/me', authenticate, async (req, res) => {
  try {
    const users = await query('SELECT id, name, email, role FROM users WHERE id = @id', { id: req.user.id });
    if (!users[0]) return res.status(404).json({ message: 'User not found' });
    res.json(users[0]);
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'DB error' });
  }
});

// ============================
// REGISTER
// ============================
router.post('/register', async (req, res) => {
  const { name, email, password } = req.body;

  if (!validateUser({ name, email, password }))
    return res.status(400).json({ message: 'Invalid input' });

  if (!emailRegex.test(email))
    return res.status(400).json({ message: 'Invalid email format' });

  try {
    const existing = await query('SELECT id FROM users WHERE email = @email', { email });
    if (existing.length > 0) return res.status(400).json({ message: 'Email already exists' });

    const hashedPassword = await bcrypt.hash(password, 10);

    await query(
      'INSERT INTO users (name, email, password, role) VALUES (@name, @email, @password, @role)',
      { name, email, password: hashedPassword, role: 'user' }
    );

    res.status(201).json({ message: 'User registered successfully' });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'DB error' });
  }
});

// ============================
// LOGIN
// ============================
router.post('/login', async (req, res) => {
  const { email, password } = req.body;
  try {
    const users = await query('SELECT * FROM users WHERE email = @email', { email });
    const user = users[0];
    if (!user) return res.status(400).json({ message: 'Invalid credentials' });

    const match = await bcrypt.compare(password, user.password);
    if (!match) return res.status(400).json({ message: 'Invalid credentials' });

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

    res.json({ message: 'Logged in successfully' });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'DB error' });
  }
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
// GET all users (admin only)
// ============================
router.get('/', authenticate, authorizeAdmin, async (req, res) => {
  try {
    const users = await query('SELECT id, name, email, role FROM users');
    res.json(users);
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'DB error' });
  }
});

// ============================
// UPDATE user (admin only)
// ============================
router.put('/:id', authenticate, authorizeAdmin, async (req, res) => {
  const { id } = req.params;
  const { name, email, role } = req.body;

  try {
    const existing = await query('SELECT id FROM users WHERE id = @id', { id });
    if (!existing[0]) return res.status(404).json({ message: 'User not found' });

    if (email) {
      const emailExists = await query('SELECT id FROM users WHERE email = @email AND id != @id', { email, id });
      if (emailExists.length > 0) return res.status(400).json({ message: 'Email already in use' });
    }

    await query(
      'UPDATE users SET name = COALESCE(@name, name), email = COALESCE(@email, email), role = COALESCE(@role, role) WHERE id = @id',
      { name, email, role, id }
    );

    res.json({ message: 'User updated' });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'DB error' });
  }
});

// ============================
// DELETE user (admin only)
// ============================
router.delete('/:id', authenticate, authorizeAdmin, async (req, res) => {
  const { id } = req.params;
  try {
    const user = await query('SELECT * FROM users WHERE id = @id', { id });
    if (!user[0]) return res.status(404).json({ message: 'User not found' });

    await query('DELETE FROM users WHERE id = @id', { id });
    res.json({ message: 'User deleted', deletedUser: user[0] });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'DB error' });
  }
});

module.exports = router;
