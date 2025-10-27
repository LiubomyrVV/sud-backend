require('dotenv').config();
const express = require('express');
const cors = require('cors');
const usersRouter = require('./routes/users');

const app = express();


app.use(cors({ origin: process.env.FRONTEND_URL })); // allow frontend only
app.use(express.json());

// Routes
app.use('/api/users', usersRouter);


const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
