require('dotenv').config();
const express = require('express');
const cors = require('cors');
const usersRouter = require('./routes/users');

const app = express();


app.use(cors({ origin: 'http://localhost:5173' })); // allow frontend only
app.use(express.json());

// Routes
app.use('/api/users', usersRouter);


const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
