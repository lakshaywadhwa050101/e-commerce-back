const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcryptjs');
const cors = require('cors');
const app = express();
const PORT = process.env.PORT || 5000;

// Connect to SQLite database
const db = new sqlite3.Database('./data.db', (err) => {
  if (err) {
    console.error('SQLite connection error:', err.message);
  } else {
    console.log('Connected to SQLite database');
  }
});

app.use(express.json());
app.use(cors()); // Enable CORS

// Create users table if it doesn't exist
db.run(`CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT,
  email TEXT UNIQUE,
  phone TEXT,
  password TEXT
)`);

// Signup endpoint
app.post('/signup', async (req, res) => {
  try {
    const { name, email, phone, password } = req.body;

    // Check if user already exists
    db.get('SELECT * FROM users WHERE email = ?', [email], (err, row) => {
      if (err) {
        console.error('SQLite error:', err.message);
        return res.status(500).json({ error: 'Internal server error' });
      }

      if (row) {
        return res.status(400).json({ error: 'User already exists' });
      }

      // Hash the password
      bcrypt.hash(password, 10, (hashErr, hashedPassword) => {
        if (hashErr) {
          console.error('Password hashing error:', hashErr.message);
          return res.status(500).json({ error: 'Internal server error' });
        }

        // Insert new user into the database
        db.run('INSERT INTO users (name, email, phone, password) VALUES (?, ?, ?, ?)', [name, email, phone, hashedPassword], (insertErr) => {
          if (insertErr) {
            console.error('SQLite error:', insertErr.message);
            return res.status(500).json({ error: 'Internal server error' });
          }

          // Return success response
          res.status(201).json({ message: 'User created successfully' });
        });
      });
    });
  } catch (error) {
    console.error('Signup error:', error.message);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Login endpoint
app.post('/login', async (req, res) => {
  try {
    const { email, password } = req.body;

    // Find user by email
    db.get('SELECT * FROM users WHERE email = ?', [email], async (err, user) => {
      if (err) {
        console.error('SQLite error:', err.message);
        return res.status(500).json({ error: 'Internal server error' });
      }

      if (!user) {
        return res.status(404).json({ error: 'User not found' });
      }

      // Verify password
      const isPasswordValid = await bcrypt.compare(password, user.password);
      if (!isPasswordValid) {
        return res.status(401).json({ error: 'Invalid credentials' });
      }

      // Return success response
      res.json({ message: 'Login successful', user: { id: user.id, name: user.name, email: user.email, phone: user.phone } });
    });
  } catch (error) {
    console.error('Login error:', error.message);
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}`);
});







// // server.js

// const express = require('express');
// const mongoose = require('mongoose');
// const bcrypt = require('bcryptjs');
// const cors = require('cors');
// const User = require('./models/User/User');

// const app = express();
// const PORT = process.env.PORT || 5000;

// // Connect to MongoDB
// mongoose.connect('mongodb://localhost:27017/mydatabase', {
//   useNewUrlParser: true,
//   useUnifiedTopology: true,
// })
// .then(() => console.log('Connected to MongoDB'))
// .catch(err => console.error('MongoDB connection error:', err));

// app.use(express.json());
// app.use(cors()); // Enable CORS

// // Signup endpoint
// app.post('/signup', async (req, res) => {
//   try {
//     const { name, email, phone, password } = req.body;

//     // Check if user already exists
//     const existingUser = await User.findOne({ email });
//     if (existingUser) {
//       return res.status(400).json({ error: 'User already exists' });
//     }

//     // Hash the password
//     const hashedPassword = await bcrypt.hash(password, 10);

//     // Create new user
//     const newUser = new User({ name, email, phone, password: hashedPassword });

//     // Save user to database
//     await newUser.save();

//     res.status(201).json({ message: 'User created successfully' });
//   } catch (error) {
//     console.error('Signup error:', error.message);
//     res.status(500).json({ error: 'Internal server error' });
//   }
// });

// // Login endpoint
// app.post('/login', async (req, res) => {
//   try {
//     const { email, password } = req.body;

//     // Find user by email
//     const user = await User.findOne({ email });
//     if (!user) {
//       return res.status(404).json({ error: 'User not found' });
//     }

//     // Verify password
//     const isPasswordValid = await bcrypt.compare(password, user.password);
//     if (!isPasswordValid) {
//       return res.status(401).json({ error: 'Invalid credentials' });
//     }

//     // Return success response
//     res.json({ message: 'Login successful', user: { id: user.id, name: user.name, email: user.email, phone: user.phone } });
//   } catch (error) {
//     console.error('Login error:', error.message);
//     res.status(500).json({ error: 'Internal server error' });
//   }
// });

// app.listen(PORT, () => {
//   console.log(`Server is running on port ${PORT}`);
// });


// server.js
