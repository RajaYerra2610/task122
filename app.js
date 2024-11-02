// app.js
const express = require('express');
const jwt = require('jsonwebtoken');
const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcrypt');
const app = express();
const port = 3000;

// Secret key for JWT
const secretKey = 'your_secret_key';

// Set up express to handle JSON
app.use(express.json());

// Initialize SQLite database
const db = new sqlite3.Database('./TaskManager.db', (err) => {
    if (err) {
        console.error('Database connection error:', err.message);
    } else {
        console.log('Connected to SQLite database.');
        db.serialize(() => {
            db.run(`
                CREATE TABLE IF NOT EXISTS Users (
                    Id INTEGER PRIMARY KEY AUTOINCREMENT,
                    Name TEXT NOT NULL,
                    Email TEXT NOT NULL UNIQUE,
                    Password TEXT NOT NULL
                );
            `);

            db.run(`
                CREATE TABLE IF NOT EXISTS Tasks (
                    Id INTEGER PRIMARY KEY AUTOINCREMENT,
                    Title TEXT NOT NULL,
                    Priority TEXT NOT NULL,
                    AssignedTo TEXT,  -- JSON string of email IDs
                    CheckList TEXT,   -- JSON string of checklist items
                    IsBacklog BOOLEAN DEFAULT 0,
                    IsTodo BOOLEAN DEFAULT 0,
                    IsInProgress BOOLEAN DEFAULT 0,
                    IsDone BOOLEAN DEFAULT 0,
                    DueDate DATE,
                    CreatedAt TEXT DEFAULT CURRENT_TIMESTAMP
                );
            `);
        });
    }
});

// Authentication middleware
function authenticateToken(req, res, next) {
    const token = req.headers['authorization'] && req.headers['authorization'].split(' ')[1];
    if (!token) return res.status(401).json({ message: 'Unauthorized: Token not provided' });

    jwt.verify(token, secretKey, (err, user) => {
        if (err) return res.status(403).json({ message: 'Unauthorized: Token invalid' });
        req.user = user; // Store user information in req
        next();
    });
}

// Register endpoint
app.post('/api/register', async (req, res) => {
    const { name, email, password } = req.body;
    const hashedPassword = await bcrypt.hash(password, 10);

    db.run(
        `INSERT INTO Users (Name, Email, Password) VALUES (?, ?, ?)`,
        [name, email, hashedPassword],
        function (err) {
            if (err) {
                return res.status(400).json({ error: 'Email already exists' });
            }
            res.status(201).json({ message: 'User registered successfully' });
        }
    );
});

// Login endpoint
app.post('/api/login', (req, res) => {
    const { email, password } = req.body;

    db.get(`SELECT * FROM Users WHERE Email = ?`, [email], async (err, user) => {
        if (err || !user) {
            return res.status(400).json({ error: 'User not found' });
        }
        const validPassword = await bcrypt.compare(password, user.Password);
        if (!validPassword) {
            return res.status(401).json({ error: 'Invalid password' });
        }

        // Generate JWT
        const token = jwt.sign({ userId: user.Id, email: user.Email }, secretKey, { expiresIn: '1h' });
        res.json({ message: 'Login successful', token });
    });
});

// Create Task endpoint (authenticated)
app.post('/api/tasks', authenticateToken, (req, res) => {
    const { title, priority, assignedTo, dueDate } = req.body;
    const assignedToEmails = JSON.stringify(assignedTo);

    db.run(
        `INSERT INTO Tasks (Title, Priority, AssignedTo, DueDate) VALUES (?, ?, ?, ?)`,
        [title, priority, assignedToEmails, dueDate],
        function (err) {
            if (err) {
                return res.status(500).json({ error: err.message });
            }
            res.status(201).json({ message: 'Task created', taskId: this.lastID });
        }
    );
});

// Run server
app.listen(port, () => {
    console.log(`Server running on http://localhost:${port}`);
});
