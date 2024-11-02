const express = require('express');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
const sqlite3 = require('sqlite3').verbose();

const app = express();
app.use(express.json());

const db = new sqlite3.Database('./TaskManager.db', (err) => {
    if (err) {
        console.error('Database connection error:', err.message);
    } else {
        console.log('Connected to SQLite database.');
        
        db.run(`CREATE TABLE IF NOT EXISTS Users (
            Id INTEGER PRIMARY KEY AUTOINCREMENT,
            Name TEXT NOT NULL,
            Email TEXT NOT NULL UNIQUE,
            Password TEXT NOT NULL
        );`);
        
        db.run(`CREATE TABLE IF NOT EXISTS Tasks (
            Id INTEGER PRIMARY KEY AUTOINCREMENT,
            Title TEXT NOT NULL,
            Priority TEXT NOT NULL,
            AssignedTo TEXT,  -- List of user emails as JSON
            CheckList TEXT,   -- Checklist items as JSON
            IsBacklog BOOLEAN DEFAULT 0,
            IsTodo BOOLEAN DEFAULT 0,
            IsInProgress BOOLEAN DEFAULT 0,
            IsDone BOOLEAN DEFAULT 0,
            DueDate DATE,
            CreatedAt TEXT DEFAULT CURRENT_TIMESTAMP
        );`);
    }
});

const SECRET_KEY = 'your_secret_key';

// Middleware for authentication
function authenticateToken(req, res, next) {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
    if (!token) return res.sendStatus(401);
    
    jwt.verify(token, SECRET_KEY, (err, user) => {
        if (err) return res.sendStatus(403);
        req.user = user;
        next();
    });
}

// Register User
app.post('/api/register', async (req, res) => {
    const { name, email, password } = req.body;
    const hashedPassword = await bcrypt.hash(password, 10);
    
    db.run(`INSERT INTO Users (Name, Email, Password) VALUES (?, ?, ?)`,
        [name, email, hashedPassword],
        function(err) {
            if (err) {
                return res.status(400).json({ error: err.message });
            }
            res.json({ message: 'User registered successfully!' });
        });
});

// Login User
app.post('/api/login', (req, res) => {
    const { email, password } = req.body;
    
    db.get(`SELECT * FROM Users WHERE Email = ?`, [email], async (err, user) => {
        if (err || !user || !(await bcrypt.compare(password, user.Password))) {
            return res.status(400).json({ error: 'Invalid credentials' });
        }
        
        const token = jwt.sign({ userId: user.Id }, SECRET_KEY, { expiresIn: '1h' });
        res.json({ token });
    });
});

// Create Task
app.post('/api/tasks', authenticateToken, (req, res) => {
    const { title, priority, assignedTo, dueDate } = req.body;
    const assignedToJSON = JSON.stringify(assignedTo);  // Store as JSON

    db.run(`INSERT INTO Tasks (Title, Priority, AssignedTo, DueDate) VALUES (?, ?, ?, ?)`,
        [title, priority, assignedToJSON, dueDate],
        function(err) {
            if (err) {
                return res.status(400).json({ error: err.message });
            }
            res.json({ message: 'Task created successfully!' });
        });
});

// Filter Tasks
app.get('/api/tasks/filter/:timeframe', authenticateToken, (req, res) => {
    const { timeframe } = req.params;
    let query = 'SELECT * FROM Tasks WHERE 1=1';

    if (timeframe === 'today') {
        query += " AND DATE(CreatedAt) = DATE('now')";
    } else if (timeframe === 'this_week') {
        query += " AND DATE(CreatedAt) >= DATE('now', '-6 days')";
    } else if (timeframe === 'this_month') {
        query += " AND strftime('%Y-%m', CreatedAt) = strftime('%Y-%m', 'now')";
    } else if (timeframe === 'this_year') {
        query += " AND strftime('%Y', CreatedAt) = strftime('%Y', 'now')";
    } else {
        return res.status(400).json({ error: 'Invalid timeframe' });
    }

    db.all(query, [], (err, rows) => {
        if (err) {
            return res.status(400).json({ error: err.message });
        }
        res.json(rows);
    });
});

// Start server
const PORT = 3000;
app.listen(PORT, () => {
    console.log(`Server is running on http://localhost:${PORT}`);
});
