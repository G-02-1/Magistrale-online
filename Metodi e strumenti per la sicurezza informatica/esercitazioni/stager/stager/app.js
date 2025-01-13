const express = require('express');
const bodyParser = require('body-parser');
const session = require('express-session');
const cookieParser = require('cookie-parser');

const app = express();
app.use(bodyParser.json());
app.use(cookieParser());

// Using an in-memory session store for demonstration
app.use(session({
  secret: 'supersecretkey',
  resave: false,
  saveUninitialized: false,
  cookie: { httpOnly: true } // Ensures cookie is not accessible via JS
}));

// Mock "database"
let user = {
  id: 7357,
  name: 'Alice',
  age: 25
};

// Simple authentication mechanism
// In a real scenario, you'd check a database, hash passwords, etc.
app.post('/login', (req, res) => {
  const username = req.body.username;
  const password = req.body.password;

  // For demo: Any non-empty username/password logs in as that user
  if (username && password) {
    req.session.isLoggedIn = true;
    req.session.username = username;
    return res.json({ status: 'logged_in', username: username });
  } else {
    return res.json({ error: 'Invalid credentials' });
  }
});

// Middleware to check if user is logged in
function requireAuth(req, res, next) {
  if (req.session && req.session.isLoggedIn) {
    return next();
  } else {
    return res.status(401).json({ error: 'Unauthorized' });
  }
}

// "Delete user" endpoint now requires authentication
app.get('/authService/user/delete', requireAuth, (req, res) => {
  const name = req.query.name;
  console.log(`[ADMIN LOG] Authenticated user ${req.session.username} attempted to delete: ${name}`);
  // In a real system, you'd confirm that the authenticated user has permissions.
  res.json({ result: `User ${name} attempted to be deleted by ${req.session.username}.` });
});

// Update user details - still vulnerable to XSS
app.post('/updateDetails', requireAuth, (req, res) => {
  let newName = req.body.name || '';
  
  // Enforce a 100-character limit
  if (newName.length > 100) {
    return res.json({ error: "Name too long" });
  }

  user.id = req.body.id || user.id;
  user.name = newName;
  user.age = req.body.age || user.age;

  res.json({ status: "success" });
});

// Profile endpoint - now requires user to be logged in and displays user input unsafely
app.get('/profile', requireAuth, (req, res) => {
  const html = `
    <html>
      <head><title>Profile</title></head>
      <body>
        <h1>Welcome, ${user.name}</h1>
        <p>Your ID: ${user.id}</p>
        <p>Your Age: ${user.age}</p>
        <p>Logged in as: ${req.session.username}</p>
      </body>
    </html>
  `;
  res.send(html);
});

app.listen(3000, () => {
  console.log('Demo app with auth listening at http://0.0.0.0:3000');
});
