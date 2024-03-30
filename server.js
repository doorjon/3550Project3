const express = require('express');
const jwt = require('jsonwebtoken');
const jose = require('node-jose');
const sqlite3 = require('sqlite3').verbose();
const crypto = require('crypto');
const { v4: uuidv4 } = require('uuid');
const argon2 = require('argon2');
const db = new sqlite3.Database('./totally_not_my_privateKeys.db', sqlite3.OPEN_READWRITE, (err)=>{
  if (err) return console.error(err.message);
});
const app = express();
const port = 8080;
const encryptionKey  = process.env.NOT_MY_KEY;

if (!encryptionKey ) {
  console.error("Environment variable NOT_MY_KEY is not set.");
  process.exit(1); // Exit the process if the key is not set
}
else{
  console.log(encryptionKey);
}

let keyPair;
let expiredKeyPair;
let token;
let expiredToken;
let row;
let parsedKey;

// Middleware to parse JSON and URL-encoded bodies
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// create db tables
db.run('CREATE TABLE IF NOT EXISTS keys(kid INTEGER PRIMARY KEY AUTOINCREMENT,key BLOB NOT NULL,exp INTEGER NOT NULL)');
db.run('CREATE TABLE IF NOT EXISTS users(id INTEGER PRIMARY KEY AUTOINCREMENT,username TEXT NOT NULL UNIQUE,password_hash TEXT NOT NULL,email TEXT UNIQUE,date_registered TIMESTAMP DEFAULT CURRENT_TIMESTAMP,last_login TIMESTAMP)');
db.run('CREATE TABLE IF NOT EXISTS auth_logs(id INTEGER PRIMARY KEY AUTOINCREMENT,request_ip TEXT NOT NULL,request_timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,user_id INTEGER,FOREIGN KEY(user_id) REFERENCES users(id))');

async function generateKeyPairs() {
  keyPair = await jose.JWK.createKey('RSA', 2048, { alg: 'RS256', use: 'sig' });
  expiredKeyPair = await jose.JWK.createKey('RSA', 2048, { alg: 'RS256', use: 'sig' });

  db.run('INSERT INTO keys (key, exp) VALUES (?, ?)', [JSON.stringify(keyPair.toJSON()), Math.floor(Date.now() / 3600) + 7200], (err) => {
    if (err) {
      console.error('Error inserting key into the database:', err.message);
    }
  });
}

function generateToken() {
  // retrieve key from database
  db.get('SELECT * FROM keys WHERE kid > 0;', (err, row) => {
    if (err) {
      console.error('Error retrieving key from the database:', err.message);
    }

    // parse key into usable format
    parsedKey = jose.JWK.asKey(row.key);
    parsedKey.then(function(parsedKey) {
      const payload = {
        user: 'sampleUser',
        iat: Math.floor(Date.now() / 1000),
        exp: Math.floor(Date.now() / 1000) + 3600
      };
      const options = {
        algorithm: 'RS256',
        header: {
          typ: 'JWT',
          alg: 'RS256',
          kid: parsedKey.kid
        }
      };
      
      token = jwt.sign(payload, keyPair.toPEM(true), options);
   })
   
  });
}

function generateExpiredJWT() {
  const payload = {
    user: 'sampleUser',
    iat: Math.floor(Date.now() / 1000) - 30000,
    exp: Math.floor(Date.now() / 1000) - 3600
  };
  const options = {
    algorithm: 'RS256',
    header: {
      typ: 'JWT',
      alg: 'RS256',
      kid: expiredKeyPair.kid
    }
  };

  expiredToken = jwt.sign(payload, expiredKeyPair.toPEM(true), options);
}

function rateLimiter(req, res, next) {
  const now = Date.now();
  const windowMs = 1000; // 1 second
  const maxRequests = 10; // 10 requests per second
  const ipAddress = req.ip;

  db.all('SELECT request_timestamp FROM auth_logs WHERE request_ip = ? AND request_timestamp > ?', [ipAddress, now - windowMs], (err, rows) => {
    if (err) {
      console.error('Error checking rate limit:', err.message);
      return res.status(500).json({ error: 'Internal server error' });
    }

    if (rows.length >= maxRequests) {
      return res.status(429).json({ error: 'Too Many Requests' });
    }

    next();
  });
}

app.all('/auth', (req, res, next) => {
  if (req.method !== 'POST') {
    return res.status(405).send('Method Not Allowed');
  }
  next();
});

// Middleware to ensure only GET requests are allowed for /jwks
app.all('/.well-known/jwks.json', (req, res, next) => {
  if (req.method !== 'GET') {
    return res.status(405).send('Method Not Allowed');
  }
  next();
});

app.get('/.well-known/jwks.json', (req, res) => {
  const validKeys = [keyPair].filter(key => !key.expired);
  res.setHeader('Content-Type', 'application/json');
  res.json({ keys: validKeys.map(key => key.toJSON()) });
});

app.post('/auth', rateLimiter, (req, res) => {
  const requestIP = req.ip; // Retrieve the IP address of the request
  const timestamp = new Date().toISOString(); // Get current timestamp
  const { username } = req.body; // Assuming username is sent in the request body

  // Insert log into auth_logs table
  db.run(`INSERT INTO auth_logs (request_ip, request_timestamp, user_id) VALUES (?, ?, (SELECT id FROM users WHERE username = ?))`, [requestIP, timestamp, username], function(err) {
    if (err) {
      console.error('Error inserting authentication log:', err);
      res.status(500).json({ error: 'Error logging authentication' });
      return;
    }

    // Send the token in the response
    if (req.query.expired === 'true') {
      res.send(expiredToken);
    } else {
      res.send(token);
    }
  });
});

app.post('/register', async (req, res) => {
  try {
    const { username, email } = req.body;
    const password = uuidv4();
    const hashedPassword = await argon2.hash(password);

    db.run(`INSERT INTO users (username, password_hash, email) VALUES (?, ?, ?)`, [username, hashedPassword, email], function(err) {
      if (err) {
        console.error('Error inserting user:', err);
        return res.status(500).json({ error: 'Error registering user' });
      }

      // User inserted successfully, send response
      res.status(201).json({ password });
    });
  } catch (error) {
    console.error('Error during registration:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
})

generateKeyPairs().then(() => {
  generateToken()
  generateExpiredJWT()
  app.listen(port, () => {
    console.log(`Server started on http://localhost:${port}`);
  });
});

module.exports = app;