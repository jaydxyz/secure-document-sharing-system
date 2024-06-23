//app.js
const express = require('express');
const bodyParser = require('body-parser');
const jwt = require('jsonwebtoken');
const jsonld = require('jsonld');
const CryptoJS = require('crypto-js');
const { v4: uuidv4 } = require('uuid');

const app = express();
app.use(bodyParser.json());
app.use(express.static('public'));

// Basic route to test the server
app.get('/', (req, res) => {
  res.send('Secure Document Sharing System is running');
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));

// Mock user database (replace with a real database in production)
const users = [];

// Encrypted Data Vault storage
const userVaults = {};

// Secret key for JWT (use a strong, environment-specific secret in production)
const JWT_SECRET = 'your-secret-key';

// User registration
app.post('/register', (req, res) => {
  const { username, password } = req.body;
  if (users.find(u => u.username === username)) {
    return res.status(400).json({ message: 'Username already exists' });
  }
  const hashedPassword = CryptoJS.SHA256(password).toString();
  users.push({ username, password: hashedPassword });
  res.status(201).json({ message: 'User registered successfully' });
});

// User login
app.post('/login', (req, res) => {
  const { username, password } = req.body;
  const user = users.find(u => u.username === username);
  if (!user || user.password !== CryptoJS.SHA256(password).toString()) {
    return res.status(401).json({ message: 'Invalid credentials' });
  }
  const token = jwt.sign({ username }, JWT_SECRET, { expiresIn: '1h' });
  res.json({ token });
});

// Middleware to authenticate JWT
function authenticateToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  if (!token) return res.sendStatus(401);

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) return res.sendStatus(403);
    req.user = user;
    next();
  });
}

// Verifiable Credential issuance
app.post('/issue-credential', authenticateToken, (req, res) => {
  const { type, claim } = req.body;
  const credential = {
    "@context": [
      "https://www.w3.org/2018/credentials/v1",
      "https://www.w3.org/2018/credentials/examples/v1"
    ],
    "id": "http://example.edu/credentials/3732",
    "type": ["VerifiableCredential", type],
    "issuer": "https://example.edu/issuers/14",
    "issuanceDate": new Date().toISOString(),
    "credentialSubject": {
      "id": `did:example:${req.user.username}`,
      ...claim
    },
    "proof": {
      "type": "RsaSignature2018",
      "created": new Date().toISOString(),
      "proofPurpose": "assertionMethod",
      "verificationMethod": "https://example.edu/issuers/14#key-1",
      "jws": "eyJhbGciOiJSUzI1NiIsImI2NCI6ZmFsc2UsImNyaXQiOlsiYjY0Il19..TCYt5X"
    }
  };
  
  // In a real system, you would actually generate the proof here
  res.json(credential);
});

// Document encryption function
function encryptDocument(text, secretKey) {
  return CryptoJS.AES.encrypt(text, secretKey).toString();
}

// Document decryption function
function decryptDocument(ciphertext, secretKey) {
  const bytes = CryptoJS.AES.decrypt(ciphertext, secretKey);
  return bytes.toString(CryptoJS.enc.Utf8);
}

// Function to create a vault for a user
function createVault(username) {
  if (!userVaults[username]) {
    userVaults[username] = {
      documents: {},
      metadata: {}
    };
  }
}

// Function to add a document to a user's vault
function addToVault(username, docId, encryptedContent, encryptedMetadata) {
  createVault(username);
  userVaults[username].documents[docId] = encryptedContent;
  userVaults[username].metadata[docId] = encryptedMetadata;
}

// Upload document
app.post('/upload', authenticateToken, (req, res) => {
  const { content, title, metadata } = req.body;
  const encryptedContent = encryptDocument(content, JWT_SECRET);
  const encryptedMetadata = encryptDocument(JSON.stringify({title, ...metadata}), JWT_SECRET);
  const docId = uuidv4();
  addToVault(req.user.username, docId, encryptedContent, encryptedMetadata);
  res.json({ message: 'Document uploaded successfully', docId });
});

// Download document
app.get('/download/:id', authenticateToken, (req, res) => {
  const { username } = req.user;
  const docId = req.params.id;
  
  if (!userVaults[username] || !userVaults[username].documents[docId]) {
    return res.status(404).json({ message: 'Document not found' });
  }

  const encryptedContent = userVaults[username].documents[docId];
  const encryptedMetadata = userVaults[username].metadata[docId];

  const content = decryptDocument(encryptedContent, JWT_SECRET);
  const metadata = JSON.parse(decryptDocument(encryptedMetadata, JWT_SECRET));

  res.json({ content, ...metadata });
});

// Function to share a document
function shareDocument(ownerUsername, docId, recipientUsername) {
  if (!userVaults[ownerUsername] || !userVaults[ownerUsername].documents[docId]) {
    throw new Error('Document not found');
  }

  createVault(recipientUsername);
  userVaults[recipientUsername].documents[docId] = userVaults[ownerUsername].documents[docId];
  userVaults[recipientUsername].metadata[docId] = userVaults[ownerUsername].metadata[docId];
}

// Share document
app.post('/share/:id', authenticateToken, (req, res) => {
  const { username } = req.body;
  const docId = req.params.id;
  
  try {
    shareDocument(req.user.username, docId, username);
    res.json({ message: 'Document shared successfully' });
  } catch (error) {
    res.status(400).json({ message: error.message });
  }
});

module.exports = app;



/*Simplified version implemented above. 
Production version would need
Use a real database instead of in-memory arrays
Implement proper error handling and input validation
Use environment variables for sensitive information like JWT_SECRET
Implement more robust security measures
Add more comprehensive Verifiable Credentials handling
Implement proper digital signatures for credentials
*/