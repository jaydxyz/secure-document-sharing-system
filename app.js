//app.js
const express = require('express');
const bodyParser = require('body-parser');
const jwt = require('jsonwebtoken');
const jsonld = require('jsonld');
const CryptoJS = require('crypto-js');

const app = express();
app.use(bodyParser.json());
app.use(express.static('public'));

/*if using different port
const cors = require('cors');
app.use(cors());*/

// Basic route to test the server
app.get('/', (req, res) => {
  res.send('Secure Document Sharing System is running');
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));

// Mock user database (replace with a real database in production)
const users = [];

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


// Mock document storage (replace with a real database in production)
const documents = [];

// Document encryption function
function encryptDocument(text, secretKey) {
  return CryptoJS.AES.encrypt(text, secretKey).toString();
}

// Document decryption function
function decryptDocument(ciphertext, secretKey) {
  const bytes = CryptoJS.AES.decrypt(ciphertext, secretKey);
  return bytes.toString(CryptoJS.enc.Utf8);
}

// Upload document
app.post('/upload', authenticateToken, (req, res) => {
  const { content, title } = req.body;
  const encryptedContent = encryptDocument(content, JWT_SECRET);
  const docId = documents.length;
  documents.push({
    id: docId,
    title,
    content: encryptedContent,
    owner: req.user.username
  });
  res.json({ message: 'Document uploaded successfully', docId });
});

// Download document
app.get('/download/:id', authenticateToken, (req, res) => {
  const doc = documents[parseInt(req.params.id)];
  if (!doc || doc.owner !== req.user.username) {
    return res.status(404).json({ message: 'Document not found' });
  }
  const decryptedContent = decryptDocument(doc.content, JWT_SECRET);
  res.json({ title: doc.title, content: decryptedContent });
});

// Share document
app.post('/share/:id', authenticateToken, (req, res) => {
    const { username } = req.body;
    const docId = parseInt(req.params.id);
    const doc = documents[docId];
    if (!doc || doc.owner !== req.user.username) {
      return res.status(404).json({ message: 'Document not found' });
    }
    if (!doc.sharedWith) doc.sharedWith = [];
    doc.sharedWith.push(username);
    res.json({ message: 'Document shared successfully' });
  });
  
  // Update download endpoint to allow shared users
  app.get('/download/:id', authenticateToken, (req, res) => {
    const doc = documents[parseInt(req.params.id)];
    if (!doc || (doc.owner !== req.user.username && !doc.sharedWith?.includes(req.user.username))) {
      return res.status(404).json({ message: 'Document not found' });
    }
    const decryptedContent = decryptDocument(doc.content, JWT_SECRET);
    res.json({ title: doc.title, content: decryptedContent });
  });



/*Simplified version implemented above. 
Production version would need
Use a real database instead of in-memory arrays
Implement proper error handling and input validation
Use environment variables for sensitive information like JWT_SECRET
Implement more robust security measures
Add more comprehensive Verifiable Credentials handling
Implement proper digital signatures for credentials
*/