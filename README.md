# Secure Document Sharing System

## Overview

This project implements a basic Secure Document Sharing System using Node.js and Express. It demonstrates the use of Verifiable Credentials, an Encrypted Data Vault, and JSON-LD for secure document management and sharing.

## Features

- User Authentication: Register and login functionality
- Verifiable Credentials: Basic implementation of credential issuance
- Encrypted Data Vault: Document encryption and secure storage
- Document Sharing: Ability to share documents with other users
- JSON-LD: Used in structuring credential data

## Technologies Used

- Node.js
- Express.js
- JSON Web Tokens (JWT) for authentication
- CryptoJS for document encryption
- JSON-LD for data structuring
- Tailwind CSS for styling

## Setup

1. Clone the repository
2. Install dependencies:
   ```
   npm install
   ```
3. Start the server:
   ```
   npm run dev
   ```

## API Endpoints

- POST `/register`: Register a new user
- POST `/login`: Authenticate a user and receive a JWT
- POST `/issue-credential`: Issue a Verifiable Credential
- POST `/upload`: Upload and encrypt a document
- GET `/download/:id`: Download and decrypt a document
- POST `/share/:id`: Share a document with another user

## Frontend

A basic HTML/JavaScript frontend is provided in the `public` folder. To use it:

1. Ensure the Express server is running
2. Open `http://localhost:3000` in your web browser

## Security Considerations

This project is a demonstration and should not be used in production without significant security enhancements, including:

- Proper database integration
- Robust error handling and input validation
- Environment variable usage for sensitive information
- Implementation of proper digital signatures for Verifiable Credentials
- Enhanced encryption mechanisms for the data vault

## Future Enhancements

- Implement full Verifiable Credentials verification
- Expand JSON-LD usage for richer data representation
- Improve the user interface for a better user experience
- Add more robust document management features

## Contributing

Contributions to improve the project are welcome. Please follow the standard fork-and-pull request workflow.

## License

[MIT License](LICENSE)
