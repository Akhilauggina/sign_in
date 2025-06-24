const express = require('express');
const { MongoClient, ServerApiVersion } = require('mongodb');
const bcrypt = require('bcryptjs'); // Import bcrypt for password hashing
const cors = require('cors');       // Import cors for handling cross-origin requests
require('dotenv').config();         // Load environment variables from .env file

// Initialize the Express application
const app = express();
const port = process.env.PORT || 3001; // Use port 3001 or specified environment port

// Middleware for CORS - Allows your frontend (e.g., on localhost:3000) to communicate with this backend
app.use(cors());

// Middleware to parse JSON request bodies
app.use(express.json());

// MongoDB Atlas connection URI from environment variables
// IMPORTANT: Replace <username>, <password>, <cluster-name>, and <databaseName> with your actual details.
const uri = process.env.MONGO_URI;

// Create a MongoClient with a MongoClientOptions object to set the Stable API version
const client = new MongoClient(uri, {
  serverApi: {
    version: ServerApiVersion.v1,
    strict: true,
    deprecationErrors: true,
  }
});

let db; // Variable to hold the database instance

/**
 * Function to connect to MongoDB Atlas.
 * This function attempts to establish a connection to the MongoDB cluster.
 */
async function connectToMongoDB() {
  try {
    // Connect the client to the server (optional starting in v4.7)
    await client.connect();
    // Send a ping to confirm a successful connection
    await client.db("admin").command({ ping: 1 });
    console.log("Successfully connected to MongoDB Atlas!");

    // Set the database instance using DB_NAME from .env or default to 'authdb'
    db = client.db(process.env.DB_NAME || "authdb");

  } catch (error) {
    console.error("Error connecting to MongoDB Atlas:", error);
    // Exit the process if connection fails to prevent further errors
    process.exit(1);
  }
}

// Immediately connect to MongoDB when the server starts
connectToMongoDB();

// Define a simple API route to check database connection status
app.get('/api/status', (req, res) => {
  if (db) {
    res.status(200).json({ message: 'Database connected and ready.', dbName: db.databaseName });
  } else {
    res.status(500).json({ message: 'Database not connected.' });
  }
});

// Example route for user registration (Sign Up)
app.post('/api/register', async (req, res) => {
  try {
    const { username, email, password } = req.body; // Get user data from request body

    // Basic validation
    if (!username || !email || !password) {
      return res.status(400).json({ message: 'All fields are required.' });
    }

    // Access the 'users' collection (it will be created if it doesn't exist)
    const usersCollection = db.collection('users');

    // Check if user already exists
    const existingUser = await usersCollection.findOne({ username: username });
    if (existingUser) {
      return res.status(409).json({ message: 'Username already exists.' });
    }

    // Hash the password before saving it to the database
    // The second argument (10) is the number of salt rounds,
    // which determines how much processing time it will take to hash the password.
    // A higher number means more secure, but slower hashing. 10 is a good default.
    const hashedPassword = await bcrypt.hash(password, 10);

    // Insert the new user with the hashed password
    const result = await usersCollection.insertOne({ username, email, password: hashedPassword });

    res.status(201).json({ message: 'User registered successfully!', userId: result.insertedId });

  } catch (error) {
    console.error('Error during registration:', error);
    res.status(500).json({ message: 'Server error during registration.' });
  }
});

// Example route for user login
app.post('/api/login', async (req, res) => {
  try {
    const { username, password } = req.body;

    // Basic validation
    if (!username || !password) {
      return res.status(400).json({ message: 'Username and password are required.' });
    }

    const usersCollection = db.collection('users');

    // Find the user by username
    const user = await usersCollection.findOne({ username: username });

    // Check if user exists
    if (!user) {
      return res.status(401).json({ message: 'Invalid username or password.' });
    }

    // Compare the provided plain-text password with the stored hashed password
    const isPasswordValid = await bcrypt.compare(password, user.password);

    if (isPasswordValid) {
      res.status(200).json({ message: 'Login successful!', user: { username: user.username, email: user.email } });
    } else {
      res.status(401).json({ message: 'Invalid username or password.' });
    }

  } catch (error) {
    console.error('Error during login:', error);
    res.status(500).json({ message: 'Server error during login.' });
  }
});


// Start the Express server
// app.listen(port, () => {
//   console.log(`Server running on http://localhost:${port}`);
//   console.log('API Endpoints:');
//   console.log(`- GET /api/status`);
//   console.log(`- POST /api/register`);
//   console.log(`- POST /api/login`);
// });

// Graceful shutdown
process.on('SIGINT', async () => {
  console.log('Closing MongoDB connection...');
  await client.close();
  console.log('MongoDB connection closed.');
  process.exit(0);
});

module.exports = app;