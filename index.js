const express = require("express");
const { Client } = require("pg");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const { config } = require("dotenv");

const app = express();
const port = 200;

// Load environment variables
config();

// Middleware
app.use(express.json());
app.use(require("cors")());

// Database client setup
const client = new Client({
  user: "ugxhfuub",
  host: "rain.db.elephantsql.com",
  database: "ugxhfuub",
  password: "fhfdspsOjX3WwjT0DizGc-iQ30_XXnC0",
  port: 5432,
});

client.connect(function (err) {
  if (err) throw err;
  console.log("Connected to the database!");
});

// Middleware to verify JWT token
function verifyToken(req, res, next) {
  const token = req.headers["authorization"];

  if (!token) {
    return res.status(403).json({ message: 'No token provided' });
  }

  const tokenParts = token.split(' ');

  if (tokenParts.length !== 2 || tokenParts[0] !== 'Bearer') {
    return res.status(403).json({ message: 'Invalid token format' });
  }

  const tokenValue = tokenParts[1];

  jwt.verify(tokenValue, "rudransh", (err, decoded) => {
    if (err) {
      return res.status(401).json({ message: 'Failed to authenticate token' });
    }

    if (decoded.role !== 'admin') {
      return res.status(403).json({ message: 'You are not authorized to access this resource' });
    }

    req.decoded = decoded;
    next();
  });
}

// Routes

// signup route
app.post("/api/signup", async (req, res) => {
  let { username, password, email, role } = req.body;
  username = username.trim().toLowerCase();

  try {
    const check = "SELECT * FROM users WHERE username = $1";
    const result = await client.query(check, [username]);
    console.log(result)

    if (result.rowCount > 0) {
      return res.status(200).send({
        message: "User already exists",
      });
    } else {
      const hashedPassword = await bcrypt.hash(password, 10);
      const query = `INSERT INTO users (username, email, password, role ) VALUES ($1, $2, $3, $4)`;
      const values = [username, email, hashedPassword, role];

      await client.query(query, values);
      res.status(200).send({
        status: "Admin Account successfully created",
        status_code: 200,
      });
    }
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: "Internal Server Error" });
  }
});

// login route
app.post("/api/login", async (req, res) => {
  let { username, password } = req.body;
  username = username = username.trim().toLowerCase();
  try {
    const userQuery = 'SELECT id, username, password, role FROM users WHERE username = $1';
    const { rows } = await client.query(userQuery, [username]);

    if (rows.length === 0) {
      return res.status(401).json({
        status: 'Incorrect username/password provided. Please retry',
        status_code: 401,
      });
    }

    const storedHashedPassword = rows[0].password;
    const passwordMatch = await bcrypt.compare(password, storedHashedPassword);

    if (passwordMatch) {
      const token = jwt.sign({ username, role: rows[0].role }, "rudransh", { expiresIn: '1h' });

      res.status(200).json({
        status: 'Login successful',
        status_code: 200,
        user_id: rows[0].id,
        access_token: token,
      });
    } else {
      res.status(401).json({
        status: 'Incorrect username/password provided. Please retry',
        status_code: 401,
      });
    }
  } catch (err) {
    console.error(err);
    res.status(500).json({
      status: 'Internal server error',
      status_code: 500,
    });
  }
});

// Admin-only route
app.post('/api/matches', verifyToken, (req, res) => {
  res.send("Hi admin!");
});

// Other routes for matches, match details, team members, and player statistics
// ...

// Helper routes
app.get("/api/all-data", (req, res) => {
  client.query("SELECT * FROM users", (err, result) => {
    if (err) {
      console.error("Error executing query", err);
      res.status(500).json({ error: "Internal Server Error" });
    } else {
      const rows = result.rows;
      res.json(rows); // Respond with the fetched data as JSON
    }
  });
});

app.get("/api/erase-data", async (req, res) => {
  try {
    const query = "TRUNCATE TABLE users RESTART IDENTITY";
    await client.query(query);
    res.send("All data deleted from the table.");
  } catch (error) {
    console.error("Error erasing data:", error);
    res.status(500).send("Internal Server Error");
  }
});

// Start the server
app.listen(port, () => {
  console.log(`Server is running on port ${port}`);
});
