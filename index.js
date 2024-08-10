import express from "express";
import { MongoClient } from "mongodb";
import "dotenv/config";
import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";

const app = express();

// Middleware for parsing JSON request bodies
app.use(express.json());

// enabling cors

app.use(cors("*"));

// eg: middleware for hashing passwords, etc.

//custom middleware for admin authentication

function authenticateAdminToken(req, res, next) {
  const token = req.headers["authorization"];

  if (token == null) return res.sendStatus(401);

  jwt.verify(token, process.env.ADMIN_SECRET, (err) => {
    if (err) return res.send("admin middleware error: " + err.message);    
    next();
  });
}

const PORT = process.env.PORT || 3000;

// Connection URL
const url = process.env.MONGO_URL;

const client = new MongoClient(url);

async function ConnectDB() {
  try {
    await client.connect();
    console.log("✔✔ Connected to the database ✔✔");
    return client;
  } catch (error) {
    if (error instanceof MongoServerError) {
      console.log(`Error worth logging: ${error}`); // special case for some reason
    }
    throw error; // still want to crash
  }
}

await ConnectDB();

// Database Name and collection setup
const dbName = "Users";
const db = client.db(dbName);
const collection = db.collection("users");

// home get method
app.get("/", function (req, res) {
  res.send("Hello World");
});

app.post("/signup", async (req, res) => {
  try {
    const { username, email, password, role } = req.body;
    const existingUser = await collection.findOne({ email });

    if (existingUser) {
      return res
        .status(400)
        .send("User already exists selecet another email id");
    }

    //hash

    const saltRounds = parseInt(process.env.SALT);

    const hashedPassword = bcrypt.hash(
      password,
      saltRounds,
      async (err, hash) => {
        if (err) throw err;

        const result = await collection.insertOne({
          username,
          email,
          password: hash,
          role,
        });

        res.status(201).send("Successfully registered");
      }
    );
  } catch (error) {
    console.log(error);
    res.send(error);
  }
});

app.post("/login", async (req, res) => {
  try {
    const { email, password } = req.body;

    const user = await collection.findOne({ email });

    if (!user) {
      return res.status(404).send("User not found");
    }

    const match = await bcrypt.compare(password, user.password);

    if (match) {
      const role = user.role;
      let token;

      console.log(user)

      switch (role) {
        case "admin":
          token = jwt.sign(
            {
              data: "admin data",
            },
            "adminSecret",
            { expiresIn: "1200s" }
          );

          break;

        case "user":
          token = jwt.sign(
            {
              data: "user data",
            },
            "userSecret",
            { expiresIn: "1200s" }
          );

          break;

        default:
          token="not applicable - in default case"
          break;
      }

      res.send({ msg: "Logged in successfully", token });
    } else {
      return res.status(401).send("Invalid credentials");
    }
  } catch (error) {
    console.log(error);
    res.send(error);
  }
});

app.get("/admin",authenticateAdminToken,async (req, res) => {
  try {

    //some admin data

    const adminData = "admin secific data";

    res.send(adminData);

    
  } catch (error) {
    console.log(error); 
    res.send(error); 
  }
});

app.get("/user", async (req, res) => {
  try {
    const { token } = req.body;

    jwt.verify(token, "userSecret", (err, decoded) => {
      res.send(decoded.data)
    });
  } catch (error) {
    console.log(error); 
    res.send(error); 
  }
});

//user routes

//general routes

//callback function to our app for feedback
app.listen(PORT, () => {
  console.log("Server running on port 3000 🎉🎉🎉");
});
