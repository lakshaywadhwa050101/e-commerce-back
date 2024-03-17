const express = require("express");
const sqlite3 = require("sqlite3").verbose();
const bcrypt = require("bcryptjs");
const cors = require("cors");
const app = express();
const PORT = process.env.PORT || 5000;
const jwt = require("jsonwebtoken"); 

// Connect to SQLite database
const db = new sqlite3.Database("./data.db", (err) => {
  if (err) {
    console.error("SQLite connection error:", err.message);
  } else {
    console.log("Connected to SQLite database");
  }
});

app.use(express.json());
app.use(cors());

const JWT_SECRET = "your_secret_key";

// Create users table if it doesn't exist
// db.run(`Delete from cart_items`);

const verifyToken = (req, res, next) => {
  const token = req.headers.authorization?.split(" ")[1];

  if (!token) {
    return res.status(401).json({ error: "Unauthorized: Missing token" });
  }

  jwt.verify(token, JWT_SECRET, (err, decodedToken) => {
    if (err) {
      return res.status(401).json({ error: "Unauthorized: Invalid token" });
    }

    // Attach the decoded user information to the request object
    req.user = decodedToken;
    next();
  });
};

// Create users table if it doesn't exist
db.run(`CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT,
  email TEXT UNIQUE,
  phone TEXT,
  password TEXT
)`);

// Signup endpoint
app.post("/signup", async (req, res) => {
  try {
    const { name, email, phone, password } = req.body;

    // Check if user already exists
    db.get("SELECT * FROM users WHERE email = ?", [email], (err, row) => {
      if (err) {
        console.error("SQLite error:", err.message);
        return res.status(500).json({ error: "Internal server error" });
      }

      if (row) {
        return res.status(400).json({ error: "User already exists" });
      }

      // Hash the password
      bcrypt.hash(password, 10, (hashErr, hashedPassword) => {
        if (hashErr) {
          console.error("Password hashing error:", hashErr.message);
          return res.status(500).json({ error: "Internal server error" });
        }

        // Insert new user into the database
        db.run(
          "INSERT INTO users (name, email, phone, password) VALUES (?, ?, ?, ?)",
          [name, email, phone, hashedPassword],
          (insertErr) => {
            if (insertErr) {
              console.error("SQLite error:", insertErr.message);
              return res.status(500).json({ error: "Internal server error" });
            }

            // Return success response
            res.status(201).json({ message: "User created successfully" });
          }
        );
      });
    });
  } catch (error) {
    console.error("Signup error:", error.message);
    res.status(500).json({ error: "Internal server error" });
  }
});

// Login endpoint
app.post("/login", async (req, res) => {
  try {
    const { email, password } = req.body;

    // Find user by email
    db.get(
      "SELECT * FROM users WHERE email = ?",
      [email],
      async (err, user) => {
        if (err) {
          console.error("SQLite error:", err.message);
          return res.status(500).json({ error: "Internal server error" });
        }

        if (!user) {
          return res.status(404).json({ error: "User not found" });
        }

        // Verify password
        const isPasswordValid = await bcrypt.compare(password, user.password);
        if (!isPasswordValid) {
          return res.status(401).json({ error: "Invalid credentials" });
        }

        const token = jwt.sign(
          { userId: user.id, email: user.email },
          JWT_SECRET,
          { expiresIn: "1h" } // Token expires in 1 hour
        );

        // Return success response
        res.json({
          message: "Login successful",
          token,
          user: {
            id: user.id,
            name: user.name,
            email: user.email,
            phone: user.phone,
          },
        });
      }
    );
  } catch (error) {
    console.error("Login error:", error.message);
    res.status(500).json({ error: "Internal server error" });
  }
});

// // Create products table if it doesn't exist
db.run(`CREATE TABLE IF NOT EXISTS products (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT,
  price REAL,
  category TEXT,
  imageLink TEXT
)`);

app.post("/getUserData", verifyToken, (req,res)=>{
  try {
    // Extract user ID from the decoded token payload
    const userId = req.user.userId;

    // Fetch user details from the database based on userId
    db.get("SELECT * FROM users WHERE id = ?", [userId], (err, user) => {
      if (err) {
        console.error("Database error:", err.message);
        return res.status(500).json({ error: "Internal server error" });
      }

      if (!user) {
        return res.status(404).json({ error: "User not found" });
      }

      // Remove sensitive information like password before sending response
      const userData = {
        id: user.id,
        name: user.name,
        email: user.email,
        phone: user.phone,
        // Include other user details as needed
      };

      // Respond with the user details
      res.json({ user: userData });
    });
  } catch (error) {
    console.error("Error fetching user data:", error.message);
    res.status(500).json({ error: "Internal server error" });
  }
})
// Create product endpoint
app.post("/products", (req, res) => {
  try {
    db.all("SELECT * FROM products", (err, rows) => {
      if (err) {
        console.error("SQLite query error:", err.message);
        return;
      }

      // Check if any products were retrieved
      if (!rows || rows.length === 0) {
        console.log("No products found");
        return;
      }

      res.json({ products: rows });
    });

  } catch (error) {
    console.error("Product creation error:", error.message);
    res.status(500).json({ error: "Internal server error" });
  }
});

app.post("/getProduct",(req, res) => {
  try {
    const { product_id } = req.body;

    // Fetch product details by product ID
    db.get("SELECT * FROM products WHERE id = ?", [product_id], (err, row) => {
      if (err) {
        console.error("SQLite query error:", err.message);
        return res.status(500).json({ error: "Internal server error" });
      }

      // Check if product was retrieved
      if (!row) {
        console.log("Product not found");
        return res.status(404).json({ error: "Product not found" });
      }
      res.json({ product: row });
    });
  } catch (error) {
    console.error("Error fetching product details:", error.message);
    res.status(500).json({ error: "Internal server error" });
  }
});

app.post("/addCartItem",(req, res) => {
  const { user_id, product_id } = req.body;
  // Check if entry exists for user_id and product_id
  db.get(
    "SELECT * FROM cart_items WHERE user_id = ? AND product_id = ?",
    [user_id, product_id],
    (err, row) => {
      if (err) {
        console.error("SQLite SELECT error:", err.message);
        res
          .status(500)
          .json({ error: "Failed to check cart for existing item" });
        return;
      }

      if (row) {
        // Entry already exists, update quantity
        const newQuantity = row.quantity + 1;
        db.run(
          "UPDATE cart_items SET quantity = ? WHERE user_id = ? AND product_id = ?",
          [newQuantity, user_id, product_id],
          function (err) {
            if (err) {
              console.error("SQLite UPDATE error:", err.message);
              res
                .status(500)
                .json({ error: "Failed to update item quantity in cart" });
            } else {
              console.log(
                "Updated item quantity in cart:",
                user_id,
                product_id,
                newQuantity
              );
              res
                .status(200)
                .json({
                  message: "Item quantity updated in cart successfully",
                  cart_item_id: row.id,
                });
            }
          }
        );
      } else {
        // Entry doesn't exist, insert new row
        db.run(
          "INSERT INTO cart_items (user_id, product_id, quantity) VALUES (?, ?, ?)",
          [user_id, product_id, 1],
          function (err) {
            if (err) {
              console.error("SQLite INSERT error:", err.message);
              res.status(500).json({ error: "Failed to add item to cart" });
            } else {
              console.log("Added item to cart:", user_id, product_id);
              res
                .status(200)
                .json({
                  message: "Item added to cart successfully",
                  cart_item_id: this.lastID,
                });
            }
          }
        );
      }
    }
  );
});

app.post("/removeCartItem", (req, res) => {
  const { user_id, product_id } = req.body;

  // Check if entry exists for user_id and product_id
  db.get(
    "SELECT * FROM cart_items WHERE user_id = ? AND product_id = ?",
    [user_id, product_id],
    (err, row) => {
      if (err) {
        console.error("SQLite SELECT error:", err.message);
        res
          .status(500)
          .json({ error: "Failed to check cart for existing item" });
        return;
      }

      if (row) {
        // Entry exists, check if quantity is greater than 1
        if (row.quantity > 1) {
          const newQuantity = row.quantity - 1;
          db.run(
            "UPDATE cart_items SET quantity = ? WHERE user_id = ? AND product_id = ?",
            [newQuantity, user_id, product_id],
            function (err) {
              if (err) {
                console.error("SQLite UPDATE error:", err.message);
                res
                  .status(500)
                  .json({ error: "Failed to update item quantity in cart" });
              } else {
                console.log(
                  "Reduced item quantity in cart:",
                  user_id,
                  product_id,
                  newQuantity
                );
                res.status(200).json({
                  message: "Item quantity reduced in cart successfully",
                  cart_item_id: row.id,
                });
              }
            }
          );
        } else {
          // Quantity is 1, remove the item from the cart
          db.run(
            "DELETE FROM cart_items WHERE user_id = ? AND product_id = ?",
            [user_id, product_id],
            function (err) {
              if (err) {
                console.error("SQLite DELETE error:", err.message);
                res
                  .status(500)
                  .json({ error: "Failed to remove item from cart" });
              } else {
                console.log("Removed item from cart:", user_id, product_id);
                res.status(200).json({
                  message: "Item removed from cart successfully",
                  cart_item_id: row.id,
                });
              }
            }
          );
        }
      } else {
        // Entry doesn't exist, return error
        res
          .status(404)
          .json({ error: "Item not found in the user's cart" });
      }
    }
  );
});


app.post("/getCart",   (req, res) => {
  try {
    const { user_id } = req.body;

    db.all(
      "SELECT * FROM cart_items where user_id = ?",
      [user_id],
      (err, rows) => {
        if (err) {
          console.error("SQLite query error:", err.message);
          return;
        }

        // Check if any products were retrieved
        if (!rows || rows.length === 0) {
          console.log("No products found");
          res.json({ products: [] }); 
          return;
        }
        res.json({ products: rows });
      }
    );
  } catch (error) {
    console.error("Getting Cart error:", error.message);
    res.status(500).json({ error: "Internal server error" });
  }
});

app.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}`);
});
