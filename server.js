const express = require("express");
const path = require("path");
const mysql = require("mysql2/promise"); // Use mysql2 for promise support
const session = require("express-session");
const bcrypt = require("bcrypt");
const winston = require("winston");

const app = express();
const PORT = 3000;

// Logger setup
const logger = winston.createLogger({
  level: "info",
  format: winston.format.combine(
    winston.format.timestamp(),
    winston.format.json()
  ),
  transports: [
    new winston.transports.File({ filename: "error.log", level: "error" }),
    new winston.transports.File({ filename: "combined.log" }),
  ],
});

// DB connection
async function initDb() {
  const db = await mysql.createConnection({
    host: "localhost",
    user: "root",
    password: "",
    database: "mediprime_db",
  });
  return db;
}

// Middleware setup
app.use(
  session({
    secret: "mediprime-secret", // Use a strong, unique secret in production
    resave: false,
    saveUninitialized: false,
    cookie: {
      secure: process.env.NODE_ENV === 'production', // Use secure cookies in production
      httpOnly: true, // Prevent client-side JS from accessing the cookie
      maxAge: 1000 * 60 * 60 * 24 // 24 hours
    }
  })
);

// Make user available in all views (consistent session variable)
app.use((req, res, next) => {
  res.locals.user = req.session.user || null;
  next();
});

app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.use(express.static(path.join(__dirname, "public")));

// Set EJS as view engine
app.set("view engine", "ejs");
app.set("views", path.join(__dirname, "views"));

// ===== Routes =====
let db; // Global DB connection
initDb()
  .then((connection) => {
    db = connection;
    logger.info("Database connected successfully");
  })
  .catch((err) => {
    logger.error("Database connection failed", err);
    process.exit(1); // Exit process if DB connection fails
  });

// Homepage
app.get("/", (req, res) => {
  logger.info("GET /");
  res.render("landing.ejs", { user: res.locals.user });
});

// Signup page
app.get("/signup", (req, res) => {
  logger.info("GET /signup");
  res.render("signup.ejs");
});

// Login page
app.get("/login", (req, res) => {
  logger.info("GET /login");
  res.render("login.ejs");
});

// Pharmacy add medicine page
app.get("/pharmacy_add_medicine", (req, res) => {
  logger.info("GET /pharmacy_add_medicine");
  // Check if user is logged in and has 'pharmacy' role
  if (!req.session.user || req.session.user.role !== "pharmacy") {
    logger.warn("Unauthorized access to /pharmacy_add_medicine");
    return res.redirect("/login");
  }
  res.render("pharmacy_add_medicine");
});

// Pharmacy edit medicines page
app.get("/pharmacy_edit_medicines", async (req, res) => {
  logger.info("GET /pharmacy_edit_medicines");
  // Check if user is logged in and has 'pharmacy' role
  if (!req.session.user || req.session.user.role !== "pharmacy") {
    logger.warn("Unauthorized access to /pharmacy_edit_medicines");
    return res.redirect("/login");
  }

  try {
    // Fetch medicines belonging to the logged-in pharmacy
    const [medicines] = await db.execute(
      "SELECT * FROM medicines WHERE pharmacy_id = ?",
      [req.session.user.id]
    );
    res.render("pharmacy_edit_medicine", { medicines });
  } catch (err) {
    logger.error("Error fetching medicines for pharmacy edit", err);
    res.status(500).send("Error loading medicines for editing");
  }
});

// Medicine search page with grouping by category
app.get("/findMedicine", async (req, res) => {
  logger.info("GET /findMedicine");
  const search = req.query.query || "";

  try {
    const [results] = await db.execute(
      "SELECT * FROM medicines WHERE name LIKE ? OR location LIKE ? OR category LIKE ?",
      [`%${search}%`, `%${search}%`, `%${search}%`]
    );

    const grouped = {};
    results.forEach((med) => {
      if (!grouped[med.category]) grouped[med.category] = [];
      grouped[med.category].push(med);
    });

    res.render("findMedicine", {
      query: search,
      grouped,
      user: res.locals.user, // Pass user for navigation/display
    });
  } catch (err) {
    logger.error("Database error on /findMedicine", err);
    res.status(500).send("Database error");
  }
});

// Dashboard (admin, user, and pharmacy)
app.get("/dashboard", async (req, res) => {
  logger.info("GET /dashboard");

  if (!req.session.user) {
    logger.warn("Unauthorized access to /dashboard");
    return res.redirect("/login");
  }

  try {
    if (req.session.user.role === "admin") {
      const [meds] = await db.execute("SELECT COUNT(*) AS medCount FROM medicines");
      const [users] = await db.execute("SELECT COUNT(*) AS userCount FROM users WHERE role = 'user'");
      const [pharmacies] = await db.execute("SELECT COUNT(*) AS pharmacyCount FROM pharmacies");
      const [orders] = await db.execute("SELECT COUNT(*) AS orderCount FROM orders");

      res.render("dashboard.ejs", {
        medCount: meds[0].medCount,
        userCount: users[0].userCount,
        pharmacyCount: pharmacies[0].pharmacyCount,
        orderCount: orders[0].orderCount,
        user: req.session.user,
      });
    } else if (req.session.user.role === "pharmacy") {
      // Pharmacy dashboard, redirect to /pharmacy/dashboard
      return res.redirect("/pharmacy/dashboard");
    } else { // Regular user
      // For a regular user, the dashboard might be the find medicine page or their orders
      // Redirecting to findMedicine for now
      return res.redirect("/findMedicine");
    }
  } catch (err) {
    logger.error("Error loading dashboard", err);
    res.status(500).send("Error loading dashboard");
  }
});

// Order page (for regular users to view their orders)
app.get("/orders", async (req, res) => {
  const userId = req.session.user?.id;
  logger.info(`Accessing /order with userId: ${userId}`);

  if (!userId || req.session.user.role !== 'user') { // Ensure it's a regular user
    logger.warn("Unauthorized access to /order or not a regular user");
    return res.redirect("/login");
  }

  try {
    const query = `
      SELECT o.id, o.quantity, o.status, o.created_at,
             m.name AS medicine_name, p.name AS pharmacy_name
      FROM orders o
      JOIN medicines m ON o.medicine_id = m.id
      JOIN pharmacies p ON m.pharmacy_id = p.id
      WHERE o.user_id = ?
      ORDER BY o.created_at DESC
    `;
    const [orders] = await db.execute(query, [userId]);
    logger.info("Rendering user_orders with orders:", orders);
    res.render("user_orders", { orders, user: req.session.user });
  } catch (err) {
    logger.error("Database error in /order route", err);
    res.status(500).send("Internal Server Error");
  }
});

// Redirect /order/user_orders to /order (kept for backward compatibility if links exist)
app.get("/order/user_orders", (req, res) => {
  logger.info("Redirecting /order/user_orders to /order");
  res.redirect("/order");
});

// Place an order (POST)
app.post("/user_orders", async (req, res) => {
  if (!req.session.user || req.session.user.role !== 'user') { // Ensure it's a regular user
    logger.warn("Unauthorized order attempt or not a regular user");
    return res.status(401).send("Please login as a user to place an order.");
  }

  const userId = req.session.user.id;
  const { medicine_id, quantity } = req.body;

  if (!medicine_id || !quantity || quantity <= 0) {
    return res.status(400).send("Invalid order details");
  }

  try {
    const [results] = await db.execute(
      "SELECT availability FROM medicines WHERE id = ?",
      [medicine_id]
    );

    if (results.length === 0) {
      return res.status(404).send("Medicine not found");
    }

    const available = results[0].availability;

    if (available < quantity) {
      return res
        .status(400)
        .send(
          `Requested quantity (${quantity}) not available. Only ${available} left.`
        );
    }

    await db.execute(
      "INSERT INTO orders (user_id, medicine_id, quantity) VALUES (?, ?, ?)",
      [userId, medicine_id, quantity]
    );

    const newAvailability = available - quantity;
    await db.execute(
      "UPDATE medicines SET availability = ? WHERE id = ?",
      [newAvailability, medicine_id]
    );

    logger.info(
      `User ${userId} ordered medicine ${medicine_id} quantity ${quantity}`
    );
    res.redirect("/orders"); // Corrected redirection
  } catch (err) {
    logger.error("Error processing order", err);
    res.status(500).send("Internal Server Error");
  }
});

// Pharmacy orders (for pharmacies to view orders for their medicines)
app.get("/pharmacy_orders", async (req, res) => {
  const pharmacyId = req.session.user?.id;
  const userRole = req.session.user?.role;

  if (!pharmacyId || userRole !== "pharmacy") {
    logger.warn("Unauthorized access to /pharmacy_orders");
    return res.status(403).send("Unauthorized");
  }

  try {
    const query = `
      SELECT o.id, o.quantity, o.status, o.created_at,
             m.name AS medicine_name, u.username AS buyer_name, u.email AS buyer_email
      FROM orders o
      JOIN medicines m ON o.medicine_id = m.id
      JOIN users u ON o.user_id = u.id
      WHERE m.pharmacy_id = ?
      ORDER BY o.created_at DESC
    `;
    const [orders] = await db.execute(query, [pharmacyId]);
    res.render("pharmacy_orders", { orders, user: req.session.user }); // Pass user for navigation/display
  } catch (err) {
    logger.error("Database error in /pharmacy_orders", err);
    res.status(500).send("Internal Server Error");
  }
});

// Update pharmacy order status
app.post("/pharmacy_orders/update", async (req, res) => {
  const { order_id, new_status } = req.body;
  const user = req.session.user;

  if (!user || user.role !== "pharmacy") {
    logger.warn("Unauthorized attempt to update order");
    return res.status(403).send("Unauthorized");
  }

  try {
    // Verify that the order belongs to this pharmacy
    const [check] = await db.execute(
      `SELECT o.id FROM orders o
       JOIN medicines m ON o.medicine_id = m.id
       WHERE o.id = ? AND m.pharmacy_id = ?`,
      [order_id, user.id]
    );

    if (check.length === 0) {
      return res.status(403).send("Order not found or not associated with your pharmacy.");
    }

    await db.execute(`UPDATE orders SET status = ? WHERE id = ?`, [
      new_status,
      order_id,
    ]);

    logger.info(`Order ${order_id} status updated to ${new_status} by pharmacy ${user.id}`);
    res.redirect("/pharmacy_orders");
  } catch (err) {
    logger.error("Error updating order status", err);
    res.status(500).send("Something went wrong");
  }
});

// Admin medicines list
app.get("/admin/medicines", async (req, res) => {
  logger.info("GET /admin/medicines");

  // Only allow admin access
  if (!req.session.user || req.session.user.role !== "admin") {
    logger.warn("Access denied to /admin/medicines");
    return res.status(403).send("Access denied");
  }

  try {
    const [results] = await db.execute("SELECT * FROM medicines");
    res.render("admin_medicines.ejs", {
      user: req.session.user,
      medicines: results,
    });
  } catch (err) {
    logger.error("Error loading medicines for admin", err);
    res.status(500).send("Error loading medicines");
  }
});

// Admin edit medicine (POST)
app.post("/admin/medicines/:id/edit", async (req, res) => {
  logger.info(`POST /admin/medicines/${req.params.id}/edit`);

  if (!req.session.user || req.session.user.role !== "admin") {
    logger.warn("Access denied to admin edit medicine");
    return res.status(403).send("Access denied");
  }

  const { id } = req.params;
  const { name, location, availability, category } = req.body; // Added category to update

  try {
    await db.execute(
      "UPDATE medicines SET name = ?, location = ?, availability = ?, category = ? WHERE id = ?",
      [name, location, availability, category, id]
    );
    logger.info(`Medicine ${id} updated by admin`);
    res.redirect("/admin/medicines");
  } catch (err) {
    logger.error("Failed to update medicine", err);
    res.status(500).send("Failed to update medicine");
  }
});

// Admin delete medicine (GET - consider changing to POST/DELETE for RESTfulness)
app.get("/admin/medicines/:id/delete", async (req, res) => {
  logger.info(`GET /admin/medicines/${req.params.id}/delete`);

  if (!req.session.user || req.session.user.role !== "admin") {
    logger.warn("Access denied to admin delete medicine");
    return res.status(403).send("Access denied");
  }

  const { id } = req.params;
  try {
    await db.execute("DELETE FROM medicines WHERE id = ?", [id]);
    logger.info(`Medicine ${id} deleted by admin`);
    res.redirect("/admin/medicines");
  } catch (err) {
    logger.error("Failed to delete medicine", err);
    res.status(500).send("Failed to delete medicine");
  }
});

// Medicine filter endpoint
app.get("/medicines/filter", async (req, res) => {
  logger.info("GET /medicines/filter");
  const { name, location, availability, pharmacy, category } = req.query; // Added category filter

  let query = `SELECT * FROM medicines WHERE 1=1`;
  let params = [];

  if (name) {
    query += " AND name LIKE ?";
    params.push(`%${name}%`);
  }
  if (location) {
    query += " AND location LIKE ?";
    params.push(`%${location}%`);
  }
  if (availability !== undefined && availability !== "") {
    query += " AND availability = ?";
    params.push(availability);
  }
  if (pharmacy) {
    query += " AND pharmacy_name LIKE ?";
    params.push(`%${pharmacy}%`);
  }
  if (category) { // Added category filter
    query += " AND category LIKE ?";
    params.push(`%${category}%`);
  }

  try {
    const [results] = await db.execute(query, params);
    res.render("filtered_medicines.ejs", {
      user: res.locals.user,
      medicines: results,
      filters: req.query,
    });
  } catch (err) {
    logger.error("Database error in /medicines/filter", err);
    res.status(500).send("Database error");
  }
});

// Signup handler
app.post("/signup", async (req, res) => {
  logger.info("POST /signup");
  const { name, email, password, role } = req.body;

  if (!name || !email || !password || !role) {
    return res.status(400).send("All fields are required for signup.");
  }

  try {
    const hashedPassword = await bcrypt.hash(password, 10); // Use await for bcrypt.hash

    if (role === "user") {
      await db.execute(
        "INSERT INTO users (username, email, password, role) VALUES (?, ?, ?, 'user')",
        [name, email, hashedPassword]
      );
      logger.info(`User ${email} signed up successfully`);
      res.redirect("/login");
    } else if (role === "pharmacy") {
      await db.execute(
        "INSERT INTO pharmacies (name, email, password) VALUES (?, ?, ?)",
        [name, email, hashedPassword]
      );
      logger.info(`Pharmacy ${email} signed up successfully`);
      res.redirect("/login");
    } else {
      logger.error("Invalid role during signup attempt");
      res.status(400).send("Invalid role specified.");
    }
  } catch (err) {
    // Check for duplicate email error
    if (err.code === 'ER_DUP_ENTRY') {
      logger.warn(`Signup failed: Email ${email} already exists.`);
      return res.status(409).send("Email already registered. Please use a different email or log in.");
    }
    logger.error(`Error signing up ${role}`, err);
    res.status(500).send(`${role} registration failed due to server error.`);
  }
});

// Login handler
app.post("/login", async (req, res) => {
  logger.info("POST /login");
  const { email, password, role } = req.body;

  if (!email || !password || !role) {
    return res.status(400).send("Email, password, and role are required for login.");
  }

  try {
    if (role === "user") {
      const [results] = await db.execute("SELECT * FROM users WHERE email = ?", [email]);
      if (results.length === 0) {
        logger.warn(`Login failed for user ${email}: Invalid credentials (email not found)`);
        return res.status(401).send("Invalid credentials.");
      }
      const user = results[0];
      if (await bcrypt.compare(password, user.password)) { // Use await for bcrypt.compare
        logger.info(`User ${email} logged in successfully`);
        req.session.user = { id: user.id, name: user.username, email: user.email, role: user.role };
        res.redirect("/dashboard");
      } else {
        logger.warn(`Login failed for user ${email}: Invalid password`);
        res.status(401).send("Invalid password.");
      }
    } else if (role === "pharmacy") {
      const [results] = await db.execute("SELECT * FROM pharmacies WHERE email = ?", [email]);
      if (results.length === 0) {
        logger.warn(`Login failed for pharmacy ${email}: Invalid credentials (email not found)`);
        return res.status(401).send("Invalid credentials.");
      }
      const pharmacy = results[0];
      if (await bcrypt.compare(password, pharmacy.password)) { // Use await for bcrypt.compare
        logger.info(`Pharmacy ${email} logged in successfully`);
        // Crucially, add the role to the session object for pharmacies
        req.session.user = { id: pharmacy.id, name: pharmacy.name, email: pharmacy.email, role: "pharmacy" };
        res.redirect("/pharmacy/dashboard");
      } else {
        logger.warn(`Login failed for pharmacy ${email}: Invalid password`);
        res.status(401).send("Invalid password.");
      }
    } else {
      logger.error(`Login failed: Invalid role '${role}'`);
      res.status(400).send("Invalid role specified.");
    }
  } catch (err) {
    logger.error("Error during login", err);
    res.status(500).send("Internal Server Error during login.");
  }
});

// Pharmacy dashboard
app.get("/pharmacy/dashboard", async (req, res) => {
  logger.info("GET /pharmacy/dashboard");

  if (!req.session.user || req.session.user.role !== "pharmacy") {
    logger.warn("Unauthorized access to pharmacy dashboard");
    return res.redirect("/login");
  }

  try {
    const [medicines] = await db.execute(
      "SELECT * FROM medicines WHERE pharmacy_id = ?",
      [req.session.user.id]
    );

    const [pendingOrders] = await db.execute(
      `SELECT COUNT(*) AS count FROM orders o JOIN medicines m ON o.medicine_id = m.id WHERE m.pharmacy_id = ? AND o.status = 'pending'`,
      [req.session.user.id]
    );

    const [totalOrders] = await db.execute(
      `SELECT COUNT(*) AS count FROM orders o JOIN medicines m ON o.medicine_id = m.id WHERE m.pharmacy_id = ?`,
      [req.session.user.id]
    );

    res.render("pharmacy_dashboard.ejs", {
      pharmacy: req.session.user, // Renamed to pharmacy for clarity in EJS
      medicines: medicines,
      pendingOrderCount: pendingOrders[0].count,
      totalOrderCount: totalOrders[0].count,
    });
  } catch (err) {
    logger.error("DB error on pharmacy dashboard", err);
    res.status(500).send("DB error loading pharmacy dashboard");
  }
});

// Add medicine (pharmacy)
app.post("/pharmacy_add_medicines", async (req, res) => {
  logger.info("POST /pharmacy_add_medicines");

  if (!req.session.user || req.session.user.role !== "pharmacy") {
    logger.warn("Unauthorized attempt to add medicine");
    return res.redirect("/login");
  }

  const { name, location, availability, category } = req.body; // Added category
  const pharmacyId = req.session.user.id;
  const pharmacyName = req.session.user.name;

  if (!name || !location || !availability || !category) {
    return res.status(400).send("All medicine fields are required.");
  }

  try {
    await db.execute(
      "INSERT INTO medicines (name, location, availability, pharmacy_id, pharmacy_name, category) VALUES (?, ?, ?, ?, ?, ?)",
      [name, location, availability, pharmacyId, pharmacyName, category]
    );
    logger.info(`Medicine '${name}' added by pharmacy ${pharmacyId}`);
    res.redirect("/pharmacy/dashboard");
  } catch (err) {
    logger.error("Failed to add medicine", err);
    res.status(500).send("Failed to add medicine");
  }
});
// Pharmacy Delete Medicine (ensure this is present in server.js)
app.post("/pharmacy/medicines/:id/delete", async (req, res) => {
  logger.info(`POST /pharmacy/medicines/${req.params.id}/delete`);

  // Ensure it's a pharmacy user and they own the medicine
  if (!req.session.user || req.session.user.role !== "pharmacy") {
    logger.warn("Access denied to pharmacy delete medicine");
    return res.status(403).send("Access denied");
  }

  const { id } = req.params; // Medicine ID

  try {
    // Verify the medicine belongs to this pharmacy before deleting
    const [check] = await db.execute(
      "SELECT id FROM medicines WHERE id = ? AND pharmacy_id = ?",
      [id, req.session.user.id]
    );

    if (check.length === 0) {
      logger.warn(`Pharmacy ${req.session.user.id} tried to delete medicine ${id} which doesn't belong to them.`);
      return res.status(403).send("You are not authorized to delete this medicine.");
    }

    await db.execute("DELETE FROM medicines WHERE id = ?", [id]);
    logger.info(`Medicine ${id} deleted by pharmacy ${req.session.user.id}`);
    res.redirect("/pharmacy_edit_medicines"); // Redirect back to the edit list
  } catch (err) {
    logger.error("Failed to delete medicine", err);
    res.status(500).send("Failed to delete medicine");
  }
});
// Logout route
app.get("/logout", (req, res) => {
  logger.info("GET /logout");
  req.session.destroy((err) => {
    if (err) {
      logger.error("Logout failed", err);
      return res.status(500).send("Logout failed");
    }
    res.clearCookie('connect.sid'); // Clear session cookie
    res.redirect("/");
  });
});

// Test POST route (for debugging)
app.post("/testpost", (req, res) => {
  logger.info("Received POST /testpost with body: " + JSON.stringify(req.body));
  res.send("POST /testpost received");
});

// 404 handler
app.use((req, res) => {
  logger.warn(`404 Not Found: ${req.originalUrl}`);
  res.status(404).render("404.ejs", { user: res.locals.user }); // Render a 404 page if you have one
});

// Global error handler
app.use((err, req, res, next) => {
  logger.error("Unexpected error", err);
  res.status(500).render("500.ejs", { user: res.locals.user }); // Render a 500 page if you have one
});

// Start server


app.listen(PORT, () => {
  logger.info(`Server started on http://localhost:${PORT}`);
});
