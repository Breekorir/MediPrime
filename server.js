require("dotenv").config(); // Load environment variables first

const express = require("express");
const path = require("path");
const mysql = require("mysql2/promise"); // Use mysql2 for promise support
const session = require("express-session");
const bcrypt = require("bcrypt");
const winston = require("winston");
const { body, validationResult } = require("express-validator"); // For input validation

const app = express();
const PORT = process.env.PORT || 3000; // Use port from env or default to 3000

// --- Constants for Roles ---
const ROLES = {
  ADMIN: 'admin',
  USER: 'user',
  PHARMACY: 'pharmacy'
};

// --- Logger setup ---
const logger = winston.createLogger({
  level: "info",
  format: winston.format.combine(
    winston.format.timestamp({ format: 'YYYY-MM-DDTHH:mm:ss.SSSZ' }),
    winston.format.json()
  ),
  transports: [
    new winston.transports.File({ filename: "error.log", level: "error" }),
    new winston.transports.File({ filename: "combined.log" }),
    new winston.transports.Console({ // Also log to console for development
      format: winston.format.combine(winston.format.colorize(), winston.format.simple())
    })
  ],
});

// --- Database Connection ---
let db; // Declared here, but initialized in startServer

async function initDb() {
  try {
    const connection = await mysql.createConnection({
      host: process.env.DB_HOST || "localhost",
      user: process.env.DB_USER || "root",
      password: process.env.DB_PASSWORD || "",
      database: process.env.DB_DATABASE || "mediprime_db",
    });
    logger.info("Database connected successfully");
    return connection;
  } catch (err) {
    logger.error("Database connection failed", err);
    throw err; // Re-throw to be caught by startServer
  }
}

// --- Middleware setup ---
app.use(
  session({
    secret: process.env.SESSION_SECRET, // Use environment variable for secret
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

// --- Auth Middleware ---
const isAuthenticated = (req, res, next) => {
  if (!req.session.user) {
    logger.warn(`Unauthorized access attempt to ${req.originalUrl}`);
    return res.redirect("/login");
  }
  next();
};

const authorizeRole = (roles = []) => {
  if (typeof roles === 'string') {
    roles = [roles]; // Ensure roles is an array
  }

  return (req, res, next) => {
    if (!req.session.user) {
      logger.warn(`Unauthorized access: No user session for ${req.originalUrl}`);
      return res.redirect("/login");
    }

    if (roles.length && !roles.includes(req.session.user.role)) {
      logger.warn(`Access denied for user '${req.session.user.email}' (role: ${req.session.user.role}) to ${req.originalUrl}`);
      return res.status(403).render("403.ejs", { user: res.locals.user, message: "Access Denied: You do not have permission to view this page." });
    }
    next();
  };
};

// ===== Routes =====

// Homepage
app.get("/", (req, res) => {
  logger.info("GET /");
  res.render("landing.ejs");
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
app.get("/pharmacy_add_medicine", isAuthenticated, authorizeRole(ROLES.PHARMACY), (req, res) => {
  logger.info("GET /pharmacy_add_medicine");
  res.render("pharmacy_add_medicine");
});

// Pharmacy edit medicines page
app.get("/pharmacy_edit_medicines", isAuthenticated, authorizeRole(ROLES.PHARMACY), async (req, res) => {
  logger.info("GET /pharmacy_edit_medicines");
  try {
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

// Medicine search page with grouping by category (This will serve as the ordering page)
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
    });
  } catch (err) {
    logger.error("Database error on /findMedicine", err);
    res.status(500).send("Database error");
  }
});

// Dashboard (admin, user, and pharmacy)
app.get("/dashboard", isAuthenticated, async (req, res) => {
  logger.info("GET /dashboard");

  try {
    if (req.session.user.role === ROLES.ADMIN) {
      const [meds] = await db.execute("SELECT COUNT(*) AS medCount FROM medicines");
      const [users] = await db.execute("SELECT COUNT(*) AS userCount FROM users WHERE role = 'user'");
      const [pharmacies] = await db.execute("SELECT COUNT(*) AS pharmacyCount FROM pharmacies");
      // Re-added order count for admin dashboard
      const [orders] = await db.execute("SELECT COUNT(*) AS orderCount FROM orders");
      const [allMedicines] = await db.execute("SELECT * FROM medicines");

      res.render("dashboard.ejs", {
        medCount: meds[0].medCount,
        userCount: users[0].userCount,
        pharmacyCount: pharmacies[0].pharmacyCount,
        orderCount: orders[0].orderCount, // Re-added
        medicines: allMedicines,
      });
    } else if (req.session.user.role === ROLES.PHARMACY) {
      return res.redirect("/pharmacy/dashboard");
    } else { // Regular user
      return res.redirect("/findMedicine"); // User's dashboard is findMedicine
    }
  } catch (err) {
    logger.error("Error loading dashboard", err);
    res.status(500).send("Error loading dashboard");
  }
});

// --- Order-related routes (Re-added) ---

// Order page (for regular users to view their orders)
// Order page (for regular users to view their orders)
app.get("/orders", isAuthenticated, authorizeRole(ROLES.USER), async (req, res) => {
  const userId = req.session.user.id;
  logger.info(`Accessing /orders with userId: ${userId}`);

  try {
    const query = `
      SELECT o.id, o.quantity, o.status, o.created_at,
             m.name AS medicine_name, m.category AS medicine_category, -- Added medicine category
             p.name AS pharmacy_name, p.address AS pharmacy_address, p.email AS pharmacy_email, p.phone AS pharmacy_phone -- Added pharmacy address and phone
      FROM orders o
      JOIN medicines m ON o.medicine_id = m.id
      JOIN pharmacies p ON m.pharmacy_id = p.id
      WHERE o.user_id = ?
      ORDER BY o.created_at DESC
    `;
    const [orders] = await db.execute(query, [userId]);
    logger.info("Rendering user_orders with orders found.");
    res.render("user_orders", { orders });
  } catch (err) {
    logger.error("Database error in /orders route", err);
    res.status(500).send("Internal Server Error");
  }
});

// Redirect /order/user_orders to /orders (kept for backward compatibility if links exist)
app.get("/order/user_orders", (req, res) => {
  logger.info("Redirecting /order/user_orders to /orders");
  res.redirect("/orders");
});

// Place an order (POST)
app.post("/user_orders", isAuthenticated, [ // Removed authorizeRole(ROLES.USER) here, as any logged-in user can place order
  body('medicine_id').isInt({ gt: 0 }).withMessage('Invalid medicine ID.'),
  body('quantity').isInt({ gt: 0 }).withMessage('Quantity must be a positive integer.')
], async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    logger.warn(`Validation errors on POST /user_orders: ${JSON.stringify(errors.array())}`);
    return res.status(400).send(`Invalid order details: ${errors.array().map(e => e.msg).join(', ')}`);
  }

  const userId = req.session.user.id;
  const userRole = req.session.user.role; // Get user's role
  const { medicine_id, quantity } = req.body;

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
      `User ${userId} (role: ${userRole}) ordered medicine ${medicine_id} quantity ${quantity}`
    );

    // Dynamic redirection based on user role (Improvement)
    if (userRole === ROLES.ADMIN || userRole === ROLES.USER) {
        res.redirect("/dashboard"); // Admin and regular user go to dashboard (which redirects user to findMedicine)
    } else if (userRole === ROLES.PHARMACY) {
        res.redirect("/pharmacy/dashboard"); // Pharmacy goes to their dashboard
    } else {
        res.redirect("/"); // Fallback to homepage
    }

  } catch (err) {
    logger.error("Error processing order", err);
    res.status(500).send("Internal Server Error");
  }
});

// Pharmacy orders (for pharmacies to view orders for their medicines)
app.get("/pharmacy_orders", isAuthenticated, authorizeRole(ROLES.PHARMACY), async (req, res) => {
  const pharmacyId = req.session.user.id;

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
    res.render("pharmacy_orders", { orders });
  } catch (err) {
    logger.error("Database error in /pharmacy_orders", err);
    res.status(500).send("Internal Server Error");
  }
});

// Update pharmacy order status
app.post("/pharmacy_orders/update", isAuthenticated, authorizeRole(ROLES.PHARMACY), [
  body('order_id').isInt({ gt: 0 }).withMessage('Invalid order ID.'),
  body('new_status').isIn(['pending', 'completed', 'cancelled']).withMessage('Invalid status value.')
], async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    logger.warn(`Validation errors on POST /pharmacy_orders/update: ${JSON.stringify(errors.array())}`);
    return res.status(400).send(`Invalid update details: ${errors.array().map(e => e.msg).join(', ')}`);
  }

  const { order_id, new_status } = req.body;
  const user = req.session.user;

  try {
    // Verify that the order belongs to this pharmacy
    const [check] = await db.execute(
      `SELECT o.id FROM orders o
       JOIN medicines m ON o.medicine_id = m.id
       WHERE o.id = ? AND m.pharmacy_id = ?`,
      [order_id, user.id]
    );

    if (check.length === 0) {
      logger.warn(`Pharmacy ${user.id} tried to update order ${order_id} which doesn't belong to them.`);
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

// --- End Order-related routes ---


// Admin medicines list
app.get("/admin/medicines", isAuthenticated, authorizeRole(ROLES.ADMIN), async (req, res) => {
  logger.info("GET /admin/medicines");
  try {
    const [results] = await db.execute("SELECT * FROM medicines");
    res.render("admin_medicines.ejs", {
      medicines: results,
    });
  } catch (err) {
    logger.error("Error loading medicines for admin", err);
    res.status(500).send("Error loading medicines");
  }
});

// Admin edit medicine (POST)
app.post("/admin/medicines/:id/edit", isAuthenticated, authorizeRole(ROLES.ADMIN), [
  body('name').trim().notEmpty().withMessage('Medicine name is required.'),
  body('location').trim().notEmpty().withMessage('Location is required.'),
  body('availability').isInt({ min: 0 }).withMessage('Availability must be a non-negative integer.'),
  body('category').trim().notEmpty().withMessage('Category is required.')
], async (req, res) => {
  logger.info(`POST /admin/medicines/${req.params.id}/edit`);

  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    logger.warn(`Validation errors on POST /admin/medicines/${req.params.id}/edit: ${JSON.stringify(errors.array())}`);
    return res.status(400).send(`Invalid medicine details: ${errors.array().map(e => e.msg).join(', ')}`);
  }

  const { id } = req.params;
  const { name, location, availability, category } = req.body;

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

// Admin delete medicine (POST - changed from GET for security/RESTfulness)
app.post("/admin/medicines/:id/delete", isAuthenticated, authorizeRole(ROLES.ADMIN), async (req, res) => {
  logger.info(`POST /admin/medicines/${req.params.id}/delete`);

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
  const { name, location, availability, pharmacy, category } = req.query;

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
    if (!isNaN(parseInt(availability))) {
      query += " AND availability = ?";
      params.push(parseInt(availability));
    } else {
      logger.warn(`Invalid availability filter value: ${availability}`);
    }
  }
  if (pharmacy) {
    query += " AND pharmacy_name LIKE ?";
    params.push(`%${pharmacy}%`);
  }
  if (category) {
    query += " AND category LIKE ?";
    params.push(`%${category}%`);
  }

  try {
    const [results] = await db.execute(query, params);
    res.render("filtered_medicines.ejs", {
      medicines: results,
      filters: req.query,
    });
  } catch (err) {
    logger.error("Database error in /medicines/filter", err);
    res.status(500).send("Database error");
  }
});

// Signup handler
app.post("/signup", [
  body('name').trim().notEmpty().withMessage('Name is required.'),
  body('email').isEmail().withMessage('Valid email is required.').normalizeEmail(),
  body('password').isLength({ min: 6 }).withMessage('Password must be at least 6 characters long.'),
  body('role').isIn([ROLES.USER, ROLES.PHARMACY]).withMessage('Invalid role selected.')
], async (req, res) => {
  logger.info("POST /signup");
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    logger.warn(`Validation errors on POST /signup: ${JSON.stringify(errors.array())}`);
    return res.status(400).send(`Signup failed: ${errors.array().map(e => e.msg).join(', ')}`);
  }

  const { name, email, password, role } = req.body;

  try {
    const hashedPassword = await bcrypt.hash(password, 10);

    if (role === ROLES.USER) {
      await db.execute(
        "INSERT INTO users (username, email, password, role) VALUES (?, ?, ?, ?)",
        [name, email, hashedPassword, ROLES.USER]
      );
      logger.info(`User ${email} signed up successfully`);
      res.redirect("/login");
    } else if (role === ROLES.PHARMACY) {
      await db.execute(
        "INSERT INTO pharmacies (name, email, password) VALUES (?, ?, ?)",
        [name, email, hashedPassword]
      );
      logger.info(`Pharmacy ${email} signed up successfully`);
      res.redirect("/login");
    }
  } catch (err) {
    if (err.code === 'ER_DUP_ENTRY') {
      logger.warn(`Signup failed: Email ${email} already exists.`);
      return res.status(409).send("Email already registered. Please use a different email or log in.");
    }
    logger.error(`Error signing up ${role}`, err);
    res.status(500).send(`${role} registration failed due to server error.`);
  }
});

// Login handler
app.post("/login", [
  body('email').isEmail().withMessage('Valid email is required.').normalizeEmail(),
  body('password').notEmpty().withMessage('Password is required.'),
  body('role').isIn([ROLES.USER, ROLES.PHARMACY, ROLES.ADMIN]).withMessage('Invalid role selected.')
], async (req, res) => {
  logger.info("POST /login");
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    logger.warn(`Validation errors on POST /login: ${JSON.stringify(errors.array())}`);
    return res.status(400).send(`Login failed: ${errors.array().map(e => e.msg).join(', ')}`);
  }

  const { email, password, role } = req.body;

  try {
    let userTable, redirectTo;
    if (role === ROLES.USER || role === ROLES.ADMIN) { // Admin logs in through users table
      userTable = "users";
      redirectTo = "/dashboard";
    } else if (role === ROLES.PHARMACY) {
      userTable = "pharmacies";
      redirectTo = "/pharmacy/dashboard";
    } else {
      logger.error(`Login failed: Invalid role '${role}' (should be caught by validator)`);
      return res.status(400).send("Invalid role specified.");
    }

    const [results] = await db.execute(`SELECT * FROM ${userTable} WHERE email = ?`, [email]);

    if (results.length === 0) {
      logger.warn(`Login failed for ${role} ${email}: Invalid credentials (email not found)`);
      return res.status(401).send("Invalid credentials.");
    }

    const user = results[0];

    // Additional check for admin role from users table
    if (role === ROLES.ADMIN && user.role !== ROLES.ADMIN) {
        logger.warn(`Login failed: User ${email} tried to log in as ADMIN but has role ${user.role}`);
        return res.status(401).send("Invalid credentials or role.");
    }

    if (await bcrypt.compare(password, user.password)) {
      logger.info(`${role} ${email} logged in successfully`);
      req.session.user = {
        id: user.id,
        name: user.username || user.name, // 'username' for users, 'name' for pharmacies
        email: user.email,
        role: user.role || role // Use role from DB for users, or from form for pharmacies
      };
      res.redirect(redirectTo);
    } else {
      logger.warn(`Login failed for ${role} ${email}: Invalid password`);
      res.status(401).send("Invalid password.");
    }
  } catch (err) {
    logger.error("Error during login", err);
    res.status(500).send("Internal Server Error during login.");
  }
});

// Pharmacy dashboard
app.get("/pharmacy/dashboard", isAuthenticated, authorizeRole(ROLES.PHARMACY), async (req, res) => {
  logger.info("GET /pharmacy/dashboard");

  try {
    const [medicines] = await db.execute(
      "SELECT * FROM medicines WHERE pharmacy_id = ?",
      [req.session.user.id]
    );

    // Re-added order counts for pharmacy dashboard
    const [pendingOrders] = await db.execute(
      `SELECT COUNT(*) AS count FROM orders o JOIN medicines m ON o.medicine_id = m.id WHERE m.pharmacy_id = ? AND o.status = 'pending'`,
      [req.session.user.id]
    );
    const [totalOrders] = await db.execute(
      `SELECT COUNT(*) AS count FROM orders o JOIN medicines m ON o.medicine_id = m.id WHERE m.pharmacy_id = ?`,
      [req.session.user.id]
    );

    res.render("pharmacy_dashboard.ejs", {
      pharmacy: req.session.user,
      medicines: medicines,
      pendingOrderCount: pendingOrders[0].count, // Re-added
      totalOrderCount: totalOrders[0].count,   // Re-added
    });
  } catch (err) {
    logger.error("DB error on pharmacy dashboard", err);
    res.status(500).send("DB error loading pharmacy dashboard");
  }
});

// Add medicine (pharmacy)
app.post("/pharmacy_add_medicines", isAuthenticated, authorizeRole(ROLES.PHARMACY), [
  body('name').trim().notEmpty().withMessage('Medicine name is required.'),
  body('location').trim().notEmpty().withMessage('Location is required.'),
  body('availability').isInt({ min: 0 }).withMessage('Availability must be a non-negative integer.'),
  body('category').trim().notEmpty().withMessage('Category is required.')
], async (req, res) => {
  logger.info("POST /pharmacy_add_medicines");

  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    logger.warn(`Validation errors on POST /pharmacy_add_medicines: ${JSON.stringify(errors.array())}`);
    return res.status(400).send(`Failed to add medicine: ${errors.array().map(e => e.msg).join(', ')}`);
  }

  const { name, location, availability, category } = req.body;
  const pharmacyId = req.session.user.id;
  const pharmacyName = req.session.user.name;

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

// Pharmacy Delete Medicine (POST for security)
app.post("/pharmacy/medicines/:id/delete", isAuthenticated, authorizeRole(ROLES.PHARMACY), async (req, res) => {
  logger.info(`POST /pharmacy/medicines/${req.params.id}/delete`);

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

// Test POST route (for debugging) - kept for your utility
app.post("/testpost", (req, res) => {
  logger.info("Received POST /testpost with body: " + JSON.stringify(req.body));
  res.send("POST /testpost received");
});

// 404 handler
app.use((req, res) => {
  logger.warn(`404 Not Found: ${req.originalUrl}`);
  res.status(404).render("404.ejs"); // Render a 404 page if you have one
});

// Global error handler
app.use((err, req, res, next) => {
  logger.error("Unexpected error", err);
  // In production, avoid sending detailed error messages to the client
  res.status(500).render("500.ejs", { error: process.env.NODE_ENV === 'production' ? null : err.message });
});

// --- Start Server Function ---
async function startServer() {
  try {
    db = await initDb(); // Initialize the global db connection

    app.listen(PORT, () => {
      logger.info(`Server started on http://localhost:${PORT}`);
    });
  } catch (err) {
    logger.error("Failed to start server due to database connection error.", err);
    process.exit(1); // Exit if DB connection fails at startup
  }
}

startServer(); // Call the function to start the application
