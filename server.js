const express = require("express");
const path = require("path");
const mysql = require("mysql");
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
const db = mysql.createConnection({
  host: "localhost",
  user: "root",
  password: "",
  database: "mediprime_db",
});

// Middleware setup

// Session middleware — only once here
app.use(
  session({
    secret: "mediprime-secret",
    resave: false,
    saveUninitialized: false,
  })
);

// Make user available in all views
app.use((req, res, next) => {
  res.locals.user = req.session.user || req.session.pharmacy || null;
  next();
});

app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.use(express.static(path.join(__dirname, "public")));

// Set EJS as view engine
app.set("view engine", "ejs");
app.set("views", path.join(__dirname, "views"));

// ===== Routes =====

// Homepage
app.get("/", (req, res) => {
  logger.info("GET /");
  res.render("home.ejs", { user: res.locals.user });
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

// Medicine search page with grouping by category
app.get("/findMedicine", (req, res) => {
  logger.info("GET /findMedicine");
  const search = req.query.query || "";

  db.query(
    "SELECT * FROM medicines WHERE name LIKE ? OR location LIKE ? OR category LIKE ?",
    [`%${search}%`, `%${search}%`, `%${search}%`],
    (err, results) => {
      if (err) {
        logger.error("Database error on /findMedicine", err);
        return res.status(500).send("Database error");
      }

      const grouped = {};
      results.forEach((med) => {
        if (!grouped[med.category]) grouped[med.category] = [];
        grouped[med.category].push(med);
      });

      res.render("findMedicine", {
        query: search,
        grouped,
      });
    }
  );
});

// Dashboard (admin and user)
app.get("/dashboard", (req, res) => {
  logger.info("GET /dashboard");

  if (!req.session.user) {
    logger.warn("Unauthorized access to /dashboard");
    return res.redirect("/login");
  }

  db.query(
    "SELECT * FROM medicines WHERE pharmacy_id = ?",
    [req.session.user.id],
    (err, results) => {
      if (err) {
        logger.error("Error loading medicines on dashboard", err);
        return res.status(500).send("Error loading medicines");
      }

      if (req.session.user.role === "admin") {
        db.query("SELECT COUNT(*) AS medCount FROM medicines", (err, meds) => {
          if (err) {
            logger.error("Error loading dashboard medCount", err);
            return res.status(500).send("Error loading dashboard");
          }

          res.render("dashboard.ejs", {
            medCount: meds[0].medCount,
            reportCount: 0,
            user: req.session.user,
            medicines: results,
          });
        });
      } else {
        res.render("dashboard.ejs", {
          user: req.session.user,
          medicines: results,
        });
      }
    }
  );
});

// Admin medicines list
app.get("/admin/medicines", (req, res) => {
  logger.info("GET /admin/medicines");

  if (
    !req.session.user ||
    (req.session.user.role !== "admin" && req.session.user.role !== "user")
  ) {
    logger.warn("Access denied to /admin/medicines");
    return res.status(403).send("Access denied");
  }

  db.query("SELECT * FROM medicines", (err, results) => {
    if (err) {
      logger.error("Error loading medicines for admin", err);
      return res.status(500).send("Error loading medicines");
    }

    res.render("admin_medicines.ejs", {
      user: req.session.user,
      medicines: results,
    });
  });
});

// Admin edit medicine (POST)
app.post("/admin/medicines/:id/edit", (req, res) => {
  logger.info(`POST /admin/medicines/${req.params.id}/edit`);

  if (!req.session.user || req.session.user.role !== "admin") {
    logger.warn("Access denied to admin edit medicine");
    return res.status(403).send("Access denied");
  }

  const { id } = req.params;
  const { name, location, availability } = req.body;

  db.query(
    "UPDATE medicines SET name = ?, location = ?, availability = ? WHERE id = ?",
    [name, location, availability, id],
    (err) => {
      if (err) {
        logger.error("Failed to update medicine", err);
        return res.status(500).send("Failed to update medicine");
      }
      res.redirect("/admin/medicines");
    }
  );
});

// Admin delete medicine (GET)
app.get("/admin/medicines/:id/delete", (req, res) => {
  logger.info(`GET /admin/medicines/${req.params.id}/delete`);

  if (!req.session.user || req.session.user.role !== "admin") {
    logger.warn("Access denied to admin delete medicine");
    return res.status(403).send("Access denied");
  }

  const { id } = req.params;
  db.query("DELETE FROM medicines WHERE id = ?", [id], (err) => {
    if (err) {
      logger.error("Failed to delete medicine", err);
      return res.status(500).send("Failed to delete medicine");
    }
    res.redirect("/admin/medicines");
  });
});

// Medicine filter endpoint
app.get("/medicines/filter", (req, res) => {
  logger.info("GET /medicines/filter");
  const { name, location, availability, pharmacy } = req.query;

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

  db.query(query, params, (err, results) => {
    if (err) {
      logger.error("Database error in /medicines/filter", err);
      return res.status(500).send("Database error");
    }

    res.render("filtered_medicines.ejs", {
      user: res.locals.user,
      medicines: results,
      filters: req.query,
    });
  });
});

// Signup handler
app.post("/signup", (req, res) => {
  logger.info("POST /signup");
  const { name, email, password, role } = req.body;
  const hashedPassword = bcrypt.hashSync(password, 10);

  if (role === "user") {
    db.query(
      "INSERT INTO users (username, email, password, role) VALUES (?, ?, ?, 'user')",
      [name, email, hashedPassword],
      (err) => {
        if (err) {
          logger.error("Error signing up user", err);
          return res.status(500).send("User registration failed");
        }
        logger.info("User signed up successfully");
        res.redirect("/login");
      }
    );
  } else if (role === "pharmacy") {
    db.query(
      "INSERT INTO pharmacies (name, email, password) VALUES (?, ?, ?)",
      [name, email, hashedPassword],
      (err) => {
        if (err) {
          logger.error("Error signing up pharmacy", err);
          return res.status(500).send("Pharmacy registration failed");
        }
        logger.info("Pharmacy signed up successfully");
        res.redirect("/login");
      }
    );
  } else {
    logger.error("Invalid role during signup");
    res.status(400).send("Invalid role");
  }
});

// Login handler
app.post("/login", (req, res) => {
  logger.info("POST /login");
  const { email, password, role } = req.body;

  if (role === "user") {
    db.query("SELECT * FROM users WHERE email = ?", [email], (err, results) => {
      if (err || results.length === 0) {
        logger.error("Invalid credentials for user login");
        return res.status(401).send("Invalid credentials");
      }
      const user = results[0];
      if (bcrypt.compareSync(password, user.password)) {
        logger.info("User logged in successfully");
        req.session.user = user;
        res.redirect("/dashboard");
      } else {
        logger.error("Invalid password for user login");
        res.status(401).send("Invalid password");
      }
    });
  } else if (role === "pharmacy") {
    db.query(
      "SELECT * FROM pharmacies WHERE email = ?",
      [email],
      (err, results) => {
        if (err || results.length === 0) {
          logger.error("Invalid credentials for pharmacy login");
          return res.status(401).send("Invalid credentials");
        }
        const pharmacy = results[0];
        if (bcrypt.compareSync(password, pharmacy.password)) {
          logger.info("Pharmacy logged in successfully");
          req.session.pharmacy = pharmacy;
          res.redirect("/pharmacy/dashboard");
        } else {
          logger.error("Invalid password for pharmacy login");
          res.status(401).send("Invalid password");
        }
      }
    );
  } else {
    logger.error("Invalid role during login");
    res.status(400).send("Invalid role");
  }
});

// Pharmacy dashboard
app.get("/pharmacy/dashboard", (req, res) => {
  logger.info("GET /pharmacy/dashboard");

  if (!req.session.pharmacy) {
    logger.warn("Unauthorized access to pharmacy dashboard");
    return res.redirect("/login");
  }

  db.query(
    "SELECT * FROM medicines WHERE pharmacy_id = ?",
    [req.session.pharmacy.id],
    (err, results) => {
      if (err) {
        logger.error("DB error on pharmacy dashboard", err);
        return res.status(500).send("DB error");
      }
      res.render("pharmacy_dashboard.ejs", {
        pharmacy: req.session.pharmacy,
        medicines: results,
      });
    }
  );
});

// Add medicine (pharmacy)
app.post("/pharmacy_add_medicines", (req, res) => {
  logger.info("POST /pharmacy_add_medicines");

  if (!req.session.pharmacy) {
    logger.warn("Unauthorized attempt to add medicine");
    return res.redirect("/login");
  }

  const { name, location, availability } = req.body;
  const pharmacyId = req.session.pharmacy.id;

  db.query(
    "INSERT INTO medicines (name, location, availability, pharmacy_id, pharmacy_name) VALUES (?, ?, ?, ?, ?)",
    [name, location, availability, pharmacyId, req.session.pharmacy.name],
    (err) => {
      if (err) {
        logger.error("Failed to add medicine", err);
        return res.status(500).send("Failed to add medicine");
      }
      res.redirect("/pharmacy/dashboard");
    }
  );
});

// Logout route
app.get("/logout", (req, res) => {
  logger.info("GET /logout");
  req.session.destroy((err) => {
    if (err) {
      logger.error("Logout failed", err);
      return res.status(500).send("Logout failed");
    }
    res.redirect("/");
  });
});

// 404 handler
app.use((req, res) => {
  logger.warn(`404 Not Found: ${req.originalUrl}`);
  res.status(404).send("Page Not Found");
});

// Global error handler (optional)
app.use((err, req, res, next) => {
  logger.error("Unexpected error", err);
  res.status(500).send("Internal Server Error");
});
app.post("/order", (req, res) => {
  if (!req.session.user) {
    logger.warn("Unauthorized order attempt");
    return res.status(401).send("Please login to place an order.");
  }

  const userId = req.session.user.id;
  const { medicine_id, quantity } = req.body;

  if (!medicine_id || !quantity || quantity <= 0) {
    return res.status(400).send("Invalid order details");
  }

  // Check medicine availability first
  db.query(
    "SELECT availability FROM medicines WHERE id = ?",
    [medicine_id],
    (err, results) => {
      if (err) {
        logger.error("DB error checking medicine availability", err);
        return res.status(500).send("Internal Server Error");
      }

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

      // Insert order
      db.query(
        "INSERT INTO orders (user_id, medicine_id, quantity) VALUES (?, ?, ?)",
        [userId, medicine_id, quantity],
        (err2) => {
          if (err2) {
            logger.error("DB error inserting order", err2);
            return res.status(500).send("Internal Server Error");
          }

          // Update medicine availability
          const newAvailability = available - quantity;
          db.query(
            "UPDATE medicines SET availability = ? WHERE id = ?",
            [newAvailability, medicine_id],
            (err3) => {
              if (err3) {
                logger.error("DB error updating medicine availability", err3);
                return res.status(500).send("Internal Server Error");
              }

              logger.info(
                `User ${userId} ordered medicine ${medicine_id} quantity ${quantity}`
              );
              res.redirect("/orders");
            }
          );
        }
      );
    }
  );
});
app.get("/orders", (req, res) => {
  if (!req.session.user) {
    logger.warn("Unauthorized access to /orders");
    return res.redirect("/login");
  }

  const userId = req.session.user.id;

  const query = `
    SELECT o.id, o.quantity, o.status, o.order_date, m.name AS medicine_name
    FROM orders o
    JOIN medicines m ON o.medicine_id = m.id
    WHERE o.user_id = ?
    ORDER BY o.order_date DESC
  `;

  db.query(query, [userId], (err, results) => {
    if (err) {
      logger.error("DB error fetching user orders", err);
      return res.status(500).send("Internal Server Error");
    }
    res.render("orders.ejs", { orders: results, user: req.session.user });
  });
});

// Start server
app.listen(PORT, () => {
  logger.info(`Server started on http://localhost:${PORT}`);
});
