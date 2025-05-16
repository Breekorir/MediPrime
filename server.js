const express = require("express");
const path = require("path");
const mysql = require("mysql");
const session = require("express-session");
const bcrypt = require("bcrypt");

const app = express();
const PORT = 3000;

// DB connection
const db = mysql.createConnection({
  host: "localhost",
  user: "root",
  password: "",
  database: "mediprime_db",
});

// Session middleware — MUST come before routes
app.use(
  session({
    secret: "mediprime-secret",
    resave: false,
    saveUninitialized: false,
  })
);

// Make user available in all views
app.use((req, res, next) => {
  res.locals.user = req.session.user || null;
  next();
});

// Other middlewares
app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.use(express.static(path.join(__dirname, "public")));

// Set EJS as view engine
app.set("view engine", "ejs");
app.set("views", path.join(__dirname, "views"));


app.use(
  session({
    secret: "mediprime-secret",
    resave: false,
    saveUninitialized: false,
  })
);

// View engine
app.set("view engine", "ejs");
app.set("views", path.join(__dirname, "views"));

// ===== Routes ===== //

// Homepage
app.get("/", (req, res) => {
  res.render("home.ejs", { user: req.session.user || null });
});

// Signup Page
app.get("/signup", (req, res) => {
  res.render("signup.ejs");
});

// Login Page
app.get("/login", (req, res) => {
  res.render("login.ejs");
});

// Medicine search page
app.get("/findMedicine", (req, res) => {
  const search = req.query.q || "";

  db.query(
    "SELECT * FROM medicines WHERE name LIKE ?",
    ["%" + search + "%"],
    (err, results) => {
      if (err) return res.status(500).send("Database error");
      
      res.render("findMedicine", {
        medicines: results,
        query: search,
        filters: { name: search, location: "", availability: "" } // Add this line
      });
    }
  );

})
// Dashboard (admin and user)
app.get("/dashboard", (req, res) => {
  if (!req.session.user) return res.redirect("/login");

  db.query("SELECT * FROM medicines WHERE pharmacy_id = ?", [req.session.user.id], (err, results) => {
    if (err) return res.status(500).send("Error loading medicines");

    if (req.session.user.role === 'admin') {
      db.query("SELECT COUNT(*) AS medCount FROM medicines", (err, meds) => {
        if (err) return res.status(500).send("Error loading dashboard");

        res.render("dashboard.ejs", {
          medCount: meds[0].medCount,
          reportCount: 0,
          user: req.session.user,
          medicines: results
        });
      });
    } else {
      res.render("dashboard.ejs", {
        user: req.session.user,
        medicines: results
      });
    }
  });
});


// Admin redirect (optional)
app.get("/admin", (req, res) => {
  res.redirect("/admin");
});// Edit medicine (POST)
app.post("/admin/medicines/:id/edit", (req, res) => {
  if (!req.session.user || req.session.user.role !== "admin") {
    return res.status(403).send("Access denied");
  }

  const { id } = req.params;
  const { name, location, availability } = req.body;

  db.query(
    "UPDATE medicines SET name = ?, location = ?, availability = ? WHERE id = ?",
    [name, location, availability, id],
    (err) => {
      if (err) return res.status(500).send("Failed to update medicine");
      res.redirect("/admin/medicines");
    }
  );
});

// Delete medicine (GET)
app.get("/admin/medicines/:id/delete", (req, res) => {
  if (!req.session.user || req.session.user.role !== "admin") {
    return res.status(403).send("Access denied");
  }

  const { id } = req.params;
  db.query("DELETE FROM medicines WHERE id = ?", [id], (err) => {
    if (err) return res.status(500).send("Failed to delete medicine");
    res.redirect("/admin/medicines");
  });
});

// Admin medicine list
app.get("/admin/medicines", (req, res) => {
if (!req.session.user || (req.session.user.role !== "admin" && req.session.user.role !== "user")) {
    return res.status(403).send("Access denied");
  }

  db.query("SELECT * FROM medicines", (err, results) => {
    if (err) return res.status(500).send("Error loading medicines");

    res.render("admin_medicines.ejs", {
      user: req.session.user,
      medicines: results
    });
  });
});
app.get("/medicines/filter", (req, res) => {
  const { name, location, availability, pharmacy } = req.query;

  let query = `
    SELECT * FROM medicines
    WHERE 1=1
  `;
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
    if (err) return res.status(500).send("Database error");
    res.render("filtered_medicines.ejs", {
      user: req.session.user || null,
      medicines: results,
      filters: req.query
    });
  });
});


// Handle Signup 
app.post("/signup", (req, res) => {
  const { name, email, password, role } = req.body;
  const hashedPassword = bcrypt.hashSync(password, 10);

  if (role === "user") {
    db.query(
      "INSERT INTO users (username, email, password, role) VALUES (?, ?, ?, 'user')",
      [name, email, hashedPassword],
      (err) => {
        if (err) return res.status(500).send("User registration failed");
        res.redirect("/login");
      }
    );
  } else if (role === "pharmacy") {
    db.query(
      "INSERT INTO pharmacies (name, email, password) VALUES (?, ?, ?)",
      [name, email, hashedPassword],
      (err) => {
        if (err) return res.status(500).send("Pharmacy registration failed");
        res.redirect("/login");
      }
    );
  } else {
    res.status(400).send("Invalid role");
  }
});

// Handle Login
app.post("/login", (req, res) => {
  const { email, password, role } = req.body;

  if (role === "user") {
    db.query("SELECT * FROM users WHERE email = ?", [email], (err, results) => {
      if (err || results.length === 0) return res.status(401).send("Invalid credentials");
      const user = results[0];
      if (bcrypt.compareSync(password, user.password)) {
        req.session.user = user;
        res.redirect("/dashboard");
      } else {
        res.status(401).send("Invalid password");
      }
    });
  } else if (role === "pharmacy") {
    db.query("SELECT * FROM pharmacies WHERE email = ?", [email], (err, results) => {
      if (err || results.length === 0) return res.status(401).send("Invalid credentials");
      const pharmacy = results[0];
      if (bcrypt.compareSync(password, pharmacy.password)) {
        req.session.pharmacy = pharmacy;
        res.redirect("/pharmacy/dashboard");
      } else {
        res.status(401).send("Invalid password");
      }
    });
  } else {
    res.status(400).send("Invalid role");
  }
});

app.get("/pharmacy/dashboard", (req, res) => {
  if (!req.session.pharmacy) return res.redirect("/login");

  db.query(
    "SELECT * FROM medicines WHERE pharmacy_id = ?",
    [req.session.pharmacy.id],
    (err, results) => {
      if (err) return res.status(500).send("DB error");
      res.render("pharmacy_dashboard.ejs", {
        pharmacy: req.session.pharmacy,
        medicines: results,
      });
    }
  );
});
// Add medicine
app.post("/pharmacy/medicines/add", (req, res) => {
  const { name, location, availability } = req.body;
  const pharmacyId = req.session.pharmacy.id;

  db.query(
    "INSERT INTO medicines (name, location, availability, pharmacy_id, pharmacy_name) VALUES (?, ?, ?, ?, ?)",
    [name, location, availability, pharmacyId, req.session.pharmacy.name],
    (err) => {
      if (err) return res.status(500).send("Failed to add");
      res.redirect("/pharmacy/dashboard");
    }
  );
});

// Edit medicine
app.post("/pharmacy/medicines/:id/edit", (req, res) => {
  const { id } = req.params;
  const { name, location, availability } = req.body;

  db.query(
    "UPDATE medicines SET name = ?, location = ?, availability = ? WHERE id = ? AND pharmacy_id = ?",
    [name, location, availability, id, req.session.pharmacy.id],
    (err) => {
      if (err) return res.status(500).send("Update failed");
      res.redirect("/pharmacy/dashboard");
    }
  );
});

// Delete medicine
app.get("/pharmacy/medicines/:id/delete", (req, res) => {
  const { id } = req.params;

  db.query(
    "DELETE FROM medicines WHERE id = ? AND pharmacy_id = ?",
    [id, req.session.pharmacy.id],
    (err) => {
      if (err) return res.status(500).send("Delete failed");
      res.redirect("/pharmacy/dashboard");
    }
  );
});

// Logout
app.get("/logout", (req, res) => {
  req.session.destroy(() => {
    res.redirect("/");
  });
});
app.get("/pharmacy/medicines/new", (req, res) => {
  if (!req.session.pharmacy) return res.redirect("/login");

  res.render("pharmacy_add_medicine.ejs", { pharmacy: req.session.pharmacy });
});

app.post("/pharmacy/medicines/new", (req, res) => {
  const { name, location, availability } = req.body;
  const pharmacyId = req.session.pharmacy.id;

  db.query(
    "INSERT INTO medicines (name, location, availability, pharmacy_id) VALUES (?, ?, ?, ?)",
    [name, location, availability, pharmacyId],
    (err) => {
      if (err) return res.status(500).send("Failed to add medicine");
      res.redirect("/pharmacy/dashboard");
    }
  );
});
app.get("/pharmacy/medicines/:id/edit", (req, res) => {
  const { id } = req.params;
  if (!req.session.pharmacy) return res.redirect("/login");

  db.query("SELECT * FROM medicines WHERE id = ? AND pharmacy_id = ?", [id, req.session.pharmacy.id], (err, results) => {
    if (err || results.length === 0) return res.status(404).send("Medicine not found");

    res.render("pharmacy_edit_medicine.ejs", { medicine: results[0] });
  });
});

app.post("/pharmacy/medicines/:id/edit", (req, res) => {
  const { id } = req.params;
  const { name, location, availability } = req.body;const winston = require('winston');

const logger = winston.createLogger({
  level: 'info',
  format: winston.format.json(),
  transports: [
    new winston.transports.File({ filename: 'error.log', level: 'error' }),
    new winston.transports.File({ filename: 'combined.log' }),
  ],
});

// Add this line at the top of the file

// ...

// Add logs to the routes
app.get("/", (req, res) => {
  logger.info('GET /');
  res.render("home.ejs", { user: req.session.user || null });
});

app.get("/signup", (req, res) => {
  logger.info('GET /signup');
  res.render("signup.ejs");
});

app.get("/login", (req, res) => {
  logger.info('GET /login');
  res.render("login.ejs");
});

// ...

app.post("/signup", (req, res) => {
  logger.info('POST /signup');
  const { name, email, password, role } = req.body;
  const hashedPassword = bcrypt.hashSync(password, 10);

  if (role === "user") {
    db.query(
      "INSERT INTO users (username, email, password, role) VALUES (?, ?, ?, 'user')",
      [name, email, hashedPassword],
      (err) => {
        if (err) {
          logger.error('Error signing up user', err);
          return res.status(500).send("User registration failed");
        }
        logger.info('User signed up successfully');
        res.redirect("/login");
      }
    );
  } else if (role === "pharmacy") {
    db.query(
      "INSERT INTO pharmacies (name, email, password) VALUES (?, ?, ?)",
      [name, email, hashedPassword],
      (err) => {
        if (err) {
          logger.error('Error signing up pharmacy', err);
          return res.status(500).send("Pharmacy registration failed");
        }
        logger.info('Pharmacy signed up successfully');
        res.redirect("/login");
      }
    );
  } else {
    logger.error('Invalid role');
    res.status(400).send("Invalid role");
  }
});

// ...

app.post("/login", (req, res) => {
  logger.info('POST /login');
  const { email, password, role } = req.body;

  if (role === "user") {
    db.query("SELECT * FROM users WHERE email = ?", [email], (err, results) => {
      if (err || results.length === 0) {
        logger.error('Invalid credentials');
        return res.status(401).send("Invalid credentials");
      }
      const user = results[0];
      if (bcrypt.compareSync(password, user.password)) {
        logger.info('User logged in successfully');
        req.session.user = user;
        res.redirect("/dashboard");
      } else {
        logger.error('Invalid password');
        res.status(401).send("Invalid password");
      }
    });
  } else if (role === "pharmacy") {
    db.query("SELECT * FROM pharmacies WHERE email = ?", [email], (err, results) => {
      if (err || results.length === 0) {
        logger.error('Invalid credentials');
        return res.status(401).send("Invalid credentials");
      }
      const pharmacy = results[0];
      if (bcrypt.compareSync(password, pharmacy.password)) {
        logger.info('Pharmacy logged in successfully');
        req.session.pharmacy = pharmacy;
        res.redirect("/pharmacy/dashboard");
      } else {
        logger.error('Invalid password');
        res.status(401).send("Invalid password");
      }
    });
  } else {
    logger.error('Invalid role');
    res.status(400).send("Invalid role");
  }
});

// ...

app.get("/logout", (req, res) => {
  logger.info('GET /logout');
  req.session.destroy(() => {
    logger.info('Session destroyed');
    res.redirect("/");
  });
});

  db.query(
    "UPDATE medicines SET name = ?, location = ?, availability = ? WHERE id = ? AND pharmacy_id = ?",
    [name, location, availability, id, req.session.pharmacy.id],
    (err) => {
      if (err) return res.status(500).send("Failed to update medicine");
      res.redirect("/pharmacy/dashboard");
    }
  );
});
app.get("/pharmacy/medicines/:id/delete", (req, res) => {
  const { id } = req.params;
  if (!req.session.pharmacy) return res.redirect("/login");

  db.query("DELETE FROM medicines WHERE id = ? AND pharmacy_id = ?", [id, req.session.pharmacy.id], (err) => {
    if (err) return res.status(500).send("Failed to delete medicine");
    res.redirect("/pharmacy/dashboard");
  });
});

// Server
app.listen(PORT, () => {
  console.log(`MediPrime running at http://localhost:${PORT}`);
});
