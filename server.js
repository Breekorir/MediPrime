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
  database: "mediprime_db"
});
//session secret

// Middleware
app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.use(express.static(path.join(__dirname, "public")));

app.use(
  session({
    secret: "mediprime-secret",
    resave: false,
    saveUninitialized: false,
  })
);

// Set EJS as the view engine
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
//findmedicine Page
app.get("/findMedicine", (req, res) => {
  const search = req.query.q || "";
  db.query(
    "SELECT * FROM medicines WHERE name LIKE ?",
    ["%" + search + "%"],
    (err, results) => {
      if (err) return res.status(500).send("Database error");
      res.render("findMedicine", { medicines: results, query: search });
    }
  )
})

// Dashboard (requires login)
app.get("/dashboard", (req, res) => {
  if (!req.session.user) return res.redirect("/login");
  res.render("dashboard.ejs", { user: req.session.user });
});
app.get("/dashboard", (req, res) => {
  // Make sure only admins can access
  if (!req.session.user || req.session.user.role !== 'admin') {
    return res.status(403).send("Access denied");
  }

  db.query("SELECT COUNT(*) AS medCount FROM medicines", (err, meds) => {
    if (err) return res.status(500).send("Error loading dashboard");

    db.query("SELECT COUNT(*) AS reportCount FROM reports", (err2, reports) => {
      if (err2) return res.status(500).send("Error loading dashboard");

      res.render("dashboard.ejs", {
        medCount: meds[0].medCount,
        reportCount: reports[0].reportCount,
        user: req.session.user,
      });
    });
  });
});

// Medicine Search
app.get("/find", (req, res) => {
  const search = req.query.q || "";
  db.query(
    "SELECT * FROM medicines WHERE name LIKE ?",
    [`%${search}%`],
    (err, results) => {
      if (err) return res.status(500).send("Error searching medicines");
      res.render("find.ejs", { results });
    }
  );
});

// Handle Signup
app.post("/signup", (req, res) => {
  const { username, email, password } = req.body;
  const hashedPassword = bcrypt.hashSync(password, 10);

  db.query(
    "INSERT INTO users (username, email, password, role) VALUES (?, ?, ?, 'user')",
    [username, email, hashedPassword],
    (err) => {
      if (err) return res.status(500).send("Signup failed");
      res.redirect("/login.ejs");
    }
  );
});

// Handle Login
app.post("/login", (req, res) => {
  const { email, password } = req.body;

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
});

// Logout
app.get("/logout", (req, res) => {
  req.session.destroy(() => {
    res.redirect("/");
  });
});
//console.log(bcrypt.hashSync("admin", 3)); 

// Server
app.listen(PORT, () => {
  console.log(`MediPrime running at http://localhost:${PORT}`);
});
