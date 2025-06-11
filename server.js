require("dotenv").config(); // Load environment variables first

const express = require("express");
const path = require("path");
const mysql = require("mysql2/promise"); // Use mysql2 for promise support
const session = require("express-session");
const bcrypt = require("bcrypt");
const winston = require("winston");
const { body, validationResult } = require("express-validator"); // For input validation

// --- NEW IMPORTS FOR SOCKET.IO ---
const http = require('http');
const { Server } = require('socket.io');

const app = express();
const PORT = process.env.PORT || 3000; // Use port from env or default to 3000

// --- Constants for Roles ---
const ROLES = {
    ADMIN: 'admin',
    USER: 'user',
    PHARMACY: 'pharmacy',
    // NEW ROLE TYPE: Pharmacy Staff (internal to a pharmacy)
    PHARMACY_STAFF: 'pharmacy_staff'
};
// NEW: Sub-roles within a pharmacy
const PHARMACY_SUB_ROLES = {
    PHARMACIST: 'pharmacist',
    MANAGER: 'manager',
    ASSISTANT: 'assistant'
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

// MODIFIED: authorizeRole to handle pharmacy staff sub-roles
const authorizeRole = (roles = [], subRoles = []) => {
    if (typeof roles === 'string') {
        roles = [roles]; // Ensure roles is an array
    }
    if (typeof subRoles === 'string') {
        subRoles = [subRoles]; // Ensure subRoles is an array
    }

    return (req, res, next) => {
        if (!req.session.user) {
            logger.warn(`Unauthorized access: No user session for ${req.originalUrl}`);
            return res.redirect("/login");
        }

        const userRole = req.session.user.role;
        const userSubRole = req.session.user.roleWithinPharmacy; // NEW: For pharmacy staff

        // Check if the user's primary role is authorized
        if (roles.length && !roles.includes(userRole)) {
            logger.warn(`Access denied for user '${req.session.user.email}' (role: ${userRole}) to ${req.originalUrl}`);
            return res.status(403).render("403.ejs", { user: res.locals.user, message: "Access Denied: You do not have permission to view this page." });
        }

        // If the user is pharmacy staff, also check their sub-role if required
        if (userRole === ROLES.PHARMACY_STAFF && subRoles.length && !subRoles.includes(userSubRole)) {
            logger.warn(`Access denied for pharmacy staff '${req.session.user.email}' (sub-role: ${userSubRole}) to ${req.originalUrl}`);
            return res.status(403).render("403.ejs", { user: res.locals.user, message: "Access Denied: Your staff role does not have permission to view this page." });
        }
        next();
    };
};

// NEW: User Activity Logger Middleware
// getDetails now accepts a function to defer evaluation until req is available
const logUserActivity = (actionType, getDetails = {}) => async (req, res, next) => {
    if (req.session.user) {
        try {
            // Evaluate details only when req is available
            const details = typeof getDetails === 'function' ? getDetails(req) : getDetails;
            await db.execute(
                "INSERT INTO user_activity_logs (user_id, action_type, details, ip_address, user_agent) VALUES (?, ?, ?, ?, ?)",
                [
                    req.session.user.id,
                    actionType,
                    JSON.stringify(details),
                    req.ip,
                    req.headers['user-agent']
                ]
            );
        } catch (err) {
            logger.error(`Failed to log user activity for ${req.session.user.id}:`, err);
        }
    }
    next();
};

// ===== Routes =====

// Homepage
app.get("/", logUserActivity('homepage_view'), (req, res) => { // Added activity logging
    logger.info("GET /");
    res.render("landing.ejs");
});

// Signup page
app.get("/signup", logUserActivity('signup_page_view'), (req, res) => { // Added activity logging
    logger.info("GET /signup");
    res.render("signup.ejs");
});

// Login page
app.get("/login", logUserActivity('login_page_view'), (req, res) => { // Added activity logging
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
app.get("/findMedicine", logUserActivity('medicine_search_page_view'), async (req, res) => { // Added activity logging
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
app.get("/dashboard", isAuthenticated, logUserActivity('dashboard_view'), async (req, res) => { // Added activity logging
    logger.info("GET /dashboard");

    try {
        if (req.session.user.role === ROLES.ADMIN) {
            const [meds] = await db.execute("SELECT COUNT(*) AS medCount FROM medicines");
            const [users] = await db.execute("SELECT COUNT(*) AS userCount FROM users WHERE role = 'user'");
            const [pharmacies] = await db.execute("SELECT COUNT(*) AS pharmacyCount FROM pharmacies");
            const [orders] = await db.execute("SELECT COUNT(*) AS orderCount FROM orders");
            const [allMedicines] = await db.execute("SELECT * FROM medicines");

            res.render("dashboard.ejs", {
                medCount: meds[0].medCount,
                userCount: users[0].userCount,
                pharmacyCount: pharmacies[0].pharmacyCount,
                orderCount: orders[0].orderCount,
                medicines: allMedicines,
            });
        } else if (req.session.user.role === ROLES.PHARMACY || req.session.user.role === ROLES.PHARMACY_STAFF) {
            return res.redirect("/pharmacy/dashboard");
        } else { // Regular user
            return res.redirect("/findMedicine"); // User's dashboard is findMedicine
        }
    } catch (err) {
        logger.error("Error loading dashboard", err);
        res.status(500).send("Error loading dashboard");
    }
});

// --- Order-related routes ---

// Order page (for regular users to view their orders)
app.get("/orders", isAuthenticated, authorizeRole(ROLES.USER), logUserActivity('user_orders_view'), async (req, res) => { // Added activity logging
    const userId = req.session.user.id;
    logger.info(`Accessing /orders with userId: ${userId}`);

    try {
        const query = `
            SELECT o.id, o.quantity, o.status, o.created_at,
                   m.name AS medicine_name, m.category AS medicine_category,
                   p.name AS pharmacy_name, p.address AS pharmacy_address, p.email AS pharmacy_email, p.phone AS pharmacy_phone
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
app.post("/user_orders", isAuthenticated, logUserActivity('place_order', (req) => ({ medicine_id: req.body.medicine_id, quantity: req.body.quantity })), [ // CORRECTED logUserActivity
    body('medicine_id').isInt({ gt: 0 }).withMessage('Invalid medicine ID.'),
    body('quantity').isInt({ gt: 0 }).withMessage('Quantity must be a positive integer.')
], async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        logger.warn(`Validation errors on POST /user_orders: ${JSON.stringify(errors.array())}`);
        return res.status(400).send(`Invalid order details: ${errors.array().map(e => e.msg).join(', ')}`);
    }

    const userId = req.session.user.id;
    const userRole = req.session.user.role;
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
            res.redirect("/dashboard");
        } else if (userRole === ROLES.PHARMACY || userRole === ROLES.PHARMACY_STAFF) {
            res.redirect("/pharmacy/dashboard");
        } else {
            res.redirect("/");
        }

    } catch (err) {
        logger.error("Error processing order", err);
        res.status(500).send("Internal Server Error");
    }
});

// Pharmacy orders (for pharmacies to view orders for their medicines)
app.get("/pharmacy_orders", isAuthenticated, authorizeRole([ROLES.PHARMACY, ROLES.PHARMACY_STAFF]), logUserActivity('pharmacy_orders_view'), async (req, res) => { // Added activity logging, extended authorization
    const pharmacyId = req.session.user.role === ROLES.PHARMACY_STAFF ? req.session.user.pharmacyId : req.session.user.id; // Get parent pharmacy ID for staff

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
app.post("/pharmacy_orders/update", isAuthenticated, authorizeRole([ROLES.PHARMACY, ROLES.PHARMACY_STAFF], [PHARMACY_SUB_ROLES.PHARMACIST, PHARMACY_SUB_ROLES.MANAGER]), logUserActivity('update_order_status', (req) => ({ order_id: req.body.order_id, new_status: req.body.new_status })), [ // CORRECTED logUserActivity
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
    const pharmacyId = user.role === ROLES.PHARMACY_STAFF ? user.pharmacyId : user.id;

    try {
        // Verify that the order belongs to this pharmacy
        const [check] = await db.execute(
            `SELECT o.id FROM orders o
             JOIN medicines m ON o.medicine_id = m.id
             WHERE o.id = ? AND m.pharmacy_id = ?`,
            [order_id, pharmacyId]
        );

        if (check.length === 0) {
            logger.warn(`Pharmacy ${pharmacyId} tried to update order ${order_id} which doesn't belong to them.`);
            return res.status(403).send("Order not found or not associated with your pharmacy.");
        }

        await db.execute(`UPDATE orders SET status = ? WHERE id = ?`, [
            new_status,
            order_id,
        ]);

        logger.info(`Order ${order_id} status updated to ${new_status} by pharmacy ${pharmacyId}`);
        res.redirect("/pharmacy_orders");
    } catch (err) {
        logger.error("Error updating order status", err);
        res.status(500).send("Something went wrong");
    }
});

// --- End Order-related routes ---


// Admin medicines list
app.get("/admin/medicines", isAuthenticated, authorizeRole(ROLES.ADMIN), logUserActivity('admin_medicines_view'), async (req, res) => { // Added activity logging
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
app.post("/admin/medicines/:id/edit", isAuthenticated, authorizeRole(ROLES.ADMIN), logUserActivity('admin_edit_medicine', (req) => ({ medicine_id: req.params.id, updates: req.body })), [ // CORRECTED logUserActivity
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
app.post("/admin/medicines/:id/delete", isAuthenticated, authorizeRole(ROLES.ADMIN), logUserActivity('admin_delete_medicine', (req) => ({ medicine_id: req.params.id })), async (req, res) => { // CORRECTED logUserActivity
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
app.get("/medicines/filter", logUserActivity('medicine_filter_search', (req) => ({ filters: req.query })), async (req, res) => { // CORRECTED logUserActivity
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
app.post("/signup", logUserActivity('signup_attempt', (req) => ({ email: req.body.email })), [ // CORRECTED logUserActivity
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
            // NOTE: Pharmacies table has 'name', 'email', 'password'.
            // Consider adding 'address', 'phone' fields here if needed on signup.
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

// Login handler (MODIFIED to support Pharmacy Staff)
app.post("/login", logUserActivity('login_attempt', (req) => ({ email: req.body.email, role: req.body.role })), [ // CORRECTED logUserActivity
    body('email').isEmail().withMessage('Valid email is required.').normalizeEmail(),
    body('password').notEmpty().withMessage('Password is required.'),
    body('role').isIn([ROLES.USER, ROLES.PHARMACY, ROLES.ADMIN, ROLES.PHARMACY_STAFF]).withMessage('Invalid role selected.') // Added PHARMACY_STAFF
], async (req, res) => {
    logger.info("POST /login");
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        logger.warn(`Validation errors on POST /login: ${JSON.stringify(errors.array())}`);
        return res.status(400).send(`Login failed: ${errors.array().map(e => e.msg).join(', ')}`);
    }

    const { email, password, role } = req.body;
    let user = null;
    let userRoleInDB = null;
    let userTable = null;
    let redirectTo = "/";

    try {
        if (role === ROLES.USER || role === ROLES.ADMIN) {
            userTable = "users";
            redirectTo = "/dashboard";
            const [results] = await db.execute(`SELECT * FROM ${userTable} WHERE email = ?`, [email]);
            if (results.length > 0) {
                user = results[0];
                userRoleInDB = user.role; // Get actual role from DB
            }
        } else if (role === ROLES.PHARMACY) {
            userTable = "pharmacies";
            redirectTo = "/pharmacy/dashboard";
            const [results] = await db.execute(`SELECT * FROM ${userTable} WHERE email = ?`, [email]);
            if (results.length > 0) {
                user = results[0];
                userRoleInDB = ROLES.PHARMACY; // Pharmacies table doesn't have a 'role' column, assume 'pharmacy'
            }
        } else if (role === ROLES.PHARMACY_STAFF) { // NEW: Handle pharmacy staff login
            userTable = "pharmacy_staff";
            redirectTo = "/pharmacy/dashboard";
            const [results] = await db.execute(`SELECT ps.*, p.id AS pharmacy_id FROM pharmacy_staff ps JOIN pharmacies p ON ps.pharmacy_id = p.id WHERE ps.email = ?`, [email]);
            if (results.length > 0) {
                user = results[0];
                userRoleInDB = ROLES.PHARMACY_STAFF; // This user is a pharmacy staff member
            }
        } else {
            logger.error(`Login failed: Invalid role '${role}' (should be caught by validator)`);
            return res.status(400).send("Invalid role specified.");
        }

        if (!user) {
            logger.warn(`Login failed for ${role} ${email}: Invalid credentials (email not found)`);
            return res.status(401).send("Invalid credentials.");
        }

        // Additional check for admin role if logging in as admin
        if (role === ROLES.ADMIN && userRoleInDB !== ROLES.ADMIN) {
            logger.warn(`Login failed: User ${email} tried to log in as ADMIN but has role ${userRoleInDB}`);
            return res.status(401).send("Invalid credentials or role.");
        }
        // Additional check for pharmacy staff role if logging in as staff (ensures they are not a main pharmacy account)
        if (role === ROLES.PHARMACY_STAFF && userRoleInDB !== ROLES.PHARMACY_STAFF) {
            logger.warn(`Login failed: User ${email} tried to log in as PHARMACY_STAFF but is not.`);
            return res.status(401).send("Invalid credentials or role.");
        }


        if (await bcrypt.compare(password, user.password)) {
            logger.info(`${userRoleInDB} ${email} logged in successfully`);
            req.session.user = {
                id: user.id,
                name: user.username || user.name,
                email: user.email,
                role: userRoleInDB // Set the role correctly
            };

            // NEW: Add specific fields for pharmacy staff
            if (userRoleInDB === ROLES.PHARMACY_STAFF) {
                req.session.user.pharmacyId = user.pharmacy_id; // Parent pharmacy ID
                req.session.user.roleWithinPharmacy = user.role_within_pharmacy; // e.g., 'pharmacist', 'manager'
            }

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
app.get("/pharmacy/dashboard", isAuthenticated, authorizeRole([ROLES.PHARMACY, ROLES.PHARMACY_STAFF]), logUserActivity('pharmacy_dashboard_view'), async (req, res) => { // Added activity logging
    logger.info("GET /pharmacy/dashboard");
    const pharmacyId = req.session.user.role === ROLES.PHARMACY_STAFF ? req.session.user.pharmacyId : req.session.user.id;

    try {
        const [medicines] = await db.execute(
            "SELECT * FROM medicines WHERE pharmacy_id = ?",
            [pharmacyId]
        );

        const [pendingOrders] = await db.execute(
            `SELECT COUNT(*) AS count FROM orders o JOIN medicines m ON o.medicine_id = m.id WHERE m.pharmacy_id = ? AND o.status = 'pending'`,
            [pharmacyId]
        );
        const [totalOrders] = await db.execute(
            `SELECT COUNT(*) AS count FROM orders o JOIN medicines m ON o.medicine_id = m.id WHERE m.pharmacy_id = ?`,
            [pharmacyId]
        );

        res.render("pharmacy_dashboard.ejs", {
            pharmacy: req.session.user, // Includes staff info if logged in as staff
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
app.post("/pharmacy_add_medicines", isAuthenticated, authorizeRole([ROLES.PHARMACY, ROLES.PHARMACY_STAFF], [PHARMACY_SUB_ROLES.PHARMACIST, PHARMACY_SUB_ROLES.MANAGER]), logUserActivity('pharmacy_add_medicine', (req) => ({ name: req.body.name })), [ // CORRECTED logUserActivity
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
    const pharmacyId = req.session.user.role === ROLES.PHARMACY_STAFF ? req.session.user.pharmacyId : req.session.user.id;
    const pharmacyName = req.session.user.role === ROLES.PHARMACY_STAFF ? (await db.execute("SELECT name FROM pharmacies WHERE id = ?", [pharmacyId]))[0][0].name : req.session.user.name;

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
app.post("/pharmacy/medicines/:id/delete", isAuthenticated, authorizeRole([ROLES.PHARMACY, ROLES.PHARMACY_STAFF], [PHARMACY_SUB_ROLES.PHARMACIST, PHARMACY_SUB_ROLES.MANAGER]), logUserActivity('pharmacy_delete_medicine', (req) => ({ medicine_id: req.params.id })), async (req, res) => { // CORRECTED logUserActivity
    logger.info(`POST /pharmacy/medicines/${req.params.id}/delete`);

    const { id } = req.params; // Medicine ID
    const pharmacyId = req.session.user.role === ROLES.PHARMACY_STAFF ? req.session.user.pharmacyId : req.session.user.id;


    try {
        // Verify the medicine belongs to this pharmacy before deleting
        const [check] = await db.execute(
            "SELECT id FROM medicines WHERE id = ? AND pharmacy_id = ?",
            [id, pharmacyId]
        );

        if (check.length === 0) {
            logger.warn(`Pharmacy ${pharmacyId} tried to delete medicine ${id} which doesn't belong to them.`);
            return res.status(403).send("You are not authorized to delete this medicine.");
        }

        await db.execute("DELETE FROM medicines WHERE id = ?", [id]);
        logger.info(`Medicine ${id} deleted by pharmacy ${pharmacyId}`);
        res.redirect("/pharmacy_edit_medicines"); // Redirect back to the edit list
    } catch (err) {
        logger.error("Failed to delete medicine", err);
        res.status(500).send("Failed to delete medicine");
    }
});

// Logout route
app.get("/logout", logUserActivity('logout'), (req, res) => { // Added activity logging
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

// --- NEW ROUTES FOR FEATURES ---

// 1. User Module - Prescription History
app.get("/user/prescriptions", isAuthenticated, authorizeRole(ROLES.USER), logUserActivity('view_prescriptions'), async (req, res) => {
    logger.info(`GET /user/prescriptions for user ${req.session.user.id}`);
    try {
        const [prescriptions] = await db.execute(
            `SELECT p.*, m.name AS medicine_name, m.category AS medicine_category
             FROM prescriptions p
             LEFT JOIN medicines m ON p.medicine_id = m.id
             WHERE p.user_id = ? ORDER BY p.issue_date DESC`,
            [req.session.user.id]
        );
        res.render("user_prescriptions.ejs", { prescriptions });
    } catch (err) {
        logger.error("Error fetching user prescriptions", err);
        res.status(500).send("Error loading prescriptions");
    }
});

// Example route to add a prescription (manual entry, assuming file upload is handled separately if needed)
app.post("/user/prescriptions/add", isAuthenticated, authorizeRole(ROLES.USER), logUserActivity('add_prescription', (req) => ({ medicine_id: req.body.medicine_id, doctor_name: req.body.doctor_name })), [ // CORRECTED logUserActivity
    body('doctor_name').trim().notEmpty().withMessage('Doctor name is required.'),
    body('issue_date').isISO8601().toDate().withMessage('Valid issue date is required.'),
    body('quantity').isInt({ gt: 0 }).withMessage('Quantity must be a positive integer.'),
    body('medicine_id').optional().isInt({ gt: 0 }).withMessage('Invalid medicine ID if provided.'),
    body('prescription_text').optional().trim().notEmpty().withMessage('Prescription text is required if no medicine ID.')
], async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        logger.warn(`Validation errors on POST /user/prescriptions/add: ${JSON.stringify(errors.array())}`);
        return res.status(400).send(`Failed to add prescription: ${errors.array().map(e => e.msg).join(', ')}`);
    }

    const { medicine_id, doctor_name, issue_date, expiry_date, quantity, notes, prescription_text } = req.body;
    const userId = req.session.user.id;

    try {
        await db.execute(
            "INSERT INTO prescriptions (user_id, medicine_id, prescription_text, doctor_name, issue_date, expiry_date, quantity, notes) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            [userId, medicine_id || null, prescription_text || null, doctor_name, issue_date, expiry_date || null, quantity, notes || null]
        );
        logger.info(`Prescription added for user ${userId}`);
        res.redirect("/user/prescriptions");
    } catch (err) {
        logger.error("Failed to add prescription", err);
        res.status(500).send("Failed to add prescription");
    }
});


// 2. Secure Messaging Service Routes
// (Socket.io implementation for real-time is above, these are for rendering views and fetching message history)

// Get list of chats for the current user/pharmacy
app.get("/chats", isAuthenticated, logUserActivity('view_chat_list'), async (req, res) => {
    const currentId = req.session.user.id;
    const currentRole = req.session.user.role;
    let pharmacyId = null;

    if (currentRole === ROLES.PHARMACY_STAFF) {
        pharmacyId = req.session.user.pharmacyId;
    }

    try {
        let conversationsQuery = `
            SELECT DISTINCT
                CASE
                    WHEN sender_role = ? AND sender_id = ? THEN CONCAT(receiver_role, '-', receiver_id)
                    ELSE CONCAT(sender_role, '-', sender_id)
                END AS chat_partner_key,
                (SELECT content FROM messages WHERE (sender_id = m.sender_id AND sender_role = m.sender_role AND receiver_id = m.receiver_id AND receiver_role = m.receiver_role) OR (sender_id = m.receiver_id AND sender_role = m.receiver_role AND receiver_id = m.sender_id AND receiver_role = m.sender_role) ORDER BY timestamp DESC LIMIT 1) AS last_message,
                (SELECT timestamp FROM messages WHERE (sender_id = m.sender_id AND sender_role = m.sender_role AND receiver_id = m.receiver_id AND receiver_role = m.receiver_role) OR (sender_id = m.receiver_id AND sender_role = m.receiver_role AND receiver_id = m.sender_id AND receiver_role = m.sender_role) ORDER BY timestamp DESC LIMIT 1) AS last_message_time
            FROM messages m
            WHERE (sender_id = ? AND sender_role = ?) OR (receiver_id = ? AND receiver_role = ?)
            ORDER BY last_message_time DESC;
        `;

        // Adjust parameters based on whether it's a main pharmacy or staff
        const params = (currentRole === ROLES.PHARMACY_STAFF) ?
            [ROLES.PHARMACY, pharmacyId, pharmacyId, ROLES.PHARMACY, currentId, currentRole] :
            [currentRole, currentId, currentId, currentRole, currentId, currentRole];


        const [conversations] = await db.execute(conversationsQuery, params);

        const chatPartners = [];
        for (const convo of conversations) {
            const [partnerRole, partnerId] = convo.chat_partner_key.split('-');
            let partnerName = 'Unknown';
            if (partnerRole === ROLES.USER) {
                const [user] = await db.execute("SELECT username FROM users WHERE id = ?", [partnerId]);
                partnerName = user[0] ? user[0].username : 'Deleted User';
            } else if (partnerRole === ROLES.PHARMACY) {
                const [pharmacy] = await db.execute("SELECT name FROM pharmacies WHERE id = ?", [partnerId]);
                partnerName = pharmacy[0] ? pharmacy[0].name : 'Deleted Pharmacy';
            } else if (partnerRole === ROLES.PHARMACY_STAFF) {
                const [staff] = await db.execute("SELECT username FROM pharmacy_staff WHERE id = ?", [partnerId]);
                partnerName = staff[0] ? staff[0].username : 'Deleted Staff';
            }
            chatPartners.push({
                partnerId: partnerId,
                partnerRole: partnerRole,
                partnerName: partnerName,
                lastMessage: convo.last_message,
                lastMessageTime: convo.last_message_time
            });
        }

        res.render("chat_list.ejs", { chatPartners });
    } catch (err) {
        logger.error("Error fetching chat list:", err);
        res.status(500).send("Error loading chats");
    }
});

// Get specific chat window and message history
app.get("/chat/:recipientRole/:recipientId", isAuthenticated, logUserActivity('open_chat', (req) => ({ recipientRole: req.params.recipientRole, recipientId: req.params.recipientId })), async (req, res) => { // CORRECTED logUserActivity
    const { recipientRole, recipientId } = req.params;
    const currentId = req.session.user.id;
    const currentRole = req.session.user.role;
    let pharmacyId = null; // For staff

    if (currentRole === ROLES.PHARMACY_STAFF) {
        pharmacyId = req.session.user.pharmacyId;
    }

    try {
        let messagesQuery = `
            SELECT * FROM messages
            WHERE (sender_id = ? AND sender_role = ? AND receiver_id = ? AND receiver_role = ?)
               OR (sender_id = ? AND sender_role = ? AND receiver_id = ? AND receiver_role = ?)
            ORDER BY timestamp ASC;
        `;
        let messages;
        if (currentRole === ROLES.PHARMACY_STAFF) {
            // Staff messages are effectively from/to their pharmacy
            messages = await db.execute(messagesQuery, [
                pharmacyId, ROLES.PHARMACY, recipientId, recipientRole,
                recipientId, recipientRole, pharmacyId, ROLES.PHARMACY
            ]);
        } else {
            messages = await db.execute(messagesQuery, [
                currentId, currentRole, recipientId, recipientRole,
                recipientId, recipientRole, currentId, currentRole
            ]);
        }


        let recipientName = 'Unknown';
        if (recipientRole === ROLES.USER) {
            const [user] = await db.execute("SELECT username FROM users WHERE id = ?", [recipientId]);
            recipientName = user[0] ? user[0].username : 'Deleted User';
        } else if (recipientRole === ROLES.PHARMACY) {
            const [pharmacy] = await db.execute("SELECT name FROM pharmacies WHERE id = ?", [recipientId]);
            recipientName = pharmacy[0] ? pharmacy[0].name : 'Deleted Pharmacy';
        } else if (recipientRole === ROLES.PHARMACY_STAFF) {
            const [staff] = await db.execute("SELECT username FROM pharmacy_staff WHERE id = ?", [recipientId]);
            recipientName = staff[0] ? staff[0].username : 'Deleted Staff';
        }


        res.render("chat_window.ejs", {
            messages: messages[0],
            recipientId: recipientId,
            recipientRole: recipientRole,
            recipientName: recipientName,
            currentUserId: currentId,
            currentUserRole: currentRole,
            currentPharmacyId: pharmacyId // Pass for staff
        });
    } catch (err) {
        logger.error("Error fetching chat messages:", err);
        res.status(500).send("Error loading chat");
    }
});


// 3. Pharmacy Module - Staff Management Routes
app.get("/pharmacy/staff/manage", isAuthenticated, authorizeRole([ROLES.PHARMACY, ROLES.PHARMACY_STAFF], [PHARMACY_SUB_ROLES.MANAGER]), logUserActivity('pharmacy_staff_manage_view'), async (req, res) => { // Only managers or main pharmacy account
    const pharmacyId = req.session.user.role === ROLES.PHARMACY_STAFF ? req.session.user.pharmacyId : req.session.user.id;
    logger.info(`GET /pharmacy/staff/manage for pharmacy ${pharmacyId}`);

    try {
        const [staffMembers] = await db.execute(
            "SELECT id, username, email, role_within_pharmacy, created_at FROM pharmacy_staff WHERE pharmacy_id = ?",
            [pharmacyId]
        );
        res.render("pharmacy_staff_management.ejs", { staffMembers, pharmacyId });
    } catch (err) {
        logger.error("Error fetching pharmacy staff", err);
        res.status(500).send("Error loading staff management page");
    }
});

app.post("/pharmacy/staff/add", isAuthenticated, authorizeRole([ROLES.PHARMACY, ROLES.PHARMACY_STAFF], [PHARMACY_SUB_ROLES.MANAGER]), logUserActivity('pharmacy_staff_add', (req) => ({ email: req.body.email })), [ // CORRECTED logUserActivity
    body('username').trim().notEmpty().withMessage('Username is required.'),
    body('email').isEmail().withMessage('Valid email is required.').normalizeEmail(),
    body('password').isLength({ min: 6 }).withMessage('Password must be at least 6 characters long.'),
    body('role_within_pharmacy').isIn(Object.values(PHARMACY_SUB_ROLES)).withMessage('Invalid staff role selected.')
], async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        logger.warn(`Validation errors on POST /pharmacy/staff/add: ${JSON.stringify(errors.array())}`);
        return res.status(400).send(`Failed to add staff: ${errors.array().map(e => e.msg).join(', ')}`);
    }

    const { username, email, password, role_within_pharmacy } = req.body;
    const pharmacyId = req.session.user.role === ROLES.PHARMACY_STAFF ? req.session.user.pharmacyId : req.session.user.id;

    try {
        const hashedPassword = await bcrypt.hash(password, 10);
        await db.execute(
            "INSERT INTO pharmacy_staff (pharmacy_id, username, email, password, role_within_pharmacy) VALUES (?, ?, ?, ?, ?)",
            [pharmacyId, username, email, hashedPassword, role_within_pharmacy]
        );
        logger.info(`Staff member ${email} added to pharmacy ${pharmacyId}`);
        res.redirect("/pharmacy/staff/manage");
    } catch (err) {
        if (err.code === 'ER_DUP_ENTRY') {
            logger.warn(`Failed to add staff: Email ${email} already exists.`);
            return res.status(409).send("Email already registered for a staff member.");
        }
        logger.error("Failed to add pharmacy staff", err);
        res.status(500).send("Failed to add staff member.");
    }
});

app.post("/pharmacy/staff/:id/delete", isAuthenticated, authorizeRole([ROLES.PHARMACY, ROLES.PHARMACY_STAFF], [PHARMACY_SUB_ROLES.MANAGER]), logUserActivity('pharmacy_staff_delete', (req) => ({ staff_id: req.params.id })), async (req, res) => { // CORRECTED logUserActivity
    const { id } = req.params; // Staff ID
    const pharmacyId = req.session.user.role === ROLES.PHARMACY_STAFF ? req.session.user.pharmacyId : req.session.user.id;

    try {
        const [check] = await db.execute("SELECT id FROM pharmacy_staff WHERE id = ? AND pharmacy_id = ?", [id, pharmacyId]);
        if (check.length === 0) {
            logger.warn(`Pharmacy ${pharmacyId} tried to delete staff ${id} which doesn't belong to them.`);
            return res.status(403).send("You are not authorized to delete this staff member.");
        }
        await db.execute("DELETE FROM pharmacy_staff WHERE id = ?", [id]);
        logger.info(`Staff member ${id} deleted by pharmacy ${pharmacyId}`);
        res.redirect("/pharmacy/staff/manage");
    } catch (err) {
        logger.error("Failed to delete pharmacy staff", err);
        res.status(500).send("Failed to delete staff member.");
    }
});


// 4. Search & Discovery Service - Direct Pharmacy Search
app.get("/findPharmacy", logUserActivity('find_pharmacy_page_view'), (req, res) => {
    logger.info("GET /findPharmacy");
    res.render("find_pharmacy.ejs", { query: req.query }); // Render a search page
});

app.get("/api/pharmacies/search", logUserActivity('api_pharmacy_search', (req) => ({ filters: req.query })), async (req, res) => { // CORRECTED logUserActivity
    logger.info("GET /api/pharmacies/search");
    const { name, location, services } = req.query;

    let query = `SELECT id, name, address, email, phone, services FROM pharmacies WHERE 1=1`;
    let params = [];

    if (name) {
        query += " AND name LIKE ?";
        params.push(`%${name}%`);
    }
    if (location) {
        query += " AND address LIKE ?"; // Assuming 'address' is the location field
        params.push(`%${location}%`);
    }
    if (services) {
        // This is a basic LIKE search for services. For robust search,
        // you might need full-text search or a separate services table.
        query += " AND services LIKE ?";
        params.push(`%${services}%`);
    }

    try {
        const [results] = await db.execute(query, params);
        res.json({ pharmacies: results }); // Return JSON for client-side rendering
    } catch (err) {
        logger.error("Database error in /api/pharmacies/search", err);
        res.status(500).json({ error: "Database error" });
    }
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

        // --- Start the HTTP server AND Socket.io server ---
        // Create an HTTP server that uses your Express app
        const server = http.createServer(app);
        // Initialize Socket.io with the HTTP server
        const io = new Server(server, {
            cors: {
                origin: process.env.CLIENT_URL || "http://localhost:3000", // Allow your frontend to connect
                methods: ["GET", "POST"]
            }
        });

        // NEW: Socket.io connection handling (part of Secure Messaging Service)
        const connectedClients = {}; // { 'user-userId': socket.id, 'pharmacy-pharmacyId': socket.id, 'pharmacy_staff-staffId': socket.id }

        io.on('connection', (socket) => {
            logger.info(`Socket connected: ${socket.id}`);

            socket.on('register', ({ entityId, role }) => {
                if (entityId && role) {
                    const key = `${role}-${entityId}`;
                    connectedClients[key] = socket.id;
                    socket.join(key); // Join a room specific to their ID for direct messaging
                    logger.info(`${role} ${entityId} registered with socket ${socket.id}`);
                }
            });

            socket.on('sendMessage', async ({ senderId, senderRole, receiverId, receiverRole, content }) => {
                if (!senderId || !senderRole || !receiverId || !receiverRole || !content) {
                    logger.warn('Incomplete message data received via socket.');
                    socket.emit('messageError', 'Missing message data.');
                    return;
                }

                try {
                    // Determine the effective sender/receiver IDs and roles for database storage
                    // Acknowledge that the client passes its own ID/Role
                    // If the sender/receiver is pharmacy staff, the actual DB entry should be for their parent pharmacy.
                    let effectiveSenderId = senderId;
                    let effectiveSenderRole = senderRole;
                    let effectiveReceiverId = receiverId;
                    let effectiveReceiverRole = receiverRole;

                    if (senderRole === ROLES.PHARMACY_STAFF) {
                        const [staffInfo] = await db.execute("SELECT pharmacy_id FROM pharmacy_staff WHERE id = ?", [senderId]);
                        if (staffInfo.length > 0) {
                            effectiveSenderId = staffInfo[0].pharmacy_id;
                            effectiveSenderRole = ROLES.PHARMACY;
                        } else {
                            logger.warn(`Sender staff ID ${senderId} not found for sendMessage.`);
                            socket.emit('messageError', 'Sender identity invalid.');
                            return;
                        }
                    }

                    if (receiverRole === ROLES.PHARMACY_STAFF) {
                        const [staffInfo] = await db.execute("SELECT pharmacy_id FROM pharmacy_staff WHERE id = ?", [receiverId]);
                        if (staffInfo.length > 0) {
                            effectiveReceiverId = staffInfo[0].pharmacy_id;
                            effectiveReceiverRole = ROLES.PHARMACY;
                        } else {
                            logger.warn(`Receiver staff ID ${receiverId} not found for sendMessage.`);
                            socket.emit('messageError', 'Receiver identity invalid.');
                            return;
                        }
                    }

                    const [result] = await db.execute(
                        "INSERT INTO messages (sender_id, sender_role, receiver_id, receiver_role, content) VALUES (?, ?, ?, ?, ?)",
                        [effectiveSenderId, effectiveSenderRole, effectiveReceiverId, effectiveReceiverRole, content]
                    );
                    const messageId = result.insertId;

                    const message = { id: messageId, senderId: effectiveSenderId, senderRole: effectiveSenderRole, receiverId: effectiveReceiverId, receiverRole: effectiveReceiverRole, content, timestamp: new Date(), is_read: false };

                    // Emit to the original sender's specific room (for immediate display back to sender)
                    io.to(`${senderRole}-${senderId}`).emit('message', message);

                    // Emit to the original receiver's specific room (if online)
                    if (connectedClients[`${receiverRole}-${receiverId}`]) {
                        io.to(`${receiverRole}-${receiverId}`).emit('message', message);
                        logger.info(`Message sent from ${senderRole} ${senderId} to ${receiverRole} ${receiverId} (via socket)`);
                    } else {
                        logger.info(`Receiver ${receiverRole} ${receiverId} is offline. Message saved to DB.`);
                    }

                    // Log activity directly since 'req' is not available in socket context
                    try {
                        await db.execute(
                            "INSERT INTO user_activity_logs (user_id, action_type, details, ip_address, user_agent) VALUES (?, ?, ?, ?, ?)",
                            [
                                senderId, // Log activity with the actual user/staff ID
                                'send_message',
                                JSON.stringify({ to_id: receiverId, to_role: receiverRole, content_length: content.length }),
                                socket.request.connection.remoteAddress, // Get IP from socket request
                                socket.request.headers['user-agent'] || 'N/A' // Get User-Agent from socket request
                            ]
                        );
                    } catch (logErr) {
                        logger.error(`Failed to log socket message activity for ${senderId}:`, logErr);
                    }

                } catch (err) {
                    logger.error("Error saving/sending message via socket:", err);
                    socket.emit('messageError', 'Failed to send message.');
                }
            });

            socket.on('disconnect', () => {
                logger.info(`Socket disconnected: ${socket.id}`);
                // Remove the disconnected client from the map
                for (const key in connectedClients) {
                    if (connectedClients[key] === socket.id) {
                        delete connectedClients[key];
                        logger.info(`Unregistered ${key} from connected clients.`);
                        break;
                    }
                }
            });
        });

        server.listen(PORT, () => { // LISTEN ON THE HTTP SERVER, NOT THE EXPRESS APP DIRECTLY
            logger.info(`Server started on http://localhost:${PORT}`);
        });
    } catch (err) {
        logger.error("Failed to start server due to database connection error.", err);
        process.exit(1); // Exit if DB connection fails at startup
    }
}

startServer(); // Call the function to start the application